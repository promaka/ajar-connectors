// SPDX-License-Identifier: Apache-2.0
//
// ajar-connector (C++): the vendor-facing SDK for building byte-compatible
// connectors to the Ajar integration plane. Desktop build — types are generated
// from the same vendored event.proto via protoc, and canonical bytes are the
// deterministic protobuf encoding that gets hashed and signed. The shared
// vendor/contract/vectors.json proves the C++ output is byte-identical to the
// Rust and Go SDKs.
//
// Crypto is vendored (Monocypher Ed25519, RFC 8032) — no system crypto dep.

#ifndef AJAR_CONNECTOR_HPP
#define AJAR_CONNECTOR_HPP

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "event.pb.h" // generated from vendor/contract/event.proto (ajar.event.v1)

namespace ajar {

// The canonical event type, generated from the vendored proto.
using Event = ::ajar::event::v1::Event;
using GeoPoint = ::ajar::event::v1::GeoPoint;
using Attribute = ::ajar::event::v1::Attribute;

// Contract limits (§3).
constexpr std::size_t kMaxAttributes = 128;
constexpr std::size_t kMaxMetadata = 128;
constexpr std::size_t kMaxPolicyTags = 64;

// Length in bytes of the Ed25519 signature prefix on a sealed envelope.
constexpr std::size_t kSealSignatureLen = 64;

// Thrown by EventBuilder::build when a canonical invariant or required field is
// violated. The builder fails closed.
class BuildError : public std::runtime_error {
 public:
  explicit BuildError(const std::string& what) : std::runtime_error(what) {}
};

// An Ed25519 signing key. Each production connector holds its own; Ajar
// registers the matching verifying key in the connector's profile. The
// golden-vector seed (32 x 0x47) is a published TEST seed — never sign
// production events with it.
class SigningKey {
 public:
  // Derives a key from a 32-byte seed (RFC 8032). The seed is copied; the copy
  // is wiped after derivation.
  static SigningKey from_seed(const std::array<std::uint8_t, 32>& seed);

  // The 32-byte Ed25519 public (verifying) key.
  const std::array<std::uint8_t, 32>& verifying_key() const { return public_; }

 private:
  friend std::vector<std::uint8_t> seal(const std::string&, const SigningKey&);
  std::array<std::uint8_t, 64> secret_{};
  std::array<std::uint8_t, 32> public_{};
};

// Returns the canonical protobuf encoding of `event`: deterministic, ascending
// tag order, proto3 defaults omitted — the same bytes prost and the Go
// deterministic marshaller produce. The caller owns the attribute invariant
// (sorted by key, unique); EventBuilder guarantees it.
std::string canonical_bytes(const Event& event);

// Seals canonical bytes: 64-byte detached Ed25519 signature followed by the
// canonical bytes (sealed = sign(key, canonical) ++ canonical).
std::vector<std::uint8_t> seal(const std::string& canonical, const SigningKey& key);

// Ergonomic, fail-closed Event construction. Auto-sorts attributes, rejects
// duplicate keys, enforces required fields and limits, offers UUIDv7 / RFC 3339
// helpers. received_at is intentionally not exposed — Ajar stamps its own clock.
class EventBuilder {
 public:
  EventBuilder(std::string source_id, std::string entity_type);

  EventBuilder& id(std::string id);
  EventBuilder& new_id();              // fresh UUIDv7
  EventBuilder& timestamp(std::string ts);
  EventBuilder& now();                 // RFC 3339 UTC now
  EventBuilder& location(double latitude, double longitude, double altitude_m);
  EventBuilder& payload(std::string bytes);
  EventBuilder& policy_tag(std::string tag);
  EventBuilder& confidence(double confidence);
  EventBuilder& attribute(std::string key, std::string value);
  // Adds one ungoverned passthrough metadata entry (ADR-0030): a vendor-specific
  // field carried and audited opaquely, but not type-validated or correlated
  // (e.g. a source's native identifier). Sorted by key at build(); duplicate
  // keys rejected there.
  EventBuilder& metadata(std::string key, std::string value);
  EventBuilder& allow_unnamespaced_entity_type();

  // Validates invariants and returns the canonical Event. Throws BuildError.
  Event build() const;

 private:
  std::string source_id_;
  std::string entity_type_;
  std::string id_;
  std::string timestamp_;
  bool has_location_ = false;
  double lat_ = 0, lon_ = 0, alt_ = 0;
  std::string payload_;
  std::vector<std::string> policy_tags_;
  double confidence_ = 0.0;
  std::vector<std::pair<std::string, std::string>> attributes_;
  std::vector<std::pair<std::string, std::string>> metadata_;
  bool strict_entity_namespace_ = true;
};

// Checking a mapping against the vendored ontology, before events are built.
//
// Ajar's ingest is graceful: an entity type or attribute name the ontology does
// not declare is discarded rather than rejected, so a typo has no symptom — the
// connector runs, seals and publishes while its tracks never appear. Validation
// answers that at startup instead. It is advisory: nothing here throws or
// refuses per event; refusing to start on faults is the embedder's decision at
// their own initialisation.
//
// The ontology is compiled into the library from the vendored, hash-pinned
// vendor/contract/ontology.json, so validation is offline and cannot drift from
// the contract the release shipped with.

// One thing a declared mapping gets wrong.
struct ValidationFault {
  enum class Kind {
    UnknownEntityType,  // the ontology does not declare this type
    UnknownAttribute,   // no ancestor of the declared type governs this name
    NotInVocabulary,    // a fixed value outside a controlled, case-sensitive set
  };
  Kind kind;
  std::string subject;               // the entity type or attribute name at fault
  std::string value;                 // NotInVocabulary: the offending value
  std::string suggestion;            // same name with the correct case, if that is the mistake
  std::vector<std::string> allowed;  // NotInVocabulary: the valid values

  // A sentence naming the fault and the correction, for logs and CI output.
  std::string message() const;
};

// What a mapping proposes to emit. `fixed_values` are attribute values known at
// configuration time (an enrichment like hostility), checkable before any event.
struct DeclaredMapping {
  std::string entity_type;
  std::vector<std::string> attributes;
  std::vector<std::pair<std::string, std::string>> fixed_values;
};

// Every fault in the mapping, empty when it is clean. An x:vendor:type is the
// operator's to register and produces no faults. Attribute inheritance is
// followed, so an aircraft may set anything mim:object declares.
std::vector<ValidationFault> validate(const DeclaredMapping& mapping);

// The same check against a built event: its entity type, attribute names and
// attribute values. Suits a template's --check mode, where validating the real
// output beats validating a declaration that can drift from it.
std::vector<ValidationFault> validate(const Event& event);

// The version string of the vendored ontology, e.g. "mim-5.3-conformant-1".
const char* ontology_version();

// A connector's published self-declaration: what it may emit and how Ajar
// authenticates it. Serializes deterministically (verifying key as lowercase
// hex); byte-identical to the Rust and Go profile JSON.
class ConnectorProfile {
 public:
  ConnectorProfile(std::string source_id, std::array<std::uint8_t, 32> verifying_key);

  ConnectorProfile& allow_entity_type(std::string entity_type);
  ConnectorProfile& max_payload_bytes(std::uint64_t max);
  ConnectorProfile& rate_limit(std::uint32_t capacity, double refill_per_sec);

  std::string to_json() const;         // compact
  std::string to_json_pretty() const;  // indented

 private:
  std::string source_id_;
  std::vector<std::string> allowed_entity_types_;
  std::uint64_t max_payload_bytes_ = 64 * 1024;
  std::uint32_t rate_capacity_ = 100;
  double rate_refill_per_sec_ = 10.0;
  std::array<std::uint8_t, 32> verifying_key_{};
};

// An inbound connector: native bytes -> canonical Event. Implementations parse
// `native` and return a fully-populated event, ideally via EventBuilder.
class Connector {
 public:
  virtual ~Connector() = default;
  virtual Event normalize(const std::string& native) const = 0;
};

// An outbound profile: renders a governed Event into a target format. Its
// honesty is the modeled/lossy field declaration; round-trip conformance
// (canonical -> target -> canonical) checks the claim.
class OutboundProfile {
 public:
  virtual ~OutboundProfile() = default;
  virtual std::string target() const = 0;
  virtual std::string slug() const = 0;
  virtual std::string version() const = 0;
  virtual std::vector<std::string> modeled_fields() const = 0;
  virtual std::vector<std::string> lossy_fields() const = 0;
  virtual std::string render(const Event& event) const = 0;
};

}  // namespace ajar

#endif  // AJAR_CONNECTOR_HPP
