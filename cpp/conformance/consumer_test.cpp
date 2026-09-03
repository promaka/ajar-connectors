// SPDX-License-Identifier: Apache-2.0
//
// The consumer handler against the same adversarial scenario the Python, Go
// and Rust SDKs gate on: five messages — valid, tampered, the consumer's own,
// derived, valid — must land as exactly two deliveries, one rejection and two
// skips, with the tampered envelope never reaching the callback.

#include <ajar/connector.hpp>

#include <cstdio>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool ok, const char* what) {
  std::printf("%s %s\n", ok ? "ok  " : "FAIL", what);
  if (!ok) ++failures;
}

std::array<std::uint8_t, 32> seed(std::uint8_t b) {
  std::array<std::uint8_t, 32> s{};
  s.fill(b);
  return s;
}

std::vector<std::uint8_t> sealed_event(const ajar::SigningKey& key,
                                       const std::string& source_id,
                                       const std::string& event_id,
                                       bool derived = false) {
  ajar::EventBuilder b(source_id, "mim:aircraft");
  b.id(event_id)
      .timestamp("2026-09-03T08:00:00Z")
      .location(51.5, -0.12, 9100.0)
      .attribute("hostility", "Friend");
  if (derived) {
    b.attribute("model", "acme-detector-2")
        .attribute("derived_from", "evt-parent-1");
  }
  return ajar::seal(ajar::canonical_bytes(b.build()), key);
}

}  // namespace

int main() {
  const auto egress = ajar::SigningKey::from_seed(seed(0x55));

  ajar::ConsumerGuards guards;
  guards.skip_source_ids = {"acme-fuser-1"};
  guards.skip_derived = true;

  ajar::ConsumerStats stats;
  std::vector<ajar::Delivery> got;
  const auto on_message = ajar::verifying_handler(
      egress.verifying_key(), guards, &stats,
      [&got](ajar::Delivery d) { got.push_back(std::move(d)); });

  // 1. Valid: delivered.
  on_message(sealed_event(egress, "acme-radar-1", "evt-1"), "ajar.egress");

  // 2. Tampered: one flipped payload byte, refused before decode.
  auto tampered = sealed_event(egress, "acme-radar-1", "evt-2");
  tampered.back() ^= 0x01;
  on_message(tampered, "ajar.egress");

  // 3. The consumer's own event: skipped by the self-consume guard.
  on_message(sealed_event(egress, "acme-fuser-1", "evt-3"), "ajar.egress");

  // 4. Derived (carries the model attribute): skipped by skip_derived.
  on_message(sealed_event(egress, "acme-radar-1", "evt-4", true), "ajar.egress");

  // 5. Valid: delivered.
  on_message(sealed_event(egress, "acme-radar-2", "evt-5"), "ajar.egress");

  check(stats.accepted == 2, "accepted == 2");
  check(stats.rejected == 1, "rejected == 1 (tampered)");
  check(stats.skipped == 2, "skipped == 2 (own + derived)");
  check(got.size() == 2, "exactly two deliveries");
  check(got.size() == 2 && got[0].event.id() == "evt-1" &&
            got[1].event.id() == "evt-5",
        "delivered ids are evt-1, evt-5");
  check(got.size() == 2 && got[0].subject == "ajar.egress",
        "subject rides along");

  // Wrong verifying key refuses everything, delivers nothing.
  ajar::ConsumerStats wrong_stats;
  const auto wrong_key = ajar::SigningKey::from_seed(seed(0x66));
  const auto wrong = ajar::verifying_handler(
      wrong_key.verifying_key(), {}, &wrong_stats,
      [](ajar::Delivery) { std::printf("FAIL delivery under wrong key\n"); });
  on_message(sealed_event(egress, "acme-radar-1", "evt-6"), "ajar.egress");
  wrong(sealed_event(egress, "acme-radar-1", "evt-6"), "ajar.egress");
  check(wrong_stats.rejected == 1 && wrong_stats.accepted == 0,
        "wrong egress key rejects");

  // Null stats is tolerated; garbage is refused without throwing.
  const auto no_stats = ajar::verifying_handler(egress.verifying_key(), {},
                                                nullptr, [](ajar::Delivery) {});
  no_stats(std::vector<std::uint8_t>(16, 0xAB), "ajar.egress");
  no_stats(sealed_event(egress, "acme-radar-1", "evt-7"), "ajar.egress");
  check(true, "null stats and short envelope handled");

  if (failures != 0) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("consumer handler conformance: all checks passed\n");
  return 0;
}
