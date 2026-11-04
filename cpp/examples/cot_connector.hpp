// SPDX-License-Identifier: Apache-2.0
//
// Teaching example between Cursor-on-Target (CoT) XML and canonical Ajar events,
// with minimal XML handling and no XML dependency. Not a production CoT stack;
// for production CoT ingest, use rust/connectors/tak-cot. Mirrors the Rust and Go
// examples.

#ifndef AJAR_COT_CONNECTOR_HPP
#define AJAR_COT_CONNECTOR_HPP

#include <string>
#include <vector>

#include "ajar/connector.hpp"

namespace cot {

// A CoT connector bound to one source identity. CoT carries no Ajar source
// identity, so it comes from configuration (and matches the signing profile).
class CotConnector : public ajar::Connector, public ajar::OutboundProfile {
 public:
  explicit CotConnector(std::string source_id) : source_id_(std::move(source_id)) {}

  ajar::Event normalize(const std::string& native) const override;

  std::string target() const override { return "Cursor-on-Target"; }
  std::string slug() const override { return "tak-cot"; }
  std::string version() const override { return "0.1.0"; }
  std::vector<std::string> modeled_fields() const override {
    return {"id", "entity_type", "timestamp", "location"};
  }
  std::vector<std::string> lossy_fields() const override {
    return {"source_id", "payload", "policy_tags", "confidence", "attributes"};
  }
  std::string render(const ajar::Event& event) const override;

 private:
  std::string source_id_;
};

}  // namespace cot

#endif  // AJAR_COT_CONNECTOR_HPP
