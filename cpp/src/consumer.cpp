// SPDX-License-Identifier: Apache-2.0
//
// The security-critical middle of a consumer, transport-free: raw message in,
// verified decoded event out. Everything that must not be skippable — the
// Ed25519 check under the egress key, the decode, the guards, the counters —
// lives here; the subscription loop stays the embedder's.

#include <ajar/connector.hpp>

#include <algorithm>

namespace ajar {

std::function<void(const std::vector<std::uint8_t>&, const std::string&)>
verifying_handler(const std::array<std::uint8_t, 32>& egress_key,
                  ConsumerGuards guards, ConsumerStats* stats,
                  std::function<void(Delivery)> handle) {
  return [egress_key, guards = std::move(guards), stats,
          handle = std::move(handle)](const std::vector<std::uint8_t>& data,
                                      const std::string& subject) {
    const std::optional<std::string> canonical = verify(data, egress_key);
    if (!canonical) {
      if (stats) ++stats->rejected;
      return;
    }
    Event event;
    if (!event.ParseFromString(*canonical)) {
      if (stats) ++stats->rejected;
      return;
    }
    if (std::find(guards.skip_source_ids.begin(), guards.skip_source_ids.end(),
                  event.source_id()) != guards.skip_source_ids.end()) {
      if (stats) ++stats->skipped;
      return;
    }
    if (guards.skip_derived) {
      for (const auto& attr : event.attributes()) {
        if (attr.key() == "model") {
          if (stats) ++stats->skipped;
          return;
        }
      }
    }
    if (stats) ++stats->accepted;
    handle(Delivery{std::move(event), subject});
  };
}

}  // namespace ajar
