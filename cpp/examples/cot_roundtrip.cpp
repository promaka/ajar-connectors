// SPDX-License-Identifier: Apache-2.0
//
// Round-trip conformance for the CoT example: canonical -> CoT -> canonical is
// identity over the modeled fields (lossy fields left at defaults so full bytes
// match). Exit 0 on success.

#include <cstdio>
#include <string>

#include "ajar/connector.hpp"
#include "cot_connector.hpp"

int main() {
  cot::CotConnector conn("ad-radar-7");

  const std::string sample =
      "<event version=\"2.0\" uid=\"0191e7b0-3c2d-7e3f-8a9b-0c1d2e3f4a5d\" type=\"a-f-A\" "
      "time=\"2026-06-04T02:00:00Z\" start=\"2026-06-04T02:00:00Z\" stale=\"2026-06-04T02:00:30Z\">"
      "<point lat=\"26.4\" lon=\"50.9\" hae=\"1200.0\" ce=\"10.0\" le=\"10.0\"/></event>";

  ajar::Event normalized = conn.normalize(sample);
  if (normalized.entity_type() != "mim:aircraft") {
    std::printf("FAIL: entity_type = %s\n", normalized.entity_type().c_str());
    return 1;
  }

  // Build with only modeled fields set, render, normalize back, compare bytes.
  ajar::Event original = ajar::EventBuilder("ad-radar-7", "mim:aircraft")
                             .id("0191e7b0-3c2d-7e3f-8a9b-0c1d2e3f4a5d")
                             .timestamp("2026-06-04T02:00:00Z")
                             .location(26.4, 50.9, 1200.0)
                             .build();

  ajar::Event back = conn.normalize(conn.render(original));

  if (ajar::canonical_bytes(original) != ajar::canonical_bytes(back)) {
    std::printf("FAIL: modeled fields did not survive the CoT round trip\n");
    return 1;
  }
  std::printf("ok   CoT round trip preserves modeled fields\n");
  return 0;
}
