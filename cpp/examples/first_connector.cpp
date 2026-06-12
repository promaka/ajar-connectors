// SPDX-License-Identifier: Apache-2.0
//
// Your first connector, end to end: native CoT in, signed canonical event out.
// Build target: first_connector

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "ajar/connector.hpp"
#include "cot_connector.hpp"

int main() {
  const std::string native =
      "<event version=\"2.0\" uid=\"0191e7b0-3c2d-7e3f-8a9b-0c1d2e3f4a5d\" type=\"a-f-A\" "
      "time=\"2026-06-04T02:00:00Z\" start=\"2026-06-04T02:00:00Z\" stale=\"2026-06-04T02:00:30Z\">"
      "<point lat=\"26.4\" lon=\"50.9\" hae=\"1200.0\" ce=\"10.0\" le=\"10.0\"/></event>";

  // 1. Normalize native -> canonical event.
  cot::CotConnector connector("ad-radar-7");
  const ajar::Event event = connector.normalize(native);

  // 2. Canonicalize and sign with this connector's own key. The demo seed is
  //    illustration only — generate and persist a real per-connector key.
  std::array<std::uint8_t, 32> demo_seed = {
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
      0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01};
  const ajar::SigningKey key = ajar::SigningKey::from_seed(demo_seed);
  const std::string canonical = ajar::canonical_bytes(event);
  const std::vector<std::uint8_t> sealed = ajar::seal(canonical, key);

  // 3. Declare the profile Ajar registers for this connector.
  ajar::ConnectorProfile profile(std::string("ad-radar-7"), key.verifying_key());
  profile.allow_entity_type("mim:aircraft").rate_limit(200, 20.0);

  std::printf("entity_type : %s\n", event.entity_type().c_str());
  std::printf("canonical   : %zu bytes\n", canonical.size());
  std::printf("sealed      : %zu bytes (64-byte sig + canonical)\n", sealed.size());
  std::printf("profile     :\n%s\n", profile.to_json_pretty().c_str());
  return 0;
}
