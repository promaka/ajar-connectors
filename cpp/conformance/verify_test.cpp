// SPDX-License-Identifier: Apache-2.0
//
// The seal envelope in reverse: verify() must accept exactly what seal()
// produces and refuse a change to any byte, under either direction's key —
// there is only one envelope, so this one suite covers ingress and egress.

#include <ajar/connector.hpp>

#include <chrono>
#include <cstdio>
#include <random>

namespace {

int failures = 0;

void check(bool ok, const char* what) {
  std::printf("%s %s\n", ok ? "ok  " : "FAIL", what);
  if (!ok) ++failures;
}

std::array<std::uint8_t, 32> random_seed() {
  std::array<std::uint8_t, 32> s{};
  std::random_device rd;
  for (auto& b : s) b = static_cast<std::uint8_t>(rd());
  return s;
}

}  // namespace

int main() {
  const auto key = ajar::SigningKey::from_seed(random_seed());
  const ajar::Event event = ajar::EventBuilder("acme-radar-1", "mim:aircraft")
                                .new_id()
                                .timestamp("2026-06-10T08:00:00Z")
                                .location(25.27, 51.52, 10600.0)
                                .attribute("hostility", "Friend")
                                .build();
  const std::string canonical = ajar::canonical_bytes(event);
  const std::vector<std::uint8_t> sealed = ajar::seal(canonical, key);

  {
    const auto got = ajar::verify(sealed, key.verifying_key());
    check(got.has_value() && *got == canonical, "verify round-trips seal");
  }

  {
    bool all_refused = true;
    for (std::size_t i : {std::size_t{0}, ajar::kSealSignatureLen - 1,
                          ajar::kSealSignatureLen, sealed.size() - 1}) {
      auto bad = sealed;
      bad[i] ^= 0x01;
      if (ajar::verify(bad, key.verifying_key()).has_value()) all_refused = false;
    }
    check(all_refused, "a change to any byte is refused");
  }

  {
    std::vector<std::uint8_t> shortie(sealed.begin(), sealed.begin() + ajar::kSealSignatureLen - 1);
    check(!ajar::verify(shortie, key.verifying_key()).has_value(),
          "a truncated envelope is refused");
    const auto other = ajar::SigningKey::from_seed(random_seed());
    check(!ajar::verify(sealed, other.verifying_key()).has_value(),
          "another key's seal is refused");
  }

  {
    constexpr int n = 5000;
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < n; ++i)
      if (!ajar::verify(sealed, key.verifying_key())) return 2;
    const double secs =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    std::printf("ok   verify throughput: %.0f envelopes/sec on one core\n", n / secs);
    check(n / secs > 1000.0, "hot-path grade throughput");
  }

  if (failures) {
    std::printf("\n%d verify failure(s)\n", failures);
    return 1;
  }
  std::printf("\nseal/verify holds in both directions\n");
  return 0;
}
