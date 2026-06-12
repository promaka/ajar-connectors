// SPDX-License-Identifier: Apache-2.0

#include "ajar/connector.hpp"

extern "C" {
#include "monocypher-ed25519.h"
}

namespace ajar {

SigningKey SigningKey::from_seed(const std::array<std::uint8_t, 32>& seed) {
  SigningKey key;
  std::array<std::uint8_t, 32> seed_copy = seed;  // key_pair wipes its seed arg
  crypto_ed25519_key_pair(key.secret_.data(), key.public_.data(), seed_copy.data());
  return key;
}

std::vector<std::uint8_t> seal(const std::string& canonical, const SigningKey& key) {
  std::array<std::uint8_t, kSealSignatureLen> sig{};
  crypto_ed25519_sign(sig.data(), key.secret_.data(),
                      reinterpret_cast<const std::uint8_t*>(canonical.data()),
                      canonical.size());

  std::vector<std::uint8_t> out;
  out.reserve(kSealSignatureLen + canonical.size());
  out.insert(out.end(), sig.begin(), sig.end());
  out.insert(out.end(), canonical.begin(), canonical.end());
  return out;
}

}  // namespace ajar
