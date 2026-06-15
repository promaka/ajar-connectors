#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate an Ed25519 signing key for a connector. Writes:
#   <name>.key   the private key (KEEP SECRET — your secret store/HSM)
#   <name>.seed  the 32-byte seed your connector loads (AJAR_SIGNING_SEED)
# and prints the public key hex to register with Ajar.
#
# Usage:  scripts/gen-connector-key.sh [name]     (default name: connector)
set -euo pipefail
name="${1:-connector}"

openssl genpkey -algorithm ed25519 -out "${name}.key"
chmod 600 "${name}.key"
openssl pkey -in "${name}.key" -outform DER | tail -c 32 > "${name}.seed"
chmod 600 "${name}.seed"
pub=$(openssl pkey -in "${name}.key" -pubout -outform DER | tail -c 32 | xxd -p -c 64)

echo "wrote ${name}.key  (private — keep secret)"
echo "wrote ${name}.seed (load via AJAR_SIGNING_SEED=${name}.seed)"
echo
echo "Send this to your Ajar operator to register (verifying_key_hex):"
echo "  ${pub}"
