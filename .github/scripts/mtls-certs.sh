#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Mint a P-256 CA, server and client certificate for the mTLS gate, matching the
# profile a sovereign deployment uses: EC P-256, PKCS#8 keys, TLS 1.3, and a
# client certificate whose CN is mapped to a NATS user by verify_and_map.
set -euo pipefail
out="${1:?usage: mtls-certs.sh <outdir>}"
mkdir -p "$out" && cd "$out"

openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 1 -out ca.pem \
  -subj "/CN=ajar-ci-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

mint() { # <name> <subject> <ext>
  openssl ecparam -name prime256v1 -genkey -noout -out "$1.sec1"
  openssl pkcs8 -topk8 -nocrypt -in "$1.sec1" -out "$1.key"   # PKCS#8, not SEC1
  openssl req -new -key "$1.key" -out "$1.csr" -subj "$2"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 1 -sha256 -extfile <(printf '%s' "$3") -out "$1.pem"
  rm -f "$1.sec1" "$1.csr"
}

mint server "/CN=localhost" "subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth"
mint client "/CN=ajar-connector" "extendedKeyUsage=clientAuth"

head -1 client.key | grep -q "BEGIN PRIVATE KEY" \
  || { echo "client key is not PKCS#8"; exit 1; }

# openssl writes keys 0600 for the creating user. The connector images run as
# nonroot (uid 65532), so a key mounted straight from here is unreadable inside
# the container: the TLS config fails to build, locally and in under a
# millisecond, and the server logs nothing but an EOF. These are throwaway test
# certificates, so widen them. A real deployment mounts the key from a Secret
# whose ownership matches the runtime user instead.
chmod 0644 client.key server.key ca.key
echo "minted P-256 CA, server and client certificates in $out"
