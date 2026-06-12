# Vendored third-party crypto — provenance

The C++ SDK has no system crypto dependency: it vendors small, audited,
public-domain / permissively-licensed implementations used by **both** the
desktop and the embedded (nanopb, no-heap) builds. Each retains its upstream
licence; all are Apache-2.0 compatible.

## monocypher/ — Ed25519 (RFC 8032) + SHA-512

- Upstream:  https://monocypher.org  (github.com/LoupVaillant/Monocypher)
- Version:   4.0.2
- Licence:   dual 2-clause BSD / CC-0 (see monocypher/LICENCE.md)
- Files:     monocypher.{c,h}, optional/monocypher-ed25519.{c,h}
- Why:       constant-time, heap-free, embedded-grade. The optional
             `monocypher-ed25519` module is the RFC 8032 (SHA-512) variant, so
             it is byte-compatible with the Rust (ed25519-dalek) and Go
             (crypto/ed25519) SDKs. Provides `crypto_ed25519_key_pair` and
             `crypto_ed25519_sign` — the latter's output (sig||msg) is not used;
             we prefix the detached 64-byte signature ourselves per the seal spec.

## sha256/ — SHA-256

- Upstream:  github.com/B-Con/crypto-algorithms
- Licence:   public domain ("released into the public domain", per upstream)
- Files:     sha256.{c,h}
- Why:       tiny, heap-free SHA-256 for the conformance gate (hashing canonical
             and sealed bytes). Not used by the SDK proper — only the test.

Re-vendor by re-fetching the pinned versions above; do not edit in place.
