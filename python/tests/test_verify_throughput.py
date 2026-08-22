# SPDX-License-Identifier: Apache-2.0
"""Verification is the egress hot path, so its speed is a tested property, not
a README claim: a change that makes it slow fails here rather than quietly
degrading a consumer."""
import os
import time

from ajar_connector import EventBuilder, SigningKey, canonical_bytes, seal, verify


def test_verify_throughput_is_hot_path_grade():
    key = SigningKey.from_seed(os.urandom(32))
    event = (
        EventBuilder("acme-radar-1", "mim:aircraft")
        .new_id()
        .timestamp("2026-06-10T08:00:00Z")
        .location(25.27, 51.52, 10600.0)
        .attribute("hostility", "Friend")
        .build()
    )
    sealed = seal(canonical_bytes(event), key)
    vk = key.verifying_key

    n = 2000
    start = time.perf_counter()
    for _ in range(n):
        verify(sealed, vk)
    per_sec = n / (time.perf_counter() - start)
    print(f"verify: {per_sec:.0f} envelopes/sec on one core")
    # Python rides cryptography's (OpenSSL) Ed25519; the floor is deliberately
    # modest so CI hardware variance never flakes, while a real regression —
    # accidental pure-Python fallback, per-call key re-parsing — still fails.
    assert per_sec > 500, f"verification unexpectedly slow: {per_sec:.0f}/sec"
