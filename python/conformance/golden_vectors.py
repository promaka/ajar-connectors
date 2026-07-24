# SPDX-License-Identifier: Apache-2.0
"""THE gate (Python): for every corpus fixture, reproduce the same
canonicalSha256 + sealedSha256 the Rust/Go/C++ SDKs do, from the SAME
vendor/contract/vectors.json. Exit 0 iff all hashes match.

Run:  python conformance/golden_vectors.py   (from the python/ dir)
"""

import base64
import hashlib
import json
import pathlib
import sys

from ajar_connector import SigningKey, canonical_bytes, seal
from ajar_connector.event_pb2 import Event

CONTRACT_DIR = pathlib.Path(__file__).resolve().parents[2] / "vendor" / "contract"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture_to_event(f: dict) -> Event:
    """Build a canonical Event from a corpus fixture, verbatim (including
    received_at, which a live connector leaves for Ajar to stamp) — bypassing
    EventBuilder so byte-exact replay uses the raw fixture values."""
    e = Event()
    e.schema_version = f["schemaVersion"]
    e.id = f["id"]
    e.source_id = f["sourceId"]
    e.entity_type = f["entityType"]
    e.timestamp = f["timestamp"]
    if "receivedAt" in f:
        e.received_at = f["receivedAt"]
    loc = f.get("location")
    if loc is not None:
        e.location.latitude = loc["latitude"]
        e.location.longitude = loc["longitude"]
        e.location.altitude_m = loc.get("altitudeM", 0.0)
    if f.get("payload"):
        e.payload = base64.b64decode(f["payload"])
    for tag in f.get("policyTags", []):
        e.policy_tags.append(tag)
    if "confidence" in f:
        e.confidence = f["confidence"]
    for attr in f.get("attributes", []):
        e.attributes.add(key=attr["key"], value=attr["value"])
    for entry in f.get("metadata", []):
        e.metadata.add(key=entry["key"], value=entry["value"])
    return e


def main() -> int:
    vectors = json.loads((CONTRACT_DIR / "vectors.json").read_text())
    seed = bytes.fromhex(vectors["signingSeedHex"])
    key = SigningKey.from_seed(seed)

    failures = 0

    # 1. verifying key derives from the TEST seed.
    got_vk = key.verifying_key.hex()
    if got_vk != vectors["verifyingKeyHex"]:
        print(f"FAIL verifying key: got {got_vk} want {vectors['verifyingKeyHex']}")
        failures += 1
    else:
        print("ok   verifying key derives from TEST seed")

    # 2. each fixture: canonical + sealed hashes.
    for name, expected in vectors["vectors"].items():
        fixture = json.loads((CONTRACT_DIR / "corpus" / f"{name}.json").read_text())
        event = fixture_to_event(fixture)

        got_canon = sha256_hex(canonical_bytes(event))
        got_sealed = sha256_hex(seal(canonical_bytes(event), key))

        if got_canon != expected["canonicalSha256"] or got_sealed != expected["sealedSha256"]:
            failures += 1
            print(f"FAIL {name}")
            print(f"  canonical got {got_canon}\n           want {expected['canonicalSha256']}")
            print(f"  sealed    got {got_sealed}\n           want {expected['sealedSha256']}")
        else:
            print(f"ok   {name}")

    if failures:
        print(f"\n{failures} conformance failure(s)")
        return 1
    print("\nall conformance vectors reproduced")
    return 0


if __name__ == "__main__":
    sys.exit(main())
