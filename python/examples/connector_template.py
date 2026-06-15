# SPDX-License-Identifier: Apache-2.0
"""Connector template — your starting point (Python).

Copy this file, edit the ONE function marked `EDIT` below, and you have a
working connector. Everything else is done for you.

See a sealed event right now — no key, no NATS, no feed:

    echo '{"lat":26.4,"lon":50.9,"alt_m":11000,"quality":0.9}' \\
      | python examples/connector_template.py --dry-run

Then run for real (key from scripts/gen-connector-key.sh):

    AJAR_SIGNING_SEED=connector.seed AJAR_SOURCE_ID=acme-radar-1 \\
    NATS_URL=nats://nats.you.mil:4222  python examples/connector_template.py
"""

import asyncio
import json
import os
import sys

from ajar_connector import EventBuilder, SigningKey, canonical_bytes, seal
from ajar_connector.event_pb2 import Event


# ┌───────────────────────────────────────────────────────────────────────────┐
# │ EDIT — map one record from your feed into a canonical Event.               │
# │ `r` is one JSON object from your feed (change the fields to match yours).  │
# │ Use the entity_type Ajar assigned you. Add .attribute(k, v) only for       │
# │ attributes your entity type's ontology schema defines.                     │
# └───────────────────────────────────────────────────────────────────────────┘
def to_event(source_id: str, r: dict) -> Event:
    return (
        EventBuilder(source_id, "mim:aircraft")
        .new_id()
        .now()
        .location(r["lat"], r["lon"], r["alt_m"])
        .confidence(r["quality"])
        .build()
    )


# ─────────────────────────────────────────────────────────────────────────────
# You usually don't need to touch anything below this line.
# ─────────────────────────────────────────────────────────────────────────────


def _load_seed(dry_run: bool) -> bytes:
    path = os.environ.get("AJAR_SIGNING_SEED")
    if path:
        seed = open(path, "rb").read()
        if len(seed) != 32:
            raise SystemExit("AJAR_SIGNING_SEED file must be exactly 32 bytes")
        return seed
    if dry_run:
        print("[connector] no AJAR_SIGNING_SEED set — using a DEV seed (dry-run only)", file=sys.stderr)
        return bytes([0x03]) * 32
    raise SystemExit("set AJAR_SIGNING_SEED to your 32-byte key file (see scripts/gen-connector-key.sh)")


async def main() -> None:
    dry_run = "--dry-run" in sys.argv
    source_id = os.environ.get("AJAR_SOURCE_ID", "demo-connector")
    prefix = os.environ.get("AJAR_INGEST_PREFIX", "ajar.ingest")
    nats_url = os.environ.get("NATS_URL", "nats://127.0.0.1:4222")
    subject = f"{prefix}.{source_id}"
    key = SigningKey.from_seed(_load_seed(dry_run))

    nc = None
    if dry_run:
        print("[connector] --dry-run: building + sealing, not publishing", file=sys.stderr)
    else:
        import nats  # transport dep — only needed for a real run

        print(f"[connector] connecting to NATS at {nats_url}", file=sys.stderr)
        nc = await nats.connect(nats_url)
    print(f"[connector] source_id={source_id}  subject={subject}", file=sys.stderr)

    # Your feed: by default, newline-delimited JSON on stdin. Swap this loop for
    # your TCP socket / file / API / serial port — the rest stays the same.
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)  # parse one record
        event = to_event(source_id, record)  # EDIT maps it
        canonical = canonical_bytes(event)
        sealed = seal(canonical, key)  # sign it
        if nc is not None:
            await nc.publish(subject, sealed)  # publish it
        tag = "" if nc is not None else "  [dry-run]"
        print(f"{event.id} -> {subject} ({len(sealed)} sealed bytes){tag}")

    if nc is not None:
        await nc.flush()
        await nc.close()


if __name__ == "__main__":
    asyncio.run(main())
