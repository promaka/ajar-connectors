# SPDX-License-Identifier: Apache-2.0
"""Synthetic radar (Python): stream synthetic mim:aircraft tracks into a local
Ajar Core so a developer can watch connector -> NATS -> Core -> audit + Postgres.

The shape every connector follows is the three steps in the loop:
  1. normalize a native observation into a canonical Event (here synthesised),
  2. seal it (detached Ed25519 signature ++ canonical bytes),
  3. publish the sealed bytes to the connector's NATS ingest subject.

Clearly-marked example: dev-only signing seed + a transport (NATS via nats-py).
The ajar_connector package stays transport-free — the NATS client is an example
dependency (`pip install -e ".[examples]"`).

Run:
  python examples/synthetic_radar.py --dry-run            # build+seal+print
  python examples/synthetic_radar.py --dry-run --ticks 3  # bounded (CI)
  python examples/synthetic_radar.py                      # publish to NATS

Env overrides: NATS_URL, AJAR_SOURCE_ID, AJAR_INGEST_PREFIX.
"""

import asyncio
import math
import os
import sys

from ajar_connector import EventBuilder, SigningKey, canonical_bytes, ingest_headers, seal, ingest_headers

def load_seed():
    """AJAR_SIGNING_SEED names a 32-byte seed file (the demo stack mints one);
    unset, an ephemeral throwaway key is minted for this run. No fixed key value
    exists in this repository, so an unset seed signs events only a registry
    that has never seen the key would refuse — which is the honest default."""
    path = os.environ.get("AJAR_SIGNING_SEED")
    if path:
        seed = open(path, "rb").read()
        if len(seed) != 32:
            raise SystemExit("AJAR_SIGNING_SEED file must be exactly 32 bytes")
        return seed
    print("[synthetic-radar] no AJAR_SIGNING_SEED — ephemeral throwaway key", file=sys.stderr)
    return os.urandom(32)


class Track:
    """A synthetic aircraft moving over the Gulf region. heading in radians."""

    def __init__(self, label, lat, lon, alt_m, heading, speed_deg):
        self.label, self.lat, self.lon = label, lat, lon
        self.alt_m, self.heading, self.speed_deg = alt_m, heading, speed_deg

    def advance(self):
        self.lat += math.cos(self.heading) * self.speed_deg
        self.lon += math.sin(self.heading) * self.speed_deg
        if self.lat < 25.0 or self.lat > 28.0:  # region lat [25, 28]
            self.heading = -self.heading
            self.lat = max(25.0, min(28.0, self.lat))
        if self.lon < 49.0 or self.lon > 52.0:  # region lon [49, 52]
            self.heading = math.pi - self.heading
            self.lon = max(49.0, min(52.0, self.lon))


def _arg_ticks() -> int:
    if "--ticks" in sys.argv:
        i = sys.argv.index("--ticks")
        if i + 1 < len(sys.argv):
            return int(sys.argv[i + 1])
    return 0


async def main() -> None:
    dry_run = "--dry-run" in sys.argv
    max_ticks = _arg_ticks()
    source_id = os.environ.get("AJAR_SOURCE_ID", "demo-connector")
    prefix = os.environ.get("AJAR_INGEST_PREFIX", "ajar.ingest")
    nats_url = os.environ.get("NATS_URL", "nats://127.0.0.1:4222")
    subject = f"{prefix}.{source_id}"
    key = SigningKey.from_seed(load_seed())

    nc = None
    if dry_run:
        print("[synthetic-radar] --dry-run: building + sealing, not publishing", file=sys.stderr)
    else:
        import nats

        print(f"[synthetic-radar] connecting to NATS at {nats_url}", file=sys.stderr)
        nc = await nats.connect(nats_url)
    print(f"[synthetic-radar] source_id={source_id}  subject={subject}", file=sys.stderr)

    tracks = [
        Track("AJX-01", 26.4, 50.9, 11000, 0.3 * math.pi, 0.012),
        Track("AJX-02", 25.6, 51.4, 9500, 1.1 * math.pi, 0.009),
        Track("AJX-03", 27.2, 49.7, 12500, 1.7 * math.pi, 0.015),
    ]

    tick = 0
    while True:
        for t in tracks:
            t.advance()
            # 1. normalize (synthesised) — no attributes: seed mim:aircraft has
            #    no attribute schema, so any attribute is rejected.
            event = (
                EventBuilder(source_id, "mim:aircraft")
                .new_id()
                .now()
                .location(t.lat, t.lon, t.alt_m)
                .confidence(0.9)
                .policy_tag("air-defence")
                .build()
            )
            # 2. seal, 3. publish
            sealed = seal(canonical_bytes(event), key)
            if nc is not None:
                # Nats-Msg-Id = event id: the broker's duplicate window drops
                # retransmissions keyed on it.
                await nc.publish(subject, sealed,
                                 headers=ingest_headers(event))
            tag = "" if nc is not None else "  [dry-run]"
            print(f"{event.id} {t.label:>6}  lat={t.lat:8.4f} lon={t.lon:8.4f} "
                  f"alt={t.alt_m:7.0f}m  -> {subject} ({len(sealed)} sealed bytes){tag}")

        if nc is not None:
            await nc.flush()
        tick += 1
        if max_ticks and tick >= max_ticks:
            break
        await asyncio.sleep(1)

    if nc is not None:
        await nc.close()


if __name__ == "__main__":
    asyncio.run(main())
