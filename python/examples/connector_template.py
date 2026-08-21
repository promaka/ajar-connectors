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

Production behaviour (built in, no edits needed):
- A malformed or un-mappable record is logged and skipped, never fatal.
- A NATS publish error is logged and the connector keeps going.
- Set AJAR_HEALTH_ADDR=0.0.0.0:9090 to expose GET /healthz (liveness) and
  GET /metrics (Prometheus counters: published / skipped / publish_errors).
"""

import asyncio
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from ajar_connector import EventBuilder, SigningKey, canonical_bytes, seal
from ajar_connector.event_pb2 import Event

# Process counters, surfaced at /metrics.
_METRICS = {"published": 0, "skipped": 0, "publish_errors": 0}


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


def _spawn_health() -> None:
    """Start a tiny health/metrics HTTP server if AJAR_HEALTH_ADDR is set
    (e.g. 0.0.0.0:9090). GET /healthz -> liveness; GET /metrics -> Prometheus
    text. Stdlib only — no impact unless you opt in."""
    addr = os.environ.get("AJAR_HEALTH_ADDR")
    if not addr:
        return
    host, _, port = addr.rpartition(":")

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path.startswith("/metrics"):
                body = (
                    "# TYPE ajar_connector_published_total counter\n"
                    f"ajar_connector_published_total {_METRICS['published']}\n"
                    "# TYPE ajar_connector_skipped_total counter\n"
                    f"ajar_connector_skipped_total {_METRICS['skipped']}\n"
                    "# TYPE ajar_connector_publish_errors_total counter\n"
                    f"ajar_connector_publish_errors_total {_METRICS['publish_errors']}\n"
                )
            else:
                body = "ok\n"
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):  # silence per-request logging
            pass

    server = HTTPServer((host or "0.0.0.0", int(port)), _Handler)
    print(f"[connector] health/metrics on http://{addr}/healthz and /metrics", file=sys.stderr)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def _nats_tls_opts() -> dict:
    """mTLS when AJAR_TLS_CA / AJAR_TLS_CERT / AJAR_TLS_KEY are all set (the
    production path — client-cert CN = source_id, mounted by the Helm chart under
    /etc/ajar/tls). Unset -> plaintext for local dev."""
    ca = os.environ.get("AJAR_TLS_CA")
    cert = os.environ.get("AJAR_TLS_CERT")
    key = os.environ.get("AJAR_TLS_KEY")
    if ca and cert and key:
        import ssl

        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        print("[connector] mTLS enabled (client cert = source identity)", file=sys.stderr)
        return {"tls": ctx}
    print("[connector] no AJAR_TLS_* set — connecting without TLS (dev only)", file=sys.stderr)
    return {}


def _load_seed(dry_run: bool) -> bytes:
    path = os.environ.get("AJAR_SIGNING_SEED")
    if path:
        seed = open(path, "rb").read()
        if len(seed) != 32:
            raise SystemExit("AJAR_SIGNING_SEED file must be exactly 32 bytes")
        return seed
    if dry_run:
        print("[connector] no AJAR_SIGNING_SEED set — ephemeral throwaway key (dry-run only)", file=sys.stderr)
        return os.urandom(32)
    raise SystemExit("set AJAR_SIGNING_SEED to your 32-byte key file (see scripts/gen-connector-key.sh)")


async def main() -> None:
    dry_run = "--dry-run" in sys.argv
    source_id = os.environ.get("AJAR_SOURCE_ID", "demo-connector")
    prefix = os.environ.get("AJAR_INGEST_PREFIX", "ajar.ingest")
    nats_url = os.environ.get("NATS_URL", "nats://127.0.0.1:4222")
    subject = f"{prefix}.{source_id}"
    key = SigningKey.from_seed(_load_seed(dry_run))

    _spawn_health()  # no-op unless AJAR_HEALTH_ADDR is set

    nc = None
    if dry_run:
        print("[connector] --dry-run: building + sealing, not publishing", file=sys.stderr)
    else:
        import nats  # transport dep — only needed for a real run

        print(f"[connector] connecting to NATS at {nats_url}", file=sys.stderr)
        nc = await nats.connect(nats_url, **_nats_tls_opts())
    print(f"[connector] source_id={source_id}  subject={subject}", file=sys.stderr)

    # Your feed: by default, newline-delimited JSON on stdin. Swap this loop for
    # your TCP socket / file / API / serial port — the rest stays the same.
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        # Resilient: a bad record is logged and skipped, never fatal.
        try:
            record = json.loads(line)  # parse one record
            event = to_event(source_id, record)  # EDIT maps it
        except Exception as e:  # noqa: BLE001 — one bad input must not kill the loop
            print(f"[connector] skip: bad record: {e}", file=sys.stderr)
            _METRICS["skipped"] += 1
            continue
        canonical = canonical_bytes(event)
        sealed = seal(canonical, key)  # sign it
        if nc is not None:
            try:
                await nc.publish(subject, sealed)  # publish it
            except Exception as e:  # noqa: BLE001 — keep running on a transport blip
                print(f"[connector] publish error (continuing): {e}", file=sys.stderr)
                _METRICS["publish_errors"] += 1
                continue
        _METRICS["published"] += 1
        tag = "" if nc is not None else "  [dry-run]"
        print(f"{event.id} -> {subject} ({len(sealed)} sealed bytes){tag}")

    if nc is not None:
        await nc.flush()
        await nc.close()


if __name__ == "__main__":
    asyncio.run(main())
