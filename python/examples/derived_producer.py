# SPDX-License-Identifier: Apache-2.0
"""Consume governed events, derive an assessment, publish it back — end to end.

THE SNIPPET TO COPY is the publish_assessment() call at the bottom: that is
the only code your platform adds. The lineage wiring is the point: the ids of
the events your model reasoned over go into derived_from, and the boundary
refuses derived events without them. Everything else is the same three SDK
calls every connector makes.

Run against a live deployment:

    pip install "ajar-connector[producer]"
    export AJAR_EGRESS_PUBKEY=...   # Core's egress verifying key, hex, from your operator
    python examples/derived_producer.py \
        --nats tls://nats.operator.example:4443 \
        --source-id assess-1 --seed ./assess-1.seed \
        --consume "ajar.egress.geojson.>"

(mTLS: also pass --ca/--cert/--key, the PEMs your operator issued.)
"""

import argparse
import asyncio
import os
import sys

from ajar_connector import event_pb2, verify
from ajar_connector.producer import close, connect, publish_assessment

MODEL = "example-assessor@0.1"


def assess(event: event_pb2.Event) -> dict[str, str] | None:
    """YOUR MODEL GOES HERE. Returns governed attributes, or None to skip.

    This stand-in flags fast vessels; a real platform calls its inference
    pipeline instead. The contract is the same either way: whatever you
    return rides as governed attributes on a NEW event that names its
    sources.
    """
    attrs = {a.key: a.value for a in event.attributes}
    try:
        speed = float(attrs.get("speed", ""))
    except ValueError:
        return None
    if speed < 15.0:
        return None
    return {"threat_level": "Medium", "assessment_basis": "speed_anomaly"}


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nats", required=True)
    ap.add_argument("--source-id", required=True, help="your registered producer identity")
    ap.add_argument("--seed", required=True, help="path to your 32-byte signing seed")
    ap.add_argument("--consume", required=True, help="egress subject to consume")
    ap.add_argument("--ca")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    args = ap.parse_args()

    egress_key = bytes.fromhex(os.environ["AJAR_EGRESS_PUBKEY"])

    # One connection serves both directions.
    producer = await connect(
        args.nats,
        source_id=args.source_id,
        signing_seed=args.seed,
        ca=args.ca,
        cert=args.cert,
        key=args.key,
    )
    sub = await producer.nc.subscribe(args.consume)
    print(f"[derived-producer] consuming {args.consume}, publishing as {args.source_id}",
          file=sys.stderr)

    async for msg in sub.messages:
        # 1. CONSUME: verify Core's egress signature, decode the event.
        try:
            canonical = verify(msg.data, egress_key)
        except Exception as e:  # noqa: BLE001 - an unverifiable event is logged, never used
            print(f"[derived-producer] skip: does not verify: {e}", file=sys.stderr)
            continue
        source_event = event_pb2.Event()
        source_event.ParseFromString(canonical)

        # Never assess your own assessments: your events come back out of
        # egress too, and without this guard the loop feeds itself forever.
        if source_event.source_id == args.source_id or any(
            a.key == "model" for a in source_event.attributes
        ):
            continue

        # 2. DERIVE: run your model over the governed event.
        assessment = assess(source_event)
        if assessment is None:
            continue

        # 3. PUBLISH: a new event that names what it was derived from.
        #    >>> This call is the integration; everything else is plumbing. <<<
        event_id = await publish_assessment(
            producer,
            entity_type=source_event.entity_type,
            model=MODEL,
            derived_from=[source_event.id],  # the lineage: the event(s) you reasoned over
            attributes=assessment,
            location=(
                source_event.location.latitude,
                source_event.location.longitude,
                source_event.location.altitude_m,
            ),
            confidence=0.7,
            policy_tags=list(source_event.policy_tags),
        )
        print(f"[derived-producer] {event_id} derived_from {source_event.id}", file=sys.stderr)

    await close(producer)


if __name__ == "__main__":
    asyncio.run(main())
