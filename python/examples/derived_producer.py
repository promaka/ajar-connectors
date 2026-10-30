# SPDX-License-Identifier: Apache-2.0
"""Derived producer: consume governed events, assess them, publish the assessments back.

Each assessment names the event it was derived from in ``derived_from``. Needs the
``producer`` and ``consumer`` extras and AJAR_EGRESS_PUBKEY set to the egress key (hex).

    python examples/derived_producer.py \\
        --nats tls://nats.operator.example:4443 \\
        --source-id assess-1 --seed ./assess-1.seed \\
        --consume "ajar.egress.signed.>"

For mTLS also pass --ca, --cert and --key, the PEMs your operator issued.
"""

import argparse
import asyncio
import os
import sys

from ajar_connector.consumer import consume
from ajar_connector.producer import close, connect, publish_assessment

MODEL = "example-assessor@0.1"


def assess(event: event_pb2.Event) -> dict[str, str] | None:
    """Return attributes for an assessment of ``event``, or None to skip it.

    EDIT: call your model here; this stand-in flags fast vessels.
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

    producer = await connect(
        args.nats,
        source_id=args.source_id,
        signing_seed=args.seed,
        ca=args.ca,
        cert=args.cert,
        key=args.key,
    )
    print(f"[derived-producer] consuming {args.consume}, publishing as {args.source_id}",
          file=sys.stderr)

    # 1. Consume: every event yielded has verified under the egress key. The skip guards
    # keep the loop from assessing its own or any model's output.
    async for delivery in consume(
        args.nats,
        subject=args.consume,
        egress_verifying_key=egress_key,
        ca=args.ca,
        cert=args.cert,
        key=args.key,
        skip_source_ids={args.source_id},
        skip_derived=True,
    ):
        source_event = delivery.event

        # 2. Derive: run your model over the governed event.
        assessment = assess(source_event)
        if assessment is None:
            continue

        # 3. Publish: this call is what your platform adds.
        event_id = await publish_assessment(
            producer,
            entity_type=source_event.entity_type,
            model=MODEL,
            derived_from=[source_event.id],
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
