# SPDX-License-Identifier: Apache-2.0
"""The derived-events producer: lineage is mandatory, the envelope is the
SDK's seal byte-for-byte, and every publish carries the dedupe header.

The wire test runs against a real nats-server when one is on PATH (CI
installs it; the test fails rather than skips there, because a silently
skipped gate is no gate).
"""

import asyncio
import os
import shutil
import socket
import subprocess
import time

import pytest

from ajar_connector import event_pb2, verify
from ajar_connector.producer import Producer, close, connect, publish_assessment
from ajar_connector.seal import SigningKey

SEED = bytes([0x42]) * 32


class FakeNats:
    """Captures publishes; no broker needed for the shape tests."""

    def __init__(self):
        self.published = []

    async def publish(self, subject, payload, headers=None):
        self.published.append((subject, payload, headers))


def handle(nc=None):
    return Producer(
        nc=nc or FakeNats(),
        key=SigningKey.from_seed(SEED),
        source_id="assess-1",
        subject="ajar.ingest.assess-1",
    )


def test_lineage_is_required_not_optional():
    h = handle()
    with pytest.raises(ValueError, match="model is required"):
        asyncio.run(
            publish_assessment(h, entity_type="mim:vessel", model="  ", derived_from=["x"])
        )
    with pytest.raises(ValueError, match="derived_from is required"):
        asyncio.run(
            publish_assessment(h, entity_type="mim:vessel", model="m@1", derived_from=[])
        )
    with pytest.raises(ValueError, match="derived_from is required"):
        asyncio.run(
            publish_assessment(h, entity_type="mim:vessel", model="m@1", derived_from=["", " "])
        )
    with pytest.raises(ValueError, match="reserved for lineage"):
        asyncio.run(
            publish_assessment(
                h,
                entity_type="mim:vessel",
                model="m@1",
                derived_from=["x"],
                attributes={"model": "sneaky"},
            )
        )
    assert h.nc.published == [], "nothing may reach the wire without lineage"


def test_the_envelope_is_the_sdk_seal_with_lineage_and_dedupe_header():
    h = handle()
    event_id = asyncio.run(
        publish_assessment(
            h,
            entity_type="mim:vessel",
            model="assessment-engine@1.4",
            derived_from=["parent-b", "parent-a"],
            attributes={"threat_level": "High"},
            location=(54.5, 18.5, 0.0),
            confidence=0.87,
            policy_tags=["releasable:maritime"],
        )
    )
    (subject, payload, headers) = h.nc.published[0]
    assert subject == "ajar.ingest.assess-1"
    assert headers == {"Nats-Msg-Id": event_id}

    # The payload verifies under the producer's key and is a canonical Event.
    canonical = verify(payload, SigningKey.from_seed(SEED).verifying_key)
    event = event_pb2.Event()
    event.ParseFromString(canonical)
    assert event.id == event_id
    assert event.source_id == "assess-1"
    # Lineage rides as attributes, comma-separated parents, per the boundary
    # contract (a space-joined value would read as one malformed id).
    attrs = {a.key: a.value for a in event.attributes}
    assert attrs["model"] == "assessment-engine@1.4"
    assert attrs["derived_from"] == "parent-b,parent-a"
    assert attrs["threat_level"] == "High"
    # Canonical rules: attribute keys sorted and unique.
    keys = [a.key for a in event.attributes]
    assert keys == sorted(keys) and len(keys) == len(set(keys))


def test_partial_tls_and_bad_seeds_are_refused():
    with pytest.raises(ValueError, match="partial TLS"):
        asyncio.run(
            connect("nats://x:4222", source_id="s", signing_seed=SEED, ca="/ca.pem")
        )
    with pytest.raises(ValueError, match="32 bytes"):
        asyncio.run(connect("nats://x:4222", source_id="s", signing_seed=b"short"))


def test_a_real_broker_receives_the_assessment_intact():
    if not shutil.which("nats-server"):
        if os.environ.get("CI"):
            pytest.fail("nats-server is required in CI: the wire gate must run, not skip")
        pytest.skip("no nats-server binary (brew install nats-server)")

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(
        ["nats-server", "-p", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)

        async def roundtrip():
            import nats

            sub_nc = await nats.connect(f"nats://127.0.0.1:{port}")
            sub = await sub_nc.subscribe("ajar.ingest.assess-1")

            h = await connect(
                f"nats://127.0.0.1:{port}", source_id="assess-1", signing_seed=SEED
            )
            event_id = await publish_assessment(
                h,
                entity_type="mim:vessel",
                model="assessment-engine@1.4",
                derived_from=["0198aaaa-1111-7000-8000-000000000001"],
            )
            msg = await sub.next_msg(timeout=5)
            await close(h)
            await sub_nc.close()
            return event_id, msg

        event_id, msg = asyncio.run(roundtrip())
        assert msg.headers == {"Nats-Msg-Id": event_id}
        canonical = verify(msg.data, SigningKey.from_seed(SEED).verifying_key)
        event = event_pb2.Event()
        event.ParseFromString(canonical)
        assert event.id == event_id
        attrs = {a.key: a.value for a in event.attributes}
        assert attrs["derived_from"] == "0198aaaa-1111-7000-8000-000000000001"
        assert attrs["model"] == "assessment-engine@1.4"
    finally:
        proc.kill()
        proc.wait()
