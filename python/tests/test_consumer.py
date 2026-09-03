# SPDX-License-Identifier: Apache-2.0
"""The consumer module: verification is unskippable, guards work, and the
wire test proves it against a real broker (required in CI, skipped locally
without nats-server - same policy as every wire gate)."""

import asyncio
import os
import shutil
import socket
import subprocess
import time

import pytest

from ajar_connector import EventBuilder, canonical_bytes, seal
from ajar_connector.consumer import ConsumerStats, consume
from ajar_connector.seal import SigningKey

EGRESS_SEED = bytes([0x55]) * 32


def sealed_event(source_id: str, payload: bytes, model: str | None = None) -> bytes:
    b = EventBuilder(source_id, "mim:vessel").new_id().now().payload(payload)
    if model:
        b = b.attribute("model", model)
    return seal(canonical_bytes(b.build()), SigningKey.from_seed(EGRESS_SEED))


def test_bad_keys_and_partial_tls_are_refused():
    async def collect(**kw):
        async for _ in consume("nats://x:1", subject="s", **kw):
            pass

    with pytest.raises(ValueError, match="32 bytes"):
        asyncio.run(collect(egress_verifying_key="abcd"))
    with pytest.raises(ValueError, match="partial TLS"):
        asyncio.run(
            collect(
                egress_verifying_key=SigningKey.from_seed(EGRESS_SEED).verifying_key.hex(),
                ca="/ca.pem",
            )
        )


def test_the_wire_loop_verifies_guards_and_counts():
    if not shutil.which("nats-server"):
        if os.environ.get("CI"):
            pytest.fail("nats-server is required in CI: the wire gate must run, not skip")
        pytest.skip("no nats-server binary")

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

        async def scenario():
            import nats

            pub = await nats.connect(f"nats://127.0.0.1:{port}")
            stats = ConsumerStats()
            got = []

            async def run_consumer():
                async for d in consume(
                    f"nats://127.0.0.1:{port}",
                    subject="ajar.egress.test.>",
                    egress_verifying_key=SigningKey.from_seed(EGRESS_SEED).verifying_key,
                    skip_source_ids={"me"},
                    skip_derived=True,
                    stats=stats,
                ):
                    got.append(d)
                    if len(got) == 2:
                        return

            task = asyncio.create_task(run_consumer())
            await asyncio.sleep(0.5)

            subj = "ajar.egress.test.x"
            # 1. valid -> yielded. 2. tampered -> rejected inside the loop.
            # 3. own source -> skipped. 4. derived (model attr) -> skipped.
            # 5. valid -> yielded (proves the loop survived all of the above).
            await pub.publish(subj, sealed_event("radar-1", b"payload-one"))
            tampered = bytearray(sealed_event("radar-1", b"evil"))
            tampered[-1] ^= 0xFF
            await pub.publish(subj, bytes(tampered))
            await pub.publish(subj, sealed_event("me", b"mine"))
            await pub.publish(subj, sealed_event("ai-1", b"derived", model="m@1"))
            await pub.publish(subj, sealed_event("radar-1", b"payload-two"))
            await pub.flush()

            await asyncio.wait_for(task, timeout=10)
            await pub.close()
            return stats, got

        stats, got = asyncio.run(scenario())
        assert [d.payload for d in got] == [b"payload-one", b"payload-two"]
        assert got[0].event.source_id == "radar-1"
        assert got[0].subject == "ajar.egress.test.x"
        assert stats.accepted == 2
        assert stats.rejected == 1, "the tampered event was refused inside the loop"
        assert stats.skipped == 2, "own + derived events never reached the caller"
    finally:
        proc.kill()
        proc.wait()
