# SPDX-License-Identifier: Apache-2.0
"""Consume governed egress events, yielding only those whose signature verifies.

One call subscribes to governed egress and yields events whose Ed25519 signature
verified under the deployment's egress key. An event that does not verify is counted
and dropped inside the loop, so your code never sees it.

Requires the ``consumer`` extra for the transport::

    pip install "ajar-connector[consumer]"

Usage::

    from ajar_connector.consumer import consume

    async for delivery in consume(
        "tls://nats.operator.example:4443",
        subject="ajar.egress.signed.>",
        egress_verifying_key="<64-hex from your operator>",
        ca="ca.pem", cert="client.pem", key="client.key",
    ):
        do_something(delivery.event)        # decoded, verified Event
        # delivery.payload is the rendered bytes (GeoJSON, CoT, ...)

A platform that also publishes assessments back passes
``skip_source_ids={"your-producer-id"}``, so its own published events, which come
back out of egress like everything else, are never fed to its model.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from typing import AsyncIterator, Iterable

from . import event_pb2, verify


@dataclass
class Delivery:
    """One verified governed event."""

    event: "event_pb2.Event"
    #: Rendered payload bytes (GeoJSON, CoT, native frame).
    payload: bytes
    #: NATS subject the event arrived on.
    subject: str


@dataclass
class ConsumerStats:
    """Counters updated as the consume iterator runs."""

    accepted: int = 0
    #: Events that failed signature verification and were dropped.
    rejected: int = 0
    #: Events dropped by ``skip_source_ids`` or ``skip_derived``.
    skipped: int = 0
    _last: str = field(default="", repr=False)


async def consume(
    nats_url: str,
    *,
    subject: str,
    egress_verifying_key: str | bytes,
    ca: str | None = None,
    cert: str | None = None,
    key: str | None = None,
    skip_source_ids: Iterable[str] = (),
    skip_derived: bool = False,
    stats: ConsumerStats | None = None,
) -> AsyncIterator[Delivery]:
    """Subscribe to ``subject`` and yield verified events until cancelled.

    ``egress_verifying_key`` is the deployment's egress verifying key from your
    operator: 64-char hex or the raw 32 bytes. ``ca``, ``cert`` and ``key`` are the mTLS
    PEM paths; pass all three or none, as a partial TLS setup is refused. ``skip_derived``
    drops events carrying a ``model`` attribute, meaning anything produced by an AI or
    analytics platform; ``skip_source_ids`` drops a deriving platform's own events.

    Pass a :class:`ConsumerStats` to watch accept and reject counts from outside the
    loop; each rejection also logs one warning.
    """
    try:
        import nats
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            'the consumer needs the NATS client: pip install "ajar-connector[consumer]"'
        ) from e

    if isinstance(egress_verifying_key, bytes):
        key_bytes = egress_verifying_key
    else:
        key_bytes = bytes.fromhex(egress_verifying_key.strip())
    if len(key_bytes) != 32:
        raise ValueError(
            f"egress_verifying_key must be 32 bytes (raw or 64-char hex), got {len(key_bytes)}"
        )

    tls_set = [p for p in (ca, cert, key) if p]
    if tls_set and len(tls_set) != 3:
        raise ValueError(
            "partial TLS configuration: pass all of ca, cert and key (the files "
            "your operator issued), or none for a local cleartext dev run"
        )
    ctx = None
    if len(tls_set) == 3:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=ca)
        ctx.load_cert_chain(certfile=cert, keyfile=key)

    skips = set(skip_source_ids)
    s = stats if stats is not None else ConsumerStats()

    nc = await (nats.connect(nats_url, tls=ctx) if ctx else nats.connect(nats_url))
    try:
        sub = await nc.subscribe(subject)
        async for msg in sub.messages:
            try:
                canonical = verify(msg.data, key_bytes)
            except Exception:  # noqa: BLE001 - refuse, count, continue
                s.rejected += 1
                import logging

                logging.getLogger(__name__).warning(
                    "rejected an event that does not verify under the egress key "
                    "(total rejected: %d)",
                    s.rejected,
                )
                continue
            event = event_pb2.Event()
            event.ParseFromString(canonical)
            if event.source_id in skips or (
                skip_derived and any(a.key == "model" for a in event.attributes)
            ):
                s.skipped += 1
                continue
            s.accepted += 1
            yield Delivery(event=event, payload=bytes(event.payload), subject=msg.subject)
    finally:
        await nc.close()
