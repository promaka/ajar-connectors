# SPDX-License-Identifier: Apache-2.0
"""Publish derived events (AI assessments) back into Ajar, ready to embed.

An analytics or AI platform that consumes governed events and produces
assessments publishes those assessments back through the same front door as
any sensor: built with the SDK, sealed with the platform's own key, one event
per assessment. This module is the drop-in producer half: import it, call
:func:`connect` once, then :func:`publish_assessment` from your existing
pipeline.

Lineage is not optional. A derived event must say what it was derived from
(``derived_from``: the ids of the events you reasoned over) and what derived
it (``model``, e.g. ``"assessment-engine@1.4"``); the boundary refuses
derived events without them, so this module refuses them client-side first,
with a clearer message than the wire will give you.

Requires the ``producer`` extra for the transport::

    pip install "ajar-connector[producer]"

The sealed envelope is the SDK's :func:`~ajar_connector.seal` output,
byte-identical to any connector's, and every publish carries the
``Nats-Msg-Id`` header so broker-side deduplication works.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Mapping, Sequence

from . import EventBuilder, SigningKey, canonical_bytes, ingest_headers, seal


@dataclass
class Producer:
    """A connected producer: the NATS client plus the platform's identity."""

    nc: object
    key: SigningKey
    source_id: str
    subject: str


async def connect(
    nats_url: str,
    *,
    source_id: str,
    signing_seed: str | bytes,
    ca: str | None = None,
    cert: str | None = None,
    key: str | None = None,
    subject_prefix: str = "ajar.ingest",
) -> Producer:
    """Connect to the operator's endpoint and return a producer handle.

    ``signing_seed`` is the path to your registered 32-byte Ed25519 seed
    (raw bytes or 64-char hex), or the raw 32 bytes themselves. ``ca``,
    ``cert`` and ``key`` are the mTLS PEM paths from your operator; pass all
    three or none (a partial TLS setup is refused rather than guessed at,
    matching the connectors' fail-closed policy).
    """
    try:
        import nats  # transport dep: pip install "ajar-connector[producer]"
    except ImportError as e:  # pragma: no cover - import guidance only
        raise ImportError(
            'the producer needs the NATS client: pip install "ajar-connector[producer]"'
        ) from e

    if isinstance(signing_seed, bytes):
        seed = signing_seed
    else:
        raw = open(signing_seed, "rb").read()
        seed = raw if len(raw) == 32 else bytes.fromhex(raw.decode().strip())
    if len(seed) != 32:
        raise ValueError(
            f"signing_seed must be exactly 32 bytes (raw or 64-char hex), got {len(seed)}"
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

    nc = await (nats.connect(nats_url, tls=ctx) if ctx else nats.connect(nats_url))
    return Producer(
        nc=nc,
        key=SigningKey.from_seed(seed),
        source_id=source_id,
        subject=f"{subject_prefix}.{source_id}",
    )


async def publish_assessment(
    handle: Producer,
    *,
    entity_type: str,
    model: str,
    derived_from: Sequence[str],
    attributes: Mapping[str, str] | None = None,
    location: tuple[float, float, float] | None = None,
    policy_tags: Sequence[str] | None = None,
    confidence: float | None = None,
    metadata: Mapping[str, str] | None = None,
) -> str:
    """Seal and publish one assessment; returns the new event's id.

    ``derived_from`` must name at least one source event id (the events your
    model reasoned over) and ``model`` identifies what produced the
    assessment, ``name@version``. Both are required: the boundary refuses
    derived events without lineage, so forgetting them is an error here, not
    a silent drop there.
    """
    if not model or not model.strip():
        raise ValueError("model is required: name the system that produced this, e.g. 'engine@1.0'")
    parents = [p for p in derived_from if p and p.strip()]
    if not parents:
        raise ValueError(
            "derived_from is required and must name at least one source event id: "
            "the ids of the governed events this assessment was derived from "
            "(event.id on what you consumed)"
        )

    reserved = {"derived_from", "model"} & set(attributes or {})
    if reserved:
        raise ValueError(
            f"attributes {sorted(reserved)} are reserved for lineage; pass them via the "
            "model and derived_from arguments"
        )

    builder = EventBuilder(handle.source_id, entity_type).new_id().now()
    for k, v in _lineage_entries(model, parents):
        builder = builder.attribute(k, v)
    if location is not None:
        builder = builder.location(*location)
    if confidence is not None:
        builder = builder.confidence(confidence)
    for tag in policy_tags or ():
        builder = builder.policy_tag(tag)
    for k in sorted(attributes or {}):
        builder = builder.attribute(k, attributes[k])
    for k in sorted(metadata or {}):
        builder = builder.metadata(k, metadata[k])

    event = builder.build()
    sealed = seal(canonical_bytes(event), handle.key)
    await handle.nc.publish(handle.subject, sealed, headers=ingest_headers(event))
    return event.id


async def close(handle: Producer) -> None:
    """Flush and close the connection (call on your platform's shutdown)."""
    await handle.nc.flush()
    await handle.nc.close()


def _lineage_entries(model: str, parents: Sequence[str]) -> list[tuple[str, str]]:
    """The wire encoding of lineage, in one place, per the boundary contract.

    Lineage rides as ATTRIBUTES (not metadata): a derived_from entry with the
    parent ids comma-separated (the boundary splits on ','), and a model
    entry. The builder keeps attributes sorted and unique, as the canonical
    encoding requires.
    """
    return [
        ("derived_from", ",".join(parents)),
        ("model", model.strip()),
    ]
