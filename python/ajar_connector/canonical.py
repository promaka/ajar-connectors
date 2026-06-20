# SPDX-License-Identifier: Apache-2.0
"""Canonical byte encoding of an Event."""

from .event_pb2 import Event


def canonical_bytes(event: Event) -> bytes:
    """Return the canonical protobuf encoding of ``event``.

    ``deterministic=True`` gives ascending tag order with proto3 defaults
    omitted and map keys sorted (the contract has no maps) — the same wire
    shape prost (Rust), Go, libprotobuf, and nanopb produce. The caller owns
    the attribute invariant (sorted by key, unique); EventBuilder guarantees it.
    """
    return event.SerializeToString(deterministic=True)
