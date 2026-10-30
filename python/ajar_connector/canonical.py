# SPDX-License-Identifier: Apache-2.0
"""Canonical byte encoding of an Event."""

from .event_pb2 import Event


def canonical_bytes(event: Event) -> bytes:
    """Return the canonical protobuf encoding of ``event``.

    Attributes must already be sorted by key and unique, as EventBuilder makes them.
    """
    return event.SerializeToString(deterministic=True)
