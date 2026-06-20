# SPDX-License-Identifier: Apache-2.0
"""Ergonomic, fail-closed construction of canonical Events."""

import os
import time
from datetime import datetime, timezone

from .event_pb2 import Event

MAX_ATTRIBUTES = 128
MAX_POLICY_TAGS = 64
_SCHEMA_VERSION = "v1"


class BuildError(Exception):
    """Raised when a canonical invariant or required field is violated."""


def _uuid7() -> str:
    """A UUIDv7 string (48-bit ms timestamp + random), dependency-free."""
    b = bytearray(os.urandom(16))
    ms = int(time.time() * 1000)
    b[0] = (ms >> 40) & 0xFF
    b[1] = (ms >> 32) & 0xFF
    b[2] = (ms >> 24) & 0xFF
    b[3] = (ms >> 16) & 0xFF
    b[4] = (ms >> 8) & 0xFF
    b[5] = ms & 0xFF
    b[6] = (b[6] & 0x0F) | 0x70  # version 7
    b[8] = (b[8] & 0x3F) | 0x80  # RFC 4122 variant
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _is_namespaced(entity_type: str) -> bool:
    """True if entity_type is mim:<type> or x:<vendor>:<type>."""
    if entity_type.startswith("mim:"):
        rest = entity_type[4:]
        return bool(rest) and ":" not in rest
    if entity_type.startswith("x:"):
        parts = entity_type[2:].split(":")
        return len(parts) == 2 and all(parts)
    return False


class EventBuilder:
    """Builds a canonical Event. Auto-sorts attributes, rejects duplicate keys,
    enforces required fields and limits, offers UUIDv7 / RFC 3339 helpers.
    ``received_at`` is intentionally not exposed — Ajar stamps its own clock.
    """

    def __init__(self, source_id: str, entity_type: str) -> None:
        self._source_id = source_id
        self._entity_type = entity_type
        self._id: str | None = None
        self._timestamp: str | None = None
        self._location: tuple[float, float, float] | None = None
        self._payload = b""
        self._policy_tags: list[str] = []
        self._confidence = 0.0
        self._attributes: list[tuple[str, str]] = []
        self._strict_entity_namespace = True

    def id(self, value: str) -> "EventBuilder":
        self._id = value
        return self

    def new_id(self) -> "EventBuilder":
        self._id = _uuid7()
        return self

    def timestamp(self, ts: str) -> "EventBuilder":
        self._timestamp = ts
        return self

    def now(self) -> "EventBuilder":
        self._timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return self

    def location(self, latitude: float, longitude: float, altitude_m: float) -> "EventBuilder":
        self._location = (latitude, longitude, altitude_m)
        return self

    def payload(self, data: bytes) -> "EventBuilder":
        self._payload = data
        return self

    def policy_tag(self, tag: str) -> "EventBuilder":
        self._policy_tags.append(tag)
        return self

    def confidence(self, confidence: float) -> "EventBuilder":
        self._confidence = confidence
        return self

    def attribute(self, key: str, value: str) -> "EventBuilder":
        self._attributes.append((key, value))
        return self

    def allow_unnamespaced_entity_type(self) -> "EventBuilder":
        self._strict_entity_namespace = False
        return self

    def build(self) -> Event:
        """Validate invariants and produce the canonical Event."""
        if not self._id:
            raise BuildError("missing required field: id")
        if not self._timestamp:
            raise BuildError("missing required field: timestamp")
        if not self._source_id:
            raise BuildError("missing required field: source_id")
        if not self._entity_type:
            raise BuildError("missing required field: entity_type")
        if self._strict_entity_namespace and not _is_namespaced(self._entity_type):
            raise BuildError(
                f"entity_type {self._entity_type!r} is not namespaced as "
                "mim:<type> or x:<vendor>:<type>"
            )
        if not (0.0 <= self._confidence <= 1.0):
            raise BuildError(f"confidence {self._confidence} is outside [0.0, 1.0]")
        if len(self._policy_tags) > MAX_POLICY_TAGS:
            raise BuildError(f"too many policy tags: {len(self._policy_tags)} (max {MAX_POLICY_TAGS})")
        if len(self._attributes) > MAX_ATTRIBUTES:
            raise BuildError(f"too many attributes: {len(self._attributes)} (max {MAX_ATTRIBUTES})")

        # Canonical rule: attributes sorted by key, unique.
        attrs = sorted(self._attributes, key=lambda kv: kv[0])
        for i in range(1, len(attrs)):
            if attrs[i][0] == attrs[i - 1][0]:
                raise BuildError(f"duplicate attribute key: {attrs[i][0]!r}")

        event = Event()
        event.schema_version = _SCHEMA_VERSION
        event.id = self._id
        event.source_id = self._source_id
        event.entity_type = self._entity_type
        event.timestamp = self._timestamp
        # received_at intentionally left empty — Ajar stamps its own clock.
        if self._location is not None:
            event.location.latitude = self._location[0]
            event.location.longitude = self._location[1]
            event.location.altitude_m = self._location[2]
        event.payload = self._payload
        event.policy_tags.extend(self._policy_tags)
        event.confidence = self._confidence
        for key, value in attrs:
            event.attributes.add(key=key, value=value)
        return event
