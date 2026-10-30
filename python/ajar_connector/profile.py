# SPDX-License-Identifier: Apache-2.0
"""Connector profile: the self-declaration a connector publishes."""

import json


class ConnectorProfile:
    """A connector's published profile, serialized byte-identical to the other SDKs."""

    def __init__(self, source_id: str, verifying_key: bytes) -> None:
        self.source_id = source_id
        self.allowed_entity_types: list[str] = []
        self.max_payload_bytes = 64 * 1024
        self.rate_capacity = 100
        self.rate_refill_per_sec = 10.0
        self.verifying_key = verifying_key

    def allow_entity_type(self, entity_type: str) -> "ConnectorProfile":
        """Add an entity type the connector may emit."""
        self.allowed_entity_types.append(entity_type)
        return self

    def with_max_payload_bytes(self, max_bytes: int) -> "ConnectorProfile":
        """Set the largest payload the connector may send."""
        self.max_payload_bytes = max_bytes
        return self

    def rate_limit(self, capacity: int, refill_per_sec: float) -> "ConnectorProfile":
        """Set the token-bucket capacity and refill rate."""
        self.rate_capacity = capacity
        self.rate_refill_per_sec = refill_per_sec
        return self

    def _wire(self) -> dict:
        return {
            "source_id": self.source_id,
            "allowed_entity_types": self.allowed_entity_types,
            "max_payload_bytes": self.max_payload_bytes,
            "rate_capacity": self.rate_capacity,
            "rate_refill_per_sec": self.rate_refill_per_sec,
            "verifying_key_hex": self.verifying_key.hex(),
        }

    def to_json(self) -> str:
        """Return the profile as compact JSON."""
        return json.dumps(self._wire(), separators=(",", ":"))

    def to_json_pretty(self) -> str:
        """Return the profile as indented JSON."""
        return json.dumps(self._wire(), indent=2)
