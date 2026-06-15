# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the builder, seal, and profile (run with pytest)."""

import pytest

from ajar_connector import (
    SEAL_SIGNATURE_LEN,
    BuildError,
    ConnectorProfile,
    EventBuilder,
    SigningKey,
    seal,
)


def test_builder_sorts_attributes_and_sets_defaults():
    e = (
        EventBuilder("sensor-1", "mim:drone")
        .new_id()
        .now()
        .attribute("speed", "110")
        .attribute("heading", "225")
        .build()
    )
    assert e.schema_version == "v1"
    assert e.received_at == ""
    assert [a.key for a in e.attributes] == ["heading", "speed"]


def test_builder_rejects_duplicate_attribute_keys():
    with pytest.raises(BuildError, match="duplicate attribute key"):
        EventBuilder("sensor-1", "mim:drone").new_id().now().attribute(
            "heading", "225"
        ).attribute("heading", "226").build()


def test_builder_requires_id_and_timestamp():
    with pytest.raises(BuildError, match="missing required field: id"):
        EventBuilder("sensor-1", "mim:drone").build()


def test_builder_rejects_out_of_range_confidence():
    with pytest.raises(BuildError, match="confidence"):
        EventBuilder("sensor-1", "mim:drone").new_id().now().confidence(1.5).build()


def test_builder_enforces_namespacing_with_opt_out():
    with pytest.raises(BuildError, match="not namespaced"):
        EventBuilder("sensor-1", "drone").new_id().now().build()
    # opt-out builds fine
    EventBuilder("sensor-1", "drone").new_id().now().allow_unnamespaced_entity_type().build()


def test_seal_layout():
    key = SigningKey.from_seed(bytes([0x47]) * 32)
    canonical = b"hello ajar"
    sealed = seal(canonical, key)
    assert len(sealed) == SEAL_SIGNATURE_LEN + len(canonical)
    assert sealed[SEAL_SIGNATURE_LEN:] == canonical


def test_profile_json_serializes_verifying_key_as_hex():
    vk = SigningKey.from_seed(bytes([0x47]) * 32).verifying_key
    profile = (
        ConnectorProfile("sensor-123", vk)
        .allow_entity_type("mim:drone")
        .rate_limit(50, 5.0)
    )
    js = profile.to_json()
    assert '"source_id":"sensor-123"' in js
    assert "mim:drone" in js
    assert vk.hex() in js
    assert '"rate_refill_per_sec":5.0' in js  # float keeps the .0, like the other SDKs
