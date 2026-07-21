# SPDX-License-Identifier: Apache-2.0
"""ajar-connector: the Python SDK for building byte-compatible connectors to the
Ajar integration plane.

Types are generated from the same vendored ``event.proto`` as the Rust, Go, and
C++ SDKs; canonical bytes are the deterministic protobuf encoding that gets
hashed and signed. The shared ``vendor/contract/vectors.json`` proves this
SDK's output is byte-identical to the others.
"""

from .builder import MAX_ATTRIBUTES, MAX_METADATA, MAX_POLICY_TAGS, BuildError, EventBuilder
from .canonical import canonical_bytes
from .connector import Connector, OutboundProfile
from .event_pb2 import Attribute, Event, GeoPoint
from .profile import ConnectorProfile
from .seal import SEAL_SIGNATURE_LEN, SigningKey, seal

__all__ = [
    "Attribute",
    "BuildError",
    "Connector",
    "ConnectorProfile",
    "Event",
    "EventBuilder",
    "GeoPoint",
    "MAX_ATTRIBUTES",
    "MAX_METADATA",
    "MAX_POLICY_TAGS",
    "OutboundProfile",
    "SEAL_SIGNATURE_LEN",
    "SigningKey",
    "canonical_bytes",
    "seal",
]
