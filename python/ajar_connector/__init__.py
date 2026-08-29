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
from .seal import SEAL_SIGNATURE_LEN, SealVerificationError, SigningKey, seal, verify

#: The NATS header the ingest broker dedupes on. Publish every sealed event
#: with this header set to the event's id; the broker drops retransmissions
#: keyed on it inside its duplicate window.
NATS_MSG_ID_HEADER = "Nats-Msg-Id"


def ingest_headers(event) -> dict:
    """The headers an ingest publish must carry for ``event``.

    The SDK has no transport dependency, so this returns a plain dict your
    NATS client passes through, e.g.::

        await nc.publish(subject, sealed, headers=ingest_headers(event))
    """
    return {NATS_MSG_ID_HEADER: event.id}


__all__ = [
    "NATS_MSG_ID_HEADER",
    "ingest_headers",
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
    "SealVerificationError",
    "SigningKey",
    "canonical_bytes",
    "seal",
    "verify",
]
