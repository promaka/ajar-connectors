# SPDX-License-Identifier: Apache-2.0
"""ajar-connector: the Python SDK for building connectors to the Ajar integration plane.

Types come from the vendored ``event.proto`` shared with the Rust, Go and C++
SDKs; ``vendor/contract/vectors.json`` checks the output is byte-identical.
"""

from .builder import MAX_ATTRIBUTES, MAX_METADATA, MAX_POLICY_TAGS, BuildError, EventBuilder
from .canonical import canonical_bytes
from .connector import Connector, OutboundProfile
from .event_pb2 import Attribute, Event, GeoPoint
from .profile import ConnectorProfile
from .seal import SEAL_SIGNATURE_LEN, SealVerificationError, SigningKey, seal, verify

#: NATS header the ingest broker dedupes on. Publish every sealed event with this
#: header set to the event's id; the broker drops retransmissions keyed on it inside
#: its duplicate window.
NATS_MSG_ID_HEADER = "Nats-Msg-Id"


def ingest_headers(event) -> dict:
    """Return the NATS headers an ingest publish of ``event`` must carry.

    The SDK has no transport dependency, so this is a plain dict your NATS client
    passes through, e.g.::

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
