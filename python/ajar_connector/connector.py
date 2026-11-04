# SPDX-License-Identifier: Apache-2.0
"""Connector interfaces: inbound normalization and outbound rendering."""

import abc

from .event_pb2 import Event


class Connector(abc.ABC):
    """An inbound connector: native bytes to a canonical Event.

    Implementations parse ``native`` (CoT XML, a CSV row, a vendor frame) and return
    a fully populated event, ideally via EventBuilder.
    """

    @abc.abstractmethod
    def normalize(self, native: bytes) -> Event:
        """Parse one native frame into an Event."""


class OutboundProfile(abc.ABC):
    """An outbound profile: renders a governed Event into a target format.

    ``modeled_fields`` and ``lossy_fields`` state which canonical fields survive the
    translation; round-trip conformance (canonical -> target -> canonical) checks that.
    """

    @abc.abstractmethod
    def target(self) -> str:
        """Return the target format name."""

    @abc.abstractmethod
    def slug(self) -> str:
        """Return the profile slug."""

    @abc.abstractmethod
    def version(self) -> str:
        """Return the profile version."""

    @abc.abstractmethod
    def modeled_fields(self) -> list[str]:
        """Return the fields the target carries."""

    @abc.abstractmethod
    def lossy_fields(self) -> list[str]:
        """Return the fields the target drops or degrades."""

    @abc.abstractmethod
    def render(self, event: Event) -> bytes:
        """Render ``event`` in the target format."""
