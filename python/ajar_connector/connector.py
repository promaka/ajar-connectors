# SPDX-License-Identifier: Apache-2.0
"""Connector interfaces: inbound normalization and outbound rendering."""

import abc

from .event_pb2 import Event


class Connector(abc.ABC):
    """An inbound connector: native bytes -> canonical Event.

    Implementations parse ``native`` (CoT XML, a CSV row, a vendor frame, ...)
    and return a fully-populated event, ideally via EventBuilder.
    """

    @abc.abstractmethod
    def normalize(self, native: bytes) -> Event:
        ...


class OutboundProfile(abc.ABC):
    """An outbound profile: render a governed Event into a target format.

    Its honesty is the modeled/lossy field declaration; round-trip conformance
    (canonical -> target -> canonical) checks the claim.
    """

    @abc.abstractmethod
    def target(self) -> str: ...

    @abc.abstractmethod
    def slug(self) -> str: ...

    @abc.abstractmethod
    def version(self) -> str: ...

    @abc.abstractmethod
    def modeled_fields(self) -> list[str]: ...

    @abc.abstractmethod
    def lossy_fields(self) -> list[str]: ...

    @abc.abstractmethod
    def render(self, event: Event) -> bytes: ...
