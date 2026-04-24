"""HTTP response snapshots used by DomainIQ transports."""

from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping


def _decode_json_body(text: str) -> dict[str, Any] | list[Any]:
    decoded = _json.loads(text)
    if isinstance(decoded, (dict, list)):
        return decoded
    msg = f"Expected JSON object or array, got {type(decoded).__name__}"
    raise ValueError(msg)


@dataclass
class SyncResponse:
    """Snapshot of a synchronous HTTP response."""

    status_code: int
    headers: Mapping[str, str]
    text: str
    _json_data: dict[str, Any] | list[Any] | None = field(default=None, repr=False)

    def json(self) -> dict[str, Any] | list[Any]:
        if self._json_data is None:
            self._json_data = _decode_json_body(self.text)
        return self._json_data


@dataclass
class AsyncResponse:
    """Snapshot of an asynchronous HTTP response with body already read."""

    status: int
    headers: Mapping[str, str]
    _body: str
    _json_data: dict[str, Any] | list[Any] | None = field(default=None, repr=False)

    @property
    def status_code(self) -> int:
        return self.status

    @property
    def text(self) -> str:
        return self._body

    def json(self) -> dict[str, Any] | list[Any]:
        if self._json_data is None:
            self._json_data = _decode_json_body(self._body)
        return self._json_data


__all__ = ["AsyncResponse", "SyncResponse"]
