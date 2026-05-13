from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict


MAX_FRAME_BYTES = 1024 * 1024


class ProtocolError(Exception):
    """Raised for invalid protocol frames."""


@dataclass(frozen=True)
class Frame:
    kind: str
    payload: Dict[str, Any]

    def to_json_line(self) -> bytes:
        data = {"type": self.kind, **self.payload}
        encoded = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_FRAME_BYTES:
            raise ProtocolError("frame too large")
        return encoded + b"\n"


def parse_json_line(line: bytes) -> Frame:
    if len(line) > MAX_FRAME_BYTES:
        raise ProtocolError("frame too large")
    try:
        obj = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid json") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("json object required")
    kind = obj.get("type")
    if not isinstance(kind, str) or not kind:
        raise ProtocolError("missing frame type")
    payload = {k: v for k, v in obj.items() if k != "type"}
    return Frame(kind=kind, payload=payload)


def read_line_limited(reader) -> bytes:
    line = reader.readline(MAX_FRAME_BYTES + 1)
    if not line:
        raise EOFError("connection closed")
    if len(line) > MAX_FRAME_BYTES:
        raise ProtocolError("frame too large")
    if not line.endswith(b"\n"):
        raise ProtocolError("unterminated frame")
    return line[:-1]
