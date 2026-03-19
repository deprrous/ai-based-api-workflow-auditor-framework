from __future__ import annotations

import json
from typing import Any


def encode_sse(event: str, data: dict[str, Any]) -> str:
    payload = json.dumps(data, ensure_ascii=True, separators=(",", ":"))
    return f"event: {event}\ndata: {payload}\n\n"
