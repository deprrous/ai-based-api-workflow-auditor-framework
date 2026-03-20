from __future__ import annotations

import base64
import json
from typing import Any


def _redacted_value(value: str) -> str:
    scheme, separator, remainder = value.partition(" ")
    if separator and remainder:
        return f"{scheme} [REDACTED]"
    return "[REDACTED]"


def redact_headers(headers: dict[str, str], sensitive_header_names: tuple[str, ...]) -> dict[str, str]:
    sensitive = {header.lower() for header in sensitive_header_names}
    redacted: dict[str, str] = {}

    for key, value in headers.items():
        lowered = key.lower()
        if lowered in sensitive:
            if lowered in {"cookie", "set-cookie"}:
                cookie_parts = [part.strip() for part in value.split(";") if part.strip()]
                redacted[key] = "; ".join(
                    f"{part.split('=', 1)[0]}=[REDACTED]" if "=" in part else "[REDACTED]"
                    for part in cookie_parts
                )
            else:
                redacted[key] = _redacted_value(value)
        else:
            redacted[key] = value

    return redacted


def _redact_json_value(value: Any, sensitive_keys: set[str]) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in sensitive_keys else _redact_json_value(item, sensitive_keys)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json_value(item, sensitive_keys) for item in value]
    return value


def build_body_preview(
    body_base64: str | None,
    *,
    content_type: str | None,
    sensitive_body_keys: tuple[str, ...],
    limit: int = 240,
) -> str | None:
    if not body_base64:
        return None

    try:
        raw_bytes = base64.b64decode(body_base64.encode("ascii"))
    except Exception:
        return "[UNREADABLE BODY]"

    if not raw_bytes:
        return None

    lowered_content_type = (content_type or "").lower()
    if "json" in lowered_content_type:
        try:
            parsed = json.loads(raw_bytes.decode("utf-8", errors="ignore"))
            redacted = _redact_json_value(parsed, {key.lower() for key in sensitive_body_keys})
            text = json.dumps(redacted, ensure_ascii=True, separators=(",", ":"))
            return text[:limit]
        except Exception:
            pass

    if lowered_content_type.startswith("text/") or lowered_content_type == "application/x-www-form-urlencoded":
        text = raw_bytes.decode("utf-8", errors="ignore")
        compact = " ".join(text.split())
        return compact[:limit]

    return "[BINARY BODY STORED]"


def redact_response_excerpt(excerpt: str | None, *, sensitive_body_keys: tuple[str, ...], limit: int = 240) -> str | None:
    if excerpt is None:
        return None

    try:
        parsed = json.loads(excerpt)
        redacted = _redact_json_value(parsed, {key.lower() for key in sensitive_body_keys})
        text = json.dumps(redacted, ensure_ascii=True, separators=(",", ":"))
        return text[:limit]
    except Exception:
        return excerpt[:limit]
