from __future__ import annotations

import base64
import hashlib
import json

from cryptography.fernet import Fernet

from api.app.config import get_settings


def _fernet_key(raw_key: str) -> bytes:
    digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


class SecretService:
    def _cipher(self) -> Fernet:
        return Fernet(_fernet_key(get_settings().secret_encryption_key))

    def encrypt_json(self, payload: dict[str, object]) -> str:
        encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        return self._cipher().encrypt(encoded).decode("utf-8")

    def decrypt_json(self, ciphertext: str) -> dict[str, object]:
        decoded = self._cipher().decrypt(ciphertext.encode("utf-8"))
        parsed = json.loads(decoded.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else {}


secret_service = SecretService()
