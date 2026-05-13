from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass


class CryptoError(Exception):
    """Raised when encryption or authentication fails."""


def _to_bytes(value: str | bytes, field: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"{field} must be str or bytes")


def derive_user_password_hash(password: str, salt: bytes | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return base64.b64encode(salt).decode("ascii"), base64.b64encode(digest).decode("ascii")


def verify_user_password(password: str, salt_b64: str, digest_b64: str) -> bool:
    try:
        salt = base64.b64decode(salt_b64.encode("ascii"), validate=True)
        expected = base64.b64decode(digest_b64.encode("ascii"), validate=True)
    except Exception:
        return False
    actual = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=len(expected),
    )
    return hmac.compare_digest(actual, expected)


def derive_room_key(passphrase: str, room: str) -> bytes:
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=("room:" + room).encode("utf-8"),
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )


def _stream_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    counter = 0
    pos = 0
    while pos < len(data):
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        take = min(len(block), len(data) - pos)
        for i in range(take):
            out[pos + i] = data[pos + i] ^ block[i]
        pos += take
        counter += 1
    return bytes(out)


@dataclass(frozen=True)
class SealedMessage:
    nonce_b64: str
    ciphertext_b64: str
    mac_b64: str


def seal(key: bytes, plaintext: str | bytes, aad: str | bytes = b"") -> SealedMessage:
    pt = _to_bytes(plaintext, "plaintext")
    aad_bytes = _to_bytes(aad, "aad")
    nonce = secrets.token_bytes(16)
    ct = _stream_xor(key, nonce, pt)
    mac = hmac.new(key, b"mac-v1" + nonce + aad_bytes + ct, hashlib.sha256).digest()
    return SealedMessage(
        nonce_b64=base64.b64encode(nonce).decode("ascii"),
        ciphertext_b64=base64.b64encode(ct).decode("ascii"),
        mac_b64=base64.b64encode(mac).decode("ascii"),
    )


def open_sealed(key: bytes, sealed: SealedMessage, aad: str | bytes = b"") -> bytes:
    aad_bytes = _to_bytes(aad, "aad")
    try:
        nonce = base64.b64decode(sealed.nonce_b64.encode("ascii"), validate=True)
        ct = base64.b64decode(sealed.ciphertext_b64.encode("ascii"), validate=True)
        mac = base64.b64decode(sealed.mac_b64.encode("ascii"), validate=True)
    except Exception as exc:
        raise CryptoError("invalid base64 payload") from exc
    expected = hmac.new(key, b"mac-v1" + nonce + aad_bytes + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise CryptoError("message authentication failed")
    return _stream_xor(key, nonce, ct)
