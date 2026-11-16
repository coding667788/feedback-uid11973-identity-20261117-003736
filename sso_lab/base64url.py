"""Strict, unpadded base64url helpers (RFC 7515 flavor)."""

import base64
import binascii

_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


class B64UrlError(ValueError):
    pass


def encode(raw: bytes) -> str:
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("base64url.encode expects bytes")
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def decode_strict(text: str) -> bytes:
    """Decode unpadded base64url, rejecting anything outside the RFC 7515 alphabet.

    ``base64.urlsafe_b64decode`` silently accepts ``=`` padding, embedded
    newlines and the standard ``+/`` alphabet, which would make the JWS /
    PKCE parsing laxer than the protocol we are trying to demonstrate.
    """
    if not isinstance(text, str):
        raise B64UrlError("base64url input must be a string")
    if len(text) % 4 == 1:
        raise B64UrlError("invalid base64url length")
    if any(ch not in _ALPHABET for ch in text):
        raise B64UrlError("invalid base64url character")
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - defensive
        raise B64UrlError(str(exc)) from exc
