"""Token / identifier generation and PKCE S256."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import string

from . import base64url

_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9\-_]{43}$")
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9\-_]{16,128}$")
_URLSAFE_ALPHABET = string.ascii_letters + string.digits + "-._~"


def is_valid_opaque_token(value: object) -> bool:
    """Shape check for cookies / codes minted by :func:`random_token`."""
    return isinstance(value, str) and bool(_OPAQUE_RE.match(value))


def random_token(nbytes: int = 32) -> str:
    """Opaque, unguessable identifier: 256 bits, base64url."""
    if nbytes < 16:
        raise ValueError("refusing to mint a short secret")
    return base64url.encode(secrets.token_bytes(nbytes))


def random_pkce_verifier() -> str:
    # 64 chars drawn from the RFC 7636 unreserved set -> well inside 43..128.
    return "".join(secrets.choice(_URLSAFE_ALPHABET) for _ in range(64))


def pkce_challenge_s256(verifier: str) -> str:
    if not is_valid_pkce_verifier(verifier):
        raise ValueError("PKCE verifier does not satisfy RFC 7636 syntax")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64url.encode(digest)


def is_valid_pkce_verifier(value: object) -> bool:
    return isinstance(value, str) and bool(_VERIFIER_RE.match(value))


def is_valid_pkce_challenge(value: object) -> bool:
    return isinstance(value, str) and bool(_CHALLENGE_RE.match(value))


def pkce_matches(verifier: str, challenge: str) -> bool:
    """Constant-time comparison of S256(verifier) with the stored challenge."""
    if not is_valid_pkce_verifier(verifier) or not is_valid_pkce_challenge(challenge):
        return False
    computed = pkce_challenge_s256(verifier)
    return hmac.compare_digest(computed.encode("ascii"), challenge.encode("ascii"))
