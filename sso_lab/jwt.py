"""Hand-rolled HS256 JWS (ID Token) creation and strict verification.

Deliberately small and deliberately strict:

* exactly three base64url segments, no padding, only the RFC 7515 alphabet;
* header ``alg`` must be the literal ``HS256`` -- ``none``, ``RS256`` and
  friends are rejected before any key is touched;
* ``jku`` / ``jwks`` / ``x5u`` / ``x5c`` / ``jwk`` header members are refused
  outright: this RP never downloads key material from a token-supplied URL;
* duplicated JSON member names anywhere in the header or payload are fatal
  (``json`` would otherwise keep the last one silently);
* claim types are checked, and ``bool`` is not accepted where an integer is
  required (in Python ``isinstance(True, int)`` is ``True``);
* the signature is verified with ``hmac.compare_digest`` against a key pinned
  in trusted configuration for the expected issuer.

The whole payload is parsed *before* the signature check only to produce good
error messages; no claim is trusted until the MAC has been verified.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from . import base64url


class TokenValidationError(Exception):
    """An ID token failed verification (signature, claims, policy or time)."""

    code = "invalid_id_token"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

ALLOWED_ALG = "HS256"
FORBIDDEN_HEADER_MEMBERS = frozenset(
    {"jku", "jwks", "x5u", "x5c", "jwk", "x5t", "x5t#S256"}
)
_FORBIDDEN_MEMBERS_LOWER = frozenset(m.lower() for m in FORBIDDEN_HEADER_MEMBERS)
_MAX_TOKEN_LENGTH = 16 * 1024
_SECRET_MIN_LENGTH = 16

_SUB_RE = re.compile(r"^[A-Za-z0-9._:@\-]{1,128}$")


# --------------------------------------------------------------------------
# strict JSON
# --------------------------------------------------------------------------
class _DuplicateMember(ValueError):
    pass


def _object_pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str):
            raise _DuplicateMember("JSON object key is not a string")
        if key in result:
            raise _DuplicateMember(f"duplicate JSON member: {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise _DuplicateMember(f"non-standard JSON constant: {name}")


def strict_json_loads(data: bytes | str) -> Any:
    """``json.loads`` that rejects duplicate members and NaN/Infinity."""
    try:
        text = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
        return json.loads(
            text,
            object_pairs_hook=_object_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise TokenValidationError("JSON segment is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise TokenValidationError(f"malformed JSON segment: {exc.msg}") from exc
    except _DuplicateMember as exc:
        raise TokenValidationError(str(exc)) from exc


# --------------------------------------------------------------------------
# encoding (used by the IdPs)
# --------------------------------------------------------------------------
def _json_segment(obj: Mapping[str, Any]) -> str:
    raw = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return base64url.encode(raw)


def _mac(key: bytes, signing_input: bytes) -> bytes:
    return hmac.new(key, signing_input, hashlib.sha256).digest()


def sign_hs256(header: Mapping[str, Any], payload: Mapping[str, Any], key: bytes) -> str:
    if not isinstance(key, (bytes, bytearray)) or len(key) < _SECRET_MIN_LENGTH:
        raise ValueError("HS256 key must be at least 16 bytes")
    if header.get("alg") != ALLOWED_ALG:
        raise ValueError("only HS256 can be signed by this lab")
    h = _json_segment(header)
    p = _json_segment(payload)
    signing_input = f"{h}.{p}".encode("ascii")
    return f"{h}.{p}.{base64url.encode(_mac(bytes(key), signing_input))}"


# --------------------------------------------------------------------------
# verification
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class VerifiedIdToken:
    header: Mapping[str, Any]
    claims: Mapping[str, Any]

    @property
    def issuer(self) -> str:
        return self.claims["iss"]

    @property
    def subject(self) -> str:
        return self.claims["sub"]


def _split(token: str) -> tuple[bytes, bytes, bytes, str, str]:
    if not isinstance(token, str):
        raise TokenValidationError("ID token must be a string")
    if len(token) > _MAX_TOKEN_LENGTH:
        raise TokenValidationError("ID token too large")
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenValidationError("ID token must have exactly three segments")
    h64, p64, s64 = parts
    if not h64 or not p64 or not s64:
        raise TokenValidationError("empty JWS segment")
    try:
        return (
            base64url.decode_strict(h64),
            base64url.decode_strict(p64),
            base64url.decode_strict(s64),
            h64,
            p64,
        )
    except base64url.B64UrlError as exc:
        raise TokenValidationError(f"malformed JWS segment: {exc}") from exc


def _check_header(header: Any) -> Mapping[str, Any]:
    if not isinstance(header, dict):
        raise TokenValidationError("JWS header must be a JSON object")
    for name in header:
        if name.lower() in _FORBIDDEN_MEMBERS_LOWER:
            raise TokenValidationError(
                f"forbidden JWS header member {name!r}: keys are pinned in RP config"
            )
    alg = header.get("alg")
    if not isinstance(alg, str):
        raise TokenValidationError("JWS header alg must be a string")
    if alg != ALLOWED_ALG:
        raise TokenValidationError(f"unsupported JWS alg {alg!r}; only HS256 is accepted")
    typ = header.get("typ")
    if typ is not None and typ != "JWT":
        raise TokenValidationError(f"unexpected JWS typ {typ!r}")
    if "crit" in header:
        raise TokenValidationError("JWS 'crit' header is not supported")
    return header


def _require_str(claims: Mapping[str, Any], name: str, *, non_empty: bool = True) -> str:
    value = claims.get(name)
    if not isinstance(value, str):
        raise TokenValidationError(f"claim {name!r} must be a string")
    if non_empty and not value:
        raise TokenValidationError(f"claim {name!r} must not be empty")
    return value


def _require_int(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TokenValidationError(f"claim {name!r} must be an integer (seconds)")
    return value


def _audiences(claims: Mapping[str, Any]) -> list[str]:
    aud = claims.get("aud")
    if isinstance(aud, str):
        if not aud:
            raise TokenValidationError("claim 'aud' must not be empty")
        return [aud]
    if isinstance(aud, list):
        if not aud or len(aud) > 8:
            raise TokenValidationError("claim 'aud' must be a non-empty short list")
        out = []
        for item in aud:
            if not isinstance(item, str) or not item:
                raise TokenValidationError("claim 'aud' entries must be non-empty strings")
            out.append(item)
        return out
    raise TokenValidationError("claim 'aud' must be a string or a list of strings")


def verify_hs256_id_token(
    token: str,
    *,
    key: bytes,
    expected_issuer: str,
    expected_audience: str,
    expected_nonce: str,
    now: int,
    leeway: int = 5,
    require_nonce: bool = True,
) -> VerifiedIdToken:
    """Verify a signed ID token against pinned expectations.

    Check order: structure -> header policy -> MAC under the pinned issuer key
    -> claim presence/types -> issuer identity -> audience -> nonce -> time.
    The leeway widens both ends of the accepted window: a token is accepted
    while ``iat - leeway <= now <= exp + leeway``.
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) < _SECRET_MIN_LENGTH:
        raise ValueError("trusted HS256 key is missing or too short")
    if not isinstance(leeway, int) or leeway < 0:
        raise ValueError("leeway must be a non-negative integer")
    expected_issuer = str(expected_issuer)
    expected_audience = str(expected_audience)

    header_raw, payload_raw, signature, h64, p64 = _split(token)
    header = _check_header(strict_json_loads(header_raw))

    # --- signature under the key pinned for the *expected* issuer ----------
    signing_input = f"{h64}.{p64}".encode("ascii")
    expected_mac = _mac(bytes(key), signing_input)
    if not hmac.compare_digest(expected_mac, signature):
        raise TokenValidationError("ID token signature verification failed")

    # --- claims (only trusted now that the MAC is verified) ---------------
    claims = strict_json_loads(payload_raw)
    if not isinstance(claims, dict):
        raise TokenValidationError("ID token payload must be a JSON object")
    for required in ("iss", "sub", "aud", "nonce", "iat", "exp"):
        if required not in claims:
            raise TokenValidationError(f"ID token is missing required claim {required!r}")

    iss = _require_str(claims, "iss")
    sub = _require_str(claims, "sub")
    if not _SUB_RE.match(sub):
        raise TokenValidationError("claim 'sub' contains characters outside the lab policy")
    auds = _audiences(claims)
    nonce = _require_str(claims, "nonce")
    iat = _require_int(claims, "iat")
    exp = _require_int(claims, "exp")

    if iss != expected_issuer:
        raise TokenValidationError(
            f"issuer mismatch: token iss {iss!r} is not the pinned issuer {expected_issuer!r}"
        )
    if expected_audience not in auds:
        raise TokenValidationError(
            f"audience mismatch: token aud {auds!r} does not contain {expected_audience!r}"
        )
    if require_nonce:
        if not isinstance(expected_nonce, str) or not expected_nonce:
            raise ValueError("expected nonce must be a non-empty string")
        if not hmac.compare_digest(nonce.encode("utf-8"), expected_nonce.encode("utf-8")):
            raise TokenValidationError("nonce mismatch")

    if exp < iat:
        raise TokenValidationError("ID token exp precedes iat")
    if iat > now + leeway:
        raise TokenValidationError("ID token iat is in the future")
    if exp + leeway < now:
        raise TokenValidationError("ID token has expired")
    if exp <= iat:
        raise TokenValidationError("ID token has a non-positive lifetime")
    return VerifiedIdToken(header=header, claims=claims)
