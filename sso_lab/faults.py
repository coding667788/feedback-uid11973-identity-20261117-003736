"""Deliberately misbehaving ID tokens, for the RP's negative tests.

A provider is started with ``SSO_IDP_FAULTS`` (comma-separated ``name`` or
``name=value`` entries).  The fault applies only to the token it mints: the
authorization code and the client authentication are still genuine, so the RP
really reaches the verification step with a hostile token instead of failing
earlier for an unrelated reason.

Supported faults
----------------
``wrong_nonce[=value]``      token nonce is not the one the RP asked for
``wrong_aud[=value]``        audience is something else
``wrong_iss[=value]``        issuer claim is something else (e.g. the *other*
                             provider's issuer, the classic IdP-confusion move)
``wrong_key``                signed with a key the RP does not trust
``peer_key``                 signed with the *other* provider's real key
                             (IdP-confusion: right key, wrong issuer key slot)
``alg_none``                 unsigned token with ``alg: none``
``dup_iss``                  payload JSON repeats the ``iss`` member
``sub_number``               ``sub`` is an integer instead of a string
``expired``                  ``exp`` in the past
``future_iat``               ``iat`` far in the future
``jku[=url]``                header carries ``jku`` (must never be fetched)
``jwks_uri[=url]``           payload carries a ``jwks_uri`` hint
``long_lived``               ``exp`` a day out (still valid, just long)
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from . import base64url
from .config import ProviderConfig


def parse(spec: str | None) -> dict[str, str]:
    result: dict[str, str] = {}
    if not spec:
        return result
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        name, _, value = item.partition("=")
        result[name.strip()] = value.strip()
    return result


def _raw_segment(raw: bytes) -> str:
    return base64url.encode(raw)


def _payload_json(claims: dict[str, Any], faults: dict[str, str]) -> str:
    if "dup_iss" in faults:
        # Hand-built JSON with a repeated member.  The *first* iss is the real
        # one; a lenient parser would keep the second.  Either way the RP must
        # reject the token outright.
        body = json.dumps(
            {k: v for k, v in claims.items() if k != "iss"},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        injected = json.dumps({"iss": claims["iss"]}, separators=(",", ":"))
        dup = json.dumps({"iss": "http://attacker.invalid/issuer"}, separators=(",", ":"))
        return body[:-1] + "," + injected[1:-1] + "," + dup[1:-1] + "}"
    return json.dumps(claims, sort_keys=True, separators=(",", ":"), allow_nan=False)


def mint(provider: ProviderConfig, claims: dict[str, Any], faults: dict[str, str]) -> str:
    """Return an ID token carrying the requested faults."""
    claims = dict(claims)
    if "wrong_nonce" in faults:
        claims["nonce"] = faults["wrong_nonce"] or "nonce-from-another-login"
    if "wrong_aud" in faults:
        claims["aud"] = faults["wrong_aud"] or "some-other-client"
    if "wrong_iss" in faults:
        claims["iss"] = faults["wrong_iss"] or (provider.issuer + "-impostor")
    if "sub_number" in faults:
        claims["sub"] = 12345
    if "expired" in faults:
        # A realistically stale token: issued 200 s ago, expired 80 s ago.
        claims["iat"] = int(claims["iat"]) - 200
        claims["exp"] = int(claims["iat"]) + 120
    if "future_iat" in faults:
        claims["iat"] = int(claims["iat"]) + 3600
        claims["exp"] = int(claims["iat"]) + 120
    if "long_lived" in faults:
        claims["exp"] = int(claims["iat"]) + 86400
    if "jwks_uri" in faults:
        claims["jwks_uri"] = faults["jwks_uri"] or "http://127.0.0.1:9/jwks.json"

    header: dict[str, Any] = {"alg": "HS256", "typ": "JWT"}
    if "alg_none" in faults:
        header = {"alg": "none", "typ": "JWT"}
    if "jku" in faults:
        header["jku"] = faults["jku"] or "http://127.0.0.1:9/jwks.json"
    if "kid" in faults:
        header["kid"] = faults["kid"]

    payload = _payload_json(claims, faults)
    h64 = _raw_segment(json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    p64 = _raw_segment(payload.encode("utf-8"))
    if "alg_none" in faults:
        return f"{h64}.{p64}."
    key = provider.hs256_key
    if "wrong_key" in faults:
        key = b"attacker-controlled-key-not-in-rp-config"
    if "peer_key" in faults:
        # The other provider's genuine lab key, reconstructed from its label.
        other = "b" if provider.name == "A" else "a"
        key = f"local-lab-{other}-shared-secret-DO-NOT-REUSE".encode("ascii")
    signing_input = f"{h64}.{p64}".encode("ascii")
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{h64}.{p64}.{_raw_segment(sig)}"


def describe(faults: dict[str, str]) -> str:
    return ",".join(f"{k}={v}" if v else k for k, v in sorted(faults.items()))
