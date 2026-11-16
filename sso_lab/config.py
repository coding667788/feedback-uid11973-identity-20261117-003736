"""Trusted configuration for the lab.

Everything the RP believes about an identity provider is pinned in this module:
issuer, authorization endpoint, token endpoint, client id, client secret,
shared HS256 key, audience and the exact redirect URI.  Nothing here is derived
from network input.  In particular the signing key is *never* fetched from a
URL that a token happens to mention (``jku``/``x5u``/``iss`` are not key
sources) and an ID token cannot introduce a new issuer.

The three services listen on three loopback addresses (127.0.0.1 = RP,
127.0.0.2 = IdP A, 127.0.0.3 = IdP B) so browser cookies are naturally scoped
per host, exactly like three different sites.

All credentials below are local lab data only.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUNTIME_DIR = ROOT / "runtime"

RP_HOST = "127.0.0.1"
IDP_A_HOST = "127.0.0.2"
IDP_B_HOST = "127.0.0.3"


@dataclass(frozen=True)
class ProviderConfig:
    """One pinned identity provider binding."""

    name: str
    host: str
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    client_id: str
    client_secret: str
    hs256_key: bytes
    audience: str
    redirect_uri: str


@dataclass(frozen=True)
class RpConfig:
    host: str
    port: int
    base_url: str
    callback_path: str
    callback_url: str
    #: exact callback URL for each provider (issuer travels in the query)
    callback_url_for: Mapping[str, str]
    browser_cookie: str
    transaction_ttl_seconds: int
    session_ttl_seconds: int
    clock_skew_seconds: int
    issuers: tuple[str, ...]


@dataclass(frozen=True)
class LabConfig:
    rp: RpConfig
    providers: Mapping[str, ProviderConfig]
    code_ttl_seconds: int
    runtime_dir: Path
    database_path: Path
    idp_database_path: Mapping[str, Path]

    def provider(self, name: str) -> ProviderConfig:
        return self.providers[name]


def _provider(
    name: str,
    host: str,
    port: int,
    client_id: str,
    client_secret: str,
    key_label: str,
    redirect_uri: str,
) -> ProviderConfig:
    base = f"http://{host}:{port}"
    return ProviderConfig(
        name=name,
        host=host,
        issuer=f"{base}/issuer/{name}",
        authorization_endpoint=f"{base}/authorize",
        token_endpoint=f"{base}/token",
        client_id=client_id,
        client_secret=client_secret,
        hs256_key=f"local-lab-{key_label}-shared-secret-DO-NOT-REUSE".encode("ascii"),
        audience=client_id,
        redirect_uri=redirect_uri,
    )


def build_config(
    *,
    rp_port: int = 8800,
    idp_a_port: int = 8801,
    idp_b_port: int = 8802,
    runtime_dir: str | Path | None = None,
    code_ttl_seconds: int = 60,
) -> LabConfig:
    """Return the immutable config for one lab instance (picklable)."""
    rp_base = f"http://{RP_HOST}:{rp_port}"
    callback_url = f"{rp_base}/callback"
    callback_url_for = {
        "A": f"{callback_url}?issuer=A",
        "B": f"{callback_url}?issuer=B",
    }
    # Each provider pins the callback URL that names it, so a code authorized
    # for A can never be redeemed against a redirect_uri that says B.
    providers = {
        "A": _provider(
            "A", IDP_A_HOST, idp_a_port, "rp-client-for-A",
            "client-secret-A-lab", "a", callback_url_for["A"],
        ),
        "B": _provider(
            "B", IDP_B_HOST, idp_b_port, "rp-client-for-B",
            "client-secret-B-lab", "b", callback_url_for["B"],
        ),
    }
    runtime = Path(runtime_dir) if runtime_dir is not None else DEFAULT_RUNTIME_DIR
    return LabConfig(
        rp=RpConfig(
            host=RP_HOST,
            port=rp_port,
            base_url=rp_base,
            callback_path="/callback",
            callback_url=callback_url,
            callback_url_for=callback_url_for,
            browser_cookie="rp_sid",
            transaction_ttl_seconds=300,
            session_ttl_seconds=3600,
            clock_skew_seconds=5,
            issuers=("A", "B"),
        ),
        providers=providers,
        code_ttl_seconds=int(code_ttl_seconds),
        runtime_dir=runtime,
        database_path=runtime / "sso_lab.sqlite3",
        idp_database_path={
            "A": runtime / "idp_a.sqlite3",
            "B": runtime / "idp_b.sqlite3",
        },
    )


def build_config_from_env() -> LabConfig:
    """Config used by the service entry points (ports overridable)."""
    return build_config(
        rp_port=int(os.environ.get("SSO_RP_PORT", "8800")),
        idp_a_port=int(os.environ.get("SSO_IDP_A_PORT", "8801")),
        idp_b_port=int(os.environ.get("SSO_IDP_B_PORT", "8802")),
        runtime_dir=os.environ.get("SSO_RUNTIME_DIR"),
        code_ttl_seconds=int(os.environ.get("SSO_CODE_TTL", "60")),
    )


def describe(config: LabConfig) -> dict[str, Any]:
    """Non-secret summary for /healthz style output and the run instructions."""
    return {
        "rp": config.rp.base_url,
        "database": str(config.database_path),
        "code_ttl_seconds": config.code_ttl_seconds,
        "providers": {
            name: {
                "issuer": p.issuer,
                "authorization_endpoint": p.authorization_endpoint,
                "token_endpoint": p.token_endpoint,
                "client_id": p.client_id,
                "redirect_uri": p.redirect_uri,
            }
            for name, p in config.providers.items()
        },
    }
