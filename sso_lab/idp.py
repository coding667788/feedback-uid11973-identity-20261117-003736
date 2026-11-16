"""One identity provider (run twice, once as A and once as B).

Each provider is an independent HTTP service with its own SQLite file, its own
issuer string, its own token endpoint and its own pre-shared HS256 key.  The
only things the two providers share are the *code* of this module and the lab
user directory -- never state, keys or storage.

Authorization code semantics implemented here:

* bound to issuer, client_id, the *exact* redirect_uri, the user, the nonce and
  the PKCE S256 challenge;
* expires 60 seconds after issue (``expires_at``), single use;
* a failed exchange (wrong verifier, wrong client, wrong redirect_uri, expired
  code) never consumes the code;
* consumption is an atomic conditional UPDATE, so two concurrent exchanges of
  the same code can produce at most one token.

The token endpoint authenticates the client with HTTP Basic
(``client_secret_basic``) and issues an HS256-signed ID token whose header is
exactly ``{"alg":"HS256","typ":"JWT"}``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import re
import sqlite3
import sys
import threading
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import faults, jwt, testhooks, tokens, users
from .clock import Clock
from .config import ProviderConfig, build_config_from_env
from .db import connect, one, write_txn
from .errors import ConfigurationError, GrantError, InputError, LabError, UnauthorizedClient
from .web import (
    BaseHandler,
    HttpError,
    LabHTTPServer,
    Request,
    escape_text,
    install_signal_handlers,
)

ID_TOKEN_LIFETIME_SECONDS = 120
_APPROVAL_CONTEXT = b"/approval-v1"
_STATE_RE = re.compile(r"^[A-Za-z0-9\-._~+/]{1,512}=*$")
_CODE_RE = re.compile(r"^[A-Za-z0-9\-_]{32,128}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS codes (
    code_hash       TEXT PRIMARY KEY,
    issuer          TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    redirect_uri    TEXT NOT NULL,
    subject         TEXT NOT NULL,
    username        TEXT NOT NULL,
    email           TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    nonce           TEXT NOT NULL,
    state           TEXT NOT NULL,
    code_challenge  TEXT NOT NULL,
    created_at      REAL NOT NULL,
    expires_at      REAL NOT NULL,
    consumed_at     REAL
);
CREATE INDEX IF NOT EXISTS idx_codes_issuer ON codes(issuer, created_at);

CREATE TABLE IF NOT EXISTS idp_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    detail      TEXT,
    created_at  REAL NOT NULL
);
"""


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def connect_idp(path) -> sqlite3.Connection:
    conn = connect(path)
    conn.executescript(SCHEMA)
    return conn


@dataclass(frozen=True)
class AuthorizeParams:
    response_type: str
    client_id: str
    redirect_uri: str
    state: str
    nonce: str
    code_challenge: str
    scope: str

    def form_fields(self) -> dict[str, str]:
        return {
            "response_type": self.response_type,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "state": self.state,
            "nonce": self.nonce,
            "code_challenge": self.code_challenge,
            "code_challenge_method": "S256",
            "scope": self.scope,
        }


class IdpService:
    KNOWN_PARAMS = frozenset(
        {
            "response_type",
            "client_id",
            "redirect_uri",
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method",
            "scope",
        }
    )

    def __init__(self, provider: ProviderConfig, db_path, *, clock: Clock | None = None,
                 code_ttl_seconds: int = 60, fault_spec: str | None = None) -> None:
        if code_ttl_seconds <= 0:
            raise ConfigurationError("code TTL must be positive")
        self.provider = provider
        self.db_path = db_path
        self.clock = clock or Clock.from_env()
        self.code_ttl = int(code_ttl_seconds)
        self._approval_key = provider.hs256_key + _APPROVAL_CONTEXT
        self.server: LabHTTPServer | None = None
        self.faults: dict[str, str] = {}
        if fault_spec and testhooks.enabled():
            self.faults = faults.parse(fault_spec)

    # -- lifecycle --------------------------------------------------------
    def make_server(self, host: str, port: int) -> LabHTTPServer:
        service = self

        class Handler(BaseHandler):
            def handle_request(self) -> None:
                service.handle(Request(self), self)

        self.server = LabHTTPServer((host, port), Handler, lab_name=f"idp-{self.provider.name}")
        return self.server

    def serve_forever(self) -> None:
        assert self.server is not None
        try:
            self.server.serve_forever(poll_interval=0.1)
        finally:
            self.server.server_close()

    # -- routing ----------------------------------------------------------
    def handle(self, request: Request, handler: BaseHandler) -> None:
        path = request.raw_path
        if path == "/authorize" and request.method == "GET":
            self.handle_authorize(request, handler)
        elif path == "/authorize/approve" and request.method == "POST":
            self.handle_approve(request, handler)
        elif path == "/token" and request.method == "POST":
            self.handle_token(request, handler)
        elif path == "/healthz":
            handler.send_json(200, {"ok": True, "provider": self.provider.name,
                                    "issuer": self.provider.issuer, "pid": __import__("os").getpid()})
        elif path == "/lab/metadata":
            # Human-facing only.  The RP never fetches this: its bindings are
            # pinned in trusted configuration and not discoverable at runtime.
            handler.send_json(
                200,
                {
                    "note": "documentation only; RP bindings are pinned, never discovered",
                    "issuer": self.provider.issuer,
                    "authorization_endpoint": self.provider.authorization_endpoint,
                    "token_endpoint": self.provider.token_endpoint,
                    "client_id": self.provider.client_id,
                    "signing_alg": "HS256",
                },
            )
        elif path == "/lab/clock":
            self.handle_lab_clock(request, handler)
        elif path == "/lab/code-status":
            self.handle_lab_code_status(request, handler)
        else:
            raise HttpError(404, "not found")

    # -- lab-only introspection (never used by the RP) ---------------------
    def _require_test_hooks(self) -> None:
        if not testhooks.enabled():
            raise HttpError(404, "not found")

    def handle_lab_clock(self, request: Request, handler: BaseHandler) -> None:
        """Move this provider's clock so code expiry can be tested.

        The RP deliberately has no equivalent endpoint: it is a *peer* of the
        provider under test, so letting a caller move its clock would be
        cheating rather than testing.
        """
        self._require_test_hooks()
        query = request.query()
        try:
            offset = float(query["offset"])
        except (KeyError, ValueError):
            raise HttpError(400, "offset=<seconds> required")
        self.clock.set_offset(offset)
        handler.send_json(200, {"provider": self.provider.name, "offset": self.clock.offset,
                                "now": self.clock.now()})

    def handle_lab_code_status(self, request: Request, handler: BaseHandler) -> None:
        self._require_test_hooks()
        code = request.query().get("code", "")
        if not _CODE_RE.match(code):
            raise HttpError(400, "code=<code> required")
        conn = connect_idp(self.db_path)
        try:
            row = one(conn, "SELECT created_at, expires_at, consumed_at FROM codes WHERE code_hash = ?",
                      (_sha256_hex(code),))
        finally:
            conn.close()
        if row is None:
            handler.send_json(404, {"found": False})
            return
        handler.send_json(200, {
            "found": True,
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "consumed": row["consumed_at"] is not None,
            "age_seconds": self.clock.now() - row["created_at"],
        })

    # -- authorize --------------------------------------------------------
    def _validate_authorize(self, params: dict[str, str]) -> AuthorizeParams:
        unknown = set(params) - self.KNOWN_PARAMS
        if unknown:
            raise InputError(f"unsupported authorize parameter(s): {', '.join(sorted(unknown))}")
        for name in ("response_type", "client_id", "redirect_uri", "state", "nonce",
                     "code_challenge", "code_challenge_method"):
            if name not in params or params[name] == "":
                raise InputError(f"missing required parameter {name!r}")
        if params["response_type"] != "code":
            raise InputError("only response_type=code is supported")
        if params["client_id"] != self.provider.client_id:
            raise InputError("unknown client_id")
        if params["redirect_uri"] != self.provider.redirect_uri:
            # Never redirect on redirect_uri mismatch: that is an open-redirect
            # primitive.  Render the error at the provider instead.
            raise InputError("redirect_uri does not exactly match the registered URI")
        if params["code_challenge_method"] != "S256":
            raise InputError("only code_challenge_method=S256 is supported")
        if not tokens.is_valid_pkce_challenge(params["code_challenge"]):
            raise InputError("code_challenge must be 43 base64url characters (S256)")
        if not _STATE_RE.match(params["state"]):
            raise InputError("state has invalid syntax")
        if not _STATE_RE.match(params["nonce"]):
            raise InputError("nonce has invalid syntax")
        scope = params.get("scope", "openid")
        if scope not in ("openid", "openid profile", "openid email", "openid profile email"):
            raise InputError("unsupported scope")
        return AuthorizeParams(
            response_type=params["response_type"],
            client_id=params["client_id"],
            redirect_uri=params["redirect_uri"],
            state=params["state"],
            nonce=params["nonce"],
            code_challenge=params["code_challenge"],
            scope=scope,
        )

    def _approval_token(self, params: AuthorizeParams) -> str:
        canonical = "\n".join(f"{k}={params.form_fields()[k]}" for k in sorted(params.form_fields()))
        return hmac.new(self._approval_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def _login_form(self, params: AuthorizeParams) -> str:
        hidden = "".join(
            f'<input type="hidden" name="{escape_text(k)}" value="{escape_text(v)}">'
            for k, v in params.form_fields().items()
        )
        hidden += (
            f'<input type="hidden" name="approval_token" '
            f'value="{escape_text(self._approval_token(params))}">'
        )
        rows = []
        for user in users.list_users(self.provider.name):
            rows.append(
                '<label style="display:block;margin:.4rem 0">'
                f'<input type="radio" name="username" value="{escape_text(user.username)}">'
                f' <b>{escape_text(user.display_name)}</b> '
                f'<code>{escape_text(user.email)}</code> '
                f'(sub=<code>{escape_text(user.sub)}</code>)</label>'
            )
        return (
            "<p>Local lab sign-in at provider "
            f"<b>{escape_text(self.provider.name)}</b>. No password: pick a test account.</p>"
            f'<form method="post" action="/authorize/approve">{hidden}'
            '<fieldset><legend>Choose a test account</legend>'
            + "".join(rows)
            + '</fieldset><button type="submit" name="decision" value="allow">Approve</button> '
            '<button type="submit" name="decision" value="deny">Deny</button></form>'
        )

    def handle_authorize(self, request: Request, handler: BaseHandler) -> None:
        params_dict = request.query()
        try:
            params = self._validate_authorize(params_dict)
        except InputError as exc:
            handler.send_html(400, "Authorization request rejected",
                              f"<p class=bad>{escape_text(exc.message)}</p>")
            return
        handler.send_html(200, f"Sign in at IdP {self.provider.name}", self._login_form(params))

    def handle_approve(self, request: Request, handler: BaseHandler) -> None:
        form = request.form()
        authorize_form = {k: v for k, v in form.items() if k in self.KNOWN_PARAMS}
        try:
            params = self._validate_authorize(authorize_form)
        except InputError as exc:
            handler.send_html(400, "Authorization request rejected",
                              f"<p class=bad>{escape_text(exc.message)}</p>")
            return
        token = form.get("approval_token", "")
        if not hmac.compare_digest(token, self._approval_token(params)):
            handler.send_html(400, "Authorization request rejected",
                              "<p class=bad>approval form integrity check failed</p>")
            return
        decision = form.get("decision", "allow")
        if decision != "allow":
            location = self._redirect_with(params.redirect_uri,
                                           {"error": "access_denied", "state": params.state})
            handler.redirect(location)
            return
        username = form.get("username", "")
        try:
            user = users.lookup(self.provider.name, username)
        except LabError as exc:
            handler.send_html(400, "Sign-in failed",
                              f"<p class=bad>{escape_text(exc.message)}</p>")
            return
        code = tokens.random_token(32)
        now = self.clock.now()
        conn = connect_idp(self.db_path)
        try:
            with write_txn(conn):
                conn.execute(
                    """INSERT INTO codes (code_hash, issuer, client_id, redirect_uri, subject,
                           username, email, display_name, nonce, state, code_challenge,
                           created_at, expires_at, consumed_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
                    (
                        _sha256_hex(code), self.provider.issuer, self.provider.client_id,
                        self.provider.redirect_uri, user.sub, user.username, user.email,
                        user.display_name, params.nonce, params.state, params.code_challenge,
                        now, now + self.code_ttl,
                    ),
                )
                conn.execute(
                    "INSERT INTO idp_events (kind, detail, created_at) VALUES (?,?,?)",
                    ("code_issued", f"sub={user.sub} client={params.client_id}", now),
                )
        finally:
            conn.close()
        handler.redirect(self._redirect_with(params.redirect_uri,
                                             {"code": code, "state": params.state}))

    @staticmethod
    def _redirect_with(redirect_uri: str, extra: dict[str, str]) -> str:
        split = urllib.parse.urlsplit(redirect_uri)
        existing = urllib.parse.parse_qsl(split.query, keep_blank_values=True)
        merged = existing + list(extra.items())
        query = urllib.parse.urlencode(merged)
        return urllib.parse.urlunsplit((split.scheme, split.netloc, split.path, query, ""))

    # -- token ------------------------------------------------------------
    def _basic_client(self, request: Request) -> tuple[str, str]:
        header = request.headers.get("Authorization") or ""
        scheme, _, payload = header.partition(" ")
        if scheme.lower() != "basic" or not payload:
            raise UnauthorizedClient("client authentication via HTTP Basic is required")
        try:
            raw = base64.b64decode(payload.encode("ascii"), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise UnauthorizedClient("malformed Basic credentials")
        client_id, sep, secret = raw.partition(":")
        if not sep:
            raise UnauthorizedClient("malformed Basic credentials")
        expected_id = self.provider.client_id
        expected_secret = self.provider.client_secret
        if not (
            hmac.compare_digest(client_id.encode("utf-8"), expected_id.encode("utf-8"))
            and hmac.compare_digest(secret.encode("utf-8"), expected_secret.encode("utf-8"))
        ):
            raise UnauthorizedClient("client authentication failed")
        return client_id, secret

    def handle_token(self, request: Request, handler: BaseHandler) -> None:
        try:
            form = request.form()
        except HttpError:
            raise
        try:
            client_id, _ = self._basic_client(request)
            if "client_secret" in form or "client_id" in form:
                raise InputError("client credentials must be sent with HTTP Basic only")
            grant_type = form.get("grant_type")
            if grant_type != "authorization_code":
                raise InputError("only grant_type=authorization_code is supported")
            code = form.get("code", "")
            redirect_uri = form.get("redirect_uri", "")
            verifier = form.get("code_verifier", "")
            if not _CODE_RE.match(code):
                raise GrantError("invalid authorization code")
            if not redirect_uri:
                raise GrantError("missing redirect_uri")
            if not tokens.is_valid_pkce_verifier(verifier):
                raise GrantError("invalid code_verifier syntax")
            response = self._exchange(code, client_id, redirect_uri, verifier)
        except UnauthorizedClient as exc:
            handler.send_json(
                exc.http_status,
                {"error": "invalid_client", "error_description": exc.message},
                headers=[("WWW-Authenticate", 'Basic realm="sso-lab"')],
            )
            return
        except GrantError as exc:
            handler.send_json(exc.http_status, {"error": "invalid_grant",
                                                "error_description": exc.message})
            return
        except InputError as exc:
            handler.send_json(exc.http_status, {"error": "invalid_request",
                                                "error_description": exc.message})
            return
        handler.send_json(200, response)

    def _exchange(self, code: str, client_id: str, redirect_uri: str, verifier: str) -> dict[str, Any]:
        now = self.clock.now()
        code_hash = _sha256_hex(code)
        conn = connect_idp(self.db_path)
        try:
            row = one(conn, "SELECT * FROM codes WHERE code_hash = ?", (code_hash,))
            if row is None:
                raise GrantError("unknown or already used authorization code")
            if row["issuer"] != self.provider.issuer:
                # A code minted by another issuer and replayed here.  The hash
                # would not normally exist in this DB at all; keep the explicit
                # check for DB-copy scenarios.
                raise GrantError("authorization code does not belong to this issuer")
            if row["consumed_at"] is not None:
                raise GrantError("authorization code has already been used")
            if now >= row["expires_at"]:
                raise GrantError("authorization code has expired")
            if not hmac.compare_digest(row["client_id"], client_id):
                raise GrantError("authorization code was not issued to this client")
            if not hmac.compare_digest(row["redirect_uri"], redirect_uri):
                raise GrantError("redirect_uri does not match the authorization request")
            if not tokens.pkce_matches(verifier, row["code_challenge"]):
                raise GrantError("PKCE verification failed")

            with write_txn(conn):
                cursor = conn.execute(
                    "UPDATE codes SET consumed_at = ? WHERE code_hash = ? AND consumed_at IS NULL",
                    (now, code_hash),
                )
                if cursor.rowcount != 1:
                    raise GrantError("authorization code was consumed concurrently")
                conn.execute(
                    "INSERT INTO idp_events (kind, detail, created_at) VALUES (?,?,?)",
                    ("code_exchanged", f"sub={row['subject']}", now),
                )
            claims = {
                "iss": self.provider.issuer,
                "sub": row["subject"],
                "aud": self.provider.client_id,
                "nonce": row["nonce"],
                "iat": int(now),
                "exp": int(now) + ID_TOKEN_LIFETIME_SECONDS,
                "email": row["email"],
                "name": row["display_name"],
            }
            return self.build_token_response(claims, row, now)
        finally:
            conn.close()

    # -- extension points used by the security tests -----------------------
    def build_token_response(self, claims: dict[str, Any], row: sqlite3.Row, now: float) -> dict[str, Any]:
        """Mint the ID token for already-validated exchange.

        Tests subclass the service and override this to emit tokens with a
        wrong nonce, wrong audience, wrong key, duplicated members, etc.  The
        happy path is exactly what is below.
        """
        if self.faults:
            id_token = faults.mint(self.provider, claims, self.faults)
        else:
            id_token = jwt.sign_hs256(
                {"alg": "HS256", "typ": "JWT"}, claims, self.provider.hs256_key
            )
        return {
            "access_token": tokens.random_token(32),
            "token_type": "Bearer",
            "expires_in": ID_TOKEN_LIFETIME_SECONDS,
            "id_token": id_token,
            "scope": "openid",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one identity provider (A or B)")
    parser.add_argument("--provider", choices=("A", "B"), required=True)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--runtime-dir", default=None)
    args = parser.parse_args(argv)

    config = build_config_from_env()
    provider = config.providers[args.provider]
    runtime_dir = args.runtime_dir or str(config.runtime_dir)
    db_path = Path(runtime_dir) / f"idp_{args.provider.lower()}.sqlite3"
    port = args.port if args.port is not None else int(
        os.environ.get(f"SSO_IDP_{args.provider}_PORT", "8801" if args.provider == "A" else "8802")
    )
    service = IdpService(
        provider, db_path, clock=Clock.from_env(),
        code_ttl_seconds=config.code_ttl_seconds,
        fault_spec=os.environ.get(f"SSO_IDP_{args.provider}_FAULTS") or os.environ.get("SSO_IDP_FAULTS"),
    )
    server = service.make_server(provider.host, port)
    stop = threading.Event()
    install_signal_handlers(stop)
    sys.stderr.write(
        f"[idp-{args.provider}] issuer={provider.issuer} listen=http://{provider.host}:{port} "
        f"db={db_path} pid={os.getpid()}\n"
    )
    sys.stderr.flush()
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    thread.start()
    while not stop.wait(0.2):
        pass
    server.shutdown()
    server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
