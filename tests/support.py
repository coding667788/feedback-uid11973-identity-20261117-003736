"""Shared test helpers: in-process IdP, raw HTTP calls, assertions."""

from __future__ import annotations

import http.client
import json
import os
import re
import sys
import threading
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# In-process IdPs need the hook switch for the fault-injection and clock
# endpoints.  The RP processes started by the harness get their own env.
os.environ.setdefault("SSO_TEST_HOOKS", "1")

from sso_lab import tokens  # noqa: E402
from sso_lab.clock import Clock  # noqa: E402
from sso_lab.config import build_config  # noqa: E402
from sso_lab.harness import pick_ports  # noqa: E402
from sso_lab.idp import IdpService  # noqa: E402


def raw_request(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read()
        header_map = {k.lower(): v for k, v in response.getheaders()}
        return response.status, header_map, data
    finally:
        connection.close()


def json_post(
    host: str, port: int, path: str, payload: dict, *, timeout: float = 15.0
) -> tuple[int, dict[str, str], dict]:
    body = json.dumps(payload).encode("utf-8")
    status, headers, raw = raw_request(
        host, port, "POST", path, body=body,
        headers={"Content-Type": "application/json"}, timeout=timeout,
    )
    try:
        return status, headers, json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return status, headers, {}


class InProcessIdp:
    """One IdP service on a real socket, inside the test process."""

    def __init__(self, name: str = "A", *, code_ttl: int = 60, faults: str | None = None):
        self.name = name
        self.port = pick_ports(1)[0]
        base = build_config(
            rp_port=pick_ports(1)[0],
            idp_a_port=self.port if name == "A" else pick_ports(1)[0],
            idp_b_port=self.port if name == "B" else pick_ports(1)[0],
            runtime_dir=ROOT / "runtime" / "unit-idp",
        )
        self.config = base
        self.provider = base.providers[name]
        self.clock = Clock(0.0)
        self.service = IdpService(
            self.provider,
            base.idp_database_path[name].with_name(f"unit_{name}_{self.port}.sqlite3"),
            clock=self.clock,
            code_ttl_seconds=code_ttl,
            fault_spec=faults,
        )
        self.server = self.service.make_server(self.provider.host, self.port)
        self._thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)

    def __enter__(self) -> "InProcessIdp":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()

    @property
    def host(self) -> str:
        return self.provider.host

    def authorize_and_approve(self, *, username: str = "alice",
                              state: str | None = None, nonce: str | None = None,
                              challenge: str | None = None, verifier: str | None = None,
                              client_id: str | None = None,
                              redirect_uri: str | None = None) -> dict[str, str]:
        """Drive the IdP's own login form and return the callback query params."""
        state = state or tokens.random_token(32)
        nonce = nonce or tokens.random_token(32)
        verifier = verifier or tokens.random_pkce_verifier()
        challenge = challenge or tokens.pkce_challenge_s256(verifier)
        params = {
            "response_type": "code",
            "client_id": client_id or self.provider.client_id,
            "redirect_uri": redirect_uri or self.provider.redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "openid",
        }
        path = "/authorize?" + urllib.parse.urlencode(params)
        status, _, html = raw_request(self.host, self.port, "GET", path)
        assert status == 200, f"authorize returned {status}: {html[:300]}"
        match = re.search(rb'name="approval_token" value="([0-9a-f]+)"', html)
        assert match, "no approval token in login form"
        form = dict(params)
        form.update(approval_token=match.group(1).decode(), username=username, decision="allow")
        body = urllib.parse.urlencode(form).encode()
        status, headers, _ = raw_request(
            self.host, self.port, "POST", "/authorize/approve", body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert status == 302, f"approve returned {status}"
        location = headers["location"]
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query))
        query["_verifier"] = verifier
        query["_nonce"] = nonce
        query["_redirect_uri"] = params["redirect_uri"]
        query["_challenge"] = challenge
        return query

    def token(self, *, code: str, verifier: str, redirect_uri: str | None = None,
              client_id: str | None = None, secret: str | None = None,
              basic: str | None = None) -> tuple[int, dict]:
        import base64

        fields = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri or self.provider.redirect_uri,
            "code_verifier": verifier,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if basic is False:
            pass  # deliberately no Authorization header
        elif basic is not None:
            headers["Authorization"] = basic
        elif secret is not False:
            credentials = f"{client_id or self.provider.client_id}:{secret or self.provider.client_secret}"
            headers["Authorization"] = "Basic " + base64.b64encode(credentials.encode()).decode()
        body = urllib.parse.urlencode(fields).encode()
        status, _, raw = raw_request(self.host, self.port, "POST", "/token", body=body, headers=headers)
        try:
            return status, json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return status, {"_raw": raw.decode("utf-8", "replace")}

    def set_clock_offset(self, offset: float) -> None:
        self.clock.set_offset(offset)
