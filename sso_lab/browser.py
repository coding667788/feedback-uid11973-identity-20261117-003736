"""Automated browser-session simulator.

Each :class:`Browser` owns an independent cookie jar (like a separate browser
profile) and talks to the three services over real HTTP.  It never touches the
RP database: identity is always read back from the RP's ``/me`` endpoint with
whatever cookies that browser holds.

The simulator's useful trick is *interception*: :meth:`Browser.start_login`
follows the redirect chain (RP ``/login`` -> IdP ``/authorize`` -> approval POST
-> IdP redirect) and stops **at** the RP callback URL instead of requesting it.
That is exactly what a real browser does between the IdP redirect and the
network request, and it is what lets a test deliver callback A before callback
B, or hand callback A's URL to a different browser.

CLI::

    python -m sso_lab.browser --rp http://127.0.0.1:8800 --issuer A --user alice
"""

from __future__ import annotations

import argparse
import http.client
import http.cookiejar
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Iterable, Mapping


class SimulationError(RuntimeError):
    pass


class ConnectionDropped(SimulationError):
    """The service accepted the request but the connection died (crash test)."""


class _StopRedirect(Exception):
    def __init__(self, url: str) -> None:
        super().__init__(url)
        self.url = url


class _Intercept(urllib.request.HTTPRedirectHandler):
    """Stop following redirects when the target matches a predicate."""

    def __init__(self, predicate) -> None:
        self.predicate = predicate

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self.predicate(newurl):
            raise _StopRedirect(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: a 3xx surfaces as a normal Response."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.fields: dict[str, str] = {}
        self.actions: list[str] = []
        self._in_form = False
        self._seen_form = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self._in_form = True
            if not self._seen_form:
                self.actions.append(attrs.get("action", ""))
                self._seen_form = True
        elif tag == "input" and self._in_form:
            name = attrs.get("name")
            if name and attrs.get("type", "text") != "submit":
                self.fields.setdefault(name, attrs.get("value", ""))

    def handle_endtag(self, tag):
        if tag == "form":
            self._in_form = False


@dataclass
class Response:
    url: str
    status: int
    headers: Mapping[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def lab_error(self) -> str | None:
        for key, value in self.headers.items():
            if key.lower() == "x-lab-error":
                return value
        return None

    def header(self, name: str) -> str | None:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def json(self):
        return json.loads(self.text)


@dataclass
class PendingLogin:
    """A login that the IdP has redirected back for, but not yet delivered."""

    issuer: str
    username: str
    authorize_url: str
    callback_url: str
    state: str
    code: str
    idp_host: str

    def callback_query(self) -> dict[str, str]:
        return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.callback_url).query))


@dataclass
class Browser:
    name: str
    rp_base: str
    timeout: float = 15.0
    jar: http.cookiejar.CookieJar = field(default_factory=http.cookiejar.CookieJar)
    last_url: str = ""
    history: list[tuple[str, int]] = field(default_factory=list)

    # -- plumbing ---------------------------------------------------------
    def _opener(self, intercept=None):
        handlers = [
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.ProxyHandler({}),
        ]
        if intercept is not None:
            handlers.append(_Intercept(intercept))
        else:
            handlers.append(_NoRedirect())
        return urllib.request.build_opener(*handlers)

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        data: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        intercept=None,
    ) -> Response:
        body = None
        all_headers = {"Accept": "text/html,application/json", "Connection": "close"}
        if data is not None:
            body = urllib.parse.urlencode(data).encode("ascii")
            all_headers["Content-Type"] = "application/x-www-form-urlencoded"
        all_headers.update(headers or {})
        request = urllib.request.Request(url, data=body, method=method, headers=all_headers)
        try:
            with self._opener(intercept).open(request, timeout=self.timeout) as response:
                result = Response(response.geturl(), response.status,
                                  dict(response.headers), response.read())
        except urllib.error.HTTPError as exc:
            result = Response(exc.geturl(), exc.code, dict(exc.headers or {}), exc.read())
        except (http.client.RemoteDisconnected, ConnectionResetError, ConnectionAbortedError) as exc:
            raise ConnectionDropped(f"connection dropped by {url}: {exc!r}") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (ConnectionResetError, ConnectionAbortedError)):
                raise ConnectionDropped(f"connection dropped by {url}: {exc.reason!r}") from exc
            raise SimulationError(f"request to {url} failed: {exc!r}") from exc
        self.last_url = result.url
        self.history.append((result.url, result.status))
        return result

    def get(self, url: str, **kwargs) -> Response:
        return self.request(url, method="GET", **kwargs)

    def navigate(self, url: str, *, max_hops: int = 12) -> Response:
        """GET a URL and follow redirects by hand (visible in ``history``)."""
        current = url
        for _ in range(max_hops):
            response = self.get(current)
            if response.status not in (301, 302, 303, 307, 308):
                return response
            location = response.header("Location")
            if not location:
                raise SimulationError(f"redirect without Location from {current}")
            current = urllib.parse.urljoin(current, location)
        raise SimulationError("too many redirects")

    # -- cookies ----------------------------------------------------------
    def cookie_value(self, name: str) -> str | None:
        for cookie in self.jar:
            if cookie.name == name:
                return cookie.value
        return None

    def cookie_names(self) -> list[str]:
        return sorted({cookie.name for cookie in self.jar})

    # -- flows ------------------------------------------------------------
    def start_login(self, issuer: str, username: str) -> PendingLogin:
        """Begin a login and stop at the RP callback (do not deliver it)."""
        entry = f"{self.rp_base}/login?issuer={urllib.parse.quote(issuer)}"
        response = self.get(entry)
        if response.status != 302:
            raise SimulationError(f"/login did not redirect (status {response.status})")
        authorize_url = urllib.parse.urljoin(entry, response.header("Location") or "")
        if not urllib.parse.urlsplit(authorize_url).query:
            raise SimulationError("authorize URL has no query")

        page = self.get(authorize_url)
        if page.status != 200:
            raise SimulationError(f"authorize page returned {page.status}: {page.text[:300]}")
        parser = _FormParser()
        parser.feed(page.text)
        if "approval_token" not in parser.fields:
            raise SimulationError("IdP login form has no approval_token")

        form_url = urllib.parse.urljoin(authorize_url, parser.actions[0] or "/authorize/approve")
        fields = dict(parser.fields)
        fields["username"] = username
        fields["decision"] = "allow"

        rp_callback_host = urllib.parse.urlsplit(self.rp_base).netloc

        def stop_at_rp(url: str) -> bool:
            split = urllib.parse.urlsplit(urllib.parse.urljoin(form_url, url))
            return split.netloc == rp_callback_host and split.path.startswith("/callback")

        try:
            self.request(form_url, method="POST", data=fields, intercept=stop_at_rp)
        except _StopRedirect as stop:
            callback_url = stop.url
        else:
            raise SimulationError("IdP approval did not redirect to the RP callback")

        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(callback_url).query))
        if query.get("error"):
            raise SimulationError(f"IdP returned error={query['error']}")
        state = query.get("state", "")
        code = query.get("code", "")
        if not state or not code:
            raise SimulationError("callback URL is missing state or code")
        return PendingLogin(
            issuer=issuer,
            username=username,
            authorize_url=authorize_url,
            callback_url=callback_url,
            state=state,
            code=code,
            idp_host=urllib.parse.urlsplit(authorize_url).netloc,
        )

    def deliver(self, pending: PendingLogin, *, headers: Mapping[str, str] | None = None,
                url: str | None = None) -> Response:
        """Request the callback URL (the browser's next real navigation)."""
        return self.get(url or pending.callback_url, headers=headers)

    def login(self, issuer: str, username: str, **kwargs) -> Response:
        return self.deliver(self.start_login(issuer, username), **kwargs)

    # -- identity ---------------------------------------------------------
    def me(self) -> dict | None:
        response = self.get(f"{self.rp_base}/me", headers={"Accept": "application/json"})
        if response.status == 401:
            return None
        if response.status != 200:
            raise SimulationError(f"/me returned {response.status}")
        payload = response.json()
        return payload if payload.get("authenticated") else None

    def sessions(self) -> list[dict]:
        """Every session row this browser's cookie maps to, via /lab/sessions."""
        response = self.get(f"{self.rp_base}/lab/sessions", headers={"Accept": "application/json"})
        if response.status != 200:
            raise SimulationError(f"/lab/sessions returned {response.status}")
        return response.json().get("sessions", [])

    def logout(self) -> None:
        self.request(f"{self.rp_base}/logout", method="POST", data={})


def run_cli(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Drive one browser session over real HTTP")
    parser.add_argument("--rp", default="http://127.0.0.1:8800")
    parser.add_argument("--issuer", default="A", choices=("A", "B"))
    parser.add_argument("--user", default="alice")
    args = parser.parse_args(list(argv) if argv is not None else None)

    browser = Browser("cli", args.rp.rstrip("/"))
    pending = browser.start_login(args.issuer, args.user)
    print(f"intercepted callback: {pending.callback_url}")
    response = browser.deliver(pending)
    print(f"callback status={response.status} lab_error={response.lab_error}")
    identity = browser.me()
    print("identity:", json.dumps(identity, indent=2, sort_keys=True))
    return 0 if identity and identity.get("issuer", "").endswith("/" + args.issuer) else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run_cli())
