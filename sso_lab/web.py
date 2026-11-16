"""Minimal HTTP plumbing shared by the three services.

Only what the lab needs: a threaded HTTP/1.1 server, cookie handling, strict
query parsing (duplicate parameters are an error, never "last one wins"), and
JSON responses.  No framework, no OAuth client library.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import os
import signal
import socketserver
import sys
import threading
import urllib.parse
from typing import Any, Iterable, Mapping


class StrictQueryError(ValueError):
    pass


def parse_query_single(query: str) -> dict[str, str]:
    """Parse a query string, rejecting duplicate keys.

    OAuth parameters are single-valued; accepting a repeated ``state`` or
    ``iss`` and silently keeping one of them is a classic parameter-pollution
    bug, so this raises instead.
    """
    if not query:
        return {}
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, strict_parsing=False)
    out: dict[str, str] = {}
    for key, value in pairs:
        if key in out:
            raise StrictQueryError(f"duplicate query parameter: {key!r}")
        out[key] = value
    return out


def parse_cookies(header: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not header:
        return out
    for part in header.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        value = value.strip().strip('"')
        if name and name not in out:
            out[name] = value
    return out


def cookie_header(name: str, value: str, *, max_age: int | None = None) -> str:
    parts = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Lax"]
    if max_age is not None:
        parts.append(f"Max-Age={int(max_age)}")
    return "; ".join(parts)


def escape_text(text: Any) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def html_page(title: str, body_html: str, extra_html: str = "") -> bytes:
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{escape_text(title)}</title>
<style>body{{font-family:Consolas,monospace;max-width:62rem;margin:2rem auto;line-height:1.45}}
code{{background:#f2f2f2;padding:0 .2rem}} .bad{{color:#a00}} .ok{{color:#070}}
table{{border-collapse:collapse}} td,th{{border:1px solid #ccc;padding:.15rem .5rem;text-align:left}}</style>
</head><body>
<h1>{escape_text(title)}</h1>
{body_html}
{extra_html}
</body></html>
"""
    return doc.encode("utf-8")


class HttpError(Exception):
    def __init__(self, status: int, message: str, *, headers: Mapping[str, str] | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.headers = dict(headers or {})


class Request:
    """Parsed view of one HTTP request."""

    def __init__(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        self.handler = handler
        self.method = handler.command
        self.path = handler.path
        split = urllib.parse.urlsplit(handler.path)
        self.raw_path = split.path
        self.raw_query = split.query
        self.headers = handler.headers
        self.cookies = parse_cookies(handler.headers.get("Cookie"))
        self._body: bytes | None = None

    def query(self) -> dict[str, str]:
        try:
            return parse_query_single(self.raw_query)
        except StrictQueryError as exc:
            raise HttpError(400, str(exc)) from exc

    def read_body(self, limit: int = 64 * 1024) -> bytes:
        if self._body is not None:
            return self._body
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise HttpError(400, "bad Content-Length")
        if length < 0 or length > limit:
            raise HttpError(413, "request body too large")
        self._body = self.handler.rfile.read(length) if length else b""
        return self._body

    def form(self) -> dict[str, str]:
        raw = self.read_body()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise HttpError(400, "form body is not UTF-8")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype not in ("application/x-www-form-urlencoded", ""):
            raise HttpError(415, "expected application/x-www-form-urlencoded")
        try:
            return parse_query_single(text)
        except StrictQueryError as exc:
            raise HttpError(400, str(exc)) from exc

class BaseHandler(http.server.BaseHTTPRequestHandler):
    server_version = "sso-lab/1.0"
    protocol_version = "HTTP/1.1"
    timeout = 30  # do not let a dead peer pin a worker thread

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("SSO_HTTP_LOG") == "1":
            sys.stderr.write(f"[{getattr(self.server, 'lab_name', 'lab')}] {self.address_string()} {fmt % args}\n")
            sys.stderr.flush()

    # -- response helpers -------------------------------------------------
    def send_bytes(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str = "text/html; charset=utf-8",
        headers: Iterable[tuple[str, str]] = (),
        body_allowed: bool = True,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if body_allowed and body:
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

    def send_json(self, status: int, obj: Any, *, headers: Iterable[tuple[str, str]] = ()) -> None:
        body = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_bytes(status, body, content_type="application/json", headers=headers)

    def send_html(
        self,
        status: int,
        title: str,
        body_html: str,
        *,
        headers: Iterable[tuple[str, str]] = (),
        body_allowed: bool = True,
    ) -> None:
        self.send_bytes(status, html_page(title, body_html), headers=headers, body_allowed=body_allowed)

    def redirect(self, location: str, *, headers: Iterable[tuple[str, str]] = ()) -> None:
        self.send_bytes(302, b"", headers=[("Location", location), *headers])

    def _dispatch(self, body_allowed: bool) -> None:
        try:
            self.handle_request()
        except HttpError as exc:
            self.send_html(
                exc.status,
                "Request rejected",
                f"<p class=bad>{escape_text(exc.message)}</p>",
                headers=list(exc.headers.items()),
                body_allowed=body_allowed,
            )
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch(True)

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch(False)

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch(True)

    def handle_request(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


class LabHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler_cls: type[BaseHandler],
                 *, lab_name: str = "lab") -> None:
        self.lab_name = lab_name
        self.handler_cls = handler_cls
        super().__init__(address, handler_cls)

    def server_bind(self) -> None:
        # ``http.server.HTTPServer.server_bind`` calls ``socket.getfqdn(host)``,
        # i.e. a reverse DNS lookup, which can stall for many seconds on a
        # non-127.0.0.1 loopback address.  The lab never needs the FQDN.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port


def install_signal_handlers(stop: threading.Event) -> None:
    def _handler(signum: int, frame: Any) -> None:
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(ValueError, OSError):
            signal.signal(sig, _handler)
