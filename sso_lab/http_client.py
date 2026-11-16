"""HTTP client used by the RP to call a *pinned* token endpoint.

Deliberate restrictions:

* the URL always comes from the RP's trusted configuration / transaction row,
  never from a callback parameter or a token claim;
* ``http.client`` is used directly, so redirects are never followed and no
  proxy environment variable can silently reroute the request;
* only JSON responses are accepted, with a size cap;
* client authentication uses HTTP Basic (``client_secret_basic``), with the
  credentials pinned per provider.
"""

from __future__ import annotations

import base64
import http.client
import json
import urllib.parse
from dataclasses import dataclass
from typing import Any, Mapping

MAX_RESPONSE_BYTES = 256 * 1024


class ProviderUnavailable(Exception):
    """Transport-level failure: no usable HTTP response."""


class ProviderProtocolError(Exception):
    """Response arrived but was not a well-formed token response."""


@dataclass(frozen=True)
class ProviderResponse:
    status: int
    body: dict[str, Any]
    headers: Mapping[str, str]


def _read_json(response: http.client.HTTPResponse) -> dict[str, Any]:
    ctype = (response.getheader("Content-Type") or "").split(";")[0].strip().lower()
    if ctype != "application/json":
        raise ProviderProtocolError(f"expected JSON token response, got {ctype!r}")
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProviderProtocolError("token response too large")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderProtocolError("token response is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise ProviderProtocolError("token response must be a JSON object")
    return obj


def basic_auth_header(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def post_form(
    url: str,
    fields: Mapping[str, str],
    *,
    basic_auth: tuple[str, str] | None = None,
    timeout: float = 15.0,
) -> ProviderResponse:
    split = urllib.parse.urlsplit(url)
    if split.scheme != "http":
        raise ProviderProtocolError("token endpoint must be plain http in this lab")
    if not split.hostname:
        raise ProviderProtocolError("token endpoint has no host")
    target = split.path + (f"?{split.query}" if split.query else "")
    body = urllib.parse.urlencode(sorted(fields.items())).encode("ascii")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "Connection": "close",
    }
    if basic_auth is not None:
        headers["Authorization"] = basic_auth_header(*basic_auth)

    connection = http.client.HTTPConnection(split.hostname, split.port, timeout=timeout)
    try:
        connection.request("POST", target, body=body, headers=headers)
        response = connection.getresponse()
        payload = _read_json(response)
        return ProviderResponse(response.status, payload, dict(response.getheaders()))
    except (OSError, http.client.HTTPException) as exc:
        raise ProviderUnavailable(f"token endpoint unreachable: {exc}") from exc
    finally:
        connection.close()
