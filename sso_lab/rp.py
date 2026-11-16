"""The relying party (business site).

Serves on 127.0.0.1 and is run as **two or more independent worker processes**
sharing one SQLite database.  A supervisor binds the listening socket once and
hands it to each worker, so both processes genuinely accept connections on the
same port.

Login handling in one sentence: every started login is its own database row
keyed by ``state``; at callback time the row is loaded by ``state`` and every
binding is re-checked (browser cookie, callback issuer, exact callback URL,
pinned endpoints), the row is atomically claimed, the code is exchanged at the
token endpoint stored *in that row*, the ID token is verified against the
pinned key of *that issuer*, and only then is one session row committed.

Security properties enforced here
---------------------------------
* No "last state" variable exists anywhere; a second login for the same
  browser is a second row, and both can be in flight at once.
* The token endpoint used for exchange comes from the transaction row, which
  itself came from trusted config.  No callback parameter can redirect the
  exchange.
* ``iss`` must equal the transaction's pinned issuer; ``aud`` must equal the
  pinned client id; ``nonce`` must equal the transaction nonce; ``exp``/``iat``
  are checked with a small leeway.  The HS256 key is looked up by pinned
  issuer, never by anything the token says.
* Identity is ``(issuer, subject)``.  E-mail is display-only.
* At most one session is created per callback burst: the claim is an atomic
  conditional UPDATE, and the session insert plus the transaction's terminal
  state are committed together.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import sys
import urllib.parse
from dataclasses import dataclass

from . import jwt, testhooks, tokens
from .clock import Clock, SharedOffsetClock
from .db import one, write_txn
from .errors import (
    BrowserMismatchError,
    CallbackError,
    IssuerMismatchError,
    ReplayError,
    StateError,
    TransactionError,
)
from .http_client import ProviderUnavailable, post_form
from .liveness import process_alive
from .schema import connect_rp
from .web import (
    BaseHandler,
    HttpError,
    LabHTTPServer,
    Request,
    cookie_header,
    escape_text,
)

MAX_CODE_LENGTH = 256
MAX_STATE_LENGTH = 512
# A claim left behind by a worker that died is recoverable after this long.
ABANDONED_CLAIM_GRACE_SECONDS = 1.0
# No genuine exchange takes this long (the token call times out at 15 s), so an
# older claim is abandoned even if the pid looks alive -- this also covers a
# recycled pid, where "is the claimant alive?" would answer yes for a stranger.
CLAIM_MAX_AGE_SECONDS = 120.0


@dataclass(frozen=True)
class Txn:
    state: str
    browser_sid: str
    issuer_key: str
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    client_id: str
    redirect_uri: str
    nonce: str
    pkce_verifier: str
    pkce_challenge: str
    created_at: float
    expires_at: float
    status: str
    consumed_at: float | None
    claim_pid: int | None
    claimed_at: float | None


class RelyingParty:
    def __init__(self, config, *, clock: Clock | None = None) -> None:
        self.config = config
        self.rp = config.rp
        self.providers = config.providers
        self.db_path = config.database_path
        if clock is not None:
            self.clock = clock
        elif testhooks.enabled():
            self.clock = SharedOffsetClock(config.runtime_dir / "rp_clock_offset.txt")
        else:
            self.clock = Clock.from_env()
        self.server: LabHTTPServer | None = None

    # ------------------------------------------------------------------
    # database / server plumbing
    # ------------------------------------------------------------------
    def db(self) -> sqlite3.Connection:
        return connect_rp(self.db_path)

    def bootstrap(self) -> None:
        conn = self.db()
        conn.close()

    def make_server(self, host: str, port: int, sock=None) -> LabHTTPServer:
        service = self

        class Handler(BaseHandler):
            def handle_request(self) -> None:
                service.handle(Request(self), self)

        server = LabHTTPServer((host, port), Handler, lab_name="rp")
        if sock is not None:
            server.socket.close()
            server.socket = sock
            server.server_address = sock.getsockname()
        self.server = server
        return server

    def handle(self, request: Request, handler: BaseHandler) -> None:
        try:
            self._route(request, handler)
        except HttpError as exc:
            handler.send_html(
                exc.status,
                "Request rejected",
                f"<p class=bad>{escape_text(exc.message)}</p>",
                headers=[("X-Lab-Error", "bad_request")],
            )
        except CallbackError as exc:  # safety net; normally handled in-place
            handler.send_html(
                exc.http_status,
                "Sign-in failed",
                f"<p class=bad>{escape_text(exc.message)}</p>",
                headers=[("X-Lab-Error", exc.code)],
            )
        except Exception as exc:  # pragma: no cover - defensive
            sys.stderr.write(f"[rp] unhandled error pid={os.getpid()}: {exc!r}\n")
            sys.stderr.flush()
            handler.send_html(
                500,
                "Internal error",
                "<p class=bad>The request failed. No login session was established.</p>",
                headers=[("X-Lab-Error", "internal_error")],
            )

    def _route(self, request: Request, handler: BaseHandler) -> None:
        path = request.raw_path
        if path == "/" and request.method in ("GET", "HEAD"):
            self.handle_home(request, handler)
        elif path == "/login" and request.method == "GET":
            self.handle_login(request, handler)
        elif path == "/callback" and request.method == "GET":
            self.handle_callback(request, handler)
        elif path == "/me" and request.method == "GET":
            self.handle_me(request, handler)
        elif path == "/logout" and request.method == "POST":
            self.handle_logout(request, handler)
        elif path == "/healthz":
            handler.send_json(200, {"ok": True, "pid": os.getpid(), "db": str(self.db_path)})
        elif path == "/lab/sessions":
            self.handle_lab_sessions(request, handler)
        elif path == "/lab/stats":
            self.handle_lab_stats(request, handler)
        elif path == "/lab/clock":
            self.handle_lab_clock(request, handler)
        else:
            raise HttpError(404, "not found")

    # ------------------------------------------------------------------
    # lab-only introspection (test hooks must be enabled)
    # ------------------------------------------------------------------
    def handle_lab_sessions(self, request: Request, handler: BaseHandler) -> None:
        """Return the session rows that belong to the caller's own cookie.

        Only rows for *this* browser's cookie are returned, so it cannot be
        used to read another browser's session, and it is read-only.  It exists
        so the simulator can prove "at most one session" without touching the
        database.
        """
        if not testhooks.enabled():
            raise HttpError(404, "not found")
        browser_sid = request.cookies.get(self.rp.browser_cookie)
        conn = self.db()
        try:
            rows = []
            if browser_sid:
                rows = [
                    {
                        "issuer": row["issuer"],
                        "subject": row["subject"],
                        "session_id": row["session_id"],
                        "email": row["email"],
                        "created_at": row["created_at"],
                    }
                    for row in conn.execute(
                        "SELECT issuer, subject, session_id, email, created_at FROM login_sessions "
                        "WHERE browser_sid = ? ORDER BY created_at ASC",
                        (browser_sid,),
                    )
                ]
            txns = []
            if browser_sid:
                txns = [
                    {
                        "issuer_key": row["issuer_key"],
                        "state": row["state"],
                        "status": row["status"],
                        "expires_at": row["expires_at"],
                    }
                    for row in conn.execute(
                        "SELECT issuer_key, state, status, expires_at FROM login_txns "
                        "WHERE browser_sid = ? ORDER BY created_at ASC",
                        (browser_sid,),
                    )
                ]
        finally:
            conn.close()
        handler.send_json(200, {"sessions": rows, "transactions": txns})

    def handle_lab_clock(self, request: Request, handler: BaseHandler) -> None:
        """Shift this worker's clock (test scaffolding, ``SSO_TEST_HOOKS=1`` only).

        Used to walk the ID-token expiry boundary deterministically.  The RP
        never accepts time from a peer; only the test harness calls this, and
        only in a process explicitly started with test hooks enabled.
        """
        if not testhooks.enabled():
            raise HttpError(404, "not found")
        query = request.query()
        try:
            offset = float(query["offset"])
        except (KeyError, ValueError):
            raise HttpError(400, "offset=<seconds> required")
        self.clock.set_offset(offset)
        handler.send_json(200, {"offset": self.clock.offset, "now": self.clock.now(),
                                "pid": os.getpid()})

    def handle_lab_stats(self, request: Request, handler: BaseHandler) -> None:
        """Aggregate counts, used by the test runner to assert "one session"."""
        if not testhooks.enabled():
            raise HttpError(404, "not found")
        conn = self.db()
        try:
            sessions = conn.execute("SELECT COUNT(*) FROM login_sessions").fetchone()[0]
            attempts = conn.execute("SELECT COUNT(*) FROM callback_attempts").fetchone()[0]
            outcomes = {
                row[0]: row[1]
                for row in conn.execute(
                    "SELECT outcome, COUNT(*) FROM callback_attempts GROUP BY outcome"
                )
            }
            txns = {
                row[0]: row[1]
                for row in conn.execute("SELECT status, COUNT(*) FROM login_txns GROUP BY status")
            }
        finally:
            conn.close()
        handler.send_json(200, {"sessions": sessions, "attempts": attempts,
                                "outcomes": outcomes, "txn_status": txns})
        return

    # ------------------------------------------------------------------
    # read helpers
    # ------------------------------------------------------------------
    def current_session(self, conn: sqlite3.Connection, browser_sid: str | None) -> sqlite3.Row | None:
        if not browser_sid:
            return None
        return one(
            conn,
            "SELECT * FROM login_sessions WHERE browser_sid = ? AND expires_at > ? "
            "ORDER BY created_at DESC, id DESC LIMIT 1",
            (browser_sid, self.clock.now()),
        )

    # ------------------------------------------------------------------
    # GET / -- home page
    # ------------------------------------------------------------------
    def handle_home(self, request: Request, handler: BaseHandler) -> None:
        browser_sid = request.cookies.get(self.rp.browser_cookie)
        conn = self.db()
        try:
            session = self.current_session(conn, browser_sid)
            pending = []
            all_sessions = []
            if browser_sid:
                pending = list(
                    conn.execute(
                        "SELECT issuer_key, state, status, expires_at FROM login_txns "
                        "WHERE browser_sid = ? AND status IN ('pending','consuming','failed') "
                        "AND created_at > ? ORDER BY created_at ASC",
                        (browser_sid, self.clock.now() - 600),
                    ).fetchall()
                )
                all_sessions = list(
                    conn.execute(
                        "SELECT issuer, subject, display_name, created_at FROM login_sessions "
                        "WHERE browser_sid = ? ORDER BY created_at DESC",
                        (browser_sid,),
                    ).fetchall()
                )
        finally:
            conn.close()

        if session:
            who = (
                "<p class=ok>Signed in as "
                f"<b>{escape_text(session['display_name'])}</b> "
                f"&lt;{escape_text(session['email'])}&gt;<br>"
                f"issuer=<code>{escape_text(session['issuer'])}</code> "
                f"subject=<code>{escape_text(session['subject'])}</code> "
                f"session=<code>{escape_text(session['session_id'][:12])}…</code></p>"
                '<form method="post" action="/logout">'
                '<button type="submit">Sign out</button></form>'
            )
        else:
            who = "<p class=bad>Not signed in.</p>"

        buttons = "".join(
            f'<p><a href="/login?issuer={name}">Sign in with provider {name}</a> '
            f'<code>{escape_text(self.providers[name].issuer)}</code></p>'
            for name in ("A", "B")
        )
        browser = (
            f"<p>Browser session cookie (<code>{escape_text(self.rp.browser_cookie)}</code>): "
            f"<code>{escape_text(browser_sid[:12])}…</code></p>"
            if browser_sid
            else "<p>No browser session cookie yet; one is created when you start a login.</p>"
        )
        txns = ""
        if pending:
            rows = "".join(
                f"<tr><td>{escape_text(r['issuer_key'])}</td>"
                f"<td><code>{escape_text(r['state'][:14])}…</code></td>"
                f"<td>{escape_text(r['status'])}</td></tr>"
                for r in pending
            )
            txns = (
                "<h2>Login transactions started by this browser</h2>"
                "<table><tr><th>provider</th><th>state</th><th>status</th></tr>"
                f"{rows}</table>"
            )
        history = ""
        if all_sessions:
            rows = "".join(
                f"<tr><td>{escape_text(s['issuer'])}</td><td>{escape_text(s['subject'])}</td>"
                f"<td>{escape_text(s['display_name'])}</td></tr>"
                for s in all_sessions
            )
            history = (
                "<h2>Sessions held by this browser</h2>"
                "<table><tr><th>issuer</th><th>subject</th><th>who</th></tr>"
                f"{rows}</table>"
            )
        handler.send_html(
            200,
            "SSO lab business site (RP)",
            who + "<h2>Sign in</h2>" + buttons + browser + txns + history,
        )

    # ------------------------------------------------------------------
    # GET /login -- start one authentication transaction
    # ------------------------------------------------------------------
    def handle_login(self, request: Request, handler: BaseHandler) -> None:
        query = request.query()
        issuer_key = query.get("issuer", "")
        if issuer_key not in self.providers:
            raise HttpError(400, "issuer must be A or B")
        provider = self.providers[issuer_key]

        browser_sid = request.cookies.get(self.rp.browser_cookie)
        if not tokens.is_valid_opaque_token(browser_sid):
            browser_sid = tokens.random_token(32)
        set_cookie = (
            "Set-Cookie",
            cookie_header(self.rp.browser_cookie, browser_sid, max_age=7 * 24 * 3600),
        )

        state = tokens.random_token(32)
        nonce = tokens.random_token(32)
        verifier = tokens.random_pkce_verifier()
        challenge = tokens.pkce_challenge_s256(verifier)
        redirect_uri = self.rp.callback_url_for[issuer_key]
        now = self.clock.now()
        ttl = float(self.rp.transaction_ttl_seconds)
        conn = self.db()
        try:
            with write_txn(conn):
                conn.execute(
                    """INSERT INTO login_txns (state, browser_sid, issuer_key, issuer,
                           authorization_endpoint, token_endpoint, client_id, redirect_uri,
                           nonce, pkce_verifier, pkce_challenge, created_at,
                           expires_at, status, consumed_at, claim_pid, claimed_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',NULL,NULL,NULL)""",
                    (state, browser_sid, issuer_key, provider.issuer,
                     provider.authorization_endpoint, provider.token_endpoint,
                     provider.client_id, redirect_uri, nonce, verifier, challenge,
                     now, now + ttl),
                )
                self._event(conn, "login_started", f"issuer={issuer_key} state={state[:12]}")
            # Collapse old, never-finished transactions for this browser so the
            # table does not grow without bound.  Only 'pending' rows whose
            # transaction window has closed are touched.
            with write_txn(conn):
                conn.execute(
                    "UPDATE login_txns SET status = 'failed' WHERE browser_sid = ? "
                    "AND status = 'pending' AND expires_at <= ?",
                    (browser_sid, now),
                )
        finally:
            conn.close()

        params = {
            "response_type": "code",
            "client_id": provider.client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "openid",
        }
        location = provider.authorization_endpoint + "?" + urllib.parse.urlencode(params)
        handler.redirect(location, headers=[set_cookie])

    # ------------------------------------------------------------------
    # GET /callback
    # ------------------------------------------------------------------
    def handle_callback(self, request: Request, handler: BaseHandler) -> None:
        query = request.query()
        callback_id = tokens.random_token(16)
        pid = os.getpid()
        browser_sid = request.cookies.get(self.rp.browser_cookie)
        state = query.get("state", "")
        code = query.get("code", "")
        issuer_param = query.get("issuer", "")

        conn = self.db()
        session_id: str | None = None
        try:
            with write_txn(conn):
                conn.execute(
                    "INSERT INTO callback_attempts (callback_id, state, browser_sid, issuer_key,"
                    " outcome, reason, wsgi_pid, session_id, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (callback_id, state[:MAX_STATE_LENGTH], browser_sid,
                     issuer_param if issuer_param in self.providers else None,
                     "started", None, pid, None, self.clock.now()),
                )

            # ---- 1. bind state + browser + callback issuer to the txn ----
            try:
                txn = self._precheck(conn, browser_sid, issuer_param, state, code)
            except ReplayError as exc:
                self._finish_attempt(conn, callback_id, "duplicate", exc.code)
                self._render_replay(handler, exc.message)
                return
            except CallbackError as exc:
                self._finish_attempt(conn, callback_id, "rejected", exc.code)
                self._render_rejection(handler, exc)
                return

            # ---- 2. atomically claim it; exactly one worker proceeds ----
            if not self._claim(conn, txn):
                self._finish_attempt(conn, callback_id, "duplicate", "claim lost")
                self._render_replay(handler, "already being completed by another request")
                return

            # ---- 3. exchange the code at the endpoint pinned in the txn ---
            testhooks.sleep_if_requested(request.headers.get("X-Lab-Delay"))
            try:
                token_response = post_form(
                    txn.token_endpoint,
                    {
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": txn.redirect_uri,
                        "code_verifier": txn.pkce_verifier,
                    },
                    basic_auth=(self.providers[txn.issuer_key].client_id,
                                self.providers[txn.issuer_key].client_secret),
                    timeout=15.0,
                )
            except ProviderUnavailable as exc:
                self._fail_txn(conn, txn, "provider_unavailable")
                self._finish_attempt(conn, callback_id, "error", str(exc))
                handler.send_html(
                    502,
                    "Sign-in failed",
                    "<p class=bad>The identity provider's token endpoint could not be "
                    "reached.</p><p>The login transaction was closed; no session was "
                    "created. Please sign in again.</p>",
                    headers=[("X-Lab-Error", "provider_unavailable")],
                )
                return

            if token_response.status != 200:
                provider_error = token_response.body.get("error", "unexpected_status")
                self._fail_txn(conn, txn, f"token_error:{provider_error}")
                self._finish_attempt(conn, callback_id, "error", f"token_endpoint:{token_response.status}")
                handler.send_html(
                    401,
                    "Sign-in failed",
                    "<p class=bad>The authorization code could not be exchanged at the "
                    f"token endpoint of provider <b>{escape_text(txn.issuer_key)}</b> "
                    f"(<code>{escape_text(str(provider_error))}</code>).</p>"
                    "<p>This transaction is closed and no login session was created. "
                    "Please sign in again.</p>",
                    headers=[("X-Lab-Error", "token_exchange_failed")],
                )
                return

            id_token = token_response.body.get("id_token")
            if not isinstance(id_token, str) or not id_token:
                self._fail_txn(conn, txn, "missing_id_token")
                self._finish_attempt(conn, callback_id, "error", "missing id_token")
                handler.send_html(
                    400,
                    "Sign-in failed",
                    "<p class=bad>The token response contained no ID token.</p>",
                    headers=[("X-Lab-Error", "missing_id_token")],
                )
                return

            # ---- 4. verify signature, iss, aud, nonce, time --------------
            provider = self.providers[txn.issuer_key]
            try:
                verified = jwt.verify_hs256_id_token(
                    id_token,
                    key=provider.hs256_key,
                    expected_issuer=txn.issuer,
                    expected_audience=provider.audience,
                    expected_nonce=txn.nonce,
                    now=self.clock.epoch(),
                    leeway=int(self.rp.clock_skew_seconds),
                )
            except jwt.TokenValidationError as exc:
                self._fail_txn(conn, txn, f"id_token_invalid:{exc.code}")
                self._finish_attempt(conn, callback_id, "rejected", str(exc))
                handler.send_html(
                    401,
                    "Sign-in failed",
                    "<p class=bad>ID token verification failed: "
                    f"{escape_text(exc.message)}</p>"
                    "<p>No login session was created and this transaction is closed.</p>",
                    headers=[("X-Lab-Error", "invalid_id_token")],
                )
                return

            self._event(conn, "id_token_verified",
                        f"issuer={txn.issuer_key} sub={verified.subject}")

            # ---- test sync point #1: verified, nothing committed yet ----
            # X-Lab-Crash makes this process exit itself; X-Lab-Hold parks it so
            # the harness can hard-kill it from outside.  Both are gated on
            # SSO_TEST_HOOKS=1 and never reachable in normal operation.
            if testhooks.crash_requested("after-verify", request.headers.get("X-Lab-Crash")):
                testhooks.die("after-verify")
            if testhooks.hold_requested("after-verify", request.headers.get("X-Lab-Hold")):
                testhooks.hold("after-verify", txn.state[:12])

            # ---- 5. one commit: session row + transaction closure --------
            session_id = self._commit_session(conn, txn, verified, id_token)

            # ---- test sync point #2: committed, response never sent ------
            if testhooks.crash_requested("after-commit", request.headers.get("X-Lab-Crash")):
                testhooks.die("after-commit")
            if testhooks.hold_requested("after-commit", request.headers.get("X-Lab-Hold")):
                testhooks.hold("after-commit", txn.state[:12])

            self._finish_attempt(conn, callback_id, "established", "ok", session_id)
            # Report the identity this callback established, not "the newest
            # session in the browser" (a concurrent login may be newer).
            session = one(
                conn,
                "SELECT * FROM login_sessions WHERE browser_sid = ? AND session_id = ?",
                (browser_sid, session_id),
            )
            pending = list(
                conn.execute(
                    "SELECT issuer_key, state FROM login_txns WHERE browser_sid = ? "
                    "AND status = 'pending' AND expires_at > ? ORDER BY created_at ASC",
                    (browser_sid, self.clock.now()),
                ).fetchall()
            )
        finally:
            conn.close()

        body = self._identity_block(session) if session else ""
        others = ""
        if pending:
            items = "".join(
                f"<li>provider {escape_text(row['issuer_key'])} — state "
                f"<code>{escape_text(row['state'][:14])}…</code> — still pending</li>"
                for row in pending
            )
            others = f"<h2>Other in-flight logins in this browser</h2><ul>{items}</ul>"
        # No second "session cookie": a browser may legitimately hold one
        # session per issuer (A and B side by side), so sessions are looked up
        # by the browser cookie plus the composite (issuer, subject) key.
        handler.send_html(
            200,
            "Sign-in complete",
            "<p class=ok>Login established.</p>" + body + others,
            headers=[("X-Lab-Error", "none")],
        )

    # -- step 1: bindings -------------------------------------------------
    def _precheck(self, conn: sqlite3.Connection, browser_sid, issuer_param, state, code) -> Txn:
        if not tokens.is_valid_opaque_token(browser_sid):
            raise StateError("callback arrived without a valid RP browser cookie")
        if issuer_param not in self.providers:
            raise StateError("callback is missing a valid issuer parameter")
        if not state or len(state) > MAX_STATE_LENGTH:
            raise StateError("callback is missing a valid state")
        if not code or len(code) > MAX_CODE_LENGTH:
            raise StateError("callback is missing a valid code")

        row = one(conn, "SELECT * FROM login_txns WHERE state = ?", (state,))
        if row is None:
            raise StateError("state does not match any login transaction")
        txn = Txn(**{key: row[key] for key in row.keys()})

        if not _constant_time_eq(txn.browser_sid, browser_sid):
            raise BrowserMismatchError("state was issued to a different browser session")
        if txn.issuer_key != issuer_param:
            raise IssuerMismatchError(
                f"issuer mismatch: callback names {issuer_param!r} but the transaction "
                f"was started for {txn.issuer_key!r}"
            )
        if txn.redirect_uri != self.rp.callback_url_for[txn.issuer_key]:
            raise TransactionError("transaction redirect_uri is not the pinned callback URL")
        if txn.status == "done":
            raise ReplayError("this login transaction has already been completed",)
        if txn.status == "consuming":
            # A claim left by a live worker is genuinely in flight, so this
            # callback is a duplicate of a request being processed right now.
            # A claim left by a dead worker (crashed process) can never
            # complete, so close it and ask the user to sign in again.
            if self._claim_is_abandoned(txn):
                self._mark_abandoned(conn, txn)
                raise TransactionError(
                    "the worker handling this login terminated before finishing; "
                    "please sign in again"
                )
            raise ReplayError("this login transaction is being completed by another request")
        if txn.status != "pending":
            raise TransactionError("this login transaction is closed")
        if self.clock.now() >= txn.expires_at:
            raise TransactionError("this login transaction has expired")

        provider = self.providers[txn.issuer_key]
        if txn.token_endpoint != provider.token_endpoint or txn.issuer != provider.issuer:
            raise TransactionError("transaction bindings no longer match pinned configuration")
        return txn

    def _claim_is_abandoned(self, txn: Txn) -> bool:
        if txn.claim_pid is None or txn.claimed_at is None:
            return False
        age = self.clock.now() - txn.claimed_at
        if age < ABANDONED_CLAIM_GRACE_SECONDS:
            return False
        if age > CLAIM_MAX_AGE_SECONDS:
            return True
        if txn.claim_pid == os.getpid():
            return False  # this worker could still be finishing the request
        return not process_alive(txn.claim_pid)

    def _mark_abandoned(self, conn: sqlite3.Connection, txn: Txn) -> None:
        with write_txn(conn):
            conn.execute(
                "UPDATE login_txns SET status = 'failed', consumed_at = ? "
                "WHERE state = ? AND status = 'consuming'",
                (self.clock.now(), txn.state),
            )
            self._event(conn, "txn_abandoned", f"state={txn.state[:12]} claim_pid={txn.claim_pid}")

    # -- step 2: claim ----------------------------------------------------
    def _claim(self, conn: sqlite3.Connection, txn: Txn) -> bool:
        with write_txn(conn):
            cursor = conn.execute(
                "UPDATE login_txns SET status = 'consuming', claim_pid = ?, claimed_at = ? "
                "WHERE state = ? AND status = 'pending' AND expires_at > ?",
                (os.getpid(), self.clock.now(), txn.state, self.clock.now()),
            )
            return cursor.rowcount == 1

    def _fail_txn(self, conn: sqlite3.Connection, txn: Txn, reason: str) -> None:
        with write_txn(conn):
            conn.execute(
                "UPDATE login_txns SET status = 'failed', consumed_at = ? "
                "WHERE state = ? AND status = 'consuming'",
                (self.clock.now(), txn.state),
            )
            self._event(conn, "txn_failed", f"state={txn.state[:12]} reason={reason[:160]}")

    # -- step 5: commit ---------------------------------------------------
    def _commit_session(self, conn: sqlite3.Connection, txn: Txn, verified, id_token: str) -> str:
        session_id = tokens.random_token(32)
        token_hash = hashlib.sha256(id_token.encode("ascii")).hexdigest()
        now = self.clock.now()
        expires = now + float(self.rp.session_ttl_seconds)
        claims = verified.claims
        email = claims.get("email") if isinstance(claims.get("email"), str) else None
        display = claims.get("name") if isinstance(claims.get("name"), str) else None
        with write_txn(conn):
            current = one(conn, "SELECT status FROM login_txns WHERE state = ?", (txn.state,))
            if current is None or current["status"] != "consuming":
                raise TransactionError("login transaction lost its claim before commit")
            conn.execute(
                """INSERT INTO login_sessions (session_id, browser_sid, issuer, subject,
                       email, display_name, id_token_hash, state, created_at, expires_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT (browser_sid, issuer, subject) DO UPDATE SET
                       session_id = excluded.session_id,
                       id_token_hash = excluded.id_token_hash,
                       email = excluded.email,
                       display_name = excluded.display_name,
                       state = excluded.state,
                       created_at = excluded.created_at,
                       expires_at = excluded.expires_at""",
                (session_id, txn.browser_sid, verified.issuer, verified.subject, email,
                 display, token_hash, txn.state, now, expires),
            )
            cursor = conn.execute(
                "UPDATE login_txns SET status = 'done', consumed_at = ? "
                "WHERE state = ? AND status = 'consuming'",
                (now, txn.state),
            )
            if cursor.rowcount != 1:
                raise TransactionError("login transaction left 'consuming' state before commit")
            self._event(
                conn, "session_committed",
                f"issuer={verified.issuer} sub={verified.subject} state={txn.state[:12]}",
            )
        return session_id

    # -- audit helpers ----------------------------------------------------
    def _event(self, conn: sqlite3.Connection, kind: str, detail: str, pid: int | None = None) -> None:
        conn.execute(
            "INSERT INTO rp_events (kind, detail, wsgi_pid, created_at) VALUES (?,?,?,?)",
            (kind, detail[:500], pid if pid is not None else os.getpid(), self.clock.now()),
        )

    def _finish_attempt(self, conn, callback_id: str, outcome: str, reason: str | None,
                        session_id: str | None = None) -> None:
        with write_txn(conn):
            conn.execute(
                "UPDATE callback_attempts SET outcome = ?, reason = ?, session_id = ? "
                "WHERE callback_id = ?",
                (outcome, (reason or "")[:500], session_id, callback_id),
            )

    # -- rejection pages --------------------------------------------------
    def _render_rejection(self, handler: BaseHandler, exc: CallbackError) -> None:
        handler.send_html(
            400,
            "Callback rejected",
            f"<p class=bad>{escape_text(exc.message)}</p>"
            "<p>No login session was created, and no other login transaction was "
            "consumed by this request.</p>"
            '<p><a href="/">Back to the business site</a></p>',
            # One stable family header for the simulator, plus the specific
            # reason, so a caller can tell "wrong browser" from "wrong issuer".
            headers=[("X-Lab-Error", "invalid_callback"), ("X-Lab-Reason", exc.code)],
        )

    def _render_replay(self, handler: BaseHandler, detail: str) -> None:
        handler.send_html(
            409,
            "Callback already processed",
            "<p class=bad>This callback does not establish a login.</p>"
            f"<p>The transaction is {escape_text(detail)}. A replayed callback never "
            "creates or refreshes a session.</p>"
            '<p><a href="/">Back to the business site</a></p>',
            headers=[("X-Lab-Error", "replayed_callback")],
        )

    # ------------------------------------------------------------------
    # /me and /logout
    # ------------------------------------------------------------------
    def _identity_block(self, session: sqlite3.Row) -> str:
        return (
            f"<p>issuer=<code>{escape_text(session['issuer'])}</code><br>"
            f"subject=<code>{escape_text(session['subject'])}</code><br>"
            f"display=<b>{escape_text(session['display_name'])}</b><br>"
            f"email=<code>{escape_text(session['email'])}</code><br>"
            f"session=<code>{escape_text(session['session_id'])}</code></p>"
        )

    def handle_me(self, request: Request, handler: BaseHandler) -> None:
        browser_sid = request.cookies.get(self.rp.browser_cookie)
        conn = self.db()
        try:
            session = self.current_session(conn, browser_sid)
        finally:
            conn.close()
        if not session:
            handler.send_json(401, {"authenticated": False, "pid": os.getpid()})
            return
        handler.send_json(
            200,
            {
                "authenticated": True,
                "issuer": session["issuer"],
                "subject": session["subject"],
                "email": session["email"],
                "display_name": session["display_name"],
                "session_id": session["session_id"],
                "browser_sid": session["browser_sid"],
                "pid": os.getpid(),
            },
        )

    def handle_logout(self, request: Request, handler: BaseHandler) -> None:
        browser_sid = request.cookies.get(self.rp.browser_cookie)
        if browser_sid:
            conn = self.db()
            try:
                with write_txn(conn):
                    conn.execute("DELETE FROM login_sessions WHERE browser_sid = ?", (browser_sid,))
            finally:
                conn.close()
        handler.send_bytes(303, b"", headers=[("Location", "/")])


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def _constant_time_eq(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


