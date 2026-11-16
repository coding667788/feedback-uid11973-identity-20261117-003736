"""Crash tests: real process termination at two named points.

Both points are reached only with ``SSO_TEST_HOOKS=1``; the RP calls
``os._exit``, so there is no exception handling, no ``finally`` block and no
cleanup -- exactly the "process died" scenario.

Point 1 ``after-verify``
    The ID token has been verified; nothing has been committed (no session
    row, the transaction is still claimed).  The authorization code has already
    been consumed at the provider.  After restart: no session exists, the
    replay is refused, the state binding is still enforced, and a fresh login
    is required and works.

Point 2 ``after-commit``
    The session row and the transaction's terminal state are committed; the
    HTTP response was never written.  After restart: exactly one session
    exists and a replay of the same callback creates no second session.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import unittest
import urllib.parse

import support  # noqa: F401  (path setup + test hooks)
from support import ROOT, raw_request

from sso_lab import procs
from sso_lab.browser import Browser
from sso_lab.harness import _http_json, start_lab

LAB = None
RUNTIME = ROOT / "runtime" / "tests" / "crash"


def setUpModule():
    global LAB
    LAB = start_lab(root_dir=ROOT, runtime_dir=RUNTIME, workers=2, code_ttl=60)


def tearDownModule():
    if LAB is not None:
        LAB.stop()


def lab_stats() -> dict:
    status, payload = _http_json(f"{LAB.rp_base}/lab/stats", timeout=5)
    assert status == 200, status
    return payload


def db_sessions() -> list[sqlite3.Row]:
    """Read-only inspection of the shared RP database (test-side only)."""
    conn = sqlite3.connect(str(LAB.runtime_dir / "sso_lab.sqlite3"), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        return list(conn.execute("SELECT * FROM login_sessions ORDER BY id").fetchall())
    finally:
        conn.close()


def db_txn(state: str) -> sqlite3.Row | None:
    conn = sqlite3.connect(str(LAB.runtime_dir / "sso_lab.sqlite3"), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM login_txns WHERE state = ?", (state,)).fetchone()
    finally:
        conn.close()


def deliver_with_crash(browser: Browser, pending, crash_point: str, *, hold: str | None = None):
    """Deliver the callback with the crash/hold header; return what the client saw."""
    url = pending.callback_url
    path = urllib.parse.urlsplit(url).path + "?" + urllib.parse.urlsplit(url).query
    headers = {"Cookie": f"rp_sid={browser.cookie_value('rp_sid')}"}
    if hold:
        headers["X-Lab-Hold"] = hold
    else:
        headers["X-Lab-Crash"] = crash_point
    try:
        status, response_headers, body = raw_request(
            "127.0.0.1", LAB.rp_port, "GET", path, headers=headers, timeout=30,
        )
        return {"status": status, "headers": response_headers,
                "body": body.decode("utf-8", "replace")}
    except (ConnectionError, OSError) as exc:  # connection died mid-response
        return {"status": None, "error": repr(exc)}


def wait_for_worker_replacement(timeout: float = 15.0) -> list[int]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        pids = set()
        for _ in range(40):
            status, payload = _http_json(f"{LAB.rp_base}/healthz", timeout=1.0)
            if status == 200 and payload:
                pids.add(payload["pid"])
        if len(pids) >= 2:
            return sorted(pids)
        time.sleep(0.2)
    raise AssertionError("RP workers did not come back")


class CrashAfterVerify(unittest.TestCase):
    def test_crash_after_verify_leaves_no_session_and_forces_relogin(self):
        browser = Browser("crash-verify", LAB.rp_base)
        pending = browser.start_login("A", "alice")
        sessions_before = len(db_sessions())

        pid_before = set(_all_worker_pids())
        observed = deliver_with_crash(browser, pending, "after-verify")
        # The worker process really died: either the connection dropped or the
        # request never produced a normal response.
        self.assertTrue(observed["status"] is None or observed["status"] >= 500,
                        observed)

        # The specific worker that handled the request is gone.
        deadline = time.time() + 10
        while time.time() < deadline and set(_all_worker_pids()) == pid_before:
            time.sleep(0.1)
        self.assertTrue(
            any(pid not in _all_worker_pids() for pid in pid_before),
            f"no RP worker died (was {pid_before}, now {_all_worker_pids()})",
        )

        # No partial login state: no session, transaction not 'done'.
        self.assertEqual(len(db_sessions()), sessions_before)
        row = db_txn(pending.state)
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "consuming")
        self.assertIsNotNone(row["claim_pid"])
        self.assertNotEqual(row["claim_pid"], 0)

        # After restart: the browser has no session...
        new_pids = wait_for_worker_replacement()
        self.assertTrue(new_pids)
        self.assertIsNone(browser.me())

        # ...the replay cannot create one (and is told to sign in again)...
        replay = browser.deliver(pending)
        self.assertEqual(replay.status, 400)
        self.assertEqual(replay.lab_error, "invalid_callback")
        self.assertEqual(replay.header("X-Lab-Reason"), "invalid_transaction")
        self.assertIn("terminated before finishing", replay.text)
        self.assertIsNone(browser.me())
        self.assertEqual(len(db_sessions()), sessions_before)

        # ...another browser cannot use the state either...
        other = Browser("crash-verify-other", LAB.rp_base)
        other.start_login("A", "alice")  # gives it its own cookie
        foreign = other.get(pending.callback_url)
        self.assertEqual(foreign.status, 400)
        self.assertIsNone(other.me())

        # ...and a fresh login is required and works.
        fresh = browser.start_login("A", "alice")
        response = browser.deliver(fresh)
        self.assertEqual(response.status, 200, response.text[:300])
        identity = browser.me()
        self.assertIsNotNone(identity)
        self.assertEqual(identity["subject"], "user-1001")


class CrashAfterCommit(unittest.TestCase):
    def test_crash_after_commit_keeps_one_session_and_replay_is_refused(self):
        browser = Browser("crash-commit", LAB.rp_base)
        pending = browser.start_login("B", "alice")
        sessions_before = len(db_sessions())

        observed = deliver_with_crash(browser, pending, "after-commit")
        self.assertTrue(observed["status"] is None or observed["status"] >= 500, observed)

        # The commit really happened: exactly one new session, transaction done.
        sessions = db_sessions()
        self.assertEqual(len(sessions), sessions_before + 1)
        row = db_txn(pending.state)
        self.assertEqual(row["status"], "done")

        wait_for_worker_replacement()

        # The browser never got the response, but a fresh request sees the
        # session: the commit is durable and not "half applied".
        identity = browser.me()
        self.assertIsNotNone(identity)
        self.assertTrue(identity["issuer"].endswith("/issuer/B"))
        session_id = identity["session_id"]
        self.assertEqual(session_id, sessions[-1]["session_id"])

        # Replaying the callback after restart creates no second session.
        replay = browser.deliver(pending)
        self.assertEqual(replay.status, 409)
        self.assertEqual(replay.lab_error, "replayed_callback")
        self.assertEqual(len(db_sessions()), sessions_before + 1)
        self.assertEqual(browser.me()["session_id"], session_id)
        self.assertEqual(len(browser.sessions()), 1)

        # A second browser cannot replay it either.
        other = Browser("crash-commit-other", LAB.rp_base)
        other.start_login("B", "alice")
        foreign = other.get(pending.callback_url)
        self.assertEqual(foreign.status, 400)
        self.assertIsNone(other.me())


class ExternalKillAtSyncPoint(unittest.TestCase):
    """The harness -- not the RP -- kills the worker at the sync point."""

    def _hold_and_kill(self, browser, pending, point: str) -> dict:
        hold_dir = LAB.runtime_dir / "holds"
        before = set(hold_dir.glob(f"{point}.*.json")) if hold_dir.exists() else set()
        outcome: dict = {}

        def request_thread():
            try:
                outcome["result"] = deliver_with_crash(browser, pending, point, hold=point)
            except BaseException as exc:  # pragma: no cover - diagnostic
                outcome["error"] = repr(exc)

        thread = threading.Thread(target=request_thread, daemon=True)
        thread.start()

        deadline = time.time() + 15
        marker = None
        while time.time() < deadline:
            candidates = set(hold_dir.glob(f"{point}.*.json")) - before if hold_dir.exists() else set()
            if candidates:
                marker = sorted(candidates)[0]
                break
            time.sleep(0.05)
        self.assertIsNotNone(marker, f"no hold marker appeared for {point}")
        info = json.loads(marker.read_text(encoding="utf-8"))
        pid = info["pid"]
        self.assertTrue(procs.pid_alive(pid))
        self.assertTrue(procs.hard_kill(pid), "could not hard-kill the held worker")
        deadline = time.time() + 10
        while time.time() < deadline and procs.pid_alive(pid):
            time.sleep(0.05)
        thread.join(timeout=20)
        self.assertFalse(thread.is_alive())
        marker.unlink(missing_ok=True)
        return {"pid": pid, "info": info, "outcome": outcome}

    def test_external_kill_after_verify(self):
        browser = Browser("ext-verify", LAB.rp_base)
        pending = browser.start_login("A", "alice")
        before = len(db_sessions())
        killed = self._hold_and_kill(browser, pending, "after-verify")
        self.assertFalse(procs.pid_alive(killed["pid"]))
        self.assertEqual(len(db_sessions()), before, "kill after verify must not create a session")
        row = db_txn(pending.state)
        self.assertEqual(row["status"], "consuming")
        wait_for_worker_replacement()
        self.assertIsNone(browser.me())
        # Immediately after the kill the claim still looks "in flight", so a
        # replay is refused as a duplicate (409).  Once the grace period has
        # passed the claim is provably abandoned and is closed for good.
        early = browser.deliver(pending)
        self.assertIn(early.status, (400, 409))
        self.assertIsNone(browser.me())
        time.sleep(1.4)
        replay = browser.deliver(pending)
        self.assertEqual(replay.status, 400)
        self.assertEqual(replay.header("X-Lab-Reason"), "invalid_transaction")
        self.assertEqual(db_txn(pending.state)["status"], "failed")
        self.assertIsNone(browser.me())

    def test_external_kill_after_commit(self):
        browser = Browser("ext-commit", LAB.rp_base)
        pending = browser.start_login("B", "shared")
        before = len(db_sessions())
        killed = self._hold_and_kill(browser, pending, "after-commit")
        self.assertFalse(procs.pid_alive(killed["pid"]))
        self.assertEqual(len(db_sessions()), before + 1)
        self.assertEqual(db_txn(pending.state)["status"], "done")
        wait_for_worker_replacement()
        identity = browser.me()
        self.assertIsNotNone(identity)
        self.assertEqual(identity["subject"], "same-sub-7")
        replay = browser.deliver(pending)
        self.assertEqual(replay.status, 409)
        self.assertEqual(len(db_sessions()), before + 1)


class RestartBehaviour(unittest.TestCase):
    def test_full_rp_restart_does_not_resurrect_finished_transactions(self):
        browser = Browser("restart", LAB.rp_base)
        pending = browser.start_login("A", "shared")
        self.assertEqual(browser.deliver(pending).status, 200)
        session_id = browser.me()["session_id"]

        LAB.restart_rp(workers=2)
        try:
            # Cookies survive the restart (they are the browser's, not the
            # process's) and the session is still there.
            identity = browser.me()
            self.assertIsNotNone(identity)
            self.assertEqual(identity["session_id"], session_id)

            # Replay after a restart is still refused.
            replay = browser.deliver(pending)
            self.assertEqual(replay.status, 409)
            self.assertEqual(browser.me()["session_id"], session_id)
            self.assertEqual(len(browser.sessions()), 1)
        finally:
            pass


class ClaimOwnership(unittest.TestCase):
    def test_abandoned_claim_is_closed_not_reused(self):
        """A claim left by a dead worker must never be resumable."""
        browser = Browser("claim", LAB.rp_base)
        pending = browser.start_login("A", "alice")
        deliver_with_crash(browser, pending, "after-verify")
        wait_for_worker_replacement()
        time.sleep(1.2)  # past the abandoned-claim grace period
        first = browser.deliver(pending)
        self.assertEqual(first.status, 400)
        row = db_txn(pending.state)
        self.assertEqual(row["status"], "failed")
        # A third attempt reports the closed transaction, never a new login.
        second = browser.deliver(pending)
        self.assertEqual(second.status, 400)
        self.assertIsNone(browser.me())


# ----------------------------------------------------------------------
def _all_worker_pids() -> list[int]:
    pids = set()
    for _ in range(20):
        status, payload = _http_json(f"{LAB.rp_base}/healthz", timeout=1.0)
        if status == 200 and payload:
            pids.add(payload["pid"])
    return sorted(pids)


if __name__ == "__main__":
    unittest.main()
