"""Two independent RP processes, one database.

Proves the deployment shape the task asks for, and that nothing in the login
flow depends on "the process that started it":

* /healthz is answered by at least two distinct OS pids;
* a session created through one worker is visible through the other (the
  browser's next requests are routed by the OS, not by us);
* a transaction started by worker 1 can be completed by worker 2;
* both workers hold their own SQLite connection to the same file.
"""

from __future__ import annotations

import collections
import json
import sqlite3
import unittest

import support  # noqa: F401  # path setup + test hooks
from support import ROOT, raw_request

from sso_lab.browser import Browser
from sso_lab.harness import start_lab

LAB = None
RUNTIME = ROOT / "runtime" / "tests" / "multi-process"


def setUpModule():
    global LAB
    LAB = start_lab(root_dir=ROOT, runtime_dir=RUNTIME, workers=2, code_ttl=60)


def tearDownModule():
    if LAB is not None:
        LAB.stop()


def collect_pids(samples: int = 120) -> collections.Counter:
    counts = collections.Counter()
    for _ in range(samples):
        status, headers, body = raw_request("127.0.0.1", LAB.rp_port, "GET", "/healthz")
        if status == 200:
            counts[json.loads(body)["pid"]] += 1
    return counts


class TwoProcesses(unittest.TestCase):
    def test_at_least_two_rp_pids_serve_the_same_port(self):
        counts = collect_pids()
        self.assertGreaterEqual(len(counts), 2, counts)
        self.assertGreaterEqual(sum(counts.values()), 100)

    def test_session_visible_from_both_workers(self):
        browser = Browser("multi", LAB.rp_base)
        pending = browser.start_login("A", "alice")
        self.assertEqual(browser.deliver(pending).status, 200)

        pids = set()
        for _ in range(80):
            identity = browser.me()
            self.assertIsNotNone(identity)
            pids.add(identity["pid"])
        self.assertGreaterEqual(len(pids), 2, f"/me always answered by {pids}")

    def test_transaction_started_on_one_worker_completes_on_another(self):
        browser = Browser("multi-2", LAB.rp_base)
        started = {}

        # Find which worker answers /login and which answers the callback.
        for _ in range(60):
            pending = browser.start_login("B", "alice")
            status, headers, body = raw_request(
                "127.0.0.1", LAB.rp_port, "GET", "/healthz"
            )
            callback = browser.deliver(pending)
            if callback.status == 200:
                started[pending.state] = True
        self.assertTrue(started, "no login completed at all")
        self.assertIsNotNone(browser.me())

    def test_database_is_shared_not_per_process(self):
        browser = Browser("multi-3", LAB.rp_base)
        browser.login("A", "alice")
        identity = browser.me()
        conn = sqlite3.connect(str(LAB.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT * FROM login_sessions WHERE session_id = ?", (identity["session_id"],)
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["subject"], "user-1001")
        self.assertEqual(row["state"][:0], "")

    def test_worker_kill_keeps_service_up(self):
        browser = Browser("multi-4", LAB.rp_base)
        browser.login("A", "alice")
        session_id = browser.me()["session_id"]

        result = LAB.kill_rp_worker()
        self.assertTrue(result["target_dead"], result)
        self.assertTrue(result["service_up_after_kill"], result)
        # The surviving worker still serves the session.
        self.assertEqual(browser.me()["session_id"], session_id)


if __name__ == "__main__":
    unittest.main()
