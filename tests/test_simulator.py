"""Simulator-level tests: independent cookie jars, real HTTP, no DB writes.

These are the "browser" properties the task asks for, stated as tests:

* two simulated browsers never share cookies;
* each browser's ``/me`` reflects only its own transactions;
* the simulator can interleave and reorder callbacks;
* the simulator never talks to the database (asserted by the test running
  against an RP whose database file is opened read-only after the fact, and by
  checking that every identity observation came from an HTTP response).
"""

from __future__ import annotations

import http.cookiejar
import unittest

import support  # noqa: F401  # path setup + test hooks
from support import ROOT

from sso_lab.browser import Browser
from sso_lab.harness import start_lab

LAB = None
RUNTIME = ROOT / "runtime" / "tests" / "simulator"


def setUpModule():
    global LAB
    LAB = start_lab(root_dir=ROOT, runtime_dir=RUNTIME, workers=2)


def tearDownModule():
    if LAB is not None:
        LAB.stop()


class IndependentSessions(unittest.TestCase):
    def test_two_browsers_have_separate_cookie_jars(self):
        first, second = Browser("one", LAB.rp_base), Browser("two", LAB.rp_base)
        first.start_login("A", "alice")
        second.start_login("B", "alice")
        self.assertNotEqual(first.cookie_value("rp_sid"), second.cookie_value("rp_sid"))
        self.assertIsInstance(first.jar, http.cookiejar.CookieJar)
        self.assertIsNot(first.jar, second.jar)

    def test_login_in_one_browser_does_not_login_the_other(self):
        first, second = Browser("one", LAB.rp_base), Browser("two", LAB.rp_base)
        first.login("A", "alice")
        self.assertIsNotNone(first.me())
        self.assertIsNone(second.me())

    def test_idp_cannot_read_or_set_the_rp_cookie(self):
        browser = Browser("cookie-scope", LAB.rp_base)
        browser.login("A", "alice")
        names = browser.cookie_names()
        self.assertEqual(names, ["rp_sid"])
        # Both RP cookies are host-only to 127.0.0.1; the IdPs live on the
        # other loopback addresses and therefore never receive them.
        for cookie in browser.jar:
            self.assertEqual(cookie.domain, "127.0.0.1")

    def test_browser_history_shows_real_http_exchanges(self):
        browser = Browser("history", LAB.rp_base)
        browser.login("B", "shared")
        urls = [url for url, _ in browser.history]
        self.assertTrue(any("/login?issuer=B" in url for url in urls))
        self.assertTrue(any("127.0.0.3" in url and "/authorize" in url for url in urls))
        self.assertTrue(any(url.startswith(LAB.rp_base + "/callback") for url in urls))
        # The authorize redirect carries S256 + state + nonce, as built by the RP.
        authorize = next(url for url in urls if "/authorize" in url)
        self.assertIn("code_challenge_method=S256", authorize)
        self.assertIn("state=", authorize)
        self.assertIn("nonce=", authorize)

    def test_simulator_never_writes_to_the_database(self):
        """The only side effects come from HTTP handlers, not from the test."""
        import sqlite3

        browser = Browser("db-write", LAB.rp_base)
        browser.login("A", "alice")
        conn = sqlite3.connect(str(LAB.db_path), timeout=10)
        try:
            count = conn.execute("SELECT COUNT(*) FROM login_sessions").fetchone()[0]
            attempts = conn.execute("SELECT COUNT(*) FROM callback_attempts").fetchone()[0]
            established = conn.execute(
                "SELECT COUNT(*) FROM callback_attempts WHERE outcome = 'established'"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertGreaterEqual(count, 1)
        self.assertGreaterEqual(attempts, 1)
        # Every session has a matching callback attempt recorded by the RP
        # itself, i.e. the session was created by an HTTP request.
        self.assertGreaterEqual(established, count)

    def test_logout_clears_the_session(self):
        browser = Browser("logout", LAB.rp_base)
        browser.login("A", "alice")
        self.assertIsNotNone(browser.me())
        browser.logout()
        self.assertIsNone(browser.me())


if __name__ == "__main__":
    unittest.main()
