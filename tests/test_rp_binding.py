"""Integration tests: RP callback binding, issuer confusion, replay, concurrency.

All flows go through real HTTP against three running services (two RP worker
processes sharing one database).  Identity is only ever read back from ``/me``
with the browser's own cookies.
"""

from __future__ import annotations

import concurrent.futures
import http.client
import json
import threading
import time
import unittest
import urllib.parse

import support  # noqa: F401  (sets sys.path and test hooks)
from support import ROOT

from sso_lab.browser import Browser
from sso_lab.harness import start_lab

LAB = None
RUNTIME = ROOT / "runtime" / "tests" / "rp-binding"


def setUpModule():
    global LAB
    LAB = start_lab(root_dir=ROOT, runtime_dir=RUNTIME, workers=2)


def tearDownModule():
    if LAB is not None:
        LAB.stop()


def new_browser(name="b") -> Browser:
    return Browser(name, LAB.rp_base)


def callback_with(browser: Browser, pending, *, issuer=None, state=None, code=None,
                  headers=None):
    query = urllib.parse.parse_qsl(urllib.parse.urlsplit(pending.callback_url).query)
    params = dict(query)
    if issuer is not None:
        params["issuer"] = issuer
    if state is not None:
        params["state"] = state
    if code is not None:
        params["code"] = code
    url = f"{LAB.rp_base}/callback?" + urllib.parse.urlencode(params)
    return browser.get(url, headers=headers or {})


def raw_callback(cookie_value: str | None, params: dict[str, str],
                 *, headers: dict[str, str] | None = None):
    """Send a callback with an explicit Cookie header (independent of jars)."""
    path = "/callback?" + urllib.parse.urlencode(params)
    all_headers = {"Accept": "text/html"}
    if cookie_value:
        all_headers["Cookie"] = f"rp_sid={cookie_value}"
    all_headers.update(headers or {})
    from support import raw_request

    status, response_headers, body = raw_request(
        "127.0.0.1", LAB.rp_port, "GET", path, headers=all_headers
    )
    return status, response_headers, body.decode("utf-8", "replace")


class BasicLogin(unittest.TestCase):
    def test_login_with_provider_a(self):
        browser = new_browser()
        pending = browser.start_login("A", "alice")
        self.assertEqual(pending.issuer, "A")
        response = browser.deliver(pending)
        self.assertEqual(response.status, 200, response.text[:400])
        identity = browser.me()
        self.assertIsNotNone(identity)
        self.assertTrue(identity["issuer"].endswith("/issuer/A"))
        self.assertEqual(identity["subject"], "user-1001")
        self.assertEqual(identity["email"], "alice@example.test")

    def test_login_with_provider_b_same_email_different_identity(self):
        browser = new_browser()
        browser.login("B", "alice")
        identity = browser.me()
        self.assertTrue(identity["issuer"].endswith("/issuer/B"))
        self.assertEqual(identity["subject"], "user-2002")
        self.assertEqual(identity["email"], "alice@example.test")

    def test_same_sub_at_two_issuers_are_two_identities(self):
        browser = new_browser()
        browser.login("A", "shared")
        first = browser.me()
        browser.login("B", "shared")
        second = browser.me()
        self.assertEqual(first["subject"], second["subject"])  # same raw sub
        self.assertNotEqual(first["issuer"], second["issuer"])
        self.assertNotEqual(first["session_id"], second["session_id"])
        sessions = browser.sessions()
        self.assertEqual(len(sessions), 2)
        pairs = {(row["issuer"], row["subject"]) for row in sessions}
        self.assertEqual(len(pairs), 2)

    def test_callback_requires_browser_cookie(self):
        browser = new_browser()
        pending = browser.start_login("A", "alice")
        status, headers, body = raw_callback(None, pending.callback_query())
        self.assertEqual(status, 400)
        self.assertEqual(headers.get("x-lab-error"), "invalid_callback")
        # the transaction is still usable by the browser that started it
        self.assertEqual(browser.deliver(pending).status, 200)


class OrderingAndBinding(unittest.TestCase):
    def test_out_of_order_callbacks_same_browser(self):
        """A and B both started, B's callback delivered first, then A's."""
        browser = new_browser()
        pending_a = browser.start_login("A", "alice")
        pending_b = browser.start_login("B", "alice")
        self.assertNotEqual(pending_a.state, pending_b.state)

        first = browser.deliver(pending_b)
        self.assertEqual(first.status, 200, first.text[:400])
        self.assertIn("Alice at B", first.text)

        second = browser.deliver(pending_a)
        self.assertEqual(second.status, 200, second.text[:400])
        self.assertIn("Alice at A", second.text)

        sessions = browser.sessions()
        by_issuer = {row["issuer"].rsplit("/", 1)[-1]: row for row in sessions}
        self.assertEqual(set(by_issuer), {"A", "B"})
        self.assertEqual(by_issuer["A"]["subject"], "user-1001")
        self.assertEqual(by_issuer["B"]["subject"], "user-2002")

    def test_three_parallel_logins_all_complete(self):
        browser = new_browser()
        pendings = [
            browser.start_login("A", "alice"),
            browser.start_login("B", "shared"),
            browser.start_login("A", "shared"),
        ]
        # deliver in reverse order
        for pending in reversed(pendings):
            response = browser.deliver(pending)
            self.assertEqual(response.status, 200, response.text[:300])
        statuses = {
            (row["issuer"].rsplit("/", 1)[-1], row["subject"]) for row in browser.sessions()
        }
        self.assertEqual(
            statuses,
            {("A", "user-1001"), ("B", "same-sub-7"), ("A", "same-sub-7")},
        )

    def test_cross_browser_state_exchange_is_rejected_without_burning_it(self):
        victim = new_browser("victim")
        attacker = new_browser("attacker")
        # Give the attacker a real RP browser cookie of its own, so the test
        # exercises the state/browser binding rather than "no cookie at all".
        attacker_own = attacker.start_login("B", "alice")
        pending = victim.start_login("A", "alice")
        self.assertNotEqual(attacker.cookie_value("rp_sid"), victim.cookie_value("rp_sid"))

        stolen = attacker.get(pending.callback_url)
        self.assertEqual(stolen.status, 400)
        self.assertEqual(stolen.lab_error, "invalid_callback")
        self.assertIn("different browser", stolen.text)
        self.assertEqual(stolen.header("X-Lab-Reason"), "browser_mismatch")
        self.assertIsNone(attacker.me(), "rejected callback must not create a session")
        self.assertIsNone(victim.me(), "rejected callback must not create a session")

        # The victim's transaction is untouched and still completes.
        ok = victim.deliver(pending)
        self.assertEqual(ok.status, 200, ok.text[:300])
        self.assertIsNotNone(victim.me())
        # The attacker's own transaction is untouched too.
        self.assertEqual(attacker.deliver(attacker_own).status, 200)
        self.assertTrue(attacker.me()["issuer"].endswith("/issuer/B"))

    def test_callback_with_foreign_cookie_only_is_rejected(self):
        victim = new_browser("victim")
        stranger = new_browser("stranger")  # never started a login: no cookie
        pending = victim.start_login("A", "alice")
        stolen = stranger.get(pending.callback_url)
        self.assertEqual(stolen.status, 400)
        self.assertEqual(stolen.lab_error, "invalid_callback")
        self.assertIn("without a valid RP browser cookie", stolen.text)
        self.assertEqual(victim.deliver(pending).status, 200)

    def test_unknown_state_does_not_touch_pending_transaction(self):
        browser = new_browser()
        pending = browser.start_login("A", "alice")
        bogus = browser.get(
            f"{LAB.rp_base}/callback?" + urllib.parse.urlencode(
                {"issuer": "A", "state": "x" * 43, "code": "y" * 43}
            )
        )
        self.assertEqual(bogus.status, 400)
        self.assertEqual(bogus.lab_error, "invalid_callback")
        ok = browser.deliver(pending)
        self.assertEqual(ok.status, 200, ok.text[:300])

    def test_callback_issuer_swap_is_rejected(self):
        browser = new_browser()
        pending = browser.start_login("A", "alice")
        swapped = callback_with(browser, pending, issuer="B")
        self.assertEqual(swapped.status, 400)
        self.assertIn("issuer mismatch", swapped.text)
        self.assertEqual(swapped.header("X-Lab-Reason"), "issuer_mismatch")
        self.assertIsNone(browser.me())
        ok = browser.deliver(pending)
        self.assertEqual(ok.status, 200, ok.text[:300])
        self.assertTrue(browser.me()["issuer"].endswith("/issuer/A"))

    def test_callback_without_issuer_is_rejected(self):
        browser = new_browser()
        pending = browser.start_login("B", "alice")
        params = pending.callback_query()
        params.pop("issuer", None)
        status, headers, _ = raw_callback(browser.cookie_value("rp_sid"), params)
        self.assertEqual(status, 400)
        self.assertEqual(headers.get("x-lab-error"), "invalid_callback")
        self.assertEqual(browser.deliver(pending).status, 200)

    def test_duplicate_state_parameter_is_rejected(self):
        browser = new_browser()
        pending = browser.start_login("A", "alice")
        query = urllib.parse.urlencode(pending.callback_query()) + f"&state={pending.state}"
        from support import raw_request

        status, headers, _ = raw_request(
            "127.0.0.1", LAB.rp_port, "GET", "/callback?" + query,
            headers={"Cookie": f"rp_sid={browser.cookie_value('rp_sid')}"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(browser.deliver(pending).status, 200)


class CrossProviderAttacks(unittest.TestCase):
    def test_code_from_a_redeemed_at_b_is_rejected_and_a_still_works(self):
        browser = new_browser()
        pending = browser.start_login("A", "alice")
        # Drive the RP's own exchange path first?  No: redeem A's code at B.
        flow_verifier = None
        # The verifier lives only in the RP transaction, so B can never verify
        # PKCE; use a syntactically valid wrong one to reach the code lookup.
        status, body = post_token(
            "B", code=pending.code, verifier="z" * 43,
            redirect_uri=f"{LAB.rp_base}/callback?issuer=B",
        )
        self.assertEqual(status, 400)
        self.assertEqual(body.get("error"), "invalid_grant")
        ok = browser.deliver(pending)
        self.assertEqual(ok.status, 200, ok.text[:300])
        self.assertTrue(browser.me()["issuer"].endswith("/issuer/A"))

    def test_rp_transaction_pins_token_endpoint(self):
        """Swap the *transaction's* issuer to B: RP must still use A's endpoint.

        Simulated by starting A's login and then delivering at B's issuer; the
        RP rejects before any exchange, so A's code survives.
        """
        browser = new_browser()
        pending = browser.start_login("A", "alice")
        swapped = callback_with(browser, pending, issuer="B")
        self.assertEqual(swapped.status, 400)
        # Code is still redeemable by the genuine flow.
        self.assertEqual(browser.deliver(pending).status, 200)

    def test_b_token_endpoint_rejects_a_client_credentials(self):
        browser = new_browser()
        pending = browser.start_login("A", "alice")
        status, body = post_token("B", code=pending.code, verifier="z" * 43,
                                  client="rp-client-for-B")
        self.assertEqual(status, 400)

    def test_issuer_in_id_token_must_match_transaction(self):
        """A token minted by B but placed in A's transaction is rejected."""
        # Covered at unit level; here we assert the RP refuses a token whose
        # iss is the other provider (fault-injected A provider).
        lab = start_lab(
            root_dir=ROOT,
            runtime_dir=ROOT / "runtime" / "tests" / "wrong-iss",
            workers=2,
            faults={"A": "wrong_iss"},
        )
        try:
            browser = Browser("b", lab.rp_base)
            pending = browser.start_login("A", "alice")
            response = browser.deliver(pending)
            self.assertEqual(response.status, 401)
            self.assertEqual(response.lab_error, "invalid_id_token")
            self.assertIn("issuer", response.text)
            self.assertIsNone(browser.me())
        finally:
            lab.stop()


class TokenValidationFaults(unittest.TestCase):
    """Each case starts a lab whose A provider emits a bad ID token."""

    def _run_fault(self, fault: str, *, expect_in=None):
        lab = start_lab(
            root_dir=ROOT,
            runtime_dir=ROOT / "runtime" / "tests" / f"fault-{fault.replace('=', '-')}",
            workers=2,
            faults={"A": fault},
        )
        try:
            browser = Browser("b", lab.rp_base)
            pending = browser.start_login("A", "alice")
            response = browser.deliver(pending)
            self.assertEqual(response.status, 401, response.text[:400])
            self.assertEqual(response.lab_error, "invalid_id_token")
            if expect_in:
                self.assertIn(expect_in, response.text)
            self.assertIsNone(browser.me())
            self.assertEqual(browser.sessions(), [])
            # The code was consumed at the IdP even though the RP refused it.
            status, payload = code_status(lab, "A", pending.code)
            self.assertEqual(status, 200)
            self.assertTrue(payload["consumed"])
        finally:
            lab.stop()

    def test_wrong_nonce(self):
        self._run_fault("wrong_nonce", expect_in="nonce")

    def test_wrong_audience(self):
        self._run_fault("wrong_aud", expect_in="audience")

    def test_wrong_signing_key(self):
        self._run_fault("wrong_key", expect_in="signature")

    def test_other_provider_key_is_rejected(self):
        """A token signed with B's real key must not verify as A."""
        self._run_fault("peer_key", expect_in="signature")

    def test_token_supplied_urls_are_never_fetched(self):
        """``jku``/``jwks_uri`` point at a local listener; it must stay silent."""
        import http.server
        import socket
        import threading

        hits: list[str] = []

        class Collector(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                body = b'{"keys":[]}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        with socket.socket() as probe:
            probe.bind(("127.0.0.2", 0))
            collector_port = probe.getsockname()[1]
        server = http.server.ThreadingHTTPServer(("127.0.0.2", collector_port), Collector)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            lab = start_lab(
                root_dir=ROOT,
                runtime_dir=ROOT / "runtime" / "tests" / "no-key-fetch",
                workers=2,
                faults={
                    "A": f"jku=http://127.0.0.2:{collector_port}/jwks.json,"
                         f"jwks_uri=http://127.0.0.2:{collector_port}/other.json",
                },
            )
            try:
                browser = Browser("b", lab.rp_base)
                pending = browser.start_login("A", "alice")
                response = browser.deliver(pending)
                self.assertEqual(response.status, 401)
                self.assertIn("jku", response.text)
                time.sleep(0.3)
                self.assertEqual(hits, [], f"RP fetched a token-supplied URL: {hits}")
            finally:
                lab.stop()
        finally:
            server.shutdown()
            server.server_close()

    def test_alg_none(self):
        # An unsigned token has an empty third segment; it is refused before
        # any claim is looked at (the reason is "empty JWS segment").
        self._run_fault("alg_none", expect_in="JWS")

    def test_duplicate_json_member(self):
        self._run_fault("dup_iss", expect_in="duplicate")

    def test_bad_sub_type(self):
        self._run_fault("sub_number", expect_in="sub")

    def test_jku_header_is_never_used(self):
        self._run_fault("jku", expect_in="jku")

    def test_jwks_uri_claim_ignored_but_tolerated(self):
        """An unknown payload claim is harmless; the token is still valid."""
        lab = start_lab(
            root_dir=ROOT,
            runtime_dir=ROOT / "runtime" / "tests" / "fault-jwks-claim",
            workers=2,
            faults={"A": "jwks_uri"},
        )
        try:
            browser = Browser("b", lab.rp_base)
            pending = browser.start_login("A", "alice")
            response = browser.deliver(pending)
            self.assertEqual(response.status, 200, response.text[:300])
            self.assertIsNotNone(browser.me())
        finally:
            lab.stop()

    def test_expired_id_token(self):
        lab = start_lab(
            root_dir=ROOT,
            runtime_dir=ROOT / "runtime" / "tests" / "fault-expired",
            workers=2,
            faults={"A": "expired"},
        )
        try:
            browser = Browser("b", lab.rp_base)
            pending = browser.start_login("A", "alice")
            response = browser.deliver(pending)
            self.assertEqual(response.status, 401)
            self.assertIn("expired", response.text)
            self.assertIsNone(browser.me())
        finally:
            lab.stop()


class ExpiryBoundaries(unittest.TestCase):
    def tearDown(self):
        # A moved IdP clock poisons every later login in the shared lab.
        try:
            LAB.set_idp_clock("A", 0.0)
            LAB.set_idp_clock("B", 0.0)
        except Exception:
            pass
        try:
            set_rp_clock(0.0)
        except Exception:
            pass

    def test_authorization_code_expiry_at_provider(self):
        lab = start_lab(
            root_dir=ROOT,
            runtime_dir=ROOT / "runtime" / "tests" / "code-expiry",
            workers=2,
        )
        try:
            browser = Browser("b", lab.rp_base)
            pending = browser.start_login("A", "alice")
            # 59.0 s into a 60 s code window: still valid.  Both clocks move so
            # that only the code's age changes, not the token's iat/exp offset.
            advance_clocks(lab, 59.0)
            response = browser.deliver(pending)
            self.assertEqual(response.status, 200, response.text[:300])
            self.assertIsNotNone(browser.me())
        finally:
            lab.stop()

    def test_authorization_code_expired_at_provider(self):
        lab = start_lab(
            root_dir=ROOT,
            runtime_dir=ROOT / "runtime" / "tests" / "code-expired",
            workers=2,
        )
        try:
            browser = Browser("b", lab.rp_base)
            pending = browser.start_login("A", "alice")
            advance_clocks(lab, 61.0)
            response = browser.deliver(pending)
            self.assertEqual(response.status, 401)
            self.assertEqual(response.lab_error, "token_exchange_failed")
            self.assertIn("invalid_grant", response.text)
            self.assertIsNone(browser.me())

            # Recovery: a fresh login after the clock is put back succeeds.
            advance_clocks(lab, 0.0)
            again = browser.start_login("A", "alice")
            self.assertEqual(browser.deliver(again).status, 200)
        finally:
            lab.stop()

    def test_id_token_expiry_boundary_at_rp(self):
        """Walk the RP's clock across ``exp + leeway``."""
        browser = new_browser()
        pending = browser.start_login("A", "alice")
        set_rp_clock(2.0)
        try:
            inside = browser.deliver(pending)
        finally:
            set_rp_clock(0.0)
        self.assertEqual(inside.status, 200, inside.text[:300])

        second = new_browser()
        pending2 = second.start_login("B", "alice")
        set_rp_clock(130.0)
        try:
            outside = second.deliver(pending2)
        finally:
            set_rp_clock(0.0)
        self.assertEqual(outside.status, 401)
        self.assertEqual(outside.lab_error, "invalid_id_token")
        self.assertIn("expired", outside.text)
        self.assertIsNone(second.me())


class ExchangeFailureRecovery(unittest.TestCase):
    def test_bad_code_fails_then_valid_login_succeeds(self):
        browser = new_browser()
        pending = browser.start_login("A", "alice")
        tampered = pending.code[:-1] + ("A" if pending.code[-1] != "A" else "B")
        response = callback_with(browser, pending, code=tampered)
        self.assertEqual(response.status, 401)
        self.assertEqual(response.lab_error, "token_exchange_failed")
        self.assertIsNone(browser.me())

        # The tampered code was never a real code, so nothing was consumed.
        status, payload = code_status(LAB, "A", pending.code)
        self.assertFalse(payload["consumed"])

        # The closed transaction cannot be replayed, but a fresh login works.
        replay = browser.deliver(pending)
        self.assertIn(replay.status, (400, 409))
        self.assertIsNone(browser.me())
        fresh = browser.start_login("A", "alice")
        self.assertEqual(browser.deliver(fresh).status, 200)
        self.assertIsNotNone(browser.me())

    def test_provider_unreachable_is_reported_as_failure(self):
        browser = new_browser()
        pending = browser.start_login("A", "alice")
        # Kill A temporarily; the RP must report failure, not success.
        idp = LAB.services["A"]
        idp.process.terminate()
        idp.process.wait(timeout=10)
        try:
            response = browser.deliver(pending)
        finally:
            restart_idp("A")
        self.assertEqual(response.status, 502)
        self.assertEqual(response.lab_error, "provider_unavailable")
        self.assertIsNone(browser.me())
        fresh = browser.start_login("A", "alice")
        self.assertEqual(browser.deliver(fresh).status, 200)


class ReplayAndConcurrency(unittest.TestCase):
    def test_replayed_callback_creates_no_second_session(self):
        browser = new_browser()
        pending = browser.start_login("A", "alice")
        first = browser.deliver(pending)
        self.assertEqual(first.status, 200)
        session_id = browser.me()["session_id"]

        replay = browser.deliver(pending)
        self.assertEqual(replay.status, 409)
        self.assertEqual(replay.lab_error, "replayed_callback")
        self.assertEqual(len(browser.sessions()), 1)
        self.assertEqual(browser.me()["session_id"], session_id)

    def test_concurrent_identical_callbacks_create_one_session(self):
        browser = new_browser()
        pending = browser.start_login("A", "alice")
        cookie = browser.cookie_value("rp_sid")
        params = pending.callback_query()

        barrier = threading.Barrier(8)

        def worker(_):
            barrier.wait()
            return raw_callback(cookie, params, headers={"X-Lab-Delay": "0.4"})

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(8)))
        statuses = sorted(status for status, _, _ in results)
        self.assertEqual(statuses.count(200), 1, f"expected one success, got {statuses}")
        self.assertEqual(len(statuses), 8)
        self.assertTrue(all(status in (200, 409) for status in statuses), statuses)
        self.assertEqual(len(browser.sessions()), 1)
        self.assertIsNotNone(browser.me())

    def test_concurrent_callbacks_from_two_browsers_both_succeed(self):
        browsers = [new_browser(f"b{i}") for i in range(2)]
        pendings = [browsers[0].start_login("A", "alice"),
                    browsers[1].start_login("A", "shared")]
        barrier = threading.Barrier(2)

        def deliver(browser, pending):
            barrier.wait()
            return browser.deliver(pending)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(deliver, b, p) for b, p in zip(browsers, pendings)]
            results = [f.result() for f in futures]
        self.assertEqual([r.status for r in results], [200, 200])
        self.assertEqual(browsers[0].me()["subject"], "user-1001")
        self.assertEqual(browsers[1].me()["subject"], "same-sub-7")


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def post_token(provider: str, *, code: str, verifier: str, redirect_uri: str | None = None,
               client: str | None = None):
    import base64

    host = "127.0.0.2" if provider == "A" else "127.0.0.3"
    port = LAB.idp_ports[provider]
    config = LAB.env
    secret = "client-secret-A-lab" if provider == "A" else "client-secret-B-lab"
    client = client or ("rp-client-for-A" if provider == "A" else "rp-client-for-B")
    redirect_uri = redirect_uri or f"http://127.0.0.1:{LAB.rp_port}/callback?issuer={provider}"
    body = urllib.parse.urlencode(
        {"grant_type": "authorization_code", "code": code,
         "redirect_uri": redirect_uri, "code_verifier": verifier}
    ).encode()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic " + base64.b64encode(f"{client}:{secret}".encode()).decode(),
    }
    connection = http.client.HTTPConnection(host, port, timeout=10)
    try:
        connection.request("POST", "/token", body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        return response.status, json.loads(raw.decode("utf-8"))
    finally:
        connection.close()


def advance_clocks(lab, seconds: float) -> None:
    """Move the RP and both IdP clocks together (code-age tests)."""
    set_rp_clock(seconds, lab=lab)
    lab.set_idp_clock("A", seconds)
    lab.set_idp_clock("B", seconds)


def set_rp_clock(offset: float, *, lab=None) -> None:
    from support import raw_request

    target = lab or LAB
    status, _, _ = raw_request(
        "127.0.0.1", target.rp_port, "GET", f"/lab/clock?offset={offset}"
    )
    assert status == 200, status


def code_status(lab, provider: str, code: str):
    from support import raw_request

    host = "127.0.0.2" if provider == "A" else "127.0.0.3"
    port = lab.idp_ports[provider]
    status, _, raw = raw_request(
        host, port, "GET", "/lab/code-status?" + urllib.parse.urlencode({"code": code})
    )
    return status, json.loads(raw.decode("utf-8"))


def restart_idp(name: str) -> None:
    import subprocess
    import sys

    handle = LAB.services[name]
    if handle.process.poll() is None:
        handle.process.terminate()
        handle.process.wait(timeout=10)
    handle.close()
    log_path = LAB.runtime_dir / "logs" / f"idp_{name}.log"
    log_file = open(log_path, "a", encoding="utf-8")
    process = subprocess.Popen(
        [sys.executable, "-m", "sso_lab.idp", "--provider", name],
        cwd=str(ROOT), env=LAB.env, stdout=log_file, stderr=subprocess.STDOUT,
    )
    from sso_lab.harness import ServiceHandle

    LAB.services[name] = ServiceHandle(name, process, LAB.idp_base(name), log_path, log_file)
    deadline = time.time() + 20
    from sso_lab.harness import _http_json

    while time.time() < deadline:
        status, _ = _http_json(f"{LAB.idp_base(name)}/healthz", timeout=1.0)
        if status == 200:
            return
        time.sleep(0.1)
    raise AssertionError(f"IdP {name} did not restart")


if __name__ == "__main__":
    unittest.main()
