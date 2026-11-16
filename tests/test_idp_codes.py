"""Unit tests for the IdP's authorization-code semantics (in-process)."""

from __future__ import annotations

import unittest

from support import InProcessIdp  # noqa: F401  # path setup


class CodeBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.idp = InProcessIdp("A", code_ttl=60)
        cls.idp.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.idp.__exit__(None, None, None)

    def issue(self, **kwargs):
        return self.idp.authorize_and_approve(**kwargs)

    # -- happy path -------------------------------------------------------
    def test_code_can_be_exchanged_once(self):
        flow = self.issue()
        status, body = self.idp.token(code=flow["code"], verifier=flow["_verifier"])
        self.assertEqual(status, 200, body)
        self.assertIn("id_token", body)
        self.assertEqual(body["token_type"], "Bearer")
        # second exchange of the same code fails
        status, body = self.idp.token(code=flow["code"], verifier=flow["_verifier"])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid_grant")

    def test_id_token_header_and_claims(self):
        flow = self.issue()
        status, body = self.idp.token(code=flow["code"], verifier=flow["_verifier"])
        self.assertEqual(status, 200)
        import base64
        import json
        header_b64, payload_b64, _ = body["id_token"].split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
        header = json.loads(base64.urlsafe_b64decode(pad(header_b64)))
        payload = json.loads(base64.urlsafe_b64decode(pad(payload_b64)))
        self.assertEqual(header["alg"], "HS256")
        self.assertNotIn("jku", header)
        self.assertEqual(payload["iss"], self.idp.provider.issuer)
        self.assertEqual(payload["aud"], self.idp.provider.client_id)
        self.assertEqual(payload["nonce"], flow["_nonce"])
        self.assertEqual(payload["sub"], "user-1001")
        self.assertGreater(payload["exp"], payload["iat"])

    # -- failures that must NOT consume the code --------------------------
    def test_wrong_verifier_does_not_consume_code(self):
        flow = self.issue()
        status, body = self.idp.token(code=flow["code"], verifier="b" * 43)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid_grant")
        status, body = self.idp.token(code=flow["code"], verifier=flow["_verifier"])
        self.assertEqual(status, 200, "valid code was burned by a wrong verifier")

    def test_wrong_redirect_uri_does_not_consume_code(self):
        flow = self.issue()
        other = self.idp.provider.redirect_uri.replace("issuer=A", "issuer=B")
        status, body = self.idp.token(
            code=flow["code"], verifier=flow["_verifier"], redirect_uri=other
        )
        self.assertEqual(status, 400)
        status, body = self.idp.token(code=flow["code"], verifier=flow["_verifier"])
        self.assertEqual(status, 200)

    def test_concurrent_exchange_yields_exactly_one_token(self):
        """Two simultaneous exchanges of one code: exactly one 200."""
        import concurrent.futures
        import threading

        flow = self.issue()
        barrier = threading.Barrier(2)

        def exchange(_):
            barrier.wait()
            return self.idp.token(code=flow["code"], verifier=flow["_verifier"])[0]

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            statuses = sorted(pool.map(exchange, range(2)))
        self.assertEqual(statuses, [200, 400], statuses)

    def test_wrong_client_does_not_consume_code(self):
        flow = self.issue()
        status, body = self.idp.token(
            code=flow["code"], verifier=flow["_verifier"], client_id="rp-client-for-B"
        )
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "invalid_client")
        status, body = self.idp.token(
            code=flow["code"], verifier=flow["_verifier"], client_id="rp-client-for-A",
            secret="wrong-secret",
        )
        self.assertEqual(status, 401)
        status, body = self.idp.token(code=flow["code"], verifier=flow["_verifier"])
        self.assertEqual(status, 200)

    def test_missing_basic_auth_is_rejected(self):
        flow = self.issue()
        status, body = self.idp.token(code=flow["code"], verifier=flow["_verifier"], basic=False)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "invalid_client")
        status, _ = self.idp.token(code=flow["code"], verifier=flow["_verifier"])
        self.assertEqual(status, 200)

    def test_unknown_code_is_rejected(self):
        status, body = self.idp.token(code="x" * 43, verifier="a" * 43)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid_grant")

    # -- expiry -----------------------------------------------------------
    def test_code_expires_at_60_seconds(self):
        flow = self.issue()
        # The code's window is [t0, t0+60).  Just past 60 s it must be dead.
        self.idp.set_clock_offset(60.5)
        try:
            status, body = self.idp.token(code=flow["code"], verifier=flow["_verifier"])
        finally:
            self.idp.set_clock_offset(0.0)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid_grant")

    def test_code_valid_just_before_expiry(self):
        flow = self.issue()
        self.idp.set_clock_offset(59.0)
        try:
            status, body = self.idp.token(code=flow["code"], verifier=flow["_verifier"])
        finally:
            self.idp.set_clock_offset(0.0)
        self.assertEqual(status, 200, body)

    # -- authorize-endpoint validation ------------------------------------
    def test_redirect_uri_mismatch_never_redirects(self):
        import urllib.parse

        from support import raw_request

        params = {
            "response_type": "code",
            "client_id": self.idp.provider.client_id,
            "redirect_uri": "http://127.0.0.1:9999/callback?issuer=A",
            "state": "s" * 20,
            "nonce": "n" * 20,
            "code_challenge": "a" * 43,
            "code_challenge_method": "S256",
        }
        status, headers, body = raw_request(
            self.idp.host, self.idp.port, "GET", "/authorize?" + urllib.parse.urlencode(params)
        )
        self.assertEqual(status, 400)
        self.assertNotIn("location", headers)

    def test_plain_pkce_method_is_rejected(self):
        import urllib.parse

        from support import raw_request

        params = {
            "response_type": "code",
            "client_id": self.idp.provider.client_id,
            "redirect_uri": self.idp.provider.redirect_uri,
            "state": "s" * 20,
            "nonce": "n" * 20,
            "code_challenge": "a" * 43,
            "code_challenge_method": "plain",
        }
        status, _, _ = raw_request(
            self.idp.host, self.idp.port, "GET", "/authorize?" + urllib.parse.urlencode(params)
        )
        self.assertEqual(status, 400)

    def test_duplicate_query_parameter_is_rejected(self):
        import urllib.parse

        from support import raw_request

        params = {
            "response_type": "code",
            "client_id": self.idp.provider.client_id,
            "redirect_uri": self.idp.provider.redirect_uri,
            "state": "s" * 20,
            "nonce": "n" * 20,
            "code_challenge": "a" * 43,
            "code_challenge_method": "S256",
            "scope": "openid",
        }
        query = urllib.parse.urlencode(params) + "&state=other"
        status, _, _ = raw_request(self.idp.host, self.idp.port, "GET", "/authorize?" + query)
        self.assertEqual(status, 400)

    def test_sub_is_per_issuer(self):
        """A and B hand out the same raw sub for their 'shared' users."""
        with InProcessIdp("B", code_ttl=60) as idp_b:
            flow_a = self.idp.authorize_and_approve(username="shared")
            flow_b = idp_b.authorize_and_approve(username="shared")
            _, body_a = self.idp.token(code=flow_a["code"], verifier=flow_a["_verifier"])
            _, body_b = idp_b.token(code=flow_b["code"], verifier=flow_b["_verifier"])
            self.assertNotEqual(body_a["id_token"], body_b["id_token"])
            import base64
            import json

            def payload(token):
                p = token.split(".")[1]
                return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))

            sub_a = payload(body_a["id_token"])["sub"]
            sub_b = payload(body_b["id_token"])["sub"]
            self.assertEqual(sub_a, sub_b)  # identical raw sub
            self.assertNotEqual(self.idp.provider.issuer, idp_b.provider.issuer)


if __name__ == "__main__":
    unittest.main()
