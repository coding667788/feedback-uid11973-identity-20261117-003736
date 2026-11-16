"""Unit tests: strict JWS/ID-token verification and PKCE."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import unittest

import support  # noqa: F401  # puts the project root on sys.path

from sso_lab import base64url, jwt, tokens
from sso_lab.jwt import TokenValidationError, verify_hs256_id_token

KEY = b"unit-test-key-0123456789abcdef"
OTHER = b"other-key-0123456789abcdef"
ISS = "http://127.0.0.2:8801/issuer/A"
AUD = "rp-client-for-A"
NONCE = "n-1234567890"
NOW = 1_700_000_000


def claims(**overrides):
    base = {
        "iss": ISS, "sub": "user-1001", "aud": AUD, "nonce": NONCE,
        "iat": NOW - 5, "exp": NOW + 100,
    }
    base.update(overrides)
    return base


def encode_raw(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign(payload: dict, *, key: bytes = KEY, header: dict | None = None) -> str:
    header = header or {"alg": "HS256", "typ": "JWT"}
    h = encode_raw(json.dumps(header, separators=(",", ":")).encode())
    p = encode_raw(json.dumps(payload, separators=(",", ":")).encode())
    sig = encode_raw(hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def verify(token: str, **kwargs):
    options = dict(key=KEY, expected_issuer=ISS, expected_audience=AUD,
                   expected_nonce=NONCE, now=NOW, leeway=0)
    options.update(kwargs)
    return verify_hs256_id_token(token, **options)


class HappyPath(unittest.TestCase):
    def test_valid_token_is_accepted(self):
        result = verify(sign(claims()))
        self.assertEqual(result.issuer, ISS)
        self.assertEqual(result.subject, "user-1001")

    def test_leeway_covers_small_skew(self):
        token = sign(claims(iat=NOW - 2, exp=NOW + 10))
        self.assertTrue(verify(token, now=NOW + 12, leeway=5))

    def test_audience_list_containing_expected_is_accepted(self):
        self.assertTrue(verify(sign(claims(aud=["other", AUD]))))

    def test_signing_helper_round_trip(self):
        token = jwt.sign_hs256({"alg": "HS256", "typ": "JWT"}, claims(), KEY)
        self.assertTrue(verify(token))


class SignatureAndAlgorithm(unittest.TestCase):
    def test_wrong_key_is_rejected(self):
        with self.assertRaises(TokenValidationError):
            verify(sign(claims(), key=OTHER))

    def test_alg_none_is_rejected(self):
        token = sign(claims(), header={"alg": "none"})
        with self.assertRaises(TokenValidationError) as ctx:
            verify(token)
        self.assertIn("alg", str(ctx.exception))

    def test_alg_rs256_is_rejected(self):
        with self.assertRaises(TokenValidationError):
            verify(sign(claims(), header={"alg": "RS256"}))

    def test_alg_is_case_sensitive(self):
        with self.assertRaises(TokenValidationError):
            verify(sign(claims(), header={"alg": "hs256"}))

    def test_jku_header_is_rejected(self):
        token = sign(claims(), header={"alg": "HS256", "jku": "http://evil.example/jwks.json"})
        with self.assertRaises(TokenValidationError) as ctx:
            verify(token)
        self.assertIn("jku", str(ctx.exception))

    def test_jwk_header_is_rejected(self):
        token = sign(claims(), header={"alg": "HS256", "jwks": {"keys": []}})
        with self.assertRaises(TokenValidationError):
            verify(token)

    def test_tampered_payload_is_rejected(self):
        token = sign(claims())
        h, p, s = token.split(".")
        forged = encode_raw(json.dumps(claims(sub="admin")).encode())
        with self.assertRaises(TokenValidationError):
            verify(f"{h}.{forged}.{s}")

    def test_padding_in_signature_is_rejected(self):
        token = sign(claims())
        with self.assertRaises(TokenValidationError):
            verify(token + "==")

    def test_two_segments_only_is_rejected(self):
        h, p, _ = sign(claims()).split(".")
        with self.assertRaises(TokenValidationError):
            verify(f"{h}.{p}")


class Claims(unittest.TestCase):
    def test_wrong_nonce_is_rejected(self):
        with self.assertRaises(TokenValidationError) as ctx:
            verify(sign(claims(nonce="other-nonce")))
        self.assertIn("nonce", str(ctx.exception))

    def test_wrong_aud_is_rejected(self):
        with self.assertRaises(TokenValidationError) as ctx:
            verify(sign(claims(aud="rp-client-for-B")))
        self.assertIn("audience", str(ctx.exception))

    def test_wrong_issuer_is_rejected_even_with_right_key(self):
        impostor = "http://127.0.0.3:8802/issuer/B"
        with self.assertRaises(TokenValidationError) as ctx:
            verify(sign(claims(iss=impostor)))
        self.assertIn("issuer", str(ctx.exception))

    def test_sub_as_number_is_rejected(self):
        with self.assertRaises(TokenValidationError) as ctx:
            verify(sign(claims(sub=12345)))
        self.assertIn("sub", str(ctx.exception))

    def test_sub_with_control_characters_is_rejected(self):
        with self.assertRaises(TokenValidationError):
            verify(sign(claims(sub="user\n1001")))

    def test_iat_as_string_is_rejected(self):
        with self.assertRaises(TokenValidationError):
            verify(sign(claims(iat=str(NOW - 5))))

    def test_exp_as_bool_is_rejected(self):
        with self.assertRaises(TokenValidationError):
            verify(sign(claims(exp=True)))

    def test_aud_as_number_is_rejected(self):
        with self.assertRaises(TokenValidationError):
            verify(sign(claims(aud=42)))

    def test_missing_required_claim_is_rejected(self):
        payload = claims()
        del payload["nonce"]
        with self.assertRaises(TokenValidationError):
            verify(sign(payload))

    def test_duplicate_iss_member_is_rejected(self):
        h = encode_raw(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
        body = json.dumps(claims(), separators=(",", ":"))
        inner = body[1:-1] + ',' + json.dumps({"iss": ISS})[1:-1]
        p = encode_raw(("{" + inner + "}").encode())
        sig = encode_raw(hmac.new(KEY, f"{h}.{p}".encode(), hashlib.sha256).digest())
        with self.assertRaises(TokenValidationError) as ctx:
            verify(f"{h}.{p}.{sig}")
        self.assertIn("duplicate", str(ctx.exception))

    def test_nan_constant_is_rejected(self):
        h = encode_raw(b'{"alg":"HS256","typ":"JWT"}')
        p = encode_raw(b'{"iss":"' + ISS.encode() + b'","sub":"x","aud":"' + AUD.encode()
                       + b'","nonce":"' + NONCE.encode() + b'","iat":1700000000,"exp":NaN}')
        sig = encode_raw(hmac.new(KEY, f"{h}.{p}".encode(), hashlib.sha256).digest())
        with self.assertRaises(TokenValidationError):
            verify(f"{h}.{p}.{sig}")


class TimeWindow(unittest.TestCase):
    def test_expired_token_is_rejected(self):
        token = sign(claims(iat=NOW - 20, exp=NOW - 1))
        with self.assertRaises(TokenValidationError) as ctx:
            verify(token, leeway=0)
        self.assertIn("expired", str(ctx.exception))

    def test_exp_exactly_now_is_accepted_without_leeway(self):
        token = sign(claims(iat=NOW - 60, exp=NOW))
        self.assertTrue(verify(token, leeway=0))

    def test_exp_now_plus_leeway_is_accepted(self):
        token = sign(claims(iat=NOW - 60, exp=NOW - 3))
        self.assertTrue(verify(token, leeway=5, now=NOW + 1))

    def test_exp_now_plus_leeway_plus_one_is_rejected(self):
        token = sign(claims(iat=NOW - 60, exp=NOW - 3))
        with self.assertRaises(TokenValidationError):
            verify(token, leeway=5, now=NOW + 3)

    def test_future_iat_is_rejected(self):
        token = sign(claims(iat=NOW + 50, exp=NOW + 100))
        with self.assertRaises(TokenValidationError):
            verify(token, leeway=0)

    def test_exp_before_iat_is_rejected(self):
        token = sign(claims(iat=NOW + 10, exp=NOW + 5))
        with self.assertRaises(TokenValidationError):
            verify(token)


class PkceAndTokens(unittest.TestCase):
    def test_challenge_is_s256_base64url(self):
        verifier = "a" * 43
        expected = hashlib.sha256(verifier.encode()).digest()
        challenge = tokens.pkce_challenge_s256(verifier)
        self.assertEqual(challenge, base64.urlsafe_b64encode(expected).rstrip(b"=").decode())
        self.assertEqual(len(challenge), 43)

    def test_verifier_length_bounds(self):
        self.assertFalse(tokens.is_valid_pkce_verifier("a" * 42))
        self.assertTrue(tokens.is_valid_pkce_verifier("a" * 43))
        self.assertTrue(tokens.is_valid_pkce_verifier("a" * 128))
        self.assertFalse(tokens.is_valid_pkce_verifier("a" * 129))
        self.assertFalse(tokens.is_valid_pkce_verifier("a" * 43 + "$"))

    def test_mismatched_verifier_fails(self):
        challenge = tokens.pkce_challenge_s256(tokens.random_pkce_verifier())
        self.assertFalse(tokens.pkce_matches(tokens.random_pkce_verifier(), challenge))

    def test_strict_base64url(self):
        with self.assertRaises(base64url.B64UrlError):
            base64url.decode_strict("abc=")
        with self.assertRaises(base64url.B64UrlError):
            base64url.decode_strict("a+b/")
        self.assertEqual(base64url.decode_strict("YWJj"), b"abc")


if __name__ == "__main__":
    unittest.main()
