"""Error type carrying the extra facts the lab needs to report."""

from __future__ import annotations

from typing import Any


class LabError(Exception):
    """An expected, reportable failure (never a bare 500)."""

    code = "lab_error"
    http_status = 400

    def __init__(self, message: str, *, code: str | None = None, details: Any = None):
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        self.details = details


class InputError(LabError):
    code = "invalid_request"
    http_status = 400


class UnauthorizedClient(LabError):
    code = "invalid_client"
    http_status = 401


class GrantError(LabError):
    """Token-endpoint grant failure; atomically rolled back by the caller."""

    code = "invalid_grant"
    http_status = 400


class CallbackError(LabError):
    code = "invalid_callback"
    http_status = 400


class StateError(CallbackError):
    code = "invalid_state"


class BrowserMismatchError(StateError):
    """The state belongs to a different browser session."""

    code = "browser_mismatch"


class IssuerMismatchError(StateError):
    """The callback's issuer is not the issuer the transaction pinned."""

    code = "issuer_mismatch"


class TransactionError(CallbackError):
    code = "invalid_transaction"


class ReplayError(CallbackError):
    """The state is real but already used / claimed: a replay, not a forgery."""

    code = "replayed_callback"
    http_status = 409


class ConfigurationError(RuntimeError):
    """A deployment mistake (bad env var, pinned URL mismatch)."""
