"""Test hooks, enabled only when the server sets ``SSO_TEST_HOOKS=1``.

The RP honours these request headers *only* in that mode:

``X-Lab-Delay: <seconds>``
    Sleep before starting the token exchange (max 5 s).  Widens the window in
    which a burst of concurrent callbacks is genuinely concurrent.

``X-Lab-Crash: after-verify | after-commit``
    Terminate this RP worker process at the named point with ``os._exit``.
    ``after-verify`` is after the ID token has been verified and *before* the
    local transaction commits; ``after-commit`` is after the session commit and
    before the HTTP response is written.

``X-Lab-Hold: after-verify | after-commit``
    Instead of dying, park at the same point, announce the pid through a marker
    file under ``<runtime>/holds/`` and wait up to ``HOLD_SECONDS``.  This lets
    the *test harness* (a different process) hard-kill the RP worker at the
    exact synchronisation point, i.e. the same failure without any cooperation
    from inside the RP.

All of these are refused unless the environment opt-in is set, so a normally
started lab ignores them and behaves like production code.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ENV_FLAG = "SSO_TEST_HOOKS"
ENV_HOLD_DIR = "SSO_HOLD_DIR"
MAX_DELAY = 5.0
HOLD_SECONDS = 20.0
CRASH_POINTS = frozenset({"after-verify", "after-commit"})


def enabled() -> bool:
    return os.environ.get(ENV_FLAG) == "1"


def requested_delay(header_value: str | None) -> float:
    if not enabled() or not header_value:
        return 0.0
    try:
        seconds = float(header_value)
    except ValueError:
        return 0.0
    if seconds != seconds or seconds < 0:
        return 0.0
    return min(seconds, MAX_DELAY)


def sleep_if_requested(header_value: str | None) -> None:
    seconds = requested_delay(header_value)
    if seconds:
        time.sleep(seconds)


def crash_requested(point: str, header_value: str | None) -> bool:
    return enabled() and header_value == point and point in CRASH_POINTS


def hold_requested(point: str, header_value: str | None) -> bool:
    return enabled() and header_value == point and point in CRASH_POINTS


def hold(point: str, token: str = "") -> None:
    """Announce this pid and block at the synchronisation point.

    The marker file is written (and flushed) *before* blocking, so the harness
    can wait for it, then kill this pid with no chance for cleanup.
    """
    directory = Path(os.environ.get(ENV_HOLD_DIR, "runtime/holds"))
    directory.mkdir(parents=True, exist_ok=True)
    name = f"{point}.{os.getpid()}.json"
    marker = directory / name
    tmp = directory / (name + ".tmp")
    tmp.write_text(
        f'{{"point": "{point}", "pid": {os.getpid()}, "token": "{token}"}}',
        encoding="utf-8",
    )
    os.replace(tmp, marker)
    sys.stderr.write(f"[test-hook] holding at {point!r} pid={os.getpid()}\n")
    sys.stderr.flush()
    deadline = time.time() + HOLD_SECONDS
    while time.time() < deadline:
        time.sleep(0.05)
    # Nobody killed us: fail the request rather than pretend it succeeded.
    _unlink(marker)
    raise RuntimeError(f"hold at {point!r} timed out; harness never killed pid {os.getpid()}")


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def die(point: str) -> None:
    """Terminate this process for real; no exception handling, no cleanup."""
    try:
        sys.stderr.write(f"\n[test-hook] hard-exit at crash point {point!r} pid={os.getpid()}\n")
        sys.stderr.flush()
        sys.stdout.flush()
    finally:
        os._exit(70)
