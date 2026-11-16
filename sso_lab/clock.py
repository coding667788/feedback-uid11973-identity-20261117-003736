"""Clock helpers.

The lab supports a per-process "clock offset" environment variable so the expiry
boundary can be tested deterministically.  ``SSO_CLOCK_OFFSET_SECONDS`` (a float)
is added to every service's notion of "now"; services started with the same
offset share a coherent view.  This is test scaffolding, documented in the run
instructions, and never influenced by network input.
"""

from __future__ import annotations

import math
import os
import time
from pathlib import Path

from .errors import ConfigurationError


class Clock:
    def __init__(self, offset_seconds: float = 0.0) -> None:
        self._offset = float(offset_seconds)

    @classmethod
    def from_env(cls) -> "Clock":
        raw = os.environ.get("SSO_CLOCK_OFFSET_SECONDS", "0")
        try:
            offset = float(raw)
        except ValueError:
            raise ConfigurationError(f"SSO_CLOCK_OFFSET_SECONDS is not a number: {raw!r}")
        if not math.isfinite(offset):
            raise ConfigurationError("SSO_CLOCK_OFFSET_SECONDS must be finite")
        return cls(offset)

    @property
    def offset(self) -> float:
        return self._offset

    def set_offset(self, offset_seconds: float) -> None:
        """Test hook: move this service's clock (see ``/lab/clock``)."""
        value = float(offset_seconds)
        if not math.isfinite(value):
            raise ConfigurationError("clock offset must be finite")
        self._offset = value

    def now(self) -> float:
        return time.time() + self._offset

    def epoch(self) -> int:
        return int(self.now())


class SharedOffsetClock(Clock):
    """Clock offset stored in a small file so all RP workers agree.

    Only constructed when ``SSO_TEST_HOOKS=1``; the offset is written by the
    ``/lab/clock`` endpoint and re-read on every call (cheap, and it removes any
    need for cross-process signalling).  A missing or corrupt file means zero.
    """

    def __init__(self, path) -> None:
        super().__init__(0.0)
        self.path = Path(path)

    def _read(self) -> float:
        try:
            raw = self.path.read_text(encoding="ascii").strip()
        except (FileNotFoundError, OSError):
            return 0.0
        try:
            value = float(raw)
        except ValueError:
            return 0.0
        return value if math.isfinite(value) else 0.0

    @property
    def offset(self) -> float:  # type: ignore[override]
        return self._read()

    def set_offset(self, offset_seconds: float) -> None:
        value = float(offset_seconds)
        if not math.isfinite(value):
            raise ConfigurationError("clock offset must be finite")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(repr(value), encoding="ascii")
        os.replace(tmp, self.path)

    def now(self) -> float:
        return time.time() + self._read()
