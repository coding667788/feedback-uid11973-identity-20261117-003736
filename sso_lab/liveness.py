"""Cross-process liveness checks on Windows (no third-party psutil).

``os.kill(pid, 0)`` is not a liveness probe on Windows: after the target exits
it succeeds and merely synthesises an exit code.  ``OpenProcess`` +
``WaitForSingleObject`` is the reliable check, with a fallback for non-Windows
platforms.
"""

from __future__ import annotations

import os
import sys

if sys.platform == "win32":  # pragma: no cover - platform specific
    import ctypes
    from ctypes import wintypes

    _SYNCHRONIZE = 0x00100000
    _WAIT_TIMEOUT = 0x00000102
    _ERROR_ACCESS_DENIED = 5

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _kernel32.WaitForSingleObject.restype = wintypes.DWORD
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    def process_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        handle = _kernel32.OpenProcess(_SYNCHRONIZE, False, int(pid))
        if not handle:
            # Access denied means the process exists but we cannot open it.
            return ctypes.get_last_error() == _ERROR_ACCESS_DENIED
        try:
            return _kernel32.WaitForSingleObject(handle, 0) == _WAIT_TIMEOUT
        finally:
            _kernel32.CloseHandle(handle)

else:  # pragma: no cover - platform specific

    def process_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True
