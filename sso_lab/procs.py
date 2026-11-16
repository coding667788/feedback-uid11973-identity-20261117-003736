"""Process helpers used by the harness on Windows (ctypes only)."""

from __future__ import annotations

import ctypes
from ctypes import wintypes

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_TH32CS_SNAPPROCESS = 0x00000002
_PROCESS_TERMINATE = 0x0001
_SYNCHRONIZE = 0x00100000


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def _snapshot():
    snapshot = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snapshot == -1 or snapshot == 0xFFFFFFFFFFFFFFFF:
        raise OSError("CreateToolhelp32Snapshot failed")
    entry = _PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
    try:
        if not _kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return
        while True:
            yield int(entry.th32ProcessID), int(entry.th32ParentProcessID), entry.szExeFile
            if not _kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        _kernel32.CloseHandle(snapshot)


def _pid_alive(pid: int) -> bool:
    handle = _kernel32.OpenProcess(_SYNCHRONIZE, False, pid)
    if not handle:
        return False
    try:
        result = _kernel32.WaitForSingleObject(handle, 0)
        return result == 0x00000102  # WAIT_TIMEOUT -> still running
    finally:
        _kernel32.CloseHandle(handle)


def value_alive(pid: int) -> bool:
    """Public alias (avoids leading-underscore across modules)."""
    return _pid_alive(pid)


def children_of(pid: int | None) -> list[int]:
    if pid is None:
        return []
    return [child for child, parent, _ in _snapshot() if parent == pid and _pid_alive(child)]


def descendants_of(pid: int) -> list[int]:
    result: list[int] = []
    frontier = [pid]
    while frontier:
        current = frontier.pop()
        for child in children_of(current):
            if child not in result:
                result.append(child)
                frontier.append(child)
    return result


def hard_kill(pid: int) -> bool:
    """Terminate a process without giving it a chance to clean up."""
    handle = _kernel32.OpenProcess(_PROCESS_TERMINATE, False, pid)
    if not handle:
        return False
    try:
        return bool(_kernel32.TerminateProcess(handle, 1))
    finally:
        _kernel32.CloseHandle(handle)


def kill_process_tree(pid: int) -> None:
    for child in descendants_of(pid):
        hard_kill(child)
    hard_kill(pid)


# public names without the leading underscore
pid_alive = value_alive
