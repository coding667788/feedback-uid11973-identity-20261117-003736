"""Windows runner for the whole automated suite.

    python scripts/run_tests.py            # everything
    python scripts/run_tests.py -v         # verbose per-test output
    python scripts/run_tests.py unit       # only unit tests (no processes)
    python scripts/run_tests.py binding crash

Prints a compact result table and writes ``runtime/test-report.json``.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

GROUPS = {
    "unit": ["test_jwt", "test_idp_codes"],
    "binding": ["test_rp_binding"],
    "crash": ["test_crash"],
    "process": ["test_multi_process"],
    "simulator": ["test_simulator"],
}
ORDER = ["unit", "binding", "crash", "process", "simulator"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("groups", nargs="*", help="subset of: " + ", ".join(ORDER))
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--keep-going", action="store_true", default=True)
    args = parser.parse_args(argv)

    selected = args.groups or ORDER
    unknown = [g for g in selected if g not in GROUPS]
    if unknown:
        parser.error(f"unknown group(s): {', '.join(unknown)}")

    modules: list[str] = []
    for group in selected:
        modules.extend(GROUPS[group])

    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    env["PYTHONUNBUFFERED"] = "1"
    env["SSO_TEST_HOOKS"] = "1"

    command = [sys.executable, "-m", "unittest", *modules]
    if args.verbose:
        command.append("-v")

    started = time.time()
    print(f"$ {' '.join(command)}   (cwd={TESTS})", flush=True)
    process = subprocess.run(command, cwd=str(TESTS), env=env)
    elapsed = time.time() - started

    report = {
        "command": command,
        "groups": selected,
        "modules": modules,
        "module_count": len(modules),
        "exit_code": process.returncode,
        "elapsed_seconds": round(elapsed, 2),
        "python": sys.version,
        "platform": sys.platform,
    }
    out = ROOT / "runtime" / "test-report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nexit={process.returncode} elapsed={elapsed:.1f}s report={out}")
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
