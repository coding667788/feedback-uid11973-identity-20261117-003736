"""Start the three services for manual use (one foreground process tree).

    python scripts/run_lab.py
    python scripts/run_lab.py --rp-port 8800 --workers 2

Ctrl-C stops the RP supervisor plus every child process.  For the automated
tests use ``scripts/run_tests.py`` instead; this script is what a human uses to
click through the lab in a real browser.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sso_lab import procs  # noqa: E402
from sso_lab.config import build_config  # noqa: E402

BANNER = """
======================================================================
 Dual-IdP SSO lab
======================================================================
 RP (business site)   {rp}
   sign in with A     {rp}/login?issuer=A
   sign in with B     {rp}/login?issuer=B
   current identity   {rp}/me
 IdP A                {idp_a}   (issuer {issuer_a})
 IdP B                {idp_b}   (issuer {issuer_b})
 RP workers           {workers} processes, shared socket {rp}
 Database             {db}
----------------------------------------------------------------------
 Test accounts: alice, shared  (at both providers; same e-mail on purpose)
 Press Ctrl-C to stop.
======================================================================
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rp-port", type=int, default=int(os.environ.get("SSO_RP_PORT", "8800")))
    parser.add_argument("--idp-a-port", type=int, default=int(os.environ.get("SSO_IDP_A_PORT", "8801")))
    parser.add_argument("--idp-b-port", type=int, default=int(os.environ.get("SSO_IDP_B_PORT", "8802")))
    parser.add_argument("--workers", type=int, default=int(os.environ.get("SSO_RP_WORKERS", "2")))
    parser.add_argument("--runtime-dir", default=os.environ.get("SSO_RUNTIME_DIR"))
    parser.add_argument("--code-ttl", type=int, default=int(os.environ.get("SSO_CODE_TTL", "60")))
    parser.add_argument("--no-test-hooks", action="store_true",
                        help="start without SSO_TEST_HOOKS (no /lab endpoints, no crash headers)")
    args = parser.parse_args(argv)

    config = build_config(
        rp_port=args.rp_port,
        idp_a_port=args.idp_a_port,
        idp_b_port=args.idp_b_port,
        runtime_dir=args.runtime_dir,
        code_ttl_seconds=args.code_ttl,
    )
    env = dict(os.environ)
    env.update(
        {
            "PYTHONPATH": str(ROOT),
            "PYTHONUNBUFFERED": "1",
            "SSO_RUNTIME_DIR": str(config.runtime_dir),
            "SSO_RP_PORT": str(args.rp_port),
            "SSO_IDP_A_PORT": str(args.idp_a_port),
            "SSO_IDP_B_PORT": str(args.idp_b_port),
            "SSO_CODE_TTL": str(args.code_ttl),
        }
    )
    env["SSO_TEST_HOOKS"] = "0" if args.no_test_hooks else "1"
    env["SSO_HOLD_DIR"] = str(config.runtime_dir / "holds")
    config.runtime_dir.mkdir(parents=True, exist_ok=True)
    logs = config.runtime_dir / "logs"
    logs.mkdir(exist_ok=True)

    children: list[subprocess.Popen] = []
    handles = []
    try:
        for name in ("A", "B"):
            handle = open(logs / f"idp_{name}.log", "a", encoding="utf-8")
            handles.append(handle)
            children.append(
                subprocess.Popen(
                    [sys.executable, "-m", "sso_lab.idp", "--provider", name],
                    cwd=str(ROOT), env=env, stdout=handle, stderr=subprocess.STDOUT,
                )
            )
        rp_log = open(logs / "rp.log", "a", encoding="utf-8")
        handles.append(rp_log)
        supervisor = subprocess.Popen(
            [sys.executable, "-m", "sso_lab.rp_worker", "--workers", str(args.workers)],
            cwd=str(ROOT), env=env, stdout=rp_log, stderr=subprocess.STDOUT,
        )
        children.append(supervisor)

        print(
            BANNER.format(
                rp=config.rp.base_url,
                idp_a=f"http://{config.providers['A'].host}:{args.idp_a_port}",
                idp_b=f"http://{config.providers['B'].host}:{args.idp_b_port}",
                issuer_a=config.providers["A"].issuer,
                issuer_b=config.providers["B"].issuer,
                workers=args.workers,
                db=config.database_path,
            )
        )

        while True:
            for child in children:
                code = child.poll()
                if code is not None:
                    print(f"service pid={child.pid} exited with {code}; shutting down", file=sys.stderr)
                    return 1
            time.sleep(0.3)
    except KeyboardInterrupt:
        print("\nStopping...")
        return 0
    finally:
        if children:
            procs.kill_process_tree(children[-1].pid)
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                child.kill()
        for handle in handles:
            handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
