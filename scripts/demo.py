"""End-to-end demo: drives the whole scenario and prints what it observes.

    python scripts/demo.py

Starts a private lab on free ports, then:
  1. two concurrent logins (A and B) in one browser, delivered out of order;
  2. cross-browser state theft, and proof the victim's login still works;
  3. an issuer swap on a callback, and proof the original still works;
  4. same raw ``sub`` at both issuers -> two separate identities;
  5. a replayed callback -> 409 and no second session;
  6. eight concurrent identical callbacks -> exactly one session;
  7. a hard crash after ID-token verification and after session commit.

The lab is stopped at the end; nothing is left running.
"""

from __future__ import annotations

import concurrent.futures
import os
import sys
import threading
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sso_lab import procs  # noqa: E402
from sso_lab.browser import Browser  # noqa: E402
from sso_lab.harness import _http_json, start_lab  # noqa: E402

LINE = "-" * 70


def header(text: str) -> None:
    print(f"\n{LINE}\n{text}\n{LINE}")


def main() -> int:
    runtime = ROOT / "runtime" / "demo"
    os.environ.setdefault("SSO_TEST_HOOKS", "1")
    lab = start_lab(root_dir=ROOT, runtime_dir=runtime, workers=2, clean=True)
    print(f"RP {lab.rp_base}   IdP A {lab.idp_base('A')}   IdP B {lab.idp_base('B')}")
    print(f"RP worker pids observed: {lab.extra.get('observed_rp_pids')}")
    try:
        header("1. one browser, two logins (A then B), B's callback delivered first")
        browser = Browser("demo-1", lab.rp_base)
        a = browser.start_login("A", "alice")
        b = browser.start_login("B", "alice")
        print(f"  state A={a.state[:16]}…  state B={b.state[:16]}…  (different rows)")
        print(f"  deliver B -> HTTP {browser.deliver(b).status}")
        print(f"  deliver A -> HTTP {browser.deliver(a).status}")
        for row in browser.sessions():
            print(f"  session issuer={row['issuer'].rsplit('/', 1)[-1]} subject={row['subject']}")

        header("2. cross-browser state theft")
        victim = Browser("demo-victim", lab.rp_base)
        thief = Browser("demo-thief", lab.rp_base)
        pending = victim.start_login("A", "shared")
        stolen = thief.get(pending.callback_url)
        print(f"  thief replays victim's callback -> HTTP {stolen.status} / {stolen.lab_error}"
              f" ({stolen.header('X-Lab-Reason')})")
        print(f"  thief /me -> {thief.me()}")
        print(f"  victim delivers the same callback afterwards -> HTTP "
              f"{victim.deliver(pending).status}")
        print(f"  victim /me -> {victim.me()['subject']} @ "
              f"{victim.me()['issuer'].rsplit('/', 1)[-1]}")

        header("3. issuer swap on the callback")
        browser = Browser("demo-3", lab.rp_base)
        pending = browser.start_login("A", "alice")
        params = pending.callback_query()
        params["issuer"] = "B"
        swapped = browser.get(f"{lab.rp_base}/callback?" + urllib.parse.urlencode(params))
        print(f"  callback ?issuer=B for a state started on A -> HTTP {swapped.status}: "
              f"{swapped.header('X-Lab-Reason')}")
        print(f"  original A callback still works -> HTTP {browser.deliver(pending).status}")

        header("4. identical raw sub at both issuers stays two identities")
        browser = Browser("demo-4", lab.rp_base)
        browser.login("A", "shared")
        first = browser.me()
        browser.login("B", "shared")
        second = browser.me()
        print(f"  A: sub={first['subject']} session={first['session_id'][:12]}…")
        print(f"  B: sub={second['subject']} session={second['session_id'][:12]}…")
        print(f"  sessions for this browser: {len(browser.sessions())}")

        header("5. replay of a completed callback")
        browser = Browser("demo-5", lab.rp_base)
        pending = browser.start_login("A", "alice")
        first_status = browser.deliver(pending).status
        replay_status = browser.deliver(pending).status
        print(f"  first  -> HTTP {first_status}")
        print(f"  replay -> HTTP {replay_status}, sessions={len(browser.sessions())}")

        header("6. eight concurrent identical callbacks")
        browser = Browser("demo-6", lab.rp_base)
        pending = browser.start_login("B", "alice")
        cookie = browser.cookie_value("rp_sid")
        path = "/callback?" + urllib.parse.urlencode(pending.callback_query())
        barrier = threading.Barrier(8)

        def hit(_):
            import http.client

            barrier.wait()
            conn = http.client.HTTPConnection("127.0.0.1", lab.rp_port, timeout=20)
            try:
                conn.request("GET", path, headers={
                    "Cookie": f"rp_sid={cookie}", "X-Lab-Delay": "0.4",
                })
                response = conn.getresponse()
                response.read()
                return response.status
            finally:
                conn.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            statuses = sorted(pool.map(hit, range(8)))
        print(f"  statuses={statuses}")
        print(f"  sessions for this browser: {len(browser.sessions())}")

        header("7a. real crash after ID-token verification, before commit")
        browser = Browser("demo-7a", lab.rp_base)
        pending = browser.start_login("A", "alice")
        result = crash_or_hold(lab, browser, pending, "after-verify")
        print(f"  client saw: {result}")
        print(f"  crash trace: {_tail(lab.runtime_dir / 'logs' / 'rp.log', 'test-hook')}")
        wait_workers(lab)
        print(f"  after restart: /me -> {browser.me()}")
        early = browser.deliver(pending)
        time.sleep(1.4)  # past the abandoned-claim grace period
        replay = browser.deliver(pending)
        print(f"  replay right after the kill -> HTTP {early.status} (claim still in flight)")
        print(f"  replay after grace -> HTTP {replay.status}: {replay.header('X-Lab-Reason')}")
        fresh = browser.start_login("A", "alice")
        print(f"  fresh login required -> HTTP {browser.deliver(fresh).status}")

        header("7b. real crash after session commit, before response")
        browser = Browser("demo-7b", lab.rp_base)
        pending = browser.start_login("B", "alice")
        result = crash_or_hold(lab, browser, pending, "after-commit")
        print(f"  client saw: {result}")
        print(f"  crash trace: {_tail(lab.runtime_dir / 'logs' / 'rp.log', 'test-hook')}")
        wait_workers(lab)
        identity = browser.me()
        print(f"  after restart: /me -> {identity['subject']} @ "
              f"{identity['issuer'].rsplit('/', 1)[-1]}")
        replay = browser.deliver(pending)
        print(f"  replay -> HTTP {replay.status}, sessions={len(browser.sessions())}")

        header("summary")
        status, stats = _http_json(f"{lab.rp_base}/lab/stats", timeout=5)
        print(f"  {stats}")
        return 0
    finally:
        # Remember the pids before stop() clears the process handles.
        started = _started_pids(lab)
        lab.stop()
        time.sleep(0.5)
        strays = sorted(pid for pid in started if procs.pid_alive(pid))
        print(f"\nlab stopped; all {len(started)} started pids gone:", not strays, strays)


def crash_or_hold(lab, browser, pending, point: str) -> dict:
    """Kill the worker from *outside* at the hold point (no in-RP cooperation)."""
    import http.client
    import json
    import time

    hold_dir = lab.runtime_dir / "holds"
    before = set(hold_dir.glob(f"{point}.*.json")) if hold_dir.exists() else set()
    path = "/callback?" + urllib.parse.urlencode(pending.callback_query())
    outcome: dict = {}

    def request():
        conn = http.client.HTTPConnection("127.0.0.1", lab.rp_port, timeout=40)
        try:
            conn.request("GET", path, headers={
                "Cookie": f"rp_sid={browser.cookie_value('rp_sid')}",
                "X-Lab-Hold": point,
            })
            response = conn.getresponse()
            response.read()
            outcome["status"] = response.status
        except (ConnectionError, OSError) as exc:
            outcome["dropped"] = repr(exc)
        finally:
            conn.close()

    thread = threading.Thread(target=request, daemon=True)
    thread.start()
    deadline = time.time() + 15
    marker = None
    while time.time() < deadline:
        candidates = set(hold_dir.glob(f"{point}.*.json")) - before if hold_dir.exists() else set()
        if candidates:
            marker = sorted(candidates)[0]
            break
        time.sleep(0.05)
    if marker is None:
        return {"error": "no hold marker"}
    info = json.loads(marker.read_text(encoding="utf-8"))
    killed = procs.hard_kill(info["pid"])
    deadline = time.time() + 10
    while time.time() < deadline and procs.pid_alive(info["pid"]):
        time.sleep(0.05)
    thread.join(timeout=30)
    marker.unlink(missing_ok=True)
    return {"killed_pid": info["pid"], "kill_ok": killed, "client": outcome}


def wait_workers(lab, count: int = 2) -> None:
    import time

    deadline = time.time() + 20
    while time.time() < deadline:
        pids = set()
        for _ in range(30):
            status, payload = _http_json(f"{lab.rp_base}/healthz", timeout=1.0)
            if status == 200 and payload:
                pids.add(payload["pid"])
        if len(pids) >= count:
            return
        time.sleep(0.2)
    raise SystemExit("RP workers did not come back")


def _tail(path: Path, needle: str, lines: int = 3) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "<no log>"
    hits = [line.strip() for line in text.splitlines() if needle in line]
    return " | ".join(hits[-lines:]) or "<no trace>"


def _started_pids(lab) -> set[int]:
    pids = {lab.rp_supervisor.process.pid} if lab.rp_supervisor else set()
    pids.update(handle.process.pid for handle in lab.services.values())
    pids.update(lab.extra.get("observed_rp_pids", []))
    return pids


if __name__ == "__main__":
    raise SystemExit(main())
