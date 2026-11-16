"""Process harness: start the three services + real RP worker processes.

Used by the automated test-suite and by the demo runner.  Ports and the runtime
directory are chosen by the caller; ``SSO_TEST_HOOKS=1`` and the same clock
offset are propagated to every child.

The RP is started as a *supervisor* process that binds the listening socket and
hands it to N worker processes, exactly the way ``python -m sso_lab.rp_worker``
runs.  The harness keeps the supervisor's pid plus each worker's pid, because
the crash tests need to terminate a specific worker and restart the service.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from . import faults as fault_mod
from . import procs

ROOT = Path(__file__).resolve().parent.parent


class HarnessError(RuntimeError):
    pass


def _free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def pick_ports(count: int, host: str = "127.0.0.1") -> list[int]:
    ports = []
    for _ in range(count):
        port = _free_port(host)
        while port in ports:
            port = _free_port(host)
        ports.append(port)
    return ports


def _http_json(url: str, timeout: float = 5.0) -> tuple[int, Any]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, None


@dataclass
class ServiceHandle:
    name: str
    process: subprocess.Popen
    url: str
    log_path: Path
    log_file: Any = None

    def alive(self) -> bool:
        return self.process.poll() is None

    def close(self) -> None:
        if self.log_file is not None:
            try:
                self.log_file.close()
            except OSError:
                pass
            self.log_file = None


@dataclass
class Lab:
    """One running lab instance (three services, two RP workers)."""

    root_dir: Path
    runtime_dir: Path
    rp_port: int
    idp_ports: Mapping[str, int]
    env: dict[str, str]
    services: dict[str, ServiceHandle] = field(default_factory=dict)
    rp_supervisor: ServiceHandle | None = None
    workers: int = 2
    extra: dict[str, Any] = field(default_factory=dict)

    # -- URLs -------------------------------------------------------------
    @property
    def rp_base(self) -> str:
        return f"http://127.0.0.1:{self.rp_port}"

    def idp_base(self, name: str) -> str:
        host = "127.0.0.2" if name == "A" else "127.0.0.3"
        return f"http://{host}:{self.idp_ports[name]}"

    @property
    def db_path(self) -> Path:
        return self.runtime_dir / "sso_lab.sqlite3"

    # -- lifecycle --------------------------------------------------------
    def wait_ready(self, timeout: float = 25.0) -> None:
        deadline = time.time() + timeout
        targets = [f"{self.rp_base}/healthz"] + [
            f"{self.idp_base(name)}/healthz" for name in ("A", "B")
        ]
        for target in targets:
            while True:
                status, _ = _http_json(target, timeout=1.0)
                if status == 200:
                    break
                if time.time() > deadline:
                    raise HarnessError(f"service did not become ready: {target}")
                time.sleep(0.1)
        # Wait until both RP workers are actually serving (the socket is shared,
        # so probe a handful of times and insist on seeing two distinct pids).
        pids: set[int] = set()
        while time.time() < deadline:
            for _ in range(30):
                status, payload = _http_json(f"{self.rp_base}/healthz", timeout=1.0)
                if status == 200 and payload:
                    pids.add(payload.get("pid"))
            if len(pids) >= self.workers:
                self.extra["observed_rp_pids"] = sorted(p for p in pids if p)
                return
            time.sleep(0.2)
        raise HarnessError(f"expected {self.workers} RP worker pids, saw {pids}")

    def stop(self) -> None:
        # The RP supervisor owns its worker children; kill it first so the
        # workers cannot be orphaned on Windows.
        if self.rp_supervisor is not None:
            procs.kill_process_tree(self.rp_supervisor.process.pid)
            self._terminate(self.rp_supervisor.process)
            self.rp_supervisor.close()
        for handle in list(self.services.values()):
            self._terminate(handle.process)
            handle.close()
        self.services.clear()

    @staticmethod
    def _terminate(process: subprocess.Popen, timeout: float = 8.0) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=timeout)

    # -- workers ----------------------------------------------------------
    def rp_worker_pids(self) -> list[int]:
        """Live RP worker pids (children of the supervisor)."""
        parent = self.rp_supervisor.process.pid if self.rp_supervisor else None
        return [pid for pid in procs.children_of(parent) if pid in set(self.extra.get("observed_rp_pids", []))] or procs.children_of(parent)

    def kill_rp_worker(self, pid: int | None = None) -> dict:
        """Terminate a real RP worker process (hard kill, no graceful shutdown).

        Returns a dict with the pid killed and whether the service stayed up.
        """
        pids = self.rp_worker_pids()
        if not pids:
            raise HarnessError("no RP worker pids found")
        target = pid if pid is not None else pids[0]
        procs.hard_kill(target)
        deadline = time.time() + 10
        while time.time() < deadline and procs.pid_alive(target):
            time.sleep(0.05)
        status, payload = _http_json(f"{self.rp_base}/healthz", timeout=2.0)
        return {
            "killed": target,
            "target_dead": not procs.pid_alive(target),
            "service_up_after_kill": status == 200,
            "served_by_pid": payload.get("pid") if payload else None,
        }

    def restart_rp(self, workers: int = 2) -> None:
        """Stop the supervisor and start a fresh one on the same port."""
        if self.rp_supervisor is not None:
            procs.kill_process_tree(self.rp_supervisor.process.pid)
            self._terminate(self.rp_supervisor.process)
            self.rp_supervisor.close()
        log_path = self.runtime_dir / "logs" / "rp.log"
        log_file = open(log_path, "a", encoding="utf-8")
        supervisor = subprocess.Popen(
            [sys.executable, "-m", "sso_lab.rp_worker", "--workers", str(workers)],
            cwd=str(self.root_dir), env=self.env, stdout=log_file, stderr=subprocess.STDOUT,
        )
        self.rp_supervisor = ServiceHandle("rp", supervisor, self.rp_base, log_path, log_file)
        self.wait_ready_rp()

    def wait_ready_rp(self, timeout: float = 20.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            status, _ = _http_json(f"{self.rp_base}/healthz", timeout=1.0)
            if status == 200:
                time.sleep(0.4)  # let the second worker bind as well
                return
            time.sleep(0.1)
        raise HarnessError("RP supervisor did not come back up")

    # -- logs -------------------------------------------------------------
    def log_text(self, name: str) -> str:
        path = self.runtime_dir / "logs" / f"{name}.log"
        return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""

    # -- clock control ----------------------------------------------------
    def set_idp_clock(self, name: str, offset: float) -> None:
        status, payload = _http_json(
            f"{self.idp_base(name)}/lab/clock?offset={offset}"
        )
        if status != 200:
            raise HarnessError(f"could not move IdP {name} clock: {status} {payload}")


def _write_log(path: Path, text: str, mode: str = "a") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, mode, encoding="utf-8") as handle:
        handle.write(text)


def start_lab(
    *,
    root_dir: str | Path | None = None,
    runtime_dir: str | Path | None = None,
    workers: int = 2,
    code_ttl: int = 60,
    clock_offset: float = 0.0,
    test_hooks: bool = True,
    faults: Mapping[str, Iterable] | None = None,
    env_extra: Mapping[str, str] | None = None,
    clean: bool = True,
    startup_timeout: float = 30.0,
) -> Lab:
    """Start IdP A, IdP B and an RP supervisor with ``workers`` workers."""
    root = Path(root_dir) if root_dir else ROOT
    runtime = Path(runtime_dir) if runtime_dir else root / "runtime" / f"lab-{int(time.time()*1000)}"
    if clean and runtime.exists():
        shutil.rmtree(runtime, ignore_errors=True)
    (runtime / "logs").mkdir(parents=True, exist_ok=True)

    rp_port, idp_a_port, idp_b_port = pick_ports(3)
    env = dict(os.environ)
    env.update(
        {
            "PYTHONPATH": str(root),
            "PYTHONUNBUFFERED": "1",
            "SSO_RUNTIME_DIR": str(runtime),
            "SSO_RP_PORT": str(rp_port),
            "SSO_IDP_A_PORT": str(idp_a_port),
            "SSO_IDP_B_PORT": str(idp_b_port),
            "SSO_CODE_TTL": str(code_ttl),
            "SSO_CLOCK_OFFSET_SECONDS": repr(float(clock_offset)),
            "SSO_TEST_HOOKS": "1" if test_hooks else "0",
            "SSO_HOLD_DIR": str(runtime / "holds"),
        }
    )
    for name, spec in (faults or {}).items():
        env[f"SSO_IDP_{name}_FAULTS"] = spec if isinstance(spec, str) else fault_mod.describe(dict(spec))
    env.update(env_extra or {})

    lab = Lab(
        root_dir=root,
        runtime_dir=runtime,
        rp_port=rp_port,
        idp_ports={"A": idp_a_port, "B": idp_b_port},
        env=env,
        workers=workers,
    )

    for name in ("A", "B"):
        log_path = runtime / "logs" / f"idp_{name}.log"
        log_file = open(log_path, "w", encoding="utf-8")
        process = subprocess.Popen(
            [sys.executable, "-m", "sso_lab.idp", "--provider", name],
            cwd=str(root), env=env, stdout=log_file, stderr=subprocess.STDOUT,
        )
        lab.services[name] = ServiceHandle(name, process, lab.idp_base(name), log_path, log_file)

    log_path = runtime / "logs" / "rp.log"
    log_file = open(log_path, "w", encoding="utf-8")
    supervisor = subprocess.Popen(
        [sys.executable, "-m", "sso_lab.rp_worker", "--workers", str(workers)],
        cwd=str(root), env=env, stdout=log_file, stderr=subprocess.STDOUT,
    )
    lab.rp_supervisor = ServiceHandle("rp", supervisor, lab.rp_base, log_path, log_file)
    lab.wait_ready(timeout=startup_timeout)
    return lab


def start_lab_with_fault(name: str, spec: str | Mapping[str, str], **kwargs) -> Lab:
    return start_lab(faults={name: spec}, **kwargs)
