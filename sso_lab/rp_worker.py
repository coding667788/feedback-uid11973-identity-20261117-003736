"""RP supervisor + worker processes.

``python -m sso_lab.rp_worker --workers 2`` starts two genuine OS processes.
The supervisor (this process) binds the listening socket once and passes the
inherited socket to every worker via ``multiprocessing`` spawn; each worker then
serves requests from that shared socket, so the OS distributes connections
across both processes.  Killing either worker still leaves the service up.

The supervisor also mirrors the worker count to stdout so the run instructions
and the tests can see real PIDs.
"""

from __future__ import annotations

import argparse
import multiprocessing as mp
import os
import socket
import sys
import threading

from .config import build_config
from .rp import RelyingParty
from .web import install_signal_handlers


# ----------------------------------------------------------------------
# worker
# ----------------------------------------------------------------------
def run_worker(config, shared_sock) -> None:
    """Entry point of one RP worker process (also used by the tests)."""
    # RelyingParty picks the clock it needs: env offset normally, a small
    # shared offset file when the lab runs with SSO_TEST_HOOKS=1.
    service = RelyingParty(config)
    host, port = shared_sock.getsockname()[:2]
    server = service.make_server(host, port, sock=shared_sock)
    sys.stderr.write(f"[rp-worker] pid={os.getpid()} listening on http://{host}:{port}\n")
    sys.stderr.flush()
    stop = threading.Event()
    install_signal_handlers(stop)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    thread.start()
    while not stop.wait(0.2):
        pass
    server.shutdown()
    server.server_close()


def spawn_worker(config, shared_sock, ctx=None):
    ctx = ctx or mp.get_context("spawn")
    process = ctx.Process(target=run_worker, args=(config, shared_sock), daemon=False)
    process.start()
    return process


# ----------------------------------------------------------------------
# supervisor
# ----------------------------------------------------------------------
def _bind_listener(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(128)
    return sock


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the RP as N worker processes sharing one port")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--runtime-dir", default=None)
    args = parser.parse_args(argv)
    if args.workers < 1:
        raise SystemExit("--workers must be >= 1")

    config = build_config(
        rp_port=args.port or int(os.environ.get("SSO_RP_PORT", "8800")),
        idp_a_port=int(os.environ.get("SSO_IDP_A_PORT", "8801")),
        idp_b_port=int(os.environ.get("SSO_IDP_B_PORT", "8802")),
        runtime_dir=args.runtime_dir or os.environ.get("SSO_RUNTIME_DIR"),
        code_ttl_seconds=int(os.environ.get("SSO_CODE_TTL", "60")),
    )

    # Make sure the schema exists before the first request, and that the runtime
    # directory is created, no matter which process wins the race.
    RelyingParty(config).bootstrap()

    rp = config.rp
    sock = _bind_listener(rp.host, rp.port)
    host, port = sock.getsockname()[:2]
    ctx = mp.get_context("spawn")
    children = [spawn_worker(config, sock, ctx) for _ in range(args.workers)]
    print(
        f"[rp] supervisor pid={os.getpid()} listening on http://{host}:{port} "
        f"with {len(children)} workers: {[p.pid for p in children]}",
        flush=True,
    )

    stop = threading.Event()
    install_signal_handlers(stop)
    try:
        while not stop.wait(0.25):
            for index, child in enumerate(children):
                if child.is_alive():
                    continue
                sys.stderr.write(
                    f"[rp] worker pid={child.pid} exited with {child.exitcode}; restarting\n"
                )
                sys.stderr.flush()
                child.close()
                children[index] = spawn_worker(config, sock, ctx)
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
        for child in children:
            child.join(timeout=5)
        sock.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
