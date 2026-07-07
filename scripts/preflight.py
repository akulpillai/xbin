#!/usr/bin/env python3
"""Preflight readiness checker for the xbin end-to-end pipeline.

Stdlib-only so it runs on a bare `python3` BEFORE any venv exists (checking for
the venv/deps is one of its jobs). Prints an aligned PASS/FAIL/WARN table and
exits nonzero if any *required* check for the chosen tier fails.

  smoke  fid + ghidriff            -> Docker + bind:latest + Redis + a test binary
  full   + bind_se + arbiter       -> + ollama (qwen2.5-coder:7b)
  heavy  + symbolic_regression     -> + QEMU/FastDyn inside bind:latest

Usage:
  python3 scripts/preflight.py [--tier smoke|full|heavy] [--attach]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import urllib.request

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

GRPC_PORT = 50051
REST_PORT = 8000
OLLAMA_URL = "http://127.0.0.1:11434/api/tags"
OLLAMA_MODEL = "qwen2.5-coder:7b"
BIND_IMAGE = "bind:latest"
QEMU_BIN = "/home/bind/Morpheus/qemu/build/qemu-system-arm"
FASTDYN_SO = "/home/bind/Morpheus/qemu/build/tests/tcg/plugins/libvirtual.so"
DEFAULT_BINARY = os.environ.get(
    "XBIN_TEST_BINARY",
    os.path.join(REPO_ROOT, "submodules", "Morpheus", "example_config", "gs3.bin"),
)

PASS, FAIL, WARN = "PASS", "FAIL", "WARN"


class Check:
    def __init__(self, name, result, detail="", required=True):
        self.name, self.result, self.detail, self.required = name, result, detail, required


def _run(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except Exception as e:
        return 1, str(e)


def _port_open(port, host="localhost"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def check_docker():
    rc, out = _run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=15)
    return Check("docker daemon", PASS if rc == 0 else FAIL,
                 out.strip() if rc == 0 else "docker not reachable")


def check_bind_image():
    rc, _ = _run(["docker", "image", "inspect", BIND_IMAGE], timeout=15)
    return Check(f"{BIND_IMAGE} image", PASS if rc == 0 else FAIL,
                 "present" if rc == 0 else "missing -> scripts/rebuild_bind_base.sh")


def check_qemu_in_base(tier):
    # Only meaningful (and required) for the heavy tier (symbolic_regression).
    required = tier == "heavy"
    rc, _ = _run(["docker", "image", "inspect", BIND_IMAGE], timeout=15)
    if rc != 0:
        return Check("QEMU in bind:latest", FAIL if required else WARN,
                     "base image missing", required=required)
    rc, out = _run(["docker", "run", "--rm", "--entrypoint", "/bin/bash", BIND_IMAGE, "-lc",
                    f"test -f '{QEMU_BIN}' && test -f '{FASTDYN_SO}'"], timeout=60)
    ok = rc == 0
    return Check("QEMU in bind:latest", PASS if ok else (FAIL if required else WARN),
                 "qemu-system-arm+libvirtual present" if ok
                 else "missing -> scripts/rebuild_bind_base.sh (needed for symbolic_regression)",
                 required=required)


def check_redis():
    if not _port_open(6379):
        return Check("redis :6379", FAIL, "not listening")
    if shutil.which("redis-cli"):
        rc, out = _run(["redis-cli", "-p", "6379", "ping"], timeout=10)
        if "PONG" not in out:
            return Check("redis :6379", FAIL, f"ping -> {out.strip()}")
    return Check("redis :6379", PASS, "PONG")


def check_ollama(tier):
    required = tier in ("full", "heavy")
    try:
        with urllib.request.urlopen(OLLAMA_URL, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        models = [m.get("name", "") for m in data.get("models", [])]
        ok = any(OLLAMA_MODEL in m for m in models)
        return Check("ollama + model", PASS if ok else (FAIL if required else WARN),
                     f"{OLLAMA_MODEL} present" if ok else f"model missing (have: {models})",
                     required=required)
    except Exception as e:
        return Check("ollama + model", FAIL if required else WARN,
                     f"unreachable ({e}); smoke tier does not need it", required=required)


def check_ports(attach):
    # For boot mode the orchestrator must bind :8000/:50051 (must be free).
    # For --attach an orchestrator is expected to already hold them.
    busy = [p for p in (REST_PORT, GRPC_PORT) if _port_open(p)]
    if attach:
        ok = len(busy) == 2
        return Check("orchestrator ports", PASS if ok else WARN,
                     f"in use: {busy} (attach expects a running orchestrator)", required=False)
    ok = not busy
    return Check("orchestrator ports free", PASS if ok else FAIL,
                 "8000/50051 free" if ok else f"in use: {busy} (stop the running orchestrator)")


def check_python_deps():
    missing = [m for m in ("fastapi", "redis", "grpc", "uvicorn", "requests", "pytest")
               if importlib.util.find_spec(m) is None]
    if not missing:
        return Check("python deps", PASS, f"{sys.executable}")
    fix = ("/home/akul/.rye/py/cpython@3.12.9/bin/python3 -m venv .venv && "
           "source .venv/bin/activate && pip install -e . pytest")
    return Check("python deps", FAIL, f"missing {missing} -> {fix}")


def check_test_binary():
    ok = os.path.exists(DEFAULT_BINARY)
    return Check("test binary", PASS if ok else WARN,
                 DEFAULT_BINARY if ok else f"not found: {DEFAULT_BINARY} (run scripts/fetch_test_binaries.sh)",
                 required=False)


def check_outdated_instance():
    # Warn if a container is still running on an outdated (no-QEMU) bind:latest.
    rc, out = _run(["docker", "ps", "-q", "--filter", f"ancestor={BIND_IMAGE}"], timeout=15)
    if rc == 0 and out.strip():
        rc2, _ = _run(["docker", "run", "--rm", "--entrypoint", "/bin/bash", BIND_IMAGE, "-lc",
                       f"test -f '{QEMU_BIN}'"], timeout=60)
        if rc2 != 0:
            return Check("no outdated instance", WARN,
                         "a container is running on a no-QEMU bind:latest -> rebuild_bind_base.sh kills it",
                         required=False)
    return Check("no outdated instance", PASS, "none", required=False)


def main():
    ap = argparse.ArgumentParser(description="xbin preflight checker")
    ap.add_argument("--tier", choices=["smoke", "full", "heavy"], default="smoke")
    ap.add_argument("--attach", action="store_true")
    args = ap.parse_args()

    checks = [
        check_docker(),
        check_bind_image(),
        check_qemu_in_base(args.tier),
        check_redis(),
        check_ollama(args.tier),
        check_ports(args.attach),
        check_python_deps(),
        check_test_binary(),
        check_outdated_instance(),
    ]

    print(f"\nxbin preflight  (tier={args.tier}{', attach' if args.attach else ''})")
    print("-" * 72)
    width = max(len(c.name) for c in checks)
    for c in checks:
        tag = {PASS: "PASS", FAIL: "FAIL", WARN: "WARN"}[c.result]
        print(f"  [{tag}] {c.name.ljust(width)}  {c.detail}")
    print("-" * 72)

    failed = [c for c in checks if c.result == FAIL and c.required]
    if failed:
        print(f"PREFLIGHT FAILED: {', '.join(c.name for c in failed)}\n")
        return 1
    warns = [c for c in checks if c.result == WARN]
    print("PREFLIGHT OK" + (f" ({len(warns)} warning(s))" if warns else "") + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
