#!/usr/bin/env python3
"""Full-stack end-to-end driver for xbin (BINDonly).

Boots (or attaches to) the orchestrator, starts the plugin containers via the
REST API, waits for them to become RUNNING+HEALTHY, uploads a firmware binary,
polls the blackboard until the expected categories populate, then prints a rich
per-function summary. Exits nonzero on any failure (plugin crash, empty result
category, timeout).

Tiers map onto the cost tiers documented in CLAUDE.md:
  smoke  fid + ghidriff                          (signature_matching; no ollama/QEMU)
  full   + bind_se + bind_arbiter                (+ equation_recovery; +angr +ollama)
  heavy  + symbolic_regression                   (+ QEMU/FastDyn dynamic run + PySR)

Usage:
  python scripts/e2e_driver.py --smoke              # boot orchestrator, run, tear down
  python scripts/e2e_driver.py --full --attach      # use an already-running orchestrator
  python scripts/e2e_driver.py --heavy --teardown   # also stop plugin containers at the end

This module is also imported by tests/conftest.py (for wait_for_ready) and
tests/test_e2e_pipeline.py (run_tier), so keep the importable API stable.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

GRPC_PORT = 50051
REST_PORT = 8000
REST_BASE = f"http://localhost:{REST_PORT}"

# Category constants (mirror src/xbin/bind_helpers.py).
CAT_SIGNATURE = "signature_matching"
CAT_EQUATION = "equation_recovery"

# name -> category for every plugin the orchestrator can start.
ALL_PLUGINS = {
    "fid": CAT_SIGNATURE,
    "ghidriff": CAT_SIGNATURE,
    "bind_arbiter": CAT_SIGNATURE,
    "bind_se": CAT_EQUATION,
    "symbolic_regression": CAT_EQUATION,
}

# Per-tier plugin fleet (ordered), requested analyses, and the categories that
# MUST be non-empty for the run to count as a success.
TIERS = {
    "smoke": {
        "plugins": [("fid", CAT_SIGNATURE), ("ghidriff", CAT_SIGNATURE)],
        "requested": CAT_SIGNATURE,
        "require": [CAT_SIGNATURE],
        "result_timeout": 1800,     # ~30 min: Ghidra import + FID/BSim on a 2MB image
    },
    "full": {
        "plugins": [
            ("fid", CAT_SIGNATURE), ("ghidriff", CAT_SIGNATURE),
            ("bind_arbiter", CAT_SIGNATURE), ("bind_se", CAT_EQUATION),
        ],
        "requested": f"{CAT_SIGNATURE},{CAT_EQUATION}",
        "require": [CAT_SIGNATURE, CAT_EQUATION],
        "result_timeout": 9000,     # ~2.5h: bind_se symbolic execution (7200s cap)
    },
    "heavy": {
        "plugins": [
            ("fid", CAT_SIGNATURE), ("ghidriff", CAT_SIGNATURE),
            ("bind_arbiter", CAT_SIGNATURE), ("bind_se", CAT_EQUATION),
            ("symbolic_regression", CAT_EQUATION),
        ],
        "requested": f"{CAT_SIGNATURE},{CAT_EQUATION}",
        "require": [CAT_SIGNATURE, CAT_EQUATION],
        "result_timeout": 21600,    # ~6h: + QEMU/FastDyn dynamic run per float fn + PySR
    },
}

DEFAULT_BINARY = os.environ.get(
    "XBIN_TEST_BINARY",
    os.path.join(REPO_ROOT, "submodules", "Morpheus", "example_config", "gs3.bin"),
)


# --------------------------------------------------------------------------- #
# Small logging helpers
# --------------------------------------------------------------------------- #
def _ts() -> str:
    return time.strftime("%H:%M:%S")


def log(msg: str) -> None:
    print(f"[{_ts()}] {msg}", flush=True)


# --------------------------------------------------------------------------- #
# Readiness (shared with tests/conftest.py)
# --------------------------------------------------------------------------- #
def _port_open(port: int, host: str = "localhost") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def _http_ok(url: str, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def wait_for_ready(timeout: float = 30.0, rest_base: str = REST_BASE) -> bool:
    """Block until the orchestrator's gRPC port is open AND REST /health is 200.

    Returns True on success, False on timeout. This is the single readiness gate
    used by both the driver and the pytest conftest (replacing the old sleep(2)).
    """
    deadline = time.time() + timeout
    health = f"{rest_base}/api/v1/health"
    while time.time() < deadline:
        if _port_open(GRPC_PORT) and _http_ok(health):
            return True
        time.sleep(0.25)
    return False


# --------------------------------------------------------------------------- #
# REST client (uses requests when available, falls back to urllib)
# --------------------------------------------------------------------------- #
class XbinClient:
    def __init__(self, base: str = REST_BASE):
        self.base = base.rstrip("/")
        try:
            import requests  # noqa: F401
            self._requests = __import__("requests")
        except Exception:
            self._requests = None

    def _get(self, path: str, timeout: float = 10.0):
        url = f"{self.base}{path}"
        if self._requests:
            return self._requests.get(url, timeout=timeout).json()
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    def _post(self, path: str, timeout: float = 30.0):
        url = f"{self.base}{path}"
        if self._requests:
            return self._requests.post(url, timeout=timeout).json()
        req = urllib.request.Request(url, data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    # --- endpoints ---
    def available(self):
        return self._get("/api/v1/plugins/available")

    def start_plugin(self, name: str, category: str):
        return self._post(f"/api/v1/plugins/{name}/start?category={category}")

    def stop_plugin(self, name: str, category: str):
        return self._post(f"/api/v1/plugins/{name}/stop?category={category}")

    def plugin_logs(self, name: str, category: str):
        return self._get(f"/api/v1/plugins/{name}/logs?category={category}").get("logs", "")

    def system_logs(self):
        return self._get("/api/v1/system/logs").get("logs", "")

    def results(self, category: str):
        return self._get(f"/api/v1/blackboard/{category}/results").get("results", {})

    def audit(self, category: str):
        return self._get(f"/api/v1/blackboard/{category}/audit").get("logs", "")

    def upload(self, binary_path: str, requested: str, reference: str | None = None):
        """POST /api/v1/upload (multipart). Requires `requests`."""
        if not self._requests:
            raise RuntimeError("uploading requires the `requests` package (pip install -e .)")
        files = {"file": (os.path.basename(binary_path), open(binary_path, "rb"))}
        if reference:
            files["reference"] = (os.path.basename(reference), open(reference, "rb"))
        data = {"requested_analyses": requested}
        try:
            resp = self._requests.post(f"{self.base}/api/v1/upload", files=files, data=data, timeout=120)
            return resp.json()
        finally:
            for f in files.values():
                try:
                    f[1].close()
                except Exception:
                    pass


# --------------------------------------------------------------------------- #
# Orchestrator lifecycle
# --------------------------------------------------------------------------- #
def boot_orchestrator(log_path: str | None = None):
    """Start `python -m xbin_orchestrator.main --no-browser` from the repo root.

    Returns the Popen. Caller is responsible for terminate() unless attaching.
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [os.path.join(REPO_ROOT, "src"), os.path.join(REPO_ROOT, "src", "xbin_orchestrator")]
        + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )
    out = open(log_path, "w") if log_path else subprocess.DEVNULL
    log(f"booting orchestrator (log: {log_path or 'DEVNULL'}) ...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "xbin_orchestrator.main", "--no-browser"],
        cwd=REPO_ROOT, env=env, stdout=out, stderr=subprocess.STDOUT,
    )
    return proc


# --------------------------------------------------------------------------- #
# Plugin fleet management
# --------------------------------------------------------------------------- #
def _plugin_state(client: XbinClient, name: str, category: str):
    for p in client.available().get("plugins", []):
        if p.get("name") == name and p.get("category") == category:
            return p
    return None


def dump_logs(client: XbinClient, name: str, category: str):
    log(f"---- container logs: {name}/{category} ----")
    try:
        print(client.plugin_logs(name, category)[-4000:], flush=True)
    except Exception as e:
        log(f"(could not fetch logs: {e})")
    log("---- system logs (tail) ----")
    try:
        print("\n".join(client.system_logs().splitlines()[:30]), flush=True)
    except Exception:
        pass


def start_plugins(client: XbinClient, plugins):
    for name, cat in plugins:
        log(f"starting plugin {name} ({cat}) ...")
        client.start_plugin(name, cat)


def wait_plugins_ready(client: XbinClient, plugins, build_timeout: float = 900, poll: float = 3):
    """Wait until every target plugin is RUNNING+HEALTHY. Fail fast on ERROR/CRASHED."""
    deadline = time.time() + build_timeout
    last = {}
    while time.time() < deadline:
        ok = True
        for name, cat in plugins:
            st = _plugin_state(client, name, cat) or {}
            status, health = st.get("status", "?"), st.get("health", "?")
            key = f"{name}/{cat}"
            if last.get(key) != (status, health):
                log(f"  {key}: status={status} health={health}"
                    + (f" error={st.get('error')}" if st.get("error") else ""))
                last[key] = (status, health)
            if status in ("ERROR", "CRASHED"):
                log(f"[x] {key} entered {status}")
                dump_logs(client, name, cat)
                raise RuntimeError(f"plugin {key} failed to start ({status})")
            if not (status == "RUNNING" and health == "HEALTHY"):
                ok = False
        if ok:
            log("all plugins RUNNING + HEALTHY")
            return True
        time.sleep(poll)
    raise TimeoutError(f"plugins not ready within {build_timeout}s")


# --------------------------------------------------------------------------- #
# Results polling + summary
# --------------------------------------------------------------------------- #
def poll_results(client: XbinClient, require_categories, plugins, timeout: float, poll: float = 5):
    """Wait until each required category has >=1 hypothesis. Bail if a plugin crashes."""
    deadline = time.time() + timeout
    seen_counts = {}
    while time.time() < deadline:
        # Bail early if a required plugin crashed mid-analysis.
        for name, cat in plugins:
            st = _plugin_state(client, name, cat) or {}
            if st.get("status") in ("ERROR", "CRASHED"):
                log(f"[x] {name}/{cat} crashed during analysis")
                dump_logs(client, name, cat)
                raise RuntimeError(f"plugin {name}/{cat} crashed during analysis")
        counts = {cat: len(client.results(cat)) for cat in require_categories}
        if counts != seen_counts:
            log("results so far: " + ", ".join(f"{c}={n}" for c, n in counts.items()))
            seen_counts = counts
        if all(n >= 1 for n in counts.values()):
            log("all required categories populated")
            return True
        time.sleep(poll)
    raise TimeoutError(
        f"results not populated within {timeout}s (last counts: {seen_counts})")


def _resolved_text(data):
    if isinstance(data, str):
        return data
    if data.get("known_function"):
        return f"Identity: {data['known_function']}"
    if data.get("recovered_expression"):
        return f"Expr: {data['recovered_expression']}"
    if data.get("explanation"):
        first = next((l.strip() for l in str(data["explanation"]).splitlines() if l.strip()), "")
        return first[:80]
    return json.dumps(data)[:60]


def summarize(client: XbinClient, categories):
    print("\n" + "=" * 72, flush=True)
    print("E2E RESULT SUMMARY", flush=True)
    print("=" * 72, flush=True)
    grand_backends = {}
    for cat in categories:
        results = client.results(cat)
        print(f"\n### {cat}: {len(results)} function(s)", flush=True)
        conflicts = 0
        backends = {}
        for item_key in sorted(results.keys()):
            state = results[item_key]
            hyps = state.get("hypotheses", [])
            if not hyps:
                continue
            top = hyps[0]
            status = state.get("status")
            if status == "CONFLICTED":
                conflicts += 1
            for h in hyps:
                b = h.get("backend", "?")
                backends[b] = backends.get(b, 0) + 1
                grand_backends[b] = grand_backends.get(b, 0) + 1
            vc = len(top.get("validators", []))
            boosted = float(top.get("score", 0)) >= 1.5  # arbiter _SCORE_SINGLE/_CONSENSUS
            flags = []
            if status == "CONFLICTED":
                flags.append("CONFLICTED")
            if vc:
                flags.append(f"+{vc} vouch")
            if boosted:
                flags.append("arbiter")
            flag_s = f"  [{', '.join(flags)}]" if flags else ""
            print(f"  {item_key}  via {top.get('backend'):<20} "
                  f"score={top.get('score')}  {_resolved_text(top.get('data') or {})}{flag_s}",
                  flush=True)
        print(f"  -- {conflicts} conflicted; hypotheses by backend: "
              + ", ".join(f"{b}:{n}" for b, n in sorted(backends.items())), flush=True)
        audit = client.audit(cat)
        n_audit = len([l for l in audit.splitlines() if l.strip()]) if audit else 0
        print(f"  -- audit trail: {n_audit} entries", flush=True)
    print("\nHypotheses by backend (all categories): "
          + (", ".join(f"{b}:{n}" for b, n in sorted(grand_backends.items())) or "none"), flush=True)
    # Explicitly call out symbolic_regression coverage (the QEMU-dependent tool).
    sr = grand_backends.get("symbolic_regression", 0)
    print(f"symbolic_regression hypotheses: {sr}"
          + (" (0 -- check SR container logs / float-function filter)" if sr == 0 else ""),
          flush=True)
    print("=" * 72 + "\n", flush=True)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def run_tier(tier: str, attach: bool = False, binary: str | None = None,
             reference: str | None = None, teardown: bool = False,
             build_timeout: float = 900, result_timeout: float | None = None,
             orch_log: str | None = None) -> int:
    cfg = TIERS[tier]
    binary = binary or DEFAULT_BINARY
    result_timeout = result_timeout if result_timeout is not None else cfg["result_timeout"]
    client = XbinClient()
    proc = None
    try:
        if attach:
            log("attaching to a running orchestrator ...")
            if not wait_for_ready(timeout=15):
                log("[x] no orchestrator reachable on :8000/:50051 (start one, or drop --attach)")
                return 2
        else:
            proc = boot_orchestrator(orch_log)
            if not wait_for_ready(timeout=45):
                log("[x] orchestrator did not become ready within 45s")
                return 2
        log(f"orchestrator ready; tier={tier}, binary={binary}")

        if not os.path.exists(binary):
            log(f"[x] test binary not found: {binary}")
            return 2

        start_plugins(client, cfg["plugins"])
        wait_plugins_ready(client, cfg["plugins"], build_timeout=build_timeout)

        log(f"uploading {os.path.basename(binary)} (requested={cfg['requested']}) ...")
        resp = client.upload(binary, cfg["requested"], reference=reference)
        log(f"upload response: {resp}")

        poll_results(client, cfg["require"], cfg["plugins"], timeout=result_timeout)
        summarize(client, cfg["require"])
        log("E2E PASSED")
        return 0
    except Exception as e:
        log(f"[x] E2E FAILED: {e}")
        return 1
    finally:
        if teardown:
            for name, cat in cfg["plugins"]:
                try:
                    client.stop_plugin(name, cat)
                except Exception:
                    pass
        if proc is not None:
            log("terminating orchestrator ...")
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()


def main() -> int:
    ap = argparse.ArgumentParser(description="xbin full-stack E2E driver")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--smoke", action="store_const", dest="tier", const="smoke")
    g.add_argument("--full", action="store_const", dest="tier", const="full")
    g.add_argument("--heavy", action="store_const", dest="tier", const="heavy")
    ap.add_argument("--attach", action="store_true", help="use an already-running orchestrator")
    ap.add_argument("--binary", default=None, help=f"firmware to analyze (default: {DEFAULT_BINARY})")
    ap.add_argument("--reference", default=None, help="optional symbolized reference binary")
    ap.add_argument("--teardown", action="store_true", help="stop plugin containers at the end")
    ap.add_argument("--build-timeout", type=float, default=900)
    ap.add_argument("--result-timeout", type=float, default=None)
    ap.add_argument("--orch-log", default=None, help="write orchestrator output to this file")
    args = ap.parse_args()
    tier = args.tier or "smoke"
    return run_tier(tier, attach=args.attach, binary=args.binary, reference=args.reference,
                    teardown=args.teardown, build_timeout=args.build_timeout,
                    result_timeout=args.result_timeout, orch_log=args.orch_log)


if __name__ == "__main__":
    sys.exit(main())
