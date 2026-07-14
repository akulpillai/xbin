"""BIND-SE (symbolic execution) xbin plugin.

Wraps Morpheus's bind_se racing client. Per function it symbolically executes to
recover an SMT2 signature, matches it against reference signatures, and -- when
unmatched -- asks the local LLM to recover a readable expression + explanation.

It answers two questions, so it posts to two blackboards:
  * ``equation_recovery``   -- the recovered expression / explanation (primary),
    competing with symbolic_regression.
  * ``signature_matching``  -- an identity, when SE matched a known reference
    signature (competes with fid / ghidriff).

Setup guard: BindSeClient.setup() builds the target angr CFG. We compute the
BN/Ghidra function universe up front and pass it as ``function_starts`` so the
CFG covers every job address without ``force_complete_scan``'s exhaustive linear
sweep (which explodes to tens of GB on multi-MB firmware). The exhaustive scan
can be re-enabled via the ``se_target_force_complete_scan`` config key. The
universe is computed in a subprocess (``_function_universe_isolated``) because it
loads the Ghidra JVM + Binary Ninja; keeping their threads out of this process is
what lets the reference-sig-gen fork and the per-function fork guard run without
a fork-after-threads deadlock.

Per-function guard: BindSeClient.handle() runs angr symbolic execution with no
time or memory bound, so a single pathological function can spin for tens of
minutes and balloon memory to tens of GB (stalling the whole run / risking OOM).
We run each function in a forked child with a wall-clock timeout and an
address-space cap; a runaway is killed and skipped, and its memory is reclaimed
when the child exits. Tunables (env):
  BIND_SE_FUNC_TIMEOUT  per-function wall-clock seconds (default 90)
  BIND_SE_FUNC_MEM_GB   per-function RLIMIT_AS cap in GB, 0 disables (default 24)
"""

import json as _json
import multiprocessing as _mp
import os
import queue as _queue
import subprocess as _subprocess
import sys as _sys
import tempfile as _tempfile

import xbin
from xbin.bind_helpers import CAT_EQUATION, CAT_SIGNATURE, prepare_config

_FUNC_TIMEOUT = int(os.environ.get("BIND_SE_FUNC_TIMEOUT", "90"))
_FUNC_MEM_GB = float(os.environ.get("BIND_SE_FUNC_MEM_GB", "24"))


def _function_universe_isolated(config_path):
    """Compute the BN∩Ghidra function universe in a throwaway subprocess.

    ``function_universe()`` loads Binary Ninja and an in-process Ghidra JVM, each
    of which spawns dozens of long-lived threads. If those threads live in *this*
    (the worker) process, the fork-based reference signature generation inside
    ``BindSeClient.setup()`` and the per-function fork guard below would fork a
    heavily multithreaded process and deadlock -- a classic fork-after-threads
    hang: the child inherits mutexes locked by threads that do not exist in it,
    so the first allocation/lock in the child blocks forever (observed as an
    idle-CPU stall). Running the universe computation in its own short-lived
    process keeps this process free of the JVM/BN threads, so every subsequent
    fork() is clean. The child's stdout/stderr flow through so the
    ``[binja]``/``[ghidra]`` progress stays visible; the result comes back via a
    temp file.
    """
    fd, out_path = _tempfile.mkstemp(suffix=".json", prefix="xbin_universe_")
    os.close(fd)
    code = (
        "import json, sys; from xbin.bind_helpers import function_universe; "
        "open(sys.argv[2], 'w').write(json.dumps(function_universe(sys.argv[1])))"
    )
    try:
        proc = _subprocess.run([_sys.executable, "-c", code, config_path, out_path])
        if proc.returncode != 0:
            raise RuntimeError(
                f"function_universe subprocess exited {proc.returncode}")
        with open(out_path) as f:
            return _json.load(f)
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass


def _se_child(client, func, q):
    """Run one function's symbolic execution; return its result via the queue.

    Runs in a forked child (inherits the parent's loaded CFG/refs copy-on-write),
    so an address-space cap and a hard kill bound this one function only.
    """
    # Reset the SIGTERM/SIGINT handlers inherited from the worker parent. The SDK
    # installs a graceful-shutdown handler (sdk._handle_exit) that this forked
    # child would otherwise run when the guard's p.terminate() kills it on
    # timeout -- emitting a misleading "Shutdown signal 15 received" line plus a
    # weakref-cleanup traceback, and even swallowing the SIGTERM (forcing the
    # SIGKILL escalation). Default handling makes the timeout kill clean.
    import signal as _signal
    for _s in (_signal.SIGTERM, _signal.SIGINT):
        try:
            _signal.signal(_s, _signal.SIG_DFL)
        except (ValueError, OSError):
            pass
    try:
        if _FUNC_MEM_GB > 0:
            import resource
            cap = int(_FUNC_MEM_GB * (1024 ** 3))
            try:
                resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
            except (ValueError, OSError):
                pass
        q.put(client.handle(func) or {})
    except MemoryError:
        q.put({"status": "oom", "payload": None})
    except BaseException as e:  # never let a child crash take down the worker
        q.put({"status": "crash", "payload": {"error": str(e)}})


def _handle_guarded(ctx, client, func):
    """client.handle(func) with a per-function timeout + memory cap.

    Returns handle()'s result dict, or a sentinel {status: timeout|oom|crash}.
    """
    q = ctx.Queue()
    p = ctx.Process(target=_se_child, args=(client, func, q))
    p.start()
    p.join(_FUNC_TIMEOUT)
    if p.is_alive():
        p.terminate(); p.join(5)
        if p.is_alive():
            p.kill(); p.join()
        return {"status": "timeout", "payload": None}
    try:
        return q.get(timeout=10)
    except _queue.Empty:
        # Child exited without a result (e.g. RLIMIT_AS / OOM-killer).
        return {"status": "crash", "payload": None}


@xbin.plugin(
    name="bind_se",
    category="equation_recovery",
    display_name="Symbolic Execution (bind-se)",
    description="angr symbolic execution recovers each function's SMT2 signature; matches known signatures, else the local LLM explains the recovered expression.",
)
class BindSePlugin:
    def on_new_binary(self, binary_path, requested_goals):
        goals = requested_goals or []
        if CAT_EQUATION not in goals and CAT_SIGNATURE not in goals:
            print(f"[bind_se] neither {CAT_EQUATION} nor {CAT_SIGNATURE} requested; skipping")
            return

        from bind_jobs.clients.bind_se_client import BindSeClient
        from bind_jobs.util import client_output_dir

        config, config_path = prepare_config(binary_path)
        out = client_output_dir(config, "bind_se")
        timeout = int(config.get("sigmatch_timeout", 7200))
        client = BindSeClient("http://unused", out, config, os.path.join(out, "cache"), timeout=timeout)

        # Compute the BN/Ghidra function universe *before* setup() so we can seed
        # the target CFG with these starts. This lets setup() drop the exhaustive
        # force_complete_scan linear sweep (the ~47 GiB runaway on large firmware)
        # while still guaranteeing every job address is a CFG node. Thumb bit set
        # (`| 1`) to match handle()'s get_by_addr(addr | 1) lookup on Cortex-M.
        # Run it in an isolated subprocess (see _function_universe_isolated): it
        # loads the Ghidra JVM + Binary Ninja, whose threads would otherwise make
        # every later fork() in this process deadlock.
        funcs = _function_universe_isolated(config_path)
        starts = [int(f, 16) | 1 for f in funcs]

        print(f"[bind_se] loading references + target CFG for {os.path.basename(binary_path)} ...")
        client.setup(function_starts=starts)

        ctx = _mp.get_context("fork")
        print(f"[bind_se] analyzing {len(funcs)} functions with symbolic execution "
              f"(per-func cap: {_FUNC_TIMEOUT}s / {_FUNC_MEM_GB}GB) ...")
        eq_posted = id_posted = 0
        skipped = {"timeout": 0, "oom": 0, "crash": 0}
        for func in funcs:
            res = _handle_guarded(ctx, client, func) or {}
            status = res.get("status")
            if status in skipped:
                skipped[status] += 1
                print(f"[bind_se] {func}: {status} (skipped)")
                continue
            payload = res.get("payload") or {}

            # Semantic hypothesis: whenever SE recovered an expression/explanation.
            if payload.get("recovered_expression") or payload.get("explanation"):
                conf = payload.get("confidence")
                conf = float(conf) if conf is not None else (1.0 if status == "success" else 0.5)
                xbin.post_result(item_key=func, data=payload, confidence=conf, category=CAT_EQUATION)
                eq_posted += 1

            # Identity hypothesis: SE matched a known reference signature.
            if payload.get("known_function"):
                xbin.post_result(
                    item_key=func,
                    data={
                        "known_function": payload["known_function"],
                        "known_address": payload.get("known_address"),
                        "confidence": payload.get("confidence", 1.0),
                        "match_source": payload.get("match_source", "bind_se"),
                        "explanation": payload.get("explanation"),
                    },
                    confidence=float(payload.get("confidence") or 1.0),
                    category=CAT_SIGNATURE,
                )
                id_posted += 1
        print(f"[bind_se] posted {eq_posted} semantic + {id_posted} identity hypotheses; "
              f"skipped {skipped['timeout']} timeout / {skipped['oom']} oom / {skipped['crash']} crash")


if __name__ == "__main__":
    xbin.start_worker()
