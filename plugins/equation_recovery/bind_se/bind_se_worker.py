"""BIND-SE (symbolic execution) xbin plugin.

Wraps Morpheus's bind_se racing client. Per function it symbolically executes to
recover an SMT2 signature, matches it against reference signatures, and -- when
unmatched -- asks the local LLM to recover a readable expression + explanation.

It answers two questions, so it posts to two blackboards:
  * ``equation_recovery``   -- the recovered expression / explanation (primary),
    competing with symbolic_regression.
  * ``signature_matching``  -- an identity, when SE matched a known reference
    signature (competes with fid / ghidriff).

Per-function guard: BindSeClient.handle() runs angr symbolic execution with no
time or memory bound, so a single pathological function can spin for tens of
minutes and balloon memory to tens of GB (stalling the whole run / risking OOM).
We run each function in a forked child with a wall-clock timeout and an
address-space cap; a runaway is killed and skipped, and its memory is reclaimed
when the child exits. Tunables (env):
  BIND_SE_FUNC_TIMEOUT  per-function wall-clock seconds (default 90)
  BIND_SE_FUNC_MEM_GB   per-function RLIMIT_AS cap in GB, 0 disables (default 24)
"""

import multiprocessing as _mp
import os
import queue as _queue

import xbin
from xbin.bind_helpers import CAT_EQUATION, CAT_SIGNATURE, prepare_config, function_universe

_FUNC_TIMEOUT = int(os.environ.get("BIND_SE_FUNC_TIMEOUT", "90"))
_FUNC_MEM_GB = float(os.environ.get("BIND_SE_FUNC_MEM_GB", "24"))


def _se_child(client, func, q):
    """Run one function's symbolic execution; return its result via the queue.

    Runs in a forked child (inherits the parent's loaded CFG/refs copy-on-write),
    so an address-space cap and a hard kill bound this one function only.
    """
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
    display_name="BIND-SE (symbolic execution)",
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

        print(f"[bind_se] loading references + target CFG for {os.path.basename(binary_path)} ...")
        client.setup()

        ctx = _mp.get_context("fork")
        funcs = function_universe(config_path)
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
