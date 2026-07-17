"""pysindy (BIND binary->equation) xbin plugin -- automated recovery pipeline.

Drives pysyndy's end-to-end pipeline through its sanctioned two-verb API
(``submodules/pysyndy/xbin_api.py``, baked into ``pysindy:latest``):

  * ``is_candidate(func)``            -- single-basic-block FP-leaf functions.
  * ``recover_for_function(bin, addr)`` -- collect this function's I/O pairs by
    running the firmware under QEMU/FastDyn, then fit a closed-form equation.

So there is **no pre-supplied ``.iopairs.txt``** anymore: the worker discovers the
recoverable functions itself (in Binary Ninja's own address space, so the address
feeds straight into recovery -- no angr<->BN translation) and the API collects the
I/O dynamically. It competes on the ``equation_recovery`` blackboard with
``bind_se`` (angr symbolic execution) and ``symbolic_regression`` (PySR).

Requires a non-stripped Cortex-M firmware ELF with a ``main`` symbol and a vector
table -- xbin_api derives the bndb / VTOR / setup_end from it. On a stripped or
raw target (e.g. a bare ``.bin``) it logs and skips gracefully.
"""
import os
import sys

import xbin
from xbin.bind_helpers import CAT_EQUATION

# pysyndy tree baked into pysindy:latest by scripts/build_pysindy_base.sh; holds
# xbin_api.py at the root and the recovery core under binja_scripts/.
_PYSINDY_ROOT = os.environ.get("PYSINDY_ROOT", "/home/bind/pysyndy")


@xbin.plugin(
    name="pysindy",
    category="equation_recovery",
    display_name="Sparse Regression (pysindy)",
    description="Runs the firmware under QEMU/FastDyn to collect per-function I/O, then recovers a closed-form equation via SINDy-style sparse regression (pysyndy's automated pipeline).",
)
class PysindyPlugin:
    def on_new_binary(self, binary_path, requested_goals):
        if CAT_EQUATION not in (requested_goals or []):
            print(f"[pysindy] {CAT_EQUATION} not requested; skipping")
            return
        if not os.path.exists(binary_path):
            print(f"[pysindy] binary not found: {binary_path}; skipping")
            return

        # Deferred heavy imports: only importable inside pysindy:latest.
        if _PYSINDY_ROOT not in sys.path:
            sys.path.insert(0, _PYSINDY_ROOT)
        try:
            import binaryninja as bn
            import xbin_api
        except Exception as e:
            print(f"[pysindy] pipeline unavailable ({e!r}); skipping")
            return

        # Discover candidates (single-bb FP leaves) in Binary Ninja's own address
        # space -- the addresses recover_for_function expects.
        try:
            bv = bn.load(binary_path)
            bv.update_analysis_and_wait()
            cands = [f.start for f in bv.functions if xbin_api.is_candidate(f)]
            bv.file.close()
        except Exception as e:
            print(f"[pysindy] Binary Ninja discovery failed ({e!r}); skipping "
                  "(need a non-stripped Cortex-M firmware ELF)")
            return
        print(f"[pysindy] {len(cands)} candidate FP function(s): {[hex(a) for a in cands]}")

        posted = 0
        for addr in cands:
            try:
                res = xbin_api.recover_for_function(binary_path, addr)
            except Exception as e:
                print(f"[pysindy] recovery errored for {hex(addr)}: {e!r}")
                continue
            if not res or not res.get("equation") or str(res["equation"]).startswith("<fit-error"):
                print(f"[pysindy] no equation for {hex(addr)} (no usable I/O pairs)")
                continue
            eq = res["equation"]
            r2 = res.get("r2")
            verified = res.get("verified")
            confidence = (1.0 if verified
                          else (float(r2) if isinstance(r2, (int, float)) and 0.0 <= r2 <= 1.0
                                else 0.5))
            xbin.post_result(
                item_key=f"0x{addr:08x}",
                data={
                    "recovered_expression": eq,
                    "explanation": (f"pysindy recovered: {eq} "
                                    f"(R2={r2}, rmse={res.get('rmse')}, verified={verified})"),
                    "function": res.get("function"),
                    "function_start": res.get("function_start"),
                    "r2": r2,
                    "rmse": res.get("rmse"),
                    "median_rel_err": res.get("median_rel_err"),
                    "verified": verified,
                    "iopairs": res.get("iopairs"),
                    "match_source": "pysindy_sindy",
                },
                confidence=confidence,
                category=CAT_EQUATION,
            )
            posted += 1
            print(f"[pysindy] posted 0x{addr:08x}: {eq} (conf {round(confidence, 3)})")
        print(f"[pysindy] done; posted {posted}/{len(cands)} equations")


if __name__ == "__main__":
    xbin.start_worker()
