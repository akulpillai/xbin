"""pysindy (BIND binary->equation) xbin plugin.

Wraps pysyndy's ``recover_equation`` (baked at ``$PYSINDY_ROOT/binja_scripts`` in
the ``pysindy:latest`` base). It competes on the ``equation_recovery`` blackboard
with ``bind_se`` (angr symbolic execution) and ``symbolic_regression`` (PySR):
pysindy lifts each function with Binary Ninja to recover the equation *structure*,
then fits a closed-form equation via SINDy-style sparse regression (STLSQ).

v1 iopairs policy (sibling only): the fit needs numeric I/O pairs (X, y). We read
them from a sibling ``<stem>.iopairs.txt`` (``load_iopairs``). If none is present
(``recover_equation`` would return ``equation=None`` -- structure only), we log
and skip *without* loading every function through Binary Ninja. Best-effort
dynamic (QEMU/FastDyn) iopair collection is a documented follow-up.
"""
import os
import sys

import xbin
from xbin.bind_helpers import CAT_EQUATION, prepare_config, function_universe, sibling

# pysyndy's recovery core, baked into pysindy:latest by scripts/build_pysindy_base.sh.
_PYSINDY_CORE = os.path.join(
    os.environ.get("PYSINDY_ROOT", "/home/bind/pysyndy"), "binja_scripts")


@xbin.plugin(
    name="pysindy",
    category="equation_recovery",
    display_name="Sparse Regression (pysindy)",
    description="Lifts each function with Binary Ninja and recovers a closed-form equation via SINDy-style sparse regression; fits/verifies against sibling I/O pairs when provided.",
)
class PysindyPlugin:
    def on_new_binary(self, binary_path, requested_goals):
        if CAT_EQUATION not in (requested_goals or []):
            print(f"[pysindy] {CAT_EQUATION} not requested; skipping")
            return

        # Fit needs numeric I/O pairs; without a sibling file the recovery is
        # structure-only (equation=None), so skip fast rather than lifting every
        # function through Binary Ninja for nothing.
        io_path = sibling(binary_path, ".iopairs.txt")
        if not io_path:
            print("[pysindy] no <stem>.iopairs.txt sibling; skipping recovery "
                  "(dynamic I/O-pair collection is a follow-up)")
            return

        # Heavy imports deferred: only importable inside pysindy:latest.
        if _PYSINDY_CORE not in sys.path:
            sys.path.insert(0, _PYSINDY_CORE)
        import equation_recovery as PIPE   # recover_equation + load_iopairs

        try:
            _names, X, y = PIPE.load_iopairs(io_path)
        except Exception as e:
            print(f"[pysindy] iopairs load failed ({io_path}): {e!r}; skipping")
            return
        print(f"[pysindy] loaded I/O pairs from {os.path.basename(io_path)}")

        config, config_path = prepare_config(binary_path)
        funcs = function_universe(config_path)   # BN∩Ghidra addrs (normalized hex)
        print(f"[pysindy] {len(funcs)} functions in the BN∩Ghidra universe")

        posted = 0
        for func in funcs:
            try:
                res = PIPE.recover_equation(binary_path, func=int(func, 16), X=X, y=y)
            except Exception as e:
                print(f"[pysindy] recovery failed for {func}: {e!r}")
                continue
            eq = res.get("equation")
            if not eq or str(eq).startswith("<fit-error"):
                continue
            r2 = res.get("r2")
            confidence = (1.0 if res.get("verified")
                          else (float(r2) if isinstance(r2, (int, float)) and 0.0 <= r2 <= 1.0
                                else 0.5))
            xbin.post_result(
                item_key=func,
                data={
                    "recovered_expression": eq,
                    "explanation": (f"pysindy recovered: {eq} "
                                    f"(R2={r2}, rmse={res.get('rmse')}, verified={res.get('verified')})"),
                    "function": res.get("function"),
                    "function_start": res.get("function_start"),
                    "r2": r2,
                    "rmse": res.get("rmse"),
                    "median_rel_err": res.get("median_rel_err"),
                    "verified": res.get("verified"),
                    "match_source": "pysindy_sindy",
                },
                confidence=confidence,
                category=CAT_EQUATION,
            )
            posted += 1
        print(f"[pysindy] posted {posted} recovered equations")


if __name__ == "__main__":
    xbin.start_worker()
