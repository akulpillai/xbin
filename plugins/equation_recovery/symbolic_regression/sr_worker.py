"""Symbolic Regression (PySR) xbin plugin.

Wraps Morpheus's symbolic_regression client. It keeps only the hardware-float
functions (ordered simplest-first), runs each through the full BIND-SR recovery
pipeline (QEMU/FastDyn I/O collection -> PySR formula -> local-LLM explanation),
and posts each recovered formula to the ``equation_recovery`` blackboard
(competing with bind_se).
"""

import os

import xbin
from xbin.bind_helpers import CAT_EQUATION, prepare_config, function_universe


def _first_line(text):
    if not text:
        return None
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:200]
    return None


@xbin.plugin(
    name="symbolic_regression",
    category="equation_recovery",
    display_name="Symbolic Regression (PySR)",
    description="Runs the firmware in QEMU to collect per-function I/O, then PySR recovers a closed-form formula and the local LLM explains it.",
)
class SymbolicRegressionPlugin:
    def on_new_binary(self, binary_path, requested_goals):
        if CAT_EQUATION not in (requested_goals or []):
            print(f"[symbolic_regression] {CAT_EQUATION} not requested; skipping")
            return

        from bind_jobs.clients.symbolic_regression_client import SymbolicRegressionClient
        from bind_jobs.arbiter_core import read_sr_analysis
        from bind_jobs.util import results_base_dir

        config, config_path = prepare_config(binary_path)
        client = SymbolicRegressionClient("http://unused", results_base_dir(config), config, config_path)
        client.setup()

        funcs = function_universe(config_path)
        ordered_fp, skipped = client._filter_and_order(funcs)
        print(f"[symbolic_regression] {len(ordered_fp)} float functions to recover ({len(skipped)} non-fp skipped)")

        posted = 0
        for func in ordered_fp:
            res = client.handle(func) or {}
            if res.get("status") != "success":
                continue
            out_dir = (res.get("payload") or {}).get("output_dir")
            analysis = read_sr_analysis(out_dir)
            xbin.post_result(
                item_key=func,
                data={
                    "recovered_expression": _first_line(analysis),
                    "explanation": analysis,
                    "output_dir": out_dir,
                    "match_source": "symbolic_regression",
                },
                confidence=0.9,
                category=CAT_EQUATION,
            )
            posted += 1
        print(f"[symbolic_regression] posted {posted} recovered formulas")


if __name__ == "__main__":
    xbin.start_worker()
