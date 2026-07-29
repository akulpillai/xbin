"""Binary Ninja hardware-VFP float detection (fp_classification producer).

Posts one hypothesis per function that contains a hardware VFP instruction,
labelled ``arithmetic`` (computes a float) or ``movement`` (only moves
float-shaped bits). Measured F1 1.000 against "contains VFP arithmetic" when
restricted to arithmetic mnemonics; see docs/fp_detector_eval.md.

This is the detection that used to live inside symbolic_regression as a private
filter step, where nothing could see or contest it.
"""

import os

import xbin
from xbin.bind_helpers import CAT_FP, prepare_config, function_universe
from xbin.fp_common import (
    KIND_ARITHMETIC,
    KIND_CONFIDENCE,
    KIND_MOVEMENT,
    classify_mnemonics,
    hypothesis,
)

_BACKEND = "binja_fp"


@xbin.plugin(
    name="binja_fp",
    category="fp_classification",
    display_name="Float Detection (Binary Ninja)",
    description="Flags functions containing hardware VFP instructions, separating those that compute a float from those that only move float-shaped bits.",
)
class BinjaFpPlugin:
    def on_new_binary(self, binary_path, requested_goals):
        if CAT_FP not in (requested_goals or []):
            print(f"[{_BACKEND}] {CAT_FP} not requested; skipping")
            return

        from bind_jobs.util import load_address, norm_addr

        config, config_path = prepare_config(binary_path)
        funcs = function_universe(config_path)
        if not funcs:
            print(f"[{_BACKEND}] empty function universe; nothing to classify")
            return

        target = config.get("bndb_path") if os.path.exists(
            config.get("bndb_path") or "") else config["firmware_bin_path"]
        base = load_address(config)

        import sys
        sys.path.insert(0, os.path.join(
            os.environ.get("MORPHEUS_ROOT", "/home/bind/Morpheus"), "binja_scripts"))
        from fp_function_filter_order import _load_bv, _func_size

        wanted = {int(f, 16) & ~1 for f in funcs}
        bv = _load_bv(target, base)
        posted = counts = 0
        tally = {}
        try:
            for f in bv.functions:
                addr = f.start & ~1
                if addr not in wanted:
                    continue
                counts += 1
                kind = classify_mnemonics(
                    (item[0][0].text if item[0] else "") for item in f.instructions)
                if kind is None:
                    continue  # no hardware VFP -- may still be soft-float
                n_instrs, n_bbs = _func_size(f)
                xbin.post_result(
                    item_key=norm_addr(addr),
                    data=hypothesis(kind, "binja_mnemonics", _BACKEND,
                                    instructions=n_instrs, basic_blocks=n_bbs),
                    confidence=KIND_CONFIDENCE[kind],
                    category=CAT_FP,
                )
                tally[kind] = tally.get(kind, 0) + 1
                posted += 1
        finally:
            try:
                bv.file.close()
            except Exception:
                pass

        print(f"[{_BACKEND}] examined {counts} functions; posted {posted} "
              f"({tally.get(KIND_ARITHMETIC, 0)} arithmetic, "
              f"{tally.get(KIND_MOVEMENT, 0)} movement)")


if __name__ == "__main__":
    xbin.start_worker()
