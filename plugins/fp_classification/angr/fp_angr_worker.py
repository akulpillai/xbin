"""angr/capstone hardware-VFP float detection (fp_classification producer).

The independent second opinion on hardware VFP. Uses angr's CFG plus capstone
disassembly and applies the *same* arithmetic/movement split as the Binary Ninja
producer (via xbin.fp_common), so "the two backends agree" is a meaningful claim
rather than a comparison of differently-defined labels.

Note this replaces what were two byte-identical copies of the same capstone
VFP-group logic in Morpheus (``angr_scripts/fp_func_filter.py`` and
``bind_se/iret/fp_filter.py`` -- measured Jaccard 1.000, Cohen kappa 1.000).
Shipping both as separate producers would have manufactured false consensus:
three near-identical votes outweighing the one genuinely independent signal.

This producer depends only on angr + capstone (both pip-installable), so unlike
the Binary Ninja producer it can live in the public repository.
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

_BACKEND = "angr_fp"


@xbin.plugin(
    name="angr_fp",
    category="fp_classification",
    display_name="Float Detection (angr)",
    description="Independent hardware-VFP detection over angr's CFG using capstone disassembly, split into float arithmetic vs float data movement.",
)
class AngrFpPlugin:
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

        import struct
        import sys

        target = config["firmware_bin_path"]
        base = load_address(config)
        wanted = {int(f, 16) & ~1 for f in funcs}

        # Reuse Morpheus's loader rather than hand-rolling main_opts: Cortex-M
        # needs arch="ARMCortexM", and loading a Thumb-only image as "ARMEL"
        # recovers almost nothing (measured: 6 functions where BN found 28).
        sys.path.insert(0, os.path.join(
            os.environ.get("MORPHEUS_ROOT", "/home/bind/Morpheus"), "angr_scripts"))
        from list_functions import _make_project

        # Force the blob backend AND the base address explicitly. _make_project
        # only applies base_addr in its CLECompatibilityError fallback, but angr
        # happily auto-detects a raw .bin as a blob at base 0 -- so the fallback
        # never fires and every address comes out 0x08000000 too low, matching
        # nothing in the function universe (measured: 0 functions examined).
        blob = {"backend": "blob", "base_addr": base}
        proj0 = _make_project(target, base, main_opts=blob)
        # The reset handler is the real entry point; seeding it lets CFGFast
        # follow the firmware's own call graph instead of guessing.
        _sp, reset = struct.unpack("<II", proj0.loader.memory.load(base, 8))
        # Keep the Thumb bit SET. angr keys Cortex-M functions at entry|1, and
        # seeding an even address makes it decode Thumb code in ARM mode: the
        # recovered function starts came out ~3 bytes past the real ones, so the
        # intersection with the function universe was empty (0 of 30). With the
        # Thumb bit set it is 29 of 30.
        entry = reset | 1
        proj = _make_project(target, base, main_opts=dict(blob, entry_point=entry))

        # Seed with the known function starts so a headerless blob does not need
        # the O(address-space) linear sweep.
        cfg = proj.analyses.CFGFast(
            normalize=True,
            function_starts=sorted({a | 1 for a in wanted} | {entry}),
            show_progressbar=False)

        posted = examined = 0
        tally = {}
        for addr, func in cfg.kb.functions.items():
            norm = addr & ~1
            if norm not in wanted or func.is_simprocedure or func.is_plt:
                continue
            examined += 1
            mnemonics, n_instrs, n_bbs = [], 0, 0
            for block in func.blocks:
                n_bbs += 1
                try:
                    insns = block.capstone.insns
                except Exception:
                    continue
                n_instrs += len(insns)
                mnemonics.extend(i.mnemonic for i in insns)
            kind = classify_mnemonics(mnemonics)
            if kind is None:
                continue
            xbin.post_result(
                item_key=norm_addr(norm),
                data=hypothesis(kind, "angr_capstone", _BACKEND,
                                instructions=n_instrs, basic_blocks=n_bbs),
                confidence=KIND_CONFIDENCE[kind],
                category=CAT_FP,
            )
            tally[kind] = tally.get(kind, 0) + 1
            posted += 1

        print(f"[{_BACKEND}] examined {examined} functions; posted {posted} "
              f"({tally.get(KIND_ARITHMETIC, 0)} arithmetic, "
              f"{tally.get(KIND_MOVEMENT, 0)} movement)")


if __name__ == "__main__":
    xbin.start_worker()
