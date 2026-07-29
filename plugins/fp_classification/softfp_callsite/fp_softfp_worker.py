"""Soft-float call-site detection (fp_classification producer).

This is the producer that makes the category worth having. On a soft-float build
the arithmetic is libgcc calls and there is no VFP instruction anywhere, so the
hardware detectors are blind to it: measured, they cap at 0.600 recall on "does
float math" and score 0.067 on "calls a soft-FP helper". This producer scores
0.957/1.000 there, and is *anti-correlated* with them (Cohen kappa -0.10).
Together they reach 1.000 recall. See docs/fp_detector_eval.md.

A function is flagged ``soft`` when it calls a known soft-float helper. The
helper set comes from ``soft_fp_addr_file``, which xbin now derives from the
ELF symbol table (exact and free) -- see bind_helpers.elf_to_firmware. When the
``softfp_helpers`` category lands this should subscribe to it instead, so the
helper set is itself a ranked consensus rather than a file.
"""

import os

import xbin
from xbin.bind_helpers import CAT_FP, prepare_config, function_universe
from xbin.fp_common import KIND_CONFIDENCE, KIND_SOFT, hypothesis

_BACKEND = "softfp_callsite"


def _load_helpers(config):
    """{addr: name} of soft-float helpers from ``soft_fp_addr_file``.

    Format is one ``<name>, <hex addr>`` per line. The newline matters: the
    parser rejects any line that does not split into exactly two fields, so a
    file written without line breaks silently yields nothing.
    """
    path = config.get("soft_fp_addr_file") or ""
    if not path or not os.path.exists(path):
        return {}
    helpers = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) != 2:
                print(f"[{_BACKEND}] skipping malformed line: {line[:80]!r}")
                continue
            try:
                helpers[int(parts[1].strip(), 16) & ~1] = parts[0].strip()
            except ValueError:
                print(f"[{_BACKEND}] skipping unparseable address: {line[:80]!r}")
    return helpers


@xbin.plugin(
    name="softfp_callsite",
    category="fp_classification",
    display_name="Float Detection (soft-float call sites)",
    description="Flags functions that do float math through libgcc soft-float helper calls, which contain no VFP instruction and are invisible to the hardware detectors.",
)
class SoftFpCallsitePlugin:
    def on_new_binary(self, binary_path, requested_goals):
        if CAT_FP not in (requested_goals or []):
            print(f"[{_BACKEND}] {CAT_FP} not requested; skipping")
            return

        from bind_jobs.util import load_address, norm_addr

        config, config_path = prepare_config(binary_path)
        helpers = _load_helpers(config)
        if not helpers:
            print(f"[{_BACKEND}] no soft-float helper list available "
                  f"(soft_fp_addr_file={config.get('soft_fp_addr_file')!r}); "
                  f"cannot classify soft-float callers -- skipping rather than "
                  f"reporting an empty result as 'no soft float'")
            return
        print(f"[{_BACKEND}] {len(helpers)} known soft-float helpers")

        funcs = function_universe(config_path)
        wanted = {int(f, 16) & ~1 for f in funcs}

        target = config.get("bndb_path") if os.path.exists(
            config.get("bndb_path") or "") else config["firmware_bin_path"]

        import sys
        sys.path.insert(0, os.path.join(
            os.environ.get("MORPHEUS_ROOT", "/home/bind/Morpheus"), "binja_scripts"))
        from fp_function_filter_order import _load_bv
        from fp_func_filter_softfp import is_call_site

        bv = _load_bv(target, load_address(config))
        # caller addr -> set of helper names it calls
        callers = {}
        try:
            for helper_addr, helper_name in helpers.items():
                for ref in bv.get_code_refs(helper_addr):
                    fn = ref.function
                    if fn is None:
                        continue
                    caller = fn.start & ~1
                    if caller not in wanted or caller in helpers:
                        continue  # helpers calling helpers is not user float math
                    try:
                        if not is_call_site(fn, ref.address, helper_addr):
                            continue
                    except Exception:
                        continue
                    callers.setdefault(caller, set()).add(helper_name)
        finally:
            try:
                bv.file.close()
            except Exception:
                pass

        for caller, names in sorted(callers.items()):
            xbin.post_result(
                item_key=norm_addr(caller),
                data=hypothesis(KIND_SOFT, "binja_callsite", _BACKEND,
                                helpers=sorted(names)),
                confidence=KIND_CONFIDENCE[KIND_SOFT],
                category=CAT_FP,
            )
        print(f"[{_BACKEND}] posted {len(callers)} soft-float callers")


if __name__ == "__main__":
    xbin.start_worker()
