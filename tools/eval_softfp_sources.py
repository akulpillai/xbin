#!/usr/bin/env python3
"""Evaluate soft-FP helper identification sources against symbol ground truth.

Companion to ``eval_fp_detectors.py`` (whose ground-truth helpers this imports).
Kept separate because these sources need metrics the M1-M6 shape does not carry:
a FID score-threshold sweep, recall as a function of helper size (the
small-function cliff), and ABI-family recall.

ABI-family recall is the metric that matters for the pipeline. Downstream
(``gpr_input_is_float_analysis`` via ``softfp_addrs_inout_dict``) consumes the
*ABI*, not the name -- and every ``__aeabi_fcmpXX`` shares one ABI (r0,r1 -> r0).
So recovering "some helper whose ABI is (r0,r1)->r0" at the right address makes
the taint analysis correct even when the exact name is wrong or missing.

Sources:
  S1        ELF symbol names                (exact; defines the ground truth)
  S3-libgcc FID against a libgcc .fidb      (the candidate)
  S3-bind   FID against the shipped bind.fidb (documents whether it loads at all)

Run inside ``bind:latest``:

  docker run --rm -v /evaldisk/akul/xbin:/host bind:latest \
      python3 /host/xbin/tools/eval_softfp_sources.py \
          --binary /host/pysyndy/example_config/real_world.axf \
          --raw    /host/fp-eval/real_world.fw.bin \
          --morpheus /host/xbin/submodules/Morpheus \
          --fidb /host/fp-eval/libgcc.fidb \
          --out /host/fp-eval/softfp_sources
"""

import argparse
import importlib.util
import json
import os
import sys
import time
import traceback


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def norm(a):
    return a & ~1


# --------------------------------------------------------------------------- #
# Ground truth: address -> every symbol name at that address (aliases matter)
# --------------------------------------------------------------------------- #

def alias_map(elf_path):
    """{norm_addr: {name, ...}} over defined FUNC symbols.

    libgcc exports several names per address (``__aeabi_dsub`` and ``__subdf3``
    are the same code), and FID records only one of them. Scoring a recovered
    name against a single "the" name would count a correct alias as wrong.
    """
    from elftools.elf.elffile import ELFFile

    out = {}
    with open(elf_path, "rb") as fh:
        elf = ELFFile(fh)
        for sec in elf.iter_sections():
            if sec.header["sh_type"] not in ("SHT_SYMTAB", "SHT_DYNSYM"):
                continue
            for sym in sec.iter_symbols():
                if sym.entry["st_info"]["type"] != "STT_FUNC":
                    continue
                if sym.entry["st_shndx"] == "SHN_UNDEF":
                    continue
                a = norm(sym.entry["st_value"])
                if a and sym.name:
                    out.setdefault(a, set()).add(sym.name)
    return out


def abi_signature(abi):
    """Hashable ABI identity: (inputs, outputs). None when unknown."""
    if not abi:
        return None
    return (tuple(abi.get("inputs", [])), tuple(abi.get("outputs", [])))


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

def score(pred, truth, universe):
    pred, truth = pred & universe, truth & universe
    tp, fp, fn = len(pred & truth), len(pred - truth), len(truth - pred)
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (2 * prec * rec / (prec + rec)) if (prec == prec and rec == rec and prec + rec) else float("nan")
    return {"tp": tp, "fp": fp, "fn": fn, "precision": prec, "recall": rec,
            "f1": f1, "n_pred": len(pred), "n_truth": len(truth)}


def fmt(x):
    return "  n/a" if x != x else f"{x:5.3f}"


# --------------------------------------------------------------------------- #
# FID
# --------------------------------------------------------------------------- #

def fid_matches(target, fidb_paths, project_location, load_address, lang, threshold):
    """(all_matches, load_report) from FidAnalysis.match_program.

    Also reports whether each .fidb actually loaded: addUserFidFile() returns
    null on failure and match_program never checks, while hasLoadedFidFiles()
    stays True because Ghidra's bundled Visual Studio databases are always
    present. A silently-unloaded database yields matching against MSVC x86
    signatures only.
    """
    import pyghidra

    pyghidra.start()  # must boot the JVM before any `ghidra.*` import resolves
    from bind_se.iret.fid_analysis import FidAnalysis
    from ghidra.feature.fid.db import FidFileManager
    from java.io import File

    fm = FidFileManager.getInstance()
    load_report = {}
    for p in fidb_paths:
        res = fm.addUserFidFile(File(str(p)))
        load_report[os.path.basename(str(p))] = (res is not None)

    fa = FidAnalysis()
    matches, all_addrs = fa.match_program(
        target_bin_path=target, fid_db_paths=fidb_paths,
        project_location=project_location, load_address=load_address,
        lang_id_str=lang, score_threshold=threshold,
    )
    return matches, all_addrs, load_report


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True, help="non-stripped ELF (ground truth)")
    ap.add_argument("--raw", default=None,
                    help="raw firmware image (what xbin actually feeds the tools)")
    ap.add_argument("--base-addr", default="0x08000000", help="raw image load base")
    ap.add_argument("--morpheus", required=True)
    ap.add_argument("--fidb", action="append", default=[],
                    help="libgcc .fidb (repeatable)")
    ap.add_argument("--bind-fidb", default=None,
                    help="the shipped bind.fidb, to test whether it loads")
    ap.add_argument("--thresholds", default="14.6,10,6,4,2",
                    help="FID score thresholds to sweep")
    ap.add_argument("--lang", default="ARM:LE:32:Cortex")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    ev = _load(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "eval_fp_detectors.py"), "ev")
    abi_mod = _load(os.path.join(args.morpheus, "binja_scripts", "softfp",
                                 "get_softfp_abi.py"), "softfp_abi")

    # ---------------- ground truth ---------------- #
    aliases = alias_map(args.binary)
    universe = set(aliases)
    truth = {a for a, names in aliases.items()
             if any(ev.is_softfp_name(n) for n in names)}
    sizes = {}
    for a, f in ev.load_elf_functions(args.binary).items():
        sizes[a] = f["size"]

    print(f"[*] {len(universe)} functions, {len(truth)} soft-FP helpers (ground truth)")
    print(f"[*] ABI table knows {len(abi_mod.SOFTFP_ABI)} helper names")

    # True ABI identities per helper address (any alias's ABI counts).
    true_abis = {}
    for a in truth:
        s = {abi_signature(abi_mod.get_softfp_abi(n)) for n in aliases[a]}
        true_abis[a] = {x for x in s if x is not None}
    resolvable = {a for a, s in true_abis.items() if s}
    print(f"[*] {len(resolvable)}/{len(truth)} helpers have a known ABI in the table")

    results = {"binary": args.binary, "raw": args.raw,
               "n_universe": len(universe), "n_truth": len(truth),
               "n_abi_resolvable": len(resolvable), "runs": {}}

    # ---------------- S1: symbols ---------------- #
    t0 = time.time()
    s1 = {a for a, names in aliases.items() if any(ev.is_softfp_name(n) for n in names)}
    s1_time = time.time() - t0
    s = score(s1, truth, universe)
    print(f"\n=== S1 symbols === P={fmt(s['precision'])} R={fmt(s['recall'])} "
          f"({s['tp']}/{len(truth)}) in {s1_time:.3f}s  [defines the label]")
    results["runs"]["S1"] = {"score": s, "seconds": s1_time}

    # ---------------- S3: FID sweep ---------------- #
    thresholds = [float(x) for x in args.thresholds.split(",") if x.strip()]
    targets = [("elf", args.binary, 0x0)]
    if args.raw:
        targets.append(("raw", args.raw, int(args.base_addr, 0)))

    for space, target, load_addr in targets:
        for label, dbs in (("libgcc", args.fidb),
                           ("bind", [args.bind_fidb] if args.bind_fidb else None)):
            if not dbs:
                continue
            for th in thresholds:
                key = f"S3-{label}/{space}/th={th}"
                proj = f"/tmp/fidmatch-{label}-{space}"
                print(f"\n=== {key} ===")
                t0 = time.time()
                try:
                    matches, all_addrs, loaded = fid_matches(
                        target, dbs, proj, load_addr, args.lang, th)
                except Exception as e:
                    print(f"    FAILED: {type(e).__name__}: {e}")
                    traceback.print_exc()
                    results["runs"][key] = {"error": f"{type(e).__name__}: {e}"}
                    continue
                elapsed = time.time() - t0

                print(f"    fidb loaded: {loaded}")
                if not any(loaded.values()):
                    print("    !! no user FID database loaded -- any matches below "
                          "come from Ghidra's bundled Visual Studio x86 databases")

                # Producer semantics: an address is a claimed helper when FID
                # named it something the soft-FP ABI table recognizes.
                pred, named, correct_name, correct_abi = set(), {}, set(), set()
                for m in matches:
                    a = norm(int(m["target_address"], 16))
                    n = m["known_function"]
                    named[a] = n
                    if ev.is_softfp_name(n) or abi_mod.get_softfp_abi(n):
                        pred.add(a)
                        if a in aliases and n in aliases[a]:
                            correct_name.add(a)
                        sig = abi_signature(abi_mod.get_softfp_abi(n))
                        if sig is not None and sig in true_abis.get(a, set()):
                            correct_abi.add(a)

                s = score(pred, truth, universe)
                name_prec = len(correct_name) / len(pred & truth) if (pred & truth) else float("nan")
                abi_recall = len(correct_abi) / len(resolvable) if resolvable else float("nan")
                abi_prec = len(correct_abi) / len(pred) if pred else float("nan")

                print(f"    total FID matches (any name): {len(matches)} over {len(all_addrs)} functions")
                print(f"    helper detection : P={fmt(s['precision'])} R={fmt(s['recall'])} "
                      f"F1={fmt(s['f1'])}  ({s['tp']}/{len(truth)})")
                print(f"    exact-name acc   : {fmt(name_prec)}  (of correctly-located helpers)")
                print(f"    ABI-family       : R={fmt(abi_recall)} P={fmt(abi_prec)}  "
                      f"<- the gate metric")
                print(f"    {elapsed:.1f}s")

                # size cliff
                buckets = [(0, 20), (20, 40), (40, 80), (80, 160), (160, 10 ** 9)]
                cliff = {}
                for lo, hi in buckets:
                    b = {a for a in truth if lo <= sizes.get(a, 0) < hi}
                    if not b:
                        continue
                    cliff[f"{lo}-{hi if hi < 10**9 else 'inf'}B"] = {
                        "n": len(b), "found": len(b & pred),
                        "recall": len(b & pred) / len(b)}
                print("    recall by helper size:")
                for k, v in cliff.items():
                    print(f"      {k:>10}  {v['found']:3d}/{v['n']:<3d}  R={v['recall']:.3f}")

                # Separate "FID failed to match a function Ghidra found" from
                # "Ghidra never recovered a function there at all". The second is
                # a function-boundary failure, not a FID failure, and it caps
                # FID's achievable recall no matter how the threshold is tuned.
                recovered = {norm(a) for a in all_addrs}
                boundary_missing = sorted(
                    f"0x{a:08x}:{sorted(aliases[a])[0]}"
                    for a in (truth - pred) if a not in recovered)
                fid_missed_but_found = sorted(
                    f"0x{a:08x}:{sorted(aliases[a])[0]}"
                    for a in (truth - pred) if a in recovered)
                print(f"    of {len(truth - pred)} missed helpers: "
                      f"{len(boundary_missing)} never recovered as a function by "
                      f"Ghidra, {len(fid_missed_but_found)} recovered but unmatched")

                results["runs"][key] = {
                    "score": s, "seconds": elapsed, "fidb_loaded": loaded,
                    "total_fid_matches": len(matches), "n_functions": len(all_addrs),
                    "helpers_recovered_as_functions": len(truth & recovered),
                    "boundary_missing": boundary_missing,
                    "fid_missed_but_found": fid_missed_but_found,
                    "exact_name_accuracy": name_prec,
                    "abi_family_recall": abi_recall, "abi_family_precision": abi_prec,
                    "size_cliff": cliff,
                    "missed": sorted(f"0x{a:08x}:{sorted(aliases[a])[0]}"
                                     for a in (truth - pred)),
                    "matched": sorted(f"0x{a:08x}:{named.get(a)}"
                                      for a in (truth & pred)),
                }

    with open(args.out + ".json", "w") as fh:
        json.dump(results, fh, indent=2, default=str)
    print(f"\n[+] wrote {args.out}.json")


if __name__ == "__main__":
    main()
