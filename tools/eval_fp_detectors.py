#!/usr/bin/env python3
"""Measure the effectiveness of Morpheus's FP-function and soft-FP detectors.

Runs every in-tree detector over the same function universe and scores each
against ground truth derived from a non-stripped ARM ELF (symbol table + DWARF +
capstone disassembly). The point is to quantify a specific claim: the detectors
answer *different questions* while being used interchangeably, so a firmware that
does float math via libgcc calls (rather than hardware VFP) is invisible to most
of them.

Ground-truth labels (deliberately separate):
  GT_softfp       -- soft-FP helper addresses, from symbol names (exact, no heuristic)
  GT_fp_hw        -- contains a true VFP *arithmetic* instruction (movement excluded)
  GT_fp_soft      -- calls a member of GT_softfp
  GT_fp_semantic  -- DWARF signature has float/double in a parameter or the return

Detectors under test:
  D1 fp_function_filter_order        BN mnemonic prefix allowlist (incl. movement)
  D1b (same, movement mnemonics excluded -- measures the movement false-positive rate)
  D2 func_float_instr_analysis       BN MLIL/LLIL op sets
  D3 angr_scripts/fp_func_filter     capstone VFP2/3/4+NEON groups
  D4 bind_se/iret/fp_filter          same mechanism as D3 (near-duplicate)
  D5 fp_func_filter_softfp           BN call-site -> soft-FP helper
  S1 symbol-based soft-FP identification (the free, exact source xbin does not use)

Run inside ``bind:latest`` (needs Binary Ninja + angr + capstone + pyelftools):

  docker run --rm -v /evaldisk/akul/xbin:/host bind:latest \
      python3 /host/xbin/tools/eval_fp_detectors.py \
          --binary /host/pysyndy/example_config/real_world.axf \
          --morpheus /host/xbin/submodules/Morpheus \
          --out /host/fp-eval/real_world
"""

import argparse
import json
import os
import sys
import time
import traceback
from collections import defaultdict

# --------------------------------------------------------------------------- #
# soft-FP helper name families (ARM EABI + libgcc soft-float)
# --------------------------------------------------------------------------- #

# Prefix/suffix families rather than a fixed list, so a firmware built against a
# different libgcc still labels correctly.
_AEABI_SOFTFP = (
    "fadd", "fsub", "frsub", "fmul", "fdiv", "fneg",
    "dadd", "dsub", "drsub", "dmul", "ddiv", "dneg",
    "fcmpeq", "fcmplt", "fcmple", "fcmpge", "fcmpgt", "fcmpun",
    "dcmpeq", "dcmplt", "dcmple", "dcmpge", "dcmpgt", "dcmpun",
    "cfcmpeq", "cfcmple", "cfrcmple", "cdcmpeq", "cdcmple", "cdrcmple",
    "f2iz", "f2uiz", "d2iz", "d2uiz", "f2d", "d2f",
    "i2f", "ui2f", "i2d", "ui2d", "l2f", "ul2f", "l2d", "ul2d",
    "f2lz", "f2ulz", "d2lz", "d2ulz",
)
# libgcc internal names: __<op><s|d>f<n>  e.g. __addsf3, __muldf3, __cmpsf2
_LIBGCC_OPS = ("add", "sub", "mul", "div", "neg", "cmp", "eq", "ne",
               "lt", "le", "gt", "ge", "unord")
_LIBGCC_CONV = ("__extendsfdf2", "__truncdfsf2", "__fixsfsi", "__fixdfsi",
                "__fixunssfsi", "__fixunsdfsi", "__floatsisf", "__floatsidf",
                "__floatunsisf", "__floatunsidf", "__fixsfdi", "__fixdfdi",
                "__floatdisf", "__floatdidf")


def is_softfp_name(name):
    """True if a symbol name is an ARM soft-float / libgcc float helper.

    Excludes the unwinder helpers, which share the __aeabi_ prefix but are not
    float math (they are what makes a naive '__aeabi_' prefix test wrong).
    """
    if not name:
        return False
    n = name.split("@")[0]
    if n.startswith("__aeabi_"):
        tail = n[len("__aeabi_"):]
        if tail.startswith("unwind") or tail.startswith("idiv") or \
           tail.startswith("uidiv") or tail.startswith("ldivmod") or \
           tail.startswith("uldivmod") or tail.startswith("memcpy") or \
           tail.startswith("memset") or tail.startswith("memclr") or \
           tail.startswith("memmove") or tail.startswith("atexit"):
            return False
        return tail in _AEABI_SOFTFP
    if n in _LIBGCC_CONV:
        return True
    # __<op><s|d>f<digit>  -- __addsf3, __cmpdf2, __nesf2, ...
    if n.startswith("__") and len(n) > 6:
        body = n[2:]
        for op in _LIBGCC_OPS:
            if body.startswith(op):
                rest = body[len(op):]
                if len(rest) >= 3 and rest[0] in "sd" and rest[1] == "f" and rest[2:].isdigit():
                    return True
    return False


# --------------------------------------------------------------------------- #
# True VFP arithmetic vs movement -- the F8 split
# --------------------------------------------------------------------------- #

# Instructions that actually compute a floating-point value.
VFP_ARITHMETIC = (
    "vadd", "vsub", "vmul", "vnmul", "vdiv", "vsqrt", "vabs", "vneg",
    "vcmp", "vcvt", "vmla", "vmls", "vnmla", "vnmls", "vfma", "vfms",
    "vfnma", "vfnms", "vmaxnm", "vminnm", "vrint", "vsel",
)
# Instructions that only move float-shaped bits around. A function that merely
# spills callee-saved S-registers around a call contains only these.
VFP_MOVEMENT = (
    "vmov", "vldr", "vstr", "vldm", "vstm", "vpush", "vpop", "vmrs", "vmsr",
)


def _mnem_in(mnem, prefixes):
    m = mnem.strip().lower()
    return any(m.startswith(p) for p in prefixes)


# --------------------------------------------------------------------------- #
# Ground truth from the ELF
# --------------------------------------------------------------------------- #

def norm(addr):
    """Normalize a code address: clear the Thumb bit."""
    return addr & ~1


def load_elf_functions(path):
    """{norm_addr: {"name", "size", "addr"}} for every defined FUNC symbol."""
    from elftools.elf.elffile import ELFFile

    funcs = {}
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        for sec in elf.iter_sections():
            if sec.header["sh_type"] not in ("SHT_SYMTAB", "SHT_DYNSYM"):
                continue
            for sym in sec.iter_symbols():
                info = sym.entry["st_info"]
                if info["type"] != "STT_FUNC":
                    continue
                if sym.entry["st_shndx"] == "SHN_UNDEF":
                    continue
                a = norm(sym.entry["st_value"])
                if a == 0:
                    continue
                # Prefer the entry with a real size / a non-mangled name.
                prev = funcs.get(a)
                if prev is None or (not prev["size"] and sym.entry["st_size"]):
                    funcs[a] = {"addr": a, "name": sym.name,
                                "size": sym.entry["st_size"]}
    return funcs


def read_func_bytes(path, addr, size):
    """Raw bytes of [addr, addr+size) from whichever section contains it."""
    from elftools.elf.elffile import ELFFile

    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        for sec in elf.iter_sections():
            h = sec.header
            if not (h["sh_flags"] & 0x4):  # SHF_EXECINSTR
                continue
            start, sz = h["sh_addr"], h["sh_size"]
            if start <= addr < start + sz:
                off = addr - start
                return sec.data()[off:off + size]
    return b""


def disasm_labels(path, funcs, softfp_addrs):
    """Per-function GT_fp_hw / GT_fp_soft / movement-only, via capstone Thumb.

    Returns {addr: {"vfp_arith": bool, "vfp_move": bool, "calls_softfp": bool,
                    "callees": [addr...]}}
    """
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    out = {}
    for a, f in funcs.items():
        size = f["size"] or 0
        rec = {"vfp_arith": False, "vfp_move": False,
               "calls_softfp": False, "callees": []}
        if size:
            data = read_func_bytes(path, a, size)
            try:
                for insn in md.disasm(data, a):
                    m = insn.mnemonic
                    if _mnem_in(m, VFP_ARITHMETIC):
                        rec["vfp_arith"] = True
                    elif _mnem_in(m, VFP_MOVEMENT):
                        rec["vfp_move"] = True
                    if m.lower().startswith(("bl", "blx")) and insn.operands:
                        op = insn.operands[0]
                        if op.type == capstone.arm.ARM_OP_IMM:
                            t = norm(op.imm)
                            rec["callees"].append(t)
                            if t in softfp_addrs:
                                rec["calls_softfp"] = True
            except Exception:
                pass
        out[a] = rec
    return out


_FLOAT_TYPE_NAMES = ("float", "double", "_Float", "__fp16", "half")


def dwarf_float_signatures(path):
    """Addresses whose DWARF signature mentions float/double (param or return).

    Returns (set_of_addrs, n_subprograms_seen).
    """
    from elftools.elf.elffile import ELFFile

    def type_is_float(die, depth=0):
        if die is None or depth > 12:
            return False
        tag = die.tag
        if tag == "DW_TAG_base_type":
            nm = die.attributes.get("DW_AT_name")
            if nm:
                v = nm.value.decode("utf-8", "replace") if isinstance(nm.value, bytes) else str(nm.value)
                return any(k in v for k in _FLOAT_TYPE_NAMES)
            return False
        # Follow typedef / const / volatile / restrict chains. A pointer to
        # float is deliberately NOT counted: the value passed is an address.
        if tag in ("DW_TAG_typedef", "DW_TAG_const_type",
                   "DW_TAG_volatile_type", "DW_TAG_restrict_type"):
            ref = die.attributes.get("DW_AT_type")
            if ref is None:
                return False
            try:
                return type_is_float(die.get_DIE_from_attribute("DW_AT_type"), depth + 1)
            except Exception:
                return False
        return False

    hits, seen = set(), 0
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        if not elf.has_dwarf_info():
            return hits, 0
        dw = elf.get_dwarf_info()
        for cu in dw.iter_CUs():
            try:
                dies = list(cu.iter_DIEs())
            except Exception:
                continue
            for die in dies:
                if die.tag != "DW_TAG_subprogram":
                    continue
                low = die.attributes.get("DW_AT_low_pc")
                if low is None:
                    continue
                seen += 1
                addr = norm(low.value)
                is_float = False
                if "DW_AT_type" in die.attributes:
                    try:
                        is_float = type_is_float(die.get_DIE_from_attribute("DW_AT_type"))
                    except Exception:
                        pass
                if not is_float:
                    for child in die.iter_children():
                        if child.tag != "DW_TAG_formal_parameter":
                            continue
                        if "DW_AT_type" not in child.attributes:
                            continue
                        try:
                            if type_is_float(child.get_DIE_from_attribute("DW_AT_type")):
                                is_float = True
                                break
                        except Exception:
                            pass
                if is_float:
                    hits.add(addr)
    return hits, seen


def build_ground_truth(path):
    funcs = load_elf_functions(path)
    softfp = {a for a, f in funcs.items() if is_softfp_name(f["name"])}
    dis = disasm_labels(path, funcs, softfp)
    sem, n_sub = dwarf_float_signatures(path)

    gt = {
        "GT_softfp": softfp,
        "GT_fp_hw": {a for a, r in dis.items() if r["vfp_arith"]},
        "GT_fp_move_only": {a for a, r in dis.items()
                            if r["vfp_move"] and not r["vfp_arith"]},
        "GT_fp_soft": {a for a, r in dis.items() if r["calls_softfp"]},
        "GT_fp_semantic": {a for a in sem if a in funcs},
    }
    gt["GT_fp_any"] = gt["GT_fp_hw"] | gt["GT_fp_soft"]
    return funcs, gt, dis, n_sub


# --------------------------------------------------------------------------- #
# Detector adapters
# --------------------------------------------------------------------------- #

def _load_module(path, name):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class Ctx:
    """Lazily-built shared analysis state (a BN BinaryView, an angr CFG)."""

    def __init__(self, binary, morpheus, base_addr=None):
        self.binary = binary
        self.morpheus = morpheus
        self.base_addr = base_addr
        self._bv = None
        self._cfg = None
        self.timings = {}

    @property
    def bv(self):
        if self._bv is None:
            t0 = time.time()
            from binaryninja import load
            if self.base_addr is not None:
                import binaryninja as bn
                opts = {
                    "loader.architecture": "thumb2",
                    "loader.imageBase": self.base_addr,
                    "loader.platform": bn.Architecture["thumb2"].standalone_platform.name,
                }
                self._bv = load(self.binary, options=opts)
            else:
                self._bv = load(self.binary)
            self._bv.update_analysis_and_wait()
            self.timings["bn_load"] = time.time() - t0
        return self._bv

    @property
    def cfg(self):
        if self._cfg is None:
            t0 = time.time()
            import angr
            if self.base_addr is not None:
                proj = angr.Project(
                    self.binary, auto_load_libs=False,
                    main_opts={"backend": "blob", "base_addr": self.base_addr,
                               "arch": "ARMEL", "entry_point": self.base_addr},
                )
            else:
                proj = angr.Project(self.binary, auto_load_libs=False)
            self._cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
            self.timings["angr_cfg"] = time.time() - t0
        return self._cfg


def d1_binja_mnemonic(ctx, universe, movement=True):
    """fp_function_filter_order.py -- BN mnemonic prefix allowlist.

    ``movement=False`` reruns the same logic with the movement-only mnemonics
    removed from the allowlist, which isolates the F8 false-positive rate.
    """
    path = os.path.join(ctx.morpheus, "binja_scripts", "fp_function_filter_order.py")
    mod = _load_module(path, "fp_function_filter_order")
    if not movement:
        mod._VFP_PREFIXES = tuple(VFP_ARITHMETIC)
    bv = ctx.bv
    by_norm = {norm(f.start): f for f in bv.functions}
    hits = set()
    for a in universe:
        f = by_norm.get(a)
        if f is None:
            continue
        try:
            if mod._has_fp_instruction(f):
                hits.add(a)
        except Exception:
            pass
    return hits


def d2_binja_il(ctx, universe):
    """func_analysis/func_float_instr_analysis.py -- BN MLIL/LLIL op sets."""
    sys.path.insert(0, os.path.join(ctx.morpheus, "binja_scripts"))
    path = os.path.join(ctx.morpheus, "binja_scripts", "func_analysis",
                        "func_float_instr_analysis.py")
    mod = _load_module(path, "func_float_instr_analysis")
    bv = ctx.bv
    by_norm = {norm(f.start): f for f in bv.functions}
    hits = set()
    for a in universe:
        f = by_norm.get(a)
        if f is None:
            continue
        try:
            if mod.function_has_float_instr(f):
                hits.add(a)
        except Exception:
            pass
    return hits


def _capstone_group_detector(ctx, universe, path, name):
    mod = _load_module(path, name)
    cfg = ctx.cfg
    found = set(norm(a) for a in mod.find_fp_functions(cfg))
    return {a for a in universe if a in found}


def d3_angr_groups(ctx, universe):
    """angr_scripts/fp_func_filter.py -- capstone VFP/NEON instruction groups."""
    return _capstone_group_detector(
        ctx, universe,
        os.path.join(ctx.morpheus, "angr_scripts", "fp_func_filter.py"),
        "angr_fp_func_filter")


def d4_iret_groups(ctx, universe):
    """bind_se/iret/fp_filter.py -- the near-duplicate of D3."""
    return _capstone_group_detector(
        ctx, universe,
        os.path.join(ctx.morpheus, "signature_matching", "bind_se", "src",
                     "bind_se", "iret", "fp_filter.py"),
        "iret_fp_filter")


def d5_binja_callsite(ctx, universe, softfp_addrs):
    """fp_func_filter_softfp.py -- BN call-site -> soft-FP helper.

    The file has no library entry point (hard-coded DB_PATH + address list in
    main()), so this reuses its ``is_call_site`` helper over a supplied helper
    set -- i.e. it measures the *logic*, given the wiring it does not have.
    """
    path = os.path.join(ctx.morpheus, "binja_scripts", "fp_func_filter_softfp.py")
    mod = _load_module(path, "fp_func_filter_softfp")
    bv = ctx.bv
    hits = set()
    for target in softfp_addrs:
        for ref in bv.get_code_refs(target):
            fn = ref.function
            if fn is None:
                continue
            try:
                if mod.is_call_site(fn, ref.address, norm(target)):
                    hits.add(norm(fn.start))
            except Exception:
                pass
    return {a for a in hits if a in universe}


def s1_symbol_softfp(funcs):
    """The free, exact soft-FP source: ELF symbol names.

    This *is* how GT_softfp is defined, so its score against that label is
    tautologically perfect. It is included to make the point that the exact
    source exists and costs nothing -- and that xbin never uses it.
    """
    return {a for a, f in funcs.items() if is_softfp_name(f["name"])}


def s2_sigmatch_acquired(ctx, universe, ref_path, timeout):
    """The real acquisition mechanism: sigmatch.py:match_softfp_functions().

    Generates angr/bind_se symbolic signatures for the soft-FP reference binary
    and for the target, and matches them structurally. This is what
    ``signature_matching = true`` + ``softfp_match_binary`` is supposed to
    produce, and what should be feeding ``soft_fp_addr_file``.
    """
    sys.path.insert(0, os.path.join(ctx.morpheus, "signature_matching"))
    mod = _load_module(os.path.join(ctx.morpheus, "signature_matching", "sigmatch.py"),
                       "sigmatch")
    matches = mod.match_softfp_functions(
        ref_path, ctx.binary, sorted(universe), timeout=timeout,
        output_dir=os.environ.get("SIGCACHE", "/tmp/sigcache"))
    return {norm(int(m["target_address"], 16)) for m in matches}


def s2_ceiling(funcs, ref_path):
    """Upper bound on what the acquisition mechanism could ever find: target
    soft-FP helpers whose name also exists in the reference binary. Isolates
    'the reference lacks this helper' from 'the matcher failed'."""
    ref_names = set()
    with open(ref_path, "rb") as fh:
        from elftools.elf.elffile import ELFFile
        elf = ELFFile(fh)
        for sec in elf.iter_sections():
            if sec.header["sh_type"] not in ("SHT_SYMTAB", "SHT_DYNSYM"):
                continue
            for sym in sec.iter_symbols():
                if sym.entry["st_info"]["type"] == "STT_FUNC":
                    ref_names.add(sym.name)
    return {a for a, f in funcs.items()
            if is_softfp_name(f["name"]) and f["name"] in ref_names}


def s0_shipped_hardcoded(ctx):
    """The soft-FP list as actually shipped: the hard-coded addresses in
    ``softfp_input_identification.py`` (an arduino-giga build), scored against
    whatever binary is under test. This measures the real code path, not an
    idealized one."""
    path = os.path.join(ctx.morpheus, "binja_scripts", "softfp_input_identification.py")
    addrs = set()
    with open(path) as fh:
        in_list = False
        for line in fh:
            if "softfp_addrs = [" in line:
                in_list = True
                continue
            if in_list:
                if "]" in line:
                    break
                m = line.strip().split(",")[0].strip()
                if m.startswith("0x"):
                    try:
                        addrs.add(norm(int(m, 16)))
                    except ValueError:
                        pass
    return addrs


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

def score(pred, truth, universe):
    pred = pred & universe
    truth = truth & universe
    tp = len(pred & truth)
    fp = len(pred - truth)
    fn = len(truth - pred)
    tn = len(universe) - tp - fp - fn
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (2 * prec * rec / (prec + rec)) if (prec == prec and rec == rec and (prec + rec)) else float("nan")
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": prec, "recall": rec, "f1": f1, "n_pred": len(pred),
            "n_truth": len(truth)}


def jaccard(a, b):
    u = len(a | b)
    return (len(a & b) / u) if u else float("nan")


def kappa(a, b, universe):
    n = len(universe)
    if not n:
        return float("nan")
    a, b = a & universe, b & universe
    both = len(a & b)
    neither = n - len(a | b)
    po = (both + neither) / n
    pa, pb = len(a) / n, len(b) / n
    pe = pa * pb + (1 - pa) * (1 - pb)
    return (po - pe) / (1 - pe) if (1 - pe) else float("nan")


def fmt(x):
    return "  n/a" if x != x else f"{x:5.3f}"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True, help="non-stripped ARM ELF")
    ap.add_argument("--morpheus", required=True, help="Morpheus checkout root")
    ap.add_argument("--out", required=True, help="output prefix (dir is created)")
    ap.add_argument("--base-addr", default=None,
                    help="load base for a raw blob (hex); omit for an ELF")
    ap.add_argument("--skip", default="", help="comma-separated detector ids to skip")
    ap.add_argument("--softfp-ref", default=None,
                    help="soft-FP reference binary; enables S2/S2c (the real "
                         "acquisition mechanism)")
    ap.add_argument("--se-timeout", type=int, default=1800,
                    help="signature-generation timeout for S2 (seconds)")
    args = ap.parse_args()

    base = int(args.base_addr, 0) if args.base_addr else None
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)

    print(f"[*] ground truth from {args.binary}")
    t0 = time.time()
    funcs, gt, dis, n_sub = build_ground_truth(args.binary)
    gt_time = time.time() - t0
    universe = set(funcs)
    print(f"[*] {len(universe)} FUNC symbols, {n_sub} DWARF subprograms "
          f"({gt_time:.1f}s)")
    for k in ("GT_softfp", "GT_fp_hw", "GT_fp_soft", "GT_fp_any",
              "GT_fp_semantic", "GT_fp_move_only"):
        print(f"      {k:16} {len(gt[k]):5}")

    ctx = Ctx(args.binary, args.morpheus, base)
    softfp = gt["GT_softfp"]

    detectors = [
        ("D1",  "fp_function_filter_order (BN mnemonic, incl. movement)",
         lambda: d1_binja_mnemonic(ctx, universe, movement=True)),
        ("D1b", "fp_function_filter_order (arithmetic mnemonics only)",
         lambda: d1_binja_mnemonic(ctx, universe, movement=False)),
        ("D2",  "func_float_instr_analysis (BN MLIL/LLIL op sets)",
         lambda: d2_binja_il(ctx, universe)),
        ("D3",  "angr_scripts/fp_func_filter (capstone groups)",
         lambda: d3_angr_groups(ctx, universe)),
        ("D4",  "bind_se/iret/fp_filter (capstone groups)",
         lambda: d4_iret_groups(ctx, universe)),
        ("D5",  "fp_func_filter_softfp (BN call-site)",
         lambda: d5_binja_callsite(ctx, universe, softfp)),
        ("S0",  "softfp_input_identification (hard-coded address list, as shipped)",
         lambda: s0_shipped_hardcoded(ctx)),
        ("S1",  "symbol-based soft-FP identification",
         lambda: s1_symbol_softfp(funcs)),
    ]
    if args.softfp_ref:
        detectors.append(
            ("S2c", "sigmatch acquisition CEILING (helper present in reference)",
             lambda: s2_ceiling(funcs, args.softfp_ref)))
        detectors.append(
            ("S2", "sigmatch.match_softfp_functions (real acquisition mechanism)",
             lambda: s2_sigmatch_acquired(ctx, universe, args.softfp_ref,
                                         args.se_timeout)))

    preds, times, errors = {}, {}, {}
    for did, desc, fn in detectors:
        if did in skip:
            print(f"[-] {did} skipped")
            continue
        print(f"[*] running {did}: {desc}")
        t0 = time.time()
        try:
            preds[did] = fn()
            times[did] = time.time() - t0
            print(f"    -> {len(preds[did])} functions ({times[did]:.1f}s)")
        except Exception as e:
            times[did] = time.time() - t0
            errors[did] = f"{type(e).__name__}: {e}"
            print(f"    !! FAILED after {times[did]:.1f}s: {errors[did]}")
            traceback.print_exc()

    # ---------------- M1: precision/recall vs each label ------------------- #
    labels = ["GT_fp_hw", "GT_fp_soft", "GT_fp_any", "GT_fp_semantic", "GT_softfp"]
    print("\n=== M1: detector vs ground-truth label (P / R / F1) ===")
    header = f"{'det':4} {'n_pred':>7} " + " ".join(f"{l.replace('GT_',''):>22}" for l in labels)
    print(header)
    m1 = {}
    for did in preds:
        row = f"{did:4} {len(preds[did]):>7} "
        m1[did] = {}
        for l in labels:
            s = score(preds[did], gt[l], universe)
            m1[did][l] = s
            row += f"  {fmt(s['precision'])}/{fmt(s['recall'])}/{fmt(s['f1'])}"
        print(row)

    # ---------------- M2: pairwise agreement ------------------------------ #
    print("\n=== M2: pairwise agreement (Jaccard / Cohen kappa) ===")
    ids = [d for d in ("D1", "D1b", "D2", "D3", "D4", "D5") if d in preds]
    m2 = {}
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            j = jaccard(preds[a] & universe, preds[b] & universe)
            k = kappa(preds[a], preds[b], universe)
            m2[f"{a}~{b}"] = {"jaccard": j, "kappa": k}
            print(f"  {a:4}~{b:4}  J={fmt(j)}  k={fmt(k)}")

    # ---------------- M3: movement false positives ------------------------ #
    print("\n=== M3: VFP movement-only false positives (F8) ===")
    m3 = {}
    if "D1" in preds and "D1b" in preds:
        extra = preds["D1"] - preds["D1b"]
        move_only = gt["GT_fp_move_only"]
        m3 = {
            "d1_only": len(extra),
            "of_which_movement_only_by_gt": len(extra & move_only),
            "d1_precision_vs_fp_any": m1["D1"]["GT_fp_any"]["precision"],
            "d1b_precision_vs_fp_any": m1["D1b"]["GT_fp_any"]["precision"],
        }
        print(f"  D1 admits {len(extra)} functions D1b rejects; "
              f"{len(extra & move_only)} of those have no VFP arithmetic at all")
        print(f"  precision vs GT_fp_any: D1={fmt(m3['d1_precision_vs_fp_any'])} "
              f"-> D1b={fmt(m3['d1b_precision_vs_fp_any'])}")

    # ---------------- M4: recall on the recoverable set ------------------- #
    print("\n=== M4: recall on GT_fp_semantic (what SR/pysindy could fit) ===")
    m4 = {}
    for did in preds:
        s = m1[did]["GT_fp_semantic"]
        m4[did] = s["recall"]
        print(f"  {did:4} recall={fmt(s['recall'])}  "
              f"({s['tp']}/{s['n_truth']} float-signature functions admitted)")

    # ---------------- M5: union coverage (the consensus argument) ---------- #
    print("\n=== M5: does combining detectors beat any single one? (vs GT_fp_any) ===")
    m5 = {}
    combos = [("D1",), ("D1b",), ("D2",), ("D3",), ("D5",),
              ("D1", "D5"), ("D1b", "D5"), ("D2", "D5"), ("D3", "D5"),
              ("D1", "D2", "D3", "D5")]
    for combo in combos:
        if not all(c in preds for c in combo):
            continue
        u = set()
        for c in combo:
            u |= preds[c]
        s = score(u, gt["GT_fp_any"], universe)
        m5["+".join(combo)] = s
        print(f"  {'+'.join(combo):20} P={fmt(s['precision'])} R={fmt(s['recall'])} "
              f"F1={fmt(s['f1'])}  ({s['tp']}/{s['n_truth']})")

    # ---------------- soft-FP acquisition chain --------------------------- #
    if "S2c" in preds or "S2" in preds:
        print("\n=== soft-FP acquisition: ceiling vs realized ===")
        truth = gt["GT_softfp"]
        if "S2c" in preds:
            print(f"  reference covers {len(preds['S2c'] & truth)}/{len(truth)} "
                  f"of the target's helpers (ceiling)")
        if "S2" in preds:
            s = score(preds["S2"], truth, universe)
            print(f"  matcher realized  {s['tp']}/{len(truth)}  "
                  f"P={fmt(s['precision'])} R={fmt(s['recall'])}")
            if "S2c" in preds and len(preds["S2c"] & truth):
                print(f"  realized/ceiling  "
                      f"{s['tp'] / len(preds['S2c'] & truth):.3f}")

    # ---------------- M6: runtime ----------------------------------------- #
    print("\n=== M6: runtime ===")
    for did in sorted(times):
        print(f"  {did:4} {times[did]:7.1f}s")
    for k, v in ctx.timings.items():
        print(f"  {k:16} {v:7.1f}s (shared)")

    # ---------------- persist --------------------------------------------- #
    out_json = args.out + ".json"
    with open(out_json, "w") as fh:
        json.dump({
            "binary": args.binary,
            "base_addr": args.base_addr,
            "n_universe": len(universe),
            "n_dwarf_subprograms": n_sub,
            "ground_truth_sizes": {k: len(v) for k, v in gt.items()},
            "detector_pred_sizes": {k: len(v) for k, v in preds.items()},
            "errors": errors,
            "timings": {**times, **ctx.timings},
            "M1": m1, "M2": m2, "M3": m3, "M4": m4, "M5": m5,
            "softfp_names": sorted(funcs[a]["name"] for a in gt["GT_softfp"]),
        }, fh, indent=2, default=str)

    out_csv = args.out + ".csv"
    with open(out_csv, "w") as fh:
        cols = ["addr", "name", "size"] + labels + ["GT_fp_move_only"] + sorted(preds)
        fh.write(",".join(cols) + "\n")
        for a in sorted(universe):
            f = funcs[a]
            row = [f"0x{a:08x}", f['name'].replace(",", "_"), str(f["size"])]
            row += ["1" if a in gt[l] else "0" for l in labels]
            row += ["1" if a in gt["GT_fp_move_only"] else "0"]
            row += ["1" if a in preds[d] else "0" for d in sorted(preds)]
            fh.write(",".join(row) + "\n")

    print(f"\n[+] wrote {out_json}")
    print(f"[+] wrote {out_csv}")
    if errors:
        print(f"[!] {len(errors)} detector(s) failed: {list(errors)}")


if __name__ == "__main__":
    main()
