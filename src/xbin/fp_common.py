"""Shared vocabulary for the ``fp_classification`` blackboard category.

Every producer must mean the same thing by ``kind``, otherwise "two backends
agree" is meaningless and the validator/ranker cannot do their job. The
arithmetic/movement split lives here rather than in each worker so the BN and
angr producers are genuinely comparable.

Why the split exists (measured on a 425-function firmware, see
``docs/fp_detector_eval.md``): counting VFP *movement* instructions as float math
drops precision against "contains VFP arithmetic" from 1.00 to 0.82, but raises
recall against "has a float in its DWARF signature" from 0.86 to 1.00. Movement
is a crude proxy for "handles float data". Neither answer is simply right, so the
kind is reported and consensus decides.

And crucially, hardware-VFP absence does not mean "no float math": on a
soft-float build the arithmetic is libgcc calls with no VFP instruction at all.
The hardware producers cap at 0.600 recall on "does float math"; pairing them
with the soft-FP call-site producer reaches 1.000.
"""

# Instructions that compute a floating-point value.
VFP_ARITHMETIC = (
    "vadd", "vsub", "vmul", "vnmul", "vdiv", "vsqrt", "vabs", "vneg",
    "vcmp", "vcvt", "vmla", "vmls", "vnmla", "vnmls", "vfma", "vfms",
    "vfnma", "vfnms", "vmaxnm", "vminnm", "vrint", "vsel",
)
# Instructions that only move float-shaped bits (register spills, struct copies).
VFP_MOVEMENT = (
    "vmov", "vldr", "vstr", "vldm", "vstm", "vpush", "vpop", "vmrs", "vmsr",
)

#: Hypothesis ``kind`` values, strongest evidence first.
KIND_ARITHMETIC = "arithmetic"  # computes a float value in hardware VFP
KIND_MOVEMENT = "movement"      # only moves float-shaped bits
KIND_SOFT = "soft"              # no VFP; calls a soft-float (libgcc) helper

#: Per-kind confidence. Derived from measured precision against
#: "does float math": arithmetic-only detection scored 1.000, movement-inclusive
#: 0.818, and the soft-FP call-site detector 0.957.
KIND_CONFIDENCE = {
    KIND_ARITHMETIC: 0.95,
    KIND_MOVEMENT: 0.60,
    KIND_SOFT: 0.95,
}


#: ARM EABI / libgcc soft-float helper name families, used to recognise a helper
#: from its symbol name. This duplicates knowledge that properly belongs to
#: Morpheus's ABI table (``binja_scripts/softfp/get_softfp_abi.py``), but it has
#: to be reachable without it: ``bind:latest`` bakes its own Morpheus copy, so a
#: plugin container sees the *baked* table, not the checkout. The table stays the
#: authority when reachable; this is the fallback.
_AEABI_FLOAT_SUFFIXES = (
    "fadd", "fsub", "frsub", "fmul", "fdiv", "fneg",
    "dadd", "dsub", "drsub", "dmul", "ddiv", "dneg",
    "fcmpeq", "fcmplt", "fcmple", "fcmpge", "fcmpgt", "fcmpun",
    "dcmpeq", "dcmplt", "dcmple", "dcmpge", "dcmpgt", "dcmpun",
    "cfcmpeq", "cfcmple", "cfrcmple", "cdcmpeq", "cdcmple", "cdrcmple",
    "f2iz", "f2uiz", "d2iz", "d2uiz", "f2d", "d2f",
    "i2f", "ui2f", "i2d", "ui2d", "l2f", "ul2f", "l2d", "ul2d",
    "f2lz", "f2ulz", "d2lz", "d2ulz",
)
_LIBGCC_OPS = ("add", "sub", "mul", "div", "neg", "cmp", "eq", "ne",
               "lt", "le", "gt", "ge", "unord")
_LIBGCC_CONV = frozenset((
    "__extendsfdf2", "__truncdfsf2", "__fixsfsi", "__fixdfsi", "__fixunssfsi",
    "__fixunsdfsi", "__floatsisf", "__floatsidf", "__floatunsisf",
    "__floatunsidf", "__fixsfdi", "__fixdfdi", "__floatdisf", "__floatdidf",
))


def is_softfp_name(name):
    """True if a symbol name is an ARM soft-float / libgcc float helper.

    Deliberately excludes the ``__aeabi_`` routines that are not float math --
    the unwinder and the integer div/mod helpers -- which is why a bare
    ``__aeabi_`` prefix test is wrong.
    """
    if not name:
        return False
    n = str(name).split("@")[0]
    if n.startswith("__aeabi_"):
        return n[len("__aeabi_"):] in _AEABI_FLOAT_SUFFIXES
    if n in _LIBGCC_CONV:
        return True
    # __<op><s|d>f<digit>: __addsf3, __cmpdf2, __nesf2, ...
    if n.startswith("__") and len(n) > 6:
        body = n[2:]
        for op in _LIBGCC_OPS:
            if body.startswith(op):
                rest = body[len(op):]
                if len(rest) >= 3 and rest[0] in "sd" and rest[1] == "f" \
                        and rest[2:].isdigit():
                    return True
    return False


def classify_mnemonics(mnemonics):
    """Classify a function from its instruction mnemonics.

    Returns ``KIND_ARITHMETIC``, ``KIND_MOVEMENT``, or None when no hardware VFP
    instruction is present (which is *not* the same as "does no float math").
    """
    movement = False
    for m in mnemonics:
        if not m:
            continue
        m = m.strip().lower()
        if any(m.startswith(p) for p in VFP_ARITHMETIC):
            return KIND_ARITHMETIC  # strongest signal; stop scanning
        if any(m.startswith(p) for p in VFP_MOVEMENT):
            movement = True
    return KIND_MOVEMENT if movement else None


def hypothesis(kind, detector, backend, **evidence):
    """Build an ``fp_classification`` hypothesis.

    The claim (``is_fp``, ``kind``) is kept separate from ``evidence`` because the
    orchestrator derives a hypothesis id from ``sha256`` of the whole data dict:
    engine-specific counts differ between BN and angr, so identical claims would
    never dedupe if the counts sat alongside them. The validator compares the
    claim and ignores the evidence, which is the agreement check dedup cannot do.
    """
    return {
        "is_fp": True,
        "kind": kind,
        "evidence": dict(detector=detector, backend=backend, **evidence),
    }


def claim_of(data):
    """The comparable part of a hypothesis: ``(is_fp, kind)``. None if malformed."""
    if not isinstance(data, dict):
        return None
    if "is_fp" not in data:
        return None
    return (bool(data.get("is_fp")), data.get("kind"))
