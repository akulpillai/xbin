# FP-function and soft-FP detector evaluation

Measured effectiveness of Morpheus's floating-point-function and soft-FP-helper
detectors, the defects found, and what the numbers imply for exposing them as
ranked xbin blackboard categories.

Harness: [`tools/eval_fp_detectors.py`](../tools/eval_fp_detectors.py). Re-runnable:

```bash
docker run --rm -v /evaldisk/akul/xbin:/host \
    -e MORPHEUS_ROOT=/host/xbin/submodules/Morpheus bind:latest \
    python3 /host/xbin/tools/eval_fp_detectors.py \
        --binary /host/pysyndy/example_config/real_world.axf \
        --morpheus /host/xbin/submodules/Morpheus \
        --out /host/fp-eval/real_world
```

> `bind:latest` bakes its own copy of Morpheus at `/home/bind/Morpheus`, so
> `MORPHEUS_ROOT` must point at the live checkout or the image must be rebuilt,
> otherwise the fixes below are not the code under test.

## Setup

**Target**: `pysyndy/example_config/real_world.axf` — non-stripped ARM Cortex-M
ELF with DWARF. 425 defined `STT_FUNC` symbols, 92 DWARF subprograms. A *mixed*
build: it has both hardware VFP arithmetic and libgcc soft-float helpers, which
is what makes it a useful discriminator.

**Ground truth**, four labels kept deliberately separate — the central finding is
that the detectors are used interchangeably while answering different questions:

| Label | Definition | Count |
|---|---|---|
| `GT_softfp` | soft-FP helper addresses, from symbol names | 42 |
| `GT_fp_hw` | contains a true VFP *arithmetic* instruction (movement excluded) | 63 |
| `GT_fp_soft` | calls a member of `GT_softfp` | 45 |
| `GT_fp_any` | `GT_fp_hw ∪ GT_fp_soft` — "does float math" | 105 |
| `GT_fp_semantic` | DWARF signature has float/double in a param or the return | 51 |
| `GT_fp_move_only` | VFP movement instructions but no arithmetic | 10 |

**Detectors**:

| id | implementation | mechanism |
|---|---|---|
| D1 | `binja_scripts/fp_function_filter_order.py` | BN mnemonic allowlist, arithmetic **+ movement** |
| D1b | same, arithmetic mnemonics only | isolates the movement contribution |
| D2 | `func_analysis/func_float_instr_analysis.py` | BN MLIL/LLIL float-op sets |
| D3 | `angr_scripts/fp_func_filter.py` | capstone VFP2/3/4+NEON groups |
| D4 | `bind_se/iret/fp_filter.py` | same mechanism as D3 |
| D5 | `binja_scripts/fp_func_filter_softfp.py` | BN call-site → soft-FP helper |
| S0 | `softfp_input_identification.py` | hard-coded address list, **as shipped** |
| S1 | ELF symbol names | the free exact source; defines `GT_softfp` |
| S2c | sigmatch acquisition *ceiling* | helper also present in the reference binary |

## M1 — detector vs ground-truth label (precision / recall / F1)

| det | n_pred | fp_hw | fp_soft | fp_any | fp_semantic |
|---|---|---|---|---|---|
| D1  | 77 | 0.818 / 1.000 / 0.900 | 0.039 / 0.067 / 0.049 | 0.818 / 0.600 / 0.692 | 0.662 / **1.000** / 0.797 |
| D1b | 63 | **1.000 / 1.000 / 1.000** | 0.048 / 0.067 / 0.056 | 1.000 / 0.600 / 0.750 | 0.698 / 0.863 / 0.772 |
| D2  | 64 | 0.984 / 1.000 / 0.992 | 0.047 / 0.067 / 0.055 | 0.984 / 0.600 / 0.746 | 0.688 / 0.863 / 0.765 |
| D3  | 78 | 0.808 / 1.000 / 0.894 | 0.038 / 0.067 / 0.049 | 0.808 / 0.600 / 0.689 | 0.654 / 1.000 / 0.791 |
| D4  | 78 | 0.808 / 1.000 / 0.894 | 0.038 / 0.067 / 0.049 | 0.808 / 0.600 / 0.689 | 0.654 / 1.000 / 0.791 |
| D5  | 47 | 0.064 / 0.048 / 0.055 | **0.957 / 1.000 / 0.978** | 0.957 / 0.429 / 0.592 | 0.000 / 0.000 |
| S0  |  6 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |

**No detector exceeds recall 0.600 on `GT_fp_any`.** The hardware detectors
(D1–D4) are excellent on VFP arithmetic and near-blind to soft-float
(recall 0.067); D5 is the mirror image (0.957/1.000 on soft-float, 0.048 recall
on hardware VFP). They are not competing implementations of one analysis — they
are two different analyses that have been used as substitutes.

Caveat: `GT_fp_semantic` is only defined over the 92 functions with DWARF
subprogram entries, so that column's denominator (51) is a subset of the universe.

## M2 — pairwise agreement (Jaccard / Cohen κ)

| pair | J | κ |
|---|---|---|
| D3 ~ D4 | **1.000** | **1.000** |
| D1 ~ D3 | 0.987 | 0.992 |
| D1b ~ D2 | 0.984 | 0.991 |
| D1 ~ D1b | 0.818 | 0.881 |
| D1 ~ D5 | **0.025** | **−0.103** |
| D2 ~ D5 | 0.028 | −0.084 |

D3 and D4 are byte-identical in output — confirming they are a copy-paste pair
that will drift; they should be one module with two callers, and they must not be
allowed to count as two independent votes on the blackboard.

D1 vs D5 is κ ≈ −0.10: *anti-correlated*. That is the empirical case for treating
soft-FP and hardware-FP as separate producers rather than redundant ones.

## M3 — the movement-mnemonic question

D1's allowlist includes `vmov/vldr/vstr/vldm/vstm/vpush/vpop/vmrs/vmsr`, which
only move float-shaped bits. D1 admits **14** functions D1b rejects; **9** of
those contain no VFP arithmetic at all.

| | precision vs `GT_fp_any` | recall vs `GT_fp_semantic` |
|---|---|---|
| D1 (with movement) | 0.818 | **1.000** |
| D1b (arithmetic only) | **1.000** | 0.863 |

This reverses the obvious "fix". Including movement costs precision but buys
recall on the label that actually matters — 7 of 51 float-signature functions are
reachable *only* via movement mnemonics. Movement is a crude proxy for "handles
float data". So the code was not simply wrong, and removing those mnemonics would
have silently dropped recoverable functions.

## M4 — recall on `GT_fp_semantic` (what SR/pysindy could actually fit)

D1 1.000 · D3/D4 1.000 · D1b 0.863 · D2 0.863 · D5 0.000 · S0 0.000

## M5 — combining detectors (the headline)

Against `GT_fp_any`:

| combination | P | R | F1 | covered |
|---|---|---|---|---|
| D1 alone | 0.818 | 0.600 | 0.692 | 63/105 |
| D1b alone | 1.000 | 0.600 | 0.750 | 63/105 |
| D2 alone | 0.984 | 0.600 | 0.746 | 63/105 |
| D5 alone | 0.957 | 0.429 | 0.592 | 45/105 |
| D1 + D5 | 0.868 | **1.000** | 0.929 | 105/105 |
| **D1b + D5** | **0.981** | **1.000** | **0.991** | 105/105 |
| D2 + D5 | 0.972 | **1.000** | 0.986 | 105/105 |

Every single detector caps at 0.600 recall; **any hardware detector plus D5
reaches 1.000**. The best pairing is arithmetic-only detection with the soft-FP
call-site detector (F1 0.991) — and note that once D5 is present, D1's movement
mnemonics stop being needed for recall and merely cost precision (0.929 vs
0.991). The kind distinction and the soft-FP producer together do what neither
does alone.

## M6 — runtime

Shared: BN load 9.7 s, angr CFG 5.6 s. Per detector: D1 10.6 s · D2 6.9 s ·
D3 7.1 s · D1b 0.9 s · D4 0.5 s · D5 1.2 s · S0/S1 ~0 s. All cheap enough to run
unconditionally; the shared BN/angr load dominates.

## Soft-FP helper identification

The address list is *acquired*, not hard-coded: `sigmatch.py:match_softfp_functions`
generates bind_se symbolic signatures for a libgcc reference binary and matches
them against the target, writing `softfp_matches.txt`, which is then supposed to
be used as `soft_fp_addr_file`. Findings on that chain:

- **Ceiling (S2c): 42/42.** The baked reference
  `signature_matching/signatures/arm-7e-m-libgcc/output.elf` (2015 functions)
  contains every one of the target's 42 helpers, so the mechanism is not
  reference-limited.
- **Realized (S2): 0/42, in 1517 s.** The measured run found **zero** helpers.
  It hit the 1500 s signature-generation timeout having produced 277 of 2015
  reference signatures (13.7%) and 44 of 425 target signatures (10.4%).

  This is **not** just the timeout. Of the 44 target signatures generated, 6 are
  at genuine helper addresses, and for all 6 the same-named counterpart *was*
  among the reference signatures:

  | target helper | signature generated | counterpart in reference set | matched |
  |---|---|---|---|
  | `__gedf2` | yes | yes | **no** |
  | `__ledf2` | yes | yes | **no** |
  | `__aeabi_d2f` | yes | yes | **no** |
  | `__aeabi_frsub` | yes | yes | **no** |
  | `__gesf2` | yes | yes | **no** |
  | `__lesf2` | yes | yes | **no** |

  So in 6 controlled comparisons — same function by name, non-empty signatures on
  both sides — `check_signature_match` matched **0**. The mechanism is not "slow
  but correct"; on this class of function it does not match regardless of budget.
  (Sample is 6, so treat the *rate* as indicative, not the exact figure.)

  One concrete hypothesis worth testing: the reference loads at ~`0x8000` while
  the target sits at `0x08000000`. Soft-FP helpers are branch-heavy and reference
  literal pools, so if any concrete address leaks into the recorded SMT2
  expression the two builds can never compare equal. `gen_signature` also caps
  exploration (`MAX_EXPLORE_STEPS = 256`) and keeps only the first non-trivial
  AAPCS return register, which is a fragile summary for a bit-twiddling helper.
- **The chain was broken in four places**, each silently:
  1. xbin never set `softfp_match_binary` or `soft_fp_addr_file`, so the soft-FP
     stage never ran at all.
  2. `match_softfp_functions` wrote its output with `f.write(l)` and **no
     newline**, concatenating every match onto one line. The consumer rejects any
     line that doesn't split into exactly two fields, so a *successful* match
     produced a file that parsed to zero entries.
  3. That file went to the process CWD, not `output_dir`, and nothing wired it
     back to `soft_fp_addr_file` — the README documents this as a manual step.
  4. The ABI table resolved 11 of the 69 helper names present (~16%), and
     unknown names are dropped by the caller.
- **S0, the shipped fallback** (`softfp_input_identification.py`'s six hard-coded
  arduino-giga addresses) scores 0 on every label here — those addresses are not
  soft-FP helpers in this binary. It is a workaround for the broken chain, not a
  detector.
- D5's 0.340 precision against `GT_softfp` is not a defect: D5 reports *callers*
  of helpers, and helpers call each other (e.g. `__aeabi_dadd` → `__aeabi_dsub`),
  so 16 of its 47 hits are themselves helpers.
- **Cost/benefit is lopsided.** Symbol extraction: **0.0 s, 42/42 exact**.
  SE-signature acquisition: **1517 s, 0/42**. For non-stripped uploads the free
  source strictly dominates, so `elf_to_firmware` now emits it. For *stripped*
  targets the SE path is not a usable fallback either on this evidence, which
  leaves name matching via FID/ghidriff against the helper families as the
  realistic option — a different mechanism this evaluation has not yet measured.

## FID as the soft-FP source (Phase 1 gate) — **PASS**

Harness: [`tools/eval_softfp_sources.py`](../tools/eval_softfp_sources.py). A libgcc
FID database was built from the same reference the SE path used, with the existing
builder:

```bash
python signature_matching/build_fid_db.py libgcc.fidb \
    signature_matching/signatures/arm-7e-m-libgcc/output.elf \
    --library-name libgcc --library-variant arm-7e-m \
    --arch ARM:LE:32:Cortex --load-address 0x8000
```

Measured on the **raw firmware image** at its VTOR base — the space xbin actually
feeds the tools. (Ghidra's `_import_and_analyze` *rebases* to the supplied
`load_address`, so passing 0 for an ELF shifts every address and scores a spurious
0; the ELF rows in the JSON are invalid for that reason.)

| score_threshold | helpers found | P | R | exact-name acc | ABI-family R | time |
|---|---|---|---|---|---|---|
| 14.6 (Ghidra default) | 17/44 | 1.000 | 0.386 | 1.000 | 0.386 | 13.8 s |
| **10** | **28/44** | **1.000** | **0.636** | **1.000** | **0.636** | 0.4 s* |
| 6 | 28/44 | 1.000 | 0.636 | 1.000 | 0.636 | 0.5 s* |
| 4 | 28/44 | 1.000 | 0.636 | 1.000 | 0.636 | 0.5 s* |

\* after the first run; the Ghidra project is reused across thresholds.

**Gate:** ABI-family recall ≥ 0.50 and name precision ≥ 0.90. Result **0.636 / 1.000
→ adopt.** For contrast the incumbent SE-signature path scored **0/44 in 1517 s**;
FID scores 28/44 in ~14 s with *every* recovered name exactly correct.

**Use threshold 10, not Ghidra's 14.6 default.** The default costs 11 helpers, all
small: the 0–20 B bucket goes from 2/13 at 14.6 to **12/13** at 10. Recall plateaus
at 10, so there is no reason to go lower.

### The predicted "small-function cliff" was backwards

| helper size | recall @ th=10 |
|---|---|
| 0–20 B | **0.923** (12/13) |
| 20–40 B | 0.667 (4/6) |
| 40–80 B | 1.000 (5/5) |
| 80–160 B | **0.273** (3/11) |
| 160+ B | 0.444 (4/9) |

Small helpers are the *best* recovered once the threshold is lowered; the worst
bucket is 80–160 B. The size floor was real but purely a *threshold* effect, and
lowering the threshold fixes it — it never prevented fingerprinting (`__aeabi_fcmpeq`,
an 18-byte wrapper, is present in the database).

### The residual 16 misses are mostly a function-boundary failure, not a FID failure

Of the 16 helpers FID did not report:

- **11 were never recovered as a function by Ghidra at all** on the raw blob
  (Ghidra finds 316 functions where the ELF declares 425 symbols).
- **5 were recovered but unmatched** — of which 4 are libgcc fall-through entry
  points sitting 8–16 B inside a body whose primary entry *was* matched
  (`__gedf2`/`__ledf2` → `__nedf2`; `__gesf2`/`__lesf2` → `__cmpsf2`). One function
  body, several ABI-distinct entry points, so FID can only name the outermost.

So on the functions it can actually see, FID scores **28/33 = 0.848 recall at
precision 1.000**. The ceiling is set by function-boundary recovery, which is the
shared fact the boundary-consensus category is meant to improve — better boundaries
raise soft-FP recall, which raises FP classification recall, which raises SR's
target list. Worth pairing FID with the ELF-symbol producer (which supplies all 44
when the upload is non-stripped) and treating the boundary gap as the next lever.

### Separately: `bind.fidb` does not load at all

While building the libgcc database, the shipped `signature_matching/signatures/fid/bind.fidb`
was found to be **silently unusable** with the image's Ghidra 12.1:

```
addUserFidFile(bind.fidb)   -> None      (null = not added; 1284161 bytes, exists)
addUserFidFile(libgcc.fidb) -> libgcc.fidb
```

`FidAnalysis.match_program` never checks that return value, and its only guard is
`hasLoadedFidFiles()` — which is **True regardless**, because Ghidra ships 10 bundled
Visual Studio x86/x64 FID databases that are always loaded. So FID matching on ARM
Cortex-M firmware has been running against **MSVC x86 signatures only**, with no
error and no warning. `fid` carries the highest `BACKEND_WEIGHTS` entry (1.0) and is
documented as "typically the first client to solve the easy functions".

Confirmed in production, not just at the API level. The live worker
(`xbin-worker-signature_matching-fid`, up 11 days) logs the same line on every run:

```
[fid] cached 0 matches over 19 functions; 0 meet confidence >= 0.78
[fid] posted 0 identifications to the blackboard
```

and the live `signature_matching` blackboard holds 4 hypotheses, **all from
ghidriff, none from fid**. The highest-weighted backend has contributed nothing for
the lifetime of the deployment.

The fix is the same mechanism proven above — regenerate the database with the current
Ghidra from `signature_matching/signatures/arducopter_cubeorange_default`. That
changes what the existing `fid` plugin matches, so it is called out rather than
bundled into this work. `match_program` should also fail loudly when a requested
`.fidb` does not load.

## Defects found and fixed

| # | Defect | Status | Measured effect |
|---|---|---|---|
| F1 | `prepare_config` never set `softfp_match_binary` / `soft_fp_addr_file`; whole soft-FP path inert | **fixed** (xbin) | `softfp_addrs_inout_dict`: **0 → 44 entries** |
| F9 | `match_softfp_functions` wrote the address file with no newlines → 100% of lines rejected by the consumer | **fixed** (Morpheus) | file now parses; also written to `output_dir` |
| F5 | ABI table covered 11/69 helper names | **fixed** (Morpheus) | table 13 → 92 entries; coverage **11/69 → 74/74 (100%)** |
| F6 | `get_softfp_abi.__main__` crashed (`"error" in None`, `abi['output']`); commented pair entries used `"r0:r1"` strings that would iterate character-by-character in `outputs` | **fixed** | self-test runs; all entries verified flat `rN` lists |
| F4 | `gpr_input_is_float_analysis` listed `LLIL_FCEIL/FFLOOR/FROUND`, which do not exist in BN; a `hasattr` guard dropped them silently | **fixed** | ceil/floor/round float use no longer invisible; unresolved names now warn |
| F3 | `func_float_instr_analysis` built its float-op set by name pattern, pulling in `LLIL_FLAG*`, `LLIL_FORCE_VER*`, `MLIL_FREE_VAR_SLOT*` | **fixed** | **latent, not firing**: 0 top-level hits, but 967 nested hits across 155/442 functions, so any caller walking operand trees would have classified a third of the binary as float. D2's scores are unchanged after the fix (verified). |
| F8 | movement mnemonics counted as float math | **fixed additively** | now reports `kind` (63 arithmetic / 14 movement); membership and ordering unchanged, so bind_sr is unaffected |
| F7 | D3/D4 are copy-paste duplicates (J=1.000); three files carry hard-coded `/home/zzhong/...` paths and address lists | **open** | needed before these become plugins |

The F8 change is additive by design: `filter_and_order_fp_functions` still
returns the same set in the same order and gains a `kind` field, and
`_has_fp_instruction` keeps its original behaviour, so bind_sr's target filter is
untouched. Verified: 77 functions, 63 arithmetic + 14 movement, ordering preserved.

## Implications for the xbin integration

1. **Two producers, not five.** D1/D2/D3/D4 all answer "hardware VFP"; D3≡D4
   exactly and D1b≈D2 (J=0.984). Shipping them as four independent voters would
   manufacture false consensus — three near-identical votes would outweigh the
   one genuinely independent signal. Ship one hardware producer per *engine*
   (BN and angr) and one soft-FP producer.
2. **`kind` belongs in the hypothesis**, not a boolean. `{"is_fp": true, "kind":
   "arithmetic"|"movement"|"soft"}` is what makes D1-vs-D1b resolvable by a
   ranker instead of by an unrecorded coin flip.
3. **The soft-FP producer is what unlocks recall**, taking 0.600 → 1.000, so it
   must be first-class. But it is only as good as the helper list it is given,
   and that list is the weakest link in the whole pipeline.
4. **Symbol-derived soft-FP is the primary source, not a shortcut.** Exact,
   0.0 s, and applies whenever the upload is non-stripped — the common case for
   the ELFs xbin already special-cases. The SE-signature alternative measured
   0/42 in 1517 s, so this is not a convenience preference: it is the only source
   currently shown to work.
5. **Stripped targets are an open problem.** Neither the hard-coded list (0/42)
   nor SE matching (0/42) works, and symbols are unavailable by definition. Until
   FID/ghidriff name matching is measured on the helper families, a stripped
   soft-float firmware should be reported as *unsupported* rather than silently
   analyzed with an empty helper set — which is exactly the failure mode that
   made this invisible for so long.
6. **Weight D5 and the hardware detectors independently.** They are
   anti-correlated (κ = −0.10); a single `BACKEND_WEIGHTS` entry keyed only by
   backend name cannot express "authoritative on soft-float, useless on VFP".
