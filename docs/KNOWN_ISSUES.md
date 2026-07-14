# Known Issues & Findings (BINDonly)

Findings from building the end-to-end testing mechanism (`docs/e2e_testing.md`)
and running the full pipeline against `submodules/Morpheus/example_config/gs3.bin`
(2 MB ArduPilot single-image Cortex-M firmware).

## Verification status

- **Fast Docker-free lane** (`make test` / `pytest`): **24 passing** — consensus
  math, REST API, plugin metadata. CI-ready.
- **Smoke tier** (fid + ghidriff): PASSED.
- **Heavy tier** (all 5 plugins): ran ~39 h on `gs3.bin` and produced
  `signature_matching` = 5,497 functions (ghidriff + fid) and
  `equation_recovery` = 489 functions (symbolic_regression 487 + bind_se 2).
- Environment: `bind:latest` rebuilt to include the QEMU/FastDyn stack; Python
  env via rye `cpython@3.12.9` venv (`make setup`).
- **bind_se focused verification** (issues A + B below), on a smaller target:
  **Betaflight 4.5.1, STM32F411** unified target
  (<https://github.com/betaflight/betaflight/releases/tag/4.5.1>, asset
  `betaflight_4.5.1_STM32F411.hex`, sha256
  `5391158fefe97959c449d05c1b3b3fe30c6e6b7594568637a9233a2ed3cd4abc`), converted
  to a raw blob via `arm-none-eabi-objcopy -I ihex -O binary` (473,405 B, sha256
  `d9e463cd2239b8b8c661939c15a42dbf1be6ff6850be5cdfc16c7d47c13e17fd`, load base
  `0x08000000`). Kept in `uploads/` (gitignored); **not committed**. bind_se
  `setup()` completed, analyzed **982** functions, posted to `equation_recovery`
  with **0** `not in target CFG` misses, worker memory bounded (~0.5 GiB; no
  ~47 GiB runaway).

---

## Fixed

### 1. Workers never posted results (all 5 plugins) — FIXED
Each worker did `from xbin.sdk import _current_worker` at import time, which binds
the name to `None` (the `@xbin.plugin` decorator that sets the singleton runs
*after* the import). `on_new_binary` then hit `AttributeError: 'NoneType' has no
attribute 'post_result'` and the pipeline produced nothing.
**Fix:** producers use the public `xbin.post_result(...)` helper (resolves the
live singleton at call time); the arbiter uses `import xbin.sdk as _sdk` /
`_sdk._current_worker`. Verified: fid/ghidriff/SR all post.

### 2. `ghidra_scripts/` dropped from `bind:latest` — FIXED
`scripts/build_bind_base.sh` staged the Morpheus tree with `--exclude='./ghidra_*'`
(intended for a versioned Ghidra *install*), but the only matching entry is
`ghidra_scripts/` — so `ghidra_scripts/list_functions.py` was omitted and
`get_func_intersection` / `function_universe` crashed bind_se + symbolic_regression
with `FileNotFoundError`.
**Fix:** narrowed the glob to `--exclude='./ghidra_[0-9]*'`. The running image was
patched with a COPY layer; future rebuilds pick it up from the corrected script.

### 3. `uploads/` not writable by worker containers — FIXED
`uploads/` is bind-mounted into every worker, but the host dir was owned by uid
1002 with mode 755 while containers run as `bind` (uid 1000) → workers couldn't
write the `<bin>.setup_end` / `<bin>.bndb` sidecars Morpheus caches next to the
firmware. symbolic_regression crashed per-function on `open(sidecar, "w")`.
**Fix:** the orchestrator now `chmod 0777`s `UPLOAD_DIR` on startup
(`src/xbin_orchestrator/main.py`).

### 4. `bind:latest` shipped without QEMU/FastDyn — FIXED (operational)
The base image lacked `qemu-system-arm` + `libvirtual.so`, so symbolic_regression
(which needs a QEMU dynamic run) could not work. Rebuilt via
`scripts/rebuild_bind_base.sh` (kills the outdated running instance first, then
delegates to `build_bind_base.sh`, prunes, and verifies QEMU is present).

### 5. bind_se `setup()` CFG runaway on large firmware (was Open A) — FIXED
`BindSeClient.setup()` built the **target** angr CFG with
`CFGFast(force_complete_scan=True)`
(`submodules/Morpheus/bind_jobs/clients/bind_se_client.py`). On a multi-MB blob
that does an exhaustive linear sweep (every address a candidate function start)
and exploded memory/time — **~47 GiB, one core pegged, no progress** — stalling
*before* the per-function loop. `force_complete_scan` was **not required**: its
only job (guarantee every BN∩Ghidra job address is a CFG node so
`get_by_addr` doesn't `KeyError`) is done precisely and cheaply by seeding the
CFG with those addresses.
**Fix:**
- `bind_se_client.py`: `setup(function_starts=None)` builds the target CFG as
  `CFGFast(function_starts=function_starts or [], force_complete_scan=bool(config.get("se_target_force_complete_scan", False)), …)`.
  Default `False`; the `se_target_force_complete_scan` key (documented in
  `bind_config.toml`) can re-enable the exhaustive scan.
- `bind_se_worker.py`: computes the BN∩Ghidra universe **before** `setup()` and
  passes Thumb-decorated starts (`int(addr,16) | 1`, to match
  `get_by_addr(addr | 1)` on Cortex-M).
**Verified** on Betaflight 4.5.1 STM32F411 (see Verification status): target CFG
built in ~34 s at ~2.5 GiB (isolated probe: 2648 → 2783 functions *with* the
seed, i.e. seeding *raised* coverage), setup() completed, loop analyzed 982
functions with **0** `not in target CFG` misses.
Deployed to the running `bind:latest` via a COPY-layer patch of the two edited
Morpheus files; a `scripts/rebuild_bind_base.sh --force` will bake the corrected
submodule source in durably.

### 6. bind_se fork-after-threads deadlock in setup / guard — FIXED
Surfaced while fixing #5: `function_universe()` loads Binary Ninja **and** an
in-process Ghidra JVM (≈118 threads) into the worker. `setup()`'s fork-based
reference sig generation (`sigmatch._generate_sigs_with_cache` → `Process(...)`)
and the per-function fork guard (#7) then fork a heavily multithreaded process →
classic **fork-after-threads deadlock** (child inherits mutexes locked by threads
that don't exist in it; observed as an idle-CPU stall, worker never progresses).
Computing `function_universe` before `setup()` (needed for #5) made this hit
reference generation; the same hazard already made the guard unforkable.
**Fix:** `bind_se_worker._function_universe_isolated()` runs the universe
computation in a throwaway subprocess, so the JVM/BN threads never live in the
worker — every subsequent `fork()` is clean. Verified: after the subprocess
exits the worker drops to ~0.3 GiB, reference sig-gen completes, and both the
sig-gen fork and the guard fork run without stalling.

### 7. bind_se per-function loop unbounded (was Open B) — FIXED / VERIFIED
`handle()` → `_gen_target_signature` → `gen_signature` runs angr symbolic
execution with no time/memory bound (`sigmatch_timeout` only guards setup-phase
reference generation). The per-function fork guard in `bind_se_worker.py` runs
each `handle(func)` in a child with a wall-clock timeout + `RLIMIT_AS` cap
(`BIND_SE_FUNC_TIMEOUT` default 90 s, `BIND_SE_FUNC_MEM_GB` default 24). It was
previously unverifiable (issue #5 blocked reaching the loop) **and** latently
broken (issue #6 fork deadlock). Now:
- The orchestrator forwards an operator-specified env allowlist to worker
  containers (`XBIN_WORKER_ENV_PASSTHROUGH`, generic — no plugin-specific names
  in the core), so `BIND_SE_FUNC_TIMEOUT` / `BIND_SE_FUNC_MEM_GB` are tunable at
  fleet start. **Committed separately** as the Issue-B enabling feature.
- `_se_child` resets inherited SIGTERM/SIGINT to `SIG_DFL` so the guard's
  `terminate()` kills the child cleanly (no misleading "Shutdown signal 15" +
  weakref traceback, and no SIGTERM swallowing).
**Verified** with `BIND_SE_FUNC_TIMEOUT=1` on the Betaflight target: the loop ran
at `per-func cap: 1s`, the guard reported repeated `0x…: timeout (skipped)`, the
worker **survived and continued**, and after the signal reset the kill logs are
clean (0 "Shutdown signal 15", 0 tracebacks).

---

## Open

### A. bind_se reference signature generation is slow / coarsely bounded — NOTE
`setup()` generates SMT2 signatures for every function of the reference binary
(`_generate_sigs_with_cache`), bounded only by a single `sigmatch_timeout`
(default 7200 s). On the baked 3.6 MB `arducopter_cubeorange_default` reference
this "routinely hits the 2h cap" (per the sigmatch code comment) and saves a
partial set. It is CPU-bound slow-compute (now that #6 is fixed), not broken, but
it dominates `setup()` wall-clock on a full run. The Betaflight verification above
used a **tiny custom reference** (a 4-function Cortex-M ELF as the
`<stem>.reference` sibling) to keep reference gen to seconds; a production run
against a real reference should expect the long reference-gen phase (or a
pre-warmed sig cache). Not caused by the #5/#6 fixes.

### C. bind_se low yield — NOTE
Even past setup, bind_se posted only 2 hypotheses in ~39 h on `gs3.bin`, whereas
symbolic_regression robustly covered `equation_recovery` (487 formulas). Treat
bind_se as best-effort / secondary on large firmware; symbolic_regression is the
practical `equation_recovery` producer. (With #5/#6 fixed, bind_se now reaches
and works through its per-function loop far more readily — it posted steadily on
the Betaflight target — but this note stands for large firmware.)

### D. pysindy needs sibling I/O pairs (v1) — NOTE
The `pysindy` plugin (`equation_recovery`, from `submodules/pysyndy`) recovers a
function's equation *structure* statically with Binary Ninja, but `recover_equation`
only emits a fitted equation when given numeric I/O pairs `(X, y)`. In v1 those come
**only** from a sibling `<stem>.iopairs.txt` (`load_iopairs`); if none is present the
worker logs and skips (no per-function Binary Ninja load). So on a target without an
`.iopairs.txt` (e.g. Betaflight) `pysindy` posts nothing — the same effective limit
as `symbolic_regression`, whose QEMU/FastDyn boot-stall detection also fails on
Betaflight. Best-effort dynamic I/O-pair collection (QEMU/FastDyn) is the planned
follow-up that would let `pysindy`/`symbolic_regression` produce equations without a
pre-supplied iopairs file.

---

## Notes for future rebuilds

- The `bind:latest` running image carries COPY-layer patches (ghidra_scripts, and
  the issue-#5 `bind_se_client.py` + `bind_config.toml` patch). The #5 patch was
  applied as a fast `FROM bind:latest` COPY layer re-tagged `bind:latest` (the
  Dockerfile's `COPY Morpheus` sits *before* the QEMU-from-source build, so a full
  rebuild would rebuild QEMU/Ghidra/BN just for a 2-file source patch). A
  `scripts/rebuild_bind_base.sh --force` rebuilds from the submodule and bakes the
  corrected source in durably; re-apply any submodule source edits there so they
  persist. (The `bind_se_worker.py` fixes live in the plugin dir and are baked into
  the `xbin-plugin-*` thin layer on every fleet start, so they need no base rebuild.)
- Editing files under `submodules/Morpheus/` creates a local submodule diff; a
  later `git submodule update` may reset it. Track intended Morpheus changes
  upstream (purseclab/Morpheus, `integration` branch) or re-apply after updates.
