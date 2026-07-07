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

---

## Open

### A. bind_se `setup()` CFG runaway on large firmware — OPEN (primary blocker)
`BindSeClient.setup()` builds the **target** angr CFG with
`CFGFast(force_complete_scan=True)`
(`submodules/Morpheus/bind_jobs/clients/bind_se_client.py`). On a multi-MB blob
this does an exhaustive linear sweep (every address a candidate function start)
and explodes memory/time — observed **~47 GiB, one core pegged, no progress**,
stalling *before* bind_se reaches its per-function loop. (It did complete this
phase in the 39 h run and posted 2, so it is heavy-but-not-strictly-broken.)

**Proposed fix (not yet applied):** make the target CFG's `force_complete_scan`
config-driven and default it to `False` (matching the reference-binary CFGs),
e.g. `force_complete_scan=bool(config.get("se_target_force_complete_scan", False))`.
Deploy via a COPY-layer patch of `bind_se_client.py` (fast) and/or a
`bind:latest` rebuild (durable). **Unverified tradeoff:** the lighter recursive
scan may recover fewer functions (some `function_universe` addresses may be
absent from the CFG → `get_by_addr` KeyError → skipped). If coverage drops too
far, pass the known BN∩Ghidra addresses to `CFGFast(function_starts=...)` for
cheap-and-complete coverage (requires computing `function_universe` before
`setup()` and threading the addresses in).

### B. bind_se per-function loop unbounded — MITIGATED (unverified)
`handle()` → `_gen_target_signature` → `gen_signature` runs angr symbolic
execution with no time/memory bound (`self.timeout`/`sigmatch_timeout` only
guards setup-phase reference generation). A single pathological function can spin
tens of minutes and balloon memory.
**Mitigation (implemented, not yet exercised):** a per-function fork guard in
`plugins/equation_recovery/bind_se/bind_se_worker.py` runs each `handle(func)` in
a child with a wall-clock timeout + address-space cap (`BIND_SE_FUNC_TIMEOUT`
default 90s, `BIND_SE_FUNC_MEM_GB` default 24). It could not be verified end-to-end
because issue A blocks reaching the loop on `gs3.bin`; verify once A is resolved.

### C. bind_se low yield — NOTE
Even past setup, bind_se posted only 2 hypotheses in ~39 h, whereas
symbolic_regression robustly covered `equation_recovery` (487 formulas). Treat
bind_se as best-effort / secondary on large firmware; symbolic_regression is the
practical `equation_recovery` producer.

---

## Notes for future rebuilds

- The `bind:latest` running image carries COPY-layer patches (ghidra_scripts, and
  any future bind_se_client patch). A full `scripts/rebuild_bind_base.sh --force`
  rebuilds from the submodule and bakes in the corrected `build_bind_base.sh`
  exclude; re-apply any submodule source edits there so they persist.
- Editing files under `submodules/Morpheus/` creates a local submodule diff; a
  later `git submodule update` may reset it. Track intended Morpheus changes
  upstream (purseclab/Morpheus, `integration` branch) or re-apply after updates.
