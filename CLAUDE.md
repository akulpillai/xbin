# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**xbin** is a blackboard-architecture orchestrator for binary analysis. Specialized workers run as Docker containers and post competing *hypotheses* about a binary to a central blackboard; the orchestrator computes weighted consensus and broadcasts updates, and workers react. See `README.md` and `docs/sdk_reference.md` / `docs/grpc_schemas.md` for the generic framework story.

This branch (`BINDonly`) is pared down to the **four Morpheus/BIND analysis tools** plus an LLM arbiter — everything else (cfg_generation, function_boundary, flirt, the old pysyndy-based equation_recovery/morpheus plugins) has been removed. The four tools live in the **`submodules/Morpheus`** submodule (always on its **`integration`** branch) and map onto two blackboard categories grouped by "what question they answer":

- **`signature_matching`** ("what known function is this"): `fid` (Ghidra Function ID) and `ghidriff` (ghidriff/BSim diff), plus bind_se's identity matches.
- **`equation_recovery`** ("what does it compute"): `bind_se` (angr symbolic execution + local LLM), `symbolic_regression` (PySR + local LLM), and `pysindy` (Binary Ninja structure analysis + numpy STLSQ sparse regression, from the `submodules/pysyndy` submodule). `pysindy` runs pysyndy's **automated** pipeline via its `xbin_api` seam: it discovers single-basic-block FP-leaf functions and, per function, **collects I/O pairs by running the firmware under QEMU/FastDyn** and fits a closed form — no pre-supplied `.iopairs.txt`. It needs a **non-stripped Cortex-M firmware ELF** (with `main` + a vector-table section, from which `xbin_api` derives the bndb/VTOR/setup_end); on a raw `.bin` or stripped target it skips.

The `bind_arbiter` plugin is an xbin **ranker** that reconciles competing identifications per function via the local ollama endpoint. Item keys are function addresses (`norm_addr` → `0x%08x`), so every tool posts hypotheses for the same function side-by-side.

## Commands

```bash
git submodule update --init --recursive --remote submodules/Morpheus  # fetch Morpheus (integration branch)
git submodule update --init submodules/pysyndy                        # fetch pysyndy (main branch, private)
scripts/build_bind_base.sh [<binja-dir-or-zip>] [<license.dat>]        # build the heavy `bind:latest` base ONCE
                                      # (reads scripts/build.conf if args omitted; needs a Binary Ninja install + license)
scripts/build_pysindy_base.sh         # build `pysindy:latest` (= bind:latest + pysyndy code) ONCE, after bind:latest

pip install -e .                      # editable install (already active here via a .pth file)
xbin-orchestrator                     # start engine: gRPC :50051, REST+dashboard :8000, auto-opens browser
xbin-orchestrator --no-browser        # for headless / CI
xbin-orchestrator --plugin-dir PATH   # load out-of-tree plugin collections (repeatable)
xbin-orchestrator --plugin PATH[:category]  # load a single external plugin dir/file (repeatable)

ollama serve && ollama pull qwen2.5-coder:7b   # local LLM for bind_se/SR explanations + the arbiter

pytest tests/ -v                      # integration suite (see caveat below)
pytest tests/test_blackboard.py::test_analyzer_submission -v   # single test

docker compose up                     # full stack (redis + orchestrator) in containers
```

The four plugins build `FROM bind:latest`, so `scripts/build_bind_base.sh` must succeed before starting them. The base image is heavy (Ghidra + Binary Ninja + a QEMU fork + PySR) and bakes in the Binary Ninja license — **keep it local, never push it**.

**Tests require a reachable Redis on `localhost:6379`.** `tests/conftest.py` launches a real orchestrator subprocess (`python -m xbin_orchestrator.main`) and flushes the DB before each test; the orchestrator's `ensure_redis()` will `docker run` a container named `xbin-redis` if none is up. Tests exercise the live gRPC + Redis path, not mocks.

**Regenerating gRPC stubs:** `orchestrator_pb2.py` / `orchestrator_pb2_grpc.py` are generated (marked `DO NOT EDIT`) and checked in. After editing `src/xbin_orchestrator/orchestrator.proto`, regenerate with grpcio-tools (a declared build dep):
```bash
python -m grpc_tools.protoc -I src/xbin_orchestrator \
  --python_out=src/xbin_orchestrator --grpc_python_out=src/xbin_orchestrator \
  src/xbin_orchestrator/orchestrator.proto
```

## Architecture

Two importable packages live under `src/` (both installed by the one `xbin-orchestrator` distribution):

- **`xbin_orchestrator`** — the central engine. `main.py` is the whole backend: FastAPI REST API + gRPC blackboard servicer + Docker container management, plus the entire web dashboard as one embedded HTML string in the `dashboard()` route. Entry point `xbin-orchestrator` → `xbin_orchestrator.main:main`.
- **`xbin`** — the SDK plugins import (`import xbin`). `sdk.py` defines the `Worker` class and the module-level helpers.

**Redis is the blackboard** — both persistent state and the pub/sub event bus. Key conventions:
- `xbin:bb:{category}:{item_key}` → hypothesis state: `{"status", "hypotheses": [...]}`, `hypotheses` sorted by `score` descending (index 0 is the current "truth").
- `xbin:bb_logs:{category}` → audit trail; `xbin:syslogs` → system log.
- `xbin:events` → pub/sub channel carrying `NEW_BINARY` and `BLACKBOARD_UPDATE` events. This is the only thing workers subscribe to.
- `xbin:active_workers`, `xbin:worker_health`, `xbin:plugin_state:{category}:{name}` → fleet/liveness/plugin-state tracking.

**The Triad (plugin roles)** — a plugin is a class decorated with `@xbin.plugin(...)` that implements callbacks and ends with `xbin.start_worker()`:
- **Analyzer/Producer**: implements `on_new_binary(binary_path, requested_goals)` → `xbin.post_result(item_key, data, confidence)`.
- **Validator** (`is_validator=True`): implements `on_update(category, item_key, new_hypothesis, top_hypothesis)` → `xbin.post_validation(item_key, target_id="TOP")` to vouch.
- **Ranker** (`is_ranker=True`): implements `on_update(...)` → `xbin.update_rank(item_key, target_id, new_score)` to absolutely override a hypothesis score. `bind_arbiter` is the concrete ranker (ollama-backed).

The decorator also takes `display_name=` and `description=` (shown on the dashboard cards; discovered statically via regex before the plugin starts). `post_result(item_key, data, confidence, category=...)` accepts an optional `category` override so one worker can post to a different blackboard than its own (e.g. `bind_se` posts semantics to `equation_recovery` and identity matches to `signature_matching`).

**Consensus math** lives entirely in `XbinOrchestratorServicer.PostResult` / `UpdateRank` in `main.py`:
- A hypothesis `id` is `sha256(sorted-json of data)[:12]` → identical data from different backends deduplicates and auto-vouches.
- `score = confidence * BACKEND_WEIGHTS.get(backend_name, 0.5)`; a vouch adds `confidence * weight` to the target's score. `BACKEND_WEIGHTS` is keyed by `backend_name` (the decorator `name=`): `fid` 1.0, `ghidriff` 0.95, `symbolic_regression` 0.90 (highest-priority recoverer), `bind_se`/`pysindy` 0.85, `bind_arbiter` 1.0; unknown backends fall back to `0.5`.
- Status is `CONFLICTED` when the top two hypotheses differ in data and their score gap is `<= MARGIN_THRESHOLD` (0.05); otherwise `RESOLVED`.
- Rankers bypass additive scoring: `update_rank` sets `score` outright, then re-sorts.

## Plugin system & Docker (the non-obvious part)

The orchestrator **builds and runs each plugin as its own Docker container** — it shells out to the `docker` CLI, so the daemon must be reachable (docker-compose mounts the socket).

- **Discovery**: walks `PLUGIN_DIRS` (default `plugins/`) for any directory containing a `Dockerfile`. Category/name default to the parent-dir / dir names, **but source is regex-scanned for `@xbin.plugin(name=..., category=..., display_name=..., description=...)` which overrides directory inference.** For the BIND plugins the dir names already match, so both agree. Plugins are grouped on disk as `plugins/<category>/<tool>/`.
- **SDK injection at build time**: `_build_plugin_image` copies the plugin dir into a temp context and injects `src/` (the SDK), `pyproject.toml`, and `README.md`. That's why plugin Dockerfiles can `COPY src /opt/xbin_sdk` — those files aren't in the plugin dir on disk. (The BIND plugins put the SDK on `PYTHONPATH` rather than `pip install .`, to avoid pulling the orchestrator's server deps into a worker.)
- **Container runtime**: started with `--network host`, `uploads/` mounted to `/app/uploads`, and env `XBIN_ORCHESTRATOR=localhost:50051`, `REDIS_HOST=localhost`. `--network host` is why the workers reach a host ollama at `http://127.0.0.1:11434/v1`.
- **The `bind:latest` base image** (self-containment): the four BIND plugins are thin layers `FROM bind:latest`, which is built once by `scripts/build_bind_base.sh` directly from `submodules/Morpheus/docker/Dockerfile` (Ghidra + Binary Ninja + QEMU fork + PySR + the Morpheus tree at `/home/bind/Morpheus`). The orchestrator builds the thin layers normally (no `.xbin-prebuilt` marker); they just need `bind:latest` present. **Do not** use the submodule's `docker/build_docker.sh` — it is stale (references a non-existent `Dockerfile.bind` and reads a `gemini.key`); `build_bind_base.sh` uses the real `Dockerfile` and passes no Gemini key (we use ollama). The `pysindy` plugin adds a second base, **`pysindy:latest`**, built once by `scripts/build_pysindy_base.sh` as a thin layer `FROM bind:latest` that bakes in the `submodules/pysyndy` code (reusing bind:latest's Binary Ninja/QEMU/Ghidra/PySR — no re-download, no license needed at that step). The `pysindy` plugin is then a normal in-tree thin layer `FROM pysindy:latest` (no `.xbin-prebuilt` marker); it just needs `pysindy:latest` present. `pysindy:latest` also **symlinks** pysyndy's expected QEMU/FastDyn paths (`/home/bind/pysyndy/qemu/build/{qemu-system-arm,tests/tcg/plugins/libvirtual.so}`, which `xbin_api._cfg_for` hard-codes) to bind:latest's Morpheus copies — pysyndy's `qemu/` source is untracked, and the BIND QEMU fork + FastDyn plugin are the same lineage, so the dynamic collection runs without a QEMU rebuild. The dynamic run needs a 512M `/dev/shm`, so worker containers are started with `--shm-size=1g`.
- **How the workers run the analysis**: each worker (`plugins/*/*/*_worker.py`) reacts to `NEW_BINARY`, builds a per-run `bind_config.toml` via `xbin.bind_helpers.prepare_config`, computes the BN∩Ghidra function universe (`get_func_intersection`), and drives the corresponding Morpheus client's `setup()`/`handle(func)` directly — **bypassing** Morpheus's own HTTP job server (`bind_integration.py`). Without that server `JobClient.is_cancelled()` safely returns False, so the clients just run to completion. `src/xbin/bind_helpers.py` holds the shared config/universe helpers (Morpheus imports are deferred so it loads on a dev box too).

## Notable gotchas

- **`main()` calls `r.flushdb()` on every startup** — launching the orchestrator wipes all blackboard state.
- The orchestrator manages Redis itself: if none is running and it's not inside Docker, it `docker run`s `xbin-redis`.
- `sdk.py` has a two-path gRPC import fallback to cope with protobuf's flat import scheme; keep both paths working when touching imports.
- Editing the dashboard means editing the large HTML/JS string literal inside `main.py:dashboard()`. The old `showConsensus`/`visualizeBoundaries` JS functions are now dead (their UI buttons were removed with cfg/boundary); `showExplanation` is the live per-function detail viewer. Cytoscape.js is still loaded from a CDN but unused.
- Workers reach the SDK singleton either via module helpers (`xbin.post_result(...)`) or `from xbin.sdk import _current_worker`; both patterns appear across plugins.
- **reference-binary convention**: ghidriff/bind_se match against a symbolized reference. On upload the orchestrator saves an optional uploaded reference as `<binary-stem>.reference` next to the target (sibling convention); `prepare_config` also picks up a `<stem>.fidb`. Absent an upload, the baked arducopter defaults are used.
- The analysis stack is tuned for **ARM Cortex-M firmware** (`ARM:LE:32:Cortex`, VTOR load address, FP-function filtering). Symbolic regression additionally needs the QEMU/FastDyn dynamic run, so full end-to-end SR is a bigger-server job; fid/ghidriff smoke-test more easily (with a reference).

## Submodule (always the `integration` branch)

`submodules/Morpheus` (`git@github.com:purseclab/Morpheus.git`) backs **all four** BIND plugins and the arbiter. **Always use its `integration` branch** — `.gitmodules` pins `branch = integration`, and `scripts/build_bind_base.sh` checks out `integration` before building. Note: the submodule's `docker/run_bind_integration.sh` hardcodes a `GEMINI_API_KEY` default and `build_docker.sh` reads a `gemini.key`; xbin uses ollama and never propagates either, but that key should be rotated upstream.

A second submodule `submodules/pysyndy` (`git@github.com:PSecLab/pysyndy.git`, **private**, pinned to `branch = main`) backs the `pysindy` equation_recovery plugin. Like Morpheus it is referenced by URL + commit SHA only (no vendored content), so the public fork never carries pysyndy's code or firmware fixtures. `scripts/build_pysindy_base.sh` bakes its recovery code into `pysindy:latest` (excluding the heavy firmware/signature blobs). A fresh clone needs SSH access to the private repo: `git submodule update --init submodules/pysyndy`. The **only** pysyndy surface the plugin imports is `xbin_api.py` (`is_candidate` + `recover_for_function`) — the sanctioned two-verb seam; the rest of pysyndy (bind_auto, recover_equations, the FastDyn/QEMU invocation) stays behind it. pysyndy also ships full `xbin_plugins/` (binja_boundary + equation_recovery + morpheus), but those target upstream xbin's `function_boundary`+`symbol_matching` two-stage model; BINDonly instead drives the same `xbin_api` from its own self-contained `equation_recovery` plugin, so those `xbin_plugins/` are unused here.
