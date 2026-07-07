# xbin End-to-End Testing Guide (BINDonly)

This guide covers **both** the automated test mechanism and the **manual/visual**
walkthrough of the web dashboard. xbin runs on a **remote server**, so §1 shows
how to reach the dashboard from your laptop.

Two ways to test:

| | What it exercises | Needs |
|---|---|---|
| **Automated fast lane** — `make test` | consensus math, REST API, plugin metadata (Docker-free) | venv + Redis (seconds) |
| **Automated full stack** — `scripts/e2e.sh <tier>` | upload → real plugin containers → blackboard, with a summary | Docker + `bind:latest` (+ ollama) |
| **Manual / visual** — the dashboard | what a human sees: fleet health, tables, per-function explanations | an SSH tunnel + a browser |

The pieces:

- `scripts/preflight.py` / `.sh` — readiness checker (docker, `bind:latest`, QEMU, redis, ollama, deps, ports).
- `scripts/e2e_driver.py` — tiered full-stack driver (`--smoke`/`--full`/`--heavy`, `--attach`).
- `scripts/e2e.sh` + `Makefile` — glue.
- `scripts/fetch_test_binaries.sh` — stage `gs3.bin` into `uploads/`.
- `scripts/rebuild_bind_base.sh` — rebuild `bind:latest` with QEMU (needed for `symbolic_regression`).
- `tests/` — the pytest suites (`pytest` = fast lane; `pytest -m e2e` = full stack).

---

## Tiers

| Tier | Plugins | Question answered | Extra deps | Speed |
|---|---|---|---|---|
| `smoke` | fid, ghidriff | signature_matching | none (no ollama/QEMU) | minutes |
| `full`  | + bind_se, bind_arbiter | + equation_recovery | ollama (`qwen2.5-coder:7b`) | up to ~2h (angr) |
| `heavy` | + symbolic_regression | + PySR formulas | **QEMU/FastDyn in `bind:latest`** | hours |

---

## 1. Reach the dashboard from your laptop (SSH tunnel)

The orchestrator serves the dashboard on the server at `http://localhost:8000`.
The cleanest way to view it from your laptop is an **SSH local-port-forward**
(private, no firewall change). From your **laptop**:

```bash
ssh -L 8000:localhost:8000 akul@purs3chikoo.ecn.purdue.edu
#        └ template: ssh -L 8000:localhost:8000 <user>@<server>
```

Keep that SSH session open, then open **http://localhost:8000** in your laptop's
browser.

- The gRPC port **`:50051` is internal** — worker containers reach it via
  `--network host` at `localhost:50051`. **Do not** forward it.
- Alternatives:
  - **VS Code Remote-SSH**: connect to the server; when the orchestrator starts,
    VS Code auto-forwards `8000` (see the Ports panel) — open `http://localhost:8000`.
  - **Background tunnel**: `ssh -fN -L 8000:localhost:8000 akul@purs3chikoo.ecn.purdue.edu`.

---

## 2. One-time server setup

Run these on the **server**, from the repo root `/evaldisk/akul/xbin/xbin`.

```bash
# 0. Confirm you're on the right branch and the Morpheus submodule is populated.
git branch --show-current                     # -> BINDonly
git -C submodules/Morpheus rev-parse --short HEAD   # -> a2e19cb (integration)

# 1. Create the Python env (system python3 lacks the deps; use rye's cpython).
make setup
#   == /home/akul/.rye/py/cpython@3.12.9/bin/python3 -m venv .venv
#      .venv/bin/pip install -e . pytest        (puts `xbin-orchestrator` on PATH)
source .venv/bin/activate

# 2. Only if you want the `heavy` tier (symbolic_regression): the shipped
#    bind:latest has NO QEMU. Rebuild it (multi-hour; removes the outdated
#    `bind_corrupt` scratch container first):
scripts/rebuild_bind_base.sh

# 3. Sanity-check prerequisites.
scripts/preflight.sh --tier smoke      # or --tier heavy once QEMU is built

# 4. Stage the test firmware into uploads/ (for the manual/curl path).
scripts/fetch_test_binaries.sh
```

Prereqs the preflight verifies: Docker; `bind:latest`; Redis on `:6379`; ollama
on `:11434` with `qwen2.5-coder:7b` (full/heavy); the Python deps; free ports;
and the test binary.

---

## 3. Launch the orchestrator (headless)

Run from the repo root (`uploads/` and `plugins/` are relative paths), inside
`tmux` so a laptop/tunnel drop doesn't kill it:

```bash
tmux new -s xbin                 # detach later with Ctrl-b then d; reattach: tmux attach -t xbin
cd /evaldisk/akul/xbin/xbin && source .venv/bin/activate
xbin-orchestrator --no-browser
```

Healthy startup prints just two lines (uvicorn is quiet at `log_level=warning`,
so there is **no "Uvicorn running" banner**):

```
[HH:MM:SS] Cleanup stale containers...
[HH:MM:SS] xbin Multi-Analysis Engine Online
```

Confirm readiness from another shell: `curl -s localhost:8000/api/v1/health`
→ `{"orchestrator":"HEALTHY",...}`.

> **Warning:** every orchestrator start runs `flushdb` — it wipes all blackboard
> state. Don't restart mid-test. The header **Clear Session** button also flushes
> (use it deliberately to reset).

---

## 4. Visual walkthrough

Open **http://localhost:8000** (through the tunnel).

### Tier 1 — Signature Matching (fid + ghidriff)

1. **Dashboard loads.** Top-right shows a green **`Orchestrator: OK`** badge. The
   left sidebar lists the plugins in two collapsible sections (Signature Matching,
   Equation Recovery), all **STOPPED**. `bind_arbiter` shows a blue **Ranker** badge.
2. **Start the fleet.** Click **Start Fleet** (header) — or start just **fid** and
   **ghidriff** via their per-card toggles for the fastest smoke test. Each card
   walks **BUILDING → STARTING → RUNNING**, then shows a green **READY** flag once
   healthy, with a heartbeat "ping" animation.
   - *First build is slow:* the orchestrator builds each plugin as a thin
     `--no-cache` layer over `bind:latest` — allow a few minutes per plugin the
     first time.
3. **Announce the target.** Two options:
   - **Recommended (server-side, no laptop copy):** on the server run
     ```
     curl -F file=@uploads/gs3.bin -F requested_analyses=signature_matching http://localhost:8000/api/v1/upload
     ```
   - **UI picker:** first copy the binary to your laptop
     (`scp akul@purs3chikoo.ecn.purdue.edu:/evaldisk/akul/xbin/xbin/uploads/gs3.bin .`),
     then click **📁 Choose Binary** → pick `gs3.bin`, ensure the **Signature
     Matching** checkbox is checked, and click **🚀 Start Analysis**. You'll see a
     **"Binary Announced"** toast.
   - No reference upload is needed — the symbolized reference and FID db are baked
     into `bind:latest`.
4. **Watch results.** A **Signature Matching** card appears with a
   **`Ranker: bind_arbiter`** badge and an **Audit Trail** button, then a table
   (**Function | Result | Detail**) — one row per function address (`0x...`). Rows
   populate within seconds-to-minutes of the workers being READY.
5. **Inspect a function.** Click **Details** on a row → a modal lists every
   hypothesis: `#i via <backend> score=.. raw_conf=..`, `Identity: <known_function>`,
   `Matchers`, and (for semantic backends) `Expression:` / `Explanation:` / `Output:`.
6. **Consensus signals.** A green **✓ + "+N vouches"** on a row means two tools
   agreed on identical data (fid and ghidriff auto-vouch each other). The
   **`Ranker: bind_arbiter`** badge means the LLM arbiter reconciles conflicts.
   Click **Audit Trail** for the per-category log and a plugin's **Logs** for its
   container output.

### Tier 2 — Equation Recovery (bind_se)

7. Start **bind_se** (Equation Recovery section) and announce with
   `requested_analyses=equation_recovery` (or `signature_matching,equation_recovery`).
   An **Equation Recovery** card fills with `recovered_expression` / explanation
   text. *This is slow* — angr symbolic execution runs up to a 2h cap and uses
   ollama for the explanation. Be patient before calling it stuck.

### Tier 3 — Symbolic Regression (heavy, optional)

8. Start **symbolic_regression**. It filters to hardware-float functions, runs each
   in **QEMU** to collect I/O, then PySR recovers a formula. This is the heaviest
   path (needs QEMU built into `bind:latest`) and can take hours.

---

## 5. What "success" looks like

- **Setup:** `make setup` succeeds; `xbin-orchestrator` is on PATH.
- **Launch:** the two sys_log lines; `/api/v1/health` → HEALTHY; green
  **Orchestrator: OK** badge.
- **Fleet:** signature cards reach **RUNNING + READY** with heartbeat pings.
- **Analysis:** "Binary Announced" toast; the Signature Matching table fills with
  `0x...` rows and resolved names within minutes; Details modals render; the
  **Ranker: bind_arbiter** badge is present.
- **Equation Recovery / SR:** the second table fills with expressions/formulas
  (slower).

---

## 6. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Full-screen 🔌 **Connection Lost** / **Backend Offline** badge | orchestrator died OR SSH tunnel dropped | Check the tmux window; re-run `xbin-orchestrator --no-browser`; reopen the `ssh -L` tunnel. The page auto-recovers when the backend returns. |
| Plugin card stuck **BUILDING** on first start | first `--no-cache` thin-layer build over the 6.85GB base | Wait a few minutes; watch `docker ps -a`. Escalate only if it flips to ERROR. |
| Plugin card shows **ERROR** (red line) | build/run failure | Click the card's **Logs**. If "image ... missing", confirm `bind:latest` (`docker images \| grep bind`). |
| Build fails immediately | `bind:latest` missing | `scripts/rebuild_bind_base.sh` (needs the Binary Ninja inputs in `scripts/build.conf`). |
| Empty results table after announcing | goal not checked / worker not HEALTHY / ollama down | Confirm the matching goal was checked or passed in the curl; confirm the card is **RUNNING + READY**; for equation_recovery/arbiter confirm ollama (`curl localhost:11434/api/tags`). |
| `symbolic_regression` posts nothing | no qualifying float functions, or QEMU missing | Check its **Logs**; confirm QEMU is in `bind:latest` (`scripts/preflight.sh --tier heavy`). |
| No **✓** / no **Validator** badge | **expected** — there is no `is_validator` plugin in BINDonly | Not a bug. The ✓ appears only when fid + ghidriff agree on identical data (dedup auto-vouch). Look for the **Ranker: bind_arbiter** badge. |
| UI file picker can't find `gs3.bin` | the browser reads your **laptop's** files, not the server's | Use the server-side `curl` announce, or `scp` the binary to your laptop first. |
| Blackboard reset unexpectedly | orchestrator restarted (`flushdb` on boot) | Don't restart mid-test; use **Clear Session** deliberately. |

---

## 7. Automated runs (recap)

```bash
# Fast, Docker-free lane (consensus/REST/metadata) — run this in CI:
make test                      # == .venv/bin/pytest   (excludes -m e2e)

# Full-stack, one command per tier (boots its own orchestrator, prints a summary):
scripts/e2e.sh smoke
scripts/e2e.sh full            # needs ollama
scripts/e2e.sh heavy           # needs QEMU in bind:latest

# Or drive an orchestrator you're already watching in the dashboard:
xbin-orchestrator --no-browser &          # (in tmux)
python scripts/e2e_driver.py --smoke --attach   # results appear live in the browser

# As a pytest (against the session orchestrator; opt-in):
pytest -m e2e                  # smoke tier; XBIN_E2E_TIER=full|heavy to change
```

The driver polls until the expected categories populate, then prints a
per-function summary (top hypothesis, backend, score, RESOLVED/CONFLICTED,
vouches, arbiter boosts) and a per-backend hypothesis count — including how many
`symbolic_regression` posted. It exits nonzero on any plugin crash, empty
required category, or timeout, and dumps the failing container's logs.
