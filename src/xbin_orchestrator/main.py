import os
import re
import json
import threading
from concurrent import futures
import time
import subprocess
import shutil
import hashlib
import sys
import tempfile
import webbrowser
import socket
import argparse
import argcomplete

import grpc
import redis
import requests
from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks, Form
from fastapi.responses import HTMLResponse
import uvicorn

# Fix gRPC relative import issues when installed as a package
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    import orchestrator_pb2
    import orchestrator_pb2_grpc
except (ImportError, ValueError):
    from . import orchestrator_pb2
    from . import orchestrator_pb2_grpc

# ==========================================
# CONFIGURATION
# ==========================================
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
GRPC_PORT = "[::]:50051"
REST_PORT = 8000
# Local ollama endpoint used to turn raw results (SMT2 expressions / matched
# function names) into a readable one-liner for the dashboard. Same model the
# workers/arbiter use. Reached over --network host at 127.0.0.1.
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/v1/chat/completions")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
DEFAULT_PLUGINS_DIR = os.getenv("XBIN_PLUGINS_DIR", "plugins")
PLUGIN_DIRS = [DEFAULT_PLUGINS_DIR]
EXPLICIT_PLUGINS = []
UPLOAD_DIR = "uploads"
# Server-side library of symbolized reference binaries (betaflight, arducopter,
# ...). The user picks one from a dropdown instead of uploading a reference every
# time; the chosen file is copied to uploads/<target-stem>.reference so the BIND
# plugins pick it up via bind_helpers.sibling(). Drop more *.reference ELFs here
# to extend the menu.
REFERENCE_DIR = "references"

# Persistent per-analysis cache on the big disk, mounted into every worker so the
# expensive artifacts survive a fleet restart (and are reused on a re-run of the
# same binary -- e.g. a demo). Two sinks the Morpheus tools reuse across runs:
#   job_outputs/  -> ghidriff's whole-program diff cache (skips re-diffing the
#                    multi-MB reference when its <ref>-<target>_diff.json exists)
#                    + fid's Ghidra project + symbolic_regression outputs.
#   se_sigdb/     -> bind_se's growing signature DB (skips angr + LLM for
#                    already-recovered signatures).
# Both baked dirs are empty in bind:latest, so mounting over them hides nothing.
# (bind_se's angr rtdb and pysindy's outputs already land under uploads/, which is
# likewise persisted.) Keeping the fleet warm between runs reuses these too.
CACHE_DIR = "cache"

# Scratch/temp on the big disk, NOT root. This server's /tmp lives on the small
# root filesystem (~50G free); the repo (and Docker's data-root) live on the
# multi-TB /evaldisk. Point every host-side tempfile (the plugin build staging in
# _build_plugin_image, bind_helpers' config temps, etc.) at a repo-local scratch
# dir so a build or run can never fill root. Container-internal scratch already
# lands on evaldisk via Docker's data-root. Override with XBIN_TMPDIR if desired.
SCRATCH_DIR = os.getenv("XBIN_TMPDIR") or os.path.abspath(".xbin_scratch")
try:
    os.makedirs(SCRATCH_DIR, exist_ok=True)
    os.environ["TMPDIR"] = os.environ["TMP"] = os.environ["TEMP"] = SCRATCH_DIR
    tempfile.tempdir = SCRATCH_DIR
except OSError:
    pass  # fall back to the system default rather than refusing to start

# Generic worker env passthrough: forward an operator-specified allowlist of env
# vars from the orchestrator's environment into every worker container (via
# `docker run -e`) when they are set. Empty by default (nothing forwarded), so
# behaviour is unchanged unless configured. Set XBIN_WORKER_ENV_PASSTHROUGH to a
# comma-separated list to enable -- e.g. to tune a plugin's worker knobs at fleet
# start without rebuilding its image. Deliberately plugin-agnostic: no plugin- or
# tool-specific variable names live in the orchestrator core.
WORKER_ENV_PASSTHROUGH = tuple(
    v.strip() for v in os.getenv("XBIN_WORKER_ENV_PASSTHROUGH", "").split(",") if v.strip()
)

# Per-backend consensus weights (multiplied into each result's raw confidence).
# The four BIND tools + the ollama arbiter. Signature matchers (fid/ghidriff)
# produce high-precision identity matches, so they carry more weight than the
# semantic recoverers (bind_se/symbolic_regression). Unknown backends -> 0.5.
BACKEND_WEIGHTS = {
    "fid": 1.0,                  # Ghidra FunctionID signature matching
    "ghidriff": 0.95,           # Ghidra ghidriff / BSim binary diffing
    "symbolic_regression": 0.90, # PySR symbolic regression + ollama explanation (highest-priority recoverer)
    "bind_se": 0.85,            # angr symbolic execution + ollama explanation
    "pysindy": 0.85,            # BIND binary->equation (Binja structure + numpy STLSQ sparse regression)
    "bind_arbiter": 1.0,        # ollama arbiter (ranker)
}
MARGIN_THRESHOLD = 0.05

r = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

def sys_log(msg):
    timestamp = time.strftime("%H:%M:%S")
    entry = f"[{timestamp}] {msg}"
    print(entry)
    r.lpush("xbin:syslogs", entry)
    r.ltrim("xbin:syslogs", 0, 4999)  # keep enough for a full ~100-function verbose run

def set_plugin_state(name, category, status, error=None):
    state = {"status": status, "last_update": time.time()}
    if error: state["error"] = error
    r.set(f"xbin:plugin_state:{category}:{name}", json.dumps(state))

def ensure_redis():
    try:
        r.ping()
    except redis.ConnectionError:
        if os.path.exists("/.dockerenv") or REDIS_HOST != "localhost": exit(1)
        try:
            check = subprocess.run(["docker", "ps", "-a", "--filter", "name=xbin-redis", "--format", "{{.Names}}"], capture_output=True, text=True)
            if "xbin-redis" in check.stdout:
                subprocess.run(["docker", "start", "xbin-redis"], check=True, stdout=subprocess.DEVNULL)
            else:
                subprocess.run(["docker", "run", "-d", "--name", "xbin-redis", "-p", "6379:6379", "redis:alpine"], check=True, stdout=subprocess.DEVNULL)
            for _ in range(10):
                try:
                    if r.ping(): return
                except: time.sleep(1)
            exit(1)
        except: exit(1)

def cleanup_stale_plugins():
    try:
        sys_log("Cleanup stale containers...")
        subprocess.run("docker rm -f $(docker ps -aq --filter name=xbin-worker-)", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        r.delete("xbin:active_workers")
        r.delete("xbin:worker_health")
        r.delete("xbin:syslogs")
        
        # Reset building states
        keys = r.keys("xbin:plugin_state:*")
        for k in keys:
            state = json.loads(r.get(k))
            if state.get("status") in ["BUILDING", "STARTING"]:
                parts = k.split(":")
                if len(parts) >= 4:
                    set_plugin_state(parts[3], parts[2], "STOPPED")
    except: pass

# ==========================================
# MULTI-ANALYSIS BLACKBOARD API
# ==========================================
app = FastAPI(title="xbin Multi-Analysis Orchestrator", version="1.8.0")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REFERENCE_DIR, exist_ok=True)
# Persistent worker caches (job_outputs = ghidriff diff / fid ghidra proj / SR out;
# se_sigdb = bind_se signature DB). Created here + world-writable for the same
# reason as uploads/ (workers run as uid bind=1000).
CACHE_JOB_OUTPUTS = os.path.join(CACHE_DIR, "job_outputs")
CACHE_SE_SIGDB = os.path.join(CACHE_DIR, "se_sigdb")
# uploads/ is bind-mounted into every worker container, but the workers run as a
# different uid (bind=1000) and cache sidecars (<bin>.setup_end, <bin>.bndb) next
# to the firmware. Make it world-writable so bind_se/symbolic_regression can run.
for _d in (UPLOAD_DIR, CACHE_JOB_OUTPUTS, CACHE_SE_SIGDB):
    os.makedirs(_d, exist_ok=True)
    try: os.chmod(_d, 0o777)
    except OSError: pass

def get_container_name(name: str, category: str):
    return f"xbin-worker-{category.strip()}-{name.strip()}"

@app.get("/api/v1/system/logs")
def get_system_logs():
    logs = r.lrange("xbin:syslogs", 0, -1)
    return {"logs": "\n".join(reversed(logs))}

@app.post("/api/v1/session/clear")
def clear_session():
    r.flushdb()
    sys_log("Session cleared.")
    return {"status": "success"}

@app.get("/api/v1/health")
def get_health():
    health_data = r.hgetall("xbin:worker_health")
    workers = []
    now = time.time()
    for worker_id, val in health_data.items():
        data = json.loads(val)
        workers.append({
            "worker_id": worker_id, 
            "status": "HEALTHY" if (now - data["last_heartbeat"]) < 10 else "DEAD",
            "last_beat": data["last_heartbeat"]
        })
    return {"orchestrator": "HEALTHY", "worker_fleet": workers}

def list_references():
    """Reference binaries available in the server-side library (name -> path)."""
    refs = {}
    try:
        for fn in sorted(os.listdir(REFERENCE_DIR)):
            if fn.endswith(".reference"):
                refs[os.path.splitext(fn)[0]] = os.path.join(REFERENCE_DIR, fn)
    except OSError:
        pass
    return refs

def suggest_reference(target_filename, refs):
    """Auto-pick a reference by matching its name against the target filename."""
    stem = os.path.splitext(os.path.basename(target_filename or ""))[0].lower()
    for name in refs:
        if name.lower() in stem:
            return name
    return ""

@app.get("/api/v1/references")
def get_references(target: str = ""):
    refs = list_references()
    return {"references": sorted(refs.keys()), "suggested": suggest_reference(target, refs)}

@app.post("/api/v1/upload")
async def upload_binary(file: UploadFile = File(...), reference: UploadFile = File(None),
                        reference_name: str = Form(""), requested_analyses: str = Form("")):
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer: shutil.copyfileobj(file.file, buffer)
    # Symbolized reference binary saved next to the target under the sibling name
    # the BIND plugins derive (<binary-stem>.reference) so ghidriff/bind_se diff
    # against it instead of the baked default. Priority:
    #   1. an explicitly uploaded custom reference, else
    #   2. a reference_name selected from the server-side library, else
    #   3. nothing -> the baked default reference applies.
    ref_path = os.path.join(UPLOAD_DIR, os.path.splitext(file.filename)[0] + ".reference")
    if reference is not None and reference.filename:
        with open(ref_path, "wb") as buffer: shutil.copyfileobj(reference.file, buffer)
        sys_log(f"Upload: custom reference -> {os.path.basename(ref_path)}")
    elif reference_name:
        src = list_references().get(reference_name)
        if src:
            shutil.copyfile(src, ref_path)
            sys_log(f"Upload: reference '{reference_name}' -> {os.path.basename(ref_path)}")
        else:
            sys_log(f"Upload: reference '{reference_name}' not found in library; using baked default")
    analyses = [a.strip() for a in requested_analyses.split(",") if a.strip()]
    sys_log(f"Upload: {file.filename} for {analyses}")
    r.publish("xbin:events", json.dumps({"type": "NEW_BINARY", "filename": file.filename, "path": f"/app/uploads/{file.filename}", "requested_analyses": analyses}))
    return {"status": "success"}

@app.get("/api/v1/plugins/{name}/logs")
def get_plugin_logs(name: str, category: str):
    container_name = get_container_name(name, category)
    try:
        res = subprocess.run(["docker", "logs", "--tail", "100", container_name], capture_output=True, text=True, timeout=5)
        return {"logs": res.stdout + res.stderr}
    except Exception as e: return {"logs": f"Error: {e}"}

@app.get("/api/v1/workers/logs")
def get_merged_worker_logs(tail: int = 80):
    """Merged stdout of every running worker container, one interleaved stream.

    Tails each `xbin-worker-*` container with docker's RFC3339 --timestamps and
    sorts lexically (== chronologically), tagging each line with the short worker
    name. This is the "Worker Deep Dive" live view: the richest per-function
    progress (workers print `Result posted for <addr>` etc. to stdout). Every
    subprocess is timeout-guarded and per-container isolated so one wedged
    container/daemon can't blank the whole response.
    """
    tail = max(1, min(tail, 200))
    try:
        ps = subprocess.run(
            ["docker", "ps", "--filter", "name=xbin-worker-", "--filter", "status=running", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5)
        names = [n for n in ps.stdout.splitlines() if n]
    except Exception as e:
        return {"logs": f"Error listing workers: {e}", "workers": [], "count": 0}
    merged = []
    for cname in names:
        short = cname.replace("xbin-worker-", "")
        try:
            res = subprocess.run(["docker", "logs", "--tail", str(tail), "--timestamps", cname],
                                 capture_output=True, text=True, timeout=5)
            for line in (res.stdout + res.stderr).splitlines():
                ts, _, rest = line.partition(" ")  # RFC3339 prefix sorts chronologically
                merged.append((ts, f"[{short}] {rest}"))
        except Exception as e:
            merged.append(("", f"[{short}] <log error: {e}>"))
    merged.sort(key=lambda x: x[0])
    return {"logs": "\n".join(m[1] for m in merged) or "No worker output yet.",
            "workers": names, "count": len(merged)}

@app.get("/api/v1/plugins/available")
def list_available_plugins():
    cmd = ["docker", "ps", "-a", "--filter", "name=xbin-worker-", "--format", "{{.Names}}|{{.Status}}|{{.State}}"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    docker_data = {}
    for line in res.stdout.splitlines():
        name, status, state = line.split("|")
        docker_data[name.replace("xbin-worker-", "")] = {"status": status, "state": state}
    available = []
    health_data = r.hgetall("xbin:worker_health")
    now = time.time()
    
    # 1. Discover plugins in PLUGIN_DIRS
    for pdir in PLUGIN_DIRS:
        if not os.path.exists(pdir): continue
        for root, dirs, files in os.walk(pdir):
            if "Dockerfile" in files:
                name = os.path.basename(root)
                category = os.path.basename(os.path.dirname(root))
                available.append(_get_plugin_info(root, name, category, docker_data, health_data, now))

    # 2. Add EXPLICIT_PLUGINS
    for path, category in EXPLICIT_PLUGINS:
        if not os.path.exists(path): continue
        name = os.path.basename(path)
        if os.path.isdir(path):
            if "Dockerfile" in os.listdir(path):
                available.append(_get_plugin_info(path, name, category, docker_data, health_data, now))
        elif path.endswith(".py"):
            # For .py files, we still require a Dockerfile in the same directory if they are to be built
            if "Dockerfile" in os.listdir(os.path.dirname(path)):
                available.append(_get_plugin_info(os.path.dirname(path), name.replace(".py", ""), category, docker_data, health_data, now))

    # 3. Add dynamically connected workers
    active_workers = r.hgetall("xbin:active_workers")
    for w_id, type_info in active_workers.items():
        if ":" in type_info:
            category, name = type_info.split(":", 1)
            # Add if not statically discovered
            if not any(p["name"] == name and p["category"] == category for p in available):
                available.append(_get_plugin_info("", name, category, docker_data, health_data, now))

    # De-duplicate by unique_id (category-name)
    seen = set()
    unique_available = []
    for p in available:
        uid = f"{p['category']}-{p['name']}"
        if uid not in seen:
            unique_available.append(p)
            seen.add(uid)

    # Map each category to its active ranker name (if any is registered)
    categories = list(set([p["category"] for p in unique_available] + ["signature_matching", "equation_recovery"]))
    ranker_map = {}
    for cat in categories:
        ranker_map[cat] = next((p["name"] for p in unique_available if p["category"] == cat and p["is_ranker"]), "Baseline")
    
    return {"plugins": unique_available, "rankers": ranker_map}

def get_static_plugin_info(root):
    """Try to find the category and name in the source code first."""
    if not os.path.exists(root): return None, None
    files = os.listdir(root) if os.path.isdir(root) else [os.path.basename(root)]
    search_dir = root if os.path.isdir(root) else os.path.dirname(root)
    
    cat = None
    name = None
    for f in files:
        if f.endswith(".py"):
            try:
                with open(os.path.join(search_dir, f), "r") as pf:
                    content = pf.read()
                    import re
                    # Look for category="something" or category='something'
                    cat_match = re.search(r'category=["\']([^"\']+)["\']', content)
                    if cat_match: cat = cat_match.group(1)
                    
                    name_match = re.search(r'name=["\']([^"\']+)["\']', content)
                    if name_match: name = name_match.group(1)
                    
                    if cat and name: return cat, name
            except: pass
    return cat, name

def _get_plugin_info(root, name, category, docker_data, health_data, now):
    # Prioritize category and name found in source code
    static_cat, static_name = get_static_plugin_info(root)
    if static_cat: category = static_cat
    if static_name: name = static_name

    unique_id = f"{category}-{name}"

    state_str = r.get(f"xbin:plugin_state:{category}:{name}")
    saved = json.loads(state_str) if state_str else {"status": "STOPPED"}
    status = saved["status"]
    
    # Static discovery: scan the plugin source for decorator metadata so the
    # dashboard can show validator/ranker badges + a display name/description
    # BEFORE the plugin is ever started.
    is_validator = saved.get("is_validator", False)
    is_ranker = saved.get("is_ranker", False)
    display_name = saved.get("display_name", "")
    description = saved.get("description", "")
    files = os.listdir(root) if os.path.isdir(root) else []
    for f in files:
        if not f.endswith(".py"): continue
        try:
            with open(os.path.join(root, f), "r") as pf:
                content = pf.read()
        except: continue
        if "is_validator=True" in content: is_validator = True
        if "is_ranker=True" in content: is_ranker = True
        if not display_name:
            m = re.search(r'display_name\s*=\s*["\']([^"\']+)["\']', content)
            if m: display_name = m.group(1)
        if not description:
            m = re.search(r'description\s*=\s*["\']([^"\']+)["\']', content)
            if m: description = m.group(1)

    if unique_id in docker_data:
        d = docker_data[unique_id]
        status = "RUNNING" if d["state"] == "running" else "CRASHED" if "Exited (0)" not in d["status"] else "STOPPED"
    
    health_status = "UNKNOWN"; last_beat = 0
    for w_id, w_val in health_data.items():
        w_data = json.loads(w_val)
        if w_data.get("backend") == name:
            last_beat = w_data["last_heartbeat"]; health_status = "HEALTHY" if (now - last_beat) < 10 else "DEAD"
            if "is_validator" in w_data: is_validator = w_data["is_validator"]
            if "is_ranker" in w_data: is_ranker = w_data["is_ranker"]
            if w_data.get("display_name"): display_name = w_data["display_name"]
            if w_data.get("description"): description = w_data["description"]

    return {"name": name, "category": category, "status": status, "health": health_status, "last_beat": last_beat, "error": saved.get("error"), "is_validator": is_validator, "is_ranker": is_ranker, "display_name": display_name or name, "description": description}

def _plugin_matches(root, name, category):
    static_cat, static_name = get_static_plugin_info(root)
    dir_name = os.path.basename(root)
    dir_cat = os.path.basename(os.path.dirname(root))

    eff_name = static_name if static_name else dir_name
    eff_cat = static_cat if static_cat else dir_cat
    return eff_name == name and eff_cat == category

def get_plugin_path_and_context(name: str, category: str):
    # 1. Check EXPLICIT_PLUGINS first
    for path, p_category in EXPLICIT_PLUGINS:
        static_cat, static_name = get_static_plugin_info(path)
        
        # Determine effective name and category for this explicit path
        eff_name = static_name if static_name else os.path.basename(path).replace(".py", "")
        eff_cat = static_cat if static_cat else p_category
        
        if eff_name == name and eff_cat == category:
            if os.path.isdir(path):
                return path, path
            else:
                return os.path.dirname(path), os.path.dirname(path)

    # 2. Default in-tree plugins build from the plugin directory. The build
    # helper stages that directory and injects the SDK files the Dockerfiles need.
    default_path = os.path.join(DEFAULT_PLUGINS_DIR, category, name)
    if os.path.exists(default_path):
        return default_path, default_path

    # Plugin directories do not have to match the decorator name; discovery scans
    # the source for @xbin.plugin(name=..., category=...) and prefers those.
    for pdir in PLUGIN_DIRS:
        if not os.path.exists(pdir):
            continue
        for root, dirs, files in os.walk(pdir):
            if "Dockerfile" not in files:
                continue
            if _plugin_matches(root, name, category):
                return root, root
        
    # 3. Out-of-tree plugins in PLUGIN_DIRS
    for pdir in PLUGIN_DIRS:
        if pdir == DEFAULT_PLUGINS_DIR: continue
        epath = os.path.join(pdir, category, name)
        if os.path.exists(epath):
            return epath, epath
        # Also check standalone in pdir
        spath = os.path.join(pdir, name)
        if category == "standalone" and os.path.exists(spath):
            return spath, spath
    print(f'plugin directory: {PLUGIN_DIRS}')      
    raise Exception(f"Plugin {category}/{name} not found in any PLUGIN_DIRS or EXPLICIT_PLUGINS")

def _image_exists(image_name: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", image_name],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def bg_start_plugin(name: str, category: str):
    container_name = get_container_name(name, category)
    image_name = f"xbin-plugin-{category}-{name}"
    try:
        p_path, p_context = get_plugin_path_and_context(name, category)

        # Prebuilt plugins (marker file) are built out-of-band by their own
        # build.sh -- e.g. equation_recovery, whose image extends a heavy Binary
        # Ninja base the orchestrator can't build. Reuse the existing image and
        # skip the build entirely; to rebuild, run build.sh again (or docker rmi).
        if os.path.exists(os.path.join(p_path, ".xbin-prebuilt")):
            if not _image_exists(image_name):
                raise Exception(
                    f"{name}/{category} is marked .xbin-prebuilt but image "
                    f"'{image_name}' is missing -- run {p_path}/build.sh first")
            sys_log(f"{image_name} is prebuilt; skipping build.")
        else:
            set_plugin_state(name, category, "BUILDING")
            _build_plugin_image(name, category, image_name, p_path, p_context)

        set_plugin_state(name, category, "STARTING")
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        abs_uploads = os.path.abspath(UPLOAD_DIR)
        abs_job_outputs = os.path.abspath(CACHE_JOB_OUTPUTS)
        abs_se_sigdb = os.path.abspath(CACHE_SE_SIGDB)
        # --shm-size: the pysindy/symbolic_regression dynamic runs boot Cortex-M
        # firmware under QEMU system mode with a 512M /dev/shm memory-backend-file;
        # the 64M container default is too small, so give every worker room.
        run_cmd = ["docker", "run", "-d", "--name", container_name, "--network", "host", "--shm-size=1g",
                   "-v", f"{abs_uploads}:/app/uploads",
                   # Persist the reusable analysis caches across restarts so a
                   # re-run of the same binary skips ghidriff's reference diff and
                   # bind_se's already-recovered signatures.
                   "-v", f"{abs_job_outputs}:/home/bind/Morpheus/job_outputs",
                   "-v", f"{abs_se_sigdb}:/home/bind/Morpheus/signature_matching/signatures/se",
                   "-e", "XBIN_ORCHESTRATOR=localhost:50051", "-e", "REDIS_HOST=localhost", "-e", "PYTHONUNBUFFERED=1"]
        # Forward opt-in worker tunables (e.g. the bind_se fork-guard caps) when set.
        for _var in WORKER_ENV_PASSTHROUGH:
            _val = os.environ.get(_var)
            if _val is not None:
                run_cmd += ["-e", f"{_var}={_val}"]
        run_cmd.append(image_name)
        subprocess.run(run_cmd, check=True, stdout=subprocess.DEVNULL)
    except Exception as e:
        sys_log(f"Fail {name}: {e}"); set_plugin_state(name, category, "ERROR", error=str(e))

def _build_plugin_image(name: str, category: str, image_name: str, p_path: str, p_context: str):
        # Stage the plugin directory and inject the xbin SDK into the build context.
        if p_context != ".":
            with tempfile.TemporaryDirectory() as tmp_dir:
                sys_log(f"Building plugin {category}/{name} in {tmp_dir}")
                # Copy everything from the plugin context into the temp dir
                shutil.copytree(p_context, tmp_dir, dirs_exist_ok=True)
                
                # Inject the SDK from the current xbin project
                sdk_src = os.path.abspath("src")
                if os.path.exists(sdk_src):
                    shutil.copytree(sdk_src, os.path.join(tmp_dir, "src"), dirs_exist_ok=True)
                for f in ["pyproject.toml", "README.md"]:
                    if os.path.exists(f):
                        shutil.copy(f, tmp_dir)
                
                # Build from the temp directory
                dockerfile_path = os.path.join(tmp_dir, "Dockerfile")
                if not os.path.exists(dockerfile_path):
                    raise Exception(f"Dockerfile not found in {p_context}")
                
                subprocess.run(["docker", "build", "--no-cache", "-t", image_name, "-f", dockerfile_path, tmp_dir], check=True, stdout=subprocess.DEVNULL)
        else:
            subprocess.run(["docker", "build", "-t", image_name, "-f", os.path.join(p_path, "Dockerfile"), p_context], check=True, stdout=subprocess.DEVNULL)

@app.post("/api/v1/plugins/{name}/start")
def start_plugin(name: str, category: str, background_tasks: BackgroundTasks):
    background_tasks.add_task(bg_start_plugin, name, category)
    return {"status": "accepted"}

@app.post("/api/v1/plugins/{name}/stop")
def stop_plugin(name: str, category: str):
    container_name = get_container_name(name, category)
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
    set_plugin_state(name, category, "STOPPED")
    return {"status": "success"}

@app.post("/api/v1/shutdown")
def shutdown_backend():
    sys_log("Backend shutdown requested via API.")
    def kill_server():
        time.sleep(1)
        os._exit(0)
    threading.Thread(target=kill_server).start()
    return {"status": "shutting_down"}

@app.get("/api/v1/blackboard/{analysis_type}/audit")
def get_blackboard_audit(analysis_type: str):
    cat = analysis_type.strip(); audit_key = f"xbin:bb_logs:{cat}"; logs = r.lrange(audit_key, 0, -1)
    return {"logs": "\n".join(logs) if logs else "No history recorded yet."}

def _summary_from_explanation(data):
    """Pull a clean one-line summary out of a worker's ollama `explanation`.

    Both fid/ghidriff and bind_se already pipe their result through ollama and
    store a markdown `explanation` beginning with a "Summary of Functionality"
    section. Reuse that (no new LLM call) so the results table shows readable
    text instead of raw SMT2. Falls back to the identity/first line.
    """
    if not isinstance(data, dict):
        return str(data)[:200] if data is not None else ""
    exp = data.get("explanation") or ""
    if exp:
        lines = [ln.strip() for ln in exp.replace("\r", "").split("\n")]
        def _is_header(l):
            s = l.lstrip("#* ").rstrip(":*# ").lower()
            return l.startswith("#") or (l.startswith("**") and l.rstrip().endswith(("**", ":", "  "))) or s in (
                "summary of functionality", "matched known function", "explanation",
                "recovered expression", "rewritten expression", "recovered smt2")
        # collect the block right after the "Summary of Functionality" header
        collected, capturing = [], False
        for ln in lines:
            low = ln.lstrip("#* ").rstrip(":*# ").lower()
            if "summary of functionality" in low:
                capturing = True; continue
            if capturing:
                if not ln:
                    if collected: break
                    continue
                if _is_header(ln):
                    break
                collected.append(ln.lstrip("-* ").strip())
        text = " ".join(collected).strip()
        if not text:  # header not found: first meaningful non-header line
            for ln in lines:
                if ln and not _is_header(ln):
                    text = ln.lstrip("-* ").strip(); break
        text = text.replace("**", "").strip()
        if text:
            if data.get("known_function"):
                return f"{data['known_function']} — {text}"
            return text
    if data.get("known_function"):
        return data["known_function"]
    if data.get("recovered_expression"):
        return "symbolic expression (open Details for the simplified form)"
    return (json.dumps(data)[:80] + "…") if data else ""

def _ollama_chat(prompt, max_tokens=200, timeout=45):
    resp = requests.post(OLLAMA_URL, json={
        "model": OLLAMA_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens, "temperature": 0.1, "stream": False,
    }, timeout=timeout)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()

@app.get("/api/v1/blackboard/{analysis_type}/results")
def get_analysis_results(analysis_type: str):
    keys = r.keys(f"xbin:bb:{analysis_type.strip()}:*")
    results = {}
    for k in keys:
        item = json.loads(r.get(k))
        hyps = item.get("hypotheses") or []
        # Attach a readable one-liner (reuses the worker's ollama explanation, no
        # new LLM call) so the table never shows raw SMT2.
        item["display_summary"] = _summary_from_explanation(hyps[0].get("data")) if hyps else ""
        results[k.split(":")[-1]] = item
    return {"results": results}

@app.get("/api/v1/blackboard/{analysis_type}/{item_key}/summary")
def get_result_summary(analysis_type: str, item_key: str):
    """Pipe the top hypothesis through ollama for a concise result:
    a simplified expression (equation_recovery) or a plain-language description
    of the identified function (signature_matching). Cached per hypothesis id;
    degrades gracefully to the parsed explanation if ollama is unavailable.
    """
    cat = analysis_type.strip()
    state_str = r.get(f"xbin:bb:{cat}:{item_key}")
    if not state_str:
        raise HTTPException(status_code=404)
    state = json.loads(state_str)
    hyps = state.get("hypotheses") or []
    if not hyps:
        return {"summary": ""}
    top = hyps[0]; data = top.get("data") or {}; hyp_id = top.get("id")
    cache_key = f"xbin:summary:{cat}:{item_key}"
    cached = r.get(cache_key)
    if cached:
        c = json.loads(cached)
        if c.get("hyp_id") == hyp_id:
            return {"summary": c["text"], "cached": True}
    if isinstance(data, dict) and data.get("known_function"):
        prompt = (f"In one or two plain sentences, describe what the function "
                  f"'{data['known_function']}' does. No preamble, no code.")
    elif isinstance(data, dict) and data.get("recovered_expression"):
        prompt = ("Rewrite this SMT2 bit-vector expression as a concise, human-readable "
                  "formula (or a one-line plain-English description of what it computes). "
                  "Output ONLY the simplified result, no preamble, no raw SMT2:\n\n"
                  f"{data['recovered_expression']}")
    else:
        return {"summary": _summary_from_explanation(data)}
    try:
        text = _ollama_chat(prompt)
        r.set(cache_key, json.dumps({"hyp_id": hyp_id, "text": text}), ex=86400)
        return {"summary": text, "cached": False}
    except Exception as e:
        return {"summary": _summary_from_explanation(data), "error": str(e)}

@app.get("/api/v1/blackboard/{analysis_type}/{item_key}/consensus")
def get_consensus(analysis_type: str, item_key: str):
    state_str = r.get(f"xbin:bb:{analysis_type.strip()}:{item_key}")
    if not state_str: raise HTTPException(status_code=404)
    state = json.loads(state_str); consensus = {"nodes": {}, "edges": {}}
    for hyp in state["hypotheses"]:
        backend = hyp["backend"]; confidence = hyp.get("raw_conf", 1.0); data = hyp["data"]
        for node in data.get("nodes", []):
            nid = node["id"]
            if nid not in consensus["nodes"]: consensus["nodes"][nid] = {"label": node.get("label", nid), "vouches": []}
            consensus["nodes"][nid]["vouches"].append({"backend": backend, "confidence": confidence})
        for edge in data.get("edges", []):
            eid = f"{edge['source']}->{edge['target']}"
            if eid not in consensus["edges"]: consensus["edges"][eid] = {"source": edge["source"], "target": edge["target"], "vouches": []}
            consensus["edges"][eid]["vouches"].append({"backend": backend, "confidence": confidence})
    return consensus

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>xbin | Visual Analysis Dashboard</title>
        <!-- No external assets: the page must load fully self-contained over plain
             HTTP from a remote browser (the old Cytoscape CDN was unused/dead). -->
        <style>
            :root { --bg: #0b0f1a; --card: #161e2e; --text: #f3f4f6; --accent: #3b82f6; --danger: #ef4444; --success: #10b981; --warning: #f59e0b; --muted: #6b7280; --border: #2d3748; }
            body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); margin: 0; display: flex; flex-direction: column; height: 100vh; overflow: hidden; }
            header { background: var(--card); padding: 1rem 2rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; z-index: 100; box-shadow: 0 4px 12px rgba(0,0,0,0.5); }
            .main-layout { display: grid; grid-template-columns: 340px 1fr; flex: 1; overflow: hidden; }
            .sidebar { border-right: 1px solid var(--border); padding: 1.5rem; overflow-y: auto; background: rgba(22, 30, 46, 0.5); }
            .content { padding: 2rem; overflow-y: auto; position: relative; }
            .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; margin-bottom: 1.5rem; }
            .btn { border: none; padding: 0.5rem 1rem; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 0.8rem; display: flex; align-items: center; gap: 0.5rem; transition: all 0.2s ease; }
            .btn:active { transform: scale(0.92); }
            .btn-primary { background: var(--accent); color: white; }
            .btn-danger { background: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.2); }
            .btn-action { padding: 0.3rem 0.6rem; font-size: 0.7rem; }
            .plugin-item { padding: 1rem; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 0.75rem; background: rgba(0,0,0,0.3); position: relative; overflow: hidden; }
            .heartbeat-ping { position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: var(--success); opacity: 0; pointer-events: none; }
            @keyframes pulse-ping { 0% { opacity: 0; } 10% { opacity: 1; box-shadow: 0 0 15px var(--success); } 100% { opacity: 0; } }
            .ping-active { animation: pulse-ping 1.2s ease-out; }
            .badge { padding: 0.2rem 0.5rem; border-radius: 99px; font-size: 0.6rem; font-weight: 800; text-transform: uppercase; }
            .badge-running { background: rgba(16, 185, 129, 0.1); color: var(--success); }
            .badge-validator { background: rgba(139, 92, 246, 0.1); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.3); }
            .badge-ranker { background: rgba(59, 130, 246, 0.1); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); font-style: italic; }
            .badge-wait { background: rgba(245, 158, 11, 0.1); color: var(--warning); animation: blink 1.5s infinite; }
            @keyframes blink { 50% { opacity: 0.5; } }
            table { width: 100%; border-collapse: collapse; }
            th { text-align: left; padding: 0.8rem; color: var(--muted); font-size: 0.7rem; text-transform: uppercase; border-bottom: 1px solid var(--border); }
            td { padding: 0.8rem; border-bottom: 1px solid var(--border); font-size: 0.85rem; }
            #overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.9); z-index: 900; display: none; backdrop-filter: blur(4px); }
            #modal { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 85vw; height: 80vh; background: var(--card); border: 1px solid var(--accent); border-radius: 16px; padding: 2rem; z-index: 1000; display: none; flex-direction: column; box-shadow: 0 0 40px rgba(0,0,0,0.8); }
            .log-box { flex: 1; background: #070a13; padding: 1.5rem; border-radius: 8px; font-family: monospace; font-size: 0.75rem; color: #cbd5e1; overflow-y: auto; border: 1px solid var(--border); white-space: pre-wrap; }
            #cy-container { flex: 1; background: #070a13; border-radius: 8px; border: 1px solid var(--border); margin-top: 1rem; width: 100%; height: 100%; }
            #mem-map-container { background: #070a13; border-radius: 8px; border: 1px solid var(--border); padding: 1rem; margin-top: 1rem; display: none; overflow-x: auto; white-space: nowrap; height: 120px; position: relative; }
            .mem-block { position: absolute; height: 40px; top: 40px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.1); cursor: pointer; transition: all 0.2s; display: flex; align-items: center; justify-content: center; font-size: 0.6rem; color: white; overflow: hidden; }
            .mem-block:hover { transform: translateY(-5px); box-shadow: 0 5px 15px rgba(59, 130, 246, 0.4); z-index: 10; }
            .mem-label { position: absolute; top: 10px; font-size: 0.6rem; color: var(--muted); border-left: 1px solid var(--border); padding-left: 4px; }
            .toast-container { position: fixed; bottom: 2rem; right: 2rem; z-index: 2000; }
            .toast { background: var(--card); border: 1px solid var(--accent); padding: 1rem; border-radius: 8px; box-shadow: 0 10px 20px rgba(0,0,0,0.5); margin-top: 0.5rem; animation: slideIn 0.3s ease; }
            @keyframes slideIn { from { transform: translateX(100%); } to { transform: translateX(0); } }
            @keyframes logo-ripple { 0% { transform: scale(1); opacity: 0.8; } 100% { transform: scale(2.5); opacity: 0; } }
            .logo-orb { position: relative; width: 30px; height: 30px; }
            .logo-ripple { position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: var(--accent); border-radius: 6px; z-index: 1; animation: logo-ripple 2s infinite; }
            .logo-x { position: relative; z-index: 2; background: var(--accent); width: 30px; height: 30px; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-weight: 900; box-shadow: 0 0 15px rgba(59, 130, 246, 0.5); }
        </style>
    </head>
    <body>
        <header>
            <div style="display: flex; align-items: center; gap: 1rem;">
                <div class="logo-orb"><div class="logo-ripple"></div><div class="logo-x">X</div></div>
                <h1 style="margin: 0; font-size: 1.1rem;">xbin <span style="font-weight: 300; color: var(--muted);">Blackboard</span></h1>
            </div>
            <div style="display: flex; gap: 1rem; align-items: center;">
                <button class="btn" style="background: #2d3748;" onclick="showSystemLogs()">System Logs</button>
                <button class="btn" style="background: #2d3748;" onclick="showWorkerLogs()">Worker Deep Dive</button>
                <button class="btn btn-danger btn-action" onclick="clearSession()">Clear Session</button>
                <button class="btn btn-primary btn-action" onclick="bulkAction('start')">Start Fleet</button>
                <button class="btn btn-danger btn-action" onclick="powerOff()">Power Off</button>
                <div id="orc-health" class="badge badge-running">Orchestrator: OK</div>
            </div>
        </header>
        <div class="main-layout">
            <aside class="sidebar">
                <div class="card">
                    <h2>Deploy Analysis</h2>
                    <input type="file" id="f" style="display:none" onchange="document.getElementById('fl').innerText=this.files[0].name; loadReferences(this.files[0].name)">
                    <button class="btn btn-primary" style="width:100%" onclick="document.getElementById('f').click()">📁 <span id="fl">Choose Binary</span></button>
                    <div style="margin-top:1rem;">
                        <label style="font-size:0.7rem; color:var(--muted); text-transform:uppercase; letter-spacing:0.05em;">Reference Binary <span style="text-transform:none; color:var(--muted)">(server-selected)</span></label>
                        <select id="refsel" onchange="onRefSelChange(this)" style="width:100%; margin-top:0.3rem; padding:0.5rem; background:#0b0f1a; color:var(--text); border:1px solid var(--border); border-radius:8px; font-size:0.8rem;">
                            <option value="">Baked default (arducopter)</option>
                        </select>
                        <input type="file" id="ref" style="display:none" onchange="onCustomRef(this)">
                        <div id="refl" style="font-size:0.62rem; color:var(--muted); margin-top:0.25rem;"></div>
                    </div>
                    <div style="margin-top:1rem; padding-top:1rem; border-top:1px solid var(--border);">
                        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:0.4rem;">
                            <label style="font-size:0.75rem; display:flex; align-items:center; gap:0.3rem;"><input type="checkbox" class="goal" value="signature_matching" checked> Signature Matching</label>
                            <label style="font-size:0.75rem; display:flex; align-items:center; gap:0.3rem;"><input type="checkbox" class="goal" value="equation_recovery" checked> Equation Recovery</label>
                        </div>
                    </div>
                    <button class="btn btn-primary" style="width:100%; margin-top:1rem; background:var(--success)" onclick="upload()">🚀 Start Analysis</button>
                </div>
                <div id="plugin-list"></div>
            </aside>
            <main class="content" id="bb-content"></main>
        </div>
        <div id="overlay" onclick="closeModal()"></div>
        <div id="modal">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
                <h3 id="modal-title" style="margin:0; color:var(--accent);">Result</h3>
                <div id="modal-legend" style="display:flex; gap:1rem; font-size:0.7rem; color:var(--muted);"></div>
                <div style="display:flex; gap:0.5rem;">
                    <button class="btn btn-primary btn-action" onclick="copyLogs()">📋 Copy</button>
                    <button onclick="closeModal()" class="btn btn-danger btn-action">Close</button>
                </div>
            </div>
            <div id="modal-content" class="log-box"></div>
            <div id="cy-container" style="display:none"></div>
            <div id="mem-map-container" style="display:none"></div>
        </div>
        <div class="toast-container" id="toasts"></div>
        <script>
            let lastHeartbeats = {};
            // ---- Live log tail (shared by System Logs + Worker Deep Dive) ----
            let logTimer = null;
            function stopLiveTail() {
                if (logTimer) { clearInterval(logTimer); logTimer = null; }
                const lg = document.getElementById('modal-legend'); if (lg) lg.innerHTML = '';
            }
            // fetchFn: async () => log-text string ; ms: poll cadence
            function startLiveTail(fetchFn, ms) {
                stopLiveTail();
                const el = document.getElementById('modal-content');
                document.getElementById('modal-legend').innerHTML =
                    '<span style="color:var(--success); animation:blink 1.5s infinite;">● LIVE</span>';
                let first = true;
                const tick = async () => {
                    if (document.getElementById('modal').style.display === 'none') { stopLiveTail(); return; }
                    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
                    try { el.innerText = (await fetchFn()) || 'No output yet.'; }   // innerText: no XSS from log bytes
                    catch (e) { el.innerText = 'Error loading logs: ' + e.message; }
                    if (first || nearBottom) el.scrollTop = el.scrollHeight;        // auto-scroll unless user scrolled up
                    first = false;
                };
                tick();
                logTimer = setInterval(tick, ms);
            }
            const CAT_LABELS = { signature_matching: 'Signature Matching', equation_recovery: 'Equation Recovery' };
            function catLabel(c) { return CAT_LABELS[c] || c.replace(/_/g,' '); }
            function toast(m) { const t=document.createElement('div'); t.className='toast'; t.innerText=m; document.getElementById('toasts').appendChild(t); setTimeout(()=>t.remove(),3000); }
            async function loadReferences(target) {
                try {
                    const res = await fetch('/api/v1/references?target=' + encodeURIComponent(target||''));
                    const d = await res.json();
                    const sel = document.getElementById('refsel');
                    let html = '<option value="">Baked default (arducopter)</option>';
                    (d.references||[]).forEach(n => { html += `<option value="${n}">${n}</option>`; });
                    html += '<option value="__custom__">Upload custom file…</option>';
                    sel.innerHTML = html;
                    sel.value = d.suggested || '';
                    document.getElementById('ref').value = '';
                    document.getElementById('refl').innerText = d.suggested ? ('auto-selected: ' + d.suggested) : '';
                } catch(e) {}
            }
            function onRefSelChange(sel) {
                const label = document.getElementById('refl');
                if (sel.value === '__custom__') { document.getElementById('ref').click(); }
                else { document.getElementById('ref').value = ''; label.innerText = sel.value ? ('using: ' + sel.value) : 'using baked default'; }
            }
            function onCustomRef(inp) {
                const label = document.getElementById('refl');
                if (inp.files[0]) { label.innerText = 'custom: ' + inp.files[0].name; }
                else { document.getElementById('refsel').value = ''; label.innerText = 'using baked default'; }
            }
            async function upload() {
                const f = document.getElementById('f').files[0];
                if (!f) { toast('Choose a binary first'); return; }
                const fd=new FormData(); fd.append('file', f);
                const sel = document.getElementById('refsel').value;
                if (sel === '__custom__') {
                    const ref=document.getElementById('ref').files[0];
                    if(ref) fd.append('reference', ref);
                } else if (sel) {
                    fd.append('reference_name', sel);
                }
                const goals=Array.from(document.querySelectorAll('.goal:checked')).map(i=>i.value);
                fd.append('requested_analyses', goals.join(','));
                await fetch('/api/v1/upload', {method:'POST', body:fd}); toast('Binary Announced');
            }
            async function powerOff() {
                if(confirm('Are you sure you want to shut down the xbin orchestrator?')) {
                    toast('Shutting down...');
                    try { await fetch('/api/v1/shutdown', {method:'POST'}); } catch(e) {}
                    setTimeout(() => { document.body.innerHTML = '<div style="display:flex; justify-content:center; align-items:center; height:100vh; font-size:2rem; color:var(--muted);">Backend Offline. You can safely close this tab.</div>'; }, 1000);
                }
            }
            async function clearSession() { if(confirm('Clear all data?')) { await fetch('/api/v1/session/clear', {method:'POST'}); location.reload(); } }
            async function toggle(n,c,s) { const action=s==='RUNNING'?'stop':'start'; await fetch(`/api/v1/plugins/${n}/${action}?category=${c}`, {method:'POST'}); refresh(); }
            async function bulkAction(a, category = null) {
                const res=await fetch('/api/v1/plugins/available'); const data=await res.json();
                const targets = data.plugins.filter(p => {
                    if (category && p.category !== category) return false;
                    if (a === 'start') return !['RUNNING', 'BUILDING', 'STARTING'].includes(p.status);
                    if (a === 'stop') return p.status === 'RUNNING';
                    return false;
                });
                toast(`${a==='start'?'Deploying':'Stopping'} ${targets.length} plugins...`);
                targets.forEach(p => {
                    const url = a === 'start' ? `/api/v1/plugins/${p.name}/start?category=${p.category}` : `/api/v1/plugins/${p.name}/stop?category=${p.category}`;
                    fetch(url, {method:'POST'});
                });
            }
            async function showLogs(n, c="") {
                stopLiveTail();
                document.getElementById('modal-title').innerText=`Logs: ${n}`;
                document.getElementById('cy-container').style.display='none'; document.getElementById('mem-map-container').style.display='none';
                document.getElementById('modal-content').style.display='block'; document.getElementById('overlay').style.display='block'; document.getElementById('modal').style.display='flex';
                const res = await fetch(`/api/v1/plugins/${n}/logs?category=${c}`); const d = await res.json();
                document.getElementById('modal-content').innerText = d.logs || 'No output.';
            }
            function showSystemLogs() {
                document.getElementById('modal-title').innerText='System Logs';
                document.getElementById('cy-container').style.display='none'; document.getElementById('mem-map-container').style.display='none';
                document.getElementById('modal-content').style.display='block';
                document.getElementById('overlay').style.display='block'; document.getElementById('modal').style.display='flex';
                document.getElementById('modal-content').innerText = 'Loading...';
                startLiveTail(async () => {
                    const res = await fetch('/api/v1/system/logs');
                    const d = await res.json();
                    return d.logs;
                }, 2000);
            }
            function showWorkerLogs() {
                document.getElementById('modal-title').innerText='Worker Deep Dive (all containers)';
                document.getElementById('cy-container').style.display='none'; document.getElementById('mem-map-container').style.display='none';
                document.getElementById('modal-content').style.display='block';
                document.getElementById('overlay').style.display='block'; document.getElementById('modal').style.display='flex';
                document.getElementById('modal-content').innerText = 'Loading...';
                startLiveTail(async () => {
                    const res = await fetch('/api/v1/workers/logs?tail=80');
                    const d = await res.json();
                    return d.logs;
                }, 3000);
            }
            function showBlackboardLogs(cat) {
                stopLiveTail();
                document.getElementById('modal-title').innerText=`Audit Trail: ${cat}`;
                document.getElementById('cy-container').style.display='none'; document.getElementById('mem-map-container').style.display='none';
                document.getElementById('modal-legend').innerHTML = ''; document.getElementById('modal-content').style.display='block';
                document.getElementById('overlay').style.display='block'; document.getElementById('modal').style.display='flex';
                fetch(`/api/v1/blackboard/${cat}/audit`).then(r=>r.json()).then(d=>document.getElementById('modal-content').innerText=d.logs || 'No entries.');
            }
            async function showExplanation(cat, item) {
                stopLiveTail();
                document.getElementById('modal-title').innerText = `${catLabel(cat)}: ${item}`;
                document.getElementById('cy-container').style.display='none';
                document.getElementById('mem-map-container').style.display='none';
                document.getElementById('modal-legend').innerHTML = '';
                const content = document.getElementById('modal-content');
                content.style.display='block';
                document.getElementById('overlay').style.display='block';
                document.getElementById('modal').style.display='flex';
                content.innerText = 'Simplifying via ollama…';
                try {
                    const res = await fetch(`/api/v1/blackboard/${cat}/results`);
                    const d = await res.json();
                    const entry = (d.results || {})[item];
                    if (!entry || !entry.hypotheses || !entry.hypotheses.length) { content.innerText = 'No data.'; return; }
                    const lines = [];
                    // Headline: the ollama-simplified result (simpler expression, or a
                    // description for a signature match). Falls back to display_summary.
                    let simplified = entry.display_summary || '';
                    try {
                        const sRes = await fetch(`/api/v1/blackboard/${cat}/${encodeURIComponent(item)}/summary`);
                        const sD = await sRes.json();
                        if (sD.summary) simplified = sD.summary;
                    } catch (e) {}
                    if (simplified) {
                        lines.push('┌─ Simplified (ollama) ' + '─'.repeat(38));
                        lines.push(simplified);
                        lines.push('└' + '─'.repeat(59));
                        lines.push('');
                    }
                    entry.hypotheses.forEach((h, i) => {
                        const data = h.data || {};
                        lines.push('='.repeat(60));
                        lines.push(`#${i+1}  via ${h.backend}   score=${h.score}   raw_conf=${h.raw_conf}`);
                        if ((h.validators||[]).length) lines.push(`vouched by: ${h.validators.join(', ')}`);
                        if (data.known_function) lines.push(`Identity: ${data.known_function}` + (data.confidence!=null?`  (conf ${data.confidence})`:''));
                        if (data.matchers) lines.push(`Matchers: ${(data.matchers||[]).join(', ')}`);
                        if (data.explanation) lines.push(`\nExplanation:\n${data.explanation}`);
                        if (data.recovered_expression) lines.push(`\nRaw SMT2:\n${data.recovered_expression}`);
                        if (data.output_dir) lines.push(`Output: ${data.output_dir}`);
                        lines.push('');
                    });
                    content.innerText = lines.join('\\n');
                } catch (e) { content.innerText = `Error: ${e.message}`; }
            }
            async function showConsensus(cat, item) {
                const modal = document.getElementById('modal'); const overlay = document.getElementById('overlay');
                const title = document.getElementById('modal-title'); const content = document.getElementById('modal-content');
                const cyContainer = document.getElementById('cy-container'); const legend = document.getElementById('modal-legend');
                title.innerText = `Consensus CFG: ${item}`; content.style.display = 'none'; legend.innerHTML = '';
                cyContainer.style.display = 'block'; cyContainer.innerHTML = '<div style="color:var(--muted); padding:2rem;">Initialising engine...</div>';
                overlay.style.display = 'block'; modal.style.display = 'flex';
                try {
                    const res = await fetch(`/api/v1/blackboard/${cat}/${encodeURIComponent(item)}/consensus`);
                    const data = await res.json();
                    if (!data.nodes || Object.keys(data.nodes).length === 0) { cyContainer.innerHTML = '<div style="color:var(--danger); padding:2rem;">No data.</div>'; return; }
                    const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#f97316'];
                    const backendColors = {}; let colorIdx = 0; const elements = [];
                    for(let id in data.nodes) {
                        const node = data.nodes[id];
                        const avgConf = node.vouches.reduce((a, b) => a + (b.confidence || 0), 0) / node.vouches.length;
                        const nodeData = { id: id, label: `${node.label}\\nConf: ${Math.round(avgConf*100)}%`, avgConf: avgConf };
                        node.vouches.forEach((v, i) => {
                            if (!backendColors[v.backend]) backendColors[v.backend] = colors[colorIdx++ % colors.length];
                            if (i < 6) { nodeData[`pie${i+1}val`] = 100 / node.vouches.length; nodeData[`pie${i+1}col`] = backendColors[v.backend]; }
                        });
                        for(let j=node.vouches.length+1; j<=6; j++) { nodeData[`pie${j}val`] = 0; nodeData[`pie${j}col`] = 'transparent'; }
                        elements.push({ data: nodeData });
                    }
                    legend.innerHTML = Object.keys(backendColors).map(b => `<div style="display:flex; align-items:center; gap:0.3rem;"><div style="width:10px; height:10px; border-radius:2px; background:${backendColors[b]}"></div><span>${b}</span></div>`).join('');
                    for(let id in data.edges) {
                        const edge = data.edges[id];
                        const avgConf = edge.vouches.reduce((a, b) => a + (b.confidence || 0), 0) / edge.vouches.length;
                        elements.push({ data: { id: id, source: edge.source, target: edge.target, avgConf: avgConf } });
                    }
                    cyContainer.innerHTML = '';
                    cytoscape({
                        container: cyContainer, elements: elements,
                        style: [
                            { selector: 'node', style: { 'background-color': '#2d3748', 'label': 'data(label)', 'color': '#fff', 'font-size': '8px', 'text-wrap': 'wrap', 'text-valign': 'center', 'width': (n) => 40 + (n.data('avgConf') * 30), 'height': (n) => 40 + (n.data('avgConf') * 30), 'pie-size': '100%', 'pie-1-background-size': 'data(pie1val)', 'pie-1-background-color': 'data(pie1col)', 'pie-2-background-size': 'data(pie2val)', 'pie-2-background-color': 'data(pie2col)', 'pie-3-background-size': 'data(pie3val)', 'pie-3-background-color': 'data(pie3col)', 'pie-4-background-size': 'data(pie4val)', 'pie-4-background-color': 'data(pie4col)', 'pie-5-background-size': 'data(pie5val)', 'pie-5-background-color': 'data(pie5col)', 'pie-6-background-size': 'data(pie6val)', 'pie-6-background-color': 'data(pie6col)' } },
                            { selector: 'edge', style: { 'width': (e) => 1 + (e.data('avgConf') * 6), 'line-color': '#4a5568', 'target-arrow-color': '#4a5568', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'opacity': 0.7 } }
                        ],
                        layout: { name: 'cose', animate: false }
                    });
                } catch (e) { cyContainer.innerHTML = `<div style="color:var(--danger); padding:2rem;">Error: ${e.message}</div>`; }
            }
            function visualizeBoundaries(data) {
                document.getElementById('modal-title').innerText='Function Boundary Map';
                document.getElementById('modal-content').style.display='none'; document.getElementById('cy-container').style.display='none';
                const container = document.getElementById('mem-map-container'); container.style.display = 'block'; container.innerHTML = '';
                document.getElementById('overlay').style.display='block'; document.getElementById('modal').style.display='flex';
                const addresses = Object.keys(data).map(a => parseInt(a, 16)).sort((a,b) => a-b);
                if (addresses.length === 0) return;
                const min = addresses[0]; const max = addresses[addresses.length-1] + (data[hex(addresses[addresses.length-1])].hypotheses[0].data.size || 100);
                const range = max - min; const viewWidth = 1000;
                addresses.forEach(addr => {
                    const func = data[hex(addr)]; const top = func.hypotheses[0]; const meta = top.data;
                    const left = ((addr - min) / range) * viewWidth; const width = (meta.size / range) * viewWidth;
                    const block = document.createElement('div'); block.className = 'mem-block'; block.style.left = `${left}px`; block.style.width = `${Math.max(width, 2)}px`;
                    block.style.background = top.backend.includes('angr') ? '#3b82f6' : '#10b981';
                    block.innerText = meta.name_hint || hex(addr); block.title = `${hex(addr)} - ${meta.end}`;
                    container.appendChild(block);
                    const label = document.createElement('div'); label.className = 'mem-label'; label.style.left = `${left}px`; label.innerText = hex(addr);
                    container.appendChild(label);
                });
            }
            function hex(n) { return '0x' + n.toString(16); }
            function copyLogs() {
                const text = document.getElementById('modal-content').innerText;
                // navigator.clipboard is undefined on non-secure origins (plain HTTP
                // via direct IP), so fall back to a hidden textarea + execCommand.
                if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText(text).then(()=>toast('Copied!'), ()=>fallbackCopy(text));
                } else { fallbackCopy(text); }
            }
            function fallbackCopy(text) {
                const ta = document.createElement('textarea');
                ta.value = text; ta.style.position='fixed'; ta.style.opacity='0';
                document.body.appendChild(ta); ta.focus(); ta.select();
                try { toast(document.execCommand('copy') ? 'Copied!' : 'Copy failed — select manually'); }
                catch(e) { toast('Copy failed — select manually'); }
                document.body.removeChild(ta);
            }
            function closeModal() { stopLiveTail(); document.getElementById('modal').style.display='none'; document.getElementById('overlay').style.display='none'; }
            let collapsedCategories = {};
            function toggleCategory(cat) {
                collapsedCategories[cat] = !collapsedCategories[cat];
                const content = document.getElementById(`cat-content-${cat}`);
                const arrow = document.getElementById(`cat-arrow-${cat}`);
                if (content) content.style.display = collapsedCategories[cat] ? 'none' : 'block';
                if (arrow) arrow.style.transform = collapsedCategories[cat] ? 'rotate(-90deg)' : 'rotate(0deg)';
            }
            
            let isOffline = false;
            async function refresh() {
                try {
                    const pRes = await fetch('/api/v1/plugins/available'); 
                    if (isOffline) {
                        location.reload();
                        return;
                    }
                    const pData = await pRes.json();
                    const pluginList = document.getElementById('plugin-list');
                    const cats = {}; pData.plugins.forEach(p => { if(!cats[p.category]) cats[p.category]=[]; cats[p.category].push(p); });
                    let html = '';
                    for(let cat in cats) {
                        const isCollapsed = collapsedCategories[cat];
                        html += `<div style="display:flex; justify-content:space-between; align-items:center; margin:1.5rem 0 0.5rem; cursor:pointer; user-select:none;" onclick="toggleCategory('${cat}')"><div style="font-size:0.7rem; color:var(--muted); text-transform:uppercase; letter-spacing:0.1em; font-weight:700;"><span id="cat-arrow-${cat}" style="display:inline-block; transition:transform 0.2s; transform:${isCollapsed ? 'rotate(-90deg)' : 'rotate(0deg)'};">&#9660;</span> ${catLabel(cat)}</div><div style="display:flex; gap:0.25rem" onclick="event.stopPropagation()"><button class="btn btn-action" onclick="bulkAction('stop', '${cat}')">Stop</button><button class="btn btn-primary btn-action" onclick="bulkAction('start', '${cat}')">Start</button></div></div>`;
                        html += `<div id="cat-content-${cat}" style="display:${isCollapsed ? 'none' : 'block'};">`;
                        cats[cat].forEach(p => {
                            const isNewBeat = p.last_beat > (lastHeartbeats[p.name] || 0);
                            html += `<div class="plugin-item" id="card-${p.name}"><div id="beat-${p.name}" class="heartbeat-ping ${isNewBeat ? 'ping-active' : ''}"></div><div style="display:flex; justify-content:space-between; align-items:start"><div style="flex:1; min-width:0"><div style="font-weight:bold">${p.display_name || p.name}</div><div style="font-size:0.6rem; color:var(--muted); font-family:monospace">${p.name}</div><div style="display:flex; align-items:center; gap:0.3rem; margin-top:0.2rem; flex-wrap:wrap"><div class="badge badge-${p.status==='RUNNING'?'running':p.status==='STOPPED'?'stopped':'error'}">${p.status}</div>${p.is_validator ? '<div class="badge badge-validator">Validator</div>' : ''}${p.is_ranker ? '<div class="badge badge-ranker" style="font-style:normal;">Ranker</div>' : ''}${p.health==='HEALTHY'?'<span style="color:var(--success); font-size:0.6rem; font-weight:bold">READY</span>':''}</div>${p.description ? '<div style="font-size:0.62rem; color:var(--muted); margin-top:0.35rem; line-height:1.3">'+p.description+'</div>' : ''}</div><div style="display:flex; flex-direction:column; gap:0.2rem"><button class="btn btn-action ${p.status==='RUNNING'?'btn-danger':'btn-primary'}" onclick="toggle('${p.name}','${p.category}','${p.status}')">${p.status==='RUNNING'?'Stop':'Start'}</button><button class="btn btn-action" style="background:#2d3748" onclick="showLogs('${p.name}','${p.category}')">Logs</button></div></div>${p.error ? `<div style="font-size:0.6rem; color:var(--danger); margin-top:0.3rem; border-top:1px solid rgba(239,68,68,0.1); padding-top:0.2rem">${p.error}</div>` : ''}</div>`;
                            if (isNewBeat) lastHeartbeats[p.name] = p.last_beat;
                        });
                        html += `</div>`;
                    }
                    if (pluginList.innerHTML !== html) pluginList.innerHTML = html;
                    const bb = document.getElementById('bb-content');
                    const rankers = pData.rankers || {};
                    const categories = [...new Set([...pData.plugins.map(p => p.category), 'signature_matching', 'equation_recovery'])];
                    for (let cat of categories) {
                        const res = await fetch(`/api/v1/blackboard/${cat}/results`); const d = await res.json();
                        let catId = `bb-section-${cat}`; let section = document.getElementById(catId);
                        if (Object.keys(d.results).length > 0) {
                            if (!section) { section = document.createElement('div'); section.id = catId; section.className = 'card'; bb.appendChild(section); }
                            const rankerName = rankers[cat] || "Baseline";
                            let tableHtml = `<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;"><div><h2 style="display:inline; margin-right:1rem;">${catLabel(cat)}</h2><div class="badge badge-ranker" style="display:inline; vertical-align:middle;">Ranker: ${rankerName}</div></div><div style="display:flex; gap:0.5rem;"><button class="btn btn-action" onclick="showBlackboardLogs('${cat}')">Audit Trail</button></div></div><table><thead><tr><th>Function</th><th>Result</th><th>Detail</th></tr></thead><tbody>`;
                            for(let k in d.results) {
                                const item = d.results[k]; const top = item.hypotheses[0];
                                const validators = top.validators || [];
                                const vCount = validators.length;
                                const data = top.data || {};
                                // Prefer the server-computed readable summary (ollama-derived);
                                // never show raw SMT2 in the results table.
                                let resText = item.display_summary
                                    || ((typeof top.data === 'string') ? top.data
                                        : (data.known_function || JSON.stringify(data).substring(0,40)+'...'));
                                resText = String(resText).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
                                const vList = vCount ? `Vouched by: ${validators.join(', ')}` : 'No validations yet';
                                tableHtml += `<tr class="bb-row"><td><code>${k}</code></td><td style="color:var(--accent); font-weight:500;">${vCount ? '<span style="color:var(--success); margin-right:0.3rem;" title="'+vList+'">✓</span>' : ''}${resText}</td><td><button class="btn btn-primary btn-action" onclick="showExplanation('${cat}','${k}')">Details</button> <span style="font-size:0.6rem; color:var(--muted)">via ${top.backend}${vCount ? ` <span style="color:var(--success); cursor:help;" title="${vList}">+${vCount} vouches</span>` : ''} (Score: ${top.score})</span></td></tr>`;
                            }
                            tableHtml += '</tbody></table>';
                            if (section.innerHTML !== tableHtml) { section.innerHTML = tableHtml; section.style.animation = 'glow-pulse 0.5s ease-out'; }
                        }
                    }
                    const badge = document.getElementById('orc-health');
                    if(badge) { badge.className = 'badge badge-running'; badge.innerText = 'Orchestrator: OK'; }
                } catch(e) {
                    const badge = document.getElementById('orc-health');
                    if(badge) { badge.className = 'badge badge-error'; badge.innerText = 'Backend Offline'; badge.style.background = 'rgba(239, 68, 68, 0.1)'; badge.style.color = 'var(--danger)'; }
                    // If we failed to fetch entirely (e.g. backend dead), show an overlay
                    if(e instanceof TypeError) {
                        isOffline = true;
                        document.body.innerHTML = '<style>@keyframes floatOff { 0% { transform: translateY(0px) rotate(0deg); } 50% { transform: translateY(-15px) rotate(5deg); } 100% { transform: translateY(0px) rotate(0deg); } } @keyframes glowOff { 0% { filter: drop-shadow(0 0 10px rgba(239,68,68,0.2)); } 50% { filter: drop-shadow(0 0 40px rgba(239,68,68,0.7)); } 100% { filter: drop-shadow(0 0 10px rgba(239,68,68,0.2)); } }</style><div style="display:flex; justify-content:center; align-items:center; height:100vh; flex-direction:column; gap:1.5rem; background: radial-gradient(circle at center, #1a0b10 0%, var(--bg) 100%);"><div style="font-size: 7rem; animation: floatOff 4s ease-in-out infinite, glowOff 2s infinite;">🔌</div><div style="font-size:2.5rem; color:var(--danger); font-weight:800; letter-spacing:0.1em; text-transform:uppercase;">Connection Lost</div><div style="font-size:1rem; color:var(--muted); max-width:400px; text-align:center; line-height:1.5;">The xbin Orchestrator has gone offline.<br>Restart the backend process to resume analysis.<br><br><span style="font-size:0.8rem; color:var(--accent); animation: blink 1.5s infinite;">Waiting for connection to return...</span></div></div>';
                    }
                }
            }
            setInterval(refresh, 2000); refresh(); loadReferences('');
        </script>
    </body>
    </html>
    """

# ==========================================
# gRPC BLACKBOARD ENGINE
# ==========================================
class XbinOrchestratorServicer(orchestrator_pb2_grpc.OrchestratorServiceServicer):
    def RegisterWorker(self, request, context):
        r.hset("xbin:active_workers", request.worker_id, f"{request.analysis_type}:{request.backend_name}")
        r.hset("xbin:worker_health", request.worker_id, json.dumps({
            "backend": request.backend_name,
            "last_heartbeat": time.time(),
            "message": "Welcome Signal Received",
            "is_validator": request.is_validator,
            "is_ranker": request.is_ranker,
            "display_name": request.display_name,
            "description": request.description
        }))

        # Persist type status in long-term plugin state
        state_key = f"xbin:plugin_state:{request.analysis_type}:{request.backend_name}"
        state = json.loads(r.get(state_key)) if r.exists(state_key) else {"status": "RUNNING"}
        state["is_validator"] = request.is_validator
        state["is_ranker"] = request.is_ranker
        if request.display_name: state["display_name"] = request.display_name
        if request.description: state["description"] = request.description
        r.set(state_key, json.dumps(state))

        type_str = "[VALIDATOR]" if request.is_validator else "[RANKER]" if request.is_ranker else ""
        sys_log(f"Handshake: {request.worker_id} {type_str}")
        return orchestrator_pb2.RegisterResponse(success=True)

    def Heartbeat(self, request, context):
        worker_info = r.hget("xbin:active_workers", request.worker_id)
        if worker_info:
            r.hset("xbin:worker_health", request.worker_id, json.dumps({"backend": worker_info.split(":")[-1], "last_heartbeat": time.time(), "message": request.status_message}))
        return orchestrator_pb2.HeartbeatResponse(acknowledged=True)

    def PostResult(self, request, context):
        cat = request.analysis_type.strip()
        bb_key = f"xbin:bb:{cat}:{request.item_key}"
        weight = BACKEND_WEIGHTS.get(request.backend_name, 0.50)
        timestamp = time.strftime("%H:%M:%S")
        audit_key = f"xbin:bb_logs:{cat}"
        
        state = json.loads(r.get(bb_key)) if r.exists(bb_key) else {"status": "PENDING", "hypotheses": []}
        
        # 1. Handle Validation (Vouching)
        if request.validation_target_id:
            target_hyp = None
            if request.validation_target_id == "TOP":
                if state["hypotheses"]: target_hyp = state["hypotheses"][0]
            else:
                for hyp in state["hypotheses"]:
                    if hyp.get("id") == request.validation_target_id:
                        target_hyp = hyp
                        break
            
            if target_hyp:
                if request.backend_name not in target_hyp.setdefault("validators", []) and request.backend_name != target_hyp["backend"]:
                    target_hyp["validators"].append(request.backend_name)
                    target_hyp["score"] = round(target_hyp["score"] + (request.confidence * weight), 3)
                    log_entry = f"[{timestamp}] {request.backend_name} VOUCHED for {request.item_key} (ID: {target_hyp.get('id')})"
                    r.lpush(audit_key, log_entry); r.ltrim(audit_key, 0, 4999)
                    sys_log(f"Validation: {request.backend_name} -> {cat}/{request.item_key} (score {target_hyp['score']})")
                new_hyp = target_hyp # For the event broadcast
            else:
                return orchestrator_pb2.PostResultResponse(accepted=False, current_status="TARGET_NOT_FOUND")
        
        # 2. Handle New Data Submission
        else:
            data = json.loads(request.result_data)
            hyp_id = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:12]
            
            # Deduplication: Check if this data already exists as a hypothesis
            existing = next((h for h in state["hypotheses"] if h.get("id") == hyp_id), None)
            if existing:
                if request.backend_name not in existing.setdefault("validators", []) and request.backend_name != existing["backend"]:
                    existing["validators"].append(request.backend_name)
                    existing["score"] = round(existing["score"] + (request.confidence * weight), 3)
                new_hyp = existing
            else:
                new_hyp = {
                    "id": hyp_id,
                    "data": data, 
                    "score": round(request.confidence * weight, 3), 
                    "raw_conf": round(request.confidence, 3),
                    "backend": request.backend_name,
                    "validators": []
                }
                state["hypotheses"].append(new_hyp)
                log_entry = f"[{timestamp}] {request.backend_name} -> {request.item_key} (New Hypothesis)"
                r.lpush(audit_key, log_entry); r.ltrim(audit_key, 0, 4999)
                # Verbose per-function progress into the System Logs stream so the
                # live viewer shows results landing one function at a time.
                _d = data if isinstance(data, dict) else {}
                _summary = (_d.get("known_function") or _d.get("recovered_expression")
                            or (_d.get("explanation", "")[:60]) or "result")
                sys_log(f"Result: {request.backend_name} -> {cat}/{request.item_key} = {_summary} (conf {round(request.confidence, 3)})")

        # Re-sort and determine status
        state["hypotheses"] = sorted(state["hypotheses"], key=lambda x: x["score"], reverse=True)
        status = "RESOLVED"
        if len(state["hypotheses"]) > 1:
            if state["hypotheses"][0]["data"] != state["hypotheses"][1]["data"] and (state["hypotheses"][0]["score"] - state["hypotheses"][1]["score"]) <= MARGIN_THRESHOLD:
                status = "CONFLICTED"
        
        state["status"] = status
        r.set(bb_key, json.dumps(state))
        
        r.publish("xbin:events", json.dumps({
            "type": "BLACKBOARD_UPDATE", 
            "analysis_type": cat, 
            "item_key": request.item_key, 
            "new_hypothesis": new_hyp, 
            "top_hypothesis": state["hypotheses"][0], 
            "status": status
        }))
        return orchestrator_pb2.PostResultResponse(accepted=True, current_status=status)

    def UpdateRank(self, request, context):
        cat = request.analysis_type.strip()
        bb_key = f"xbin:bb:{cat}:{request.item_key}"
        if not r.exists(bb_key):
            return orchestrator_pb2.UpdateRankResponse(accepted=False)
            
        state = json.loads(r.get(bb_key))
        target_hyp = next((h for h in state["hypotheses"] if h.get("id") == request.target_hypothesis_id), None)
        
        if not target_hyp:
            return orchestrator_pb2.UpdateRankResponse(accepted=False)
            
        target_hyp["score"] = round(request.new_score, 3)
        state["hypotheses"] = sorted(state["hypotheses"], key=lambda x: x["score"], reverse=True)
        
        status = "RESOLVED"
        if len(state["hypotheses"]) > 1:
            if state["hypotheses"][0]["data"] != state["hypotheses"][1]["data"] and (state["hypotheses"][0]["score"] - state["hypotheses"][1]["score"]) <= MARGIN_THRESHOLD:
                status = "CONFLICTED"
        
        state["status"] = status
        r.set(bb_key, json.dumps(state))
        
        sys_log(f"Rank Update [{cat}]: {request.item_key} via {request.backend_name}")
        r.publish("xbin:events", json.dumps({
            "type": "BLACKBOARD_UPDATE", 
            "analysis_type": cat, 
            "item_key": request.item_key, 
            "new_hypothesis": target_hyp, 
            "top_hypothesis": state["hypotheses"][0], 
            "status": status,
            "is_rank_update": True
        }))
        return orchestrator_pb2.UpdateRankResponse(accepted=True)

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def main():
    parser = argparse.ArgumentParser(description="xbin Orchestrator")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open the dashboard in a browser.")
    parser.add_argument("--plugin-dir", action="append", default=[], help="Path to an external directory containing custom plugins (can be used multiple times).")
    parser.add_argument("--plugin", action="append", default=[], help="Path to an individual plugin file (.py) or directory (containing a Dockerfile).")
    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    
    global PLUGIN_DIRS, EXPLICIT_PLUGINS
    for pd in args.plugin_dir:
        PLUGIN_DIRS.append(os.path.abspath(pd))
    for p in args.plugin:
        if ":" in p:
            path, category = p.rsplit(":", 1)
        else:
            path = p
            # Infer category from parent directory if not provided
            category = os.path.basename(os.path.dirname(os.path.abspath(path)))
        EXPLICIT_PLUGINS.append((os.path.abspath(path), category))

    ensure_redis(); cleanup_stale_plugins(); r.flushdb()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    orchestrator_pb2_grpc.add_OrchestratorServiceServicer_to_server(XbinOrchestratorServicer(), server)
    server.add_insecure_port(GRPC_PORT); server.start()
    sys_log("xbin Multi-Analysis Engine Online")
    
    # Only open browser if the flag isn't set
    if not args.no_browser:
        def open_browser():
            time.sleep(1) # Give Uvicorn a moment to bind
            print(f"[*] Opening dashboard at http://localhost:{REST_PORT} ...")
            webbrowser.open(f"http://localhost:{REST_PORT}")
            
        threading.Thread(target=open_browser, daemon=True).start()
        
    uvicorn.run(app, host="0.0.0.0", port=REST_PORT, log_level="warning")

if __name__ == '__main__':
    main()
