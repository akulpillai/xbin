"""Helpers shared by the four Morpheus/BIND xbin plugins.

These run *inside* the ``bind:latest`` image (built from the Morpheus submodule
via ``scripts/build_bind_base.sh``), where the Morpheus tree is on PYTHONPATH and
``bind_se`` is installed. Every Morpheus import is deferred into a function so
this module imports fine anywhere -- e.g. when the orchestrator statically scans
plugin source, or on a dev box without the heavy stack.

The four analysis tools map onto two xbin blackboard categories (tools that
answer the same question compete, like angr+radare both posting a CFG):

* ``signature_matching``  -- "what known function is this": fid, ghidriff
  (and bind_se's identity matches).
* ``equation_recovery``   -- "what does it compute": bind_se (angr symex + LLM),
  symbolic_regression (PySR + LLM).
"""

import os
import re
import tempfile

# xbin blackboard categories for the BIND tools.
CAT_SIGNATURE = "signature_matching"
CAT_EQUATION = "equation_recovery"

# In-image absolute paths (baked by submodules/Morpheus/docker/Dockerfile).
MORPHEUS_ROOT = os.environ.get("MORPHEUS_ROOT", "/home/bind/Morpheus")
_QEMU = os.path.join(MORPHEUS_ROOT, "qemu", "build", "qemu-system-arm")
_FASTDYN = os.path.join(MORPHEUS_ROOT, "qemu", "build", "tests", "tcg", "plugins", "libvirtual.so")


def sibling(binary_path, suffix):
    """Return ``<binary-stem><suffix>`` next to the uploaded binary if it exists.

    Mirrors the iopairs upload convention: optional reference files are uploaded
    alongside the target and picked up here.
    """
    cand = os.path.splitext(binary_path)[0] + suffix
    return cand if os.path.exists(cand) else None


def _toml_val(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_toml_val(x) for x in v) + "]"
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _write_overrides(base_toml, overrides):
    """Copy the baked bind_config.toml, replacing (or appending) the given keys.

    Line-based so we never produce duplicate keys (which tomllib rejects) and we
    preserve every other setting / comment verbatim. Returns a temp file path.
    """
    with open(base_toml) as f:
        lines = f.readlines()
    remaining = dict(overrides)
    out = []
    for line in lines:
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if m and m.group(1) in remaining:
            key = m.group(1)
            out.append(f"{key} = {_toml_val(remaining.pop(key))}\n")
        else:
            out.append(line)
    for key, val in remaining.items():
        out.append(f"{key} = {_toml_val(val)}\n")
    fd, path = tempfile.mkstemp(suffix=".toml", prefix="bind_cfg_")
    with os.fdopen(fd, "w") as f:
        f.writelines(out)
    return path


def prepare_config(binary_path, extra=None):
    """Build a per-run bind config for the uploaded binary.

    Returns ``(config_dict, config_path)``. ``config_path`` is a temp TOML file
    (needed by the symbolic_regression subprocess, which re-reads the config);
    ``config_dict`` is what the warm-worker clients consume directly.

    Optional sibling uploads override the baked reference set:
      ``<stem>.reference`` -> ``signature_match_binary`` (symbolized reference)
      ``<stem>.fidb``      -> ``fid_db_paths``           (prebuilt FID database)
    """
    from bind_jobs.util import load_bind_config, import_bind

    bind = import_bind()
    base_toml = os.path.join(MORPHEUS_ROOT, bind.DEFAULT_CONFIG_PATH)

    overrides = {
        "firmware_bin_path": os.path.abspath(binary_path),
        # Point at the qemu/FastDyn built inside the image (under Morpheus/qemu),
        # overriding the repo-relative defaults in bind_config.toml.
        "qemu_path": _QEMU,
        "fastdyn_plugin_path": _FASTDYN,
    }
    ref = sibling(binary_path, ".reference")
    if ref:
        overrides["signature_match_binary"] = ref
    fidb = sibling(binary_path, ".fidb")
    if fidb:
        overrides["fid_db_paths"] = [fidb]
    if extra:
        overrides.update(extra)

    cfg_path = _write_overrides(base_toml, overrides)
    return load_bind_config(cfg_path), cfg_path


def function_universe(config_path):
    """BN ∩ Ghidra function addresses (as ``norm_addr`` strings) for the target.

    This is the same universe the Morpheus job server hands out; every tool posts
    hypotheses keyed by these addresses so their results line up on the board.
    """
    from bind_integration import get_func_intersection
    from bind_jobs.util import norm_addr

    return [norm_addr(a) for a in get_func_intersection(config_path)]
