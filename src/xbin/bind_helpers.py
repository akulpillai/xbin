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


def elf_to_firmware(binary_path):
    """If ``binary_path`` is an ELF, derive the raw Cortex-M flash image Morpheus
    expects, plus its VTOR and setup_end. Returns ``(raw_bin_path, vtor, setup_end)``
    or ``(None, None, None)`` when the input is not an ELF (already a raw ``.bin``)
    or conversion fails.

    fid/ghidriff/bind_se/symbolic_regression all load the firmware as a *raw* image
    mapped at the VTOR (``list_binja_functions``/Ghidra/QEMU), and ``find_vtor`` reads
    the file's reset vector -- both assume a raw ``.bin``. An ELF upload (e.g.
    ``sample.axf``) breaks them (``detect_vtor`` sees the ``\\x7fELF`` magic). We
    objcopy-equivalent the ELF to its raw flash image (placing each PT_LOAD by its
    physical address, i.e. LMA), and read VTOR (= lowest LMA) and setup_end (= the
    ``main`` symbol) straight from the ELF so ``detect_vtor``/boot-trace never run on
    a non-raw input. pysyndy/pysindy still consume the ELF directly via xbin_api.
    """
    try:
        with open(binary_path, "rb") as f:
            if f.read(4) != b"\x7fELF":
                return None, None, None
    except OSError:
        return None, None, None
    try:
        from elftools.elf.elffile import ELFFile

        raw_path = os.path.abspath(binary_path) + ".fw.bin"
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            loads = [s for s in elf.iter_segments()
                     if s["p_type"] == "PT_LOAD" and s["p_filesz"] > 0]
            if not loads:
                return None, None, None
            base = min(s["p_paddr"] for s in loads)
            # Keep only the flash region contiguous with the vector table; drop
            # far segments (e.g. a RAM-LMA .data at 0x2000_0000) that would
            # otherwise inflate the raw image to hundreds of MB.
            _FLASH_SPAN = 16 * 1024 * 1024
            loads = [s for s in loads if 0 <= s["p_paddr"] - base < _FLASH_SPAN]
            end = max(s["p_paddr"] + s["p_filesz"] for s in loads)
            if end - base > 128 * 1024 * 1024:  # sanity backstop
                return None, None, None
            img = bytearray(end - base)  # gaps zero-filled, like objcopy -O binary
            for s in loads:
                data = s.data()
                off = s["p_paddr"] - base
                img[off:off + len(data)] = data
            setup_end = None
            func_addrs = set()
            symtab = elf.get_section_by_name(".symtab")
            if symtab is not None:
                for sym in symtab.iter_symbols():
                    if sym.name == "main" and setup_end is None:
                        setup_end = int(sym["st_value"]) & ~1  # drop the Thumb bit
                    if sym["st_info"]["type"] == "STT_FUNC":
                        a = int(sym["st_value"]) & ~1
                        if base <= a < end:
                            func_addrs.add(a)
        with open(raw_path, "wb") as f:
            f.write(img)
        # Authoritative function list from the ELF's symbol table. The raw-blob
        # BN∩Ghidra intersection drops symbol-less leaf functions (on sample.axf it
        # returned the 4 reset-reachable functions and missed every FP leaf), so
        # function_universe() prefers this list when present.
        if func_addrs:
            with open(raw_path + ".funcs", "w") as f:
                f.write("\n".join(f"0x{a:08x}" for a in sorted(func_addrs)) + "\n")
        # Cache the setup-end (main) as the sidecar Morpheus's find_setup_end reads.
        # symbolic_regression's get_setup_end() only honors this sidecar or a live
        # QEMU boot-trace (it ignores firmware_setup_end_addr in the config), and the
        # boot-trace's "confident boot stall" heuristic fails on many images -- so
        # seeding it from the ELF's `main` lets SR skip the boot-trace entirely.
        if setup_end is not None:
            with open(raw_path + ".setup_end", "w") as f:
                f.write(f"{setup_end:#x}\n")
        return raw_path, base, setup_end
    except Exception as e:  # never let conversion break the run -- fall back to raw
        print(f"[bind_helpers] ELF->raw firmware conversion failed for "
              f"{binary_path}: {e!r}")
        return None, None, None


def prepare_config(binary_path, extra=None):
    """Build a per-run bind config for the uploaded binary.

    Returns ``(config_dict, config_path)``. ``config_path`` is a temp TOML file
    (needed by the symbolic_regression subprocess, which re-reads the config);
    ``config_dict`` is what the warm-worker clients consume directly.

    Optional sibling uploads override the baked reference set:
      ``<stem>.reference`` -> ``signature_match_binary`` (symbolized reference)
      ``<stem>.fidb``      -> ``fid_db_paths``           (prebuilt FID database)

    ELF uploads are converted to the raw Cortex-M flash image Morpheus's tools
    expect (see ``elf_to_firmware``); a raw ``.bin`` is used as-is.
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
    # An ELF upload (e.g. sample.axf) isn't a raw Cortex-M image: convert it and
    # pin the VTOR/setup_end so detect_vtor / boot-trace don't run on a non-raw file.
    raw_bin, vtor, setup_end = elf_to_firmware(binary_path)
    if raw_bin:
        overrides["firmware_bin_path"] = raw_bin
        overrides["firmware_vtor_table_addr"] = f"0x{vtor:08x}"
        if setup_end is not None:
            overrides["firmware_setup_end_addr"] = f"0x{setup_end:08x}"
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
    from bind_jobs.util import norm_addr

    # Prefer the ELF-derived authoritative function list (written by
    # elf_to_firmware next to the raw image) when the upload was an ELF: the
    # raw-blob BN∩Ghidra intersection misses symbol-less leaf functions, so
    # SR/bind_se would otherwise see none of the FP leaves pysindy recovers.
    try:
        from bind_jobs.util import load_bind_config
        cfg = load_bind_config(config_path)
        fw = cfg.get("firmware_bin_path") if hasattr(cfg, "get") else None
        if fw and os.path.exists(fw + ".funcs"):
            addrs = [ln.strip() for ln in open(fw + ".funcs") if ln.strip()]
            if addrs:
                return addrs
    except Exception as e:
        print(f"[bind_helpers] .funcs universe unavailable ({e!r}); using BN∩Ghidra")

    from bind_integration import get_func_intersection
    return [norm_addr(a) for a in get_func_intersection(config_path)]
