#!/usr/bin/env bash
# Rebuild the `bind:latest` base image, adding the QEMU/FastDyn dynamic-analysis
# stack that `symbolic_regression` needs (the previous image was built without
# it). This is a guard + verify wrapper around scripts/build_bind_base.sh:
#
#   1. If the current bind:latest already has QEMU, do nothing (idempotent).
#   2. Otherwise KILL the outdated running instance -- any container still on the
#      old bind:latest (e.g. the leftover `bind_corrupt` scratch container), all
#      xbin-worker-* containers, and the stale xbin-plugin-* thin-layer images --
#      so nothing keeps running the outdated code and the old layers can be freed.
#   3. Rebuild via build_bind_base.sh (sources the Morpheus submodule, which must
#      be populated on `integration`; the Dockerfile clones+builds the QEMU fork).
#   4. Prune the now-dangling old base and VERIFY qemu-system-arm + libvirtual.so
#      are present in the new image (fail loudly otherwise).
#
# Usage: scripts/rebuild_bind_base.sh [--force]
#   --force  rebuild even if the current image already has QEMU.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
IMAGE="${BIND_IMAGE:-bind:latest}"

QEMU_BIN="/home/bind/Morpheus/qemu/build/qemu-system-arm"
FASTDYN_SO="/home/bind/Morpheus/qemu/build/tests/tcg/plugins/libvirtual.so"

FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

# --- has_qemu <image> : does the image already contain the QEMU stack? --------
has_qemu() {
  docker run --rm --entrypoint /bin/bash "$1" -lc \
    "test -f '$QEMU_BIN' && test -f '$FASTDYN_SO'" >/dev/null 2>&1
}

echo "[*] rebuild_bind_base: target image = $IMAGE"

if [[ "$FORCE" -eq 0 ]] && docker image inspect "$IMAGE" >/dev/null 2>&1 && has_qemu "$IMAGE"; then
  echo "[=] $IMAGE already contains QEMU ($QEMU_BIN). Nothing to do."
  echo "    (pass --force to rebuild anyway.)"
  exit 0
fi

# --- 2. Kill the outdated running instance -----------------------------------
echo "[!] $IMAGE is missing QEMU (or --force). Removing the outdated running instance..."

# Any orchestrator running against the old image/plugins.
if pgrep -f 'xbin_orchestrator.main' >/dev/null 2>&1; then
  echo "    - stopping running orchestrator (xbin_orchestrator.main)"
  pkill -f 'xbin_orchestrator.main' || true
fi

# Containers built FROM / running the current bind:latest (e.g. bind_corrupt).
OLD_CONTAINERS="$(docker ps -aq --filter "ancestor=$IMAGE" 2>/dev/null || true)"
if [[ -n "$OLD_CONTAINERS" ]]; then
  echo "    - removing containers on $IMAGE:"
  docker ps -a --filter "ancestor=$IMAGE" --format '        {{.Names}} ({{.Status}})' || true
  docker rm -f $OLD_CONTAINERS >/dev/null 2>&1 || true
fi

# Any xbin plugin worker containers (mirrors cleanup_stale_plugins in main.py).
WORKERS="$(docker ps -aq --filter 'name=xbin-worker-' 2>/dev/null || true)"
if [[ -n "$WORKERS" ]]; then
  echo "    - removing xbin-worker-* containers"
  docker rm -f $WORKERS >/dev/null 2>&1 || true
fi

# Stale thin-layer plugin images so they rebuild FROM the new base next start.
PLUGIN_IMAGES="$(docker images -q 'xbin-plugin-*' 2>/dev/null || true)"
if [[ -n "$PLUGIN_IMAGES" ]]; then
  echo "    - removing stale xbin-plugin-* images"
  docker rmi -f $PLUGIN_IMAGES >/dev/null 2>&1 || true
fi

# --- 3. Rebuild via the canonical builder ------------------------------------
echo "[+] Rebuilding $IMAGE via scripts/build_bind_base.sh (heavy: Ghidra + Binary Ninja + QEMU + PySR)..."
"$HERE/build_bind_base.sh"

# --- 4. Prune dangling old base + verify QEMU landed -------------------------
echo "[+] Pruning dangling images..."
docker image prune -f >/dev/null 2>&1 || true

echo "[*] Verifying QEMU/FastDyn in the new $IMAGE..."
if has_qemu "$IMAGE"; then
  echo "[+] OK: $QEMU_BIN and $FASTDYN_SO are present in $IMAGE."
  docker run --rm --entrypoint /bin/bash "$IMAGE" -lc "'$QEMU_BIN' --version | head -1" || true
  echo "[+] Rebuild complete. The five plugins build FROM $IMAGE (--no-cache) on next start."
else
  echo "[x] FAILED: $IMAGE still lacks $QEMU_BIN after rebuild." >&2
  echo "    Check the Dockerfile QEMU steps (git clone tonitick/qemu; make qemu-system-arm; make test-plugins)." >&2
  exit 1
fi
