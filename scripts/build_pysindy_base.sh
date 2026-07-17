#!/usr/bin/env bash
# Build `pysindy:latest` = `bind:latest` + the pysyndy submodule's recovery code
# baked in. Binary Ninja / QEMU / FastDyn / Ghidra / PySR / numpy are reused from
# bind:latest, so this only layers the pysyndy Python tree onto PYTHONPATH -- no
# re-download, no Binary Ninja license needed here (it is already baked into
# bind:latest). The thin plugin plugins/equation_recovery/pysindy/ builds FROM
# this image (in-tree, by the orchestrator).
#
# Prereq: scripts/build_bind_base.sh must have produced bind:latest first.
# Usage:  scripts/build_pysindy_base.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
PYSINDY_DIR="$REPO_ROOT/submodules/pysyndy"
IMAGE="${PYSINDY_IMAGE:-pysindy:latest}"
BASE="${BIND_IMAGE:-bind:latest}"

# --- Ensure base image + submodule are present -----------------------------
docker image inspect "$BASE" >/dev/null 2>&1 || {
  echo "Base image '$BASE' missing -- run scripts/build_bind_base.sh first" >&2; exit 1; }
if [[ ! -d "$PYSINDY_DIR/binja_scripts" ]]; then
  echo "[*] Initializing pysyndy submodule..."
  git -C "$REPO_ROOT" submodule update --init submodules/pysyndy
fi

# --- Keep the (large) staging context off the small root /tmp --------------
export TMPDIR="${TMPDIR:-$REPO_ROOT/.xbin_scratch}"
mkdir -p "$TMPDIR"
BUILD_CTX="$(mktemp -d -t pysindy-build-XXXXXX)"
trap 'rm -rf "$BUILD_CTX"' EXIT

echo "[+] Staging pysyndy code (tracked files at the pinned commit) into $BUILD_CTX"
mkdir "$BUILD_CTX/pysyndy"
# `git archive` emits only tracked files at HEAD (the submodule's pinned commit).
git -C "$PYSINDY_DIR" archive HEAD | tar -x -C "$BUILD_CTX/pysyndy"
# Drop heavy/proprietary blobs the equation-recovery core never needs (firmware
# fixtures, other-lab signatures, IDA/QEMU-corruption experiments). Keeps the
# image lean and avoids baking proprietary firmware into it.
rm -rf "$BUILD_CTX/pysyndy/example_config" \
       "$BUILD_CTX/pysyndy/hitl" \
       "$BUILD_CTX/pysyndy/ida_scripts" \
       "$BUILD_CTX/pysyndy/clibtest" \
       "$BUILD_CTX/pysyndy/qpr8_corrupt" \
       "$BUILD_CTX/pysyndy/signature_matching"

cat > "$BUILD_CTX/Dockerfile" <<EOF
FROM ${BASE}
USER root
COPY --chown=bind:bind pysyndy /home/bind/pysyndy
ENV PYSINDY_ROOT=/home/bind/pysyndy \\
    PYTHONPATH=/home/bind/Morpheus:/home/bind/pysyndy:/home/bind/pysyndy/binja_scripts
# pysyndy's core needs only numpy/BN (both in bind:latest); add a tomli fallback
# for its config parsing on Python < 3.11.
RUN python3 -m pip install --no-cache-dir tomli || true
# pysyndy's automated collection (xbin_api._cfg_for) hard-codes its QEMU/FastDyn
# at <pysyndy>/qemu/build. pysyndy's qemu source is untracked, but bind:latest
# already ships the same BIND QEMU fork + FastDyn plugin (from Morpheus) -- point
# pysyndy's expected paths at those so the dynamic run works without a rebuild.
RUN mkdir -p /home/bind/pysyndy/qemu/build/tests/tcg/plugins && \\
    ln -sf /home/bind/Morpheus/qemu/build/qemu-system-arm \\
           /home/bind/pysyndy/qemu/build/qemu-system-arm && \\
    ln -sf /home/bind/Morpheus/qemu/build/tests/tcg/plugins/libvirtual.so \\
           /home/bind/pysyndy/qemu/build/tests/tcg/plugins/libvirtual.so && \\
    chown -R bind:bind /home/bind/pysyndy/qemu
USER bind
WORKDIR /home/bind/Morpheus
EOF

echo "[+] Building $IMAGE FROM $BASE ..."
docker build -f "$BUILD_CTX/Dockerfile" -t "$IMAGE" "$BUILD_CTX"
echo "[+] Built $IMAGE. The pysindy plugin builds FROM this image."
