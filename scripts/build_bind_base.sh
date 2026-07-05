#!/usr/bin/env bash
# Build the self-contained `bind:latest` base image from the Morpheus submodule.
#
# This is what makes the repo self-contained: instead of the old external
# `pysyndy` image, the four xbin analysis plugins (fid, ghidriff, bind_se,
# symbolic_regression) build FROM `bind:latest`, which is produced here directly
# from submodules/Morpheus/docker/Dockerfile.
#
# We deliberately do NOT use submodules/Morpheus/docker/build_docker.sh -- it is
# stale (references a non-existent Dockerfile.bind and reads a gemini.key). We
# also do NOT pass a Gemini key: xbin uses a local ollama for all LLM steps.
#
# Usage:
#   scripts/build_bind_base.sh [<binaryninja-dir-or-zip>] [<license.dat>]
#
# Missing args fall back to scripts/build.conf. The Binary Ninja install and
# license are baked into the image, so keep the resulting image local -- do not
# push it.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
MORPHEUS_DIR="$REPO_ROOT/submodules/Morpheus"
DOCKER_DIR="$MORPHEUS_DIR/docker"
DOCKERFILE="$DOCKER_DIR/Dockerfile"
IMAGE="${BIND_IMAGE:-bind:latest}"

conf() {  # read a "label: value" line from build.conf (quotes/space trimmed, ~ expanded)
  local v
  v="$(sed -n "s/^[[:space:]]*$1[[:space:]]*:[[:space:]]*//p" "$HERE/build.conf" 2>/dev/null \
        | head -n1 | sed -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/")"
  printf '%s' "${v/#\~/$HOME}"
}

BINJA_DIR="${1:-$(conf 'binja dir')}"
LICENSE="${2:-$(conf 'license path')}"

# --- Ensure the submodule is present and on the integration branch ----------
if [[ ! -f "$DOCKERFILE" ]]; then
  echo "[*] Initializing Morpheus submodule..."
  git -C "$REPO_ROOT" submodule update --init --recursive submodules/Morpheus
fi
CUR_BRANCH="$(git -C "$MORPHEUS_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo DETACHED)"
if [[ "$CUR_BRANCH" != "integration" ]]; then
  echo "[!] Morpheus is on '$CUR_BRANCH'; checking out 'integration' (xbin always uses integration)."
  git -C "$MORPHEUS_DIR" fetch origin integration --quiet || true
  git -C "$MORPHEUS_DIR" checkout integration
fi

# --- Validate inputs --------------------------------------------------------
[[ -n "$BINJA_DIR" && -e "$BINJA_DIR" ]] || { echo "Binary Ninja install not found: '$BINJA_DIR' (set it in scripts/build.conf or pass as arg 1)" >&2; exit 1; }
[[ -n "$LICENSE"   && -f "$LICENSE"   ]] || { echo "license.dat not found: '$LICENSE' (set it in scripts/build.conf or pass as arg 2)" >&2; exit 1; }

# --- Stage the build context (Dockerfile COPYs Morpheus/, binaryninja/, license.dat) ---
BUILD_CTX="$(mktemp -d -t bind-build-XXXXXX)"
trap 'rm -rf "$BUILD_CTX"' EXIT

echo "[+] Staging build context at $BUILD_CTX"
cp "$DOCKERFILE" "$BUILD_CTX/Dockerfile"

if [[ "$BINJA_DIR" == *.zip ]]; then
  echo "[+] Unzipping Binary Ninja..."
  unzip -q "$BINJA_DIR" -d "$BUILD_CTX"
  [[ -d "$BUILD_CTX/binaryninja" ]] || { echo "Expected 'binaryninja/' at the top level of the zip" >&2; exit 1; }
else
  cp -a "$BINJA_DIR" "$BUILD_CTX/binaryninja"
fi
cp "$LICENSE" "$BUILD_CTX/license.dat"

# Copy the Morpheus tree without the heavy/regenerated bits the image rebuilds.
mkdir "$BUILD_CTX/Morpheus"
tar -C "$MORPHEUS_DIR" \
    --exclude='./.git' \
    --exclude='./qemu' \
    --exclude='./ghidra_*' \
    --exclude='./.claude' \
    --exclude='./docker/binaryninja' \
    --exclude='./docker/license.dat' \
    -cf - . | tar -C "$BUILD_CTX/Morpheus" -xf -

# --- Build (no Gemini key: ollama-only) -------------------------------------
echo "[+] Building $IMAGE (this is heavy: Binary Ninja + Ghidra + QEMU + PySR)..."
docker build --build-arg GEMINI_API_KEY="" -f "$BUILD_CTX/Dockerfile" -t "$IMAGE" "$BUILD_CTX"
echo "[+] Built $IMAGE. The four Morpheus plugins build FROM this image."
