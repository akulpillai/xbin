#!/usr/bin/env bash
# Stage test firmware into uploads/ for end-to-end runs.
#
# Default: COPY (not symlink) the on-repo gs3.bin (2MB ArduPilot single-image
# Cortex-M) into uploads/gs3.bin. A copy is required, not a symlink: uploads/ is
# bind-mounted into each worker container, and an external symlink would dangle
# inside the container. (A symlink is only OK as a `curl -F file=@...` source.)
#
# gs3.bin is all a smoke test needs -- the symbolized reference and FID db are
# baked into bind:latest, so no reference upload is required.
#
# Usage:
#   scripts/fetch_test_binaries.sh                 # stage gs3.bin
#   scripts/fetch_test_binaries.sh --selfmatch     # also stage the arducopter ELF as a self-match target
#   scripts/fetch_test_binaries.sh --announce signature_matching   # also print the ready curl command
#   scripts/fetch_test_binaries.sh --apj <file|url>   # (advanced) extract a matched CubeOrange image from an ArduPilot .apj
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
UPLOADS="$REPO_ROOT/uploads"
mkdir -p "$UPLOADS"

# Source paths (env-overridable). Prefer the in-repo submodule copy.
GS3_SRC="${GS3_SRC:-$REPO_ROOT/submodules/Morpheus/example_config/gs3.bin}"
[[ -f "$GS3_SRC" ]] || GS3_SRC="/evaldisk/akul/integration/Morpheus/example_config/gs3.bin"
ARDU_ELF_SRC="${ARDU_ELF_SRC:-$REPO_ROOT/submodules/Morpheus/signature_matching/signatures/arducopter_cubeorange_default}"
[[ -f "$ARDU_ELF_SRC" ]] || ARDU_ELF_SRC="/evaldisk/akul/integration/Morpheus/signature_matching/signatures/arducopter_cubeorange_default"

SELFMATCH=0
ANNOUNCE=""
APJ=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --selfmatch) SELFMATCH=1; shift ;;
    --announce) ANNOUNCE="${2:-signature_matching}"; shift 2 ;;
    --apj) APJ="${2:?--apj needs a file or URL}"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

stage() {  # stage <src> <dest-name>
  local src="$1" dest="$UPLOADS/$2"
  [[ -f "$src" ]] || { echo "[x] source not found: $src" >&2; return 1; }
  if [[ -f "$dest" ]] && cmp -s "$src" "$dest"; then
    echo "[=] $2 already staged ($(du -h "$dest" | cut -f1))"
  else
    cp -f "$src" "$dest"
    echo "[+] staged $2 <- $src ($(du -h "$dest" | cut -f1))"
  fi
}

stage "$GS3_SRC" gs3.bin

if [[ "$SELFMATCH" -eq 1 ]]; then
  # Strong-signal target: ghidriff diffs this symbolized ELF against the
  # identical baked reference -> near-perfect name recovery.
  stage "$ARDU_ELF_SRC" arducopter_cubeorange_default
fi

if [[ -n "$APJ" ]]; then
  # ArduPilot .apj is JSON with a base64+gzip "image" field. Morpheus has NO
  # .apj support, so extract the raw image and stage that as a .bin target.
  echo "[*] extracting raw image from .apj: $APJ"
  TMP_APJ="$APJ"
  if [[ "$APJ" == http*://* ]]; then
    TMP_APJ="$(mktemp --suffix=.apj)"
    curl -fsSL "$APJ" -o "$TMP_APJ"
  fi
  python3 - "$TMP_APJ" "$UPLOADS/arducopter_from_apj.bin" <<'PY'
import base64, gzip, json, sys
apj, out = sys.argv[1], sys.argv[2]
d = json.load(open(apj))
img = gzip.decompress(base64.b64decode(d["image"]))
open(out, "wb").write(img)
print(f"[+] wrote {out} ({len(img)} bytes)")
PY
fi

echo
echo "Staged files in $UPLOADS:"
ls -la "$UPLOADS" | grep -vE '^\.|\.gitkeep' | tail -n +2 || true

if [[ -n "$ANNOUNCE" ]]; then
  echo
  echo "To announce for analysis (server-side, no laptop copy needed):"
  echo "  curl -F file=@uploads/gs3.bin -F requested_analyses=$ANNOUNCE http://localhost:8000/api/v1/upload"
fi
