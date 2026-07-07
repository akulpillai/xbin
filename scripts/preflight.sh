#!/usr/bin/env bash
# Thin wrapper so CI/humans can run preflight without knowing the interpreter.
# Prefers the project .venv (so the python-deps check reflects the real env);
# falls back to a bare python3 (preflight.py is stdlib-only and works there too).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$HERE/../.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
exec "$PY" "$HERE/preflight.py" "$@"
