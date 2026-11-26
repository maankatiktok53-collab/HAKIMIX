#!/usr/bin/env bash
# HAKIMIX bash launcher: checks Python, dependencies, permissions, then starts hakimix.py.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON="${PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "[!] Python not found: $PYTHON" >&2
    exit 1
fi

if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)'; then
    echo "[!] Python 3.8 or newer is required" >&2
    exit 1
fi

for required in hakimix.py config.json core/utils.py core/paths.py; do
    if [[ ! -f "$required" ]]; then
        echo "[!] missing required file: $required" >&2
        exit 1
    fi
    if [[ ! -r "$required" ]]; then
        echo "[!] unreadable required file: $required" >&2
        exit 1
    fi
done

if ! "$PYTHON" -m py_compile hakimix.py core/*.py 2>/dev/null; then
    echo "[!] dependency check failed: Python sources do not compile" >&2
    exit 1
fi

if [[ ! -w "$SCRIPT_DIR" ]]; then
    echo "[!] project directory is not writable: $SCRIPT_DIR" >&2
    exit 1
fi

mkdir -p output

if [[ "${HAKIMIX_SKIP_TOOLCHECK:-0}" != "1" ]]; then
    "$PYTHON" hakimix.py --check-tools || true
fi

exec "$PYTHON" hakimix.py "$@"
