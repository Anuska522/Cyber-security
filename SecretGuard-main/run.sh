#!/usr/bin/env bash
# SecretGuard zero-friction launcher for macOS / Linux
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Locate suitable Python 3.11+ interpreter
PYTHON_BIN=""
for cmd in python3.14 python3.13 python3.12 python3.11 python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PY_VER=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)
        MAJOR=$(echo "$PY_VER" | cut -d. -f1)
        MINOR=$(echo "$PY_VER" | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 11 ]; then
            PYTHON_BIN="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "SecretGuard requires Python 3.11 or newer. Please install Python 3.11+." >&2
    exit 1
fi

# 2. Provision virtualenv if missing
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment in .venv..."
    "$PYTHON_BIN" -m venv .venv
fi

# 3. Quietly ensure package and dependencies are installed
if [ ! -f ".venv/bin/secretguard" ]; then
    echo "Provisioning dependencies..."
    .venv/bin/pip install -q --upgrade pip
    .venv/bin/pip install -q -e .
fi

# 4. Launch SecretGuard
exec .venv/bin/secretguard "$@"
