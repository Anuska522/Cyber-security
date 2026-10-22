#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/SecretGuard-main/run.sh" ]]; then
    exec "$SCRIPT_DIR/SecretGuard-main/run.sh" "$@"
fi

exec python3 "$SCRIPT_DIR/run.py" "$@"
