#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run this script with sudo."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="/usr/local/bin"

echo "Removing All hitsuit utilities from the system"
shopt -s nullglob
for target in "$DEST_DIR"/hit*; do
    if [[ -L "$target" ]]; then
        real_path="$(realpath "$target")"
        if [[ "$real_path" == "$SCRIPT_DIR"/hitsuit/hit*.py ]]; then
            rm -f "$target"
        fi
    fi
done
shopt -u nullglob

echo "All hitsuit are removed"
