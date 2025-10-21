#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run this script with sudo."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
DEST_DIR="/usr/local/bin"
REQUIREMENTS_FILE="$SCRIPT_DIR/requirements.txt"
HITSUITE_DIR="$SCRIPT_DIR/hitsuit"

echo "Installing Python dependencies..."
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    sudo -u "${SUDO_USER}" -H "$PYTHON_BIN" -m pip install --user -r "$REQUIREMENTS_FILE"
else
    "$PYTHON_BIN" -m pip install -r "$REQUIREMENTS_FILE"
fi
shopt -s nullglob
for script in "$HITSUITE_DIR"/hit*.py; do
    base_name="$(basename "$script" .py)"
    echo "Preparing $base_name..."
    chmod +x "$script"
    ln -sf "$script" "$DEST_DIR/$base_name"
    chmod +x "$DEST_DIR/$base_name"
done
shopt -u nullglob

echo "Installation complete."