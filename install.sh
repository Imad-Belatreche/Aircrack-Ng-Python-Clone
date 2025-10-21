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
commands_list=()

setup_completions() {
    if [[ -z "${SUDO_USER:-}" || "${SUDO_USER}" == "root" ]]; then
        echo "Skipping completion setup (no sudo user detected)."
        return
    fi

    local user_entry user_shell user_home shell_name
    user_entry="$(getent passwd "$SUDO_USER" || true)"
    user_shell="$(echo "$user_entry" | cut -d: -f7)"
    user_home="$(echo "$user_entry" | cut -d: -f6)"

    if [[ -z "$user_shell" || -z "$user_home" ]]; then
        echo "Could not determine user shell or home; skipping completion setup."
        return
    fi

    shell_name="$(basename "$user_shell")"

    case "$shell_name" in
        bash|zsh)
            if command -v activate-global-python-argcomplete >/dev/null 2>&1; then
                echo "Registering global argcomplete for bash/zsh..."
                activate-global-python-argcomplete
            else
                echo "Registering global argcomplete for bash/zsh..."
                "$PYTHON_BIN" -m argcomplete.scripts.activate_global_python_argcomplete
            fi
            ;;
        fish)
            if ! command -v register-python-argcomplete >/dev/null 2>&1; then
                echo "register-python-argcomplete not found; fish completions not configured."
                return
            fi
            local comp_dir="$user_home/.config/fish/completions"
            sudo -u "$SUDO_USER" mkdir -p "$comp_dir"
            for command in "${commands_list[@]}"; do
                local completion_file="$comp_dir/${command}.fish"
                sudo -u "$SUDO_USER" register-python-argcomplete --shell fish "$command" \
                    | sudo -u "$SUDO_USER" tee "$completion_file" >/dev/null
            done
            echo "Registering autocomplete for fish..."

            ;;
        pwsh|powershell)
            if ! command -v register-python-argcomplete >/dev/null 2>&1; then
                echo "register-python-argcomplete not found; PowerShell completions not configured."
                return
            fi
            local module_dir="$user_home/.config/powershell/completions"
            sudo -u "$SUDO_USER" mkdir -p "$module_dir"
            local profile_file="$user_home/.config/powershell/Microsoft.PowerShell_profile.ps1"
            sudo -u "$SUDO_USER" mkdir -p "$(dirname "$profile_file")"
            sudo -u "$SUDO_USER" touch "$profile_file"
            for command in "${commands_list[@]}"; do
                local module_file="$module_dir/${command}.psm1"
                sudo -u "$SUDO_USER" register-python-argcomplete --shell powershell "$command" \
                    | sudo -u "$SUDO_USER" tee "$module_file" >/dev/null
                local import_line="Import-Module \"${module_file}\""
                if ! sudo -u "$SUDO_USER" grep -Fq "$import_line" "$profile_file"; then
                    printf '\n%s\n' "$import_line" | sudo -u "$SUDO_USER" tee -a "$profile_file" >/dev/null
                fi
            done
            echo "Registering autocomplete for powershell..."

            ;;
        *)
            echo "Shell '$shell_name' not automatically supported; configure completions manually."
            ;;
    esac
}

echo "Installing Python dependencies..."
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    sudo -u "${SUDO_USER}" -H "$PYTHON_BIN" -m pip install --user -r "$REQUIREMENTS_FILE"
else
    "$PYTHON_BIN" -m pip install -r "$REQUIREMENTS_FILE"
fi
shopt -s nullglob
for script in "$HITSUITE_DIR"/hit*.py; do
    base_name="$(basename "$script" .py)"
    commands_list+=("$base_name")
    echo "Preparing $base_name..."
    chmod +x "$script"
    ln -sf "$script" "$DEST_DIR/$base_name"
    chmod +x "$DEST_DIR/$base_name"
done
shopt -u nullglob

setup_completions
echo "Installation complete."