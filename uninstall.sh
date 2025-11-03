#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run this script with sudo."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="/usr/local/bin"
VENV_DIR="$SCRIPT_DIR/.venv"

remove_completions() {
    if [[ -z "${SUDO_USER:-}" || "${SUDO_USER}" == "root" ]]; then
        echo "Skipping completion removal (no sudo user detected)."
        return
    fi

    local user_entry user_shell user_home shell_name
    user_entry="$(getent passwd "$SUDO_USER" || true)"
    user_shell="$(echo "$user_entry" | cut -d: -f7)"
    user_home="$(echo "$user_entry" | cut -d: -f6)"

    if [[ -z "$user_shell" || -z "$user_home" ]]; then
        echo "Could not determine user shell or home; skipping completion removal."
        return
    fi

    shell_name="$(basename "$user_shell")"

    case "$shell_name" in
        bash|zsh)
            echo "Note: Global bash/zsh argcomplete registrations may need manual removal."
            ;;
        fish)
            local comp_dir="$user_home/.config/fish/completions"
            for script in "$SCRIPT_DIR/hitsuit"/hit*.py; do
                local base_name="$(basename "$script" .py)"
                local completion_file="$comp_dir/${base_name}.fish"
                if [[ -f "$completion_file" ]]; then
                    sudo -u "$SUDO_USER" rm -f "$completion_file"
                    echo "Removed fish completion: $completion_file"
                fi
            done
            ;;
        pwsh|powershell)
            local module_dir="$user_home/.config/powershell/completions"
            local profile_file="$user_home/.config/powershell/Microsoft.PowerShell_profile.ps1"
            for script in "$SCRIPT_DIR/hitsuit"/hit*.py; do
                local base_name="$(basename "$script" .py)"
                local module_file="$module_dir/${base_name}.psm1"
                
                # Remove the module file
                if [[ -f "$module_file" ]]; then
                    sudo -u "$SUDO_USER" rm -f "$module_file"
                    echo "Removed PowerShell module: $module_file"
                fi
                
                # Remove import line from profile
                if [[ -f "$profile_file" ]]; then
                    local import_line="Import-Module \"${module_file}\""
                    sudo -u "$SUDO_USER" sed -i "\|^${import_line}$|d" "$profile_file" 2>/dev/null || true
                fi
            done
            # Clean up empty directories
            if [[ -d "$module_dir" ]] && [[ -z "$(ls -A "$module_dir")" ]]; then
                sudo -u "$SUDO_USER" rmdir "$module_dir" 2>/dev/null || true
            fi
            ;;
        *)
            echo "Shell '$shell_name' completions may need manual removal."
            ;;
    esac
}

echo "Removing hitsuit utilities from the system..."

# Remove wrapper scripts from /usr/local/bin
shopt -s nullglob
for script in "$SCRIPT_DIR/hitsuit"/hit*.py; do
    base_name="$(basename "$script" .py)"
    wrapper_script="$DEST_DIR/$base_name"
    
    if [[ -f "$wrapper_script" ]]; then
        # Check if it's our wrapper script by checking the content
        if grep -q "$VENV_DIR/bin/python" "$wrapper_script" 2>/dev/null || 
           grep -q "$SCRIPT_DIR" "$wrapper_script" 2>/dev/null; then
            rm -f "$wrapper_script"
            echo "Removed wrapper script: $wrapper_script"
        fi
    fi
done
shopt -u nullglob

# Remove completions
remove_completions

# Remove virtual environment
if [[ -d "$VENV_DIR" ]]; then
    echo "Removing virtual environment..."
    rm -rf "$VENV_DIR"
fi

echo "All hitsuit utilities have been removed"