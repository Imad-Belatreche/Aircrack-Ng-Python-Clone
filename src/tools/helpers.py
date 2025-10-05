import os
import subprocess
import sys

from colorama import Fore


def run_command(command, check=False):
    """Runs a command and return it's output"""
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, check=check
        )
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.CalledProcessError as e:
        return e.stdout.strip(), e.stderr.strip()
    except FileNotFoundError:
        return "", f"{Fore.RED}Command not found: {command.split()[0]}{Fore.RESET}"


def check_root():
    """Basically checks if the script did run as a root"""
    if os.getuid() != 0:
        print(f"{Fore.RED}Run it as root !{Fore.RESET}")
        sys.exit(1)
