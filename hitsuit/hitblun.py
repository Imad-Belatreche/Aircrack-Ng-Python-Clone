import argparse
import re
import subprocess
import sys
from colorama import Fore

from helpers import check_root, run_command


def strip_ansi_codes(text):
    ansi_esc = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_esc.sub("", text)


def scan_devices(scan_time=5):
    """Start scanning for new bluetooth devices"""
    print(f"{Fore.CYAN}[*] Searching devices for {scan_time} seconds...{Fore.RESET}")
    command = (
        f"(echo 'scan on'; sleep {scan_time}; echo 'scan off'; exit) | bluetoothctl"
    )
    out, err = run_command(command)
    clean_err = strip_ansi_codes(err)
    clean_out = strip_ansi_codes(out)

    if clean_err:
        if "No default controller available" in clean_err:
            print(f"{Fore.RED}Error: No Bluetooth controller found.{Fore.RESET}")
            print(
                f"{Fore.YELLOW}Hint: Try turning on your Bluetooth adapter with 'bluetoothctl power on'.{Fore.RESET}"
            )
            return
        else:
            print(f"{Fore.RED}An error occurred during scan: {clean_err}{Fore.RESET}")

    device_pattern = re.compile(
        r"\[NEW\] Device ((?:[0-9A-F]{2}:){5}[0-9A-F]{2}) ([^\n\r]+)"
    )

    devices = dict(device_pattern.findall(clean_out))
    if not devices:
        print(f"{Fore.YELLOW}No new devices found.{Fore.RESET}")
        return

    print(f"\n{Fore.GREEN}[+] Found {len(devices)} unique devices:{Fore.RESET}")
    for mac, name in devices.items():
        print(f"  - MAC: {mac}\n    Name: {name}")


def start_sniffing(interface="hci0"):
    """Start sniffing on a given bluetooth interface (btmon)"""
    print(
        f"{Fore.CYAN}[*] Sniffing on {interface}... Hit Ctrl + C to stop.{Fore.RESET}"
    )
    try:
        process = subprocess.Popen(
            ["btmon", "-i", interface],
            stdout=sys.stdout,
            stderr=sys.stderr,
            text=True,
        )
    except FileNotFoundError:
        print(
            f"{Fore.RED}Error: 'btmon' command not found. Please be sure to install it !"
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.GREEN}[+] Sniffinf stopped.{Fore.RESET}")
    finally:
        if "process" in locals() and process.poll() is None:
            process.terminate()

if __name__ == "__main__":
    check_root()
    parser = argparse.ArgumentParser("hitblun", description="A simple tool that scans for bluetooth devices, captures and analyzes communication,")
scan_devices(140)
