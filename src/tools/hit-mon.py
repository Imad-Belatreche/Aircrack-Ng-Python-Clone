import argparse
from ast import arg
import os
import signal
import subprocess
import sys

from colorama import Fore

# All processes that may interfer with the monitor mode (Directly from airmon-ng code)
INTERFERING_PROCESSES = [
    "wpa_supplicant",
    "wpa_action",
    "wpa_cli",
    "dhclient",
    "ifplugd",
    "dhcdbd",
    "dhcpcd",
    "udhcpc",
    "NetworkManager",
    "knetworkmanager",
    "avahi-autoipd",
    "avahi-daemon",
    "wlassistant",
    "wifibox",
    "net_applet",
    "wicd-daemon",
    "wicd-client",
    "iwd",
    "hostapd",
]


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


def save_procs(procs):
    try:
        file = open(".bak_proc", "+x")
        file.write(procs)
        file.close()
    except FileExistsError:
        print(f"{Fore.RED}File already exists !{Fore.RESET}")


def check_root():
    """Basically checks if the script did run as a root"""
    if os.getuid() != 0:
        print(f"{Fore.RED}Run it as root !{Fore.RESET}")
        sys.exit(1)


        
    

def scan_processes(kill=False):
    """Scans and optionally kills interfering processes automatically"""

    print("Scanning for interfering processes...")
    found_pids = {}

    process_regex = "|".join(INTERFERING_PROCESSES)

    ps_out, ps_err = run_command(
        f"ps -A -o pid,comm | grep -E '{process_regex}' | grep -v grep"
    )
    if ps_err:
        print(f"{Fore.RED}Error while scanning processes: {ps_err}{Fore.RED}")
        return

    if not ps_out:
        print(f"{Fore.GREEN}No interfering processes found !{Fore.RESET}")
        return

    processes = ps_out.strip().split("\n")
    for ps in processes:
        if not ps:
            continue
        ps_id, ps_name = ps.strip().split(" ")
        found_pids[ps_id] = ps_name

    if not found_pids:
        print(f"{Fore.GREEN}No interfering processes found !{Fore.RESET}")
        return

    print(f"{Fore.CYAN}Found {len(found_pids)} processes that could cause trouble.")
    for ps in found_pids:
        print(f"- {ps} : {found_pids[ps]}")

    if not kill:
        print(
            f"{Fore.GREEN}Aight, don't forget to kill them using 'hit-mon proc kill'{Fore.RESET}"
        )
        return

    check_root()
    print("\nKilling these processes ...")
    bak_ps = []
    for pid, name in found_pids.items:
        try:
            bak_ps.append(name)
            os.kill(pid, signal.SIGKILL)
            print(f"Killed PID {pid}")
        except OSError as e:
            print(f"{Fore.RED}Failed to kill PID {pid}: {e}{Fore.RESET}")

    save_procs(bak_ps)

    print(f"{Fore.GREEN}\nProcesses killed.{Fore.RESET}")


def main():
    parser = argparse.ArgumentParser(
        prog="Hitmon",
        description="Enables monitor mode on wireless interfaces, kill network managers or to go from monitor to managed mode",
        epilog="By NS-Guys",
    )
    subparser = parser.add_subparsers(dest="command", help="")

    # proc argument
    proc_parser = subparser.add_parser(name="proc", help="Show interfering proccesses")
    proc_parser.add_argument("kill", nargs="?", help="Kill interfering proccesses")
    proc_parser.add_argument("enable", nargs="?", help="Enable interfering proccesses")

    # start argument
    start_parser = subparser.add_parser(
        name="start", help="Enable monitor mode on given interface"
    )
    start_parser.add_argument("interface", help="Wireless interface")
    start_parser.add_argument(
        "channel", nargs="?", help="Optional channel to set the nic"
    )

    # stop argument
    stop_parser = subparser.add_parser(name="stop", help="Go back to managed mode")
    stop_parser.add_argument("interface", help="Wireless interface in monitor mode")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "proc":
        if args.kill == "kill":
            scan_processes(kill=True)
        elif args.enable == "enable":
            
        elif args.kill is None or args.enable is None:
            scan_processes(kill=False)
        else:
            proc_parser.print_help()


if __name__ == "__main__":
    main()
