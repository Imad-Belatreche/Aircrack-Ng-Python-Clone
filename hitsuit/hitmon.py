#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import os
import subprocess
import sys
import argcomplete

from pathlib import Path
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
    
from helpers import add_interface_argument

if "_ARGCOMPLETE" not in os.environ:
    from colorama import Fore
    from helpers import check_root, run_command

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

# TODO: Needs a deep test on multiple machines and on vm and on external
# TODO: Make the tool also work for windows


def _get_phy(interface):
    """Get's physical address of given interface (needed for iw command)"""
    stdout, _ = run_command(f"cat /sys/class/net/{interface}/phy80211/name")
    return stdout


def _save_procs(procs: list):
    """Saves killed processes to .bak_proc file"""
    try:
        with open(".bak_proc", "+a") as file:
            file.seek(0)
            saved_procs = [line.strip() for line in file.readlines()]
            for p in procs:
                if p not in saved_procs:
                    file.write(
                        f"{p}\n",
                    )
    except IOError as e:
        print(f"{Fore.RED}Error saving processes: {e}{Fore.RESET}")


def _check_socket(proc):
    """Check if the process have triggering units"""
    out, _ = run_command(f"systemctl status {proc}.socket")
    if out:
        return True
    else:
        return False


def _enable_processes():
    """Re-enables killed processes"""
    try:
        with open(
            ".bak_proc",
            "+r",
        ) as file:
            procs = file.readlines()
            for p in procs:
                proc_name = p.strip()
                if proc_name:
                    print(f"Enabling {proc_name}...")
                    run_command(f"systemctl start {proc_name}")

                    if _check_socket(proc_name):
                        run_command(f"systemctl start {proc_name}.socket")

        os.remove(".bak_proc")

    except FileNotFoundError:
        print(f"{Fore.RED}File doesn't exist !{Fore.RESET}")


def _scan_processes(kill=False):
    """Scans and optionally kills interfering processes with their triggering units automatically"""

    print("Scanning for interfering processes...")
    found_pids = {}

    process_join = " ".join(INTERFERING_PROCESSES)

    ps_out, ps_err = run_command(f'for ps in {process_join}; do pgrep -l "$ps"; done')
    if ps_err:
        print(f"{Fore.RED}Error while scanning processes: {ps_err}{Fore.RED}")
        return 2

    if not ps_out:
        print(f"{Fore.GREEN}No interfering processes found !{Fore.RESET}")
        return 0

    processes = ps_out.strip().split("\n")
    for ps in processes:
        if not ps:
            continue
        ps_id, ps_name = ps.strip().split(" ")
        if ps_name not in found_pids.values():
            found_pids[ps_id] = ps_name

    if not found_pids:
        print(f"{Fore.GREEN}No interfering processes found !{Fore.RESET}")
        return 0

    print(f"{Fore.CYAN}Found {len(found_pids)} processes that could cause trouble.")
    for ps in found_pids:
        print(f"- {ps} : {found_pids[ps]}")

    if not kill:
        print(
            f"{Fore.GREEN}Don't forget to kill them using 'hit-mon proc kill'{Fore.RESET}"
        )
        return 1

    print("\nKilling these processes ...")
    bak_ps = []
    for pid, name in found_pids.items():
        try:
            bak_ps.append(name)
            if _check_socket(name):
                subprocess.run(
                    ["systemctl", "stop", f"{name}.socket"],
                )
            subprocess.run(["systemctl", "stop", name])
            print(f"Killed process: {name}")
        except OSError as e:
            print(f"{Fore.RED}Failed to kill process {name} - {pid}: {e}{Fore.RESET}")

    _save_procs(bak_ps)

    print(f"{Fore.GREEN}\nProcesses killed.{Fore.RESET}")
    return 0


def _start_mon(interface: str, channel: int = None):
    """Starts monitor mode on a given channel"""
    op = _scan_processes(kill=True)
    if op == 2 or op == 1:
        return

    phy = _get_phy(interface)
    if not phy:
        print(f"{Fore.RED}Could not determine phy for {interface}{Fore.RESET}")
        return

    print(f"Starting monitor mode on {interface} [{phy}]")
    _, err = run_command(f"ip link set {interface} down")
    if err:
        print(f"{Fore.RED}Couldn't set interface link to down: {err}{Fore.RESET}")
        return

    # Attempting to create a monitor mode interface
    mon_interface = f"{interface}mon"
    _, err = run_command(f"iw phy {phy} interface add {mon_interface} type monitor")
    if err:
        print(f"{Fore.RED}Could not create {mon_interface}: {err}!\n")

        # If device can't create new interface, change the original interface mode to monitor
        print(f"{Fore.RESET}Attempting to set type on {interface}")
        out, err = run_command(f"iw dev {interface} set type monitor")
        if err:
            print(f"{Fore.RED}Failed to start monitor mode: {err}{Fore.RESET}")
            run_command(f"ip link set {interface} up")
            return
        mon_interface = interface

    # Set the monitor interface to be up (Enabling it)
    out, err = run_command(f"ip link set {mon_interface} up")
    if err:
        print(f"{Fore.RED}Couldn't set {mon_interface} link to up: {err}{Fore.RESET}")

    if channel:
        print(f"Setting channel to {channel}")
        out, err = run_command(f"iw dev {mon_interface} set channel {channel}")
        if err:
            print(f"{Fore.RED}Warning: Failed to set channel: {err}{Fore.RESET}")

    print(f"{Fore.GREEN}Monitor mode enabled on {mon_interface} !{Fore.RESET}")


def _stop_mon(interface: str):
    """This will stop monitor mode, go back to managed mode and re-enable killed processes"""
    phy = _get_phy(interface)

    if not phy:
        print(f"{Fore.RED}Couldn't determine phy for {interface}{Fore.RESET}")
        return

    print(f"{Fore.GREEN}Stopping monitor mode on {interface} [{phy}]{Fore.RESET}")

    run_command(f"ip link set {interface} down")
    if interface.endswith("mon"):
        _, err = run_command(f"iw dev {interface} del")
        if err:
            print(f"{Fore.RED}Failed to delete interface {interface}: {err}")
            return
        org_interface = interface[:-3]
        if org_interface:
            print(f"{Fore.GREEN}Bringing {org_interface} back to up state{Fore.RESET}")
            run_command(f"ip link set {org_interface} up")
    else:
        print(f"{Fore.GREEN}Bringing {interface} back to up state{Fore.RESET}")
        _, err = run_command(f"iw dev {interface} set type managed")
        if err:
            print(
                f"{Fore.RED}Failed to set interface back to managed mode: {err}{Fore.RESET}"
            )
            return
        run_command(f"ip link set {interface} up")

    _enable_processes()

    print(f"{Fore.GREEN}Monitor mode stopped !{Fore.RESET}")


def main():
    """Main function"""
    art = r"""
 /$$       /$$   /$$                                      
| $$      |__/  | $$                                      
| $$$$$$$  /$$ /$$$$$$   /$$$$$$/$$$$   /$$$$$$  /$$$$$$$ 
| $$__  $$| $$|_  $$_/  | $$_  $$_  $$ /$$__  $$| $$__  $$
| $$  \ $$| $$  | $$    | $$ \ $$ \ $$| $$  \ $$| $$  \ $$
| $$  | $$| $$  | $$ /$$| $$ | $$ | $$| $$  | $$| $$  | $$
| $$  | $$| $$  |  $$$$/| $$ | $$ | $$|  $$$$$$/| $$  | $$
|__/  |__/|__/   \___/  |__/ |__/ |__/ \______/ |__/  |__/
"""
    parser = argparse.ArgumentParser(
        prog="hitmon",
        description=art
        + "\n\nEnables monitor mode on wireless interfaces, kill network managers or to go from monitor to managed mode",
        epilog="@By NS-Guys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparser = parser.add_subparsers(dest="command", help="")
    subparser.required = True
    commands = [
        ("proc", "Show interfering proccesses"),
        ("start", "Enable monitor mode on given interface"),
        ("stop", "Stop monitor mode and back to managed mode"),
    ]
    for name, help in commands:
        # proc argument
        command_parser = subparser.add_parser(name=name, help=help, description=help)
        if name == "proc":
            proc_subparsers = command_parser.add_subparsers(
                dest="action", help="Available actions"
            )
            proc_subparsers.required = False
            proc_action = [
                ("kill", "Kill interfering processes"),
                ("enable", "Enable interfering processes"),
            ]
            for name, help in proc_action:
                proc_subparsers.add_parser(name=name, help=help, description=help)

        if name == "start":
            # start argument
            add_interface_argument(command_parser)
            command_parser.add_argument(
                "channel", nargs="?", help="Optional channel to set the nic"
            )
        if name == "stop":
            # stop argument
            add_interface_argument(command_parser)

    argcomplete.autocomplete(parser)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    check_root()
    if args.command == "proc":
        if args.action == "kill":
            _scan_processes(kill=True)
        elif args.action == "enable":
            _enable_processes()
        else:
            _scan_processes(kill=False)

        return
    elif args.command == "start":
        if args.channel:
            chan = int(args.channel)
            if chan <= 14 and chan > 0:
                _start_mon(interface=args.interface, channel=args.channel)
            else:
                print(
                    f"{Fore.RED}You have entered an invalid channel value, it must be between 1-14{Fore.RESET}"
                )
                sys.exit(1)
        else:
            _start_mon(interface=args.interface)

    elif args.command == "stop":
        _stop_mon(interface=args.interface)


if __name__ == "__main__":
    main()
