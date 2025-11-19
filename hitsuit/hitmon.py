#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
from tempfile import NamedTemporaryFile
import time
import argcomplete
from argcomplete.completers import ChoicesCompleter

from pathlib import Path

from regex import S

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from helpers import (
    Interface_State,
    add_interface_argument,
    check_monitor,
    get_phy,
)

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

FILE_PATH = f"{SCRIPT_DIR}/../.bak_proc.csv"
FILE_FIELDS = ["name", "new_status", "old_status", "socket"]

# TODO: Needs a deep test on multiple machines and on vm and on external
# TODO: Make the tool also work for windows
# TODO: Confirm the new process saving method to csv file
# TODO: Move constants to a new constant file
# TODO: Fix the issue where all the vinterfaces got deleted when monitoring on one and attacking on another one


def _get_state(interface):
    out, err = run_command(
        f"ip link show {interface} | awk '/state/ {{for (i=0;i<=NF;i++) if ($i == \"state\") print $(i+1)}}'"
    )
    if err:
        print(f"{Fore.RED}Couldn't determin the interface state !: {err}")
        return
    return out


def _get_interfaces():
    interfaces = os.listdir("/sys/class/net")
    return interfaces


def _get_channel(interface):
    try:
        out, err = run_command(
            f"iw dev {interface} info | grep channel | awk '{{print $2}}'"
        )
        if out:
            channel = int(str(out))
        else:
            channel = 6

        if err:
            print(
                f"{Fore.RED}Wasn't able to get the interface channel ! (Defaulting to 6)"
            )
            channel = 6

    except Exception as e:
        print(f"{Fore.RED}Error getting the channel: {e}")
        channel = 6
    return channel


def _delete_vinterface(vinterface):
    try:
        _, err = run_command(f"iw dev {vinterface} del")
        if err:
            raise Exception(err)
    except Exception as e:
        print(
            f"{Fore.RED}An error occured while deleting virtual interface {vinterface}: {e}"
        )


def _create_init_proc_file(filepath):
    """Creates and populate the target file with interfering processes

    Args:
        filepath (string): Path of the file
    """
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            count = sum(1 for line in f)
            print(count)
        if os.path.getsize(filepath) > 400 and count >= 20:
            print(f"{Fore.RED}File '{filepath}' already exists")
            return
    try:
        with open(filepath, "w") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=FILE_FIELDS, delimiter="|")
            writer.writeheader()
            for proc in INTERFERING_PROCESSES:
                data = {
                    "name": proc,
                    "new_status": False,
                    "old_status": False,
                    "socket": False,
                }
                writer.writerow(data)

            print(f"{Fore.GREEN}File created and populated with processes")
            time.sleep(1)

    except IOError as e:
        print(
            f"{Fore.RED}Error creating and saving processes to {filepath}: {e}{Fore.RESET}"
        )


def _check_socket(proc):
    """Check if the process have triggering units"""
    out, _ = run_command(f"systemctl status {proc}.socket")
    if out:
        return True
    else:
        return False


def _save_procs(procs_list: list, set_status_to: bool):
    """Saves killed processes to .bak_proc file"""
    if not procs_list:
        print("No list")
        return

    if not os.path.exists(FILE_PATH):
        print("No path")
        _create_init_proc_file(FILE_PATH)

    tempfile = NamedTemporaryFile(mode="w", delete=False)
    updated_procs = []
    try:
        with open(FILE_PATH, "r+") as csvfile, tempfile:
            reader = csv.DictReader(csvfile, FILE_FIELDS, delimiter="|")
            writer = csv.DictWriter(tempfile, FILE_FIELDS, delimiter="|")

            for row in reader:
                if row["name"] in procs_list:
                    row["old_status"] = row["new_status"]
                    row["new_status"] = set_status_to
                    row["socket"] = str(_check_socket(row["name"]))
                    updated_procs.append(row["name"])

                writer.writerow(row)
        shutil.move(tempfile.name, FILE_PATH)
        if updated_procs:
            status_text = "stopped" if set_status_to else "enabled"
            print(
                f"{Fore.GREEN}Updated status to {status_text} for: {', '.join(updated_procs)}{Fore.RESET}"
            )

    except IOError as e:
        print(f"{Fore.RED}Error saving processes: {e}{Fore.RESET}")
    finally:
        if os.path.exists(tempfile.name):
            os.remove(tempfile.name)


def _enable_processes():
    """Re-enables killed processes"""
    if not os.path.exists(FILE_PATH):
        print(
            f"{Fore.RED}File '{FILE_PATH}' doesn't exist! Cannot enable processes.{Fore.RESET}"
        )
        return

    procs_to_enable = []
    units_to_manage = []

    try:
        with open(FILE_PATH, "r") as csvfile:
            reader = csv.DictReader(csvfile, fieldnames=FILE_FIELDS, delimiter="|")
            for row in reader:
                if row["new_status"] == "True" or row["old_status"] == "True":
                    proc_name = row["name"]
                    procs_to_enable.append(proc_name)
                    units_to_manage.append(f"{proc_name}.service")

                    if row["socket"] == "True":
                        units_to_manage.append(f"{proc_name}.socket")

        if not units_to_manage:
            print(f"{Fore.YELLOW}No processes to re-enable.{Fore.RESET}")
            return

        units_str = " ".join(units_to_manage)
        print(f"Unmasking and starting: {units_str}")
        run_command(f"systemctl unmask {units_str}")
        run_command(f"systemctl start {units_str}")

        _save_procs(procs_to_enable, set_status_to=False)
        print(f"{Fore.GREEN}Processes re-enabled successfully.{Fore.RESET}")

    except (IOError, csv.Error) as e:
        print(f"{Fore.RED}Error reading {FILE_PATH}: {e}{Fore.RESET}")


def _scan_processes(kill=False, verbose=True):
    """Scans and optionally kills interfering processes with their triggering units automatically"""
    if verbose:
        print("Scanning for interfering processes...")
    found_pids = {}

    process_join = " ".join(INTERFERING_PROCESSES)

    ps_out, ps_err = run_command(f'for ps in {process_join}; do pgrep -x "$ps"; done')
    if ps_err:
        print(f"{Fore.RED}Error while scanning processes: {ps_err}{Fore.RED}")
        return 2

    if not ps_out:
        if verbose:
            print(f"{Fore.GREEN}No interfering processes found !{Fore.RESET}")
        return 0

    pids = ps_out.strip().split("\n")
    for pid in pids:
        if not pid:
            continue

        pid = pid.strip()
        name_out, _ = run_command(f"ps -p {pid} -o comm=")
        name = name_out.strip()

        if name and pid not in found_pids:
            found_pids[pid] = name

    if not found_pids:
        if verbose:
            print(f"{Fore.GREEN}No interfering processes found !{Fore.RESET}")
        return 0
    if verbose:
        print(f"{Fore.CYAN}Found {len(found_pids)} processes that could cause trouble.")
        for pid in found_pids:
            print(f"- {pid} : {found_pids[pid]}")

    if not kill:
        if verbose:
            print(
                f"{Fore.GREEN}Don't forget to kill them using 'hit-mon proc kill'{Fore.RESET}"
            )
        return 1
    if verbose:
        print("\nKilling these processes ...")

    process_names = list(found_pids.values())
    units_to_stop = []
    for name in process_names:
        units_to_stop.append(f"{name}.service")
        if _check_socket(name):
            units_to_stop.append(f"{name}.socket")

    units_str = " ".join(units_to_stop)
    try:
        run_command(f"systemctl mask {units_str}")
        run_command(f"systemctl stop {units_str}")

        print(f"Killed processess: {units_str}")
    except OSError as e:
        print(f"{Fore.RED}Failed to kill processes `{units_str}`: {e}{Fore.RESET}")

    _save_procs(process_names, set_status_to=True)
    if verbose:
        print(f"{Fore.GREEN}\nProcesses killed.{Fore.RESET}")
    return 0


def _start_mon(interface: str, channel: int = None):
    """Starts monitor mode on a given channel"""

    ret = _scan_processes(kill=True)
    if ret == 2 or ret == 1:
        return

    phy = get_phy(interface)
    if not phy:
        print(f"{Fore.RED}Could not determine phy for {interface}{Fore.RESET}")
        return

    # Get the original interface channel
    if channel is None:
        channel = _get_channel(interface)

    print(f"Starting monitor mode on {interface} [{phy}]")
    int_state = _get_state(interface)
    if int_state in (Interface_State[0], Interface_State[2]):
        _, err = run_command(f"ip link set {interface} down")
        if err:
            print(f"{Fore.RED}Couldn't set interface link to down: {err}{Fore.RESET}")
            return

    # Attempting to create a monitor mode interface
    mon_interface = f"{interface}mon"
    interfaces = _get_interfaces()
    while mon_interface in interfaces:
        num = re.search(r"\d*$", mon_interface).group(0)
        if not num:
            num = 0
        new_interface = re.sub(r"\d*$", "", mon_interface)
        mon_interface = new_interface + str(int(num) + 1)

    _, err = run_command(f"iw phy {phy} interface add {mon_interface} type monitor")
    if err:
        print(f"{Fore.RED}Could not create {mon_interface}: {err}!\n")

        # If device can't create new interface, change the original interface mode to monitor
        print(f"{Fore.RESET}Attempting to set monitor mode on {interface}")

        _, err = run_command(f"iw dev {interface} set type monitor")
        if err:
            print(f"{Fore.RED}Failed to start monitor mode: {err}{Fore.RESET}")
            run_command(f"ip link set {interface} up")
            _enable_processes()
            return

        mon_interface = interface

    # Set the monitor interface to be up (Enabling it)
    _, err = run_command(f"ip link set {mon_interface} up")
    if err:
        print(f"{Fore.RED}Couldn't set {mon_interface} link to up: {err}{Fore.RESET}")
        run_command(f"iw dev {mon_interface} del")
        run_command(f"ip link set {interface} up")
        _enable_processes()

    if channel:
        print(f"Setting channel to {channel}")
        _, err = run_command(f"iw dev {mon_interface} set channel {channel}")
        if err:
            print(f"{Fore.RED}Warning ! Failed to set channel: {err}{Fore.RESET}")

    print(f"{Fore.GREEN}Monitor mode enabled on {mon_interface} !{Fore.RESET}")


def _stop_mon(interface: str, verbose=True):
    """This will stop monitor mode, go back to managed mode and re-enable killed processes"""
    phy = get_phy(interface)

    if not phy:
        print(f"{Fore.RED}Couldn't determine phy for {interface}{Fore.RESET}")
        return
    if verbose:
        print(f"{Fore.GREEN}Stopping monitor mode on {interface} [{phy}]{Fore.RESET}")

    run_command(f"ip link set {interface} down")
    exist = re.search(r"mon\d*$", interface)
    if exist:
        _delete_vinterface(interface)
        org_interface = re.sub(r"mon\d*$", "", interface)
        if org_interface:
            if verbose:
                print(
                    f"{Fore.GREEN}Bringing {org_interface} back to up state{Fore.RESET}"
                )
            _, err = run_command(f"ip link set {org_interface} up")
            if err:
                print(
                    f"{Fore.RED}Warning! Was not able to bring original interface to up state command `ip link set {org_interface} up` failed !"
                )
                return
    else:
        if verbose:
            print(f"{Fore.GREEN}Bringing {interface} back to up state{Fore.RESET}")
        _, err = run_command(f"iw dev {interface} set type managed")
        if err:
            print(
                f"{Fore.RED}Failed to set interface back to managed mode: {err}{Fore.RESET}"
            )

        _, err = run_command(f"ip link set {interface} up")
        if err:
            print(
                f"{Fore.RED}Warning! Was not able to bring original interface to up state command `ip link set {org_interface} up` failed !"
            )
    _enable_processes()

    print(f"{Fore.GREEN}Monitor mode stopped on {interface}!{Fore.RESET}")


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
    subparser = parser.add_subparsers(dest="command", help="", required=True)
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
            ).completer = ChoicesCompleter(map(str, range(1, 15)))
        if name == "stop":
            # stop argument
            add_interface_argument(command_parser)
            command_parser.add_argument(
                "-a",
                "--all",
                action="store_true",
                help="Stop monitor mode and delete all created interfaces",
            )
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
        is_monitor, _ = check_monitor(args.interface)
        if is_monitor:
            print(f"{Fore.RED}Interface already in monitor mode !")
            sys.exit(0)

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
        if args.all:
            if _get_state(args.interface) == Interface_State[0]:
                is_monitor, _ = check_monitor(args.interface)
                if not is_monitor:
                    print(f"{Fore.RED}Interface is not in monitor mode!")
                    sys.exit(0)

            print(f"{Fore.GREEN}Deleting all virtual interfaces of {args.interface}")
            counter = 0
            interfaces = _get_interfaces()
            for inter in interfaces:
                found_inter = re.search("mon", inter)
                if found_inter:
                    is_monitor, _ = check_monitor(inter)
                    if not is_monitor:
                        print(f"{Fore.RED}Interface {inter} is not in monitor mode!")
                        continue
                    _stop_mon(interface=inter, verbose=True)
                    counter += 1
                    print(". ", end="", flush=True)
            print(f"{Fore.GREEN}>> {counter} virtual interfaces removed !{Fore.RESET}")
        else:
            is_monitor, _ = check_monitor(args.interface)
            if not is_monitor:
                print(f"{Fore.RED}Interface is not in monitor mode!")
                sys.exit(0)
            _stop_mon(interface=args.interface, verbose=True)


if __name__ == "__main__":
    main()
