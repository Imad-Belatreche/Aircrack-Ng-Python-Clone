import os
import re
import subprocess
import sys
from scapy.layers.l2 import ARP
from scapy.sendrecv import sr1

from colorama import Fore


# May be used later to ease user experience
def _get_mac_address(ip_address):
    """
    Gets the Mac address of an access point using its IP address
    """
    arp_request = ARP(pdst=ip_address)
    arp_replay = sr1(arp_request, verbose=False, timeout=1)
    if arp_replay is not None:
        return arp_replay.hwsrc
    else:
        return None


# Adds autocompletion of interfaces


def interface_completer(prefix, **kwargs):
    """Gets all avilable interfaces."""
    try:
        return (i for i in os.listdir("/sys/class/net/") if i.startswith(prefix))
    except FileNotFoundError:
        return []


def add_interface_argument(subparser):
    """Adds the autocompletion"""
    interface_arg = subparser.add_argument(
        "interface",
        help="The network interface to use.",
    )
    interface_arg.completer = interface_completer
    return interface_arg


def run_command(command, check=False):
    """Runs a command and return it's output (stdout and stderr)"""
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


def check_mac(mac):
    """Validate if the input is a correct mac address or not"""
    result = re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac)
    if result:
        return
    else:
        print(f"{Fore.RED}Please enter a valid mac address")
        sys.exit(1)


def check_interface(interface):
    """Checks if interface exists"""
    interfaces = os.listdir("/sys/class/net")
    if interface in interfaces:
        return
    else:
        print(f"{Fore.RED}Please enter a valid interface{Fore.RESET}")
        print("Available interfaces: ")
        for inter in interfaces:
            print(f"- {inter}")
        sys.exit(1)
