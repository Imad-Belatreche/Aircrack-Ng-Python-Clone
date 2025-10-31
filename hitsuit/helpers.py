from concurrent.futures import ThreadPoolExecutor
import os
import re
import subprocess
import sys
from scapy.layers.l2 import ARP
from scapy.sendrecv import sr1
from scapy.all import sniff, Packet
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11, Dot11Elt

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


def check_monitor(interface):
    """Checks if monitor mode is enabled"""

    out, err = run_command(f"iw dev {interface} info")
    if err:
        print(f"{Fore.RED}An error occured: {err}")
        return False

    wireless_types = ["ibss", "monitor", "mesh", "wds", "managed"]

    for type in wireless_types:
        search = re.search(type, out)
        if search is not None:
            break
    result = search.group(0)

    if result == "monitor":
        return True, None
    else:
        return False, result


def set_right_channel(interface, bssid):
    """
    Sets the interface to the right channel that the provided access point (bssid) is operating on.
    Uses actual channel information from beacon frames for accuracy.
    """
    print(f"{Fore.GREEN}\n+==============================================+{Fore.GREEN}")
    
    out, _ = run_command(f"iw dev {interface} info | grep channel | awk '{{print $2}}'")
    init_channel = int(out)

    target_bssid = bssid.lower().strip()
    found_channel = None
    stop_sniffing = False

    def packet_handler(packet: Packet):
        nonlocal found_channel, stop_sniffing
        if packet.haslayer(Dot11Beacon):
            if packet[Dot11].addr2 and packet[Dot11].addr2.lower() == target_bssid:
                actual_channel = None

                # Extract channel from frame
                elt = packet[Dot11Elt]
                while elt:
                    if elt.ID == 3 and len(elt.info) == 1:
                        actual_channel = ord(elt.info)
                        break
                    elt = elt.payload.getlayer(Dot11Elt)

                # If prev fails, try to get use the loop
                if actual_channel is None:
                    actual_channel = current_channel
                    print(
                        f"{Fore.YELLOW}Warning: Using interface channel {actual_channel} (could not extract from beacon){Fore.RESET}"
                    )
                else:
                    print(
                        f"{Fore.GREEN}Beacon reports actual channel: {actual_channel}{Fore.RESET}"
                    )

                found_channel = actual_channel

                # Extract SSID
                ssid = "Unknown"
                ssid_elem = packet[Dot11Elt]
                while ssid_elem and ssid_elem.ID != 0:
                    ssid_elem = ssid_elem.payload.getlayer(Dot11Elt)
                if ssid_elem and ssid_elem.ID == 0:
                    ssid = ssid_elem.info.decode("utf-8", errors="ignore") or "<Hidden>"

                print(
                    f"{Fore.GREEN}Found {bssid} (SSID: {ssid}) on actual channel {actual_channel}{Fore.RESET}"
                )
                stop_sniffing = True
                return

    def stop_filter(packet):
        return stop_sniffing

    # First, check if we're already on the right channel
    current_channel = init_channel
    print(f"{Fore.WHITE}Checking current channel {init_channel}...{Fore.RESET}")
    sniff(
        iface=interface,
        prn=packet_handler,
        timeout=1.5,
        store=0,
        stop_filter=stop_filter,
    )

    if not found_channel:
        channels = list(range(1, 15))
        for channel in channels:
            if channel == init_channel:  # Skip since we already checked
                continue

            current_channel = channel
            run_command(f"iw dev {interface} set channel {channel}")
            print(f"{Fore.WHITE}Trying channel {channel}...{Fore.RESET}")

            stop_sniffing = False
            sniff(
                iface=interface,
                prn=packet_handler,
                timeout=1,
                store=0,
                stop_filter=stop_filter,
            )

            if found_channel:
                break

    if found_channel:
        # Set to the ACTUAL channel found in beacon frames
        print(
            f"{Fore.GREEN}Setting interface to actual channel {found_channel}{Fore.RESET}"
        )
        run_command(f"iw dev {interface} set channel {found_channel}")
        return found_channel
    else:
        print(f"{Fore.RED}Could not find the channel of that BSSID!{Fore.RESET}")
        run_command(f"iw dev {interface} set channel {init_channel}")
        sys.exit(1)

    print(f"{Fore.GREEN}+==============================================+{Fore.GREEN}\n")