#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import os
import re
import subprocess
import sys
import threading
import time
import argcomplete
from datetime import datetime
from pathlib import Path
from scapy.all import Dot11Beacon, Dot11Elt, Dot11EltRSN, Dot11EltVendorSpecific

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from helpers import add_interface_argument, check_interface, check_mac

if "_ARGCOMPLETE" not in os.environ:
    from colorama import Fore, Style, init
    from scapy.all import (
        sniff,
        Dot11,
        Dot11Beacon,
        Dot11ProbeResp,
        Dot11AssoReq,
        Dot11ReassoReq,
        Dot11Elt,
        RadioTap,
        Dot11ProbeReq,
        wrpcap,
    )
    from helpers import check_root, run_command

    init(autoreset=True)

# GLOBAL DATA STRUCTURES
access_points = {}
clients = {}
ap_lock = threading.Lock()
client_lock = threading.Lock()
packet_count = 0
start_time = None
captured_packets = []

hopping_active = False
hop_thread = None

current_interface = None
current_channel = None
output_file = None
filter_bssid = None

# RSN (WPA2/WPA3) Cipher Suite mappings (IEEE 802.11-2016)
RSN_CIPHER_MAP = {
    0: "GROUP",
    1: "WEP-40",
    2: "TKIP",
    3: "RESERVED",
    4: "CCMP",
    5: "WEP-104",
    6: "BIP-CMAC",
    7: "GROUP-NA",
    8: "GCMP",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "BIP-GMAC-128",
    12: "BIP-GMAC-256",
    13: "BIP-CMAC-256",
}

# RSN Authentication and Key Management (AKM) Suite mappings
RSN_AUTH_MAP = {
    0: "RESERVED",
    1: "MGT",
    2: "PSK",
    3: "FT-MGT",
    4: "FT-PSK",
    5: "MGT-SHA256",
    6: "PSK-SHA256",
    7: "TDLS",
    8: "SAE",
    9: "FT-SAE",
    10: "AP-PEER",
    11: "MGT-SUITE-B",
    12: "MGT-SUITE-B-192",
    13: "FT-MGT-SHA384",
    14: "FILS-SHA256",
    15: "FILS-SHA384",
    16: "FT-FILS-SHA256",
    17: "FT-FILS-SHA384",
    18: "OWE",
}

# WPA (WPA1) Cipher Suite mappings
WPA_CIPHER_MAP = {
    0: "GROUP",
    1: "WEP-40",
    2: "TKIP",
    3: "RESERVED",
    4: "CCMP",
    5: "WEP-104",
}

# WPA (WPA1) Authentication Suite mappings
WPA_AUTH_MAP = {
    0: "RESERVED",
    1: "MGT",
    2: "PSK",
}
class AccessPoint:
    """Represents a discovered access point"""

    def __init__(self, bssid, essid, channel, crypto, cipher, auth):
        self.bssid = bssid
        self.essid = essid or "<Hidden>"
        self.channel = channel
        self.crypto = crypto
        self.cipher = cipher
        self.auth = auth
        self.beacons = 0
        self.data_packets = 0
        self.last_data_count = 0
        self.last_rate_update = datetime.now()
        self.current_data_rate = 0
        self.power = -100
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.clients = set()

    def update(self, essid=None, channel=None, power=None):
        """Update access point information"""
        self.last_seen = datetime.now()
        
        if essid and essid != "" and self.essid == "<Hidden>":
            self.essid = essid
        
        if channel and channel != -1 and self.channel == -1:
            self.channel = channel
        
        if power and power > self.power:
            self.power = int(0.7 * self.power + 0.3 * power)

class Client:
    """Represents a discovered client station"""

    def __init__(self, mac, bssid=None):
        self.mac = mac
        self.bssid = bssid or "(not associated)"
        self.power = -100
        self.packets = 0
        self.last_seq = None
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.probes = set()

        self.window_frames = 0
        self.window_lost = 0
        self.window_start = datetime.now()

    def update(self, bssid=None, power=None, probe=None):
        """Update client information"""
        self.last_seen = datetime.now()
        self.packets += 1
        
        if bssid and bssid != "(not associated)":
            self.bssid = bssid
        
        if power and power > self.power:
            self.power = int(0.7 * self.power + 0.3 * power)
        
        if probe and probe != "":
            self.probes.add(probe)

    def update_sequence(self, seq_num, is_retry=False):
        """
        Update sequence number and detect packet loss
        
        Args:
            seq_num: Sequence number (0-4095)
            is_retry: True if this is a retransmission
        """
        if is_retry:
            return
        
        if self.last_seq is not None and seq_num == self.last_seq:
            return
        
        if self.last_seq is not None:
            expected_seq = (self.last_seq + 1) % 4096
            
            if seq_num != expected_seq:
                gap = (seq_num - expected_seq) % 4096
                
                if 0 < gap < 100:
                    self.window_lost += gap

        self.last_seq = seq_num

def is_retry(packet):
    """Check if packet is a retransmission"""
    try:
        if packet.haslayer(Dot11):
            return (packet[Dot11].FCfield & 0x08) != 0
        return False
    except Exception:
        return False

def get_sequence_number(packet):
    """Extract sequence number from 802.11 frame"""
    
    try:
        if not packet.haslayer(Dot11):
            return None
        
        dot11 = packet[Dot11]
        
        if hasattr(dot11, 'SC'):
            sc = dot11.SC
            sequence = (sc >> 4) & 0xFFF
            return sequence
        
        return None
    
    except Exception:
        return None

def data_rate_update():
    """update data rates for all APs"""
    with ap_lock:
        now = datetime.now()
        for ap in access_points.values():
            time_diff = (now - ap.last_rate_update).total_seconds()
            if time_diff >= 1.0:
                packets_diff = ap.data_packets - ap.last_data_count
                ap.current_data_rate = int(packets_diff / time_diff)
                ap.last_data_count = ap.data_packets
                ap.last_rate_update = now


def update_window_stats(interval=5):
    """
    Update windowed statistics for all clients periodically.
    Calculates RX quality and resets window counters every interval seconds.
    """
    while True:
        try:
            time.sleep(interval)
            
            with client_lock:
                now = datetime.now()
                for client in clients.values():

                    client.window_frames = 0
                    client.window_lost = 0
                    client.window_start = now
        
        except Exception:
            pass


def channel_hopper(interface, channels=None, dwell_time=0.1):
    """Continuously hop through WiFi channels"""
    global hopping_active, current_channel

    if channels is None:
        # get_supported_channels does not take an interface argument
        channels = get_supported_channels()

    if not channels:
        print(f"Warning: No valid channels found for {interface}, using defaults")
        channels = [1, 6, 11]
    print(f"Channel hopping started on channels: {channels}")

    while hopping_active:
        for channel in channels:
            if not hopping_active:
                break
            
            try:
                stdout,stderr = run_command(f"iw dev {interface} set channel {channel}")
                if stderr and "command failed" in stderr.lower():
                    continue

                current_channel = channel
                time.sleep(dwell_time)

            except Exception as e:
                pass

    print("Channel hopping stopped")

def get_supported_channels():
    """Parse `iw list` output and return a sorted list of usable channel numbers."""
    try:
        output = subprocess.check_output(['iw', 'list'], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return []

    channels = []
    for line in output.splitlines():
        line = line.strip()
        m = re.search(r"\[(\d+)\]", line)
        if m:
            if '(disabled)' in line:
                continue
            ch = int(m.group(1))
            channels.append(ch)

    print("Successfully detected channels")
    return sorted(set(channels))

def get_crypto_info(packet):
    """
    Extract cryptographic information from beacon/probe response
    using Scapy's built-in layers.
    Returns: (crypto_type, cipher, auth) tuple
    """
    try:
        crypto = "OPN"
        cipher = ""
        auth = ""

        cap = packet.sprintf("%Dot11Beacon.cap%")
        if "privacy" in cap.lower():
            pass

        rsn = packet.getlayer(Dot11EltRSN)
        if rsn:
            crypto = "WPA2"
            if rsn.pairwise_cipher_suites:
                
                ciphers = [suite.cipher for suite in rsn.pairwise_cipher_suites]
                
                if 9 in ciphers:
                    cipher_code = 9
                elif 10 in ciphers:
                    cipher_code = 10
                elif 8 in ciphers:
                    cipher_code = 8
                elif 4 in ciphers:
                    cipher_code = 4
                else:
                    cipher_code = rsn.pairwise_cipher_suites[0].cipher
                
                cipher = RSN_CIPHER_MAP.get(cipher_code, f"UNDEF({cipher_code})")

            if rsn.akm_suites:
                auth_code = rsn.akm_suites[0].suite
                auth = RSN_AUTH_MAP.get(auth_code, f"UNDEF({auth_code})")
            
            if auth == "SAE":
                crypto = "WPA3"
            elif auth == "OWE":
                crypto = "OWE"
                cipher = "CCMP"
            
            if "GCMP" in cipher:
                crypto = "WPA3"

        elif packet.haslayer(Dot11EltVendorSpecific):
            p = packet[Dot11EltVendorSpecific]
            while p:
                if p.oui == 0x0050f2 and p.info.startswith(b'\x01\x01\x00'):
                    crypto = "WPA"
                    
                    try:
                        from scapy.layers.dot11 import WPA_IE
                        wpa_info = WPA_IE(p.info[4:])

                        cipher_code = wpa_info.pairwise_cipher_suites[0].cipher
                        cipher = WPA_CIPHER_MAP.get(cipher_code, f"UNDEF({cipher_code})")
                        
                        auth_code = wpa_info.akm_suites[0].suite
                        auth = WPA_AUTH_MAP.get(auth_code, f"UNDEF({auth_code})")
                        
                    except ImportError:

                        if b'\x00\x50\xf2\x04' in p.info: cipher = "CCMP"
                        elif b'\x00\x50\xf2\x02' in p.info: cipher = "TKIP"
                        if b'\x00\x50\xf2\x02' in p.info: auth = "PSK"
                        elif b'\x00\x50\xf2\x01' in p.info: auth = "MGT"
                    
                    break
                
                p = p.payload.getlayer(Dot11EltVendorSpecific)

        if crypto == "OPN" and "privacy" in cap.lower():
            crypto = "WEP"
            cipher = "WEP"
            auth = "OPN"

        return crypto, cipher, auth

    except Exception as e:

        import traceback
        print(f"\n[ERROR] Failed to parse crypto info: {e}")
        print(f"Packet: {packet.summary()}")
        traceback.print_exc()
        return "OPN", "", ""

def get_rssi(packet):
    """Extract RSSI/signal strength from RadioTap header"""
    try:
        if packet.haslayer(RadioTap):
            if hasattr(packet[RadioTap], 'dBm_AntSignal'):
                return packet[RadioTap].dBm_AntSignal
            
            if hasattr(packet[RadioTap], 'dbm_antsignal'):
                return packet[RadioTap].dbm_antsignal
        
        return -100
    except Exception:
        return -100

def save_packet(packet):
    """Save packet to capture file if output is enabled"""
    if output_file:
        captured_packets.append(packet)

def packet_handler(packet):
    """Process each captured packet"""
    global packet_count, access_points, clients, captured_packets, filter_bssid

    packet_count += 1

    try:
        if not packet.haslayer(Dot11):
            return
        
        power = get_rssi(packet)
        sequence = get_sequence_number(packet)

        dot11 = packet[Dot11]
        
        addr1 = dot11.addr1
        addr2 = dot11.addr2
        addr3 = dot11.addr3
        
        if not addr2 or addr2 == "ff:ff:ff:ff:ff:ff":
            return
        
        if packet.haslayer(Dot11Beacon):
            bssid = addr3 or addr2
            
            if filter_bssid and bssid.lower() != filter_bssid.lower():
                return
            
            essid = "<Hidden>"
            channel = -1
            
            p = packet[Dot11Elt]
            while p:
                if p.ID == 0 and p.len > 0:
                    try:
                        essid = p.info.decode('utf-8', errors='ignore')
                    except:
                        essid = "<Hidden>"
                
                elif p.ID == 3:
                    channel = ord(p.info)
                
                p = p.payload.getlayer(Dot11Elt)
            
            crypto, cipher, auth = get_crypto_info(packet)
            
            with ap_lock:
                if bssid not in access_points:
                    access_points[bssid] = AccessPoint(
                        bssid, essid, channel, crypto, cipher, auth
                    )
                
                ap = access_points[bssid]
                ap.beacons += 1
                ap.update(essid=essid, channel=channel, power=power)
            
            save_packet(packet)
        
        elif packet.haslayer(Dot11ProbeResp):
            bssid = addr3 or addr2
            
            if filter_bssid and bssid.lower() != filter_bssid.lower():
                return
            
            essid = "<Hidden>"
            channel = -1
            
            p = packet[Dot11Elt]
            while p:
                if p.ID == 0 and p.len > 0:
                    try:
                        essid = p.info.decode('utf-8', errors='ignore')
                    except:
                        essid = "<Hidden>"
                
                elif p.ID == 3:
                    channel = ord(p.info)
                
                p = p.payload.getlayer(Dot11Elt)
            
            crypto, cipher, auth = get_crypto_info(packet)
            
            with ap_lock:
                if bssid not in access_points:
                    access_points[bssid] = AccessPoint(
                        bssid, essid, channel, crypto, cipher, auth
                    )
                
                ap = access_points[bssid]
                ap.update(essid=essid, channel=channel, power=power)
            
            save_packet(packet)
        
        elif packet.haslayer(Dot11ProbeReq):

            if filter_bssid:
                return
            
            client_mac = addr2
            
            probe_essid = ""
            p = packet[Dot11Elt]
            while p:
                if p.ID == 0 and p.len > 0: 
                    try:
                        probe_essid = p.info.decode('utf-8', errors='ignore')
                    except:
                        probe_essid = ""
                p = p.payload.getlayer(Dot11Elt)
            
            with client_lock:
                if client_mac not in clients:
                    clients[client_mac] = Client(client_mac)
                
                clients[client_mac].update(power=power, probe=probe_essid)
            
            save_packet(packet)
        
        elif packet.haslayer(Dot11AssoReq) or packet.haslayer(Dot11ReassoReq):
            client_mac = addr2
            bssid = addr1
            
            if filter_bssid and bssid.lower() != filter_bssid.lower():
                return
            
            with client_lock:
                if client_mac not in clients:
                    clients[client_mac] = Client(client_mac, bssid)
                
                clients[client_mac].update(bssid=bssid, power=power)
            
            with ap_lock:
                if bssid in access_points:
                    access_points[bssid].clients.add(client_mac)
            
            save_packet(packet)
        
        elif dot11.type == 2:
            
            to_ds = (dot11.FCfield & 0x1) != 0
            from_ds = (dot11.FCfield & 0x2) != 0
            
            if to_ds and not from_ds:
                client_mac = addr2
                bssid = addr1
            elif from_ds and not to_ds:
                client_mac = addr1
                bssid = addr2
            else:
                return
            
            if filter_bssid and bssid.lower() != filter_bssid.lower():
                return
            
            with ap_lock:
                if bssid in access_points:
                    access_points[bssid].data_packets += 1
                    access_points[bssid].clients.add(client_mac)
            
            with client_lock:
                if client_mac not in clients:
                    clients[client_mac] = Client(client_mac, bssid)
                
                clients[client_mac].update(bssid=bssid, power=power)
                
                if sequence is not None:
                    retry = is_retry(packet)
                    clients[client_mac].update_sequence(sequence, retry)
                    if not retry:
                        clients[client_mac].window_frames += 1
            
            save_packet(packet)

    except Exception as e:
        pass

def display_interface(interface, channel):
    """Display header information"""
    global start_time, packet_count
    
    elapsed = datetime.now() - start_time
    elapsed_seconds = int(elapsed.total_seconds())
    
    if channel:
        ch_display = f"CH {channel:>2}"
    else:
        ch_display = "CH  -"
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
    
    print(f" {ch_display} ][ Elapsed: {elapsed_seconds} s ][ {timestamp}\n")

def display_access_points():
    """Display discovered access points"""
    print(" BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID\n")
    
    with ap_lock:
        sorted_aps = sorted(
            access_points.values(),
            key=lambda x: x.power,
            reverse=True
        )
        
        if not sorted_aps:
            print(" No access points detected yet...")
        
        for ap in sorted_aps:
            ch_str = str(ap.channel) if ap.channel != -1 else "-"
            essid = ap.essid[:20] if len(ap.essid) <= 20 else ap.essid[:17] + "..."
            
            data_rate = ap.current_data_rate

            #TODO: Implement max bitrate calculation based on capabilities, currently just a placeholder 
            max_bitrate = 270
            
            print(f" {ap.bssid.upper():17s}  {ap.power:>3d}  {ap.beacons:>7d}    {ap.data_packets:>5d} {data_rate:>4d}  {ch_str:>2s}  {max_bitrate:>3d}   {ap.crypto:4s} {ap.cipher:6s}  {ap.auth:4s} {essid}")

def display_clients():
    """Display discovered clients"""
    print("\n BSSID              STATION            PWR    Rate    Lost   Frames  Notes  Probes\n")
    
    with client_lock:
        sorted_clients = sorted(
            clients.values(),
            key=lambda x: x.packets,
            reverse=True
        )[:30]
        
        if not sorted_clients:
            print(" No stations detected yet...")
        
        for client in sorted_clients:
            #TODO: implement the rate display method, currently just a placeholder 
            rate_display = "0 - 0"
            lost = client.window_lost

            probes_list = list(client.probes)[:2]
            probes_str = ", ".join(probes_list) if probes_list else ""
            if len(probes_str) > 20:
                probes_str = probes_str[:17] + "..."
            
            bssid_display = client.bssid.upper() if client.bssid != "(not associated)" else "(not associated)"
            
            print(f" {bssid_display:17s}  {client.mac.upper():17s}  {client.power:>3d}    {rate_display:7s}  {lost:>5d}   {client.packets:>6d}         {probes_str}")

def display_stats():
    """Display all statistics"""
    sys.stdout.write("\033[H\033[J")
    sys.stdout.flush()

    data_rate_update()

    display_interface(current_interface, current_channel)
    
    display_access_points()

    display_clients()
    


def display_loop(interval=1):
    """Continuously update the display"""
    while True:
        try:
            display_stats()
            time.sleep(interval)
        except KeyboardInterrupt:
            break

def start_sniffer(interface, channel=None, output_file_path=None, target_bssid=None):
    """Start packet capture on the specified interface"""
    global start_time, current_interface, current_channel, output_file, filter_bssid

    global hop_thread, hopping_active

    current_interface = interface
    current_channel = channel
    output_file = output_file_path
    filter_bssid = target_bssid
    start_time = datetime.now()

    print(f"\nStarting hitdump-ng")
    print(f"Interface: {interface}")
    
    if channel:
        print(f"Channel: {channel}")
        print(f"Setting channel to {channel}...")
        stdout, stderr = run_command(f"iw dev {interface} set channel {channel}")
        if stderr:
            print(f"Failed to set channel: {stderr}")
            print(f"Continuing anyway...")
        else:
            print(f"Channel set successfully")
    else:
        print(f"Channel: Hopping (scanning all channels)")
        try:
            hopping_active = True
            hop_thread = threading.Thread(target=channel_hopper, args=(interface, None, 0.1), daemon=True)
            hop_thread.start()
            print("Channel hopper thread started")
        except Exception as e:
            print(f"Failed to start channel hopper: {e}")

    if filter_bssid:
        print(f"Filter: BSSID = {filter_bssid}")
    
    if output_file:
        print(f"Output: {output_file}")
    
    print(f"\nStarting packet capture...")
    print(f"Initializing... Please wait...\n")
    
    time.sleep(2)

    # Start windowed statistics update thread
    window_stats_thread = threading.Thread(target=update_window_stats, args=(5,), daemon=True)
    window_stats_thread.start()

    display_thread = threading.Thread(target=display_loop, daemon=True)
    display_thread.start()

    try:
        sniff(
            iface=interface,
            prn=packet_handler,
            store=False
        )
    except KeyboardInterrupt:
        print(f"\nStopping capture...")
    except Exception as e:
        print(f"\nError during capture: {e}")
    finally:

        try:
            hopping_active = False
            if hop_thread and hasattr(hop_thread, 'is_alive') and hop_thread.is_alive():
                hop_thread.join(timeout=1)
        except Exception:
            pass
        if output_file and captured_packets:
            print(f"\nWriting {len(captured_packets)} packets to {output_file}...")
            try:
                wrpcap(output_file, captured_packets)
                print(f"PCAP file saved successfully.")
            except Exception as e:
                print(f"Failed to write PCAP: {e}")
        
        print(f"\nCapture stopped.")
        print(f"Total Access Points: {len(access_points)}")
        print(f"Total Clients: {len(clients)}")
        print(f"Total Packets: {packet_count}")

def _check_monitor_mode(interface):
    """Verify interface is in monitor mode"""
    try:
        result = os.popen(f"iw dev {interface} info").read()
        
        if "type monitor" in result.lower():
            return True
        else:
            print(f"\nError: Interface {interface} is not in monitor mode")
            
            all_interfaces = os.listdir("/sys/class/net")
            monitor_interfaces = [iface for iface in all_interfaces if "mon" in iface.lower()]
            
            if monitor_interfaces:
                print(f"Available monitor interfaces:")
                for iface in monitor_interfaces:
                    print(f"  • {iface}")
                print(f"\nTry: sudo hitdump {monitor_interfaces[0]}\n")
            else:
                print(f"No monitor mode interfaces found.")
                print(f"Enable monitor mode first:")
                
                base_interface = interface.replace("mon", "")
                print(f"  sudo hitmon start {base_interface}")
                print(f"\nThen run hitdump with the monitor interface:")
                print(f"  sudo hitdump {base_interface}mon\n")
            
            return False
    except Exception as e:
        print(f"Error checking monitor mode: {e}")
        return False

def main():
    """Main function"""
    art = r"""
  /$$       /$$   /$$           /$$                                  
| $$      |__/  | $$          | $$                                  
| $$$$$$$  /$$ /$$$$$$    /$$$$$$$ /$$   /$$  /$$$$$$  /$$$$$$/$$$$ 
| $$__  $$| $$|_  $$_/   /$$__  $$| $$  | $$ /$$__  $$| $$_  $$_  $$
| $$  \ $$| $$  | $$    | $$  | $$| $$  | $$| $$  \ $$| $$ \ $$ \ $$
| $$  | $$| $$  | $$ /$$| $$  | $$| $$  | $$| $$  | $$| $$ | $$ | $$
| $$  | $$| $$  |  $$$$/|  $$$$$$$|  $$$$$$/| $$$$$$$/| $$ | $$ | $$
|__/  |__/|__/   \___/   \_______/ \______/ | $$____/ |__/ |__/ |__/
                                            | $$                    
                                            | $$                    
                                            |__/                        
"""
    parser = argparse.ArgumentParser(
        prog="hitdump",
        description=art + "\n\nCapture and display WiFi networks and clients in real-time",
        epilog="@By NS-Guys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    add_interface_argument(parser)

    parser.add_argument(
        "-c",
        "--channel",
        type=int,
        help="Set interface to specific channel (1-14 for 2.4GHz, 36-165 for 5GHz)",
        metavar="CH",
    )

    parser.add_argument(
        "-w",
        "--write",
        help="Write captured packets to pcap file",
        metavar="FILE",
    )

    parser.add_argument(
        "-d",
        "--bssid",
        help="Filter and monitor only the specified BSSID (MAC address)",
        metavar="MAC",
    )

    argcomplete.autocomplete(parser)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    check_root()
    check_interface(args.interface)

    if not _check_monitor_mode(args.interface):
        sys.exit(1)

    if args.channel:
        if not ((1 <= args.channel <= 14) or (36 <= args.channel <= 165)):
            print(f"Invalid channel. Must be 1-14 (2.4GHz) or 36-165 (5GHz)")
            sys.exit(1)

    if args.bssid:
        check_mac(args.bssid)

    start_sniffer(args.interface, args.channel, args.write, args.bssid)

if __name__ == "__main__":
    main()