#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import os
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

# Global data structures
access_points = {}  # BSSID -> AP info
clients = {}  # Client MAC -> client info
ap_lock = threading.Lock()
client_lock = threading.Lock()
packet_count = 0
start_time = None
captured_packets = []  # Store packets for PCAP writing

# RSN (WPA2/WPA3) Cipher Suite mappings (IEEE 802.11-2016)
RSN_CIPHER_MAP = {
    0: "GROUP",      # Use group cipher suite
    1: "WEP-40",     # WEP-40
    2: "TKIP",       # TKIP
    3: "RESERVED",   # Reserved
    4: "CCMP",       # CCMP-128 (AES)
    5: "WEP-104",    # WEP-104
    6: "BIP-CMAC",   # BIP-CMAC-128
    7: "GROUP-NA",   # Group addressed traffic not allowed
    8: "GCMP",       # GCMP-128
    9: "GCMP-256",   # GCMP-256
    10: "CCMP-256",  # CCMP-256
    11: "BIP-GMAC-128",  # BIP-GMAC-128
    12: "BIP-GMAC-256",  # BIP-GMAC-256
    13: "BIP-CMAC-256",  # BIP-CMAC-256
}

# RSN Authentication and Key Management (AKM) Suite mappings
RSN_AUTH_MAP = {
    0: "RESERVED",   # Reserved
    1: "MGT",        # IEEE 802.1X / EAP (Enterprise)
    2: "PSK",        # PSK (Pre-Shared Key)
    3: "FT-MGT",     # FT over IEEE 802.1X
    4: "FT-PSK",     # FT using PSK
    5: "MGT-SHA256", # IEEE 802.1X SHA-256
    6: "PSK-SHA256", # PSK SHA-256
    7: "TDLS",       # TDLS / TPK Handshake
    8: "SAE",        # SAE (WPA3-Personal)
    9: "FT-SAE",     # FT using SAE
    10: "AP-PEER",   # AP Peer Key
    11: "MGT-SUITE-B",     # Suite B
    12: "MGT-SUITE-B-192", # Suite B 192-bit
    13: "FT-MGT-SHA384",   # FT over 802.1X SHA-384
    14: "FILS-SHA256",     # FILS SHA-256
    15: "FILS-SHA384",     # FILS SHA-384
    16: "FT-FILS-SHA256",  # FT FILS SHA-256
    17: "FT-FILS-SHA384",  # FT FILS SHA-384
    18: "OWE",       # OWE (Opportunistic Wireless Encryption)
}

# WPA (WPA1) Cipher Suite mappings - similar to RSN but uses different OUI
WPA_CIPHER_MAP = {
    0: "GROUP",      # Use group cipher suite
    1: "WEP-40",     # WEP-40
    2: "TKIP",       # TKIP
    3: "RESERVED",   # Reserved
    4: "CCMP",       # CCMP (rarely used in WPA1)
    5: "WEP-104",    # WEP-104
}

# WPA (WPA1) Authentication Suite mappings
WPA_AUTH_MAP = {
    0: "RESERVED",   # Reserved
    1: "MGT",        # IEEE 802.1X / EAP
    2: "PSK",        # PSK (Pre-Shared Key)
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
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.probes = set()  # Set of probed ESSIDs

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


def get_crypto_info(packet):
    """
    Extract cryptographic information from beacon/probe response
    using Scapy's built-in layers.
    Returns: (crypto_type, cipher, auth) tuple
    """
    try:
        # --- Default values ---
        crypto = "OPN"
        cipher = ""
        auth = ""

        # --- 1. Check for basic WEP (Privacy bit) ---
        cap = packet.sprintf("%Dot11Beacon.cap%")
        if "privacy" in cap.lower():
            crypto = "WEP"
            cipher = "WEP" # WEP is both
            auth = "OPN"   # or "SKA" but we can't easily tell from here

        # --- 2. Check for RSN (WPA2/WPA3) ---
        # Scapy auto-parses ID 48 into this layer
        rsn = packet.getlayer(Dot11EltRSN)
        if rsn:
            # We found an RSN element, so it's at least WPA2
            crypto = "WPA2"
            
            # Parse Pairwise Cipher (the one used for clients)
            # It's a list, but we usually just care about the first one
            if rsn.pairwise_cipher_suites:
                cipher_code = rsn.pairwise_cipher_suites[0].suite
                cipher = RSN_CIPHER_MAP.get(cipher_code, f"UNDEF({cipher_code})")

            # Parse Authentication (AKM)
            if rsn.akm_suites:
                auth_code = rsn.akm_suites[0].suite
                auth = RSN_AUTH_MAP.get(auth_code, f"UNDEF({auth_code})")
            
            # Check for WPA3 / OWE
            if auth == "SAE":
                crypto = "WPA3"
            elif auth == "OWE":
                crypto = "OWE"
                cipher = "CCMP" # OWE mandates CCMP
            
            # WPA3-Enterprise uses GCMP
            if "GCMP" in cipher:
                crypto = "WPA3"

        # --- 3. Check for WPA1 (Vendor-Specific IE) ---
        # This is an 'elif' because RSN (WPA2/3) takes precedence
        elif packet.haslayer(Dot11EltVendorSpecific):
            # We have to find the WPA1 OUI: 00:50:f2:01
            p = packet[Dot11EltVendorSpecific]
            while p:
                if p.oui == 0x0050f2 and p.info.startswith(b'\x01\x01\x00'): # WPA1 OUI + type 1
                    crypto = "WPA"
                    
                    # WPA1 is tricky and Scapy doesn't parse it as deeply as RSN.
                    # We can use your original byte-matching, but it's cleaner.
                    # Or, we can instantiate the WPA_IE class from the info
                    try:
                        from scapy.layers.dot11 import WPA_IE
                        wpa_info = WPA_IE(p.info[4:]) # Skip OUI and type

                        cipher_code = wpa_info.pairwise_cipher_suites[0].suite
                        cipher = WPA_CIPHER_MAP.get(cipher_code, f"UNDEF({cipher_code})")
                        
                        auth_code = wpa_info.akm_suites[0].suite
                        auth = WPA_AUTH_MAP.get(auth_code, f"UNDEF({auth_code})")
                        
                    except ImportError:
                        # Fallback if WPA_IE is not available or fails
                        # This is similar to your original code
                        if b'\x00\x50\xf2\x04' in p.info: cipher = "CCMP"
                        elif b'\x00\x50\xf2\x02' in p.info: cipher = "TKIP"
                        if b'\x00\x50\xf2\x02' in p.info: auth = "PSK"
                        elif b'\x00\x50\xf2\x01' in p.info: auth = "MGT"
                    
                    break # Found WPA1, no need to check other vendor IEs
                
                # Move to the next vendor-specific IE, if there are multiple
                p = p.payload.getlayer(Dot11EltVendorSpecific)

        return crypto, cipher, auth

    except Exception as e:

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


def packet_handler(packet):
    """Process each captured packet"""
    global packet_count, access_points, clients, captured_packets, filter_bssid

    packet_count += 1

    try:
        if not packet.haslayer(Dot11):
            return
        
        if output_file:
            captured_packets.append(packet)
        
        power = get_rssi(packet)
        
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
        
        elif packet.haslayer(Dot11ProbeReq):
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

    except Exception as e:
        pass


def display_interface(interface, channel):
    """Display header information"""
    global start_time, packet_count
    
    elapsed = datetime.now() - start_time
    elapsed_str = str(elapsed).split('.')[0]
    
    if channel:
        ch_display = f"CH {channel}"
    else:
        ch_display = "Hopping"
    
    elapsed_seconds = max(1, (datetime.now() - start_time).total_seconds())
    pps = int(packet_count / elapsed_seconds)
    
    border = "═" * 96
    print(f"\n╔{border}╗")
    print(f"║ hitdump-ng v1.0{' ' * 80}║")
    print(f"╠{border}╣")
    print(f"║ Interface: {interface:15s} │ Channel: {ch_display:10s} │ Elapsed: {elapsed_str:8s} │ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ║")
    print(f"║ Packets: {packet_count:10d} │ Rate: {pps:6d} pkt/s │ APs: {len(access_points):6d} │ Clients: {len(clients):6d}       ║")
    print(f"╚{border}╝\n")


def display_access_points():
    """Display discovered access points in a table"""
    border = "─" * 96
    print(f"┌{border}┐")
    print(f"│{' ' * 39}ACCESS POINTS{' ' * 45}│")
    print(f"├{border}┤")
    print(f"│ BSSID                PWR  Beacons  #Data  CH   ENC        CIPHER   AUTH    ESSID                │")
    print(f"├{border}┤")
    
    with ap_lock:
        sorted_aps = sorted(
            access_points.values(),
            key=lambda x: x.power,
            reverse=True
        )
        
        if not sorted_aps:
            print(f"│ No access points detected yet... Keep scanning{' ' * 48}│")
        
        for ap in sorted_aps:

            if ap.power >= -50:
                signal_bars = "▰▰▰▰"
            elif ap.power >= -60:
                signal_bars = "▰▰▰▱"
            elif ap.power >= -70:
                signal_bars = "▰▰▱▱"
            elif ap.power >= -80:
                signal_bars = "▰▱▱▱"
            else:
                signal_bars = "▱▱▱▱"
            
            ch_str = str(ap.channel) if ap.channel != -1 else "?"
            
            essid = ap.essid[:16] if len(ap.essid) <= 16 else ap.essid[:13] + "..."
            
            bssid_col = f"{ap.bssid:17s}"
            pwr_col = f"{signal_bars} {ap.power:3d}"
            beacons_col = f"{ap.beacons:7d}"
            data_col = f"{ap.data_packets:6d}"
            ch_col = f"{ch_str:>3s}"
            enc_col = f"{ap.crypto:10s}"
            cipher_col = f"{ap.cipher:8s}"
            auth_col = f"{ap.auth:7s}"
            essid_col = f"{essid:16s}"
            
            print(f"│ {bssid_col}  {pwr_col}  {beacons_col}  {data_col}  {ch_col}  {enc_col}  {cipher_col}  {auth_col}  {essid_col} │")
    
    border = "─" * 96
    print(f"└{border}┘")


def display_clients():
    """Display discovered clients in a table"""
    border = "─" * 96
    print(f"\n┌{border}┐")
    print(f"│{' ' * 43}STATIONS{' ' * 45}│")
    print(f"├{border}┤")
    print(f"│ CLIENT MAC          PWR  Packets   Rate    BSSID              Probed ESSIDs            │")
    print(f"├{border}┤")
    
    with client_lock:
        sorted_clients = sorted(
            clients.values(),
            key=lambda x: x.packets,
            reverse=True
        )[:30]
        
        if not sorted_clients:
            print(f"│ No stations detected yet... Waiting for activity{' ' * 44}│")
        
        for client in sorted_clients:
            elapsed = (datetime.now() - client.first_seen).total_seconds()
            rate = int(client.packets / max(1, elapsed)) if elapsed > 0 else 0
            rate_str = f"{rate}/s" if rate > 0 else "-"
            
            probes_list = list(client.probes)[:2]
            probes_str = ", ".join(probes_list) if probes_list else "-"
            if len(client.probes) > 2:
                probes_str += f" +{len(client.probes) - 2}"
            
            if len(probes_str) > 24:
                probes_str = probes_str[:21] + "..."
            
            mac_col = f"{client.mac:17s}"
            pwr_col = f"{client.power:4d}"
            packets_col = f"{client.packets:8d}"
            rate_col = f"{rate_str:>7s}"
            bssid_col = f"{client.bssid:17s}"
            probes_col = f"{probes_str:24s}"
            
            print(f"│ {mac_col}  {pwr_col}  {packets_col}  {rate_col}  {bssid_col}  {probes_col} │")
    
    border = "─" * 96
    print(f"└{border}┘")


def display_stats():
    """Display all statistics"""
    os.system('clear' if os.name == 'posix' else 'cls')
    
    display_interface(current_interface, current_channel)
    
    display_access_points()
    
    display_clients()
    
    with ap_lock:
        open_aps = sum(1 for ap in access_points.values() if ap.crypto == "OPN")
        wpa2_aps = sum(1 for ap in access_points.values() if ap.crypto == "WPA2")
        wpa3_aps = sum(1 for ap in access_points.values() if ap.crypto in ["WPA3", "OWE"])
        wep_aps = sum(1 for ap in access_points.values() if ap.crypto == "WEP")
    
    with client_lock:
        associated = sum(1 for c in clients.values() if c.bssid != "(not associated)")
        probing = len(clients) - associated
    
    border = "═" * 96
    print(f"\n╔{border}╗")
    print(f"║ STATISTICS{' ' * 86}║")
    print(f"╠{border}╣")
    print(f"║ Networks: Open: {open_aps:3d} │ WEP: {wep_aps:3d} │ WPA2: {wpa2_aps:3d} │ WPA3: {wpa3_aps:3d}{' ' * 40}║")
    print(f"║ Stations: Associated: {associated:3d} │ Probing: {probing:3d}{' ' * 54}║")
    
    if filter_bssid:
        print(f"║ Filter: Monitoring BSSID {filter_bssid}{' ' * 49}║")
    
    print(f"╠{border}╣")
    print(f"║ Press Ctrl+C to stop capture{' ' * 68}║")
    print(f"╚{border}╝")


def display_loop(interval=2):
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

    current_interface = interface
    current_channel = channel
    output_file = output_file_path
    filter_bssid = target_bssid
    start_time = datetime.now()

    print(f"\n{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║{Style.RESET_ALL}                    {Fore.GREEN}Starting hitdump-ng{Style.RESET_ALL}                     {Fore.CYAN}║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
    
    print(f"  {Fore.YELLOW}Interface:{Style.RESET_ALL}  {interface}")
    
    if channel:
        print(f"  {Fore.YELLOW}Channel:{Style.RESET_ALL}    {channel}")
        print(f"  {Fore.CYAN}Setting channel to {channel}...{Style.RESET_ALL}")
        stdout, stderr = run_command(f"iw dev {interface} set channel {channel}")
        if stderr:
            print(f"  {Fore.RED}   Failed to set channel: {stderr}{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}Continuing anyway...{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Channel set successfully{Style.RESET_ALL}")
    else:
        print(f"  {Fore.YELLOW}Channel:{Style.RESET_ALL}    Hopping (scanning all channels)")

    if filter_bssid:
        print(f"  {Fore.YELLOW}Filter:{Style.RESET_ALL}     BSSID = {Fore.CYAN}{filter_bssid}{Style.RESET_ALL}")
    
    if output_file:
        print(f"  {Fore.YELLOW}Output:{Style.RESET_ALL}     {output_file}")
    
    print(f"\n  {Fore.GREEN}✓ Starting packet capture...{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Initializing... Please wait...{Style.RESET_ALL}\n")
    
    time.sleep(2)

    display_thread = threading.Thread(target=display_loop, daemon=True)
    display_thread.start()

    try:
        sniff(
            iface=interface,
            prn=packet_handler,
            store=False
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Stopping capture...{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Error during capture: {e}{Style.RESET_ALL}")
    finally:
        if output_file and captured_packets:
            print(f"\n{Fore.CYAN}Writing {len(captured_packets)} packets to {output_file}...{Style.RESET_ALL}")
            try:
                wrpcap(output_file, captured_packets)
                print(f"{Fore.GREEN}PCAP file saved successfully.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Failed to write PCAP: {e}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}Capture stopped.{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Total Access Points: {len(access_points)}")
        print(f"Total Clients: {len(clients)}")
        print(f"Total Packets: {packet_count}{Style.RESET_ALL}")


def _check_monitor_mode(interface):
    """Verify interface is in monitor mode"""
    try:
        result = os.popen(f"iw dev {interface} info").read()
        
        if "type monitor" in result.lower():
            return True
        else:
            print(f"\n{Fore.RED}╔═══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
            print(f"{Fore.RED}║{Style.RESET_ALL}       Error: Interface {interface} is not in monitor mode   {Fore.RED}║{Style.RESET_ALL}")
            print(f"{Fore.RED}╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
            
            all_interfaces = os.listdir("/sys/class/net")
            monitor_interfaces = [iface for iface in all_interfaces if "mon" in iface.lower()]
            
            if monitor_interfaces:
                print(f"{Fore.YELLOW}Available monitor interfaces:{Style.RESET_ALL}")
                for iface in monitor_interfaces:
                    print(f"  • {Fore.GREEN}{iface}{Style.RESET_ALL}")
                print(f"\n{Fore.CYAN}Try: sudo hitdump {monitor_interfaces[0]}{Style.RESET_ALL}\n")
            else:
                print(f"{Fore.YELLOW}No monitor mode interfaces found.{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Enable monitor mode first:{Style.RESET_ALL}")
                
                base_interface = interface.replace("mon", "")
                print(f"  sudo hitmon start {base_interface}\n")
                print(f"{Fore.CYAN}Then run hitdump with the monitor interface:{Style.RESET_ALL}")
                print(f"  sudo hitdump {base_interface}mon\n")
            
            return False
    except Exception as e:
        print(f"{Fore.RED}Error checking monitor mode: {e}{Style.RESET_ALL}")
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
            print(
                f"{Fore.RED}Invalid channel. Must be 1-14 (2.4GHz) or 36-165 (5GHz){Style.RESET_ALL}"
            )
            sys.exit(1)

    if args.bssid:
        check_mac(args.bssid)

    print(f"{Fore.GREEN}Starting hitdump-ng...{Style.RESET_ALL}")
    start_sniffer(args.interface, args.channel, args.write, args.bssid)


current_interface = None
current_channel = None
output_file = None
filter_bssid = None


if __name__ == "__main__":
    main()