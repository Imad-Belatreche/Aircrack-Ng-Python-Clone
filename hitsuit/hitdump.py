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
from constants import (
    RSN_CIPHER_MAP,
    RSN_AUTH_MAP,
    WPA_CIPHER_MAP,
    WPA_AUTH_MAP,
    AIRODUMP_MB_VALUES,
    HT_MCS_RATES,
    VHT_MCS_RATES,
    HE_MCS_RATES
)

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
filter_essid_regex = None

filtered_ap_count = 0
total_ap_count = 0

def matches_essid_filter(essid):
    """Check if ESSID matches the regex filter"""
    global filter_essid_regex
    
    if filter_essid_regex is None:
        return True
    
    if essid == "<Hidden>":
        return False
    
    try:
        return filter_essid_regex.search(essid) is not None
    except Exception:
        return False

def is_valid_client_mac(mac):
    """ Check if MAC address is a valid client (not broadcast/multicast) """
    if not mac:
        return False
        
        #check if the mac is broadcast
    if mac.lower() == "ff:ff:ff:ff:ff:ff":
        return False
    
        #check if the mac is multicast, (if the LSB of the first byte is odd nbr, it's multicast)
    try:
        first_octet = int(mac.split(':')[0], 16)
        
        if first_octet & 0x01:
            return False
        
        return True
    
    except (ValueError, IndexError):
        return False

def parse_supported_rates(packet):
    """
    Extract maximum supported rate from legacy 802.11a/b/g networks.
    Parses Element ID 1 (Supported Rates) and Element ID 50 (Extended Supported Rates).
    """
    try:
        max_rate = 0.0
        
        if not packet.haslayer(Dot11Elt):
            return max_rate
        
        elt = packet[Dot11Elt]
        
        while elt:

            if elt.ID in (1, 50) and elt.len > 0:
                try:
                    for byte in elt.info:
                        if isinstance(byte, str):
                            byte = ord(byte)
                            
                        rate = (byte & 0x7F) * 0.5
                        if rate > max_rate:
                            max_rate = rate
                except Exception:
                    pass
            
            elt = elt.payload.getlayer(Dot11Elt)
        
        return max_rate
    
    except Exception:
        return 0.0


def parse_ht_capabilities(packet):
    """
    Parse HT Capabilities (Element ID 45) for 802.11n networks.
    Determines maximum throughput based on channel width, guard interval, and MCS.
    """
    try:
        if not packet.haslayer(Dot11Elt):
            return 0
        
        elt = packet[Dot11Elt]
        
        while elt:
            if elt.ID == 45 and elt.len >= 26:
                try:
                    info = elt.info
                    if isinstance(info, str):
                        info = bytes(info, 'latin-1')
                    
                    ht_cap_info = int.from_bytes(info[0:2], byteorder='little')
                    
                    supports_40mhz = (ht_cap_info & 0x0002) != 0
                    
                    short_gi_20 = (ht_cap_info & 0x0020) != 0
                    short_gi_40 = (ht_cap_info & 0x0040) != 0
                    
                    if len(info) >= 7:
                        mcs_set = info[3:7]
                        
                        max_mcs = -1
                        for byte_idx, byte_val in enumerate(mcs_set):
                            if isinstance(byte_val, str):
                                byte_val = ord(byte_val)
                            for bit_idx in range(8):
                                if byte_val & (1 << bit_idx):
                                    mcs_idx = byte_idx * 8 + bit_idx
                                    if mcs_idx <= 31:
                                        max_mcs = mcs_idx
                        
                        if max_mcs >= 0 and max_mcs in HT_MCS_RATES:
                            if supports_40mhz and short_gi_40:
                                rate = HT_MCS_RATES[max_mcs][3]
                            elif supports_40mhz:
                                rate = HT_MCS_RATES[max_mcs][2]
                            elif short_gi_20:
                                rate = HT_MCS_RATES[max_mcs][1]
                            else:
                                rate = HT_MCS_RATES[max_mcs][0]
                            
                            return rate
                    
                except Exception:
                    pass
            
            elt = elt.payload.getlayer(Dot11Elt)
        
        return 0
    
    except Exception:
        return 0


def parse_vht_capabilities(packet):
    """
    Parse VHT Capabilities (Element ID 191) for 802.11ac networks.
    Calculates maximum throughput using comprehensive MCS tables.
    """
    try:
        if not packet.haslayer(Dot11Elt):
            return 0
        
        elt = packet[Dot11Elt]
        
        while elt:
            if elt.ID == 191 and elt.len >= 12:
                try:
                    info = elt.info
                    if isinstance(info, str):
                        info = bytes(info, 'latin-1')
                    vht_cap_info = int.from_bytes(info[0:4], byteorder='little')
                    
                    channel_width_set = (vht_cap_info >> 2) & 0x03
                    if channel_width_set in (1, 2):
                        bandwidth = 160
                    else:
                        bandwidth = 80
                    
                    short_gi_80 = (vht_cap_info & (1 << 5)) != 0
                    short_gi_160 = (vht_cap_info & (1 << 6)) != 0
                    
                    if len(info) >= 6:
                        mcs_map = int.from_bytes(info[4:6], byteorder='little')
                        
                        max_ss = 0
                        max_mcs = 7
                        
                        for ss in range(1, 5):
                            mcs_support = (mcs_map >> ((ss - 1) * 2)) & 0x03
                            if mcs_support != 3:
                                max_ss = ss
                                if mcs_support == 2:
                                    max_mcs = 9
                                elif mcs_support == 1:
                                    max_mcs = 8
                                else:
                                    max_mcs = 7
                        
                        if max_ss > 0 and bandwidth in VHT_MCS_RATES:
                            if max_ss in VHT_MCS_RATES[bandwidth]:
                                if max_mcs in VHT_MCS_RATES[bandwidth][max_ss]:
                                    rates = VHT_MCS_RATES[bandwidth][max_ss][max_mcs]
                                    
                                    if bandwidth == 160 and short_gi_160:
                                        return rates[1]
                                    elif bandwidth == 80 and short_gi_80:
                                        return rates[1]
                                    else:
                                        return rates[0]
                    
                except Exception:
                    pass
            
            elt = elt.payload.getlayer(Dot11Elt)
        
        return 0
    
    except Exception:
        return 0


def parse_he_capabilities(packet):
    """
    Parse HE Capabilities (Element ID Extension 35) for 802.11ax networks.
    Calculates maximum throughput using comprehensive MCS tables.
    """
    try:
        if not packet.haslayer(Dot11Elt):
            return 0
        
        elt = packet[Dot11Elt]
        
        while elt:

            if elt.ID == 255 and elt.len > 1:
                try:
                    info = elt.info
                    if isinstance(info, str):
                        info = bytes(info, 'latin-1')
                    
                    ext_id = info[0] if isinstance(info[0], int) else ord(info[0])
                    
                    if ext_id == 35 and len(info) >= 22:
                        
                        phy_cap_byte0 = info[7] if isinstance(info[7], int) else ord(info[7])
                        
                        supports_160 = (phy_cap_byte0 & 0x0C) != 0
                        supports_80 = (phy_cap_byte0 & 0x04) != 0
                        
                        if supports_160:
                            bandwidth = 160
                        elif supports_80:
                            bandwidth = 80
                        else:
                            bandwidth = 20
                        
                        if len(info) >= 22:
                            mcs_map_80 = int.from_bytes(info[18:20], byteorder='little')
                            
                            max_ss = 0
                            max_mcs = 7
                            
                            for ss in range(1, 5):
                                mcs_support = (mcs_map_80 >> ((ss - 1) * 2)) & 0x03
                                if mcs_support != 3:
                                    max_ss = ss
                                    if mcs_support == 2:
                                        max_mcs = 11
                                    elif mcs_support == 1:
                                        max_mcs = 9
                                    else:
                                        max_mcs = 7
                            
                            if max_ss > 0 and bandwidth in HE_MCS_RATES:
                                if max_ss in HE_MCS_RATES[bandwidth]:
                                    if max_mcs in HE_MCS_RATES[bandwidth][max_ss]:
                                        rates = HE_MCS_RATES[bandwidth][max_ss][max_mcs]
                                        return rates[0]
                    
                except Exception:
                    pass
            
            elt = elt.payload.getlayer(Dot11Elt)
        
        return 0
    
    except Exception:
        return 0


def map_to_airodump_mb(raw_rate):
    """
    Convert calculated rate to nearest standard airodump-ng MB value.
    This ensures consistency with airodump-ng display format.
    """
    if raw_rate <= 0:
        return 54
    
    closest = min(AIRODUMP_MB_VALUES, key=lambda x: abs(x - raw_rate))
    
    return int(closest) if closest == int(closest) else closest


def calculate_mb_value(packet):
    """
    Main function that replicates airodump-ng MB calculation.
    Priority order:
    1. HE Capabilities (802.11ax) - highest priority
    2. VHT Capabilities (802.11ac)
    3. HT Capabilities (802.11n)
    4. Supported Rates (802.11a/b/g)
    5. Fallback to 54 Mbps
    """
    try:
        if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
            return 54
        
        he_rate = parse_he_capabilities(packet)
        if he_rate > 0:
            return map_to_airodump_mb(he_rate)
        
        vht_rate = parse_vht_capabilities(packet)
        if vht_rate > 0:
            return map_to_airodump_mb(vht_rate)
        
        ht_rate = parse_ht_capabilities(packet)
        if ht_rate > 0:
            return map_to_airodump_mb(ht_rate)
        
        legacy_rate = parse_supported_rates(packet)
        if legacy_rate > 0:
            return map_to_airodump_mb(legacy_rate)
        
        return 54
    
    except Exception:
        return 54

class AccessPoint:
    """Represents a discovered access point"""

    def __init__(self, bssid, essid, channel, crypto, cipher, auth, mb=54):
        self.bssid = bssid
        self.essid = essid or "<Hidden>"
        self.channel = channel
        self.crypto = crypto
        self.cipher = cipher
        self.auth = auth
        self.mb = mb
        self.beacons = 0
        self.data_packets = 0
        self.last_data_count = 0
        self.last_rate_update = datetime.now()
        self.current_data_rate = 0
        self.power = -100
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.clients = set()

    def update(self, essid=None, channel=None, power=None, mb=None, 
                crypto=None, cipher=None, auth=None):
        
        """Update access point information"""

        self.last_seen = datetime.now()
        
        if essid and essid != "" and self.essid == "<Hidden>":
            self.essid = essid
        
        if channel and channel != -1 and self.channel == -1:
            self.channel = channel
        
        if power and power > self.power:
            self.power = int(0.7 * self.power + 0.3 * power)
        
        if mb and mb > self.mb:
            self.mb = mb
        
        if crypto:
            self.crypto = crypto
        
        if cipher:
            self.cipher = cipher
        
        if auth:
            self.auth = auth

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
    

def write_csv(filename, aps_dict, clients_dict, ap_lock, client_lock):
    if not filename.endswith('.csv'):
        filename = f"{filename}.csv"
    try: 
        with open(filename, 'w', encoding='utf-8') as f:

            #Sections which handles writing AP's
            f.write("BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
                   "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, "
                   "ESSID, Key\n")
            with ap_lock:
                sorted_aps = sorted(
                    aps_dict.values(),
                    key=lambda x: x.power,
                    reverse=True
                )
                for ap in sorted_aps:
                    first_seen = ap.first_seen.strftime("%Y-%m-%d %H:%M:%S")
                    last_seen = ap.last_seen.strftime("%Y-%m-%d %H:%M:%S")
                    channel = ap.channel if ap.channel != -1 else -1
                    speed = ap.mb
                    privacy = ap.crypto
                    cipher = ap.cipher if ap.cipher else ""
                    authentication = ap.auth if ap.auth else ""

                    power = ap.power
                    beacons = ap.beacons

                    #TODO: this is only related to WEP i'll figure out a way to calculate it later in WEP case.
                    iv_count = 0
                    #this element doesn't matter, it won't be shown at least in the airgraph-ng.
                    lan_ip = "0.0.0.0"
                    essid = ap.essid
                    essid_length = len(essid)
                    #well the key is only available when the AP is cracked. (no need for it anyways).
                    key = ""
                    
                    f.write(f"{ap.bssid}, {first_seen}, {last_seen}, {channel}, "
                           f"{speed}, {privacy}, {cipher}, {authentication}, "
                           f"{power}, {beacons}, {iv_count}, {lan_ip}, "
                           f"{essid_length}, {essid}, {key}\n")
            
            f.write("\n") # this is just a spacer for formatting.
            
            # And sections for clients.
            f.write("Station MAC, First time seen, Last time seen, Power, # packets, "
                   "BSSID, Probed ESSIDs\n")
            
            # Write Client data rows
            with client_lock:
                sorted_clients = sorted(
                    clients_dict.values(),
                    key=lambda x: x.packets,
                    reverse=True
                )
                
                for client in sorted_clients:
                    
                    first_seen = client.first_seen.strftime("%Y-%m-%d %H:%M:%S")
                    last_seen = client.last_seen.strftime("%Y-%m-%d %H:%M:%S")
                    power = client.power
                    packets = client.packets
                    bssid = client.bssid

                    if client.probes:
                        probed_essids = ",".join(sorted(client.probes))
                    else:
                        probed_essids = ""
                    
                    f.write(f"{client.mac}, {first_seen}, {last_seen}, "
                           f"{power}, {packets}, {bssid}, {probed_essids}\n")
        
        print(f"[+] CSV file saved: {filename}")
        return filename
    
    except PermissionError:
        print(f"[!] Permission denied: Cannot write to {filename}")
        return None
    except IOError as e:
        print(f"[!] I/O error writing CSV file: {e}")
        return None
    except Exception as e:
        print(f"[!] Error writing CSV file: {e}")
        import traceback
        traceback.print_exc()
        return None       

def auto_save_csv(filename, aps_dict, clients_dict, ap_lock, client_lock, interval=30):
    """
    Periodically save CSV file in background thread.
    Better than writing all at once on exit.  
    """
    def save_loop():
        """Background thread function for periodic CSV saves"""
        while True:
            try:
                time.sleep(interval)
                write_csv(filename, aps_dict, clients_dict, ap_lock, client_lock)
            except Exception as e:
                pass

    thread = threading.Thread(
        target=save_loop,
        name="csv_auto_save",
        daemon=True
    )
    thread.start()
    
    return thread

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
        
        save_packet(packet)

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
            
            if not matches_essid_filter(essid):
                return
            
            crypto, cipher, auth = get_crypto_info(packet)
            mb_value = calculate_mb_value(packet)
            
            with ap_lock:
                if bssid not in access_points:
                    access_points[bssid] = AccessPoint(
                        bssid, essid, channel, crypto, cipher, auth, mb_value
                    )
                
                ap = access_points[bssid]
                ap.beacons += 1
                ap.update(essid=essid, channel=channel, power=power, mb=mb_value,
                    crypto=crypto, cipher=cipher, auth=auth)            
            
        
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
            
            if not matches_essid_filter(essid):
                return

            crypto, cipher, auth = get_crypto_info(packet)
            mb_value = calculate_mb_value(packet)
            
            with ap_lock:
                if bssid not in access_points:
                    access_points[bssid] = AccessPoint(
                        bssid, essid, channel, crypto, cipher, auth, mb_value
                    )
                
                ap = access_points[bssid]
                ap.update(essid=essid, channel=channel, power=power, mb=mb_value, crypto=crypto, cipher=cipher, auth=auth)
                    
        elif packet.haslayer(Dot11ProbeReq):

            if filter_bssid:
                return
            
            client_mac = addr2
            
            if not is_valid_client_mac(client_mac):
                return
    
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
            
            if not is_valid_client_mac(client_mac):
                return
            
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
            
            if not is_valid_client_mac(client_mac):
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
            
    except Exception as e:
        pass

def display_interface(interface, channel):
    """Display header information with filter status"""
    global start_time, packet_count, filter_bssid, filter_essid_regex
    global filtered_ap_count, total_ap_count
    
    elapsed = datetime.now() - start_time
    elapsed_seconds = int(elapsed.total_seconds())
    
    if channel:
        ch_display = f"CH {channel:>2}"
    else:
        ch_display = "CH  -"
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
    
    filter_status = ""
    if filter_bssid:
        filter_status = f" [ FILTER: BSSID={filter_bssid.upper()} ]"
    elif filter_essid_regex:
        filter_status = f" [ FILTER: ESSID='{filter_essid_regex.pattern}' ]"
        if total_ap_count > 0:
            filter_status += f" [ APs: {filtered_ap_count}/{total_ap_count} ]"
    
    print(f" {ch_display} ][ Elapsed: {elapsed_seconds} s ][ {timestamp}{filter_status}\n")

def display_access_points():
    """Display discovered access points with filter tracking"""
    global filtered_ap_count, total_ap_count
    
    print(" BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID\n")
    
    with ap_lock:
        total_ap_count = len(access_points)
        
        sorted_aps = sorted(
            access_points.values(),
            key=lambda x: x.power,
            reverse=True
        )
        
        filtered_ap_count = len(sorted_aps)
        
        if not sorted_aps:
            print(" No access points detected yet...")
        
        for ap in sorted_aps:

            ch_str = str(ap.channel) if ap.channel != -1 else "-"
            essid = ap.essid[:20] if len(ap.essid) <= 20 else ap.essid[:17] + "..."
            data_rate = ap.current_data_rate
            max_bitrate = ap.mb
            
            print(f" {ap.bssid.upper():17s}  {ap.power:>3d}  {ap.beacons:>7d}    {ap.data_packets:>5d} {data_rate:>4d}  {ch_str:>2s}  {max_bitrate:>3}   {ap.crypto:4s} {ap.cipher:6s}  {ap.auth:4s} {essid}")

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

def start_sniffer(interface, channel=None, output_prefix=None, output_formats=None, target_bssid=None, essid_pattern=None):
    """Start packet capture on the specified interface"""
    global start_time, current_interface, current_channel, output_file
    global filter_bssid, filter_essid_regex
    global hop_thread, hopping_active

    current_interface = interface
    current_channel = channel
    pcap_file = None
    csv_file = None
    filter_bssid = target_bssid
    start_time = datetime.now()
    
    if output_prefix and output_formats:
        if 'pcap' in output_formats or 'both' in output_formats:
            pcap_file = f"{output_prefix}.pcap" if not output_prefix.endswith('.pcap') else output_prefix
        if 'csv' in output_formats or 'both' in output_formats:
            csv_file = f"{output_prefix}.csv" if not output_prefix.endswith('.csv') else output_prefix
            if csv_file.endswith('.pcap'):
                csv_file = csv_file.replace('.pcap', '.csv')
    
    output_file = pcap_file
    
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

    if essid_pattern:
        try:
            filter_essid_regex = re.compile(essid_pattern, re.IGNORECASE)
            print(f"ESSID Filter: Regex pattern '{essid_pattern}'")
        except re.error as e:
            print(f"Error: Invalid regex pattern '{essid_pattern}': {e}")
            sys.exit(1)
    else:
        filter_essid_regex = None
        
    if filter_bssid:
        print(f"Filter: BSSID = {filter_bssid}")
    
    if pcap_file:
        print(f"PCAP Output: {pcap_file}")
    
    if csv_file:
        print(f"CSV Output: {csv_file}")
    
    print(f"\nStarting packet capture...")
    print(f"Initializing... Please wait...\n")
    
    time.sleep(2)

    # Start windowed statistics update thread
    window_stats_thread = threading.Thread(target=update_window_stats, args=(5,), daemon=True)
    window_stats_thread.start()

    display_thread = threading.Thread(target=display_loop, daemon=True)
    display_thread.start()

    csv_thread = None
    if csv_file:
        csv_thread = auto_save_csv(
            csv_file, 
            access_points,
            clients,
            ap_lock, 
            client_lock, 
            interval=30
        )
        print(f"CSV auto-save enabled (every 30 seconds)")

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
        
        if pcap_file and captured_packets:
            print(f"\nWriting {len(captured_packets)} packets to {pcap_file}...")
            try:
                wrpcap(pcap_file, captured_packets)
                print(f"PCAP file saved successfully.")
            except Exception as e:
                print(f"Failed to write PCAP: {e}")

        if csv_file:
            try:
                print(f"Saving final CSV data...")
                write_csv(csv_file, access_points, clients, ap_lock, client_lock)
                print(f"CSV file saved successfully.")

            except Exception as e:
                print(f"Failed to write CSV: {e}")

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
| $$$$$$$  /$$ /$$$$$$    /$$$$$$$ /$$   /$$ /$$$$$$/$$$$   /$$$$$$ 
| $$__  $$| $$|_  $$_/   /$$__  $$| $$  | $$| $$_  $$_  $$ /$$__  $$
| $$  \ $$| $$  | $$    | $$  | $$| $$  | $$| $$ \ $$ \ $$| $$  \ $$
| $$  | $$| $$  | $$ /$$| $$  | $$| $$  | $$| $$ | $$ | $$| $$  | $$
| $$  | $$| $$  |  $$$$/|  $$$$$$$|  $$$$$$/| $$ | $$ | $$| $$$$$$$/
|__/  |__/|__/   \___/   \_______/ \______/ |__/ |__/ |__/| $$____/ 
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
        dest="output_prefix",
        help="Write both PCAP and CSV output files with the given prefix",
        metavar="PREFIX",
    )

    parser.add_argument(
        "--output-format",
        dest="output_format",
        nargs=2,
        metavar=("FORMAT", "PREFIX"),
        help="Write specific format only: 'pcap' or 'csv' followed by file prefix",
    )

    filter_group = parser.add_argument_group('filtering options')
    filter_mutex = filter_group.add_mutually_exclusive_group()
    
    filter_mutex.add_argument(
        "--bssid",
        help="Filter by specific BSSID (MAC address). Only show data for this AP.",
        metavar="MAC",
    )
    
    filter_mutex.add_argument(
        "--essid",
        dest="essid_regex",
        help="Filter APs by ESSID using regex pattern (e.g: '^Home.*', '.*WiFi$', 'Guest|Public')",
        metavar="PATTERN",
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
    
    if args.output_prefix and args.output_format:
        print("Error: Cannot use both -w/--write and --output-format together")
        sys.exit(1)
    
    output_prefix = None
    output_formats = None
    
    if args.output_format:

        format_type = args.output_format[0]
        output_prefix = args.output_format[1]
        
        if format_type not in ['pcap', 'csv']:
            print(f"Error: Invalid format '{format_type}'. Must be 'pcap' or 'csv'")
            sys.exit(1)
        
        output_formats = [format_type]
    
    elif args.output_prefix:

        output_prefix = args.output_prefix
        output_formats = ['both']

    start_sniffer(
        args.interface, 
        args.channel, 
        output_prefix,
        output_formats,
        args.bssid,
        args.essid_regex
    )

if __name__ == "__main__":
    main()