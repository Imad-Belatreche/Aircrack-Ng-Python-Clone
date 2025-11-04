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


# Standard airodump-ng MB values for mapping
AIRODUMP_MB_VALUES = [1, 2, 5.5, 6, 9, 11, 12, 18, 24, 36, 48, 54, 
                      150, 270, 433, 600, 866, 1000, 1200, 1733, 2600, 3466]

# 802.11n HT MCS Rate Tables (Mbps)
# Format: [20MHz, 20MHz+SGI, 40MHz, 40MHz+SGI]
HT_MCS_RATES = {
    # Single spatial stream (MCS 0-7)
    0: [6.5, 7.2, 13.5, 15.0],
    1: [13.0, 14.4, 27.0, 30.0],
    2: [19.5, 21.7, 40.5, 45.0],
    3: [26.0, 28.9, 54.0, 60.0],
    4: [39.0, 43.3, 81.0, 90.0],
    5: [52.0, 57.8, 108.0, 120.0],
    6: [58.5, 65.0, 121.5, 135.0],
    7: [65.0, 72.2, 135.0, 150.0],
    # Two spatial streams (MCS 8-15)
    8: [13.0, 14.4, 27.0, 30.0],
    9: [26.0, 28.9, 54.0, 60.0],
    10: [39.0, 43.3, 81.0, 90.0],
    11: [52.0, 57.8, 108.0, 120.0],
    12: [78.0, 86.7, 162.0, 180.0],
    13: [104.0, 115.6, 216.0, 240.0],
    14: [117.0, 130.0, 243.0, 270.0],
    15: [130.0, 144.4, 270.0, 300.0],
    # Three spatial streams (MCS 16-23)
    16: [19.5, 21.7, 40.5, 45.0],
    17: [39.0, 43.3, 81.0, 90.0],
    18: [58.5, 65.0, 121.5, 135.0],
    19: [78.0, 86.7, 162.0, 180.0],
    20: [117.0, 130.0, 243.0, 270.0],
    21: [156.0, 173.3, 324.0, 360.0],
    22: [175.5, 195.0, 364.5, 405.0],
    23: [195.0, 216.7, 405.0, 450.0],
    # Four spatial streams (MCS 24-31)
    24: [26.0, 28.9, 54.0, 60.0],
    25: [52.0, 57.8, 108.0, 120.0],
    26: [78.0, 86.7, 162.0, 180.0],
    27: [104.0, 115.6, 216.0, 240.0],
    28: [156.0, 173.3, 324.0, 360.0],
    29: [208.0, 231.1, 432.0, 480.0],
    30: [234.0, 260.0, 486.0, 540.0],
    31: [260.0, 288.9, 540.0, 600.0],
}

# 802.11ac VHT MCS Rate Tables (Mbps)
# Format: {bandwidth: {spatial_streams: {mcs: [rate, rate_with_sgi]}}}
# SGI (Short Guard Interval) provides ~11% increase (400ns vs 800ns)
VHT_MCS_RATES = {
    20: {  # 20 MHz channel width
        1: {  # 1 spatial stream
            0: [6.5, 7.2], 1: [13.0, 14.4], 2: [19.5, 21.7], 3: [26.0, 28.9],
            4: [39.0, 43.3], 5: [52.0, 57.8], 6: [58.5, 65.0], 7: [65.0, 72.2],
            8: [78.0, 86.7], 9: [86.7, 96.3]
        },
        2: {  # 2 spatial streams
            0: [13.0, 14.4], 1: [26.0, 28.9], 2: [39.0, 43.3], 3: [52.0, 57.8],
            4: [78.0, 86.7], 5: [104.0, 115.6], 6: [117.0, 130.0], 7: [130.0, 144.4],
            8: [156.0, 173.3], 9: [173.3, 192.4]
        },
        3: {  # 3 spatial streams
            0: [19.5, 21.7], 1: [39.0, 43.3], 2: [58.5, 65.0], 3: [78.0, 86.7],
            4: [117.0, 130.0], 5: [156.0, 173.3], 6: [175.5, 195.0], 7: [195.0, 216.7],
            8: [234.0, 260.0], 9: [260.0, 288.9]
        },
        4: {  # 4 spatial streams
            0: [26.0, 28.9], 1: [52.0, 57.8], 2: [78.0, 86.7], 3: [104.0, 115.6],
            4: [156.0, 173.3], 5: [208.0, 231.1], 6: [234.0, 260.0], 7: [260.0, 288.9],
            8: [312.0, 346.7], 9: [346.7, 385.2]
        },
    },
    40: {  # 40 MHz channel width
        1: {
            0: [13.5, 15.0], 1: [27.0, 30.0], 2: [40.5, 45.0], 3: [54.0, 60.0],
            4: [81.0, 90.0], 5: [108.0, 120.0], 6: [121.5, 135.0], 7: [135.0, 150.0],
            8: [162.0, 180.0], 9: [180.0, 200.0]
        },
        2: {
            0: [27.0, 30.0], 1: [54.0, 60.0], 2: [81.0, 90.0], 3: [108.0, 120.0],
            4: [162.0, 180.0], 5: [216.0, 240.0], 6: [243.0, 270.0], 7: [270.0, 300.0],
            8: [324.0, 360.0], 9: [360.0, 400.0]
        },
        3: {
            0: [40.5, 45.0], 1: [81.0, 90.0], 2: [121.5, 135.0], 3: [162.0, 180.0],
            4: [243.0, 270.0], 5: [324.0, 360.0], 6: [364.5, 405.0], 7: [405.0, 450.0],
            8: [486.0, 540.0], 9: [540.0, 600.0]
        },
        4: {
            0: [54.0, 60.0], 1: [108.0, 120.0], 2: [162.0, 180.0], 3: [216.0, 240.0],
            4: [324.0, 360.0], 5: [432.0, 480.0], 6: [486.0, 540.0], 7: [540.0, 600.0],
            8: [648.0, 720.0], 9: [720.0, 800.0]
        },
    },
    80: {  # 80 MHz channel width
        1: {
            0: [29.3, 32.5], 1: [58.5, 65.0], 2: [87.8, 97.5], 3: [117.0, 130.0],
            4: [175.5, 195.0], 5: [234.0, 260.0], 6: [263.3, 292.5], 7: [292.5, 325.0],
            8: [351.0, 390.0], 9: [390.0, 433.3]
        },
        2: {
            0: [58.5, 65.0], 1: [117.0, 130.0], 2: [175.5, 195.0], 3: [234.0, 260.0],
            4: [351.0, 390.0], 5: [468.0, 520.0], 6: [526.5, 585.0], 7: [585.0, 650.0],
            8: [702.0, 780.0], 9: [780.0, 866.7]
        },
        3: {
            0: [87.8, 97.5], 1: [175.5, 195.0], 2: [263.3, 292.5], 3: [351.0, 390.0],
            4: [526.5, 585.0], 5: [702.0, 780.0], 6: [789.8, 877.5], 7: [877.5, 975.0],
            8: [1053.0, 1170.0], 9: [1170.0, 1300.0]
        },
        4: {
            0: [117.0, 130.0], 1: [234.0, 260.0], 2: [351.0, 390.0], 3: [468.0, 520.0],
            4: [702.0, 780.0], 5: [936.0, 1040.0], 6: [1053.0, 1170.0], 7: [1170.0, 1300.0],
            8: [1404.0, 1560.0], 9: [1560.0, 1733.3]
        },
    },
    160: {  # 160 MHz channel width
        1: {
            0: [58.5, 65.0], 1: [117.0, 130.0], 2: [175.5, 195.0], 3: [234.0, 260.0],
            4: [351.0, 390.0], 5: [468.0, 520.0], 6: [526.5, 585.0], 7: [585.0, 650.0],
            8: [702.0, 780.0], 9: [780.0, 866.7]
        },
        2: {
            0: [117.0, 130.0], 1: [234.0, 260.0], 2: [351.0, 390.0], 3: [468.0, 520.0],
            4: [702.0, 780.0], 5: [936.0, 1040.0], 6: [1053.0, 1170.0], 7: [1170.0, 1300.0],
            8: [1404.0, 1560.0], 9: [1560.0, 1733.3]
        },
        3: {
            0: [175.5, 195.0], 1: [351.0, 390.0], 2: [526.5, 585.0], 3: [702.0, 780.0],
            4: [1053.0, 1170.0], 5: [1404.0, 1560.0], 6: [1579.5, 1755.0], 7: [1755.0, 1950.0],
            8: [2106.0, 2340.0], 9: [2340.0, 2600.0]
        },
        4: {
            0: [234.0, 260.0], 1: [468.0, 520.0], 2: [702.0, 780.0], 3: [936.0, 1040.0],
            4: [1404.0, 1560.0], 5: [1872.0, 2080.0], 6: [2106.0, 2340.0], 7: [2340.0, 2600.0],
            8: [2808.0, 3120.0], 9: [3120.0, 3466.7]
        },
    }
}

# 802.11ax HE MCS Rate Tables (Mbps)
# Format: {bandwidth: {spatial_streams: {mcs: [rate_0.8us_gi, rate_1.6us_gi, rate_3.2us_gi]}}}
# 802.11ax uses 0.8, 1.6, or 3.2 μs guard intervals
HE_MCS_RATES = {
    20: {  # 20 MHz channel width
        1: {  # 1 spatial stream
            0: [8.6, 8.1, 7.3], 1: [17.2, 16.3, 14.6], 2: [25.8, 24.4, 21.9],
            3: [34.4, 32.5, 29.3], 4: [51.6, 48.8, 43.9], 5: [68.8, 65.0, 58.5],
            6: [77.4, 73.1, 65.8], 7: [86.0, 81.3, 73.1], 8: [103.2, 97.5, 87.8],
            9: [114.7, 108.3, 97.5], 10: [129.0, 122.1, 109.9], 11: [143.4, 135.4, 121.9]
        },
        2: {  # 2 spatial streams
            0: [17.2, 16.3, 14.6], 1: [34.4, 32.5, 29.3], 2: [51.6, 48.8, 43.9],
            3: [68.8, 65.0, 58.5], 4: [103.2, 97.5, 87.8], 5: [137.6, 130.0, 117.0],
            6: [154.9, 146.3, 131.6], 7: [172.1, 162.5, 146.3], 8: [206.5, 195.0, 175.5],
            9: [229.4, 216.7, 195.0], 10: [258.1, 244.1, 219.8], 11: [286.8, 270.8, 243.8]
        },
        3: {  # 3 spatial streams
            0: [25.8, 24.4, 21.9], 1: [51.6, 48.8, 43.9], 2: [77.4, 73.1, 65.8],
            3: [103.2, 97.5, 87.8], 4: [154.9, 146.3, 131.6], 5: [206.5, 195.0, 175.5],
            6: [232.3, 219.4, 197.4], 7: [258.1, 243.8, 219.4], 8: [309.7, 292.5, 263.3],
            9: [344.1, 325.0, 292.5], 10: [387.1, 366.1, 329.6], 11: [430.1, 406.3, 365.6]
        },
        4: {  # 4 spatial streams
            0: [34.4, 32.5, 29.3], 1: [68.8, 65.0, 58.5], 2: [103.2, 97.5, 87.8],
            3: [137.6, 130.0, 117.0], 4: [206.5, 195.0, 175.5], 5: [275.3, 260.0, 234.0],
            6: [309.7, 292.5, 263.3], 7: [344.1, 325.0, 292.5], 8: [412.9, 390.0, 351.0],
            9: [458.8, 433.3, 390.0], 10: [516.2, 488.3, 439.5], 11: [573.5, 541.7, 487.5]
        },
    },
    40: {  # 40 MHz channel width
        1: {
            0: [17.2, 16.3, 14.6], 1: [34.4, 32.5, 29.3], 2: [51.6, 48.8, 43.9],
            3: [68.8, 65.0, 58.5], 4: [103.2, 97.5, 87.8], 5: [137.6, 130.0, 117.0],
            6: [154.9, 146.3, 131.6], 7: [172.1, 162.5, 146.3], 8: [206.5, 195.0, 175.5],
            9: [229.4, 216.7, 195.0], 10: [258.1, 244.1, 219.8], 11: [286.8, 270.8, 243.8]
        },
        2: {
            0: [34.4, 32.5, 29.3], 1: [68.8, 65.0, 58.5], 2: [103.2, 97.5, 87.8],
            3: [137.6, 130.0, 117.0], 4: [206.5, 195.0, 175.5], 5: [275.3, 260.0, 234.0],
            6: [309.7, 292.5, 263.3], 7: [344.1, 325.0, 292.5], 8: [412.9, 390.0, 351.0],
            9: [458.8, 433.3, 390.0], 10: [516.2, 488.3, 439.5], 11: [573.5, 541.7, 487.5]
        },
        3: {
            0: [51.6, 48.8, 43.9], 1: [103.2, 97.5, 87.8], 2: [154.9, 146.3, 131.6],
            3: [206.5, 195.0, 175.5], 4: [309.7, 292.5, 263.3], 5: [412.9, 390.0, 351.0],
            6: [464.6, 438.8, 395.1], 7: [516.2, 487.5, 438.8], 8: [619.4, 585.0, 526.5],
            9: [688.2, 650.0, 585.0], 10: [774.2, 732.4, 659.3], 11: [860.3, 812.5, 731.3]
        },
        4: {
            0: [68.8, 65.0, 58.5], 1: [137.6, 130.0, 117.0], 2: [206.5, 195.0, 175.5],
            3: [275.3, 260.0, 234.0], 4: [412.9, 390.0, 351.0], 5: [550.6, 520.0, 468.0],
            6: [619.4, 585.0, 526.5], 7: [688.2, 650.0, 585.0], 8: [825.9, 780.0, 702.0],
            9: [917.6, 866.7, 780.0], 10: [1032.4, 976.5, 878.9], 11: [1147.1, 1083.3, 975.0]
        },
    },
    80: {  # 80 MHz channel width
        1: {
            0: [36.0, 34.0, 30.6], 1: [72.1, 68.1, 61.3], 2: [108.1, 102.1, 91.9],
            3: [144.1, 136.1, 122.5], 4: [216.2, 204.2, 183.8], 5: [288.2, 272.2, 245.0],
            6: [324.3, 306.3, 275.6], 7: [360.3, 340.3, 306.3], 8: [432.4, 408.3, 367.5],
            9: [480.4, 453.7, 408.3], 10: [540.4, 510.4, 459.4], 11: [600.5, 567.1, 510.4]
        },
        2: {
            0: [72.1, 68.1, 61.3], 1: [144.1, 136.1, 122.5], 2: [216.2, 204.2, 183.8],
            3: [288.2, 272.2, 245.0], 4: [432.4, 408.3, 367.5], 5: [576.5, 544.4, 490.0],
            6: [648.5, 612.5, 551.3], 7: [720.6, 680.6, 612.5], 8: [864.7, 816.7, 735.0],
            9: [960.8, 907.4, 816.7], 10: [1080.9, 1020.8, 918.8], 11: [1201.0, 1134.3, 1020.8]
        },
        3: {
            0: [108.1, 102.1, 91.9], 1: [216.2, 204.2, 183.8], 2: [324.3, 306.3, 275.6],
            3: [432.4, 408.3, 367.5], 4: [648.5, 612.5, 551.3], 5: [864.7, 816.7, 735.0],
            6: [972.8, 918.8, 826.9], 7: [1080.9, 1020.8, 918.8], 8: [1297.1, 1225.0, 1102.5],
            9: [1441.2, 1361.1, 1225.0], 10: [1621.3, 1531.3, 1378.1], 11: [1801.4, 1701.4, 1531.3]
        },
        4: {
            0: [144.1, 136.1, 122.5], 1: [288.2, 272.2, 245.0], 2: [432.4, 408.3, 367.5],
            3: [576.5, 544.4, 490.0], 4: [864.7, 816.7, 735.0], 5: [1152.9, 1088.9, 980.0],
            6: [1297.1, 1225.0, 1102.5], 7: [1441.2, 1361.1, 1225.0], 8: [1729.4, 1633.3, 1470.0],
            9: [1921.6, 1814.8, 1633.3], 10: [2161.8, 2041.7, 1837.5], 11: [2401.9, 2268.5, 2041.7]
        },
    },
    160: {  # 160 MHz channel width
        1: {
            0: [72.1, 68.1, 61.3], 1: [144.1, 136.1, 122.5], 2: [216.2, 204.2, 183.8],
            3: [288.2, 272.2, 245.0], 4: [432.4, 408.3, 367.5], 5: [576.5, 544.4, 490.0],
            6: [648.5, 612.5, 551.3], 7: [720.6, 680.6, 612.5], 8: [864.7, 816.7, 735.0],
            9: [960.8, 907.4, 816.7], 10: [1080.9, 1020.8, 918.8], 11: [1201.0, 1134.3, 1020.8]
        },
        2: {
            0: [144.1, 136.1, 122.5], 1: [288.2, 272.2, 245.0], 2: [432.4, 408.3, 367.5],
            3: [576.5, 544.4, 490.0], 4: [864.7, 816.7, 735.0], 5: [1152.9, 1088.9, 980.0],
            6: [1297.1, 1225.0, 1102.5], 7: [1441.2, 1361.1, 1225.0], 8: [1729.4, 1633.3, 1470.0],
            9: [1921.6, 1814.8, 1633.3], 10: [2161.8, 2041.7, 1837.5], 11: [2401.9, 2268.5, 2041.7]
        },
        3: {
            0: [216.2, 204.2, 183.8], 1: [432.4, 408.3, 367.5], 2: [648.5, 612.5, 551.3],
            3: [864.7, 816.7, 735.0], 4: [1297.1, 1225.0, 1102.5], 5: [1729.4, 1633.3, 1470.0],
            6: [1945.6, 1837.5, 1653.8], 7: [2161.8, 2041.7, 1837.5], 8: [2594.1, 2450.0, 2205.0],
            9: [2882.4, 2722.2, 2450.0], 10: [3242.7, 3062.5, 2756.3], 11: [3602.9, 3402.8, 3062.5]
        },
        4: {
            0: [288.2, 272.2, 245.0], 1: [576.5, 544.4, 490.0], 2: [864.7, 816.7, 735.0],
            3: [1152.9, 1088.9, 980.0], 4: [1729.4, 1633.3, 1470.0], 5: [2305.9, 2177.8, 1960.0],
            6: [2594.1, 2450.0, 2205.0], 7: [2882.4, 2722.2, 2450.0], 8: [3458.8, 3266.7, 2940.0],
            9: [3843.2, 3629.6, 3266.7], 10: [4323.5, 4083.3, 3675.0], 11: [4803.8, 4537.0, 4083.3]
        },
    }
}

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

    def update(self, essid=None, channel=None, power=None, mb=None):
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
            mb_value = calculate_mb_value(packet)
            
            with ap_lock:
                if bssid not in access_points:
                    access_points[bssid] = AccessPoint(
                        bssid, essid, channel, crypto, cipher, auth, mb_value
                    )
                
                ap = access_points[bssid]
                ap.beacons += 1
                ap.update(essid=essid, channel=channel, power=power, mb=mb_value)
            
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
            mb_value = calculate_mb_value(packet)
            
            with ap_lock:
                if bssid not in access_points:
                    access_points[bssid] = AccessPoint(
                        bssid, essid, channel, crypto, cipher, auth, mb_value
                    )
                
                ap = access_points[bssid]
                ap.update(essid=essid, channel=channel, power=power, mb=mb_value)
            
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

def start_sniffer(interface, channel=None, output_file_path=None, csv_file_path=None, target_bssid=None):
    """Start packet capture on the specified interface"""
    global start_time, current_interface, current_channel, output_file, filter_bssid

    global hop_thread, hopping_active

    current_interface = interface
    current_channel = channel
    csv_file = csv_file_path
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
        print(f"PCAP Output: {output_file}")
    
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
    if csv_file_path:
        csv_thread = auto_save_csv(
            csv_file_path, 
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
        
        if output_file and captured_packets:
            print(f"\nWriting {len(captured_packets)} packets to {output_file}...")
            try:
                wrpcap(output_file, captured_packets)
                print(f"PCAP file saved successfully.")
            except Exception as e:
                print(f"Failed to write PCAP: {e}")

        if csv_file:
            try:
                print(f"Saving final CSV data...")
                write_csv(csv_file_path, access_points, clients, ap_lock, client_lock)
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
        "-wp",
        "--write-pcap",
        help="Write captured packets to pcap file",
        metavar="FILE",
    )

    parser.add_argument(
        "-b",
        "--bssid",
        help="Filter and monitor only the specified BSSID (MAC address)",
        metavar="MAC",
    )
    parser.add_argument(
        "-wv",
        "--write-csv",
        help="Write AP and client data to CSV file (airodump-ng format)",
        metavar="FILE",
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

    start_sniffer(
        args.interface, 
        args.channel, 
        args.write_pcap,
        args.write_csv,
        args.bssid
    )

if __name__ == "__main__":
    main()