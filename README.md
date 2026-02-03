# Aircrack-Ng-Python-Clone

A simple yet effective set of wireless network penetration testing tools built using Python.

## Main tools

### Hitmon

Enables monitor mode on wireless interfaces, kill network managers or to go from monitor to managed mode

```fish
hitmon -h
usage: hitmon [-h] {proc,start,stop} ...

 /$$       /$$   /$$                                      
| $$      |__/  | $$                                      
| $$$$$$$  /$$ /$$$$$$   /$$$$$$/$$$$   /$$$$$$  /$$$$$$$ 
| $$__  $$| $$|_  $$_/  | $$_  $$_  $$ /$$__  $$| $$__  $$
| $$  \ $$| $$  | $$    | $$ \ $$ \ $$| $$  \ $$| $$  \ $$
| $$  | $$| $$  | $$ /$$| $$ | $$ | $$| $$  | $$| $$  | $$
| $$  | $$| $$  |  $$$$/| $$ | $$ | $$|  $$$$$$/| $$  | $$
|__/  |__/|__/   \___/  |__/ |__/ |__/ \______/ |__/  |__/

Enables monitor mode on wireless interfaces, kill network managers or to go from monitor to managed mode

positional arguments:
  {proc,start,stop}
    proc             Show interfering proccesses
    start            Enable monitor mode on given interface
    stop             Stop monitor mode and back to managed mode

options:
  -h, --help         show this help message and exit

@By NS-Guys
```

### Hitplay

Used to inject and replay wireless frames. Right now, it only performs [**Deauthentication attack**](https://en.wikipedia.org/wiki/Wi-Fi_deauthentication_attack)

```fish
hitplay -h
usage: hitplay [-h] attack-mode ...

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

A tool that does Deauthenticaion attack on wireless devices

positional arguments:
  attack-mode    Attack mode
    deauth       Deauthenticate one station. (Implemented)
    fakeauth     Fake authentication with an access point. (Not Yet)
    interactive  Interactive frame selection. (Not Yet)
    arpreplay    Standard ARP-request replay. (Not Yet)
    chopchop     Decrypt or chopchop a WEP packet. (Not Yet)
    fragment     Generate a valid keystream via fragmentation. (Not Yet)
    caffe-latte  Query a client for new IVs. (Not Yet)
    cfrag        Fragmentation attack against a client. (Not Yet)
    migmode      Attack WPA migration mode. (Not Yet)
    test         Test injection capability and link quality. (Not Yet)

options:
  -h, --help     show this help message and exit

@By NS-Guys
```

### Hitdump

hitdump is a lightweight Wi-Fi scanning and monitoring tool designed to capture and display nearby access points and clients in real time. It operates in monitor mode to extract key details like BSSID, ESSID, signal strength, and channel, and optionally apply filters (e.g., ESSID or BSSID filters).

```fish
hitdump -h
usage: hitdump [-h] [-c CH] [-w PREFIX] [--output-format FORMAT PREFIX] [--bssid MAC | --essid PATTERN] interface

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

Capture and display WiFi networks and clients in real-time

positional arguments:
  interface             The network interface to use.

options:
  -h, --help            show this help message and exit
  -c, --channel CH      Set interface to specific channel (1-14 for 2.4GHz, 36-165 for 5GHz)
  -w, --write PREFIX    Write both PCAP and CSV output files with the given prefix
  --output-format FORMAT PREFIX
                        Write specific format only: 'pcap' or 'csv' followed by file prefix

filtering options:
  --bssid MAC           Filter by specific BSSID (MAC address). Only show data for this AP.
  --essid PATTERN       Filter APs by ESSID using regex pattern (e.g: '^Home.*', '.*WiFi$', 'Guest|Public')

@By NS-Guys
```

### Hitgraph

WiFi network visualization tool that generates graphs from hitdump-ng CSV output. Creates three types of network relationship diagrams with signal strength analysis and client tracking detection.

```fish
hitgraph -h
usage: hitgraph [-h] {carp,cpg,caig,all} ...

     /$$       /$$   /$$                                            /$$      
    | $$      |__/  | $$                                           | $$      
    | $$$$$$$  /$$ /$$$$$$    /$$$$$$   /$$$$$$  /$$$$$$   /$$$$$$ | $$$$$$$ 
    | $$__  $$| $$|_  $$_/   /$$__  $$ /$$__  $$|____  $$ /$$__  $$| $$__  $$
    | $$  \ $$| $$  | $$    | $$  \ $$| $$  \__/ /$$$$$$$| $$  \ $$| $$  \ $$
    | $$  | $$| $$  | $$ /$$| $$  | $$| $$      /$$__  $$| $$  | $$| $$  | $$
    | $$  | $$| $$  |  $$$$/|  $$$$$$$| $$     |  $$$$$$$| $$$$$$$/| $$  | $$
    |__/  |__/|__/   \___/   \____  $$|__/      \_______/| $$____/ |__/  |__/
                             /$$  \ $$                   | $$                
                            |  $$$$$$/                   | $$                
                             \______/                    |__/                

WiFi Network Visualization Tool

positional arguments:
  {carp,cpg,caig,all}
    carp                Client-AP Relationship graph
    cpg                 Common Probe Graph
    caig                Complete Interaction Graph
    all                 Generate all graph types

options:
  -h, --help            show this help message and exit

### Hitcrack

hitcrack is a WPA/WPA2 password cracking tool that extracts 4-way handshakes from capture files and performs dictionary-based attacks to recover wireless passwords.

```fish
hitcrack -h
usage: hitcrack [-h] -c FILE -w FILE -b BSSID [-o FILE] [-p MODE]

   /$$       /$$   /$$                                            /$$      
| $$      |__/  | $$                                           | $$      
| $$$$$$$  /$$ /$$$$$$    /$$$$$$$  /$$$$$$  /$$$$$$   /$$$$$$$| $$   /$$
| $$__  $$| $$|_  $$_/   /$$_____/ /$$__  $$|____  $$ /$$_____/| $$  /$$/
| $$  \ $$| $$  | $$    | $$      | $$  \__/ /$$$$$$$| $$      | $$$$$$/ 
| $$  | $$| $$  | $$ /$$| $$      | $$      /$$__  $$| $$      | $$_  $$ 
| $$  | $$| $$  |  $$$$/|  $$$$$$$| $$     |  $$$$$$$|  $$$$$$$| $$ \  $$
|__/  |__/|__/   \___/   \_______/|__/      \_______/ \_______/|__/  \__/

Capture and analyze WiFi handshakes for WPA/WPA2 cracking

options:
  -h, --help            show this help message and exit
  -c, --capture FILE    Path to .cap file containing handshake
  -w, --wordlist FILE   Path to wordlist file
  -b, --bssid BSSID     Target BSSID (e.g., AA:BB:CC:DD:EE:FF)
  -o, --output FILE     Save handshake packets to .cap file for later use
  -p, --processes MODE  Use 0 for max CPU cores (parallel), or 1 for single-process (default)

@By NS-Guys
```

## Installation

Simple and easy, the installation script will do everything needed:

```bash
sudo chmod +x ./install.sh
sudo ./install.sh
```

## Uninstalling

There is also a script for uninstallation:

```bash
sudo chmod +x ./uninstall.sh
sudo ./uninstall.sh
```

## Used Python libraries

- For parsing command arguments: **argparse**
- For terminal tab autocompletion: **argcomplete**
- For executing system commands: **subprocess** and **os**
- For text colors: **colorama**
- For crafting and editing frames and packets: **scapy**
- For network graph visualization: **graphviz**
