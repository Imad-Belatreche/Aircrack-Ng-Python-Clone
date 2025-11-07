# Aircrack-Ng-Python-Clone

A simple yet effective clone of the known wireless network security tool Aircrack-Ng, built using Python.

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
usage: hitdump [-h] [-c CH] [-wp FILE] [-b MAC] [-wv FILE] [-r PATTERN] interface

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

Capture and display WiFi networks and clients in real-time

positional arguments:
  interface             The network interface to use.

options:
  -h, --help            show this help message and exit
  -c, --channel CH      Set interface to specific channel (1-14 for 2.4GHz, 36-165 for 5GHz)
  -wp, --write-pcap FILE
                        Write captured packets to pcap file
  -b, --bssid MAC       Filter and monitor only the specified BSSID (MAC address)
  -wv, --write-csv FILE
                        Write AP and client data to CSV file (airodump-ng format)
  -r, --regex PATTERN   Filter APs by ESSID using regex pattern (e.g., '^Home.*', '.*WiFi$', 'Guest|Public')

@By NS-Guys
```

## Instalation

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
- For excuting system commands: **subprocess** and **os**
- For text colors: **colorama**
- For crafting and editing farmes and packets: **scapy**
