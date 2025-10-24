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
