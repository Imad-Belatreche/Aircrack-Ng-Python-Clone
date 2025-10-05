# Aircrack-Ng-Python-Clone

A simple yet effective clone of the known wireless network security tool Aircrack-Ng, built using Python.

## Main tools

### Hitmon

Enables monitor mode on wireless interfaces, kill network managers or to go from monitor to managed mode

```fish
sudo python src/tools/hitmon.py
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
    stop             Go back to managed mode

options:
  -h, --help         show this help message and exit

@By NS-Guys
```

## Used libraries

- For parsing command arguments: **argparse**
- For excuting system commands: **subprocess** and **os**

