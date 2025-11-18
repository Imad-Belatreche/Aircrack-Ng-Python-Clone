#!/usr/bin/env python3
"""
hitgraph - WiFi network visualization tool
Generates graphs from hitdump CSV output files
"""

import sys
import os
import csv
import argparse
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict

try:
    from graphviz import Digraph
except ImportError:
    print("Error: graphviz module not found.")
    print("Install it with: pip install graphviz")
    sys.exit(1)

class HitGraphUI:
    """
    provide basic UI to user
    """
    def header(self):
            
            print("""
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
                             \______/                    |__/                """)
            print("WiFi Network Visualization Tool")
            print("=" * 60)

class CSVParser:
    """
    Class for parsing hitdump CSV files
    """

    def __init__(self, csv_file: str):
        self.csv_file = csv_file
        self.data = {'aps': [], 'clients': []}
    
    def parse(self) -> Dict:
        """Parse CSV file and return structured data"""
        if not os.path.exists(self.csv_file):
            raise FileNotFoundError(f"CSV file not found: {self.csv_file}")
        
        with open(self.csv_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Split into AP and client sections
        sections = content.split('\n\n')
        if len(sections) < 2:
            raise ValueError("Invalid CSV format: missing AP or client section")
        
        # Parse APs
        ap_lines = sections[0].strip().split('\n')
        if len(ap_lines) > 1:  # Skip if only header
            ap_reader = csv.DictReader(ap_lines)
            for row in ap_reader:
                # Clean whitespace from keys and values
                row = {k.strip(): v.strip() for k, v in row.items()}
                self.data['aps'].append({
                    'bssid': row.get('BSSID', ''),
                    'essid': row.get('ESSID', '<Hidden>'),
                    'channel': row.get('channel', '-1'),
                    'encryption': row.get('Privacy', 'OPN'),
                    'power': row.get('Power', '-100'),
                    'clients': []  # Will be populated from client section
                })
        
        # Parse Clients
        client_lines = sections[1].strip().split('\n')
        if len(client_lines) > 1:  # Skip if only header
            client_reader = csv.DictReader(client_lines)
            for row in client_reader:
                row = {k.strip(): v.strip() for k, v in row.items()}
                client_data = {
                    'mac': row.get('Station MAC', ''),
                    'bssid': row.get('BSSID', '(not associated)'),
                    'power': row.get('Power', '-100'),
                    'packets': row.get('# packets', '0'),
                    'probes': [p.strip() for p in row.get('Probed ESSIDs', '').split(',') if p.strip()]
                }
                self.data['clients'].append(client_data)
                
                # Associate client with AP
                for ap in self.data['aps']:
                    if ap['bssid'] == client_data['bssid']:
                        ap['clients'].append(client_data)
                        break
        
        return self.data      
    
         


class GraphGenerator:
    pass









class dotHitCreat:
    """
    Class for creating graphviz .dot config files
    """
    def __init__(self, hitdict, outdir):
        self.hitdict = hitdict
        self.outdir = outdir
        self.dot = Digraph(comment='Hit Suit Graph')
        self.dot.attr(rankdir='LR') # Left to Right orientation
        #144x144 hard code image size to 12feet x 12feet
        #start graphviz config file
        self.dot.attr(size='14,14!')



    def CARP(self):
        """
        Client AP relationship graph
        Display a graph showing what clients are talking to what AP's
        """
        for ap in self.hitdict['aps']:
            ap_label = f"{ap['bssid']}\n{ap['essid']}"
            self.dot.node(ap['bssid'], ap_label, shape='box', style='filled', fillcolor='lightblue')
            for client in ap['clients']:
                client_label = f"{client['mac']}"
                self.dot.node(client['mac'], client_label, shape='ellipse', style='filled', fillcolor='lightgreen')
                self.dot.edge(client['mac'], ap['bssid'])
        
        output_path = os.path.join(self.outdir, 'carp_graph')
        self.dot.render(output_path, format='png', cleanup=True)
        print(f"CARP graph saved to {output_path}.png")
        return

    def CPG(self):
        """
        Common Probe Graph
        Shows a graph of every client requesting similar probes
        """
        probe_dict = {}
        for ap in self.hitdict['aps']:
            for client in ap['clients']:
                for probe in client.get('probes', []):
                    if probe not in probe_dict:
                        probe_dict[probe] = []
                    probe_dict[probe].append(client['mac'])
        
        for probe, clients in probe_dict.items():
            probe_label = f"Probe: {probe}"
            self.dot.node(probe, probe_label, shape='box', style='filled', fillcolor='orange')
            for client_mac in clients:
                client_label = f"{client_mac}"
                self.dot.node(client_mac, client_label, shape='ellipse', style='filled', fillcolor='lightgreen')
                self.dot.edge(client_mac, probe)
        
        output_path = os.path.join(self.outdir, 'cpg_graph')
        self.dot.render(output_path, format='png', cleanup=True)
        print(f"CPG graph saved to {output_path}.png")
        return 
    




def main():
    pass











if __name__ == "__main__":
    main()