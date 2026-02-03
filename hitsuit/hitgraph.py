#!/usr/bin/env python3
"""
hitgraph - WiFi network visualization tool
Generates graphs from hitdump-ng CSV output files
"""

import sys
import os
import csv
import argparse
from pathlib import Path
from typing import Dict, List, Set, Any
from collections import defaultdict

try:
    from graphviz import Digraph
except ImportError:
    print("Error: graphviz module not found.")
    print("Install it with: pip install graphviz")
    sys.exit(1)


class HitGraphUI:
    """Provides user interface functionality"""
    
    @staticmethod
    def print_header():
        """Display ASCII art header"""
        print(r"""
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
        """)
        


class CSVParser:
    """Parse hitdump-ng CSV files"""
    
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
    """Generate various graph visualizations"""
    
    def __init__(self, data: Dict, output_dir: str = '.'):
        self.data = data
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _create_base_graph(self, name: str) -> Digraph:
        """Create base graph with common attributes"""
        dot = Digraph(name=name, comment=f'Hit Suite {name} Graph')
        dot.attr(rankdir='LR', size='14,14!')
        dot.attr('node', fontname='Arial', fontsize='10')
        dot.attr('edge', fontname='Arial', fontsize='8')
        return dot
    
    def generate_carp(self, min_power: int = -100, show_encryption: bool = True) -> Dict[str, str]:
        """
        Client-AP Relationship Graph
        Shows which clients are connected to which access points
        
        Args:
            min_power: Minimum signal strength to include (-100 to 0)
            show_encryption: Include encryption info in AP labels
        
        Returns:
            Dictionary with output path and statistics
        """
        dot = self._create_base_graph('CARP')
        
        # Track which nodes we've added
        added_aps = set()
        added_clients = set()
        
        # Helper function to sanitize node IDs (replace colons with underscores)
        def sanitize_id(mac_address):
            return mac_address.replace(':', '_')
        
        for ap in self.data['aps']:
            if int(ap.get('power', -100)) < min_power:
                continue
            
            # Create AP node
            essid = ap['essid'] if ap['essid'] else '❌ Hidden'
            if show_encryption:
                ap_label = f"{ap['bssid']}\n{essid}\n[{ap.get('encryption', 'OPN')}]"
            else:
                ap_label = f"{ap['bssid']}\n{essid}"
            
            power = int(ap.get('power', -100))
            # Color code by signal strength
            if power >= -50:
                color = 'lightgreen'
            elif power >= -70:
                color = 'lightblue'
            else:
                color = 'lightgray'
            
            ap_id = sanitize_id(ap['bssid'])
            dot.node(ap_id, ap_label, shape='box', style='filled', 
                    fillcolor=color, penwidth='2')
            added_aps.add(ap_id)
            
            # Add connected clients
            for client in ap['clients']:
                if int(client.get('power', -100)) < min_power:
                    continue
                
                client_label = client['mac']
                packets = client.get('packets', '0')
                client_id = sanitize_id(client['mac'])
                
                if client_id not in added_clients:
                    dot.node(client_id, client_label, shape='ellipse', 
                            style='filled', fillcolor='lightyellow')
                    added_clients.add(client_id)
                
                # Add edge with packet count
                dot.edge(client_id, ap_id, 
                        label=f"{packets} pkts", color='gray')
        
        # Add unassociated clients
        for client in self.data['clients']:
            if client['bssid'] == '(not associated)':
                client_id = sanitize_id(client['mac'])
                if client_id not in added_clients:
                    if int(client.get('power', -100)) < min_power:
                        continue
                        
                    dot.node(client_id, client['mac'], shape='ellipse',
                            style='filled,dashed', fillcolor='pink')
                    added_clients.add(client_id)
        
        output_path = self.output_dir / 'carp_graph'
        dot.render(str(output_path), format='png', cleanup=True)
        
        return {
            'path': f"{output_path}.png",
            'aps': len(added_aps),
            'clients': len(added_clients)
        }
    
    def generate_cpg(self, min_clients: int = 2) -> Dict[str, Any]:
        """
        Common Probe Graph
        Shows clients that probe for the same ESSIDs (potential tracking)
        
        Args:
            min_clients: Minimum number of clients probing for an ESSID to include it
        
        Returns:
            Dictionary with output path and statistics, or None if no data
        """
        dot = self._create_base_graph('CPG')
        
        # Helper to sanitize node IDs
        def sanitize_id(mac_address):
            return mac_address.replace(':', '_')
        
        # Build probe -> clients mapping
        probe_dict = defaultdict(set)
        client_probes = defaultdict(set)
        
        for client in self.data['clients']:
            for probe in client.get('probes', []):
                if probe:  # Skip empty probes
                    probe_dict[probe].add(client['mac'])
                    client_probes[client['mac']].add(probe)
        
        # Filter probes with minimum client count
        filtered_probes = {probe: clients for probe, clients in probe_dict.items() 
                          if len(clients) >= min_clients}
        
        if not filtered_probes:
            return None
        
        # Add nodes and edges
        added_clients = set()
        
        for probe, client_macs in filtered_probes.items():
            # Create probe node with sanitized ID
            probe_id = f"probe_{hash(probe) % 10000}"  # Use hash to avoid special chars
            probe_label = probe.replace('"', '\\"').replace('\n', ' ')
            probe_label = f"{probe}\n({len(client_macs)} clients)"
            dot.node(probe_id, probe_label, shape='box', 
                    style='filled', fillcolor='orange', penwidth='2')
            
            # Add client nodes and edges
            for client_mac in client_macs:
                client_id = sanitize_id(client_mac)
                if client_id not in added_clients:
                    probe_count = len(client_probes[client_mac])
                    client_label = f"{client_mac}\n({probe_count} probes)"
                    dot.node(client_id, client_label, shape='ellipse',
                            style='filled', fillcolor='lightyellow')
                    added_clients.add(client_id)
                
                dot.edge(client_id, probe_id, color='gray', dir='forward')
        
        output_path = self.output_dir / 'cpg_graph'
        dot.render(str(output_path), format='png', cleanup=True)
        
        return {
            'path': f"{output_path}.png",
            'probes': len(filtered_probes),
            'clients': len(added_clients)
        }
    
    def generate_caig(self) -> Dict[str, Any]:
        """
        Client-AP Interaction Graph
        Shows all relationships including unassociated clients and their probes
        
        Returns:
            Dictionary with output path and statistics
        """
        dot = self._create_base_graph('CAIG')
        
        # Helper to sanitize node IDs
        def sanitize_id(mac_address):
            return mac_address.replace(':', '_')
        
        # Add all APs
        ap_count = 0
        for ap in self.data['aps']:
            essid = ap['essid'] if ap['essid'] else '<Hidden>'
            ap_label = f"{ap['bssid']}\n{essid}\nCh: {ap.get('channel', '?')}"
            ap_id = sanitize_id(ap['bssid'])
            dot.node(ap_id, ap_label, shape='box', style='filled',
                    fillcolor='lightblue', penwidth='2')
            ap_count += 1
        
        # Add all clients with their relationships
        client_count = 0
        connection_count = 0
        probe_count = 0
        
        for client in self.data['clients']:
            client_mac = client['mac']
            client_id = sanitize_id(client_mac)
            dot.node(client_id, client_mac, shape='ellipse',
                    style='filled', fillcolor='lightyellow')
            client_count += 1
            
            # Connection to AP (solid line)
            if client['bssid'] != '(not associated)':
                ap_id = sanitize_id(client['bssid'])
                dot.edge(client_id, ap_id, 
                        color='green', style='solid', label='connected')
                connection_count += 1
            
            # Probes (dashed lines)
            for probe in client.get('probes', []):
                if probe:
                    # Check if probe matches any known AP
                    for ap in self.data['aps']:
                        if ap['essid'] == probe:
                            ap_id = sanitize_id(ap['bssid'])
                            dot.edge(client_id, ap_id,
                                   color='orange', style='dashed', label='probe')
                            probe_count += 1
                            break
        
        output_path = self.output_dir / 'caig_graph'
        dot.render(str(output_path), format='png', cleanup=True)
        
        return {
            'path': f"{output_path}.png",
            'aps': ap_count,
            'clients': client_count,
            'connections': connection_count,
            'probes': probe_count
        }


# Subcommand handlers
def handle_carp(args):
    """Handle CARP graph generation"""
    try:
        print(f"\n📂 Parsing CSV file: {args.input}")
        csv_parser = CSVParser(args.input)
        data = csv_parser.parse()
        print(f"✓ Found {len(data['aps'])} APs and {len(data['clients'])} clients\n")
        
        generator = GraphGenerator(data, args.output_dir)
        result = generator.generate_carp(
            min_power=args.min_power,
            show_encryption=not args.no_encryption
        )
        
        print(f"✓ CARP graph saved to {result['path']}")
        print(f"  - Access Points: {result['aps']}")
        print(f"  - Clients: {result['clients']}")
        print()
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


def handle_cpg(args):
    """Handle CPG graph generation"""
    try:
        print(f"\n📂 Parsing CSV file: {args.input}")
        csv_parser = CSVParser(args.input)
        data = csv_parser.parse()
        print(f"✓ Found {len(data['aps'])} APs and {len(data['clients'])} clients\n")
        
        generator = GraphGenerator(data, args.output_dir)
        result = generator.generate_cpg(min_clients=args.min_clients)
        
        if result is None:
            print(f"⚠ CPG: No probes found with at least {args.min_clients} clients")
        else:
            print(f"✓ CPG graph saved to {result['path']}")
            print(f"  - Unique Probes: {result['probes']}")
            print(f"  - Clients: {result['clients']}")
        print()
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


def handle_caig(args):
    """Handle CAIG graph generation"""
    try:
        print(f"\n📂 Parsing CSV file: {args.input}")
        csv_parser = CSVParser(args.input)
        data = csv_parser.parse()
        print(f"✓ Found {len(data['aps'])} APs and {len(data['clients'])} clients\n")
        
        generator = GraphGenerator(data, args.output_dir)
        result = generator.generate_caig()
        
        print(f"✓ CAIG graph saved to {result['path']}")
        print(f"  - Access Points: {result['aps']}")
        print(f"  - Clients: {result['clients']}")
        print(f"  - Active Connections: {result['connections']}")
        print(f"  - Probe Relationships: {result['probes']}")
        print()
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


def handle_all(args):
    """Handle all graph generation"""
    try:
        print(f"\n📂 Parsing CSV file: {args.input}")
        csv_parser = CSVParser(args.input)
        data = csv_parser.parse()
        print(f"✓ Found {len(data['aps'])} APs and {len(data['clients'])} clients\n")
        
        generator = GraphGenerator(data, args.output_dir)
        print("🎨 Generating graphs...\n")
        
        # CARP
        result = generator.generate_carp(
            min_power=args.min_power,
            show_encryption=not args.no_encryption
        )
        print(f"✓ CARP graph saved to {result['path']}")
        print(f"  - Access Points: {result['aps']}")
        print(f"  - Clients: {result['clients']}\n")
        
        # CPG
        result = generator.generate_cpg(min_clients=args.min_clients)
        if result is None:
            print(f"⚠ CPG: No probes found with at least {args.min_clients} clients\n")
        else:
            print(f"✓ CPG graph saved to {result['path']}")
            print(f"  - Unique Probes: {result['probes']}")
            print(f"  - Clients: {result['clients']}\n")
        
        # CAIG
        result = generator.generate_caig()
        print(f"✓ CAIG graph saved to {result['path']}")
        print(f"  - Access Points: {result['aps']}")
        print(f"  - Clients: {result['clients']}")
        print(f"  - Active Connections: {result['connections']}")
        print(f"  - Probe Relationships: {result['probes']}\n")
        
        print("✅ All graphs generated successfully!")
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    """Main entry point with subcommands"""
    main_parser = argparse.ArgumentParser(
        prog='hitgraph',
        description='WiFi network visualization tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
USAGE EXAMPLES:
  hitgraph carp -i capture.csv
  hitgraph cpg -i capture.csv --min-clients 1
  hitgraph caig -i capture.csv -o ./graphs
  hitgraph all -i capture.csv

GRAPH TYPES:
  carp   - Client-AP Relationship (who connects to what)
  cpg    - Common Probe Graph (clients probing same networks)
  caig   - Complete Interaction Graph (all relationships)
  all    - Generate all graph types

For detailed help, use: hitgraph <graph-type> --help

@By NS-Guys
        """
    )
    
    subparsers = main_parser.add_subparsers(title='graph-type', dest='graph_type')
    
    # CARP subcommand
    carp_parser = subparsers.add_parser('carp', help='Client-AP Relationship graph')
    carp_parser.add_argument('-i', '--input', required=True, help='Input CSV file')
    carp_parser.add_argument('-o', '--output-dir', default='.', help='Output directory')
    carp_parser.add_argument('--min-power', type=int, default=-100, help='Minimum signal power')
    carp_parser.add_argument('--no-encryption', action='store_true', help='Hide encryption info')
    carp_parser.set_defaults(func=handle_carp)
    
    # CPG subcommand
    cpg_parser = subparsers.add_parser('cpg', help='Common Probe Graph')
    cpg_parser.add_argument('-i', '--input', required=True, help='Input CSV file')
    cpg_parser.add_argument('-o', '--output-dir', default='.', help='Output directory')
    cpg_parser.add_argument('--min-clients', type=int, default=2, help='Min clients per probe')
    cpg_parser.set_defaults(func=handle_cpg)
    
    # CAIG subcommand
    caig_parser = subparsers.add_parser('caig', help='Complete Interaction Graph')
    caig_parser.add_argument('-i', '--input', required=True, help='Input CSV file')
    caig_parser.add_argument('-o', '--output-dir', default='.', help='Output directory')
    caig_parser.set_defaults(func=handle_caig)
    
    # ALL subcommand
    all_parser = subparsers.add_parser('all', help='Generate all graph types')
    all_parser.add_argument('-i', '--input', required=True, help='Input CSV file')
    all_parser.add_argument('-o', '--output-dir', default='.', help='Output directory')
    all_parser.add_argument('--min-power', type=int, default=-100, help='Minimum signal power')
    all_parser.add_argument('--min-clients', type=int, default=2, help='Min clients per probe')
    all_parser.add_argument('--no-encryption', action='store_true', help='Hide encryption info')
    all_parser.set_defaults(func=handle_all)
    
    # Parse and show header
    args = main_parser.parse_args()
    
    HitGraphUI.print_header()
    
    # Show help if no subcommand
    if not hasattr(args, 'func'):
        main_parser.print_help()
        sys.exit(0)
    
    # Execute subcommand
    args.func(args)


if __name__ == "__main__":
    main()