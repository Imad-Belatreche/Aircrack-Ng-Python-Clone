from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static, Label
from textual.screen import ModalScreen
from textual.containers import Container, ScrollableContainer
from rich.text import Text
from datetime import datetime
import os

class HelpScreen(ModalScreen):
    CSS = """
    HelpScreen {
        align: center middle;
        background: rgba(0,0,0,0.7);
    }
    #help_container {
        width: 80%;
        height: 80%;
        border: solid blue;
        background: $surface;
        padding: 1 2;
    }
    #help_content {
        width: 100%;
        height: auto;
    }
    .help_footer {
        width: 100%;
        text-align: center;
        text-style: bold;
    }
    """
    
    BINDINGS = [("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        help_text = getattr(self.app.context, "HELP_TEXT", "No help available.")
        with Container(id="help_container"):
            with ScrollableContainer():
                yield Static(help_text, id="help_content")
            yield Label("\nPress ESC to close", classes="help_footer")

    def action_dismiss(self) -> None:
        self.dismiss()

class HitDumpApp(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    .box {
        height: 1fr;
        border: solid blue;
    }
    #infobar {
        height: 1;
        dock: top;
        content-align: center middle;
        background: blue;
        color: white;
    }
    #statusbar {
        height: 1;
        dock: top;
        background: $surface-darken-1;
        color: $text;
    }
    """
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("c", "clear_screen", "Clear"),
        ("h", "help", "Help"),
        ("s", "screenshot", "Screenshot"),
    ]

    def __init__(self, context):
        super().__init__()
        self.context = context

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="infobar")
        yield Static(id="statusbar")
        yield DataTable(id="ap_table", classes="box")
        yield DataTable(id="client_table", classes="box")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "HitDump-NG TUI"
        
        ap_table = self.query_one("#ap_table", DataTable)
        ap_table.cursor_type = "row"
        ap_table.add_columns("BSSID", "PWR", "Beacons", "Data", "#/s", "CH", "MB", "ENC", "CIPHER", "AUTH", "ESSID", "SEEN")
        
        client_table = self.query_one("#client_table", DataTable)
        client_table.cursor_type = "row"
        client_table.add_columns("BSSID", "STATION", "PWR", "Rate", "Lost", "Frames", "Probes")

        self.set_interval(1.0, self.update_stats)

    def action_clear_screen(self) -> None:
        """Clear the discovered devices."""
        self.clear_notifications()
        with self.context.ap_lock:
            self.context.access_points.clear()
        with self.context.client_lock:
            self.context.clients.clear()
        
        self.query_one("#ap_table", DataTable).clear()
        self.query_one("#client_table", DataTable).clear()

    def action_help(self) -> None:
        self.clear_notifications()
        self.push_screen(HelpScreen())

    def action_screenshot(self) -> None:
        filename = f"hitdump_screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.svg"
        self.save_screenshot(filename)
        self.notify(f"Screenshot saved to {filename}")

    def _get_signal_bar(self, dbm):
        """Convert dBm to visual bar with color coding"""
        if dbm == -100:
             return Text(f"[{dbm}] " + "░"*8, style="red")

        # Normalize -90 to -30 range to 0-8 blocks
        normalized = max(0, min(60, dbm + 90))
        filled = int((normalized / 60) * 8)
        bar = "█" * filled + "░" * (8 - filled)
        
        text = f"[{dbm}] {bar}"
        
        if dbm > -50:
            style = "green"
        elif dbm > -70:
            style = "yellow"
        else:
            style = "red"
            
        return Text(text, style=style)

    def _get_enc_text(self, enc):
        """Color code encryption type"""
        enc = enc.strip()
        if "OPN" in enc:
            return Text(enc, style="white on red")
        elif "WEP" in enc:
            return Text(enc, style="orange1")
        elif "WPA3" in enc:
            return Text(enc, style="green")
        elif "WPA" in enc: # WPA or WPA2
            return Text(enc, style="yellow")
        return Text(enc)

    def _format_duration(self, start, end):
        """Format duration as 1h 20m or 5m 30s"""
        diff = end - start
        seconds = int(diff.total_seconds())
        m, s = divmod(seconds, 60)
        h, m = divmod(m, 60)
        if h > 0:
            return f"{h}h {m}m"
        else:
            return f"{m}m {s}s"

    def update_stats(self) -> None:
        # Update logic using context
        self.context.data_rate_update() 
        
        start_time = self.context.start_time
        current_interface = self.context.current_interface
        current_channel = self.context.current_channel
        filter_bssid = self.context.filter_bssid
        filter_essid_regex = self.context.filter_essid_regex
        
        now = datetime.now()
        elapsed = now - start_time
        elapsed_seconds = int(elapsed.total_seconds())
        
        ch_display = f"CH {current_channel}" if current_channel else "CH: Hopping"
        timestamp = now.strftime('%Y-%m-%d %H:%M')
        
        filter_status = "None"
        if filter_bssid:
            filter_status = f"BSSID={filter_bssid.upper()}"
        elif filter_essid_regex:
            filter_status = f"ESSID='{filter_essid_regex.pattern}'"

        info_text = f"HitDump-NG | {current_interface} | {ch_display} | {timestamp}"
        self.query_one("#infobar", Static).update(info_text)

        pcap_f = self.context.output_file
        csv_f = self.context.csv_file
        
        file_info = "File: None"
        
        if pcap_f and csv_f:

            prefix = os.path.splitext(pcap_f)[0]
            file_info = f"File Prefix: {os.path.basename(prefix)}"
        elif pcap_f:
            fname = pcap_f
            fsize = "0B"
            if os.path.exists(fname):
                size_bytes = os.path.getsize(fname)
                if size_bytes > 1024*1024:
                    fsize = f"{size_bytes/(1024*1024):.1f}MB"
                elif size_bytes > 1024:
                    fsize = f"{size_bytes/1024:.1f}KB"
                else:
                    fsize = f"{size_bytes}B"
            file_info = f"File: {os.path.basename(fname)} {fsize}"
        elif csv_f:
            fname = csv_f
            fsize = "0B"
            if os.path.exists(fname):
                size_bytes = os.path.getsize(fname)
                if size_bytes > 1024*1024:
                    fsize = f"{size_bytes/(1024*1024):.1f}MB"
                elif size_bytes > 1024:
                    fsize = f"{size_bytes/1024:.1f}KB"
                else:
                    fsize = f"{size_bytes}B"
            file_info = f"File: {os.path.basename(fname)} {fsize}"

        packet_count = self.context.packet_count
        status_text = f"[{file_info}] [Packets: {packet_count:,}] [Interface: {current_interface} | {ch_display}] [Uptime: {elapsed_seconds}s] [Filter: {filter_status}]"
        self.query_one("#statusbar", Static).update(status_text)

        ap_table = self.query_one("#ap_table", DataTable)
        ap_table.clear()
        
        with self.context.ap_lock:
            sorted_aps = sorted(self.context.access_points.values(), key=lambda x: x.power, reverse=True)
            for ap in sorted_aps:
                essid = ap.essid[:20] if len(ap.essid) <= 20 else ap.essid[:17] + "..."
                
                pwr_display = self._get_signal_bar(ap.power)
                enc_display = self._get_enc_text(ap.crypto)
                seen_display = self._format_duration(ap.first_seen, now)

                ap_table.add_row(
                    ap.bssid.upper(),
                    pwr_display,
                    str(ap.beacons),
                    str(ap.data_packets),
                    str(ap.current_data_rate),
                    str(ap.channel) if ap.channel != -1 else "-",
                    str(ap.mb),
                    enc_display,
                    ap.cipher,
                    ap.auth,
                    essid,
                    seen_display
                )

        client_table = self.query_one("#client_table", DataTable)
        client_table.clear()
        
        with self.context.client_lock:
            sorted_clients = sorted(self.context.clients.values(), key=lambda x: x.packets, reverse=True)[:50]
            for client in sorted_clients:
                probes_list = list(client.probes)[:2]
                probes_str = ", ".join(probes_list) if probes_list else ""
                if len(probes_str) > 20:
                    probes_str = probes_str[:17] + "..."
                
                bssid_display = client.bssid.upper() if client.bssid != "(not associated)" else "(not associated)"
                
                pwr_display = self._get_signal_bar(client.power)

                client_table.add_row(
                    bssid_display,
                    client.mac.upper(),
                    pwr_display,
                    "0 - 0", # Rate placeholder for now...
                    str(client.window_lost),
                    str(client.packets),
                    probes_str
                )
