import psutil
import time
import argparse
import requests
import hashlib
import socket
import csv
import os
from collections import defaultdict
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich import box
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, HostLookupError

class SecurityMonitor:
    def __init__(self, interval, export_file=None):
        self.interval = interval
        self.export_file = export_file
        self.conn_history = defaultdict(list)
        self.ip_cache = {}  # Caches Geo, WHOIS, and DNS
        self.file_hash_cache = {} # Caches SHA256 of exes to save CPU
        self.console = Console()
        self.headers = {'User-Agent': 'SecNetMon/2.0'}
        
        # IOC Heuristics
        self.suspicious_ports = [4444, 3333, 6667, 1337, 31337] # Common C2/Miner ports
        self.suspicious_paths = ['appdata', 'temp', 'users\\public', 'downloads']

    def get_file_hash(self, path):
        """Generates SHA256 hash for IOC matching."""
        if path in self.file_hash_cache:
            return self.file_hash_cache[path]
        
        if not path or not os.path.exists(path) or not os.path.isfile(path):
            return "N/A"

        try:
            sha256_hash = hashlib.sha256()
            with open(path, "rb") as f:
                # Read in chunks to avoid memory issues with large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            digest = sha256_hash.hexdigest()
            self.file_hash_cache[path] = digest
            return digest
        except (PermissionError, OSError):
            return "ACCESS_DENIED"

    def get_ip_details(self, ip):
        """Aggregates Geo, WHOIS, and Reverse DNS."""
        if ip not in self.ip_cache:
            details = {
                'country': 'Unknown',
                'org': 'Unknown',
                'hostname': 'N/A'
            }
            
            # 1. Reverse DNS (PTR)
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                details['hostname'] = hostname
            except:
                pass

            # 2. GeoIP (Fast API)
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    details['country'] = data.get('country', 'Unknown')
                    details['org'] = data.get('isp', 'Unknown')
            except:
                pass

            self.ip_cache[ip] = details
        return self.ip_cache[ip]

    def analyze_risk(self, conn_info):
        """Basic heuristic analysis to flag suspicious connections."""
        risk_score = 0
        flags = []

        # Check Path
        path_lower = conn_info['path'].lower()
        if any(sp in path_lower for sp in self.suspicious_paths):
            risk_score += 1
            flags.append("SUSPICIOUS_PATH")

        # Check Port
        try:
            r_port = int(conn_info['remote'].split(':')[-1])
            if r_port in self.suspicious_ports:
                risk_score += 2
                flags.append("HIGH_RISK_PORT")
        except:
            pass

        # Check Process Name anomalies
        if conn_info['app'] == "svchost.exe" and "windows\\system32" not in path_lower:
             risk_score += 3
             flags.append("IMPOSTOR_SVCHOST")

        return "HIGH" if risk_score >= 2 else "MED" if risk_score == 1 else "LOW", ", ".join(flags)

    def get_connections(self):
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            try:
                # Skip loopback for cleaner 'external' view (optional, kept for full visibility)
                # if conn.raddr and conn.raddr.ip == '127.0.0.1': continue

                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ''
                remote_ip = conn.raddr.ip if conn.raddr else ''
                remote_port = conn.raddr.port if conn.raddr else ''
                remote_addr = f"{remote_ip}:{remote_port}" if remote_ip else ''
                
                pid = conn.pid
                app_name = 'Unknown'
                exe_path = 'N/A'
                file_hash = 'N/A'
                username = 'N/A'

                if pid:
                    try:
                        proc = psutil.Process(pid)
                        app_name = proc.name()
                        exe_path = proc.exe()
                        username = proc.username()
                        file_hash = self.get_file_hash(exe_path)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        app_name = 'System/Protected'
                        exe_path = 'Access Denied'
                
                # Enrich IP Data
                ip_info = self.get_ip_details(remote_ip) if remote_ip else {'country': 'N/A', 'org': 'N/A', 'hostname': 'N/A'}

                conn_data = {
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'pid': pid,
                    'app': app_name,
                    'user': username,
                    'path': exe_path,
                    'hash': file_hash,
                    'local': local_addr,
                    'remote': remote_addr,
                    'status': conn.status,
                    'country': ip_info['country'],
                    'org': ip_info['org'],
                    'hostname': ip_info['hostname']
                }

                # Add risk assessment
                risk_level, risk_flags = self.analyze_risk(conn_data)
                conn_data['risk'] = risk_level
                conn_data['flags'] = risk_flags

                connections.append(conn_data)

            except Exception as e:
                continue
        return connections

    def monitor(self):
        start_time = datetime.now()
        self.console.print(f"[bold green]Starting Security Monitor... (Duration: {self.interval}s)[/bold green]")
        
        try:
            while (datetime.now() - start_time).seconds < self.interval:
                current_conns = self.get_connections()
                for conn in current_conns:
                    # Unique key: PID + Remote Socket (tracks unique sessions)
                    key = (conn['pid'], conn['remote'])
                    if key not in self.conn_history:
                        self.conn_history[key] = conn # Store full object, no list needed for snapshot
                time.sleep(1)
        except KeyboardInterrupt:
            self.console.print("\nMonitoring interrupted by user...")
        
        self.display_results()
        if self.export_file:
            self.export_csv()

    def display_results(self):
        # Create responsive table
        table = Table(
            show_header=True, 
            header_style="bold magenta", 
            box=box.SIMPLE, 
            expand=True,
            title="Active Network Connections & IOCs"
        )
        
        table.add_column("Risk", style="bold red", width=6)
        table.add_column("Process", style="cyan", no_wrap=True)
        table.add_column("PID", style="dim", width=6)
        # CRITICAL FIX: overflow='fold' ensures the full path is shown on new lines if needed
        table.add_column("Full Path", style="dim", overflow="fold", min_width=40) 
        table.add_column("Remote Addr", style="yellow")
        table.add_column("Geo/Org", style="green")
        table.add_column("SHA256 (Truncated)", style="white")

        for key, data in self.conn_history.items():
            # Truncate hash for display, full hash is in CSV
            short_hash = data['hash'][:12] + "..." if len(data['hash']) > 12 else data['hash']
            
            # Combine Geo/Org for space
            geo_org = f"{data['country']}\n{data['org']}"
            
            # Color code risk
            risk_style = "red" if data['risk'] == "HIGH" else "yellow" if data['risk'] == "MED" else "green"

            table.add_row(
                f"[{risk_style}]{data['risk']}[/{risk_style}]",
                data['app'],
                str(data['pid']),
                data['path'],
                f"{data['remote']}\n({data['hostname']})",
                geo_org,
                short_hash
            )
        
        self.console.print(table)

    def export_csv(self):
        if not self.conn_history:
            return
        
        keys = list(self.conn_history.values())[0].keys()
        try:
            with open(self.export_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(self.conn_history.values())
            self.console.print(f"\n[bold green]Success:[/bold green] Full IOC data exported to {self.export_file}")
        except Exception as e:
            self.console.print(f"[bold red]Error exporting CSV:[/bold red] {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cybersecurity Network Monitor (IOC Focused)")
    parser.add_argument('-t', '--time', type=int, default=15,
                       help="Monitoring duration in seconds")
    parser.add_argument('-o', '--output', type=str, default="netmon_iocs.csv",
                       help="CSV file to export full data (default: netmon_iocs.csv)")
    
    args = parser.parse_args()
    
    # Check for Admin privileges (needed for Path/Hash of system processes)
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
    if not is_admin:
        print("WARNING: Not running as Administrator/Root. Some paths and hashes will be Access Denied.")
        time.sleep(2)

    monitor = SecurityMonitor(args.time, args.output)
    monitor.monitor()
