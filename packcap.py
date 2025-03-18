#!/usr/bin/env python3
import os
import sys
import socket
import csv
from collections import Counter
from datetime import datetime, timezone
from scapy.all import sniff, wrpcap, rdpcap, get_if_list, get_if_addr, load_layer
import pyshark
import subprocess
import json
import time
import pandas as pd

# Load TLS layer explicitly
load_layer("tls")

# Import the complete cipher suite mapping from external file
from cipher_suites import CIPHER_SUITES

# Attempt to import netifaces for interface details
try:
    import netifaces
except ImportError:
    netifaces = None

# Attempt to import TLS layers
try:
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
    tls_available = True
except ImportError:
    tls_available = False

# Import DNS layers for domain name extraction
from scapy.layers.dns import DNS, DNSQR

# Import Rich components for beautiful output
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.text import Text
from rich.padding import Padding
from rich.style import Style

console = Console()

# Default settings
defaults = {
    'interface': None,
    'src_ip': '',
    'dst_ip': '',
    'protocol': '',
    'capture_file': 'capture.pcap',
    'project_path': ''
}

def set_default_interface():
    """Automatically select the first non-loopback interface."""
    interfaces = get_if_list()
    for iface in interfaces:
        if iface != "lo":
            defaults['interface'] = iface
            break
    if not defaults['interface']:
        defaults['interface'] = "eth0"

def clear_screen():
    os.system('clear')

def print_banner():
    """Display a centered ASCII banner with consistent styling."""
    banner_text = r"""
            ██╗██████╗ ███████╗
            ██║██╔══██╗╚══███╔╝
            ██║██║  ██║  ███╔╝ 
       ██   ██║██║  ██║ ███╔╝  
       ╚█████╔╝██████╔╝███████╗
        ╚════╝ ╚═════╝ ╚══════╝

Advanced Network & Packet Analysis Tool
         Cybersecurity Edition
    """
    
    # Align the entire banner block to center
    banner = Panel(
        Align.center(banner_text, vertical="middle"),
        box=box.DOUBLE,
        style="bold cyan",
        expand=False,
        padding=(1, 2)  # Consistent padding for better alignment
    )
    console.print(Align.center(banner))

def manage_project():
    """Manage projects by listing existing folders or creating a new one."""
    clear_screen()
    console.print(Panel.fit("[bold cyan]Project Management[/bold cyan]", box=box.DOUBLE))
    
    # Get the directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    projects_dir = script_dir
    
    # Filter Function to Exclude Temporary Folders
    def is_valid_project(folder_name):
        return (
            not folder_name.startswith('.') and   # Exclude hidden folders
            not (folder_name.startswith('__') and folder_name.endswith('__'))  # Exclude __pycache__, __init__, etc.
        )
    
    # List relevant project folders
    existing_projects = [
        f for f in os.listdir(projects_dir)
        if os.path.isdir(os.path.join(projects_dir, f)) and is_valid_project(f)
    ]
    
    console.print("[bold magenta]Available Projects:[/bold magenta]")
    
    if existing_projects:
        table = Table(title="Projects", box=box.SIMPLE)
        table.add_column("No.", justify="right", style="cyan", no_wrap=True)
        table.add_column("Project Name", style="green")
        
        for idx, proj in enumerate(existing_projects, 1):
            table.add_row(str(idx), proj)
        
        console.print(table)
    else:
        console.print("[yellow]No existing projects found.[/yellow]")
    
    # Add an option to create a new project
    console.print("\n[bold cyan]Options:[/bold cyan]")
    console.print("[bold yellow]0. Create New Project[/bold yellow]")
    console.print("[bold yellow]Q. Go Back to Main Menu[/bold yellow]")
    
    choice = console.input("\n[bold yellow]Select project number, 0 to create new, or Q to go back: [/bold yellow]").strip().lower()
    
    # Handle user's choice
    if choice == 'q':
        return
    
    # Create New Project
    if choice == '0':
        new_project_name = console.input("[bold yellow]Enter new project name: [/bold yellow]").strip()
        new_project_path = os.path.join(projects_dir, new_project_name)
        
        if not new_project_name:
            console.print("[red]Project name cannot be empty. Returning to Project Management...[/red]")
            return
        
        if os.path.exists(new_project_path):
            console.print("[red]A project with this name already exists. Choose a different name.[/red]")
            return
        
        try:
            os.makedirs(new_project_path)
            console.print(f"[green]New project '{new_project_name}' created successfully![/green]")
            defaults['project_path'] = new_project_path
        except Exception as e:
            console.print(f"[red]Failed to create project folder. Error: {str(e)}[/red]")
        return

    # Select Existing Project
    try:
        idx = int(choice)
        if 1 <= idx <= len(existing_projects):
            selected_project = existing_projects[idx - 1]
            defaults['project_path'] = os.path.join(projects_dir, selected_project)
            console.print(f"[green]Selected Project:[/green] {selected_project}")
        else:
            console.print("[red]Invalid selection. Returning to Project Management...[/red]")
    except ValueError:
        console.print("[red]Invalid input. Returning to Project Management...[/red]")

    # Set project_path as the default for the entire script
    os.chdir(defaults['project_path'])
    console.print(f"[cyan]Default path set to:[/cyan] {defaults['project_path']}")

def display_defaults():
    """Display current default settings in a center-aligned table, including selected project."""
    table = Table(title="Current Default Settings", box=box.SIMPLE_HEAVY)
    table.add_column("Setting", style="bold", justify="center")
    table.add_column("Value", style="magenta", justify="center")
    
    # Network Interface Details
    table.add_row("Network Interface", defaults['interface'] if defaults['interface'] else "Not Set")
    table.add_row("Source IP", defaults['src_ip'] if defaults['src_ip'] else "Any")
    table.add_row("Destination IP", defaults['dst_ip'] if defaults['dst_ip'] else "Any")
    table.add_row("Protocol Filter", defaults['protocol'] if defaults['protocol'] else "Any")
    table.add_row("Capture File", defaults['capture_file'])
    
    # Display Selected Project
    selected_project = (
        os.path.basename(defaults['project_path']) if defaults['project_path'] else "None"
    )
    table.add_row("Selected Project", selected_project)
    
    console.print(Align.center(table))

def get_interface_details():
    """Get details (IP and MAC Address) for all available network interfaces."""
    interface_details = []
    interfaces = get_if_list()
    
    for iface in interfaces:
        ip_addr = "N/A"
        mac_addr = "N/A"
        
        # Get IP Address
        try:
            ip_addr = get_if_addr(iface)
        except Exception:
            ip_addr = "N/A"
        
        # Get MAC Address using netifaces (if available)
        if netifaces:
            try:
                if netifaces.AF_LINK in netifaces.ifaddresses(iface):
                    mac_addr = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
            except Exception:
                mac_addr = "N/A"
        
        interface_details.append({
            "name": iface,
            "ip": ip_addr,
            "mac": mac_addr
        })
    
    return interface_details

def choose_interface():
    """Enhanced interface selection with IP and MAC Address details."""
    interface_details = get_interface_details()
    table = Table(title="Available Network Interfaces", box=box.SIMPLE_HEAVY)
    table.add_column("No.", justify="right", style="cyan", no_wrap=True)
    table.add_column("Interface", style="green")
    table.add_column("IP Address", style="magenta")
    table.add_column("MAC Address", style="yellow")
    
    for idx, detail in enumerate(interface_details, 1):
        table.add_row(
            str(idx),
            detail["name"],
            detail["ip"],
            detail["mac"]
        )
    
    console.print(table)
    choice = console.input("[bold yellow]Select interface number (or press Enter for default): [/bold yellow]").strip()
    
    if choice:
        try:
            idx = int(choice)
            if 1 <= idx <= len(interface_details):
                return interface_details[idx - 1]["name"]
            else:
                console.print("[red]Invalid selection. Using default.[/red]")
                return defaults['interface']
        except ValueError:
            console.print("[red]Invalid input. Using default.[/red]")
            return defaults['interface']
    
    return defaults['interface']

def choose_src_ip(interface):
    ips = []
    if netifaces:
        try:
            addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET]
            ips = [addr['addr'] for addr in addresses]
        except Exception:
            ips = []
    else:
        ips = [get_if_addr(interface)]
    if ips:
        table = Table(title=f"Available Source IPs for {interface}", box=box.SIMPLE)
        table.add_column("No.", justify="right", style="cyan", no_wrap=True)
        table.add_column("IP Address", style="green")
        for idx, ip in enumerate(ips, 1):
            table.add_row(str(idx), ip)
        console.print(table)
        choice = console.input("[bold yellow]Select source IP number (or press Enter for any): [/bold yellow]").strip()
        if choice:
            try:
                idx = int(choice)
                if 1 <= idx <= len(ips):
                    return ips[idx - 1]
                else:
                    console.print("[red]Invalid selection. Using 'Any'.[/red]")
                    return ''
            except ValueError:
                console.print("[red]Invalid input. Using 'Any'.[/red]")
                return ''
        else:
            return ''
    else:
        console.print("[red]No IP suggestions available. Using 'Any'.[/red]")
        return ''

def choose_dst_ip(interface):
    ip = console.input("[bold yellow]Enter destination IP (or press Enter for any): [/bold yellow]").strip()
    return ip

def choose_protocol():
    """Protocol selection with multiple choices and optional custom port."""
    protocol_options = {
        '1': ("HTTP", 80),
        '2': ("HTTPS", 443),
        '3': ("DNS", 53),
        '4': ("mDNS", 5353),
        '5': ("FTP", 21),
        '6': ("SSH", 22),
        '7': ("SMTP", 25),
        '8': ("POP3", 110),
        '9': ("IMAP", 143),
        '10': ("Telnet", 23)
    }

    # Display Protocol Options with Default Ports
    table = Table(title="Protocol Filter Options", box=box.SIMPLE_HEAVY)
    table.add_column("No.", justify="right", style="cyan", no_wrap=True)
    table.add_column("Protocol", style="green")
    table.add_column("Default Port", justify="center", style="magenta")

    for key, (proto, port) in protocol_options.items():
        table.add_row(key, proto, str(port))
    table.add_row("11", "Custom Port", "Manual Entry")

    console.print(table)

    # User Input
    selected_protocols = console.input(
        "[bold yellow]Select protocol numbers to add (separate with spaces): [/bold yellow]"
    ).strip().split()

    # Collect Filters
    additional_filters = []

    # Process Selected Protocols
    for choice in selected_protocols:
        if choice in protocol_options:
            proto, port = protocol_options[choice]
            additional_filters.append(f"port {port}")
        elif choice == '11':
            # Custom Port Entry
            custom_port = console.input("[bold yellow]Enter a custom port (or press Enter to skip): [/bold yellow]").strip()
            if custom_port.isdigit() and 0 < int(custom_port) < 65536:
                additional_filters.append(f"port {custom_port}")
            else:
                console.print("[red]Invalid custom port. Skipping.[/red]")
        else:
            console.print(f"[red]Invalid selection: {choice}. Skipping.[/red]")

    # Build Filter String
    if additional_filters:
        filter_str = " or ".join(additional_filters)
        console.print(f"[cyan]Selected Protocol Filters:[/cyan] {filter_str}")
        return filter_str

    console.print("[green]No protocol filters selected. Using default (Any).[/green]")
    return ''

def modify_defaults():
    clear_screen()
    console.print(Panel.fit("[bold cyan]Modify Default Settings[/bold cyan]", box=box.DOUBLE))
    new_iface = choose_interface()
    defaults['interface'] = new_iface
    console.print(f"[cyan]Selected Interface:[/cyan] {new_iface}")
    new_src = choose_src_ip(new_iface)
    defaults['src_ip'] = new_src
    console.print(f"[cyan]Selected Source IP:[/cyan] {new_src if new_src else 'Any'}")
    new_dst = choose_dst_ip(new_iface)
    defaults['dst_ip'] = new_dst
    console.print(f"[cyan]Selected Destination IP:[/cyan] {new_dst if new_dst else 'Any'}")
    new_proto = choose_protocol()
    defaults['protocol'] = new_proto
    console.print(f"[cyan]Selected Protocol:[/cyan] {new_proto if new_proto else 'Any'}")
    new_file = console.input(f"[bold yellow]Enter Capture File Name (current: {defaults['capture_file']}): [/bold yellow]").strip()
    if new_file:
        defaults['capture_file'] = new_file + '.pcap'
    console.print(Panel.fit("[bold green]Defaults updated.[/bold green]", box=box.SIMPLE))
    console.input("[bold yellow]Press Enter to return to the main menu...[/bold yellow]")

def capture_packets():
    clear_screen()
    filters = []
    if defaults['src_ip']:
        filters.append(f"src {defaults['src_ip']}")
    if defaults['dst_ip']:
        filters.append(f"dst {defaults['dst_ip']}")
    if defaults['protocol']:
        filters.append(defaults['protocol'])
    filter_str = " and ".join(filters) if filters else None
    
    console.print(Panel.fit("[bold cyan]Packet Capture[/bold cyan]", box=box.DOUBLE))
    console.print(f"[blue]Interface:[/blue] {defaults['interface']}")
    console.print(f"[blue]Filter:[/blue] {filter_str if filter_str else 'None'}")
    console.print(f"[yellow]Press Ctrl+C to stop capturing...[/yellow]\n")
    
    packets = []
    try:
        sniff(iface=defaults['interface'], filter=filter_str, prn=lambda pkt: (console.print(f"[green]{pkt.summary()}[/green]"), packets.append(pkt)))
    except KeyboardInterrupt:
        pass

    # Prompt for file name, default to timestamped name if no input
    capture_file_name = console.input("[bold yellow]Enter Capture File Name (or press Enter for timestamped name): [/bold yellow]").strip()
    
    if not capture_file_name:  # If no input, use timestamped default
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        defaults['capture_file'] = f"capture_{timestamp}.pcap"
    else:
        defaults['capture_file'] = capture_file_name + '.pcap'

    # Determine output file path
    if defaults['project_path']:
        # Ensure the project directory exists
        if not os.path.exists(defaults['project_path']):
            os.makedirs(defaults['project_path'])
        output_file = os.path.join(defaults['project_path'], defaults['capture_file'])
    else:
        output_file = defaults['capture_file']
    
    # Save the captured packets to the output file
    try:
        wrpcap(output_file, packets)
        console.print(Panel.fit(f"[bold cyan]Capture stopped. {len(packets)} packets saved to {output_file}[/bold cyan]", box=box.DOUBLE))
    except Exception as e:
        console.print(f"[red]Failed to save capture file: {e}[/red]")
    
    console.input("[bold yellow]Press Enter to return to the main menu...[/bold yellow]")
 
def resolve_cipher(cipher):
    """Resolve a cipher suite code to its human‑readable name and recommended flag.
       Returns a tuple: (name, recommended)"""
    try:
        if isinstance(cipher, int):
            code = cipher
        elif isinstance(cipher, str):
            if cipher.startswith("0x") or cipher.startswith("0X"):
                code = int(cipher, 16)
            else:
                code = int(cipher)
        else:
            code = int(cipher)
    except Exception:
        return (str(cipher), False)
    if code in CIPHER_SUITES:
        return CIPHER_SUITES[code]
    else:
        return (f"0x{code:04x}", False)

def build_dns_map(packets):
    """Build a mapping from IP to domain names based on DNS answer records."""
    dns_map = {}
    for pkt in packets:
        if pkt.haslayer(DNS):
            dns_layer = pkt[DNS]
            if dns_layer.an:
                try:
                    for i in range(dns_layer.ancount):
                        rr = dns_layer.an[i] if dns_layer.ancount > 1 else dns_layer.an
                        if rr.type == 1:
                            ip = rr.rdata
                            name = rr.rrname.decode() if isinstance(rr.rrname, bytes) else rr.rrname
                            dns_map.setdefault(ip, []).append(name)
                except Exception:
                    rr = dns_layer.an
                    if rr and rr.type == 1:
                        ip = rr.rdata
                        name = rr.rrname.decode() if isinstance(rr.rrname, bytes) else rr.rrname
                        dns_map.setdefault(ip, []).append(name)
    return dns_map

def resolve_ip_with_hostname(ip, dns_map=None):
    """Return IP with domain name from DNS map if available; otherwise, perform reverse DNS lookup."""
    if dns_map and ip in dns_map:
        names = ", ".join(sorted(set(dns_map[ip])))
        return f"{ip} ({names})"
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return f"{ip} ({hostname})"
        else:
            return ip
    except Exception:
        return ip

def export_tls_sessions_to_csv(sessions, dns_map, specific_session=None):
    """Export TLS sessions data to a CSV file."""
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    
    # File naming convention
    if specific_session:
        client_ip, server_ip = specific_session
        filename = f"tls_session_{client_ip}_{server_ip}_{timestamp}.csv"
    else:
        filename = f"tls_sessions_{timestamp}.csv"
    
    # Save file to the current project directory
    file_path = os.path.join(defaults['project_path'], filename) if defaults['project_path'] else filename
    
    # CSV Header
    headers = ["Client Address", "Server Address", "Offered Cipher Suite", 
               "Offered Best Practice", "Selected Cipher Suite", "Selected Best Practice"]
    
    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        
        # Export either all sessions or a specific one
        for session in sessions:
            if specific_session and (session["client"], session["server"]) != specific_session:
                continue
            
            # Resolve IP with Domain Name
            client_addr = resolve_ip_with_hostname(session['client'], dns_map)
            server_addr = resolve_ip_with_hostname(session['server'], dns_map)
            
            # Selected Cipher Details (Once per Session)
            selected_name, selected_rec = session["selected"]
            selected_cipher = f"{selected_name}"
            selected_best_practice = "Yes" if selected_rec else "No"
            
            # Format Offered Ciphers - Each Cipher Suite on a New Row
            if session['offered']:
                # Flag to display Client and Server Address only once per session
                first_row = True
                for name, rec in session['offered']:
                    offered_cipher = name
                    offered_best_practice = "Yes" if rec else "No"
                    
                    # Display Client/Server Address and Selected Cipher only once per session
                    if first_row:
                        writer.writerow([
                            client_addr, 
                            server_addr, 
                            offered_cipher, 
                            offered_best_practice, 
                            selected_cipher, 
                            selected_best_practice
                        ])
                        first_row = False
                    else:
                        # Leave Client/Server Address and Selected Cipher empty for subsequent rows
                        writer.writerow([
                            "", 
                            "", 
                            offered_cipher, 
                            offered_best_practice, 
                            "", 
                            ""
                        ])
            else:
                # If no offered ciphers, still write the session details once
                writer.writerow([
                    client_addr, 
                    server_addr, 
                    "N/A", 
                    "N/A", 
                    selected_cipher, 
                    selected_best_practice
                ])
    
    console.print(f"[green]TLS session data exported successfully to {file_path}[/green]")

def advanced_packet_analysis(packets):
    clear_screen()
    console.print(Panel.fit("[bold cyan]Advanced Packet Analysis[/bold cyan]", box=box.DOUBLE))
    total = len(packets)
    console.print(f"[blue]Total Packets:[/blue] {total}\n")
    
    dns_map = build_dns_map(packets)
    
    # Basic Protocol Distribution
    tcp_count = udp_count = icmp_count = other_count = syn_count = 0
    for pkt in packets:
        if pkt.haslayer("TCP"):
            tcp_count += 1
            if pkt["TCP"].flags & 0x02 and not (pkt["TCP"].flags & 0x10):
                syn_count += 1
        elif pkt.haslayer("UDP"):
            udp_count += 1
        elif pkt.haslayer("ICMP"):
            icmp_count += 1
        else:
            other_count += 1
    proto_table = Table(title="Protocol Distribution", box=box.MINIMAL_DOUBLE_HEAD)
    proto_table.add_column("Protocol", style="bold")
    proto_table.add_column("Count", justify="right")
    proto_table.add_column("Percentage", justify="right")
    if total:
        proto_table.add_row("TCP", str(tcp_count), f"{(tcp_count/total)*100:5.2f}%")
        proto_table.add_row("UDP", str(udp_count), f"{(udp_count/total)*100:5.2f}%")
        proto_table.add_row("ICMP", str(icmp_count), f"{(icmp_count/total)*100:5.2f}%")
        proto_table.add_row("Other", str(other_count), f"{(other_count/total)*100:5.2f}%")
    console.print(proto_table)
    if tcp_count:
        syn_ratio = syn_count / tcp_count
        console.print(f"[blue]TCP SYN Packets:[/blue] {syn_count} ({syn_ratio*100:5.2f}%)")
        if syn_ratio > 0.5:
            console.print(Panel.fit("[red]WARNING: High SYN ratio detected![/red]", style="red"))
        else:
            console.print(Panel.fit("[green]SYN ratio appears normal.[/green]", style="green"))
    
    # Top Talkers with DNS mapping
    src_ips = [pkt["IP"].src for pkt in packets if pkt.haslayer("IP")]
    dst_ips = [pkt["IP"].dst for pkt in packets if pkt.haslayer("IP")]
    if src_ips:
        top_src = Counter(src_ips).most_common(5)
        src_table = Table(title="Top Source IPs", box=box.SIMPLE)
        src_table.add_column("Source IP (Hostname)", style="bold")
        src_table.add_column("Packets", justify="right")
        for ip, count in top_src:
            src_table.add_row(resolve_ip_with_hostname(ip, dns_map), str(count))
        console.print(src_table)
    if dst_ips:
        top_dst = Counter(dst_ips).most_common(5)
        dst_table = Table(title="Top Destination IPs", box=box.SIMPLE)
        dst_table.add_column("Destination IP (Hostname)", style="bold")
        dst_table.add_column("Packets", justify="right")
        for ip, count in top_dst:
            dst_table.add_row(resolve_ip_with_hostname(ip, dns_map), str(count))
        console.print(dst_table)
    
    # DNS Analysis: Queries
    dns_queries = []
    for pkt in packets:
        if pkt.haslayer(DNS):
            dns_layer = pkt[DNS]
            if dns_layer.qd:
                domain = dns_layer.qd.qname.decode() if isinstance(dns_layer.qd.qname, bytes) else dns_layer.qd.qname
                dns_queries.append(domain)
    if dns_queries:
        dns_table = Table(title="DNS Queries", box=box.SIMPLE)
        dns_table.add_column("Domain", style="bold")
        dns_table.add_column("Count", justify="right")
        for domain, count in Counter(dns_queries).most_common(10):
            dns_table.add_row(domain, str(count))
        console.print(dns_table)
    else:
        console.print("[red]No DNS queries found.[/red]")
    
    # DNS Answers: Resolved
    dns_answers = []
    for pkt in packets:
        if pkt.haslayer(DNS):
            dns_layer = pkt[DNS]
            if dns_layer.an:
                try:
                    for i in range(dns_layer.ancount):
                        ans = dns_layer.an[i] if dns_layer.ancount > 1 else dns_layer.an
                        if ans.type == 1:
                            dns_answers.append(ans.rdata)
                except Exception:
                    ans = dns_layer.an
                    if ans and ans.type == 1:
                        dns_answers.append(ans.rdata)
    if dns_answers:
        dns_ans_table = Table(title="DNS Answers (Resolved)", box=box.SIMPLE)
        dns_ans_table.add_column("IP (Hostname)", style="bold")
        dns_ans_table.add_column("Responses", justify="right")
        for ip, count in Counter(dns_answers).most_common(10):
            dns_ans_table.add_row(resolve_ip_with_hostname(ip, dns_map), str(count))
        console.print(dns_ans_table)
    
    # Additional Analysis: Packet Size & ARP
    pkt_sizes = [len(pkt) for pkt in packets]
    if pkt_sizes:
        min_size = min(pkt_sizes)
        max_size = max(pkt_sizes)
        avg_size = sum(pkt_sizes) / len(pkt_sizes)
        console.print(f"[blue]Packet Size:[/blue] Min: {min_size}  Max: {max_size}  Avg: {avg_size:5.2f} bytes")
    else:
        console.print("[red]No packet size data available.[/red]")
    
    arp_requests = arp_replies = 0
    arp_map = {}
    for pkt in packets:
        if pkt.haslayer("ARP"):
            arp = pkt["ARP"]
            if arp.op == 1:
                arp_requests += 1
            elif arp.op == 2:
                arp_replies += 1
                ip = arp.psrc
                mac = arp.hwsrc
                arp_map.setdefault(ip, set()).add(mac)
    console.print(f"[blue]ARP Requests:[/blue] {arp_requests}  [blue]ARP Replies:[/blue] {arp_replies}")
    suspicious = {ip: macs for ip, macs in arp_map.items() if len(macs) > 1}
    if suspicious:
        console.print("[red]Suspicious ARP entries (multiple MACs for one IP):[/red]")
        for ip, macs in suspicious.items():
            console.print(f"  {ip} -> {', '.join(macs)}")
    else:
        console.print("[green]No suspicious ARP activity detected.[/green]")
    
    # Advanced TLS Analysis
    if tls_available:
        console.print(Panel.fit("[bold cyan]TLS Analysis[/bold cyan]", box=box.DOUBLE))
        client_sessions = {}
        server_sessions = {}
        
        # Process TLS Client Hello packets
        for pkt in packets:
            if pkt.haslayer(TLSClientHello):
                client_ip = pkt["IP"].src if pkt.haslayer("IP") else "N/A"
                server_ip = pkt["IP"].dst if pkt.haslayer("IP") else "N/A"
                key = (client_ip, server_ip)
                tls_client = pkt[TLSClientHello]
                sni = None
                if hasattr(tls_client, 'extensions'):
                    for ext in tls_client.extensions:
                        if ext.type == 0 and ext.servernames:
                            sni = ext.servernames[0].data
                            if isinstance(sni, bytes):
                                sni = sni.decode()
                offered = []
                if hasattr(tls_client, 'cipher_suites') and tls_client.cipher_suites:
                    offered = tls_client.cipher_suites
                elif hasattr(tls_client, 'ciphers') and tls_client.ciphers:
                    offered = tls_client.ciphers
                offered_resolved = [resolve_cipher(cs) for cs in offered]
                client_sessions[key] = {
                    "client": client_ip,
                    "server": server_ip,
                    "sni": sni if sni else "N/A",
                    "offered": offered_resolved
                }
        
        # Process TLS Server Hello packets
        for pkt in packets:
            if pkt.haslayer(TLSServerHello):
                server_ip = pkt["IP"].src if pkt.haslayer("IP") else "N/A"
                client_ip = pkt["IP"].dst if pkt.haslayer("IP") else "N/A"
                key = (client_ip, server_ip)
                tls_server = pkt[TLSServerHello]
                server_cipher = None
                if hasattr(tls_server, "fields"):
                    server_cipher = tls_server.fields.get("cipher_suite", None)
                if server_cipher is None:
                    server_cipher = getattr(tls_server, 'ciphers', None)
                if server_cipher is None:
                    server_cipher = getattr(tls_server, 'cipher', None)
                if isinstance(server_cipher, list) and len(server_cipher) > 0:
                    server_cipher = server_cipher[0]
                resolved_server = resolve_cipher(server_cipher) if server_cipher is not None else ("N/A", False)
                server_sessions[key] = {
                    "selected": resolved_server,
                    "client": client_ip,
                    "server": server_ip
                }
        
        # Merge TLS sessions by (client, server) pair
        sessions = []
        for key, client_info in client_sessions.items():
            session = client_info.copy()
            if key in server_sessions:
                session["selected"] = server_sessions[key]["selected"]
            else:
                session["selected"] = ("N/A", False)
            sessions.append(session)
        
        if sessions:
            tls_table = Table(title="TLS Sessions", box=box.HEAVY_EDGE)
            tls_table.add_column("Client IP", style="bold cyan")
            tls_table.add_column("Server IP", style="bold cyan")
            tls_table.add_column("SNI", style="magenta")
            tls_table.add_column("Offered Ciphers", style="green")
            tls_table.add_column("Selected Cipher", style="bold")
            for sess in sessions:
                client_disp = resolve_ip_with_hostname(sess['client'], dns_map)
                server_disp = resolve_ip_with_hostname(sess['server'], dns_map)
                offered = ", ".join(
                    f"[green]{name}[/green]" if rec else f"[red]{name}[/red]"
                    for name, rec in sess['offered']
                ) if sess['offered'] else "N/A"
                selected_name, selected_rec = sess["selected"]
                selected_disp = f"[green]{selected_name}[/green]" if selected_rec else f"[red]{selected_name}[/red]"
                tls_table.add_row(client_disp, server_disp, sess['sni'], offered, selected_disp)
            console.print(tls_table)

            # Option to Export TLS Data
            export_choice = console.input("[bold yellow]\nDo you want to export TLS session data? (y/N): [/bold yellow]").strip().lower()
            if export_choice == 'y':
                console.print("[bold cyan]\nSelect Session to Export:[/bold cyan]")
                console.print("[green]0. Export All Sessions[/green]")
                for idx, sess in enumerate(sessions, 1):
                    client_disp = resolve_ip_with_hostname(sess['client'], dns_map)
                    server_disp = resolve_ip_with_hostname(sess['server'], dns_map)
                    console.print(f"[green]{idx}.[/green] Client: {client_disp}, Server: {server_disp}")
                session_choice = console.input("[bold yellow]Select session number (or 0 for all): [/bold yellow]").strip()
                
                if session_choice == '0':
                    export_tls_sessions_to_csv(sessions, dns_map)
                else:
                    idx = int(session_choice) - 1
                    specific_session = (sessions[idx]['client'], sessions[idx]['server'])
                    export_tls_sessions_to_csv(sessions, dns_map, specific_session)
        else:
            console.print("[red]No TLS sessions found.[/red]")
    else:
        console.print("[red]TLS analysis is not available (Scapy TLS support missing).[/red]")
    
    console.input("\n[bold yellow]Advanced analysis complete. Press Enter to return to the main menu...[/bold yellow]")

def flow_analysis():
    clear_screen()
    console.print(Panel.fit("[bold cyan]Flow Analysis[/bold cyan]", box=box.DOUBLE))
    
    # List available PCAP files
    pcap_files = list_pcap_files()
    if not pcap_files:
        console.input("\n[bold yellow]No PCAP files found. Press Enter to return to the main menu...[/bold yellow]")
        return
    
    # Select a PCAP file by number
    choice = console.input("\n[bold yellow]Select file number for flow analysis (or Q to go back): [/bold yellow]").strip().lower()
    if choice == 'q':
        return
    
    try:
        idx = int(choice)
        if 1 <= idx <= len(pcap_files):
            selected_file = pcap_files[idx - 1]
            file_path = os.path.join(defaults['project_path'], selected_file) if defaults['project_path'] else selected_file
        else:
            console.print("[red]Invalid selection. Returning to Flow Analysis...[/red]")
            return
    except ValueError:
        console.print("[red]Invalid input. Returning to Flow Analysis...[/red]")
        return
    
    # Load packets from the selected file
    try:
        packets = rdpcap(file_path)
        console.print(f"[blue]Total Packets Loaded:[/blue] {len(packets)}\n")
    except Exception as e:
        console.print(f"[red]Failed to load PCAP file: {e}[/red]")
        return

    # Perform the actual flow analysis
    perform_flow_analysis(packets)

    console.input("[bold yellow]Press Enter to return to the main menu...[/bold yellow]")


def perform_flow_analysis(packets):
    # Build DNS mapping from DNS answers to associate IPs with domain names
    dns_map = build_dns_map(packets)
    flows = {}
    for pkt in packets:
        if pkt.haslayer("TCP"):
            protocol = "TCP"
            src_ip = pkt["IP"].src if pkt.haslayer("IP") else "N/A"
            dst_ip = pkt["IP"].dst if pkt.haslayer("IP") else "N/A"
            src_port = pkt["TCP"].sport
            dst_port = pkt["TCP"].dport
        elif pkt.haslayer("UDP"):
            protocol = "UDP"
            src_ip = pkt["IP"].src if pkt.haslayer("IP") else "N/A"
            dst_ip = pkt["IP"].dst if pkt.haslayer("IP") else "N/A"
            src_port = pkt["UDP"].sport
            dst_port = pkt["UDP"].dport
        else:
            continue
        key = (src_ip, src_port, dst_ip, dst_port, protocol)
        size = len(pkt)
        flows.setdefault(key, {"packets": 0, "bytes": 0})
        flows[key]["packets"] += 1
        flows[key]["bytes"] += size

    flow_table = Table(title="Flow Analysis", box=box.MINIMAL_DOUBLE_HEAD)
    flow_table.add_column("Source IP (Hostname)", style="bold cyan")
    flow_table.add_column("Src Port", justify="right", style="magenta")
    flow_table.add_column("Destination IP (Hostname)", style="bold cyan")
    flow_table.add_column("Dst Port", justify="right", style="magenta")
    flow_table.add_column("Protocol", style="green")
    flow_table.add_column("Packets", justify="right")
    flow_table.add_column("Bytes", justify="right")

    for (src_ip, src_port, dst_ip, dst_port, protocol), stats in flows.items():
        src_disp = resolve_ip_with_hostname(src_ip, dns_map)
        dst_disp = resolve_ip_with_hostname(dst_ip, dns_map)
        flow_table.add_row(src_disp, str(src_port), dst_disp, str(dst_port), protocol, str(stats["packets"]), str(stats["bytes"]))
    console.print(flow_table)

def list_pcap_files():
    """List all PCAP files in the selected project folder or current directory."""
    # Determine the directory to list from
    if defaults['project_path']:
        directory = defaults['project_path']
    else:
        directory = os.getcwd()
    
    # Find all .pcap files in the directory
    pcap_files = [f for f in os.listdir(directory) if f.endswith(('.pcap', '.log'))]
    
    # Display the list of PCAP files
    if pcap_files:
        console.print("[bold magenta]Available PCAP Files:[/bold magenta]")
        table = Table(title="PCAP Files", box=box.SIMPLE)
        table.add_column("No.", justify="right", style="cyan", no_wrap=True)
        table.add_column("File Name", style="green")
        
        for idx, file_name in enumerate(pcap_files, 1):
            table.add_row(str(idx), file_name)
        
        console.print(table)
    else:
        console.print("[yellow]No PCAP files found in the selected project folder.[/yellow]")
    
    return pcap_files

def list_log_files():
    """List all .log files in the selected project folder or current directory."""
    # Determine the directory to list from
    if defaults['project_path']:
        directory = defaults['project_path']
    else:
        directory = os.getcwd()
    
    # Find all .log files in the directory
    log_files = [f for f in os.listdir(directory) if f.endswith('.log')]
    
    # Display the list of .log files
    if log_files:
        console.print("[bold magenta]Available Bluetooth Log Files (.log):[/bold magenta]")
        table = Table(title="Log Files", box=box.SIMPLE)
        table.add_column("No.", justify="right", style="cyan", no_wrap=True)
        table.add_column("File Name", style="green")
        
        for idx, file_name in enumerate(log_files, 1):
            table.add_row(str(idx), file_name)
        
        console.print(table)
    else:
        console.print("[yellow]No .log files found in the selected project folder.[/yellow]")
    
    return log_files

def analyze_bluetooth_trace():
    clear_screen()
    console.print(Panel.fit("[bold cyan]Bluetooth Trace File Analysis[/bold cyan]", box=box.DOUBLE))
    
    # List available Bluetooth HCI Log files
    pcap_files = list_pcap_files()
    if not pcap_files:
        console.input("\n[bold yellow]No Bluetooth trace files found. Press Enter to return to the main menu...[/bold yellow]")
        return
    
    # Select a Bluetooth HCI Log file by number
    choice = console.input("\n[bold yellow]Select file number for Bluetooth analysis (or Q to go back): [/bold yellow]").strip().lower()
    if choice == 'q':
        return
    
    try:
        idx = int(choice)
        if 1 <= idx <= len(pcap_files):
            selected_file = pcap_files[idx - 1]
            file_path = os.path.join(defaults['project_path'], selected_file) if defaults['project_path'] else selected_file
        else:
            console.print("[red]Invalid selection. Returning to Bluetooth Trace Analysis...[/red]")
            return
    except ValueError:
        console.print("[red]Invalid input. Returning to Bluetooth Trace Analysis...[/red]")
        return
    
    # Load Bluetooth HCI Log with PyShark
    try:
        bt_cap = pyshark.FileCapture(file_path, display_filter="bthci_evt or bthci_cmd or bthci_acl")
        console.print(f"[blue]Total Packets Loaded:[/blue] {len(bt_cap)}\n")
    except Exception as e:
        console.print(f"[red]Failed to load Bluetooth trace file: {e}[/red]")
        return

    # Perform Bluetooth Analysis
    sessions = {}

    # Process Each Packet in the Bluetooth HCI Log
    for pkt_num, pkt in enumerate(bt_cap, 1):
        try:
            src_mac = dst_mac = conn_handle = "N/A"
            is_encrypted = False
            link_key = ltk_key = "N/A"
            key_packet_num = None
            
            # Extract Source and Destination MAC Addresses
            if 'bthci_acl' in pkt:
                src_mac = pkt.bthci_acl.src_bd_addr if hasattr(pkt.bthci_acl, 'src_bd_addr') else "N/A"
                dst_mac = pkt.bthci_acl.dst_bd_addr if hasattr(pkt.bthci_acl, 'dst_bd_addr') else "N/A"
                conn_handle = pkt.bthci_acl.connection_handle if hasattr(pkt.bthci_acl, 'connection_handle') else "N/A"
            
            elif 'bthci_evt' in pkt:
                src_mac = pkt.bthci_evt.bd_addr if hasattr(pkt.bthci_evt, 'bd_addr') else "N/A"
                dst_mac = pkt.bthci_evt.dst_bd_addr if hasattr(pkt.bthci_evt, 'dst_bd_addr') else "N/A"
                conn_handle = pkt.bthci_evt.connection_handle if hasattr(pkt.bthci_evt, 'connection_handle') else "N/A"
                
                # Check Encryption Flag in Link Layer packets
                if hasattr(pkt.bthci_evt, 'llctrl_enc_rsp'):
                    is_encrypted = True
                
                # Extract Link Key
                if hasattr(pkt.bthci_evt, 'link_key'):
                    link_key = pkt.bthci_evt.link_key.replace(':', '')
                    key_packet_num = pkt_num
            
            elif 'bthci_cmd' in pkt:
                # Extract Long Term Key (LTK)
                if hasattr(pkt.bthci_cmd, 'ltk'):
                    ltk_key = pkt.bthci_cmd.ltk.replace(':', '')
                    key_packet_num = pkt_num
        
            # Identify Session Key
            session_key = (src_mac, dst_mac, conn_handle)
            if session_key not in sessions:
                sessions[session_key] = {
                    "packets": [],
                    "encrypted": is_encrypted,
                    "link_key": None,
                    "ltk_key": None,
                    "key_packet_num": None
                }
            sessions[session_key]["packets"].append(pkt_num)
            
            # Store Link Key or LTK
            if link_key != "N/A":
                sessions[session_key]["link_key"] = link_key
                sessions[session_key]["key_packet_num"] = key_packet_num
            elif ltk_key != "N/A":
                sessions[session_key]["ltk_key"] = ltk_key
                sessions[session_key]["key_packet_num"] = key_packet_num
        
        except AttributeError:
            continue
    
    # Display Session Overview
    console.print(Panel.fit("[bold cyan]Session Overview[/bold cyan]", box=box.DOUBLE))
    session_table = Table(title="Bluetooth Sessions", box=box.SIMPLE)
    session_table.add_column("Source MAC", style="cyan", justify="left")
    session_table.add_column("Destination MAC", style="cyan", justify="left")
    session_table.add_column("Connection Handle", style="green", justify="center")
    session_table.add_column("Encrypted", style="magenta", justify="center")
    session_table.add_column("Link Key", style="yellow", justify="left")
    session_table.add_column("LTK", style="yellow", justify="left")
    session_table.add_column("Key Packet No.", style="red", justify="right")

    for (src_mac, dst_mac, conn_handle), details in sessions.items():
        session_table.add_row(
            src_mac, 
            dst_mac, 
            conn_handle, 
            "Yes" if details["encrypted"] else "No", 
            details["link_key"] if details["link_key"] else "N/A",
            details["ltk_key"] if details["ltk_key"] else "N/A",
            str(details["key_packet_num"]) if details["key_packet_num"] else "N/A"
        )
    console.print(session_table)
    
    console.input("[bold yellow]Press Enter to return to the main menu...[/bold yellow]")


def analyze_trace():
    clear_screen()
    console.print(Panel.fit("[bold cyan]Analyze Trace File[/bold cyan]", box=box.DOUBLE))
    
    # List available PCAP files
    pcap_files = list_pcap_files()
    if not pcap_files:
        console.input("\n[bold yellow]No PCAP files found. Press Enter to return to the main menu...[/bold yellow]")
        return
    
    # Select a PCAP file by number
    choice = console.input("\n[bold yellow]Select file number to analyze (or Q to go back): [/bold yellow]").strip().lower()
    if choice == 'q':
        return
    
    try:
        idx = int(choice)
        if 1 <= idx <= len(pcap_files):
            selected_file = pcap_files[idx - 1]
            file_path = os.path.join(defaults['project_path'], selected_file) if defaults['project_path'] else selected_file
        else:
            console.print("[red]Invalid selection. Returning to Analyze Trace...[/red]")
            return
    except ValueError:
        console.print("[red]Invalid input. Returning to Analyze Trace...[/red]")
        return
    
    # Load and analyze the selected PCAP file
    console.print(Panel.fit(f"[bold cyan]Analyzing PCAP File: {selected_file}[/bold cyan]", box=box.DOUBLE))
    packets = rdpcap(file_path)
    console.print(f"[blue]Total Packets:[/blue] {len(packets)}\n")
    for i, pkt in enumerate(packets, 1):
        console.print(f"{str(i).rjust(3)}: {pkt.summary()}")
    
    # Ask for advanced analysis
    choice = console.input(f"\n[bold yellow]Perform advanced cybersecurity analysis? (y/N): [/bold yellow]").strip().lower()
    if choice == 'y':
        advanced_packet_analysis(packets)
    else:
        console.input("\n[bold yellow]Press Enter to return to the main menu...[/bold yellow]")

def run_nessus_scan():
    """Run a Nessus scan on a target IP with policy selection"""
    console.print("[bold cyan]Fetching available Nessus policies...[/bold cyan]")

    try:
        # Fetch Nessus policies
        result = subprocess.run(["/opt/nessus/sbin/nessuscli", "policy", "list"], capture_output=True, text=True)
        if result.returncode != 0:
            console.print("[red]Failed to retrieve scan policies. Check if Nessus is running.[/red]")
            return
        policies = result.stdout.strip().split("\n")
        if not policies:
            console.print("[red]No scan policies found![/red]")
            return

        # Display policies
        policy_table = Table(title="Available Nessus Scan Policies", box=box.SIMPLE_HEAVY)
        policy_table.add_column("No.", justify="right", style="cyan")
        policy_table.add_column("Policy Name", style="green")
        for i, policy in enumerate(policies, start=1):
            policy_table.add_row(str(i), policy)

        console.print(policy_table)

        # Prompt user to select a policy
        while True:
            choice = console.input("[bold yellow]Select a policy number: [/bold yellow]").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(policies):
                selected_policy = policies[int(choice) - 1]
                break
            console.print("[red]Invalid selection. Please enter a valid policy number.[/red]")

    except Exception as e:
        console.print(f"[red]Error retrieving policies: {e}[/red]")
        return

    # Prompt for target IP
    target = console.input("[bold yellow]Enter target IP or hostname: [/bold yellow]").strip()
    if not target:
        console.print("[red]Target is required![/red]")
        return

    # Prompt for Nessus credentials
    username = console.input("[bold yellow]Enter Nessus username: [/bold yellow]").strip()
    password = console.input("[bold yellow]Enter Nessus password: [/bold yellow]").strip()

    console.print(f"[cyan]Starting Nessus scan on {target} using policy '{selected_policy}'...[/cyan]")

    try:
        # Run Nessus scan
        result = subprocess.run(
            ["/opt/nessus/sbin/nessuscli", "scan", "--target", target, "--policy", selected_policy,
             "--username", username, "--password", password],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            console.print("[green]Scan started successfully![/green]")
            console.print(result.stdout)
        else:
            console.print("[red]Failed to start scan. Check policy and credentials.[/red]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

    console.input("\n[bold yellow]Press Enter to return to Nessus menu...[/bold yellow]")

def nessus_scan_management():
    """Menu-driven Nessus scan execution and reporting"""
    clear_screen()
    console.print(Panel.fit("[bold cyan]Nessus Scan Management[/bold cyan]", box=box.DOUBLE))

    while True:
        # Nessus Menu Options
        nessus_menu = Table(box=box.SIMPLE_HEAVY)
        nessus_menu.add_column("Option", justify="center", style="bold magenta")
        nessus_menu.add_column("Description", style="cyan")
        nessus_menu.add_row("1", "Run Basic Network Scan")
        nessus_menu.add_row("2", "Run Policy-based Scan")
        nessus_menu.add_row("3", "List Running Scans")
        nessus_menu.add_row("4", "Export Scan Report")
        nessus_menu.add_row("5", "Return to Main Menu")

        console.print(nessus_menu)
        choice = console.input("[bold yellow]Select an option (1-5): [/bold yellow]").strip()

        if choice == "1":
            run_basic_network_scan()
        elif choice == "2":
            run_policy_scan()
        elif choice == "3":
            list_running_nessus_scans()
        elif choice == "4":
            export_nessus_scan_report()
        elif choice == "5":
            return
        else:
            console.print("[red]Invalid option. Please try again.[/red]")

def run_basic_network_scan():
    """Run a basic network scan without requiring a policy"""
    clear_screen()
    console.print(Panel.fit("[bold cyan]Basic Network Scan[/bold cyan]", box=box.DOUBLE))

    # Prompt for target IP or range
    target = console.input("[bold yellow]Enter target IP/range (e.g., 192.168.1.0/24): [/bold yellow]").strip()
    if not target:
        console.print("[red]Target is required![/red]")
        return

    # Prompt for Nessus credentials
    username = console.input("[bold yellow]Enter Nessus username: [/bold yellow]").strip()
    password = console.input("[bold yellow]Enter Nessus password: [/bold yellow]").strip()

    console.print(f"[cyan]Starting basic network scan on {target}...[/cyan]")

    try:
        # Run basic network scan with default settings
        result = subprocess.run(
            ["/opt/nessus/sbin/nessuscli", "scan", "--target", target,
             "--template", "basic",  # Use basic network scan template
             "--username", username, "--password", password],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            output_lines = result.stdout.strip().split("\n")
            scan_id = None
            
            # Extract scan ID from output
            for line in output_lines:
                if "Scan ID:" in line:
                    scan_id = line.split(":")[1].strip()
                    break
            
            if scan_id:
                console.print(f"[green]Basic network scan started successfully! Scan ID: {scan_id}[/green]")
                # Monitor scan progress
                monitor_nessus_scan(scan_id)
            else:
                console.print("[red]Scan started but couldn't retrieve scan ID.[/red]")
        else:
            console.print("[red]Failed to start basic network scan.[/red]")
            if result.stderr:
                console.print(f"[red]Error: {result.stderr}[/red]")

    except Exception as e:
        console.print(f"[red]Error starting scan: {e}[/red]")

    console.input("\n[bold yellow]Press Enter to return to Nessus menu...[/bold yellow]")

def run_policy_scan():
    """Run a Nessus scan with a selected policy"""
    clear_screen()
    console.print(Panel.fit("[bold cyan]Policy-based Scan[/bold cyan]", box=box.DOUBLE))
    console.print("[bold cyan]Fetching available Nessus policies...[/bold cyan]")

    try:
        # Fetch Nessus policies
        result = subprocess.run(["/opt/nessus/sbin/nessuscli", "policy", "list"], capture_output=True, text=True)
        if result.returncode != 0:
            console.print("[red]Failed to retrieve scan policies. Check if Nessus is running.[/red]")
            return
        policies = result.stdout.strip().split("\n")
        if not policies:
            console.print("[red]No scan policies found![/red]")
            return

        # Display policies
        policy_table = Table(title="Available Nessus Scan Policies", box=box.SIMPLE_HEAVY)
        policy_table.add_column("No.", justify="right", style="cyan")
        policy_table.add_column("Policy Name", style="green")
        for i, policy in enumerate(policies, start=1):
            policy_table.add_row(str(i), policy)

        console.print(policy_table)

        # Prompt user to select a policy
        while True:
            choice = console.input("[bold yellow]Select a policy number: [/bold yellow]").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(policies):
                selected_policy = policies[int(choice) - 1]
                break
            console.print("[red]Invalid selection. Please enter a valid policy number.[/red]")

        # Get target and credentials
        target = console.input("[bold yellow]Enter target IP/range: [/bold yellow]").strip()
        if not target:
            console.print("[red]Target is required![/red]")
            return

        username = console.input("[bold yellow]Enter Nessus username: [/bold yellow]").strip()
        password = console.input("[bold yellow]Enter Nessus password: [/bold yellow]").strip()

        console.print(f"[cyan]Starting policy-based scan on {target} using policy '{selected_policy}'...[/cyan]")

        # Run the scan
        result = subprocess.run(
            ["/opt/nessus/sbin/nessuscli", "scan", "--target", target,
             "--policy", selected_policy,
             "--username", username, "--password", password],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            scan_id = None
            for line in result.stdout.strip().split("\n"):
                if "Scan ID:" in line:
                    scan_id = line.split(":")[1].strip()
                    break
            
            if scan_id:
                console.print(f"[green]Policy scan started successfully! Scan ID: {scan_id}[/green]")
                monitor_nessus_scan(scan_id)
            else:
                console.print("[red]Scan started but couldn't retrieve scan ID.[/red]")
        else:
            console.print("[red]Failed to start policy scan.[/red]")
            if result.stderr:
                console.print(f"[red]Error: {result.stderr}[/red]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

    console.input("\n[bold yellow]Press Enter to return to Nessus menu...[/bold yellow]")

def monitor_nessus_scan(scan_id):
    """Monitor a Nessus scan until completion"""
    console.print(f"[cyan]Monitoring scan progress (ID: {scan_id})...[/cyan]")

    while True:
        try:
            # Fetch scan status
            result = subprocess.run(
                ["/opt/nessus/sbin/nessuscli", "scan", "list"],
                capture_output=True, text=True
            )

            if result.returncode != 0:
                console.print("[red]Failed to retrieve scan status.[/red]")
                return

            scans = result.stdout.strip().split("\n")
            scan_status = None

            # Parse scan status
            for scan in scans:
                if scan_id in scan:
                    scan_status = scan.split()[-1]  # Status is the last word

            if not scan_status:
                console.print("[red]Scan not found! It may have already completed or failed.[/red]")
                return

            console.print(f"[blue]Current scan status: {scan_status}[/blue]")

            # If scan is completed, notify the user
            if scan_status.lower() in ["completed", "done"]:
                console.print(f"[green]Scan {scan_id} has completed![/green]")
                return
            
            # Wait before checking again
            time.sleep(5)

        except Exception as e:
            console.print(f"[red]Error monitoring scan: {e}[/red]")
            return

def list_running_nessus_scans():
    """List currently running Nessus scans"""
    console.print("[bold cyan]Checking running scans...[/bold cyan]")

    try:
        result = subprocess.run(["/opt/nessus/sbin/nessuscli", "scan", "list"], capture_output=True, text=True)
        if result.returncode == 0:
            console.print("[green]Running Scans:[/green]\n" + result.stdout)
        else:
            console.print("[red]Failed to retrieve running scans.[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

    console.input("\n[bold yellow]Press Enter to return to Nessus menu...[/bold yellow]")

def export_nessus_scan_report():
    """List available scans and export the selected scan as a PDF report"""
    console.print("[bold cyan]Fetching available Nessus scans...[/bold cyan]")

    try:
        # Fetch list of completed scans
        result = subprocess.run(["/opt/nessus/sbin/nessuscli", "scan", "list"], capture_output=True, text=True)
        if result.returncode != 0:
            console.print("[red]Failed to retrieve scan list. Ensure Nessus is running.[/red]")
            return
        scans = result.stdout.strip().split("\n")
        if not scans:
            console.print("[red]No completed scans found![/red]")
            return

        # Display available scans
        scan_table = Table(title="Available Nessus Scans", box=box.SIMPLE_HEAVY)
        scan_table.add_column("No.", justify="right", style="cyan")
        scan_table.add_column("Scan ID", style="green")
        scan_table.add_column("Scan Name", style="magenta")

        scan_data = []
        for scan in scans:
            parts = scan.split()  # Parse scan list
            if len(parts) >= 2:
                scan_id, scan_name = parts[0], " ".join(parts[1:])
                scan_data.append((scan_id, scan_name))
                scan_table.add_row(str(len(scan_data)), scan_id, scan_name)

        console.print(scan_table)

        # Prompt user to select a scan
        while True:
            choice = console.input("[bold yellow]Select a scan number: [/bold yellow]").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(scan_data):
                selected_scan_id, selected_scan_name = scan_data[int(choice) - 1]
                break
            console.print("[red]Invalid selection. Please enter a valid scan number.[/red]")

    except Exception as e:
        console.print(f"[red]Error retrieving scans: {e}[/red]")
        return

    # Export the selected scan as a PDF
    output_file = f"nessus_report_{selected_scan_name.replace(' ', '_')}.pdf"

    console.print(f"[cyan]Exporting report for scan '{selected_scan_name}'...[/cyan]")

    try:
        result = subprocess.run(
            ["/opt/nessus/sbin/nessuscli", "report", "--export", "--format", "pdf",
             "--output", output_file, "--scan", selected_scan_id],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            console.print(f"[green]Report exported successfully: {output_file}[/green]")
        else:
            console.print("[red]Failed to export report. Check scan ID.[/red]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

    console.input("\n[bold yellow]Press Enter to return to Nessus menu...[/bold yellow]")

def copy_bluetooth_log_from_android():
    """Extract Bluetooth log from an Android device via ADB."""
    clear_screen()
    console.print(Panel.fit("[bold cyan]Copying Bluetooth Log from Android[/bold cyan]", box=box.DOUBLE))

    console.print("[bold yellow]Please connect your Android device and enable USB Debugging.[/bold yellow]")
    console.print("[cyan]Checking device connection status...[/cyan]")

    try:
        # Check if ADB is installed
        subprocess.run(["adb", "version"], capture_output=True, text=True, check=True)

        # Check if device is connected
        result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
        device_lines = result.stdout.strip().split("\n")
        
        # Filter out empty lines and the "List of devices attached" header
        devices = [line.split()[0] for line in device_lines[1:] if line.strip() and not line.startswith("List")]
        
        if not devices:
            console.print("[red]No Android device detected! Please check your connection and enable USB Debugging.[/red]")
            console.input("\n[bold yellow]Press Enter to return...[/bold yellow]")
            return

        device_id = devices[0]
        console.print(f"[green]Android device detected! Device ID: {device_id}[/green]")
        
        # Check for authorization state
        if "unauthorized" in result.stdout:
            console.print("[red]Device is unauthorized. Please check and accept the authorization dialog on your device.[/red]")
            console.input("\n[bold yellow]Press Enter after accepting the dialog...[/bold yellow]")
            
            # Check again after user confirmation
            result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
            if "unauthorized" in result.stdout:
                console.print("[red]Device still unauthorized. Please check USB debugging settings.[/red]")
                console.input("\n[bold yellow]Press Enter to return...[/bold yellow]")
                return

        # Define possible log file locations (most common paths)
        possible_paths = [
            "/data/misc/bluetooth/logs/btsnoop_hci.log",  # Common internal storage path
            "/data/misc/bluedroid/btsnoop_hci.log",  # Alternative internal path
            "/data/misc/bluetooth/btsnoop_hci.log",  # Another common path
            "/data/btsnoop/",  # Directory that might contain the log
            "/storage/emulated/0/Android/data/com.android.bluetooth/files/logs/btsnoop_hci.log",  # Internal storage Android path
            "/storage/emulated/0/Android/data/com.android.bluetooth/files/btsnoop_hci.log",  # Alternative internal storage path
            "/storage/emulated/0/btsnoop_hci.log"  # Root of internal storage
        ]

        # Get the directory to save the log file to
        project_path = defaults.get('project_path', os.getcwd())
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        destination_file = os.path.join(project_path, f"btsnoop_hci_{timestamp}.log")

        # Check each possible location
        log_found = False
        for log_file in possible_paths:
            console.print(f"[cyan]Checking for Bluetooth log at: {log_file}[/cyan]")
            
            # Use ls -l to get more detailed information about the file
            check_cmd = f"adb -s {device_id} shell 'ls -l {log_file} 2>/dev/null || echo \"NOT_FOUND\"'"
            check_result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
            
            if "NOT_FOUND" not in check_result.stdout:
                console.print(f"[green]Log file found! Copying from: {log_file}[/green]")
                
                # Try to copy the file - show more detailed output for debugging
                console.print(f"[yellow]Executing: adb -s {device_id} pull {log_file} {destination_file}[/yellow]")
                copy_result = subprocess.run(
                    ["adb", "-s", device_id, "pull", log_file, destination_file], 
                    capture_output=True, 
                    text=True
                )
                
                console.print(f"[cyan]Command output: {copy_result.stdout}[/cyan]")
                if copy_result.stderr:
                    console.print(f"[yellow]Error output: {copy_result.stderr}[/yellow]")
                
                if copy_result.returncode == 0 and os.path.exists(destination_file):
                    file_size = os.path.getsize(destination_file)
                    console.print(f"[green]Bluetooth log file successfully copied to: {destination_file}[/green]")
                    console.print(f"[green]File size: {file_size} bytes[/green]")
                    log_found = True
                    break
                else:
                    console.print("[red]Failed to copy Bluetooth log. Will try alternative paths.[/red]")
            else:
                console.print(f"[yellow]Log file not found at: {log_file}[/yellow]")

        # If no predefined paths worked, ask user for custom path
        if not log_found:
            console.print("[red]Bluetooth log file not found in common locations![/red]")
            console.print("[yellow]Attempting to search for any Bluetooth logs...[/yellow]")
            
            # Search for log files in common locations
            search_cmd = "adb -s " + device_id + " shell 'find /sdcard -name \"*snoop*\" -o -name \"*btsnoop*\" -o -name \"*bluetooth*.log\"'"
            search_result = subprocess.run(search_cmd, shell=True, capture_output=True, text=True)
            
            if search_result.stdout.strip():
                console.print("[green]Found potential Bluetooth log files:[/green]")
                found_files = search_result.stdout.strip().split('\n')
                
                for idx, file in enumerate(found_files, 1):
                    if file.strip():
                        console.print(f"[green]{idx}.[/green] {file.strip()}")
                
                choice = console.input("\n[bold yellow]Select file number to copy (or press Enter to skip): [/bold yellow]").strip()
                if choice.isdigit() and 1 <= int(choice) <= len(found_files):
                    custom_log_file = found_files[int(choice)-1].strip()
                    console.print(f"[cyan]Copying from: {custom_log_file}[/cyan]")
                    
                    copy_result = subprocess.run(
                        ["adb", "-s", device_id, "pull", custom_log_file, destination_file], 
                        capture_output=True, 
                        text=True
                    )
                    
                    if copy_result.returncode == 0 and os.path.exists(destination_file):
                        file_size = os.path.getsize(destination_file)
                        console.print(f"[green]File successfully copied to: {destination_file}[/green]")
                        console.print(f"[green]File size: {file_size} bytes[/green]")
                        log_found = True
                    else:
                        console.print("[red]Failed to copy the selected file.[/red]")
            else:
                console.print("[red]No Bluetooth log files found after searching.[/red]")
                
            if not log_found:
                console.print("[yellow]You may need to enable Bluetooth HCI snoop logging in your device's Developer Options.[/yellow]")
                console.print("[yellow]Steps to enable Bluetooth HCI logging:[/yellow]")
                console.print("[cyan]1. Enable Developer Options (tap Build Number 7 times in About Phone)[/cyan]")
                console.print("[cyan]2. Go to Developer Options[/cyan]")
                console.print("[cyan]3. Find and enable 'Enable Bluetooth HCI snoop log'[/cyan]")
                console.print("[cyan]4. Use Bluetooth for a while and try copying the log again[/cyan]")
                
                # Offer to input a custom path
                custom_path = console.input("\n[bold yellow]Enter a custom path to look for the log file (or press Enter to skip): [/bold yellow]").strip()
                if custom_path:
                    console.print(f"[cyan]Checking custom path: {custom_path}[/cyan]")
                    
                    check_cmd = f"adb -s {device_id} shell '[ -f {custom_path} ] && echo \"EXISTS\" || echo \"NOT_FOUND\"'"
                    check_result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
                    
                    if "EXISTS" in check_result.stdout:
                        console.print(f"[green]Log file found at custom path! Copying from: {custom_path}[/green]")
                        
                        copy_result = subprocess.run(
                            ["adb", "-s", device_id, "pull", custom_path, destination_file], 
                            capture_output=True, 
                            text=True
                        )
                        
                        if copy_result.returncode == 0 and os.path.exists(destination_file):
                            file_size = os.path.getsize(destination_file)
                            console.print(f"[green]File successfully copied to: {destination_file}[/green]")
                            console.print(f"[green]File size: {file_size} bytes[/green]")
                            log_found = True
                        else:
                            console.print("[red]Failed to copy from custom path.[/red]")
                    else:
                        console.print("[red]File not found at the custom path.[/red]")

    except subprocess.CalledProcessError as e:
        console.print(f"[red]ADB command error: {e}[/red]")
        console.print(f"[yellow]Error details: {e.stdout if hasattr(e, 'stdout') else 'No details available'}[/yellow]")
    except FileNotFoundError:
        console.print("[red]ADB command not found! Ensure ADB is installed and added to your system PATH.[/red]")
    except Exception as e:
        console.print(f"[red]Unexpected error: {str(e)}[/red]")

    console.input("\n[bold yellow]Press Enter to return to Bluetooth Trace Analysis menu...[/bold yellow]")

def bluetooth_trace_file_analysis():
    """Bluetooth Trace File Analysis Menu."""
    while True:
        clear_screen()
        console.print(Panel.fit("[bold cyan]Bluetooth Trace File Analysis[/bold cyan]", box=box.DOUBLE))

        # Bluetooth Analysis Submenu
        bt_menu = Table(box=box.SIMPLE_HEAVY)
        bt_menu.add_column("Option", justify="center", style="bold magenta")
        bt_menu.add_column("Description", style="cyan")
        bt_menu.add_row("1", "Copy Bluetooth Log File from Android")
        bt_menu.add_row("2", "Select Log File and Analyze")
        bt_menu.add_row("3", "Return to Main Menu")

        console.print(bt_menu)

        choice = console.input("[bold yellow]Select an option (1-3): [/bold yellow]").strip()

        if choice == "1":
            copy_bluetooth_log_from_android()
        elif choice == "2":
            analyze_bluetooth_trace()
        elif choice == "3":
            return
        else:
            console.print("[red]Invalid option. Please try again.[/red]")

def execute_remote_find():
    """Execute find command on remote terminal and store results locally"""
    clear_screen()
    console.print(Panel.fit("[bold cyan]Remote Terminal Find Operation[/bold cyan]", box=box.DOUBLE))

    # Check if project path is set
    if not defaults['project_path']:
        console.print("[red]Please select a project first![/red]")
        console.input("[bold yellow]Press Enter to return to main menu...[/bold yellow]")
        return

    try:
        # Get the current pane ID before creating new pane
        current_pane = subprocess.run(['tmux', 'display-message', '-p', '#{pane_id}'], 
                                    capture_output=True, text=True, check=True).stdout.strip()
        
        # Create new vertical pane on the right
        subprocess.run(['tmux', 'split-window', '-h'], check=True)
        
        # Get the new (right) pane ID
        right_pane = subprocess.run(['tmux', 'display-message', '-p', '#{pane_id}'], 
                                  capture_output=True, text=True, check=True).stdout.strip()
        
        # Select back the original pane
        subprocess.run(['tmux', 'select-pane', '-t', current_pane], check=True)
        
        # Display tmux navigation instructions in left pane
        navigation_table = Table(title="TMux Navigation Commands", box=box.SIMPLE_HEAVY)
        navigation_table.add_column("Command", style="bold cyan", justify="right")
        navigation_table.add_column("Description", style="green")
        
        navigation_table.add_row("Ctrl+b →", "Move to right pane")
        navigation_table.add_row("Ctrl+b ←", "Move to left pane")
        navigation_table.add_row("Ctrl+b o", "Switch to next pane")
        navigation_table.add_row("Ctrl+b ;", "Toggle last active pane")
        navigation_table.add_row("Ctrl+b x", "Close current pane")
        navigation_table.add_row("Ctrl+b q", "Show pane numbers")
        navigation_table.add_row("Ctrl+b z", "Toggle pane zoom")
        
        console.print("\n")
        console.print(navigation_table)
        console.print("\n")
        
        # Instructions for remote session
        console.print(Panel.fit(
            "[yellow]Instructions:[/yellow]\n\n"
            "1. Use [bold cyan]Ctrl+b →[/bold cyan] to move to the right pane\n"
            "2. Set up your remote session\n"
            "3. Use [bold cyan]Ctrl+b ←[/bold cyan] to return to this pane\n"
            "4. Confirm when ready to proceed",
            title="Setup Guide",
            box=box.ROUNDED
        ))
        
        ready = console.input("\n[bold yellow]Is the remote session ready? (y/N): [/bold yellow]").strip().lower()
        
        if ready != 'y':
            console.print("[red]Operation cancelled.[/red]")
            # Ask if user wants to close the right pane
            close_pane = console.input("[bold yellow]Close the right pane? (Y/n): [/bold yellow]").strip().lower()
            if close_pane != 'n':
                subprocess.run(['tmux', 'kill-pane', '-t', right_pane], check=True)
            return

        # Display find operation options after remote session is ready
        find_menu = Table(box=box.SIMPLE_HEAVY)
        find_menu.add_column("Option", justify="center", style="bold magenta")
        find_menu.add_column("Description", style="cyan")
        find_menu.add_row("1", "Manual Find (Custom path and pattern)")
        find_menu.add_row("2", "Auto Find (Multiple security-related files)")
        find_menu.add_row("3", "Return to Main Menu")
        
        console.print("\n")
        console.print(find_menu)
        find_choice = console.input("\n[bold yellow]Select find operation (1-3): [/bold yellow]").strip()

        if find_choice not in ['1', '2']:
            # Ask if user wants to close the right pane
            close_pane = console.input("[bold yellow]Close the right pane? (Y/n): [/bold yellow]").strip().lower()
            if close_pane != 'n':
                subprocess.run(['tmux', 'kill-pane', '-t', right_pane], check=True)
            return

        # Generate timestamp for default filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if find_choice == '1':
            # Manual Find
            search_path = console.input("[bold yellow]Enter remote search path (e.g., /home/user): [/bold yellow]").strip()
            search_pattern = console.input("[bold yellow]Enter search pattern (e.g., '*.txt'): [/bold yellow]").strip()

            if not search_path or not search_pattern:
                console.print("[red]Search path and pattern are required![/red]")
                # Ask if user wants to close the right pane
                close_pane = console.input("[bold yellow]Close the right pane? (Y/n): [/bold yellow]").strip().lower()
                if close_pane != 'n':
                    subprocess.run(['tmux', 'kill-pane', '-t', right_pane], check=True)
                return

            default_filename = f'manual_find_{timestamp}.txt'
            find_cmd = f"find {search_path} -name '{search_pattern}'"
            
        else:
            # First check for required packages
            try:
                import pandas as pd
                import xlsxwriter
            except ImportError as e:
                console.print("[red]Missing required packages. Installing them now...[/red]")
                try:
                    subprocess.run(['pip3', 'install', 'pandas', 'xlsxwriter'], check=True)
                    console.print("[green]Successfully installed required packages![/green]")
                    import pandas as pd
                    import xlsxwriter
                except Exception as install_error:
                    console.print(f"[red]Failed to install packages automatically. Please run:[/red]")
                    console.print("[yellow]pip3 install pandas xlsxwriter[/yellow]")
                    console.print("\n[red]Falling back to CSV format...[/red]")
                    use_excel = False
                else:
                    use_excel = True
            else:
                use_excel = True

            # Auto Find (Multiple security-related files)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            default_filename = f'security_files_{timestamp}.xlsx' if use_excel else f'security_files_{timestamp}.csv'
            
            # Define file patterns and their descriptions
            file_patterns = {
                '*.conf': 'Configuration Files',
                '*.pem': 'PEM Certificates/Keys',
                '*.crt': 'CRT Certificates',
                '*.key': 'Private Keys',
                '*.cert': 'Certificates'
            }
            
            # Dictionary to store results for each pattern
            results_dict = {}
            
            console.print("[cyan]Starting security files search...[/cyan]")
            
            # Create Excel file at the start
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            excel_file = os.path.join(defaults['project_path'], f'security_files_{timestamp}.xlsx')
            console.print(f"\n[cyan]Creating Excel file: {excel_file}[/cyan]")

            # Dictionary to store workbook and formats for reuse
            excel_objects = {
                'writer': pd.ExcelWriter(excel_file, engine='xlsxwriter'),
                'header_format': None,
                'cell_format': None
            }

            try:
                # Initialize formats
                workbook = excel_objects['writer'].book
                excel_objects['header_format'] = workbook.add_format({
                    'bold': True,
                    'bg_color': '#4F81BD',
                    'font_color': 'white',
                    'border': 1,
                    'text_wrap': True,
                    'valign': 'vcenter',
                    'align': 'center'
                })
                excel_objects['cell_format'] = workbook.add_format({
                    'text_wrap': True,
                    'valign': 'vcenter',
                    'border': 1
                })

                # Execute find command for each pattern
                for i, (pattern, description) in enumerate(file_patterns.items(), 1):
                    console.print(f"\n[bold cyan]Search {i} of {len(file_patterns)}[/bold cyan]")
                    console.print(Panel.fit(
                        f"[yellow]Searching for {description} ({pattern})[/yellow]",
                        title="Current Search",
                        box=box.ROUNDED
                    ))
                    
                    # Clear the right pane before new search
                    subprocess.run(['tmux', 'send-keys', '-t', right_pane, 'clear', 'C-m'], check=True)
                    
                    find_cmd = f"find / -type f -name '{pattern}' 2>/dev/null"
                    
                    # Send the find command to the right pane
                    subprocess.run(['tmux', 'send-keys', '-t', right_pane, find_cmd, 'C-m'], check=True)
                    
                    # Wait for user confirmation that search is complete
                    while True:
                        complete = console.input(
                            "\n[bold yellow]Is the search complete? (y/n/quit): [/bold yellow]"
                        ).strip().lower()
                        
                        if complete == 'y':
                            break
                        elif complete == 'n':
                            console.print("[cyan]Waiting for search to complete...[/cyan]")
                            time.sleep(2)
                        elif complete == 'quit':
                            console.print("[yellow]Stopping search sequence...[/yellow]")
                            excel_objects['writer'].close()
                            # Ask if user wants to close the right pane
                            close_pane = console.input("\n[bold yellow]Close the right pane? (Y/n): [/bold yellow]").strip().lower()
                            if close_pane != 'n':
                                subprocess.run(['tmux', 'kill-pane', '-t', right_pane], check=True)
                            return
                        else:
                            console.print("[red]Invalid input. Please enter 'y', 'n', or 'quit'[/red]")
                    
                    # Capture the output
                    result = subprocess.run(['tmux', 'capture-pane', '-t', right_pane, '-p'],
                                         capture_output=True, text=True, check=True)
                    
                    # Process the results
                    files = [line.strip() for line in result.stdout.split('\n') 
                            if line.strip() and pattern[1:] in line]
                    
                    # Show current search results
                    console.print(f"\n[green]Found {len(files)} {description}[/green]")
                    
                    # Create DataFrame for current results
                    if files:
                        df = pd.DataFrame({
                            'File Path': files,
                            'File Type': [pattern] * len(files),
                            'Last Modified': [
                                subprocess.run(
                                    ['tmux', 'send-keys', '-t', right_pane, f'stat -c %y "{f}"', 'C-m'],
                                    capture_output=True, text=True, check=True
                                ).stdout.strip() if os.path.exists(f) else 'N/A'
                                for f in files
                            ]
                        })
                        
                        # Save to sheet in Excel file
                        sheet_name = ''.join(c for c in description if c.isalnum())[:31]
                        df.to_excel(excel_objects['writer'], sheet_name=sheet_name, index=False)
                        
                        # Format the sheet
                        worksheet = excel_objects['writer'].sheets[sheet_name]
                        worksheet.set_column('A:A', 60)  # File Path
                        worksheet.set_column('B:B', 15)  # File Type
                        worksheet.set_column('C:C', 25)  # Last Modified
                        
                        # Apply header format
                        for col_num, value in enumerate(df.columns.values):
                            worksheet.write(0, col_num, value, excel_objects['header_format'])
                        
                        # Apply cell format to data
                        for row_num in range(len(df)):
                            for col_num in range(len(df.columns)):
                                worksheet.write(row_num + 1, col_num, 
                                             df.iloc[row_num, col_num], 
                                             excel_objects['cell_format'])
                        
                        # Add autofilter
                        worksheet.autofilter(0, 0, len(df), len(df.columns) - 1)
                        
                        # Store results for summary
                        results_dict[description] = {
                            'File Type': pattern,
                            'Count': len(files)
                        }
                    
                    # If not the last search, ask user to continue
                    if i < len(file_patterns):
                        while True:
                            next_search = console.input(
                                "\n[bold yellow]Start next search? (y/n/quit): [/bold yellow]"
                            ).strip().lower()
                            
                            if next_search == 'y':
                                break
                            elif next_search == 'n':
                                console.print("[cyan]Waiting to start next search...[/cyan]")
                                time.sleep(2)
                            elif next_search == 'quit':
                                console.print("[yellow]Stopping search sequence...[/yellow]")
                                excel_objects['writer'].close()
                                # Ask if user wants to close the right pane
                                close_pane = console.input("\n[bold yellow]Close the right pane? (Y/n): [/bold yellow]").strip().lower()
                                if close_pane != 'n':
                                    subprocess.run(['tmux', 'kill-pane', '-t', right_pane], check=True)
                                return
                            else:
                                console.print("[red]Invalid input. Please enter 'y', 'n', or 'quit'[/red]")

                # Create summary sheet
                summary_data = {
                    'File Type': [],
                    'Files Found': [],
                    'Description': []
                }
                
                for desc, data in results_dict.items():
                    summary_data['File Type'].append(data['File Type'])
                    summary_data['Files Found'].append(data['Count'])
                    summary_data['Description'].append(desc)
                
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(excel_objects['writer'], sheet_name='Summary', index=False)
                
                # Format summary sheet
                summary_sheet = excel_objects['writer'].sheets['Summary']
                summary_sheet.set_column('A:A', 15)
                summary_sheet.set_column('B:B', 12)
                summary_sheet.set_column('C:C', 30)
                
                for col_num, value in enumerate(summary_df.columns.values):
                    summary_sheet.write(0, col_num, value, excel_objects['header_format'])

                # Save and close Excel file
                excel_objects['writer'].close()
                console.print(f"\n[green]All results saved to: {excel_file}[/green]")

                # Display summary table
                console.print("\n[bold cyan]Search Summary:[/bold cyan]")
                summary_table = Table(box=box.SIMPLE_HEAVY)
                summary_table.add_column("File Type", style="yellow")
                summary_table.add_column("Files Found", style="cyan", justify="right")
                summary_table.add_column("Description", style="green")
                
                for i in range(len(summary_data['File Type'])):
                    summary_table.add_row(
                        summary_data['File Type'][i],
                        str(summary_data['Files Found'][i]),
                        summary_data['Description'][i]
                    )
                
                console.print(summary_table)

            except Exception as e:
                console.print(f"[red]Error during file operations: {str(e)}[/red]")
                try:
                    excel_objects['writer'].close()
                except:
                    pass

            # Ask if user wants to close the right pane
            close_pane = console.input("\n[bold yellow]Close the right pane? (Y/n): [/bold yellow]").strip().lower()
            if close_pane != 'n':
                subprocess.run(['tmux', 'kill-pane', '-t', right_pane], check=True)
                console.print("[green]Right pane closed.[/green]")

    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error executing tmux commands: {str(e)}[/red]")
    except Exception as e:
        console.print(f"[red]Unexpected error: {str(e)}[/red]")

    console.input("\n[bold yellow]Press Enter to return to main menu...[/bold yellow]")

def main_menu():
    while True:
        clear_screen()
        print_banner()
        display_defaults()

        # Menu Header with Gradient Effect
        title_text = Text("Main Menu", style="bold cyan", justify="center")
        title_text.stylize("bold cyan", 0, 4)
        title_text.stylize("bold magenta", 4, 8)
        title_text.stylize("bold blue", 8, 9)
        title_text = Align.center(title_text)
        console.print(title_text)
        
        # Menu Options with Consistent Style
        menu_items = [
            ("1", " Project Management", "yellow"),
            ("2", " Modify Default Settings", "green"),
            ("3", " Capture Network Packets", "cyan"),
            ("4", " Analyze Trace File", "magenta"),
            ("5", " Flow Analysis", "blue"),
            ("6", " Bluetooth Trace File Analysis", "red"),
            ("7", " Nessus Scan Management", "cyan"),
            ("8", " Remote Terminal Find", "green"),  # New menu item
            ("9", " Exit", "red"),
        ]

        # Constructing the Menu Panel
        menu_panel = Panel(
            Align.center(
                "\n".join(
                    f"[{color}][{number}][/]{description}" 
                    for number, description, color in menu_items
                )
            ),
            title="[bold blue]Select an Option[/bold blue]",
            title_align="center",
            box=box.ROUNDED,
            border_style="bold white",
            expand=True
        )
        console.print(Padding(menu_panel, (1, 10, 1, 10)))

        # Input Prompt with Better UX
        choice = console.input(
            "\n[bold yellow]Enter choice (1-9) or [bold red]Q[/bold red] to Quit: [/bold yellow]"
        ).strip().lower()

        # Handling User Choices with Correct Routing
        if choice == '1':
            manage_project()
        elif choice == '2':
            modify_defaults()
        elif choice == '3':
            capture_packets()
        elif choice == '4':
            analyze_trace()
        elif choice == '5':
            flow_analysis()
        elif choice == '6':
            bluetooth_trace_file_analysis()
        elif choice == "7":
            nessus_scan_management()
        elif choice == "8":
            execute_remote_find()
        elif choice == "9" or choice == 'q':
            console.print(Panel.fit("[bold cyan]Exiting...[/bold cyan]", box=box.DOUBLE))
            sys.exit(0)
        else:
            console.print("[red]Invalid option. Please try again.[/red]")
            console.input("[bold yellow]Press Enter to continue...[/bold yellow]")

if __name__ == '__main__':
    set_default_interface()
    main_menu()
