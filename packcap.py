#!/usr/bin/env python3
import os
import sys
import socket
from collections import Counter
from datetime import datetime, timezone
from scapy.all import sniff, wrpcap, rdpcap, get_if_list, get_if_addr, load_layer
import pyshark


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
        defaults['capture_file'] = new_file
    console.print(Panel.fit("[bold green]Defaults updated.[/bold green]", box=box.SIMPLE))
    console.input("[bold yellow]Press Enter to return to the main menu...[/bold yellow]")

import datetime  # Import datetime for UTC timestamp

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
        timestamp = datetime.datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        defaults['capture_file'] = f"capture_{timestamp}.pcap"
    else:
        defaults['capture_file'] = capture_file_name

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
            ("1", "Project Management", "blue"),
            ("2", "Modify Default Settings", "yellow"),
            ("3", "Capture Network Packets", "green"),
            ("4", "Analyze Trace File", "cyan"),
            ("5", "Flow Analysis", "magenta"),
            ("6", "Analyze Bluetooth Trace (.log)", "bright_cyan"),
            ("7", "Exit", "red")
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
            "\n[bold yellow]Enter choice (1-7) or [bold red]Q[/bold red] to Quit: [/bold yellow]"
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
            analyze_bluetooth_trace()  # New Option for Bluetooth Analysis
        elif choice == '7' or choice == 'q':
            console.print(
                Panel.fit("[bold cyan]Exiting...[/bold cyan]", box=box.DOUBLE)
            )
            sys.exit(0)
        else:
            console.print("[red]Invalid option. Please try again.[/red]")
            console.input("[bold yellow]Press Enter to continue...[/bold yellow]")

if __name__ == '__main__':
    set_default_interface()
    main_menu()
