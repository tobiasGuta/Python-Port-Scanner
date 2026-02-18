import sys
import socket
import argparse
import pyfiglet
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from datetime import datetime

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
]

TIMING_PROFILES = {
    1: {"timeout": 1.5, "workers": 25},
    2: {"timeout": 1.0, "workers": 50},
    3: {"timeout": 0.7, "workers": 100},
    4: {"timeout": 0.5, "workers": 200},
    5: {"timeout": 0.3, "workers": 400},
}

# Logging
def log(message, style="cyan"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    console.print(f"[bold blue][{timestamp}][/bold blue] [{style}]{message}[/{style}]")

# Port Handling
def validate_port(port):
    return 1 <= port <= 65535

def parse_ports(port_arg):
    ports = set()

    if port_arg == "-":
        return list(range(1, 65536))

    for part in port_arg.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            for p in range(start, end + 1):
                if validate_port(p):
                    ports.add(p)
        else:
            p = int(part)
            if validate_port(p):
                ports.add(p)

    return sorted(ports)

# Banner Grabbing Helper
def grab_banner(sock):
    try:
        # We try to read a small amount of data
        # Some services emit data immediately (SSH, FTP, SMTP)
        # Others wait for input (HTTP), so this might timeout for those.
        sock.settimeout(1.0) 
        banner = sock.recv(1024).decode(errors='ignore').strip()
        return banner if banner else "No Banner"
    except:
        return "No Banner"

# TCP Scan
def tcp_probe(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Connected. attempt to grab banner.
                banner = grab_banner(sock)
                return ("tcp", port, banner)
    except:
        pass
    return None

# UDP Scan
def udp_probe(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"", (ip, port))

            try:
                data, _ = sock.recvfrom(1024)
                # UDP usually doesn't give a clean text banner like TCP, 
                # but if we got data, we can try to show it or just mark Open.
                return ("udp", port, "Open/Response Rx") 
            except socket.timeout:
                # No response = open|filtered
                return ("udp", port, "Open|Filtered")
    except:
        pass
    return None

# Main
def main():
    ascii_banner = pyfiglet.figlet_format("Port Scanner")
    console.print(Panel.fit(ascii_banner, style="bold cyan"))

    parser = argparse.ArgumentParser(description="Minimal TCP/UDP Port Scanner")
    parser.add_argument("target")
    parser.add_argument("-p", "--ports")
    parser.add_argument("-T", type=int, choices=range(1, 6), default=3)
    parser.add_argument("-sT", action="store_true", help="TCP scan (Grabs Banner)")
    parser.add_argument("-sU", action="store_true", help="UDP scan")
    parser.add_argument("--workers", type=int)

    args = parser.parse_args()

    if not args.sT and not args.sU:
        args.sT = True  # Default to TCP

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        log("Hostname could not be resolved.", "red")
        sys.exit(1)

    log(f"Target: {ip}")

    profile = TIMING_PROFILES[args.T]
    timeout = profile["timeout"]
    workers = args.workers if args.workers else profile["workers"]

    if args.ports:
        ports_to_scan = parse_ports(args.ports)
    else:
        ports_to_scan = COMMON_PORTS

    scan_types = []
    if args.sT:
        scan_types.append("tcp")
    if args.sU:
        scan_types.append("udp")

    log(f"Scan type: {', '.join(scan_types).upper()}")
    log(f"Ports to scan: {len(ports_to_scan)}")
    log("Starting scan...\n", "green")

    open_results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=False
    ) as progress:

        total_tasks = len(ports_to_scan) * len(scan_types)
        task = progress.add_task("[cyan]Scanning...", total=total_tasks)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []

            for port in ports_to_scan:
                if args.sT:
                    futures.append(executor.submit(tcp_probe, ip, port, timeout))
                if args.sU:
                    futures.append(executor.submit(udp_probe, ip, port, timeout))

            for future in as_completed(futures):
                result = future.result()
                progress.update(task, advance=1)

                if result:
                    proto, port, banner = result
                    open_results.append((proto, port, banner))
                    
                    # Print real-time hit
                    msg = f"[bold green][+] {proto.upper()} Port {port} OPEN[/bold green]"
                    if banner and banner != "No Banner" and banner != "Open|Filtered":
                        msg += f" [dim]({banner[:30]}...)[/dim]"
                    progress.console.print(msg)

    # Results
    console.rule("[bold red]Final Results")

    if open_results:
        table = Table(box=box.DOUBLE_EDGE)
        table.add_column("Protocol", style="cyan")
        table.add_column("Port", style="bold green")
        table.add_column("Service/Banner", style="white")

        for proto, port, banner in sorted(open_results):
            # Clean up banner for display (remove newlines, truncate)
            clean_banner = str(banner).replace('\n', ' ')[:50]
            table.add_row(proto.upper(), str(port), clean_banner)

        console.print(table)
    else:
        log("No open ports found.", "red")

    console.rule("[bold blue]Scan Complete")

if __name__ == "__main__":
    main()
