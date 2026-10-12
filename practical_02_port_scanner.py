"""
Practical 02: Basic TCP Port Scanner with Lab Restriction
Subject: Threat Intelligence and Network Security

Aim:
    To implement a safe, educational TCP port scanner using Python's socket module.
    The scanner accepts a target host and port list, displays open/closed status
    along with common service names, and restricts scanning to authorized lab systems.

Ethical & Legal Notice:
    Port scanning unauthorized networks is illegal and unethical. This tool
    includes an authorization guardrail restricting scans to localhost and
    private lab test environments.
"""

import socket
import sys
import time

# Dictionary of standard ports and common services
COMMON_SERVICES = {
    20: "FTP-Data (File Transfer)",
    21: "FTP-Control (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Remote Shell)",
    25: "SMTP (Simple Mail Transfer)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Hypertext Transfer Protocol)",
    110: "POP3 (Post Office Protocol)",
    135: "Microsoft RPC (Remote Procedure Call)",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access)",
    443: "HTTPS (HTTP Secure / TLS)",
    445: "Microsoft-DS (SMB File Sharing)",
    1433: "MSSQL (Microsoft SQL Server)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    8080: "HTTP-Proxy / Alternative Web Server",
    8443: "HTTPS-Alt (Alternative Web SSL)"
}

# Authorized lab hosts allowed for demonstration
AUTHORIZED_HOSTS = ["127.0.0.1", "localhost", "::1"]


def is_authorized_target(host: str) -> bool:
    """Verifies that the target host belongs to the authorized lab environment."""
    try:
        ip = socket.gethostbyname(host)
        # Allow loopback addresses and private subnets
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
            return True
        return False
    except socket.gaierror:
        return False


def scan_port(host: str, port: int, timeout: float = 0.4):
    """
    Attempts a TCP 3-way handshake with target host:port.
    Returns True if port is OPEN, False if CLOSED/FILTERED.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.timeout, socket.error):
        sock.close()
        return False


def run_port_scanner(target_host: str, ports_to_scan: list):
    """Orchestrates port scan, enforces authorization, and tabulates results."""
    print("\n" + "=" * 70)
    print("             LABORATORY TCP PORT SCANNER REPORT")
    print("=" * 70)

    # Resolve target hostname
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"[ERROR] Hostname '{target_host}' could not be resolved.")
        return

    print(f"Target Host       : {target_host} ({target_ip})")
    print(f"Ports to Scan     : {len(ports_to_scan)} port(s)")
    print(f"Scan Policy       : Authorized Educational Lab Systems Only")

    # Authorization Check
    if not is_authorized_target(target_host):
        print("\n[!] AUTHORIZATION GUARD TRIGGERED:")
        print(f"    Target '{target_host}' is outside the authorized lab scope!")
        print("    Scanning public networks without prior written consent is strictly")
        print("    prohibited under the Information Technology Act / Computer Fraud and Abuse Act.")
        print("    Scan aborted for safety.")
        print("=" * 70 + "\n")
        return

    print("-" * 70)
    print(f"{'PORT':<8} {'STATE':<10} {'SERVICE NAME':<35} {'STATUS'}")
    print("-" * 70)

    start_time = time.time()
    open_count = 0
    closed_count = 0

    for port in sorted(ports_to_scan):
        service = COMMON_SERVICES.get(port, "Unknown / Custom Service")
        is_open = scan_port(target_ip, port)

        if is_open:
            open_count += 1
            print(f"{port:<8} {'OPEN':<10} {service:<35} [ACTIVE LISTENER]")
        else:
            closed_count += 1
            print(f"{port:<8} {'CLOSED':<10} {service:<35} [NO RESPONSE]")

    scan_duration = time.time() - start_time
    print("-" * 70)
    print(f"Scan Finished in   : {scan_duration:.2f} seconds")
    print(f"Total Ports Scanned: {len(ports_to_scan)} | Open: {open_count} | Closed: {closed_count}")
    print("\nSecurity Observation:")
    if open_count > 0:
        print("  - Active network services were discovered. Ensure unnecessary services")
        print("    are disabled and firewall rules enforce least-privilege exposure.")
    else:
        print("  - No open ports detected among scanned range. Standard host hardening observed.")
    print("=" * 70 + "\n")


def main():
    print("======================================================================")
    print("  Cybersecurity Lab - Practical 02: Basic TCP Port Scanner")
    print("======================================================================")

    default_host = "127.0.0.1"
    default_ports = [21, 22, 53, 80, 135, 443, 445, 3306, 3389, 8080]

    try:
        user_host = input(f"Enter target host (Default '{default_host}'): ").strip()
    except (EOFError, KeyboardInterrupt):
        user_host = ""

    target_host = user_host if user_host else default_host

    try:
        user_ports_str = input(
            "Enter ports to scan separated by comma (or press Enter for defaults): "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        user_ports_str = ""

    if user_ports_str:
        try:
            ports = [int(p.strip()) for p in user_ports_str.split(",") if p.strip().isdigit()]
        except ValueError:
            ports = default_ports
    else:
        ports = default_ports

    run_port_scanner(target_host, ports)


if __name__ == "__main__":
    main()
