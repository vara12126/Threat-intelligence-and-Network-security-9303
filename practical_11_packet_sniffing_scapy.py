"""
Practical 11: Network Packet Sniffing Using Scapy
Subject: Threat Intelligence and Network Security

Aim:
    To capture packets on a network interface using Scapy and display their
    summaries, while enforcing safe usage notices, handling interface selection,
    and managing permission/dependency limitations gracefully.

Description:
    Packet sniffing is a fundamental network diagnostic and security monitoring
    technique. Network administrators and security analysts inspect packet headers
    and protocol structures to detect anomalous traffic, diagnose connectivity issues,
    and monitor protocol behavior. This program uses Scapy (or an educational
    demonstration engine when Scapy/Npcap/libpcap is unavailable) to capture live
    packets and display structured packet summaries.
"""

import sys
import os
import argparse

# Safe usage notice mandatory for cybersecurity education
SAFE_USAGE_NOTICE = """======================================================================
  SAFE USAGE NOTICE & ETHICAL GUIDELINES
  - Packet capture must ONLY be performed on networks and systems
    for which you have explicit authorization.
  - Unauthorized interception of network communications violates
    university policies and legal frameworks (e.g., IT Act 2000).
  - Use this educational tool strictly in authorized lab environments.
======================================================================"""

# Try importing Scapy modules safely
try:
    from scapy.all import sniff, conf, get_if_list, IP, TCP, UDP, Ether, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def display_demo_packets(count: int = 3):
    """
    Provides a fallback demonstration mode using explicitly labeled sample packets.
    Used when Scapy is not installed, or when running without administrator / Npcap
    privileges in restricted lab environments.
    """
    print("\n[DEMONSTRATION MODE - EXPLICITLY LABELED SAMPLE PACKETS]")
    print("Notice: Live packet capture requires administrator privileges and a packet driver")
    print("        (Npcap on Windows / libpcap on Linux). Displaying explicitly labeled sample")
    print("        packets to demonstrate Scapy packet summary output.\n")
    
    demo_packets = [
        "Ether / IP / TCP 192.168.1.10:51520 > 93.184.216.34:443 S",
        "Ether / IP / UDP 192.168.1.10:53000 > 8.8.8.8:53 / DNS Qry \"example.com.\"",
        "Ether / IP / TCP 93.184.216.34:443 > 192.168.1.10:51520 SA",
        "Ether / IP / ICMP 192.168.1.10 > 1.1.1.1 echo-request 0",
        "Ether / IP / UDP 192.168.1.10:54001 > 1.1.1.1:53 / DNS Qry \"github.com.\""
    ]
    
    selected = demo_packets[:min(count, len(demo_packets))]
    for idx, pkt_summary in enumerate(selected, 1):
        print(f"Packet {idx}: {pkt_summary}")
        
    print(f"\nTotal packets captured: {len(selected)}")
    print("Packet sniffing completed (Demonstration Mode).")


def run_live_sniff(interface: str = None, count: int = 3, timeout: int = 5):
    """
    Performs live packet sniffing using Scapy and prints packet summaries.
    """
    print("\nPRACTICAL 11: PACKET SNIFFING USING SCAPY")
    print("Starting packet capture...")
    if interface:
        print(f"Interface: {interface}")
    print(f"Configured packet limit: {count}")
    print("-" * 70)

    packet_counter = 0

    def packet_callback(packet):
        nonlocal packet_counter
        packet_counter += 1
        summary = packet.summary()
        print(f"Packet {packet_counter}: {summary}")

    try:
        # Check if pcap is available on Windows
        if os.name == "nt" and conf.use_pcap is False:
            print("[ENVIRONMENT NOTICE]: Npcap/WinPcap is not detected on this Windows host.")
            print("Live packet capture requires the Npcap driver (https://npcap.com/).")
            display_demo_packets(count)
            return

        kwargs = {
            "prn": packet_callback,
            "count": count,
            "timeout": timeout,
            "store": False
        }
        if interface:
            kwargs["iface"] = interface

        sniff(**kwargs)

        print("-" * 70)
        print(f"Total packets captured: {packet_counter}")
        print("Packet sniffing completed.")

        if packet_counter == 0:
            print("\n[Notice]: No live packets were captured during the timeout window.")
            print("Switching to demonstration mode to show expected output structure:")
            display_demo_packets(count)

    except PermissionError:
        print("\n[ERROR]: Insufficient permissions to capture raw network packets.")
        print("Resolution: On Windows, run terminal as Administrator with Npcap installed.")
        print("            On Linux, run with sudo or setcap privileges.")
        display_demo_packets(count)
    except Exception as exc:
        print(f"\n[ERROR]: Live capture encountered an error: {exc}")
        print("Falling back to demonstration mode.")
        display_demo_packets(count)


def list_available_interfaces():
    """Returns a list of available network interfaces if Scapy is present."""
    if not SCAPY_AVAILABLE:
        return []
    try:
        return get_if_list()
    except Exception:
        return []


def main():
    parser = argparse.ArgumentParser(description="Practical 11: Network Packet Sniffing Using Scapy")
    parser.add_argument("--demo", action="store_true", help="Run demonstration mode directly")
    parser.add_argument("--count", type=int, default=3, help="Packet capture count (1-20)")
    parser.add_argument("--iface", type=str, default=None, help="Network interface name")
    args = parser.parse_args()

    print("======================================================================")
    print("  Cyber Threat Intelligence - Practical 11: Network Packet Sniffing")
    print("======================================================================")
    print(SAFE_USAGE_NOTICE)

    if args.demo:
        display_demo_packets(count=args.count)
        return

    # Check Scapy library availability
    if not SCAPY_AVAILABLE:
        print("\n[ENVIRONMENT NOTICE]")
        print("Scapy is not installed in the current Python environment.")
        print("To install Scapy: pip install scapy")
        print("Note for Windows users: Npcap driver (https://npcap.com/) is required for live capture.")
        print("-" * 70)
        display_demo_packets(count=args.count)
        return

    # If running in non-interactive environment or arguments provided
    if args.iface is not None:
        run_live_sniff(interface=args.iface, count=args.count, timeout=5)
        return

    # Interactive flow with fallback
    interfaces = list_available_interfaces()
    selected_iface = None
    if interfaces:
        print(f"\nDetected Network Interfaces ({len(interfaces)}):")
        for i, iface in enumerate(interfaces[:4], 1):
            print(f"  [{i}] {iface}")
        if len(interfaces) > 4:
            print(f"  ... and {len(interfaces) - 4} more.")
        print("-" * 70)

        try:
            choice = input("Enter interface number/name (or press Enter for default): ").strip()
            if choice:
                if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
                    selected_iface = interfaces[int(choice) - 1]
                else:
                    selected_iface = choice
        except (EOFError, KeyboardInterrupt):
            selected_iface = None
    else:
        print("\nNo specific network interfaces enumerated. Using default interface.")

    count = args.count
    try:
        user_count = input(f"Enter number of packets to capture [1-20, default {count}]: ").strip()
        if user_count.isdigit():
            val = int(user_count)
            if 1 <= val <= 20:
                count = val
    except (EOFError, KeyboardInterrupt):
        pass

    run_live_sniff(interface=selected_iface, count=count, timeout=5)


if __name__ == "__main__":
    main()
