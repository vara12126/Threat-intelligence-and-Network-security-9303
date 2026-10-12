"""
Practical 10: Stateful Inspection Firewall Simulator
Subject: Threat Intelligence and Network Security

Aim:
    To simulate a stateful packet inspection (SPI) firewall that:
      1. Tracks outbound TCP/UDP connections in a dynamic Connection State Table.
      2. Automatically permits legitimate matching return traffic.
      3. Drops/blocks unsolicited inbound packets from external hosts.
      4. Demonstrates state lifecycle transitions (SYN -> ESTABLISHED -> FIN/CLOSED).
      5. Displays the live connection state table and firewall decision logs.
"""

import sys
import time

# Packet directions
OUTBOUND = "OUTBOUND"  # Internal LAN/Host -> External WAN
INBOUND = "INBOUND"    # External WAN -> Internal LAN/Host


class StatefulFirewall:
    """
    Simulates a Layer 4 Stateful Packet Inspection (SPI) Firewall.
    Maintains an active connection state table (5-tuple session tracking).
    """

    def __init__(self, internal_subnet_prefix="192.168.1."):
        self.internal_prefix = internal_subnet_prefix
        # Connection Table: Session Key -> Session Metadata
        # Session Key: (src_ip, src_port, dst_ip, dst_port, protocol)
        self.state_table = {}
        self.decision_logs = []

    def _generate_session_key(self, src_ip, src_port, dst_ip, dst_port, proto):
        return (src_ip, src_port, dst_ip, dst_port, proto.upper())

    def _find_matching_return_session(self, src_ip, src_port, dst_ip, dst_port, proto):
        """
        For an INBOUND packet (dst = internal, src = external),
        check if there exists an outbound session where:
          outbound.src == inbound.dst and outbound.dst == inbound.src
        """
        for key, session in list(self.state_table.items()):
            out_src_ip, out_src_port, out_dst_ip, out_dst_port, out_proto = key
            if (
                out_src_ip == dst_ip and
                out_src_port == dst_port and
                out_dst_ip == src_ip and
                out_dst_port == src_port and
                out_proto == proto.upper()
            ):
                return key, session
        return None, None

    def process_packet(self, direction: str, src_ip: str, src_port: int,
                       dst_ip: str, dst_port: int, proto: str, flags: str = "") -> dict:
        """
        Inspects packet against state table and direction rules.
        """
        proto = proto.upper()
        flags = flags.upper()
        timestamp = time.strftime("%H:%M:%S")

        # --- OUTBOUND TRAFFIC ---
        if direction == OUTBOUND:
            session_key = self._generate_session_key(src_ip, src_port, dst_ip, dst_port, proto)

            if "SYN" in flags:
                # Initiate new connection session
                self.state_table[session_key] = {
                    "client": f"{src_ip}:{src_port}",
                    "server": f"{dst_ip}:{dst_port}",
                    "proto": proto,
                    "state": "SYN_SENT",
                    "packets": 1
                }
                action = "PERMIT"
                reason = "Outbound connection requested. Session registered in state table [SYN_SENT]."
            elif "FIN" in flags or "RST" in flags:
                # Teardown connection
                if session_key in self.state_table:
                    self.state_table[session_key]["state"] = "CLOSED"
                    del self.state_table[session_key]
                action = "PERMIT"
                reason = "Outbound connection termination. Session removed from state table [CLOSED]."
            else:
                # Existing or general outbound flow
                if session_key not in self.state_table:
                    self.state_table[session_key] = {
                        "client": f"{src_ip}:{src_port}",
                        "server": f"{dst_ip}:{dst_port}",
                        "proto": proto,
                        "state": "ESTABLISHED",
                        "packets": 1
                    }
                else:
                    self.state_table[session_key]["packets"] += 1
                action = "PERMIT"
                reason = "Permitted outbound client payload. State: ESTABLISHED."

        # --- INBOUND TRAFFIC ---
        elif direction == INBOUND:
            match_key, session = self._find_matching_return_session(src_ip, src_port, dst_ip, dst_port, proto)

            if session is not None:
                # Packet belongs to an existing authorized session
                if "SYN" in flags and "ACK" in flags:
                    session["state"] = "ESTABLISHED"
                    reason = "Legitimate return SYN-ACK handshake matched. Transitioned to [ESTABLISHED]."
                elif "FIN" in flags:
                    session["state"] = "CLOSED"
                    del self.state_table[match_key]
                    reason = "Legitimate return FIN received. Session closed and purged."
                else:
                    session["packets"] += 1
                    reason = f"Legitimate return traffic matched active session ({session['client']} <-> {session['server']})."
                action = "PERMIT"
            else:
                # Inbound packet does NOT match any established session
                action = "DROP"
                reason = "SECURITY ALERT: Unsolicited inbound packet! No matching state table session found."

        else:
            action = "DROP"
            reason = "Unknown packet direction."

        log_entry = {
            "time": timestamp,
            "direction": direction,
            "flow": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}",
            "proto": proto,
            "flags": flags if flags else "NONE",
            "action": action,
            "reason": reason
        }
        self.decision_logs.append(log_entry)
        return log_entry

    def print_state_table(self):
        """Displays currently active sessions tracked by the firewall."""
        print("-" * 75)
        print(f"{'CURRENT STATE TABLE':^75}")
        print("-" * 75)
        if not self.state_table:
            print("  [State Table Empty - No Active Connections]")
        else:
            print(f"{'CLIENT (SRC)':<22} {'SERVER (DST)':<22} {'PROTO':<8} {'STATE':<14} {'PKTS'}")
            print("-" * 75)
            for key, val in self.state_table.items():
                print(f"{val['client']:<22} {val['server']:<22} {val['proto']:<8} {val['state']:<14} {val['packets']}")
        print("-" * 75)


def run_firewall_demo():
    """Runs a simulated sequence of network packets through the stateful firewall."""
    fw = StatefulFirewall()

    print("\n" + "=" * 75)
    print("             STATEFUL INSPECTION FIREWALL SIMULATOR")
    print("=" * 75)
    print("Simulating sequence of 6 realistic packet scenarios:\n")

    test_packets = [
        {
            "num": 1,
            "desc": "LAN Client requests web page to external server (Outbound SYN)",
            "direction": OUTBOUND,
            "src": "192.168.1.50", "sport": 49152,
            "dst": "93.184.216.34", "dport": 80,
            "proto": "TCP", "flags": "SYN"
        },
        {
            "num": 2,
            "desc": "External Server replies to client request (Inbound Return SYN-ACK)",
            "direction": INBOUND,
            "src": "93.184.216.34", "sport": 80,
            "dst": "192.168.1.50", "dport": 49152,
            "proto": "TCP", "flags": "SYN,ACK"
        },
        {
            "num": 3,
            "desc": "External Server streams return HTTP data payload (Inbound Data ACK)",
            "direction": INBOUND,
            "src": "93.184.216.34", "sport": 80,
            "dst": "192.168.1.50", "dport": 49152,
            "proto": "TCP", "flags": "ACK"
        },
        {
            "num": 4,
            "desc": "Unknown External Attacker attempts unsolicited port scan probe (Inbound SYN)",
            "direction": INBOUND,
            "src": "198.51.100.77", "sport": 55123,
            "dst": "192.168.1.50", "dport": 22,
            "proto": "TCP", "flags": "SYN"
        },
        {
            "num": 5,
            "desc": "Rogue Internet Host sends unsolicited UDP packet to database port (Inbound UDP)",
            "direction": INBOUND,
            "src": "203.0.113.19", "sport": 40001,
            "dst": "192.168.1.50", "dport": 3306,
            "proto": "UDP", "flags": ""
        },
        {
            "num": 6,
            "desc": "Client terminates web session gracefully (Outbound FIN)",
            "direction": OUTBOUND,
            "src": "192.168.1.50", "sport": 49152,
            "dst": "93.184.216.34", "dport": 80,
            "proto": "TCP", "flags": "FIN"
        }
    ]

    for pkt in test_packets:
        print(f"[Packet #{pkt['num']}] {pkt['desc']}")
        result = fw.process_packet(
            direction=pkt["direction"],
            src_ip=pkt["src"], src_port=pkt["sport"],
            dst_ip=pkt["dst"], dst_port=pkt["dport"],
            proto=pkt["proto"], flags=pkt["flags"]
        )
        tag = "[ALLOW]" if result["action"] == "PERMIT" else "[DROP/BLOCK]"
        print(f"  --> Flow      : {result['flow']} ({result['direction']}) [{result['proto']} {result['flags']}]")
        print(f"  --> Decision  : {tag} ({result['action']})")
        print(f"  --> Justify   : {result['reason']}")
        fw.print_state_table()
        print()

    print("=" * 75)
    print("STATEFUL FIREWALL ARCHITECTURE SUMMARY:")
    print("  1. Stateful tracking ensures return traffic is dynamically permitted without")
    print("     having to open permanent, risky inbound firewall ports.")
    print("  2. Unsolicited inbound intrusions (Packets #4 and #5) were immediately dropped")
    print("     because no matching state entry existed in the table.")
    print("  3. Stateful inspection drastically reduces attack surface compared to stateless ACLs.")
    print("=" * 75 + "\n")


def main():
    print("======================================================================")
    print("  Cybersecurity Lab - Practical 10: Stateful Inspection Firewall")
    print("======================================================================")
    run_firewall_demo()


if __name__ == "__main__":
    main()
