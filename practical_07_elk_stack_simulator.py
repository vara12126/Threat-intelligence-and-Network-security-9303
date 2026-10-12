"""
Practical 07: ELK Stack Architecture Simulator (Logstash, Elasticsearch, Kibana)
Subject: Threat Intelligence and Network Security

Aim:
    To simulate the end-to-end security log analysis workflow of the Elastic Stack (ELK):
      1. Logstash Simulation: Ingest and parse raw web access logs into structured JSON-like events.
      2. Elasticsearch Simulation: Index events with an inverted index and document store.
      3. Kibana Simulation: Aggregate telemetry (HTTP status codes, top client IPs, requested paths)
         and render an ASCII SOC analytics dashboard with anomaly detection.
"""

import re
import sys
from collections import Counter
from datetime import datetime

# Sample raw web server logs (Apache/Nginx Combined Log Format)
RAW_ACCESS_LOGS = [
    '192.168.1.10 - - [12/Oct/2026:10:14:01 +0000] "GET /index.html HTTP/1.1" 200 4521 "Mozilla/5.0"',
    '192.168.1.15 - - [12/Oct/2026:10:14:03 +0000] "GET /products/item1 HTTP/1.1" 200 8912 "Mozilla/5.0"',
    '203.0.113.45 - - [12/Oct/2026:10:14:15 +0000] "POST /api/v1/login HTTP/1.1" 401 532 "Python-requests/2.28"',
    '203.0.113.45 - - [12/Oct/2026:10:14:18 +0000] "POST /api/v1/login HTTP/1.1" 401 532 "Python-requests/2.28"',
    '203.0.113.45 - - [12/Oct/2026:10:14:22 +0000] "POST /api/v1/login HTTP/1.1" 200 1204 "Python-requests/2.28"',
    '198.51.100.99 - - [12/Oct/2026:10:14:40 +0000] "GET /wp-admin/login.php HTTP/1.1" 404 312 "Nikto/2.1.6"',
    '198.51.100.99 - - [12/Oct/2026:10:14:42 +0000] "GET /.env HTTP/1.1" 404 312 "Nikto/2.1.6"',
    '198.51.100.99 - - [12/Oct/2026:10:14:45 +0000] "GET /phpmyadmin HTTP/1.1" 403 280 "Nikto/2.1.6"',
    '10.0.0.52 - - [12/Oct/2026:10:15:02 +0000] "GET /dashboard HTTP/1.1" 200 6720 "Mozilla/5.0"',
    '10.0.0.52 - - [12/Oct/2026:10:15:10 +0000] "GET /api/reports HTTP/1.1" 500 184 "Mozilla/5.0"',
    '192.168.1.10 - - [12/Oct/2026:10:15:30 +0000] "GET /style.css HTTP/1.1" 200 1890 "Mozilla/5.0"',
    '198.51.100.99 - - [12/Oct/2026:10:15:35 +0000] "GET /config.json HTTP/1.1" 404 312 "Nikto/2.1.6"'
]


# ==========================================
# 1. LOGSTASH SIMULATION (Ingest & Parse)
# ==========================================
def logstash_parser(raw_lines: list) -> list:
    """
    Simulates Logstash pipeline using Grok/Regex parsing to transform
    unstructured log strings into structured JSON-compatible event dicts.
    """
    # Regex matching: IP - - [TIMESTAMP] "METHOD PATH PROTOCOL" STATUS SIZE "USER_AGENT"
    log_pattern = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<bytes>\d+)\s+"(?P<user_agent>[^"]+)"'
    )

    parsed_events = []
    for line_num, line in enumerate(raw_lines, 1):
        match = log_pattern.match(line.strip())
        if match:
            data = match.groupdict()
            event = {
                "_id": f"doc-{line_num:03d}",
                "@timestamp": data["timestamp"],
                "client_ip": data["ip"],
                "http_method": data["method"],
                "request_path": data["path"],
                "status_code": int(data["status"]),
                "response_size": int(data["bytes"]),
                "user_agent": data["user_agent"]
            }
            parsed_events.append(event)
    return parsed_events


# ==========================================
# 2. ELASTICSEARCH SIMULATION (Index & Store)
# ==========================================
class ElasticsearchSimulator:
    """
    Simulates an Elasticsearch cluster holding documents and maintaining
    in-memory inverted indices for rapid keyword and attribute filtering.
    """
    def __init__(self, index_name="security-web-logs-2026"):
        self.index_name = index_name
        self.documents = {}
        self.inverted_index = {}  # term -> list of doc_ids

    def index_documents(self, events: list):
        for doc in events:
            doc_id = doc["_id"]
            self.documents[doc_id] = doc
            # Build inverted index across searchable fields
            for field in ["client_ip", "http_method", "request_path", "status_code"]:
                term = f"{field}:{doc[field]}"
                self.inverted_index.setdefault(term, []).append(doc_id)

    def search(self, term: str) -> list:
        doc_ids = self.inverted_index.get(term, [])
        return [self.documents[did] for did in doc_ids]

    def get_all(self) -> list:
        return list(self.documents.values())


# ==========================================
# 3. KIBANA SIMULATION (Aggregate & Visualize)
# ==========================================
def kibana_dashboard(documents: list):
    """
    Simulates Kibana aggregation aggregations (terms, metric, filters)
    and produces an ASCII SOC telemetry dashboard.
    """
    total_docs = len(documents)
    status_counts = Counter(d["status_code"] for d in documents)
    ip_counts = Counter(d["client_ip"] for d in documents)
    path_counts = Counter(d["request_path"] for d in documents)
    method_counts = Counter(d["http_method"] for d in documents)

    print("\n" + "=" * 75)
    print("           KIBANA SOC TELEMETRY DASHBOARD (SIMULATED)")
    print("=" * 75)
    print(f"Index: [security-web-logs-2026]  |  Total Events Indexed: {total_docs}")
    print("-" * 75)

    # Status Code Aggregation
    print("1. HTTP STATUS CODE DISTRIBUTION:")
    for code, count in sorted(status_counts.items()):
        pct = (count / total_docs) * 100
        bar = "#" * int(pct / 3)
        desc = {200: "OK", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 500: "Internal Error"}.get(code, "")
        print(f"   HTTP {code} ({desc:<14}): {count:>2} events ({pct:>5.1f}%) {bar}")

    # Top IP Aggregation
    print("\n2. TOP TALKER CLIENT IP ADDRESSES:")
    for ip, count in ip_counts.most_common(5):
        pct = (count / total_docs) * 100
        bar = "=" * int(pct / 3)
        print(f"   {ip:<18}: {count:>2} requests ({pct:>5.1f}%) {bar}")

    # Top Requested Paths
    print("\n3. FREQUENT REQUESTED PATHS & ENDPOINTS:")
    for path, count in path_counts.most_common(5):
        print(f"   {path:<28}: {count:>2} hits")

    # Threat Intelligence Alerts
    print("-" * 75)
    print("4. SECURITY INTELLIGENCE ALERTS DETECTED:")
    alerts = []
    # Check for vulnerability scanner / recon
    for doc in documents:
        if "Nikto" in doc["user_agent"]:
            alerts.append(f"[ALERT] Recon Scanner Detected: IP {doc['client_ip']} probing '{doc['request_path']}' with Nikto.")
            break
    # Check for brute force
    if status_counts.get(401, 0) >= 2:
        alerts.append("[ALERT] Credential Brute-Force: Repeated 401 Unauthorized attempts detected on /api/v1/login.")
    # Check for server error
    if status_counts.get(500, 0) > 0:
        alerts.append("[WARNING] Server Fault: HTTP 500 Internal Error observed on /api/reports.")

    for alert in alerts:
        print(f"   * {alert}")
    print("=" * 75 + "\n")


def main():
    print("======================================================================")
    print("  Cybersecurity Lab - Practical 07: ELK Stack Simulator")
    print("======================================================================")
    print(f"Ingesting {len(RAW_ACCESS_LOGS)} sample web server logs into Logstash...\n")

    # Step 1: Logstash processing
    print("[1/3] Logstash: Parsing raw syslog/access strings into structured events...")
    structured_events = logstash_parser(RAW_ACCESS_LOGS)
    print(f"      Successfully normalized {len(structured_events)} events.")
    print("      Sample Structured Event (Doc 001):")
    sample = structured_events[0]
    for k, v in sample.items():
        print(f"        {k:<14}: {v}")

    # Step 2: Elasticsearch indexing
    print("\n[2/3] Elasticsearch: Creating index and generating inverted index mappings...")
    es = ElasticsearchSimulator()
    es.index_documents(structured_events)
    print("      Indexed mappings ready for client_ip, status_code, and request_path.")

    # Demonstration query
    search_term = "status_code:404"
    hits = es.search(search_term)
    print(f"      Test Query '{search_term}': Returned {len(hits)} matching document(s).")

    # Step 3: Kibana visualization
    print("\n[3/3] Kibana: Executing aggregations and rendering dashboard...")
    kibana_dashboard(es.get_all())


if __name__ == "__main__":
    main()
