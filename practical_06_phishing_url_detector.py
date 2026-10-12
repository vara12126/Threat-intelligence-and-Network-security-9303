"""
Practical 06: Heuristic Phishing URL Detector
Subject: Threat Intelligence and Network Security

Aim:
    To analyze suspicious Uniform Resource Locators (URLs) using multi-factor
    heuristic indicators, calculate a quantitative risk score (0-100), assign
    a threat risk category, and provide detailed diagnostic justification.

Heuristic Indicators Evaluated:
    1. Suspicious keywords in domain or path (e.g., login, verify, banking, secure)
    2. IP address used directly as the hostname (bypassing DNS)
    3. Excessive subdomain nesting (domain impersonation technique)
    4. Abnormal URL length (> 75 characters)
    5. Known URL shortening services (obfuscating true destination)
    6. Misleading structural symbols ('@' character for credential spoofing, excessive hyphens)

Disclaimer:
    Heuristic rule-based detection provides probabilistic screening and cannot
    guarantee 100% accuracy. Comprehensive defense requires sandboxing and threat feeds.
"""

import re
import sys
from urllib.parse import urlparse

# Suspicious keywords commonly found in credential harvesting lures
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "banking",
    "account", "security", "secure", "confirm", "wallet", "password",
    "authenticate", "support", "billing", "recover", "appleid", "paypal"
]

# Popular URL shortening domains that hide destination URLs
SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl",
    "ow.ly", "buff.ly", "cutt.ly", "rebrand.ly"
]


def analyze_url(url: str) -> dict:
    """
    Evaluates the input URL across 6 cybersecurity heuristic checks.
    Returns calculated score, category, and list of triggered findings.
    """
    url_trimmed = url.strip()
    if not url_trimmed.startswith(("http://", "https://")):
        # Prepend scheme for standard parsing if missing
        parsed = urlparse("http://" + url_trimmed)
    else:
        parsed = urlparse(url_trimmed)

    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    full_str = url_trimmed.lower()

    findings = []
    risk_score = 0

    # Indicator 1: IP address as hostname (Weight: 30)
    # IPv4 regex: 4 octets between 0-255
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, hostname):
        risk_score += 30
        findings.append({
            "rule": "Direct IP-Based Hostname",
            "weight": 30,
            "detail": f"Hostname '{hostname}' uses a raw IP address instead of a legitimate registered domain name."
        })

    # Indicator 2: Presence of '@' symbol (Weight: 25)
    # Browsers interpret user:pass@host, ignoring preceding text
    if "@" in full_str:
        risk_score += 25
        findings.append({
            "rule": "Misleading '@' Symbol in URL",
            "weight": 25,
            "detail": "Contains '@' symbol, often used to fool users while the browser redirects to the host after '@'."
        })

    # Indicator 3: Excessive Subdomains (Weight: 20)
    subdomains = hostname.split(".")
    # Standard: sub.example.com has 3 parts. 4+ parts implies nested subdomains
    if len(subdomains) >= 4 and not re.match(ip_pattern, hostname):
        risk_score += 20
        findings.append({
            "rule": "Excessive Subdomain Nesting",
            "weight": 20,
            "detail": f"Hostname contains {len(subdomains)-2} subdomains ('{hostname}'), common in brand impersonation."
        })

    # Indicator 4: Abnormal URL Length (Weight: 15)
    if len(url_trimmed) > 75:
        risk_score += 15
        findings.append({
            "rule": "Unusual Length (> 75 chars)",
            "weight": 15,
            "detail": f"Total URL length is {len(url_trimmed)} characters, indicating possible token embedding or obfuscation."
        })

    # Indicator 5: Known URL Shortener (Weight: 15)
    if any(shortener in hostname for shortener in SHORTENER_DOMAINS):
        risk_score += 15
        findings.append({
            "rule": "URL Shortener Domain Detected",
            "weight": 15,
            "detail": f"Domain '{hostname}' obfuscates the final destination server."
        })

    # Indicator 6: Suspicious Keywords in Path or Subdomains (Weight: 10 per keyword, max 20)
    matched_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_str]
    if matched_kws:
        kw_weight = min(len(matched_kws) * 10, 20)
        risk_score += kw_weight
        findings.append({
            "rule": "Phishing Keywords Present",
            "weight": kw_weight,
            "detail": f"Detected suspicious keywords: {', '.join(matched_kws[:4])}."
        })

    # Indicator 7: Excessive Hyphens in Domain (Weight: 10)
    if hostname.count("-") >= 2:
        risk_score += 10
        findings.append({
            "rule": "Multiple Hyphens in Domain",
            "weight": 10,
            "detail": f"Domain contains {hostname.count('-')} hyphens, a common typosquatting/homograph technique."
        })

    # Clamp risk score at 100
    risk_score = min(risk_score, 100)

    # Risk Categorization
    if risk_score >= 60:
        category = "CRITICAL / HIGH RISK (Phishing Probable)"
    elif risk_score >= 35:
        category = "MEDIUM RISK (Suspicious / Caution Advised)"
    elif risk_score >= 15:
        category = "LOW RISK (Minor Anomalies Detected)"
    else:
        category = "SAFE / BENIGN (Normal Web Pattern)"

    return {
        "url": url_trimmed,
        "score": risk_score,
        "category": category,
        "findings": findings
    }


def display_phishing_report(result: dict):
    """Outputs the diagnostic threat report."""
    print("\n" + "=" * 75)
    print("             HEURISTIC PHISHING URL DETECTOR REPORT")
    print("=" * 75)
    print(f"Target URL   : {result['url']}")
    print(f"Risk Score   : {result['score']} / 100")
    print(f"Assessment   : {result['category']}")
    print("-" * 75)
    print(f"{'TRIGGERED INDICATOR':<30} {'WEIGHT':<8} {'TECHNICAL EVIDENCE'}")
    print("-" * 75)

    if result["findings"]:
        for f in result["findings"]:
            print(f"{f['rule']:<30} {f['weight']:<8} {f['detail']}")
    else:
        print("No suspicious heuristics triggered. Standard domain and path format.")

    print("-" * 75)
    print("SECURITY RECOMMENDATION & LIMITATION NOTICE:")
    if result["score"] >= 60:
        print("  - BLOCK & ISOLATE: High confidence of malicious credential harvesting or spoofing.")
        print("  - Submit URL to DNS sinkhole, firewall blocklists, and SIEM correlation rules.")
    elif result["score"] >= 35:
        print("  - SANDBOX & VERIFY: Route traffic through Web Isolation / Secure Web Gateway.")
    else:
        print("  - ALLOW: No immediate indicators found. Retain standard SSL/TLS validation.")
    print("  * Note: Heuristic rules detect known patterns. Attackers may employ zero-day")
    print("    domains. Always corroborate with threat intelligence feeds (e.g., VirusTotal).")
    print("=" * 75 + "\n")


SAMPLE_URLS = [
    "http://192.168.1.105/bank-login/verify-account-update/index.php?token=92837482348",
    "https://www.paypal.com.customer-verify.security-update.xyz/signin",
    "http://legitimate-university.edu/student/grades/portal.html"
]


def main():
    print("======================================================================")
    print("  Cybersecurity Lab - Practical 06: Phishing URL Detector")
    print("======================================================================")
    print("Pre-configured Test Cases:")
    print("  [1] IP-based credential harvester: http://192.168.1.105/bank-login/...")
    print("  [2] Subdomain impersonation link : https://www.paypal.com.customer-verify...")
    print("  [3] Benign institutional portal : http://legitimate-university.edu/...")
    print("  [4] Enter custom URL")
    print("-" * 70)

    try:
        choice = input("Enter choice (1-4, default 1): ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "1"

    if choice in ["1", "2", "3"]:
        target_url = SAMPLE_URLS[int(choice) - 1]
    elif choice == "4":
        target_url = input("Enter custom URL to scan: ").strip()
        if not target_url:
            target_url = SAMPLE_URLS[0]
    else:
        target_url = SAMPLE_URLS[0]

    result = analyze_url(target_url)
    display_phishing_report(result)


if __name__ == "__main__":
    main()
