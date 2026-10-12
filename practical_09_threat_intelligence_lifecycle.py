"""
Practical 09: Cyber Threat Intelligence Lifecycle Stage Classifier
Subject: Threat Intelligence and Network Security

Aim:
    To analyze a description of a security intelligence team's task or workflow,
    and classify it into one of the 6 classical Threat Intelligence Lifecycle stages:
      1. Direction (Planning & Scoping)
      2. Collection (Data Gathering)
      3. Processing (Normalization & Structuring)
      4. Analysis (Sensemaking & Attribution)
      5. Dissemination (Reporting & Sharing)
      6. Feedback (Evaluation & Continuous Improvement)
"""

import sys

# Knowledge base defining the 6 stages of the CTI Lifecycle
LIFECYCLE_STAGES = {
    "Direction": {
        "order": 1,
        "keywords": [
            "priority intelligence requirements", "pir", "plan", "planning", "scope",
            "goals", "stakeholder needs", "strategy", "define objectives", "governance",
            "threat modeling scope", "executive mandate"
        ],
        "summary": "Establishes goals, priorities, and intelligence requirements (PIRs) for the intelligence program."
    },
    "Collection": {
        "order": 2,
        "keywords": [
            "gather", "harvest", "scraping", "dark web", "osint", "threat feed",
            "honeypot", "crawler", "raw logs", "telemetry", "pastebin", "underground forum",
            "commercial feed", "intercept", "collecting"
        ],
        "summary": "Acquires raw, unvetted threat data from external and internal multi-source telemetry."
    },
    "Processing": {
        "order": 3,
        "keywords": [
            "normalize", "parsing", "filter", "translate", "stix", "taxii", "deduplication",
            "decryption", "enrichment", "format", "clean", "organize data", "extract iocs",
            "unstructured to structured"
        ],
        "summary": "Transforms unstructured, multilingual, or noisy data into standardized, readable formats."
    },
    "Analysis": {
        "order": 4,
        "keywords": [
            "correlate", "attribution", "threat actor", "diamond model", "kill chain",
            "mitre att&ck", "assess capability", "intent", "pattern recognition",
            "hypothesis", "adversary profiling", "risk estimation", "deep dive"
        ],
        "summary": "Synthesizes processed evidence into meaningful threat insights, identifying WHO, WHY, and HOW."
    },
    "Dissemination": {
        "order": 5,
        "keywords": [
            "publish", "distribute", "share", "briefing", "report", "ioc push", "siem ingestion",
            "alert", "newsletter", "executive summary", "tactical advisory", "misp", "disseminate"
        ],
        "summary": "Delivers actionable, tailored intelligence products to stakeholders, SOC teams, and automated tools."
    },
    "Feedback": {
        "order": 6,
        "keywords": [
            "review", "evaluate", "post-incident", "metric", "roi", "satisfaction",
            "lessons learned", "accuracy audit", "refine pirs", "stakeholder feedback",
            "effectiveness", "continuous improvement"
        ],
        "summary": "Gathers stakeholder appraisals and operational metrics to refine future requirements and direction."
    }
}


def classify_activity(activity_description: str) -> dict:
    """Classifies the given security team activity into the lifecycle stage."""
    desc_lower = activity_description.lower()
    scores = {}
    matched_kws = {}

    for stage, data in LIFECYCLE_STAGES.items():
        hits = [kw for kw in data["keywords"] if kw in desc_lower]
        scores[stage] = len(hits)
        matched_kws[stage] = hits

    sorted_stages = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    winner_stage, top_score = sorted_stages[0]

    return {
        "stage": winner_stage if top_score > 0 else "Unclassified Workflow",
        "score": top_score,
        "all_scores": scores,
        "matched": matched_kws.get(winner_stage, []),
        "details": LIFECYCLE_STAGES.get(winner_stage, {})
    }


def display_classification(activity: str, result: dict):
    """Prints the classification and lifecycle analysis."""
    print("\n" + "=" * 75)
    print("      CYBER THREAT INTELLIGENCE (CTI) LIFECYCLE CLASSIFIER")
    print("=" * 75)
    print(f"Activity Input:\n  \"{activity.strip()}\"")
    print("-" * 75)

    stage_name = result["stage"]
    if result["score"] > 0:
        stage_num = result["details"]["order"]
        print(f"Identified Stage   : Stage {stage_num}: {stage_name}")
        print(f"Confidence Score   : {result['score']} matched indicator(s)")
        print(f"Matched Indicators : {', '.join(result['matched'])}")
        print(f"Stage Definition   : {result['details']['summary']}")
    else:
        print(f"Identified Stage   : {stage_name}")
        print("Confidence Score   : 0 matches (General security activity)")

    print("-" * 75)
    print("Lifecycle Stage Score Comparison:")
    for stage, info in LIFECYCLE_STAGES.items():
        score = result["all_scores"][stage]
        bar = "#" * (score * 3)
        marker = "===>" if stage == stage_name else "    "
        print(f"{marker} [Stage {info['order']}] {stage:<15}: {score:>2} {bar}")

    print("-" * 75)
    print("Classification Reason:")
    if result["score"] > 0:
        print(f"  The activity focuses on {', '.join(result['matched'])}, which represents core")
        print(f"  operations within the '{stage_name}' phase of the intelligence cycle.")
        print("  Outputs from this stage feed directly into the subsequent phase.")
    else:
        print("  Unable to map unambiguously to an intelligence lifecycle phase.")
    print("=" * 75 + "\n")


SAMPLE_ACTIVITIES = [
    {
        "id": "1",
        "title": "Data Normalization into STIX/TAXII",
        "text": "The threat intelligence team is parsing multilingual dark web forum posts, filtering false alarms, and converting raw indicators into standardized STIX 2.1 JSON packages."
    },
    {
        "id": "2",
        "title": "Adversary Attribution & TTP Correlation",
        "text": "Senior analysts are correlating malware samples with MITRE ATT&CK techniques to attribute recent phishing campaigns to the APT28 threat actor group."
    },
    {
        "id": "3",
        "title": "Automated SIEM & Firewall IOC Push",
        "text": "Publishing verified malicious IP addresses and C2 domains to the enterprise SIEM blocklist and disseminating an emergency alert advisory to SOC tier 1."
    },
    {
        "id": "4",
        "title": "Defining Priority Intelligence Requirements (PIR)",
        "text": "CISO and leadership met with the intelligence team to define priority intelligence requirements (PIRs) and strategic scope for the 2026 fiscal year."
    }
]


def main():
    print("======================================================================")
    print("  Cybersecurity Lab - Practical 09: Threat Intelligence Lifecycle")
    print("======================================================================")
    print("Select a sample activity or provide custom input:")
    for s in SAMPLE_ACTIVITIES:
        print(f"  [{s['id']}] {s['title']}")
    print("  [5] Custom Activity Description")
    print("-" * 70)

    try:
        choice = input("Enter choice (1-5, default 1): ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "1"

    if choice in ["1", "2", "3", "4"]:
        activity_text = SAMPLE_ACTIVITIES[int(choice) - 1]["text"]
    elif choice == "5":
        activity_text = input("Enter activity description: ").strip()
        if not activity_text:
            activity_text = SAMPLE_ACTIVITIES[0]["text"]
    else:
        activity_text = SAMPLE_ACTIVITIES[0]["text"]

    result = classify_activity(activity_text)
    display_classification(activity_text, result)


if __name__ == "__main__":
    main()
