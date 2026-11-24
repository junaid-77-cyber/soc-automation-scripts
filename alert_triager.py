#!/usr/bin/env python3
"""Rule-based alert triage engine — scores alerts by severity, deduplicates, and suggests response actions."""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

DEFAULT_RULES = {
    "severity_weights": {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1,
    },
    "keywords_critical": [
        "ransomware", "data exfiltration", "privilege escalation",
        "lateral movement", "c2 beacon", "command and control",
        "mimikatz", "cobalt strike", "bloodhound",
    ],
    "keywords_high": [
        "brute force", "failed login", "unauthorized access",
        "malware detected", "suspicious process", "port scan",
        "reverse shell", "powershell encoded", "credential dump",
    ],
    "keywords_medium": [
        "policy violation", "unusual traffic", "new user created",
        "firewall deny", "vpn anomaly", "failed authentication",
    ],
    "auto_escalate_sources": [
        "edr", "ids", "dlp", "siem",
    ],
    "suppress_duplicate_window_seconds": 300,
}


def classify_severity(alert: dict, rules: dict) -> str:
    """Classify alert severity based on keyword matching."""
    title = (alert.get("title", "") + " " + alert.get("description", "")).lower()

    for keyword in rules["keywords_critical"]:
        if keyword in title:
            return "critical"
    for keyword in rules["keywords_high"]:
        if keyword in title:
            return "high"
    for keyword in rules["keywords_medium"]:
        if keyword in title:
            return "medium"

    return alert.get("severity", "low").lower()


def calculate_score(alert: dict, severity: str, rules: dict) -> int:
    """Calculate a numeric triage score."""
    base_score = rules["severity_weights"].get(severity, 1)
    source = alert.get("source", "").lower()
    if source in rules["auto_escalate_sources"]:
        base_score += 3
    if alert.get("repeated_count", 1) > 5:
        base_score += 2
    return min(base_score, 15)


def suggest_action(severity: str, alert: dict) -> str:
    """Suggest a response action based on severity and context."""
    actions = {
        "critical": "IMMEDIATE: Isolate affected host, notify incident response team, preserve evidence",
        "high": "URGENT: Investigate within 1 hour, correlate with other alerts, check for IOCs",
        "medium": "REVIEW: Investigate within 4 hours, check if policy violation is intentional",
        "low": "MONITOR: Log for trend analysis, review during next shift",
    }
    return actions.get(severity, "MONITOR: Review and document")


def deduplicate_alerts(alerts: list, window_seconds: int) -> list:
    """Remove duplicate alerts within a time window."""
    seen = {}
    deduped = []

    for alert in alerts:
        key = (alert.get("title", ""), alert.get("source_ip", ""), alert.get("source", ""))
        timestamp = alert.get("timestamp", "")

        if key in seen:
            prev = seen[key]
            prev["repeated_count"] = prev.get("repeated_count", 1) + 1
            continue

        alert["repeated_count"] = 1
        seen[key] = alert
        deduped.append(alert)

    return deduped


def triage_alerts(alerts: list, rules: dict = None) -> dict:
    """Main triage pipeline: deduplicate, classify, score, sort."""
    if rules is None:
        rules = DEFAULT_RULES

    deduped = deduplicate_alerts(alerts, rules["suppress_duplicate_window_seconds"])
    triaged = []

    for alert in deduped:
        severity = classify_severity(alert, rules)
        score = calculate_score(alert, severity, rules)
        action = suggest_action(severity, alert)

        triaged.append({
            **alert,
            "triage_severity": severity,
            "triage_score": score,
            "suggested_action": action,
        })

    triaged.sort(key=lambda x: x["triage_score"], reverse=True)

    severity_counts = Counter(a["triage_severity"] for a in triaged)

    return {
        "total_input": len(alerts),
        "after_dedup": len(triaged),
        "duplicates_suppressed": len(alerts) - len(triaged),
        "severity_breakdown": dict(severity_counts),
        "alerts": triaged,
    }


def main():
    parser = argparse.ArgumentParser(description="Triage security alerts")
    parser.add_argument("--input", "-i", required=True, help="Input alerts JSON file")
    parser.add_argument("--rules", "-r", help="Custom rules JSON file (default: built-in rules)")
    parser.add_argument("--output", "-o", help="Output JSON file (default: stdout)")
    parser.add_argument("--severity", "-s", choices=["critical", "high", "medium", "low"],
                        help="Filter output to only this severity")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    alerts = json.loads(input_path.read_text(encoding="utf-8"))
    if isinstance(alerts, dict):
        alerts = alerts.get("alerts", [])

    rules = DEFAULT_RULES
    if args.rules:
        rules_path = Path(args.rules)
        if rules_path.exists():
            custom = json.loads(rules_path.read_text(encoding="utf-8"))
            rules = {**DEFAULT_RULES, **custom}

    result = triage_alerts(alerts, rules)

    if args.severity:
        result["alerts"] = [a for a in result["alerts"] if a["triage_severity"] == args.severity]

    output = json.dumps(result, indent=2)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Triaged {result['after_dedup']} alerts -> {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
