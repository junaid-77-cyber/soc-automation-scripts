#!/usr/bin/env python3
"""Enrich IOCs against public threat intelligence sources (AbuseIPDB, VirusTotal, OTX)."""

import argparse
import json
import os
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: 'requests' library required. Run: pip install requests", file=sys.stderr)
    sys.exit(1)


class ThreatIntelEnricher:
    """Look up IOCs against public threat intelligence APIs."""

    def __init__(self):
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "SOC-Automation-Toolkit/1.0"

    def lookup_abuseipdb(self, ip: str) -> dict | None:
        """Check an IP against AbuseIPDB."""
        if not self.abuseipdb_key:
            return {"source": "abuseipdb", "status": "skipped", "reason": "No API key (set ABUSEIPDB_API_KEY)"}

        try:
            resp = self.session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "source": "abuseipdb",
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "is_malicious": data.get("abuseConfidenceScore", 0) > 50,
                }
            return {"source": "abuseipdb", "status": "error", "code": resp.status_code}
        except requests.RequestException as e:
            return {"source": "abuseipdb", "status": "error", "reason": str(e)}

    def lookup_virustotal_hash(self, file_hash: str) -> dict | None:
        """Check a file hash against VirusTotal."""
        if not self.virustotal_key:
            return {"source": "virustotal", "status": "skipped", "reason": "No API key (set VIRUSTOTAL_API_KEY)"}

        try:
            resp = self.session.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": self.virustotal_key},
                timeout=10,
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "source": "virustotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()),
                    "is_malicious": stats.get("malicious", 0) > 3,
                }
            if resp.status_code == 404:
                return {"source": "virustotal", "status": "not_found"}
            return {"source": "virustotal", "status": "error", "code": resp.status_code}
        except requests.RequestException as e:
            return {"source": "virustotal", "status": "error", "reason": str(e)}

    def enrich_ioc(self, ioc: dict) -> dict:
        """Enrich a single IOC with threat intelligence."""
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")
        enrichments = []

        if ioc_type == "ipv4":
            result = self.lookup_abuseipdb(value)
            if result:
                enrichments.append(result)

        elif ioc_type in ("md5", "sha1", "sha256"):
            result = self.lookup_virustotal_hash(value)
            if result:
                enrichments.append(result)

        is_malicious = any(e.get("is_malicious", False) for e in enrichments)

        return {
            **ioc,
            "enrichments": enrichments,
            "verdict": "malicious" if is_malicious else "clean/unknown",
        }

    def enrich_all(self, iocs: list, rate_limit_delay: float = 1.0) -> list:
        """Enrich a list of IOCs with rate limiting."""
        enriched = []
        for i, ioc in enumerate(iocs):
            enriched.append(self.enrich_ioc(ioc))
            if i < len(iocs) - 1:
                time.sleep(rate_limit_delay)
        return enriched


def main():
    parser = argparse.ArgumentParser(description="Enrich IOCs with threat intelligence")
    parser.add_argument("--input", "-i", required=True, help="Input IOCs JSON file (from ioc_extractor.py)")
    parser.add_argument("--output", "-o", help="Output JSON file (default: stdout)")
    parser.add_argument("--delay", "-d", type=float, default=1.0,
                        help="Delay between API calls in seconds (default: 1.0)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    data = json.loads(input_path.read_text(encoding="utf-8"))
    iocs = data.get("iocs", []) if isinstance(data, dict) else data

    enricher = ThreatIntelEnricher()

    api_status = []
    if not enricher.abuseipdb_key:
        api_status.append("AbuseIPDB: No API key (set ABUSEIPDB_API_KEY env var)")
    if not enricher.virustotal_key:
        api_status.append("VirusTotal: No API key (set VIRUSTOTAL_API_KEY env var)")
    if api_status:
        print("API status:", file=sys.stderr)
        for s in api_status:
            print(f"  - {s}", file=sys.stderr)

    enriched = enricher.enrich_all(iocs, args.delay)

    malicious_count = sum(1 for e in enriched if e.get("verdict") == "malicious")

    result = {
        "total_iocs": len(enriched),
        "malicious": malicious_count,
        "clean_or_unknown": len(enriched) - malicious_count,
        "iocs": enriched,
    }

    output = json.dumps(result, indent=2)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Enriched {len(enriched)} IOCs ({malicious_count} malicious) -> {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
