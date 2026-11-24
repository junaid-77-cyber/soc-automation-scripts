#!/usr/bin/env python3
"""Extract Indicators of Compromise (IOCs) from raw text, logs, or reports."""

import argparse
import json
import re
import sys
from pathlib import Path

IOC_PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|gov|edu|mil|co|info|biz|xyz|top|ru|cn|tk|de|uk)\b"
    ),
    "url": re.compile(
        r"https?://[^\s<>\"'}\])]+"
    ),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
    "md5": re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    ),
    "sha1": re.compile(
        r"\b[a-fA-F0-9]{40}\b"
    ),
    "sha256": re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    ),
    "cve": re.compile(
        r"\bCVE-\d{4}-\d{4,7}\b"
    ),
}

PRIVATE_IP_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
]

FALSE_POSITIVE_DOMAINS = {
    "example.com", "localhost.localdomain", "schema.org",
    "www.w3.org", "purl.org", "xmlns.com",
}


def is_private_ip(ip: str) -> bool:
    return any(pattern.match(ip) for pattern in PRIVATE_IP_RANGES)


def extract_iocs(text: str, include_private: bool = False) -> dict[str, list[dict]]:
    """Extract all IOC types from text. Returns a dict keyed by IOC type."""
    results = {}

    for ioc_type, pattern in IOC_PATTERNS.items():
        seen = set()
        matches = []

        for line_num, line in enumerate(text.splitlines(), 1):
            for match in pattern.finditer(line):
                value = match.group().rstrip(".,;:)")

                if value in seen:
                    continue
                seen.add(value)

                if ioc_type == "ipv4" and not include_private and is_private_ip(value):
                    continue
                if ioc_type == "domain" and value.lower() in FALSE_POSITIVE_DOMAINS:
                    continue

                context_start = max(0, match.start() - 40)
                context_end = min(len(line), match.end() + 40)
                context = line[context_start:context_end].strip()

                matches.append({
                    "value": value,
                    "type": ioc_type,
                    "line_number": line_num,
                    "context": context,
                })

        if matches:
            results[ioc_type] = matches

    return results


def extract_from_file(filepath: str, include_private: bool = False) -> dict:
    path = Path(filepath)
    if not path.exists():
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    text = path.read_text(encoding="utf-8", errors="replace")
    iocs = extract_iocs(text, include_private)

    flat_list = []
    for ioc_type, matches in iocs.items():
        for match in matches:
            match["source_file"] = str(path.name)
            flat_list.append(match)

    return {
        "source": str(filepath),
        "total_iocs": len(flat_list),
        "summary": {ioc_type: len(matches) for ioc_type, matches in iocs.items()},
        "iocs": flat_list,
    }


def main():
    parser = argparse.ArgumentParser(description="Extract IOCs from text files or logs")
    parser.add_argument("--input", "-i", required=True, help="Input file path")
    parser.add_argument("--output", "-o", help="Output JSON file (default: stdout)")
    parser.add_argument("--include-private", action="store_true",
                        help="Include private/internal IP addresses")
    parser.add_argument("--type", "-t", choices=list(IOC_PATTERNS.keys()),
                        help="Extract only this IOC type")
    args = parser.parse_args()

    result = extract_from_file(args.input, args.include_private)

    if args.type:
        result["iocs"] = [ioc for ioc in result["iocs"] if ioc["type"] == args.type]
        result["total_iocs"] = len(result["iocs"])
        result["summary"] = {args.type: result["total_iocs"]}

    output = json.dumps(result, indent=2)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Extracted {result['total_iocs']} IOCs -> {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
