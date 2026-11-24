#!/usr/bin/env python3
"""Parse and normalize syslog, Windows Event Logs, and web server access logs into structured JSON."""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

APACHE_COMBINED_PATTERN = re.compile(
    r'^(?P<remote_host>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)

AUTH_PATTERNS = {
    "failed_login": re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)"),
    "successful_login": re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)"),
    "sudo_command": re.compile(r"(\S+) : .* COMMAND=(.+)$"),
    "session_opened": re.compile(r"session opened for user (\S+)"),
    "session_closed": re.compile(r"session closed for user (\S+)"),
}


def parse_syslog_line(line: str) -> dict | None:
    match = SYSLOG_PATTERN.match(line.strip())
    if not match:
        return None

    entry = {
        "format": "syslog",
        "timestamp_raw": match.group("timestamp"),
        "hostname": match.group("hostname"),
        "process": match.group("process"),
        "pid": match.group("pid"),
        "message": match.group("message"),
        "security_events": [],
    }

    for event_type, pattern in AUTH_PATTERNS.items():
        event_match = pattern.search(entry["message"])
        if event_match:
            entry["security_events"].append({
                "type": event_type,
                "details": event_match.groups(),
            })

    return entry


def parse_apache_line(line: str) -> dict | None:
    match = APACHE_COMBINED_PATTERN.match(line.strip())
    if not match:
        return None

    status = int(match.group("status"))
    bytes_sent = match.group("bytes")

    return {
        "format": "apache_combined",
        "remote_host": match.group("remote_host"),
        "user": match.group("user") if match.group("user") != "-" else None,
        "timestamp_raw": match.group("timestamp"),
        "method": match.group("method"),
        "path": match.group("path"),
        "protocol": match.group("protocol"),
        "status": status,
        "bytes": int(bytes_sent) if bytes_sent != "-" else 0,
        "referer": match.group("referer") if match.group("referer") != "-" else None,
        "user_agent": match.group("user_agent"),
        "is_error": status >= 400,
        "is_server_error": status >= 500,
    }


PARSERS = {
    "syslog": parse_syslog_line,
    "apache": parse_apache_line,
    "auth": parse_syslog_line,
}


def parse_log_file(filepath: str, log_format: str) -> dict:
    path = Path(filepath)
    if not path.exists():
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    parser_fn = PARSERS.get(log_format)
    if not parser_fn:
        print(f"Error: Unknown format '{log_format}'. Supported: {list(PARSERS.keys())}", file=sys.stderr)
        sys.exit(1)

    entries = []
    failed_lines = 0
    security_event_count = 0

    with open(path, encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            parsed = parser_fn(line)
            if parsed:
                parsed["line_number"] = line_num
                entries.append(parsed)
                security_event_count += len(parsed.get("security_events", []))
            else:
                failed_lines += 1

    return {
        "source": str(filepath),
        "format": log_format,
        "total_entries": len(entries),
        "failed_lines": failed_lines,
        "security_events_found": security_event_count,
        "entries": entries,
    }


def main():
    parser = argparse.ArgumentParser(description="Parse logs into structured JSON")
    parser.add_argument("--input", "-i", required=True, help="Input log file")
    parser.add_argument("--format", "-f", required=True, choices=list(PARSERS.keys()),
                        help="Log format")
    parser.add_argument("--output", "-o", help="Output JSON file (default: stdout)")
    parser.add_argument("--security-only", action="store_true",
                        help="Only output entries with security events")
    args = parser.parse_args()

    result = parse_log_file(args.input, args.format)

    if args.security_only:
        result["entries"] = [e for e in result["entries"] if e.get("security_events")]
        result["total_entries"] = len(result["entries"])

    output = json.dumps(result, indent=2)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Parsed {result['total_entries']} entries -> {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
