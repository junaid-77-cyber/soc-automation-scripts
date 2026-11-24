# SOC Automation Scripts

Python toolkit for SOC analysts — log parsing, IOC extraction, threat intel enrichment, and automated alert triage helpers.

Built as hands-on practice for real-world Security Operations Center workflows.

## Tools

| Script | Purpose |
|--------|---------|
| `log_parser.py` | Parse and normalize syslog, Windows Event Logs, and Apache/Nginx access logs into structured JSON |
| `ioc_extractor.py` | Extract Indicators of Compromise (IPs, domains, URLs, hashes, emails) from raw text, logs, or reports |
| `alert_triager.py` | Rule-based alert triage engine — scores alerts by severity, deduplicates, and suggests response actions |
| `threat_intel_lookup.py` | Enrich IOCs against public threat intelligence sources (AbuseIPDB, VirusTotal, OTX) |

## Setup

```bash
pip install -r requirements.txt
```

## Usage

### Extract IOCs from a log file
```bash
python -I ioc_extractor.py --input sample_logs/auth.log --output iocs.json
```

### Parse and normalize logs
```bash
python -I log_parser.py --input sample_logs/syslog.log --format syslog --output parsed.json
```

### Triage alerts
```bash
python -I alert_triager.py --input alerts.json --rules rules/default_rules.json --output triaged.json
```

### Look up threat intel for extracted IOCs
```bash
python -I threat_intel_lookup.py --input iocs.json --output enriched.json
```

## Sample Output

```json
{
  "ioc": "192.168.1.100",
  "type": "ipv4",
  "context": "Failed SSH login attempt",
  "source_file": "auth.log",
  "line_number": 42,
  "timestamp": "2026-11-20T03:14:22Z"
}
```

## License

MIT
