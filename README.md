# CVEsweep

A command-line network vulnerability scanner that discovers open ports, fingerprints running service versions, and maps them to known CVEs from the NIST National Vulnerability Database.

---

## What It Does

CVESweep combines nmap-based port scanning with live CVE lookups to give you a clear picture of what's exposed on a network and whether those services have known vulnerabilities. Point it at a host or subnet and it will scan for open ports, detect what software is running and what version, query the NVD API for matching CVEs, and produce a report in your choice of formats.

---

## Features

- TCP connect, SYN (stealth), UDP, and aggressive scan modes
- Service version detection for accurate CVE matching
- Live CVE lookup against the NIST NVD API with 24-hour local caching
- CVSS severity filtering — show only HIGH, CRITICAL, or any threshold you choose
- NSE script support for extended service enumeration
- Multiple output formats: terminal table, plain text (`-oN`), JSON (`-oJ`), and self-contained HTML (`-oH`)
- Scan single IPs, hostnames, CIDR subnets, IP ranges, or target lists from a file
- IPv6 support

---

## Requirements

- Python 3.8+
- nmap installed and on `PATH` — `apt install nmap`
- Python dependencies: `python-libnmap`, `requests`, `rich`, `Jinja2`, `packaging`
- Root/sudo — required only for SYN scans (`-sS`), UDP scans (`-sU`), and OS detection (`-O` / `-A`)
- NVD API key (optional but recommended) — raises the rate limit from 5 to 50 requests per 30 seconds. Free key: https://nvd.nist.gov/developers/request-an-api-key

---

## Installation

```bash
git clone https://github.com/WGilesCyber/CVESweep.git
cd CVESweep
pip install -e .
cvesweep --help
```

---

## Quick Start

**Scan a single host:**
```bash
cvesweep -sT -sV 192.168.1.5
```

**Scan a subnet and save an HTML report:**
```bash
cvesweep -sT -sV --open 192.168.1.0/24 -oH report.html
```

**Show only HIGH and CRITICAL CVEs:**
```bash
cvesweep -sT -sV 10.0.0.1 --min-cvss 7.0 -v
```

**Stealth SYN scan of the 1000 most common ports (requires root):**
```bash
sudo cvesweep -sS --top-ports 1000 10.0.0.0/24 -T4 -oJ results.json
```

**Scan from a target list and output all formats:**
```bash
cvesweep -sT -sV -iL targets.txt -oN out.txt -oJ out.json -oH out.html
```

For the full list of flags, scan techniques, output options, and examples see [USAGE.md](USAGE.md).

---

## Output Formats

| Flag | Format |
|------|--------|
| (none) | Terminal table |
| `-oN <file>` | Plain text |
| `-oJ <file>` | JSON |
| `-oH <file>` | Self-contained HTML report (Bootstrap 5, no internet required) |

Multiple formats can be combined in a single run.

---

## CVSS Severity Reference

| Score | Severity |
|-------|----------|
| 0.1 – 3.9 | LOW |
| 4.0 – 6.9 | MEDIUM |
| 7.0 – 8.9 | HIGH |
| 9.0 – 10.0 | CRITICAL |

Use `--min-cvss <score>` to filter results to a minimum severity threshold.

---

## Legal Disclaimer

CVESweep is intended for use on networks and systems you own or have explicit written permission to test. Unauthorized scanning is illegal. The author assumes no liability for misuse of this tool.

---

## License

MIT
