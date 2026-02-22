# CVEsweep — Usage Guide

CVEsweep is a network service enumerator and CVE scanner. It scans targets for open ports, identifies running service versions using nmap, queries the NIST National Vulnerability Database (NVD) to find known CVEs for those services, and produces reports in terminal, plain-text, JSON, and HTML formats.

---

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Scan Targets](#scan-targets)
5. [Scan Techniques](#scan-techniques)
6. [Port Specification](#port-specification)
7. [Timing Templates](#timing-templates)
8. [CVE Options](#cve-options)
9. [Script Scanning](#script-scanning)
10. [Output Options](#output-options)
11. [Exit Codes](#exit-codes)
12. [Examples](#examples)
13. [Notes](#notes)

---

## Requirements

- **Python** 3.8 or newer
- **nmap** installed and available on `PATH` (`apt install nmap` / `brew install nmap`)
- Python dependencies (installed automatically with pip): `python-libnmap`, `requests`, `rich`, `Jinja2`, `packaging`
- **Root / sudo** — required only for SYN scans (`-sS`), UDP scans (`-sU`), and OS detection (`-O` / `-A`)
- **NVD API key** (optional, but recommended) — increases the NVD rate limit from 5 to 50 requests per 30 seconds. Free key: https://nvd.nist.gov/developers/request-an-api-key

---

## Installation

**From source (recommended during development):**
```bash
git clone <repo-url>
cd CVEsweep
pip install -e .
cvesweep --help
```

**Direct invocation (no install):**
```bash
python cvesweep.py --help
```

---

## Basic Usage

```
cvesweep [options] <target>
cvesweep [options] -iL <target-file>
```

CVEsweep requires exactly one target source — either a positional `<target>` argument or a file via `-iL`.

---

## Scan Targets

### Positional target

Provide a single target directly on the command line. Supported formats:

| Format | Example |
|--------|---------|
| Single IP address | `192.168.1.5` |
| CIDR subnet | `192.168.1.0/24` |
| Hostname | `webserver.local` |
| IP range | `10.0.0.1-10` |

```bash
cvesweep -sT 192.168.1.5
cvesweep -sT 10.0.0.0/24
cvesweep -sT webserver.local
```

### `-iL <file>` — Read targets from file

Reads one target per line. Blank lines and lines starting with `#` are ignored.

```
# targets.txt
192.168.1.1
192.168.1.50
10.0.0.0/24
# this line is a comment and will be skipped
```

```bash
cvesweep -sT -iL targets.txt
```

---

## Scan Techniques

These flags control how CVEsweep instructs nmap to probe the network.

| Flag | Name | Root required | Description |
|------|------|:---:|-------------|
| `-sT` | TCP connect scan | No | Completes the full TCP three-way handshake. Works without root and through most firewalls. The default if no scan type is specified. |
| `-sS` | TCP SYN scan (stealth) | Yes | Sends SYN packets and reads responses without completing the handshake. Faster and less likely to appear in application logs. |
| `-sV` | Version detection | No | Probes open ports to determine the product name and version number of the running service. Required for accurate CVE matching. |
| `-sU` | UDP scan | Yes | Scans UDP ports. Slower than TCP scans. Useful for finding DNS (53), SNMP (161), TFTP (69), and similar services. |
| `-O` | OS detection | Yes | Attempts to determine the operating system of the target host. |
| `-A` | Aggressive mode | Yes | Enables version detection (`-sV`), OS detection (`-O`), default nmap script scanning, and traceroute in a single flag. |
| `-Pn` | Skip host discovery | No | Treats all hosts as online and skips the ping/ICMP check. Useful when targets block ICMP but have open TCP ports. |
| `-6` | IPv6 scanning | No | Enables scanning of IPv6 addresses. |

> `-sV` is strongly recommended when CVE lookup is enabled (the default). Without version information CVEsweep cannot accurately match services to CVEs.

---

## Port Specification

### `-p <ports>` — Specify ports

Control which ports are scanned. Multiple formats are supported:

| Syntax | Meaning |
|--------|---------|
| `-p 22` | Single port |
| `-p 22,80,443` | Comma-separated list |
| `-p 1-1024` | Port range (inclusive) |
| `-p 1-65535` or `-p-` | All 65535 ports |
| `-p U:53,T:80` | Mix UDP and TCP ports |

```bash
cvesweep -sT -p 22,80,443,8080 10.0.0.1
cvesweep -sT -p 1-1024 10.0.0.1
cvesweep -sT -p- 10.0.0.1          # scan all ports
```

### `--top-ports <n>` — Most common ports

Scans the N most commonly open ports as ranked by nmap. Useful for quick surveys.

```bash
cvesweep -sT --top-ports 100 10.0.0.0/24
```

### `--open` — Only show open ports

Suppresses closed and filtered ports from the terminal output.

```bash
cvesweep -sT --open 10.0.0.0/24
```

---

## Timing Templates

`-T <0-5>` controls the speed and aggressiveness of the scan. Faster scans are noisier and more likely to trigger IDS/IPS alerts.

| Value | Name | Description |
|-------|------|-------------|
| `-T 0` | Paranoid | Extremely slow; sends one probe every 5 minutes. Designed to evade IDS. |
| `-T 1` | Sneaky | Very slow; 15-second delay between probes. |
| `-T 2` | Polite | Slows down to avoid overloading the network. |
| `-T 3` | Normal | Default nmap timing. Balanced speed and reliability. |
| `-T 4` | Aggressive | Faster; assumes a fast and reliable network (LAN). |
| `-T 5` | Insane | Maximum speed; may miss results on slow or unreliable networks. |

The compact form `-T4` (no space) is also accepted.

```bash
cvesweep -sT -T4 10.0.0.0/24          # fast LAN scan
sudo cvesweep -sS -T1 10.0.0.1        # slow stealth scan
```

---

## CVE Options

### `--no-cve` — Skip CVE lookup

Performs only the port/service scan and skips all NVD API queries. Useful when you only need discovery results or want faster output.

```bash
cvesweep -sT --no-cve 192.168.1.0/24
```

### `--cve-key <apikey>` — NVD API key

Provide an NVD API key to increase the rate limit from 5 requests/30 s to 50 requests/30 s. For large scans with many discovered services this significantly reduces total run time.

Free key registration: https://nvd.nist.gov/developers/request-an-api-key

```bash
cvesweep -sT -sV 10.0.0.1 --cve-key YOUR_KEY_HERE
```

### `--min-cvss <score>` — Filter by CVSS severity

Only display CVEs with a CVSS score at or above this threshold. Accepts a float between 0.0 and 10.0. Default is `0.0` (show all).

CVSS severity bands:
| Score range | Severity |
|-------------|----------|
| 0.1 – 3.9 | LOW |
| 4.0 – 6.9 | MEDIUM |
| 7.0 – 8.9 | HIGH |
| 9.0 – 10.0 | CRITICAL |

```bash
cvesweep -sT -sV 10.0.0.1 --min-cvss 7.0    # HIGH and CRITICAL only
cvesweep -sT -sV 10.0.0.1 --min-cvss 9.0    # CRITICAL only
```

### `--no-cache` — Disable caching

By default CVEsweep caches NVD results for 24 hours in `~/.cache/cvesweep/cve_cache.db` to avoid hitting the API repeatedly for the same services. This flag disables the cache and always queries NVD live.

```bash
cvesweep -sT -sV 10.0.0.1 --no-cache
```

### `--update-cache` — Force cache refresh

Invalidates the existing cache entries for the services found in this scan before querying NVD. Use this when you want fresh results but want to keep cache entries for services not in the current scan.

```bash
cvesweep -sT -sV 10.0.0.1 --update-cache
```

---

## Script Scanning

### `--scripts <script-list>` — Run nmap NSE scripts

Passes a comma-separated list of nmap Scripting Engine (NSE) scripts to run against discovered services. Script output is included in the scan results.

```bash
cvesweep -sT -sV 10.0.0.1 --scripts banner,http-title
cvesweep -sT -sV 10.0.0.1 --scripts ssh-auth-methods,ssl-cert
cvesweep -sT -sV 10.0.0.1 --scripts "http-headers,http-methods"
```

Refer to the [nmap NSE documentation](https://nmap.org/nsedoc/) for a full list of available scripts.

---

## Output Options

### `-v` / `-vv` — Verbosity

| Flag | Effect |
|------|--------|
| (none) | Terminal table showing hosts and open ports only |
| `-v` | Adds inline CVE IDs and CVSS scores in the service table |
| `-vv` | Adds full CVE descriptions and NVD URLs below each service |

```bash
cvesweep -sT -sV 10.0.0.1 -v
cvesweep -sT -sV 10.0.0.1 -vv
```

### `-oN <file>` — Plain-text report

Saves results in an nmap-style plain-text format.

```bash
cvesweep -sT -sV 10.0.0.1 -oN scan_results.txt
```

### `-oJ <file>` — JSON report

Saves results as pretty-printed JSON. Useful for piping into other tools or scripting.

```bash
cvesweep -sT -sV 10.0.0.1 -oJ results.json
```

### `-oH <file>` — HTML report

Saves a self-contained HTML report styled with Bootstrap 5. Includes summary cards, a sortable/filterable CVE table, and a collapsible per-host accordion. Can be opened in any browser with no internet connection required.

```bash
cvesweep -sT -sV 10.0.0.1 -oH report.html
```

Multiple output formats can be combined:

```bash
cvesweep -sT -sV 10.0.0.0/24 -oN results.txt -oJ results.json -oH report.html
```

### `-V` / `--version` — Show version

```bash
cvesweep --version
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully |
| `1` | Scan error, argument error, or interrupted |
| `2` | Scan completed but no live hosts were found |

---

## Examples

**Basic TCP connect scan with version detection on a single host:**
```bash
cvesweep -sT -sV 192.168.1.5
```

**Scan a subnet, show only open ports, save an HTML report:**
```bash
cvesweep -sT -sV --open 192.168.1.0/24 -oH report.html
```

**Scan specific ports only, show HIGH/CRITICAL CVEs inline:**
```bash
cvesweep -sT -sV -p 22,80,443,8080,8443 10.0.0.1 --min-cvss 7.0 -v
```

**Stealth SYN scan of the 1000 most common ports (root required):**
```bash
sudo cvesweep -sS --top-ports 1000 10.0.0.0/24 -T4 -oJ results.json
```

**Full port scan with aggressive detection and all output formats:**
```bash
sudo cvesweep -A -p- 10.0.0.5 -oN out.txt -oJ out.json -oH out.html
```

**Skip CVE lookup for fast discovery only:**
```bash
cvesweep -sT --no-cve --open 10.0.0.0/24
```

**Scan multiple targets from a file:**
```bash
cvesweep -sT -sV -iL targets.txt --min-cvss 4.0 -oH report.html
```

**Use an NVD API key to speed up CVE lookup on large scans:**
```bash
cvesweep -sT -sV 10.0.0.0/24 --cve-key YOUR_KEY_HERE --min-cvss 7.0 -oH report.html
```

**Force a fresh CVE lookup, bypassing the 24-hour cache:**
```bash
cvesweep -sT -sV 10.0.0.1 --update-cache -v
```

**Run nmap banner and HTTP title scripts alongside CVE lookup:**
```bash
cvesweep -sT -sV 10.0.0.1 --scripts banner,http-title -vv
```

---

## Notes

### NVD API rate limiting
Without an API key CVEsweep is limited to 5 NVD requests per 30 seconds. For scans that discover many services this means the CVE lookup phase can be slow. An API key raises this limit to 50 requests per 30 seconds and is strongly recommended for subnet scans.

### Caching
CVE lookup results are cached in `~/.cache/cvesweep/cve_cache.db` with a 24-hour TTL. The cache is keyed by the service's CPE string or keyword query. Re-running a scan for the same services will return cached results instantly without hitting the NVD API.

Use `--no-cache` to always query NVD live.
Use `--update-cache` to refresh cache entries for this scan's services while keeping other cached entries intact.

### Version-range filtering
CVEsweep uses the version constraints published in NVD's vulnerability configurations to filter out CVEs that do not apply to the detected version. This reduces false positives, but accuracy depends on nmap successfully detecting the service version (`-sV`).

### Root-required flags
`-sS`, `-sU`, `-O`, and `-A` all require root privileges to create raw sockets. Run with `sudo` when using these flags. CVEsweep will warn if a root-required flag is used without sufficient privileges.
