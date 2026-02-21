"""Core data models for CVEsweep scan results."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CVEEntry:
    """A single CVE vulnerability entry from the NVD database."""
    cve_id: str       # e.g. "CVE-2023-38408"
    cvss_score: float  # e.g. 9.8
    severity: str     # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"
    description: str  # Truncated to 300 chars
    published: str    # ISO date string e.g. "2023-07-20"
    url: str          # https://nvd.nist.gov/vuln/detail/CVE-...


@dataclass
class ServiceResult:
    """A single discovered service on an open port."""
    port: int
    protocol: str       # "tcp" | "udp"
    state: str          # "open" | "filtered" | "open|filtered"
    service_name: str   # e.g. "ssh", "http", "ftp"
    product: str        # e.g. "OpenSSH", "Apache httpd"
    version: str        # e.g. "7.4", "2.4.49"
    extrainfo: str      # e.g. "(Ubuntu)", "Debian"
    banner: str         # Raw banner string from nmap or banner grabber
    cpes: List[str]     # CPE 2.2 strings from nmap, e.g. ["cpe:/a:openbsd:openssh:7.4"]
    cves: List[CVEEntry] = field(default_factory=list)  # Populated after NVD lookup

    @property
    def display_version(self) -> str:
        """Human-readable product+version string."""
        parts = [self.product, self.version, self.extrainfo]
        return " ".join(p for p in parts if p).strip() or self.service_name or "unknown"


@dataclass
class HostResult:
    """A single scanned host and all its discovered services."""
    ip: str
    hostnames: List[str]
    status: str          # "up" | "down"
    os_match: Optional[str]  # Best OS guess or None
    services: List[ServiceResult] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        """IP with first hostname in parentheses if available."""
        if self.hostnames:
            return f"{self.ip} ({self.hostnames[0]})"
        return self.ip

    @property
    def is_vulnerable(self) -> bool:
        return any(s.cves for s in self.services)

    @property
    def total_cves(self) -> int:
        return sum(len(s.cves) for s in self.services)


@dataclass
class ScanResult:
    """Complete result of a CVEsweep scan."""
    command_line: str  # Full nmap command that was run
    scan_start: str    # ISO timestamp
    scan_end: str      # ISO timestamp
    elapsed: float     # Seconds
    hosts: List[HostResult] = field(default_factory=list)

    @property
    def all_cves(self) -> List[tuple]:
        """Flattened list of (host_ip, port, service_name, CVEEntry) tuples."""
        results = []
        for host in self.hosts:
            for svc in host.services:
                for cve in svc.cves:
                    results.append((host.ip, svc.port, svc.service_name, cve))
        return results

    @property
    def vulnerable_hosts(self) -> List[HostResult]:
        return [h for h in self.hosts if h.is_vulnerable]

    @property
    def hosts_up(self) -> List[HostResult]:
        return [h for h in self.hosts if h.status == "up"]

    @property
    def total_cves(self) -> int:
        return sum(h.total_cves for h in self.hosts)
