"""Utility functions: target validation, CPE conversion, version parsing."""

import ipaddress
import os
import re
import socket
from typing import List, Optional

from packaging.version import Version, InvalidVersion


def validate_target(target: str) -> bool:
    """Return True if target is a valid IP, CIDR, or hostname."""
    target = target.strip()
    if not target:
        return False

    # Try IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Try CIDR
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass

    # Try IP range like 10.0.0.1-10 or 10.0.0.1-10.0.0.50
    if re.match(r'^[\d.]+-[\d.]+$', target):
        return True

    # Try hostname (basic sanity check — nmap handles resolution)
    hostname_re = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )
    if hostname_re.match(target):
        return True

    return False


def parse_targets_from_file(path: str) -> List[str]:
    """Read targets from a file, one per line. Skips blank lines and comments (#)."""
    targets = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def is_root() -> bool:
    """Return True if the current process is running as root."""
    return os.geteuid() == 0


def require_root(scan_type: str) -> None:
    """Raise PermissionError with a helpful message if not running as root."""
    if not is_root():
        raise PermissionError(
            f"{scan_type} requires root privileges. "
            f"Run with: sudo cvesweep ... or switch to -sT (TCP connect scan)."
        )


def cpe22_to_cpe23(cpe22: str) -> str:
    """
    Convert a CPE 2.2 URI to CPE 2.3 formatted string.

    Input:  cpe:/a:openbsd:openssh:7.4
    Output: cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*

    CPE 2.3 has exactly 13 components after "cpe:2.3:".
    The 2.2 URI has the form: cpe:/<part>:<vendor>:<product>:<version>:...
    """
    if cpe22.startswith("cpe:2.3:"):
        return cpe22  # Already CPE 2.3

    # Strip "cpe:/" prefix
    if cpe22.startswith("cpe:/"):
        remainder = cpe22[5:]
    elif cpe22.startswith("cpe:"):
        remainder = cpe22[4:].lstrip("/")
    else:
        remainder = cpe22

    # Split on colon
    parts = remainder.split(":")

    # CPE 2.3 needs exactly 11 components after "cpe:2.3:"
    # (part, vendor, product, version, update, edition, language,
    #  sw_edition, target_sw, target_hw, other)
    while len(parts) < 11:
        parts.append("*")

    return "cpe:2.3:" + ":".join(parts[:11])


def parse_version_string(banner: str) -> Optional[str]:
    """
    Extract a version number from a raw banner string.

    Returns the first version-like pattern found, or None.
    Handles: "OpenSSH 7.4p1", "Apache/2.4.49", "nginx/1.18.0", "MySQL 5.7.38"

    The optional suffix only matches patterns that start with a known patch-level
    indicator (p, rc, beta, alpha, pre, post) followed by digits — this avoids
    false positives like "2.0-OpenSSH" or "5.7.38-log".
    """
    if not banner:
        return None
    # Core version: two or more dot-separated numeric segments (e.g., 1.2 or 1.2.3.4)
    # Optional suffix: p1, rc2, beta3, alpha1, pre1, post1 — lowercase only + digits
    # Optional patch-level suffix: separator is optional (handles "8.9p1" and "8.9-p1")
    pattern = r'(\d+(?:\.\d+)+(?:[._-]?(?:p|rc|beta|alpha|pre|post)\d+)?)'
    match = re.search(pattern, banner)
    return match.group(1) if match else None


def version_in_range(
    version_str: str,
    version_start_incl: Optional[str],
    version_start_excl: Optional[str],
    version_end_incl: Optional[str],
    version_end_excl: Optional[str],
) -> bool:
    """
    Check if a detected version falls within a CVE's affected version range.

    Uses packaging.version.Version for comparison.
    Returns True (conservative — show the CVE) if version string is unparseable
    or if no range constraints are specified.
    """
    # No constraints at all — the CVE applies to all versions
    if not any([version_start_incl, version_start_excl, version_end_incl, version_end_excl]):
        return True

    try:
        detected = Version(version_str)
    except (InvalidVersion, TypeError):
        # Can't parse version — err on the side of caution (show the CVE)
        return True

    try:
        if version_start_incl and detected < Version(version_start_incl):
            return False
        if version_start_excl and detected <= Version(version_start_excl):
            return False
        if version_end_incl and detected > Version(version_end_incl):
            return False
        if version_end_excl and detected >= Version(version_end_excl):
            return False
    except InvalidVersion:
        # If any bound is unparseable, show the CVE (conservative)
        return True

    return True


def build_keyword_query(product: str, version: str) -> str:
    """Construct an NVD keywordSearch string from product and version."""
    parts = [p.strip() for p in [product, version] if p and p.strip()]
    return " ".join(parts)


def cvss_to_severity(score: float) -> str:
    """Convert a CVSS base score to a severity string (NIST thresholds)."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "NONE"
