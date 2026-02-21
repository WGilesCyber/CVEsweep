"""Socket-based banner grabber fallback for services nmap couldn't version-detect."""

import socket
import ssl
from typing import Optional, Tuple

# Send-on-connect probes for common ports.
# Most servers (SSH, FTP, SMTP, etc.) emit a banner immediately on connect;
# for request-response protocols we send a minimal probe to elicit a response.
_PROBES: dict[int, bytes] = {
    21:    b"",                                      # FTP — banner on connect
    22:    b"",                                      # SSH — banner on connect
    23:    b"",                                      # Telnet
    25:    b"",                                      # SMTP — banner on connect
    80:    b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110:   b"",                                      # POP3 — banner on connect
    143:   b"",                                      # IMAP — banner on connect
    443:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",  # HTTPS (TLS)
    465:   b"",                                      # SMTPS
    587:   b"",                                      # Submission
    993:   b"",                                      # IMAPS
    995:   b"",                                      # POP3S
    1433:  b"",                                      # MSSQL
    3306:  b"",                                      # MySQL — banner on connect
    3389:  b"",                                      # RDP
    5432:  b"",                                      # PostgreSQL
    5900:  b"",                                      # VNC
    6379:  b"INFO\r\n",                              # Redis
    8080:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    27017: b"\x3a\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
           b"\x00\x00\x00\x00isMaster\x00",          # MongoDB ismaster
}

# Ports that always use TLS
_TLS_PORTS = {443, 465, 636, 993, 995, 8443}


def grab_banner(
    host: str,
    port: int,
    protocol: str = "tcp",
    timeout: float = 2.0,
) -> Optional[str]:
    """
    Attempt to grab a service banner via raw socket.

    Returns the first 512 bytes of the server's response as a string,
    or None if the connection fails or times out.
    """
    if protocol.lower() != "tcp":
        # UDP banner grabbing is unreliable without application-layer knowledge;
        # skip for now and let nmap handle UDP.
        return None

    probe = _PROBES.get(port, b"")
    raw: Optional[bytes] = None

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if port in _TLS_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    if probe:
                        tls_sock.sendall(probe)
                    raw = tls_sock.recv(512)
            else:
                if probe:
                    sock.sendall(probe)
                raw = sock.recv(512)
    except (OSError, ssl.SSLError, socket.timeout):
        return None

    if not raw:
        return None

    # Decode, replacing any non-UTF-8 bytes to avoid crashes on binary protocols
    text = raw.decode("utf-8", errors="replace")
    # Collapse control characters (except newline/tab) and truncate
    text = "".join(ch if ch.isprintable() or ch in "\n\t" else " " for ch in text)
    return text[:256].strip() or None


def enrich_service_with_banner(
    host: str,
    port: int,
    protocol: str,
    product: str,
    version: str,
) -> Tuple[str, str]:
    """
    Try to enrich a service's product/version via banner grabbing.

    Only makes a network call if product is currently empty.
    Returns (product, version) — either unchanged or enriched.
    """
    if product:
        # nmap already identified this service; don't second-guess it
        return product, version

    banner = grab_banner(host, port, protocol)
    if not banner:
        return product, version

    from .utils import parse_version_string

    # Try to extract a version number from the banner
    extracted_version = parse_version_string(banner)

    # Guess a product name from the first meaningful word of the banner
    first_line = banner.split("\n")[0].strip()
    # Strip common prefixes like "SSH-2.0-", "220 ", "* OK "
    first_line = first_line.lstrip("*+- ").split(" ")[0].rstrip(",:")

    inferred_product = first_line if first_line else banner[:20].strip()
    inferred_version = extracted_version or version

    return inferred_product, inferred_version
