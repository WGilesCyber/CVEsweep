"""CLI argument parsing and main orchestrator for CVEsweep."""

import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .cache import CVECache
from .cve_lookup import NVDClient
from .output import ProgressDisplay, TerminalRenderer, render_html, render_json, render_text
from .scanner import ScanError, Scanner
from .utils import is_root


# ---------------------------------------------------------------------------
# Argument pre-processing
# ---------------------------------------------------------------------------

def preprocess_argv(argv: List[str]) -> List[str]:
    """
    Transform nmap-style compact flags into the two-token form argparse expects.

    Transforms:
      -T5       → -T 5
      -p-       → -p 1-65535
      -vv       → -v -v          (handled natively by action="count" — passthrough)
      --top-ports=100 → already works, passthrough
    """
    result: List[str] = []
    for arg in argv:
        # -T<digit>  (e.g. -T4, -T5)
        if len(arg) == 3 and arg.startswith("-T") and arg[2].isdigit():
            result.extend(["-T", arg[2]])
        # -p-  (all ports shorthand)
        elif arg == "-p-":
            result.extend(["-p", "1-65535"])
        else:
            result.append(arg)
    return result


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog="cvesweep",
        description=(
            "CVEsweep — Network CVE Scanner\n"
            "Scans targets for open ports, identifies service versions with nmap,\n"
            "queries the NIST NVD for known CVEs, and produces terminal, text, JSON,\n"
            "and HTML reports."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "────────────────────────────────────────────────────────────────────\n"
            "QUICK START\n"
            "────────────────────────────────────────────────────────────────────\n"
            "  Scan a single host (TCP, version detection, show all CVEs):\n"
            "    cvesweep -sT -sV 10.0.0.1\n\n"
            "  Scan a subnet, report HIGH/CRITICAL CVEs, save HTML:\n"
            "    cvesweep -sT -sV 10.0.0.0/24 --min-cvss 7.0 -oH report.html\n\n"
            "  Fast stealth scan of top 1000 ports (requires root):\n"
            "    sudo cvesweep -sS -T4 --top-ports 1000 10.0.0.0/24\n\n"
            "────────────────────────────────────────────────────────────────────\n"
            "COMMON WORKFLOWS\n"
            "────────────────────────────────────────────────────────────────────\n"
            "  Web server audit (common web ports, verbose CVE output):\n"
            "    cvesweep -sT -sV -p 80,443,8080,8443 10.0.0.1 -vv\n\n"
            "  Full port scan with all output formats:\n"
            "    sudo cvesweep -A -p- 10.0.0.5 -oN out.txt -oJ out.json -oH out.html\n\n"
            "  Bulk scan from a target file, save JSON:\n"
            "    cvesweep -sT -sV -iL targets.txt -oJ results.json\n\n"
            "  Port discovery only (no CVE lookup), fast:\n"
            "    cvesweep -sT --no-cve --open -T4 10.0.0.0/24\n\n"
            "  Use an NVD API key for faster CVE lookups on large scans:\n"
            "    cvesweep -sT -sV 10.0.0.0/24 --cve-key YOUR_KEY --min-cvss 7.0\n\n"
            "────────────────────────────────────────────────────────────────────\n"
            "TIPS\n"
            "────────────────────────────────────────────────────────────────────\n"
            "  • -sV is required for accurate CVE matching — without it, service\n"
            "    versions cannot be detected and CVE results will be imprecise.\n"
            "  • Get a free NVD API key to raise the rate limit from 5 to\n"
            "    50 requests/30s: https://nvd.nist.gov/developers/request-an-api-key\n"
            "  • CVE results are cached for 24 h in ~/.cache/cvesweep/.\n"
            "    Use --update-cache to refresh, or --no-cache to bypass entirely.\n"
            "  • -sS, -sU, -O, and -A all require root (run with sudo).\n"
            "  • Use -T4 on a reliable LAN; use -T1 or -T2 for stealthier scans.\n"
            "  • CVSS thresholds: LOW 0.1–3.9 | MEDIUM 4.0–6.9 |\n"
            "                     HIGH 7.0–8.9 | CRITICAL 9.0–10.0\n\n"
            "Full documentation: USAGE.md\n"
        ),
    )

    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"CVEsweep {__version__}",
    )

    # -----------------------------------------------------------------------
    # Target
    # -----------------------------------------------------------------------
    target_grp = parser.add_argument_group("Scan targets")
    target_grp.add_argument(
        "target",
        nargs="?",
        metavar="<target>",
        help="IP address, CIDR, hostname (e.g. 192.168.1.0/24, 10.0.0.1, host.local)",
    )
    target_grp.add_argument(
        "-iL",
        metavar="<inputfile>",
        dest="iL",
        help="Read targets from file (one per line)",
    )

    # -----------------------------------------------------------------------
    # Scan techniques
    # -----------------------------------------------------------------------
    scan_grp = parser.add_argument_group("Scan techniques")
    scan_grp.add_argument(
        "-sS",
        action="store_true",
        default=False,
        help="TCP SYN (stealth) scan — sends SYN, reads response, never completes "
             "the handshake; faster and less visible in application logs. Requires root.",
    )
    scan_grp.add_argument(
        "-sT",
        action="store_true",
        default=False,
        help="TCP connect scan — completes the full three-way handshake. "
             "No root required. Used when -sS is not available.",
    )
    scan_grp.add_argument(
        "-sV",
        action="store_true",
        default=False,
        help="Service/version detection — probes open ports to identify product "
             "names and version numbers. Required for accurate CVE matching.",
    )
    scan_grp.add_argument(
        "-sU",
        action="store_true",
        default=False,
        help="UDP scan — discovers UDP services (DNS, SNMP, TFTP, etc.). "
             "Slower than TCP scans. Requires root.",
    )
    scan_grp.add_argument(
        "-O",
        action="store_true",
        default=False,
        help="OS detection — attempts to fingerprint the target's operating system. "
             "Requires root.",
    )
    scan_grp.add_argument(
        "-A",
        action="store_true",
        default=False,
        help="Aggressive mode — enables OS detection (-O), version detection (-sV), "
             "default NSE script scanning, and traceroute in one flag. Requires root.",
    )
    scan_grp.add_argument(
        "-Pn",
        action="store_true",
        default=False,
        help="Skip host discovery — treats all hosts as online without sending a "
             "ping/ICMP probe first. Useful when targets block ICMP.",
    )
    scan_grp.add_argument(
        "-6",
        action="store_true",
        default=False,
        dest="ipv6",
        help="Enable IPv6 scanning.",
    )

    # -----------------------------------------------------------------------
    # Port specification
    # -----------------------------------------------------------------------
    port_grp = parser.add_argument_group("Port specification")
    port_grp.add_argument(
        "-p",
        metavar="<ports>",
        help="Port(s) to scan. Formats: single (22), list (22,80,443), "
             "range (1-1024), all ports (1-65535 or -p-).",
    )
    port_grp.add_argument(
        "--top-ports",
        metavar="<n>",
        type=int,
        default=None,
        help="Scan the N most commonly open ports ranked by nmap (e.g. --top-ports 100).",
    )
    port_grp.add_argument(
        "--open",
        action="store_true",
        default=False,
        help="Only show open ports; suppress closed and filtered ports from output.",
    )

    # -----------------------------------------------------------------------
    # Timing
    # -----------------------------------------------------------------------
    timing_grp = parser.add_argument_group("Timing")
    timing_grp.add_argument(
        "-T",
        metavar="<0-5>",
        type=int,
        choices=range(6),
        default=None,
        help="Timing template (0=paranoid, 1=sneaky, 2=polite, 3=normal, "
             "4=aggressive, 5=insane). Higher values are faster but noisier. "
             "Compact form -T4 is also accepted.",
    )

    # -----------------------------------------------------------------------
    # CVE options
    # -----------------------------------------------------------------------
    cve_grp = parser.add_argument_group("CVE options")
    cve_grp.add_argument(
        "--no-cve",
        action="store_true",
        default=False,
        help="Skip CVE lookup entirely and perform a port/service scan only.",
    )
    cve_grp.add_argument(
        "--cve-key",
        metavar="<apikey>",
        default=None,
        help="NVD API key — raises the rate limit from 5 to 50 requests/30s, "
             "which significantly speeds up CVE lookups on large scans. "
             "Free key: https://nvd.nist.gov/developers/request-an-api-key",
    )
    cve_grp.add_argument(
        "--min-cvss",
        metavar="<score>",
        type=float,
        default=0.0,
        help="Only display CVEs at or above this CVSS score (0.0–10.0, default: 0.0 = all). "
             "Severity bands: LOW 0.1-3.9, MEDIUM 4.0-6.9, HIGH 7.0-8.9, CRITICAL 9.0-10.0.",
    )
    cve_grp.add_argument(
        "--no-cache",
        action="store_true",
        default=False,
        help="Disable the 24-hour CVE result cache and always query NVD live.",
    )
    cve_grp.add_argument(
        "--update-cache",
        action="store_true",
        default=False,
        help="Invalidate cached CVE entries for services found in this scan, "
             "then fetch fresh results from NVD.",
    )

    # -----------------------------------------------------------------------
    # Nmap scripts
    # -----------------------------------------------------------------------
    script_grp = parser.add_argument_group("Script scanning")
    script_grp.add_argument(
        "--scripts",
        metavar="<script-list>",
        default=None,
        help="Comma-separated list of nmap NSE scripts to run against discovered services "
             "(e.g. banner,http-title,ssh-auth-methods,ssl-cert). "
             "See https://nmap.org/nsedoc/ for available scripts.",
    )

    # -----------------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------------
    out_grp = parser.add_argument_group("Output")
    out_grp.add_argument(
        "-v",
        action="count",
        default=0,
        dest="verbose",
        help="Increase verbosity. -v shows CVE IDs and CVSS scores inline with "
             "each service; -vv additionally shows full descriptions and NVD URLs.",
    )
    out_grp.add_argument(
        "-oN",
        metavar="<file>",
        dest="oN",
        help="Save a plain-text (nmap-style) report to the specified file.",
    )
    out_grp.add_argument(
        "-oJ",
        metavar="<file>",
        dest="oJ",
        help="Save a JSON report to the specified file.",
    )
    out_grp.add_argument(
        "-oH",
        metavar="<file>",
        dest="oH",
        help="Save a self-contained HTML report (Bootstrap 5, sortable CVE table) "
             "to the specified file.",
    )

    return parser


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

def validate_args(args) -> Optional[str]:
    """
    Validate parsed arguments.
    Returns an error message string, or None if everything is valid.
    """
    # Must have a target
    if not args.target and not args.iL:
        return "No target specified. Provide a target IP/CIDR or use -iL <file>."

    # iL file must exist
    if args.iL and not Path(args.iL).is_file():
        return f"Target file not found: {args.iL}"

    # min-cvss range
    if not (0.0 <= args.min_cvss <= 10.0):
        return f"--min-cvss must be between 0.0 and 10.0, got {args.min_cvss}"

    # -A implies version detection
    if args.A:
        args.sV = True

    # top-ports must be positive
    if args.top_ports is not None and args.top_ports < 1:
        return "--top-ports must be a positive integer"

    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    """
    CVEsweep entry point.

    Returns:
        0 — success
        1 — scan or argument error
        2 — no hosts found up
    """
    if argv is None:
        argv = sys.argv[1:]

    argv = preprocess_argv(argv)

    parser = build_parser()
    args = parser.parse_args(argv)

    err = validate_args(args)
    if err:
        parser.error(err)

    renderer = TerminalRenderer(verbose=args.verbose)

    # Root warnings (warn, don't abort — scanner will raise PermissionError if needed)
    needs_root_flags = []
    if args.sS:
        needs_root_flags.append("-sS")
    if args.sU:
        needs_root_flags.append("-sU")
    if args.O:
        needs_root_flags.append("-O")
    if needs_root_flags and not is_root():
        renderer.print_warning(
            f"{' '.join(needs_root_flags)} require root. "
            "Run with sudo or switch to -sT."
        )

    # Build target string for display (nmap handles resolution)
    target_display = args.target or args.iL or "unknown"

    # Cache setup
    cache: Optional[CVECache] = None
    if not args.no_cve and not args.no_cache:
        cache = CVECache()
        removed = cache.cleanup()
        if removed and args.verbose:
            renderer.print_info(f"Cache cleanup: removed {removed} expired entries")

    # NVD client
    nvd_client: Optional[NVDClient] = None
    if not args.no_cve:
        nvd_client = NVDClient(
            api_key=args.cve_key,
            cache=cache,
            min_cvss=args.min_cvss,
        )
        if not args.cve_key:
            renderer.print_info(
                "No NVD API key set. Rate limit: 5 requests/30s. "
                "Get a free key with --cve-key to increase this."
            )

    # Run the scan
    try:
        with ProgressDisplay() as progress:
            scanner = Scanner(args, progress_callback=progress.update)
            result = scanner.run()
            progress.finish_scan()

            # CVE lookup phase
            if nvd_client:
                service_count = sum(len(h.services) for h in result.hosts_up)
                done = 0
                for host in result.hosts_up:
                    for svc in host.services:
                        renderer.print_cve_lookup_progress(host.ip, svc.port, svc.product)

                        # Optionally invalidate cache for --update-cache
                        if args.update_cache and cache:
                            for cpe in svc.cpes:
                                cache.invalidate("cpe", cpe)
                            if svc.product:
                                from .utils import build_keyword_query
                                q = build_keyword_query(svc.product, svc.version)
                                cache.invalidate("keyword", q)

                        cves = nvd_client.lookup_service(
                            svc.service_name,
                            svc.product,
                            svc.version,
                            svc.cpes,
                        )
                        svc.cves = cves
                        done += 1
                        pct = 99 + (done / max(service_count, 1))
                        progress.update(min(pct, 99.9), 0, f"CVE lookup {done}/{service_count}")

            progress.finish()

    except PermissionError as exc:
        renderer.print_error(str(exc))
        return 1
    except EnvironmentError as exc:
        renderer.print_error(str(exc))
        return 1
    except ScanError as exc:
        renderer.print_error(f"Scan failed: {exc}")
        return 1
    except KeyboardInterrupt:
        renderer.print_warning("Scan interrupted by user.")
        return 1

    # Check if any hosts were found
    if not result.hosts_up:
        renderer.print_warning(
            "No hosts found up. If hosts are blocking pings, try -Pn to skip host discovery."
        )
        return 2

    # Print banner + results
    renderer.print_banner(target_display, result.scan_start, result.command_line)
    for host in result.hosts:
        renderer.print_host(host)
    renderer.print_summary(result)

    # Write output files
    _write_output_files(args, result, renderer)

    return 0


def _write_output_files(args, result, renderer: TerminalRenderer) -> None:
    """Write any requested output files (-oN, -oJ, -oH)."""
    outputs = [
        (getattr(args, "oN", None), "text", render_text),
        (getattr(args, "oJ", None), "JSON", render_json),
        (getattr(args, "oH", None), "HTML", render_html),
    ]
    for path, fmt, render_fn in outputs:
        if not path:
            continue
        try:
            content = render_fn(result)
            Path(path).write_text(content, encoding="utf-8")
            renderer.print_info(f"Saved {fmt} report to {path}")
            from .output import console
            console.print(f"[dim][*] Saved {fmt} report → {path}[/dim]")
        except PermissionError:
            renderer.print_warning(f"Cannot write {fmt} report to {path}: permission denied")
        except Exception as exc:
            renderer.print_warning(f"Failed to write {fmt} report to {path}: {exc}")
