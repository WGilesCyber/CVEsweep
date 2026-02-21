"""libnmap wrapper: translates CLI args to nmap options, runs the scan, parses results."""

import os
import time
from typing import Callable, List, Optional

from libnmap.objects import NmapHost, NmapService
from libnmap.parser import NmapParser
from libnmap.process import NmapProcess

from .banner import enrich_service_with_banner
from .models import HostResult, ScanResult, ServiceResult


class ScanError(Exception):
    """Raised when nmap exits with a non-zero return code."""


class ScanOptions:
    """
    Translates an argparse Namespace to a nmap options string.

    All flag logic is centralised here so cli.py stays clean.
    """

    def __init__(self, args):
        self.args = args

    def needs_root(self) -> bool:
        return bool(
            getattr(self.args, "sS", False)
            or getattr(self.args, "sU", False)
            or getattr(self.args, "O", False)
        )

    def build(self) -> str:
        """Return the full nmap option string."""
        opts: List[str] = []

        # Scan technique
        if getattr(self.args, "A", False):
            opts.append("-A")  # -A implies -sV and -O
        else:
            if getattr(self.args, "sS", False):
                opts.append("-sS")
            elif getattr(self.args, "sT", False):
                opts.append("-sT")

            if getattr(self.args, "sU", False):
                opts.append("-sU")

            # Version detection — always on unless --no-cve was passed
            if not getattr(self.args, "no_cve", False):
                opts.append("-sV")

            if getattr(self.args, "O", False):
                opts.append("-O")

        # Host discovery
        if getattr(self.args, "Pn", False):
            opts.append("-Pn")

        # Port specification
        port_val = getattr(self.args, "p", None)
        top_ports = getattr(self.args, "top_ports", None)
        if port_val:
            opts.extend(["-p", port_val])
        elif top_ports:
            opts.extend(["--top-ports", str(top_ports)])
        # If neither given, nmap defaults to top-1000

        # Show only open ports
        if getattr(self.args, "open", False):
            opts.append("--open")

        # Timing template
        timing = getattr(self.args, "T", None)
        if timing is not None:
            opts.append(f"-T{timing}")

        # Extra nmap scripts (--scripts flag)
        scripts = getattr(self.args, "scripts", None)
        if scripts:
            opts.extend([f"--script={scripts}"])

        # IPv6
        if getattr(self.args, "ipv6", False):
            opts.append("-6")

        # Verbosity is handled at the CVEsweep level; don't pass -v to nmap
        # because it changes the XML output structure and makes parsing unreliable.

        return " ".join(opts)


class Scanner:
    """Runs nmap via libnmap and returns a structured ScanResult."""

    def __init__(
        self,
        args,
        progress_callback: Optional[Callable[[float, int, str], None]] = None,
        banner_enrich: bool = True,
    ):
        self.args = args
        self.progress_callback = progress_callback
        self.banner_enrich = banner_enrich
        self.scan_opts = ScanOptions(args)

    def run(self) -> ScanResult:
        """
        Execute the nmap scan and return a parsed ScanResult.

        Raises:
            ScanError: if nmap exits non-zero
            PermissionError: if a root-only scan is requested without root
            EnvironmentError: if nmap binary is not found
        """
        from .utils import is_root

        options = self.scan_opts.build()
        targets = self._resolve_targets()
        scan_start = time.strftime("%Y-%m-%dT%H:%M:%S")
        t0 = time.monotonic()

        # root-required checks
        if self.scan_opts.needs_root() and not is_root():
            flags = []
            if getattr(self.args, "sS", False):
                flags.append("-sS")
            if getattr(self.args, "sU", False):
                flags.append("-sU")
            if getattr(self.args, "O", False):
                flags.append("-O")
            raise PermissionError(
                f"{' '.join(flags)} require root privileges. "
                "Run with sudo or switch to -sT (TCP connect scan)."
            )

        try:
            nm = NmapProcess(
                targets=targets,
                options=options,
                event_callback=self._on_nmap_event,
                safe_mode=False,  # required for -iL support
            )
        except EnvironmentError as exc:
            raise EnvironmentError(
                "nmap binary not found. Install with: sudo apt install nmap"
            ) from exc

        if self.scan_opts.needs_root():
            rc = nm.sudo_run()
        else:
            rc = nm.run()

        if nm.has_failed():
            stderr = nm.stderr or ""
            raise ScanError(
                f"nmap exited with return code {rc}.\n{stderr.strip()}"
            )

        elapsed = time.monotonic() - t0
        scan_end = time.strftime("%Y-%m-%dT%H:%M:%S")

        report = NmapParser.parse_fromstring(nm.stdout)
        result = self._parse_report(report, nm.command, scan_start, scan_end, elapsed)
        return result

    def _resolve_targets(self) -> str:
        """Return the target string for NmapProcess."""
        iL = getattr(self.args, "iL", None)
        if iL:
            # libnmap accepts -iL via the options string (safe_mode=False)
            return ""  # targets passed via options
        target = getattr(self.args, "target", None)
        if not target:
            raise ValueError("No target specified. Provide a target or use -iL.")
        return target if isinstance(target, str) else " ".join(target)

    def _on_nmap_event(self, nmap_proc: NmapProcess) -> None:
        """Called by libnmap after processing each stdout line from nmap."""
        if self.progress_callback is None:
            return
        try:
            pct = float(nmap_proc.progress or 0)
            etc = int(nmap_proc.etc or 0)
            self.progress_callback(pct, etc, "Scanning...")
        except (TypeError, ValueError):
            pass

    def _parse_report(
        self,
        report,
        command_line: str,
        scan_start: str,
        scan_end: str,
        elapsed: float,
    ) -> ScanResult:
        hosts: List[HostResult] = []

        for nmap_host in report.hosts:
            host_result = self._parse_host(nmap_host)
            hosts.append(host_result)

        return ScanResult(
            command_line=command_line,
            scan_start=scan_start,
            scan_end=scan_end,
            elapsed=elapsed,
            hosts=hosts,
        )

    def _parse_host(self, nmap_host: NmapHost) -> HostResult:
        status = "up" if nmap_host.is_up() else "down"

        # Hostnames
        hostnames = []
        for h in nmap_host.hostnames:
            name = h.get("name", "") if isinstance(h, dict) else str(h)
            if name:
                hostnames.append(name)

        # OS detection
        os_match: Optional[str] = None
        try:
            probs = nmap_host.os_match_probabilities()
            if probs:
                os_match = probs[0].name
        except (AttributeError, IndexError, TypeError):
            pass

        services: List[ServiceResult] = []
        if status == "up":
            for svc in nmap_host.services:
                services.append(self._parse_service(nmap_host.address, svc))

        return HostResult(
            ip=nmap_host.address,
            hostnames=hostnames,
            status=status,
            os_match=os_match,
            services=services,
        )

    def _parse_service(self, host_ip: str, svc: NmapService) -> ServiceResult:
        # banner_dict populated when -sV probe succeeded
        banner_dict = getattr(svc, "banner_dict", {}) or {}
        product = banner_dict.get("product", "") or ""
        version = banner_dict.get("version", "") or ""
        extrainfo = banner_dict.get("extrainfo", "") or ""
        banner = getattr(svc, "banner", "") or ""

        # CPE list — libnmap may return CPE objects; convert to plain strings
        raw_cpes = getattr(svc, "cpelist", []) or []
        cpes: List[str] = [str(c) for c in raw_cpes]

        # Banner enrichment fallback when nmap couldn't identify the product
        if self.banner_enrich and not product and svc.state == "open":
            product, version = enrich_service_with_banner(
                host_ip, svc.port, svc.protocol, product, version
            )

        return ServiceResult(
            port=svc.port,
            protocol=svc.protocol,
            state=svc.state,
            service_name=svc.service or "",
            product=product,
            version=version,
            extrainfo=extrainfo,
            banner=banner,
            cpes=cpes,
        )
