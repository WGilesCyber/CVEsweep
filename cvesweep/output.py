"""Rich-powered terminal output and file format renderers (JSON, text, HTML)."""

import dataclasses
import json
from typing import List, Optional

from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from . import __version__
from .models import CVEEntry, HostResult, ScanResult, ServiceResult

# ---------------------------------------------------------------------------
# Severity → rich style mapping (NIST CVSS thresholds)
# ---------------------------------------------------------------------------
SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "bright_blue",
    "NONE":     "green",
}

SEVERITY_LABEL: dict[str, str] = {
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
    "HIGH":     "[red]HIGH[/red]",
    "MEDIUM":   "[yellow]MEDIUM[/yellow]",
    "LOW":      "[bright_blue]LOW[/bright_blue]",
    "NONE":     "[green]NONE[/green]",
}

_THEME = Theme({
    "info":         "dim white",
    "host.header":  "bold cyan",
    "port.open":    "bold green",
    "port.filtered":"yellow",
    "cve.vuln":     "bold red",
    "cve.clean":    "green",
})

console = Console(theme=_THEME)
err_console = Console(stderr=True, theme=_THEME)


# ---------------------------------------------------------------------------
# Progress display
# ---------------------------------------------------------------------------

class ProgressDisplay:
    """
    Context manager that renders a live progress bar during the nmap scan phase.

    Usage::

        with ProgressDisplay() as display:
            result = scanner.run()   # scanner calls display.update()
    """

    def __init__(self):
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("ETC: {task.fields[etc]}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        )
        self._task_id = None
        self._live: Optional[Live] = None

    def __enter__(self):
        self._live = Live(self._progress, console=console, refresh_per_second=4)
        self._live.__enter__()
        self._task_id = self._progress.add_task(
            "Starting scan...", total=100, etc="?"
        )
        return self

    def __exit__(self, *args):
        if self._live:
            self._live.__exit__(*args)

    def update(self, pct: float, etc_seconds: int, task_name: str) -> None:
        """Update the progress bar from the scanner's event callback."""
        if self._task_id is None:
            return
        etc_str = f"{etc_seconds}s" if etc_seconds > 0 else "..."
        self._progress.update(
            self._task_id,
            completed=min(pct, 99),  # leave 1% for CVE lookup
            description=task_name[:60] if task_name else "Scanning...",
            etc=etc_str,
        )

    def finish_scan(self) -> None:
        """Mark the scan phase complete (99%) before CVE lookup starts."""
        if self._task_id is not None:
            self._progress.update(self._task_id, completed=99, description="CVE lookup...", etc="...")

    def finish(self) -> None:
        """Mark 100% complete."""
        if self._task_id is not None:
            self._progress.update(self._task_id, completed=100, description="Done", etc="0s")


# ---------------------------------------------------------------------------
# Terminal renderer
# ---------------------------------------------------------------------------

class TerminalRenderer:
    """Renders scan results to the terminal using rich."""

    def __init__(self, verbose: int = 0):
        self.verbose = verbose  # 0 = normal, 1 = -v, 2 = -vv

    def print_banner(self, target: str, scan_start: str, command_line: str) -> None:
        """Print the CVEsweep tool banner."""
        title = Text(f"CVEsweep v{__version__}  —  Network CVE Scanner", style="bold cyan")
        lines = [
            f"[dim]Command:[/dim]  {command_line}",
            f"[dim]Target :[/dim]  {target}",
            f"[dim]Started:[/dim]  {scan_start}",
        ]
        console.print()
        console.print(Panel(title, border_style="cyan", expand=False))
        for line in lines:
            console.print(f"  {line}")
        console.print()

    def print_host(self, host: HostResult) -> None:
        """Print a single host block with its services and CVE status."""
        status_style = "bold green" if host.status == "up" else "bold red"
        status_str = f"[{status_style}]{host.status.upper()}[/{status_style}]"

        header = f"[host.header]Host: {host.display_name}[/host.header]  {status_str}"
        if host.os_match:
            header += f"  [dim]OS: {host.os_match}[/dim]"

        console.print(header)

        if host.status != "up" or not host.services:
            console.print("  [dim]No open ports found.[/dim]")
            console.print()
            return

        # Service table
        tbl = Table(
            show_header=True,
            header_style="bold",
            box=box.SIMPLE_HEAVY,
            padding=(0, 1),
            expand=False,
        )
        tbl.add_column("PORT", style="bold", min_width=10)
        tbl.add_column("STATE", min_width=8)
        tbl.add_column("SERVICE", min_width=10)
        tbl.add_column("VERSION", min_width=22)
        tbl.add_column("CVEs", min_width=12)

        for svc in host.services:
            port_str = f"{svc.port}/{svc.protocol}"
            state_style = "port.open" if "open" in svc.state else "port.filtered"
            state_str = f"[{state_style}]{svc.state}[/{state_style}]"

            if svc.cves:
                cve_str = f"[cve.vuln][!] {len(svc.cves)} CVE{'s' if len(svc.cves) != 1 else ''}[/cve.vuln]"
            else:
                cve_str = "[cve.clean][✓] Clean[/cve.clean]"

            tbl.add_row(port_str, state_str, svc.service_name, svc.display_version, cve_str)

            # Verbose: print CVE list under the service row
            if self.verbose >= 1 and svc.cves:
                for cve in svc.cves:
                    self._add_cve_row(tbl, cve)

        console.print(tbl)

        # -vv: print full CVE descriptions outside the table
        if self.verbose >= 2:
            for svc in host.services:
                for cve in svc.cves:
                    self._print_cve_detail(svc, cve)

        console.print()

    def _add_cve_row(self, tbl: Table, cve: CVEEntry) -> None:
        """Add an indented CVE detail row inside the service table."""
        style = SEVERITY_STYLE.get(cve.severity, "white")
        score_str = f"{cve.cvss_score:.1f}"
        desc_short = cve.description[:40] + ("..." if len(cve.description) > 40 else "")
        tbl.add_row(
            f"  └─ [dim]{cve.cve_id}[/dim]",
            f"[{style}]{score_str}[/{style}]",
            SEVERITY_LABEL.get(cve.severity, cve.severity),
            desc_short,
            "",
        )

    def _print_cve_detail(self, svc: ServiceResult, cve: CVEEntry) -> None:
        """Print full CVE description and URL (-vv mode)."""
        style = SEVERITY_STYLE.get(cve.severity, "white")
        console.print(
            f"  [{style}]{cve.cve_id}[/{style}]  "
            f"CVSS {cve.cvss_score:.1f} ({cve.severity})  "
            f"[dim]{cve.published}[/dim]"
        )
        console.print(f"    {cve.description}")
        console.print(f"    [link={cve.url}][dim]{cve.url}[/dim][/link]")
        console.print()

    def print_summary(self, result: ScanResult) -> None:
        """Print a summary table of all CVEs found across all hosts."""
        up_count = len(result.hosts_up)
        vuln_count = len(result.vulnerable_hosts)
        cve_count = result.total_cves
        elapsed = f"{result.elapsed:.1f}s"

        console.print()
        console.rule("[bold cyan]Scan Summary[/bold cyan]")
        console.print()

        if result.all_cves:
            tbl = Table(
                title=f"[bold red]CVEs Found ({cve_count} total)[/bold red]",
                box=box.ROUNDED,
                show_lines=False,
                header_style="bold",
                expand=False,
            )
            tbl.add_column("Host", style="cyan", min_width=16)
            tbl.add_column("Port", min_width=8)
            tbl.add_column("Service", min_width=10)
            tbl.add_column("CVE ID", min_width=18)
            tbl.add_column("CVSS", min_width=6, justify="right")
            tbl.add_column("Severity", min_width=10)
            tbl.add_column("Published", min_width=10)

            all_cves_sorted = sorted(result.all_cves, key=lambda x: x[3].cvss_score, reverse=True)
            for host_ip, port, svc_name, cve in all_cves_sorted:
                style = SEVERITY_STYLE.get(cve.severity, "white")
                tbl.add_row(
                    host_ip,
                    str(port),
                    svc_name,
                    f"[{style}]{cve.cve_id}[/{style}]",
                    f"[{style}]{cve.cvss_score:.1f}[/{style}]",
                    SEVERITY_LABEL.get(cve.severity, cve.severity),
                    cve.published,
                )
            console.print(tbl)
            console.print()

        # Footer stats
        vuln_style = "bold red" if vuln_count > 0 else "bold green"
        console.print(
            f"  Hosts scanned: [cyan]{up_count}[/cyan]  |  "
            f"Vulnerable: [{vuln_style}]{vuln_count}[/{vuln_style}]  |  "
            f"CVEs found: [{'bold red' if cve_count else 'green'}]{cve_count}[/{'bold red' if cve_count else 'green'}]  |  "
            f"Elapsed: [dim]{elapsed}[/dim]"
        )
        console.print()

    def print_error(self, message: str) -> None:
        err_console.print(f"[bold red][ERROR][/bold red] {message}")

    def print_warning(self, message: str) -> None:
        console.print(f"[yellow][WARN][/yellow]  {message}")

    def print_info(self, message: str) -> None:
        if self.verbose >= 1:
            console.print(f"[dim][*][/dim] {message}")

    def print_cve_lookup_progress(self, host_ip: str, port: int, product: str) -> None:
        if self.verbose >= 1:
            console.print(f"  [dim]CVE lookup: {host_ip}:{port} ({product or 'unknown'})[/dim]")


# ---------------------------------------------------------------------------
# File format renderers
# ---------------------------------------------------------------------------

def render_json(result: ScanResult) -> str:
    """Serialize a ScanResult to a pretty-printed JSON string."""
    return json.dumps(dataclasses.asdict(result), indent=2, default=str)


def render_text(result: ScanResult) -> str:
    """
    Render a plain-text (no ANSI codes) scan report in nmap-inspired style.
    Suitable for -oN file output.
    """
    lines: List[str] = []
    lines.append(f"# CVEsweep v{__version__} scan report")
    lines.append(f"# Command:  {result.command_line}")
    lines.append(f"# Started:  {result.scan_start}")
    lines.append(f"# Finished: {result.scan_end}")
    lines.append(f"# Elapsed:  {result.elapsed:.1f}s")
    lines.append("")

    for host in result.hosts:
        up_str = "up" if host.status == "up" else "down"
        hostnames = f" ({', '.join(host.hostnames)})" if host.hostnames else ""
        lines.append(f"Host: {host.ip}{hostnames} [{up_str}]")
        if host.os_match:
            lines.append(f"  OS: {host.os_match}")

        if host.status == "up" and host.services:
            lines.append(f"  {'PORT':<12} {'STATE':<10} {'SERVICE':<12} VERSION")
            for svc in host.services:
                port_col = f"{svc.port}/{svc.protocol}"
                lines.append(f"  {port_col:<12} {svc.state:<10} {svc.service_name:<12} {svc.display_version}")
                if svc.cves:
                    for cve in svc.cves:
                        lines.append(
                            f"    [{cve.cve_id}] CVSS: {cve.cvss_score:.1f} ({cve.severity})"
                        )
                        lines.append(f"      {cve.description}")
                        lines.append(f"      {cve.url}")
                else:
                    lines.append("    [CLEAN] No CVEs found")
        else:
            lines.append("  No open ports found.")

        lines.append("")

    # Summary
    up_count = len(result.hosts_up)
    vuln_count = len(result.vulnerable_hosts)
    cve_count = result.total_cves
    lines.append(f"# Summary: {up_count} host(s) up | {vuln_count} vulnerable | {cve_count} CVEs")
    return "\n".join(lines)


def render_html(result: ScanResult) -> str:
    """
    Render a self-contained HTML report using Jinja2.
    Uses Bootstrap 5 and DataTables from CDN.
    """
    try:
        from jinja2 import Environment, PackageLoader, select_autoescape
        env = Environment(
            loader=PackageLoader("cvesweep", "templates"),
            autoescape=select_autoescape(["html"]),
        )
        template = env.get_template("report.html.j2")
    except Exception:
        # Fallback: minimal inline HTML if template loading fails
        return _render_html_fallback(result)

    severity_style_map = {
        "CRITICAL": "danger",
        "HIGH": "danger",
        "MEDIUM": "warning",
        "LOW": "info",
        "NONE": "success",
    }
    return template.render(
        result=result,
        version=__version__,
        severity_style=severity_style_map,
        all_cves_sorted=sorted(result.all_cves, key=lambda x: x[3].cvss_score, reverse=True),
    )


def _render_html_fallback(result: ScanResult) -> str:
    """Minimal HTML fallback when Jinja2 template is unavailable."""
    rows = []
    for host_ip, port, svc_name, cve in sorted(
        result.all_cves, key=lambda x: x[3].cvss_score, reverse=True
    ):
        rows.append(
            f"<tr><td>{host_ip}</td><td>{port}</td><td>{svc_name}</td>"
            f"<td>{cve.cve_id}</td><td>{cve.cvss_score:.1f}</td>"
            f"<td>{cve.severity}</td><td>{cve.description[:120]}</td></tr>"
        )
    table_body = "\n".join(rows)
    return f"""<!DOCTYPE html>
<html><head><title>CVEsweep Report</title></head>
<body>
<h1>CVEsweep v{__version__} Scan Report</h1>
<p>Started: {result.scan_start} | Elapsed: {result.elapsed:.1f}s</p>
<table border="1">
<tr><th>Host</th><th>Port</th><th>Service</th><th>CVE ID</th>
<th>CVSS</th><th>Severity</th><th>Description</th></tr>
{table_body}
</table>
</body></html>"""
