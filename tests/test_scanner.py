"""Tests for cvesweep.scanner — uses fixture XML, no live network calls."""

from pathlib import Path

import pytest
from libnmap.parser import NmapParser

from cvesweep.models import HostResult, ServiceResult
from cvesweep.scanner import ScanOptions, Scanner

FIXTURE_DIR = Path(__file__).parent / "fixtures"
RICH_XML = FIXTURE_DIR / "nmap_sample_rich.xml"


# ---------------------------------------------------------------------------
# Parse the fixture XML once
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rich_report():
    return NmapParser.parse_fromfile(str(RICH_XML))


# ---------------------------------------------------------------------------
# ScanOptions tests (no network)
# ---------------------------------------------------------------------------

class TestScanOptions:
    def _args(self, **kwargs):
        """Build a minimal args namespace."""
        class Args:
            pass
        a = Args()
        # Defaults
        a.sS = False
        a.sT = False
        a.sV = False
        a.sU = False
        a.O = False
        a.A = False
        a.Pn = False
        a.ipv6 = False
        a.p = None
        a.top_ports = None
        a.open = False
        a.T = None
        a.scripts = None
        a.no_cve = False
        for k, v in kwargs.items():
            setattr(a, k, v)
        return a

    def test_sT_adds_sT_flag(self):
        args = self._args(sT=True)
        opts = ScanOptions(args).build()
        assert "-sT" in opts

    def test_default_adds_sV(self):
        args = self._args(sT=True)
        opts = ScanOptions(args).build()
        assert "-sV" in opts

    def test_no_cve_skips_sV(self):
        args = self._args(sT=True, no_cve=True)
        opts = ScanOptions(args).build()
        assert "-sV" not in opts

    def test_top_ports_included(self):
        args = self._args(sT=True, top_ports=500)
        opts = ScanOptions(args).build()
        assert "--top-ports" in opts
        assert "500" in opts

    def test_port_spec_included(self):
        args = self._args(sT=True, p="22,80,443")
        opts = ScanOptions(args).build()
        assert "-p" in opts
        assert "22,80,443" in opts

    def test_timing_template(self):
        args = self._args(sT=True, T=4)
        opts = ScanOptions(args).build()
        assert "-T4" in opts

    def test_aggressive_mode(self):
        args = self._args(A=True)
        opts = ScanOptions(args).build()
        assert "-A" in opts

    def test_needs_root_for_sS(self):
        args = self._args(sS=True)
        assert ScanOptions(args).needs_root() is True

    def test_needs_root_for_sU(self):
        args = self._args(sU=True)
        assert ScanOptions(args).needs_root() is True

    def test_no_root_required_for_sT(self):
        args = self._args(sT=True)
        assert ScanOptions(args).needs_root() is False

    def test_open_flag(self):
        args = self._args(sT=True, open=True)
        opts = ScanOptions(args).build()
        assert "--open" in opts

    def test_Pn_flag(self):
        args = self._args(sT=True, Pn=True)
        opts = ScanOptions(args).build()
        assert "-Pn" in opts


# ---------------------------------------------------------------------------
# Parser tests (use fixture XML)
# ---------------------------------------------------------------------------

class TestScannerParser:
    @pytest.fixture
    def scanner(self):
        """Return a Scanner with a dummy args object (won't actually run nmap)."""
        class Args:
            sS = False; sT = True; sV = True; sU = False; O = False; A = False
            Pn = False; ipv6 = False; p = None; top_ports = None; open = False
            T = None; scripts = None; no_cve = False; target = "127.0.0.1"
            iL = None

        return Scanner(Args(), progress_callback=None, banner_enrich=False)

    def test_parse_hosts_count(self, scanner, rich_report):
        result = scanner._parse_report(rich_report, "nmap -test", "2026-01-01", "2026-01-01", 0.0)
        assert len(result.hosts) == 1

    def test_host_ip(self, scanner, rich_report):
        result = scanner._parse_report(rich_report, "", "", "", 0.0)
        assert result.hosts[0].ip == "192.168.1.10"

    def test_host_is_up(self, scanner, rich_report):
        result = scanner._parse_report(rich_report, "", "", "", 0.0)
        assert result.hosts[0].status == "up"

    def test_host_has_hostname(self, scanner, rich_report):
        result = scanner._parse_report(rich_report, "", "", "", 0.0)
        assert "testserver.local" in result.hosts[0].hostnames

    def test_services_count(self, scanner, rich_report):
        result = scanner._parse_report(rich_report, "", "", "", 0.0)
        # fixture has 4 open ports
        assert len(result.hosts[0].services) == 4

    def test_service_port(self, scanner, rich_report):
        result = scanner._parse_report(rich_report, "", "", "", 0.0)
        ports = {s.port for s in result.hosts[0].services}
        assert 22 in ports
        assert 80 in ports

    def test_ssh_service_product(self, scanner, rich_report):
        result = scanner._parse_report(rich_report, "", "", "", 0.0)
        ssh = next(s for s in result.hosts[0].services if s.port == 22)
        assert ssh.product == "OpenSSH"
        assert ssh.version == "7.4"

    def test_ssh_service_cpe(self, scanner, rich_report):
        result = scanner._parse_report(rich_report, "", "", "", 0.0)
        ssh = next(s for s in result.hosts[0].services if s.port == 22)
        assert any("openssh" in c.lower() for c in ssh.cpes)

    def test_os_match(self, scanner, rich_report):
        result = scanner._parse_report(rich_report, "", "", "", 0.0)
        assert result.hosts[0].os_match is not None
        assert "Linux" in result.hosts[0].os_match


# ---------------------------------------------------------------------------
# CLI argv preprocessing
# ---------------------------------------------------------------------------

class TestPreprocessArgv:
    def test_T5_expanded(self):
        from cvesweep.cli import preprocess_argv
        result = preprocess_argv(["-T5"])
        assert result == ["-T", "5"]

    def test_T0_expanded(self):
        from cvesweep.cli import preprocess_argv
        result = preprocess_argv(["-T0"])
        assert result == ["-T", "0"]

    def test_p_minus_expanded(self):
        from cvesweep.cli import preprocess_argv
        result = preprocess_argv(["-p-"])
        assert result == ["-p", "1-65535"]

    def test_other_flags_passthrough(self):
        from cvesweep.cli import preprocess_argv
        result = preprocess_argv(["-sT", "-sV", "--top-ports", "100"])
        assert result == ["-sT", "-sV", "--top-ports", "100"]

    def test_mixed_flags(self):
        from cvesweep.cli import preprocess_argv
        result = preprocess_argv(["-sS", "-T4", "-p-", "10.0.0.1"])
        assert "-T" in result
        assert "4" in result
        assert "-p" in result
        assert "1-65535" in result
