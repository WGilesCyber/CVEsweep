"""Tests for cvesweep.output — format rendering."""

import json

import pytest

from cvesweep.models import CVEEntry, HostResult, ScanResult, ServiceResult
from cvesweep.output import render_json, render_text
from cvesweep.utils import cvss_to_severity


def _make_cve(cve_id: str = "CVE-2023-38408", score: float = 9.8) -> CVEEntry:
    return CVEEntry(
        cve_id=cve_id,
        cvss_score=score,
        severity=cvss_to_severity(score),
        description="A critical vulnerability in OpenSSH ssh-agent.",
        published="2023-07-20",
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )


def _make_service(port: int = 22, cves=None) -> ServiceResult:
    return ServiceResult(
        port=port,
        protocol="tcp",
        state="open",
        service_name="ssh",
        product="OpenSSH",
        version="7.4",
        extrainfo="",
        banner="",
        cpes=["cpe:/a:openbsd:openssh:7.4"],
        cves=cves or [],
    )


def _make_result(with_cves: bool = True) -> ScanResult:
    cves = [_make_cve()] if with_cves else []
    clean_svc = _make_service(port=80, cves=[])
    clean_svc.service_name = "http"
    clean_svc.product = "Apache httpd"
    clean_svc.version = "2.4.49"

    host = HostResult(
        ip="192.168.1.10",
        hostnames=["testserver.local"],
        status="up",
        os_match="Linux 4.x",
        services=[_make_service(cves=cves), clean_svc],
    )
    return ScanResult(
        command_line="cvesweep -sT -sV 192.168.1.10",
        scan_start="2026-02-21T17:00:00",
        scan_end="2026-02-21T17:00:14",
        elapsed=14.3,
        hosts=[host],
    )


# ---------------------------------------------------------------------------
# JSON renderer
# ---------------------------------------------------------------------------

class TestRenderJson:
    def test_is_valid_json(self):
        result = _make_result()
        output = render_json(result)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_contains_host_ip(self):
        result = _make_result()
        output = render_json(result)
        assert "192.168.1.10" in output

    def test_contains_cve_id(self):
        result = _make_result(with_cves=True)
        output = render_json(result)
        assert "CVE-2023-38408" in output

    def test_json_structure(self):
        result = _make_result()
        parsed = json.loads(render_json(result))
        assert "hosts" in parsed
        assert "command_line" in parsed
        assert "elapsed" in parsed
        hosts = parsed["hosts"]
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "192.168.1.10"


# ---------------------------------------------------------------------------
# Text renderer
# ---------------------------------------------------------------------------

class TestRenderText:
    def test_contains_header(self):
        result = _make_result()
        output = render_text(result)
        assert "CVEsweep" in output

    def test_contains_host_ip(self):
        result = _make_result()
        output = render_text(result)
        assert "192.168.1.10" in output

    def test_contains_cve_id(self):
        result = _make_result(with_cves=True)
        output = render_text(result)
        assert "CVE-2023-38408" in output

    def test_clean_service_marked(self):
        result = _make_result(with_cves=False)
        output = render_text(result)
        assert "CLEAN" in output

    def test_contains_summary(self):
        result = _make_result()
        output = render_text(result)
        assert "Summary" in output

    def test_no_ansi_codes(self):
        result = _make_result()
        output = render_text(result)
        # ANSI escape codes start with ESC[ (\x1b[)
        assert "\x1b[" not in output

    def test_contains_command_line(self):
        result = _make_result()
        output = render_text(result)
        assert "cvesweep -sT -sV" in output


# ---------------------------------------------------------------------------
# Model property tests
# ---------------------------------------------------------------------------

class TestModelProperties:
    def test_host_is_vulnerable(self):
        result = _make_result(with_cves=True)
        assert result.hosts[0].is_vulnerable is True

    def test_host_not_vulnerable(self):
        result = _make_result(with_cves=False)
        assert result.hosts[0].is_vulnerable is False

    def test_total_cves_count(self):
        result = _make_result(with_cves=True)
        assert result.total_cves == 1

    def test_all_cves_flatten(self):
        result = _make_result(with_cves=True)
        flat = result.all_cves
        assert len(flat) == 1
        host_ip, port, svc_name, cve = flat[0]
        assert host_ip == "192.168.1.10"
        assert port == 22
        assert cve.cve_id == "CVE-2023-38408"

    def test_vulnerable_hosts_filter(self):
        result = _make_result(with_cves=True)
        assert len(result.vulnerable_hosts) == 1

    def test_display_version(self):
        svc = _make_service()
        assert "OpenSSH" in svc.display_version
        assert "7.4" in svc.display_version

    def test_display_name_with_hostname(self):
        result = _make_result()
        assert "testserver.local" in result.hosts[0].display_name

    def test_display_name_without_hostname(self):
        result = _make_result()
        result.hosts[0].hostnames = []
        assert result.hosts[0].display_name == "192.168.1.10"
