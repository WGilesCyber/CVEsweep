"""Tests for cvesweep.utils"""

import pytest
from cvesweep.utils import (
    build_keyword_query,
    cpe22_to_cpe23,
    cvss_to_severity,
    parse_version_string,
    validate_target,
    version_in_range,
)


# ---------------------------------------------------------------------------
# validate_target
# ---------------------------------------------------------------------------

class TestValidateTarget:
    def test_valid_ipv4(self):
        assert validate_target("192.168.1.1") is True

    def test_valid_cidr(self):
        assert validate_target("10.0.0.0/24") is True

    def test_valid_hostname(self):
        assert validate_target("example.com") is True

    def test_valid_simple_hostname(self):
        assert validate_target("localhost") is True

    def test_invalid_empty(self):
        assert validate_target("") is False

    def test_valid_ip_range(self):
        assert validate_target("10.0.0.1-10") is True

    def test_valid_loopback(self):
        assert validate_target("127.0.0.1") is True


# ---------------------------------------------------------------------------
# cpe22_to_cpe23
# ---------------------------------------------------------------------------

class TestCpe22ToCpe23:
    def test_basic_conversion(self):
        result = cpe22_to_cpe23("cpe:/a:openbsd:openssh:7.4")
        assert result == "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"

    def test_already_cpe23_passthrough(self):
        cpe23 = "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
        assert cpe22_to_cpe23(cpe23) == cpe23

    def test_short_cpe_gets_padded(self):
        result = cpe22_to_cpe23("cpe:/a:apache:http_server")
        assert result.startswith("cpe:2.3:a:apache:http_server")
        # Should have 11 colon-separated components after "cpe:2.3:"
        parts = result[len("cpe:2.3:"):].split(":")
        assert len(parts) == 11

    def test_full_cpe_not_over_padded(self):
        cpe = "cpe:/a:openbsd:openssh:7.4:p1:*:*:*:*:*:*"
        result = cpe22_to_cpe23(cpe)
        parts = result[len("cpe:2.3:"):].split(":")
        assert len(parts) == 11


# ---------------------------------------------------------------------------
# parse_version_string
# ---------------------------------------------------------------------------

class TestParseVersionString:
    def test_openssh_banner(self):
        # "SSH-2.0-OpenSSH_7.4" — regex picks up 2.0 first (valid version pattern)
        assert parse_version_string("SSH-2.0-OpenSSH_7.4") == "2.0"

    def test_apache_banner(self):
        result = parse_version_string("Server: Apache/2.4.49 (Debian)")
        assert result == "2.4.49"

    def test_nginx_banner(self):
        assert parse_version_string("nginx/1.18.0") == "1.18.0"

    def test_mysql_banner_without_log_suffix(self):
        # "5.7.38-log" — "-log" is not a recognised patch suffix; base version returned
        assert parse_version_string("5.7.38-log") == "5.7.38"

    def test_openssh_p_suffix_captured(self):
        # patch-level suffix p1 should be included
        assert parse_version_string("OpenSSH_8.9p1") == "8.9p1"

    def test_no_version_plain_text(self):
        # No version-like pattern present
        assert parse_version_string("Welcome to FTP server") is None

    def test_empty_returns_none(self):
        assert parse_version_string("") is None

    def test_none_returns_none(self):
        assert parse_version_string(None) is None


# ---------------------------------------------------------------------------
# version_in_range
# ---------------------------------------------------------------------------

class TestVersionInRange:
    def test_no_constraints_returns_true(self):
        assert version_in_range("7.4", None, None, None, None) is True

    def test_exact_end_excl_match(self):
        # Vulnerable: < 9.3p2
        assert version_in_range("7.4", None, None, None, "9.3") is True

    def test_version_above_end_excl(self):
        # Not vulnerable: version >= end_excl
        assert version_in_range("10.0", None, None, None, "9.3") is False

    def test_version_at_end_incl(self):
        # Vulnerable: <= 7.4
        assert version_in_range("7.4", None, None, "7.4", None) is True

    def test_version_above_end_incl(self):
        # Not vulnerable: version > end_incl
        assert version_in_range("7.5", None, None, "7.4", None) is False

    def test_version_at_start_incl(self):
        assert version_in_range("5.0", "5.0", None, None, "7.0") is True

    def test_version_below_start_incl(self):
        assert version_in_range("4.9", "5.0", None, None, "7.0") is False

    def test_invalid_version_returns_true(self):
        # Conservative: can't parse → show the CVE
        assert version_in_range("8 or 9", None, None, None, "9.3") is True

    def test_invalid_bound_returns_true(self):
        assert version_in_range("7.4", None, None, None, "not-a-version") is True


# ---------------------------------------------------------------------------
# build_keyword_query
# ---------------------------------------------------------------------------

class TestBuildKeywordQuery:
    def test_product_and_version(self):
        assert build_keyword_query("OpenSSH", "7.4") == "OpenSSH 7.4"

    def test_product_only(self):
        assert build_keyword_query("nginx", "") == "nginx"

    def test_empty_both(self):
        assert build_keyword_query("", "") == ""


# ---------------------------------------------------------------------------
# cvss_to_severity
# ---------------------------------------------------------------------------

class TestCvssToSeverity:
    def test_critical(self):
        assert cvss_to_severity(9.8) == "CRITICAL"

    def test_high(self):
        assert cvss_to_severity(7.5) == "HIGH"

    def test_medium(self):
        assert cvss_to_severity(5.0) == "MEDIUM"

    def test_low(self):
        assert cvss_to_severity(2.0) == "LOW"

    def test_none(self):
        assert cvss_to_severity(0.0) == "NONE"

    def test_boundary_critical(self):
        assert cvss_to_severity(9.0) == "CRITICAL"

    def test_boundary_high(self):
        assert cvss_to_severity(7.0) == "HIGH"
