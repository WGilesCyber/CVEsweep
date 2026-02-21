"""Tests for cvesweep.cve_lookup — mocked HTTP, no live NVD calls."""

import json
from pathlib import Path

import pytest
import responses as responses_lib

from cvesweep.cve_lookup import NVD_BASE_URL, NVDClient
from cvesweep.models import CVEEntry

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _load_nvd_fixture() -> dict:
    return json.loads((FIXTURE_DIR / "nvd_sample.json").read_text())


def _make_nvd_response(cve_id: str, score: float = 7.5, severity: str = "HIGH") -> dict:
    """Build a minimal NVD API response dict."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2023-07-20T01:15:09.947",
                    "descriptions": [
                        {"lang": "en", "value": f"Test description for {cve_id}."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": score,
                                    "baseSeverity": severity,
                                }
                            }
                        ]
                    },
                    "configurations": [],
                }
            }
        ],
    }


@pytest.fixture
def client(tmp_path):
    """NVDClient with no cache and no API key for unit testing."""
    return NVDClient(api_key=None, cache=None, min_cvss=0.0)


@pytest.fixture
def client_with_cache(tmp_path):
    from cvesweep.cache import CVECache
    cache = CVECache(db_path=tmp_path / "cache.db", ttl=3600)
    return NVDClient(api_key=None, cache=cache, min_cvss=0.0), cache


# ---------------------------------------------------------------------------
# lookup_by_keyword
# ---------------------------------------------------------------------------

class TestLookupByKeyword:
    @responses_lib.activate
    def test_returns_cve_entries(self, client):
        responses_lib.add(
            responses_lib.GET,
            NVD_BASE_URL,
            json=_make_nvd_response("CVE-2023-38408", score=9.8, severity="CRITICAL"),
            status=200,
        )
        result = client.lookup_by_keyword("OpenSSH", "7.4")
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2023-38408"
        assert result[0].cvss_score == 9.8
        assert result[0].severity == "CRITICAL"

    @responses_lib.activate
    def test_empty_result(self, client):
        responses_lib.add(
            responses_lib.GET,
            NVD_BASE_URL,
            json={"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []},
            status=200,
        )
        result = client.lookup_by_keyword("nonexistent", "99.99")
        assert result == []

    @responses_lib.activate
    def test_min_cvss_filters(self, tmp_path):
        client_high = NVDClient(api_key=None, cache=None, min_cvss=8.0)
        responses_lib.add(
            responses_lib.GET,
            NVD_BASE_URL,
            json=_make_nvd_response("CVE-2023-0001", score=5.0, severity="MEDIUM"),
            status=200,
        )
        result = client_high.lookup_by_keyword("test", "1.0")
        assert result == []

    @responses_lib.activate
    def test_cache_is_used_on_second_call(self, client_with_cache):
        client, cache = client_with_cache
        responses_lib.add(
            responses_lib.GET,
            NVD_BASE_URL,
            json=_make_nvd_response("CVE-2023-0001"),
            status=200,
        )
        # First call hits NVD
        result1 = client.lookup_by_keyword("Apache", "2.4.49")
        # Second call should use cache (no additional HTTP call)
        result2 = client.lookup_by_keyword("Apache", "2.4.49")
        assert len(responses_lib.calls) == 1  # Only one HTTP request
        assert result1[0].cve_id == result2[0].cve_id

    def test_empty_query_returns_empty(self, client):
        result = client.lookup_by_keyword("", "")
        assert result == []


# ---------------------------------------------------------------------------
# lookup_by_cpe
# ---------------------------------------------------------------------------

class TestLookupByCpe:
    @responses_lib.activate
    def test_basic_cpe_lookup(self, client):
        responses_lib.add(
            responses_lib.GET,
            NVD_BASE_URL,
            json=_make_nvd_response("CVE-2023-38408", score=9.8, severity="CRITICAL"),
            status=200,
        )
        result = client.lookup_by_cpe("cpe:/a:openbsd:openssh:7.4", "7.4")
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2023-38408"

    @responses_lib.activate
    def test_cpe_url_uses_cpe23_format(self, client):
        responses_lib.add(
            responses_lib.GET,
            NVD_BASE_URL,
            json={"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []},
            status=200,
        )
        client.lookup_by_cpe("cpe:/a:openbsd:openssh:7.4", "7.4")
        # Verify the request used cpeName with CPE 2.3 format
        # The URL will be percent-encoded: "cpe:2.3:" → "cpe%3A2.3%3A"
        assert len(responses_lib.calls) == 1
        url = responses_lib.calls[0].request.url
        assert "cpeName" in url
        assert "cpe" in url and ("2.3" in url or "2%2E3" in url or "%3A2.3%3A" in url or "cpe%3A2.3%3A" in url)


# ---------------------------------------------------------------------------
# _parse_single: CVSS extraction
# ---------------------------------------------------------------------------

class TestCvssExtraction:
    def test_v31_preferred_over_v30(self, client):
        item = {
            "cve": {
                "id": "CVE-2023-0001",
                "published": "2023-01-01",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                    "cvssMetricV30": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}],
                },
                "configurations": [],
            }
        }
        entry = client._parse_single(item, "", use_version_filter=False)
        assert entry.cvss_score == 9.8
        assert entry.severity == "CRITICAL"

    def test_v30_fallback_when_no_v31(self, client):
        item = {
            "cve": {
                "id": "CVE-2023-0002",
                "published": "2023-01-01",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "metrics": {
                    "cvssMetricV30": [{"cvssData": {"baseScore": 7.0, "baseSeverity": "HIGH"}}],
                },
                "configurations": [],
            }
        }
        entry = client._parse_single(item, "", use_version_filter=False)
        assert entry.cvss_score == 7.0

    def test_no_metrics_returns_zero_score(self, client):
        item = {
            "cve": {
                "id": "CVE-2023-0003",
                "published": "2023-01-01",
                "descriptions": [{"lang": "en", "value": "Old CVE with no CVSS"}],
                "metrics": {},
                "configurations": [],
            }
        }
        entry = client._parse_single(item, "", use_version_filter=False)
        assert entry is not None
        assert entry.cvss_score == 0.0
        assert entry.severity == "NONE"

    def test_description_truncated_at_300(self, client):
        long_desc = "A" * 400
        item = {
            "cve": {
                "id": "CVE-2023-0004",
                "published": "2023-01-01",
                "descriptions": [{"lang": "en", "value": long_desc}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]},
                "configurations": [],
            }
        }
        entry = client._parse_single(item, "", use_version_filter=False)
        assert len(entry.description) <= 303  # 300 + "..."
        assert entry.description.endswith("...")


# ---------------------------------------------------------------------------
# lookup_service routing
# ---------------------------------------------------------------------------

class TestLookupService:
    @responses_lib.activate
    def test_uses_cpe_when_available(self, client):
        responses_lib.add(
            responses_lib.GET,
            NVD_BASE_URL,
            json=_make_nvd_response("CVE-2023-38408"),
            status=200,
        )
        result = client.lookup_service(
            "ssh", "OpenSSH", "7.4", ["cpe:/a:openbsd:openssh:7.4"]
        )
        assert len(responses_lib.calls) == 1
        assert "cpeName" in responses_lib.calls[0].request.url

    @responses_lib.activate
    def test_falls_back_to_keyword_without_cpe(self, client):
        responses_lib.add(
            responses_lib.GET,
            NVD_BASE_URL,
            json=_make_nvd_response("CVE-2023-38408"),
            status=200,
        )
        result = client.lookup_service("ssh", "OpenSSH", "7.4", [])
        assert len(responses_lib.calls) == 1
        assert "keywordSearch" in responses_lib.calls[0].request.url

    def test_returns_empty_with_no_info(self, client):
        result = client.lookup_service("", "", "", [])
        assert result == []

    @responses_lib.activate
    def test_deduplicates_across_cpes(self, client):
        """Multiple CPEs returning the same CVE should deduplicate."""
        responses_lib.add(
            responses_lib.GET,
            NVD_BASE_URL,
            json=_make_nvd_response("CVE-2023-0001"),
            status=200,
        )
        responses_lib.add(
            responses_lib.GET,
            NVD_BASE_URL,
            json=_make_nvd_response("CVE-2023-0001"),
            status=200,
        )
        result = client.lookup_service(
            "ssh", "OpenSSH", "7.4",
            ["cpe:/a:openbsd:openssh:7.4", "cpe:/a:openbsd:openssh:7.4p1"]
        )
        ids = [e.cve_id for e in result]
        assert len(ids) == len(set(ids))  # No duplicates


# ---------------------------------------------------------------------------
# NVD fixture integration (reads real cached response)
# ---------------------------------------------------------------------------

class TestNvdFixture:
    def test_parse_real_nvd_response(self, client):
        """Parse the downloaded NVD fixture — checks parser robustness."""
        fixture = _load_nvd_fixture()
        vulns = fixture.get("vulnerabilities", [])
        entries = client._parse_vulnerabilities(vulns, "7.4", use_version_filter=False)
        # The fixture has 3 results; all should parse without crashing
        assert len(entries) == len(vulns)
        for e in entries:
            assert e.cve_id.startswith("CVE-")
            assert 0.0 <= e.cvss_score <= 10.0
