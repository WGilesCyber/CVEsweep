"""Tests for cvesweep.cache"""

import time
from pathlib import Path

import pytest

from cvesweep.cache import CVECache
from cvesweep.models import CVEEntry


def _make_cve(cve_id: str, score: float = 7.0) -> CVEEntry:
    return CVEEntry(
        cve_id=cve_id,
        cvss_score=score,
        severity="HIGH",
        description="Test CVE description",
        published="2024-01-01",
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )


@pytest.fixture
def tmp_cache(tmp_path: Path) -> CVECache:
    """Return a CVECache backed by a temporary directory."""
    return CVECache(db_path=tmp_path / "test_cache.db", ttl=3600)


class TestCacheMissAndHit:
    def test_cache_miss_returns_none(self, tmp_cache):
        result = tmp_cache.get("cpe", "cpe:/a:openbsd:openssh:7.4")
        assert result is None

    def test_cache_hit_returns_data(self, tmp_cache):
        cves = [_make_cve("CVE-2023-0001")]
        tmp_cache.set("cpe", "cpe:/a:openbsd:openssh:7.4", cves)
        result = tmp_cache.get("cpe", "cpe:/a:openbsd:openssh:7.4")
        assert result is not None
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2023-0001"

    def test_empty_list_is_cached(self, tmp_cache):
        tmp_cache.set("keyword", "Apache 2.4.49", [])
        result = tmp_cache.get("keyword", "Apache 2.4.49")
        assert result == []

    def test_different_query_types_dont_collide(self, tmp_cache):
        cves_a = [_make_cve("CVE-2023-0001")]
        cves_b = [_make_cve("CVE-2023-0002")]
        tmp_cache.set("cpe", "openssh", cves_a)
        tmp_cache.set("keyword", "openssh", cves_b)
        assert tmp_cache.get("cpe", "openssh")[0].cve_id == "CVE-2023-0001"
        assert tmp_cache.get("keyword", "openssh")[0].cve_id == "CVE-2023-0002"


class TestCacheExpiry:
    def test_expired_entry_returns_none(self, tmp_path):
        cache = CVECache(db_path=tmp_path / "cache.db", ttl=1)
        cache.set("cpe", "test", [_make_cve("CVE-2023-0001")])
        time.sleep(1.1)
        assert cache.get("cpe", "test") is None

    def test_non_expired_entry_returns_data(self, tmp_path):
        cache = CVECache(db_path=tmp_path / "cache.db", ttl=60)
        cache.set("cpe", "test", [_make_cve("CVE-2023-0001")])
        result = cache.get("cpe", "test")
        assert result is not None


class TestCacheInvalidate:
    def test_invalidate_forces_miss(self, tmp_cache):
        tmp_cache.set("cpe", "test", [_make_cve("CVE-2023-0001")])
        tmp_cache.invalidate("cpe", "test")
        assert tmp_cache.get("cpe", "test") is None

    def test_invalidate_nonexistent_is_noop(self, tmp_cache):
        # Should not raise
        tmp_cache.invalidate("cpe", "nonexistent")


class TestCacheCleanup:
    def test_cleanup_removes_expired(self, tmp_path):
        cache = CVECache(db_path=tmp_path / "cache.db", ttl=1)
        cache.set("cpe", "old", [_make_cve("CVE-2023-0001")])
        cache.set("cpe", "new", [_make_cve("CVE-2023-0002")])
        time.sleep(1.1)
        removed = cache.cleanup()
        assert removed == 2

    def test_cleanup_leaves_fresh_entries(self, tmp_path):
        cache = CVECache(db_path=tmp_path / "cache.db", ttl=3600)
        cache.set("cpe", "fresh", [_make_cve("CVE-2023-0001")])
        removed = cache.cleanup()
        assert removed == 0
        assert cache.get("cpe", "fresh") is not None


class TestCacheStats:
    def test_stats_returns_dict(self, tmp_cache):
        stats = tmp_cache.stats()
        assert "total_entries" in stats
        assert "expired_entries" in stats
        assert "db_size_bytes" in stats

    def test_stats_count_increases(self, tmp_cache):
        tmp_cache.set("cpe", "a", [_make_cve("CVE-2023-0001")])
        tmp_cache.set("cpe", "b", [_make_cve("CVE-2023-0002")])
        assert tmp_cache.stats()["total_entries"] == 2


class TestCacheMultipleCVEs:
    def test_multiple_cves_round_trip(self, tmp_cache):
        cves = [_make_cve(f"CVE-2023-{i:04d}", float(i)) for i in range(5)]
        tmp_cache.set("cpe", "multi", cves)
        result = tmp_cache.get("cpe", "multi")
        assert result is not None
        assert len(result) == 5
        ids = {c.cve_id for c in result}
        assert "CVE-2023-0003" in ids
