"""NVD API v2 client with rate limiting, pagination, CPE matching, and caching."""

import time
from collections import deque
from typing import Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .cache import CVECache
from .models import CVEEntry
from .utils import build_keyword_query, cpe22_to_cpe23, cvss_to_severity, version_in_range

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 100  # NVD maximum per request


class RateLimiter:
    """
    Token-bucket rate limiter for NVD API compliance.

    Without API key: 5 requests per 30-second window.
    With API key:   50 requests per 30-second window.
    """

    def __init__(self, has_api_key: bool):
        self.limit = 50 if has_api_key else 5
        self.window = 30.0
        self._timestamps: deque = deque(maxlen=self.limit)

    def acquire(self) -> None:
        """Block until a request slot is available."""
        now = time.monotonic()

        if len(self._timestamps) < self.limit:
            # Bucket not full — go immediately
            self._timestamps.append(now)
            return

        oldest = self._timestamps[0]
        age = now - oldest
        if age < self.window:
            sleep_for = self.window - age + 0.05  # small safety margin
            time.sleep(sleep_for)

        self._timestamps.append(time.monotonic())

    def notify_retry_after(self, seconds: float) -> None:
        """Called when NVD returns a 429 with a Retry-After header."""
        time.sleep(max(seconds, 1.0))


class NVDClient:
    """
    Client for the NIST NVD CVE API v2.

    Handles rate limiting, pagination, CPE 2.2→2.3 conversion,
    version range filtering, and result caching.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache: Optional[CVECache] = None,
        min_cvss: float = 0.0,
    ):
        self.api_key = api_key
        self.cache = cache
        self.min_cvss = min_cvss
        self.rate_limiter = RateLimiter(has_api_key=bool(api_key))
        self.session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=2,
            status_forcelist=[500, 502, 503],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)

        session.headers.update({
            "Accept": "application/json",
            "User-Agent": "CVEsweep/1.0 (github.com/WGilesCyber/CVEsweep)",
        })
        if self.api_key:
            session.headers["apiKey"] = self.api_key

        return session

    def _get(self, params: dict) -> dict:
        """
        Execute a single GET request to the NVD API.

        Handles 429 (rate limit) manually using the Retry-After header.
        Returns parsed JSON dict.
        """
        for attempt in range(4):
            self.rate_limiter.acquire()
            try:
                resp = self.session.get(NVD_BASE_URL, params=params, timeout=30)
                if resp.status_code == 429:
                    retry_after = float(resp.headers.get("Retry-After", 6))
                    self.rate_limiter.notify_retry_after(retry_after)
                    continue
                resp.raise_for_status()
                return resp.json()
            except requests.RequestException as exc:
                if attempt == 3:
                    raise
                time.sleep(2 ** attempt)
        return {}

    def _fetch_all_pages(self, params: dict) -> List[dict]:
        """Paginate through all NVD results for a given query."""
        all_vulns: List[dict] = []
        start = 0

        while True:
            paged = {**params, "startIndex": start, "resultsPerPage": RESULTS_PER_PAGE}
            data = self._get(paged)
            vulnerabilities = data.get("vulnerabilities", [])
            all_vulns.extend(vulnerabilities)

            total = data.get("totalResults", 0)
            start += len(vulnerabilities)
            if start >= total or not vulnerabilities:
                break

        return all_vulns

    # ------------------------------------------------------------------
    # Public lookup methods
    # ------------------------------------------------------------------

    def lookup_by_cpe(self, cpe22: str, detected_version: str) -> List[CVEEntry]:
        """
        Look up CVEs for a specific CPE (from nmap's CPE list).

        Uses CPE-based NVD search and applies version range filtering
        using the NVD configuration data, which is the most accurate method.
        """
        if self.cache:
            cached = self.cache.get("cpe", cpe22)
            if cached is not None:
                return self._filter_cvss(cached)

        cpe23 = cpe22_to_cpe23(cpe22)
        try:
            vulns = self._fetch_all_pages({"cpeName": cpe23})
        except requests.RequestException:
            return []

        entries = self._parse_vulnerabilities(vulns, detected_version, use_version_filter=True)
        entries.sort(key=lambda e: e.cvss_score, reverse=True)

        if self.cache:
            self.cache.set("cpe", cpe22, entries)

        return self._filter_cvss(entries)

    def lookup_by_keyword(self, product: str, version: str) -> List[CVEEntry]:
        """
        Look up CVEs using keyword search (fallback when no CPE available).

        Keyword search is less precise — version range filtering is applied when a
        version is detected, using NVD's configurations data (same as CPE lookup).
        CVEs with no version range constraints are always included (conservative).
        """
        query = build_keyword_query(product, version)
        if not query:
            return []

        if self.cache:
            cached = self.cache.get("keyword", query)
            if cached is not None:
                return self._filter_cvss(cached)

        try:
            vulns = self._fetch_all_pages({"keywordSearch": query})
        except requests.RequestException:
            return []

        entries = self._parse_vulnerabilities(vulns, version, use_version_filter=True)
        entries.sort(key=lambda e: e.cvss_score, reverse=True)

        if self.cache:
            self.cache.set("keyword", query, entries)

        return self._filter_cvss(entries)

    def lookup_service(
        self,
        service_name: str,
        product: str,
        version: str,
        cpes: List[str],
    ) -> List[CVEEntry]:
        """
        Main entry point: look up CVEs for a discovered service.

        Decision tree:
          1. CPEs present  → lookup_by_cpe (most accurate)
          2. product+version → lookup_by_keyword
          3. product only   → lookup_by_keyword with empty version
          4. nothing        → return []
        """
        all_entries: Dict[str, CVEEntry] = {}

        if cpes:
            for cpe in cpes:
                for entry in self.lookup_by_cpe(cpe, version):
                    if entry.cve_id not in all_entries:
                        all_entries[entry.cve_id] = entry
        elif product:
            for entry in self.lookup_by_keyword(product, version):
                if entry.cve_id not in all_entries:
                    all_entries[entry.cve_id] = entry
        elif service_name:
            for entry in self.lookup_by_keyword(service_name, ""):
                if entry.cve_id not in all_entries:
                    all_entries[entry.cve_id] = entry
        else:
            return []

        sorted_entries = sorted(all_entries.values(), key=lambda e: e.cvss_score, reverse=True)
        return sorted_entries

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_vulnerabilities(
        self,
        vulns: List[dict],
        detected_version: str,
        use_version_filter: bool,
    ) -> List[CVEEntry]:
        """Parse a list of NVD vulnerability dicts into CVEEntry objects."""
        entries: List[CVEEntry] = []
        for item in vulns:
            entry = self._parse_single(item, detected_version, use_version_filter)
            if entry is not None:
                entries.append(entry)
        return entries

    def _parse_single(
        self,
        item: dict,
        detected_version: str,
        use_version_filter: bool,
    ) -> Optional[CVEEntry]:
        """Parse one NVD vulnerability dict. Returns None on parse failure."""
        try:
            cve_data = item.get("cve", item)
            cve_id = cve_data.get("id", "")
            published = (cve_data.get("published", "") or "")[:10]  # date only

            # English description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            if len(description) > 300:
                description = description[:297] + "..."

            # CVSS score
            metrics = cve_data.get("metrics", {})
            score, severity = self._extract_cvss(metrics)

            # Version range filtering (only when using CPE-based lookup)
            if use_version_filter and detected_version:
                ranges = self._extract_version_ranges(cve_data.get("configurations", []))
                if ranges and not self._any_range_matches(detected_version, ranges):
                    return None

            return CVEEntry(
                cve_id=cve_id,
                cvss_score=score,
                severity=severity,
                description=description,
                published=published,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        except (KeyError, TypeError, ValueError):
            return None

    def _extract_cvss(self, metrics: dict) -> Tuple[float, str]:
        """
        Extract the best available CVSS score.
        Priority: CVSS v3.1 > v3.0 > v2.
        Returns (score, severity).
        """
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if not metric_list:
                continue
            primary = metric_list[0]
            cvss_data = primary.get("cvssData", {})
            score = float(cvss_data.get("baseScore", 0.0))
            severity = cvss_data.get("baseSeverity", "") or cvss_to_severity(score)
            return score, severity.upper()

        return 0.0, "NONE"

    def _extract_version_ranges(self, configurations: list) -> List[dict]:
        """
        Walk NVD configurations and collect all vulnerable CPE match entries.

        Returns a flat list of dicts with version range fields.
        Note: AND/OR logic between nodes is intentionally flattened for v1
        (conservative — avoids false negatives at the cost of some false positives).
        """
        ranges = []
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable", False):
                        ranges.append({
                            "criteria": match.get("criteria", ""),
                            "versionStartIncluding": match.get("versionStartIncluding"),
                            "versionStartExcluding": match.get("versionStartExcluding"),
                            "versionEndIncluding": match.get("versionEndIncluding"),
                            "versionEndExcluding": match.get("versionEndExcluding"),
                        })
        return ranges

    def _any_range_matches(self, detected_version: str, ranges: List[dict]) -> bool:
        """Return True if the detected version falls within ANY of the given CPE ranges."""
        for r in ranges:
            if version_in_range(
                detected_version,
                r.get("versionStartIncluding"),
                r.get("versionStartExcluding"),
                r.get("versionEndIncluding"),
                r.get("versionEndExcluding"),
            ):
                return True
        return False

    def _filter_cvss(self, entries: List[CVEEntry]) -> List[CVEEntry]:
        """Filter entries by minimum CVSS score."""
        if self.min_cvss <= 0.0:
            return entries
        return [e for e in entries if e.cvss_score >= self.min_cvss]
