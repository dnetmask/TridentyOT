"""Client for the NVD (National Vulnerability Database) CVE 2.0 REST API,
used to look up CVEs by product/version keyword extracted from service
banners. Results are cached in the database because the public NVD API is
rate-limited (5 req/30s without an API key) and because this method should
keep working (from cache) even when the deployment has no internet access,
which is common on isolated OT networks.
"""

import json
import logging
import threading
import time

import httpx
from sqlalchemy.orm import Session

from app.config import (
    NVD_API_BASE_URL,
    NVD_API_KEY,
    NVD_CACHE_TTL_SECONDS,
    NVD_REQUEST_TIMEOUT_SECONDS,
)
from app.models import CveCache, utcnow

logger = logging.getLogger(__name__)


class _RateLimiter:
    def __init__(self, min_interval_seconds: float) -> None:
        self._min_interval = min_interval_seconds
        self._lock = threading.Lock()
        self._last_call = 0.0

    def wait(self) -> None:
        with self._lock:
            elapsed = time.monotonic() - self._last_call
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            self._last_call = time.monotonic()


# ~5.5s between calls keeps us comfortably under the public 5-requests/30s cap.
_rate_limiter = _RateLimiter(5.5)


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _extract_cve_summary(cve_item: dict) -> dict:
    cve = cve_item.get("cve", {})
    descriptions = cve.get("descriptions", [])
    description_en = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")

    metrics = cve.get("metrics", {})
    cvss_score = None
    severity = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = entries[0].get("baseSeverity") or cvss_data.get("baseSeverity")
            break

    return {
        "cve_id": cve.get("id"),
        "description": description_en[:500],
        "cvss_score": cvss_score,
        "severity": (severity or _severity_from_score(cvss_score)).lower(),
    }


def search_nvd(db_session: Session, keyword: str, max_results: int = 5) -> list[dict]:
    """Returns a list of {cve_id, description, cvss_score, severity} dicts.

    Serves from cache when fresh; on a live-lookup failure (no network,
    rate limit, NVD outage) falls back to a stale cache entry if one
    exists, otherwise returns an empty list rather than raising.
    """
    cache_row = db_session.query(CveCache).filter(CveCache.keyword == keyword).one_or_none()
    now = utcnow()
    if cache_row is not None:
        fetched_at = cache_row.fetched_at
        if fetched_at.tzinfo is None:
            fetched_at = fetched_at.replace(tzinfo=now.tzinfo)
        if (now - fetched_at).total_seconds() < NVD_CACHE_TTL_SECONDS:
            return json.loads(cache_row.response_json)[:max_results]

    try:
        _rate_limiter.wait()
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        response = httpx.get(
            NVD_API_BASE_URL,
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            headers=headers,
            timeout=NVD_REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
        results = [
            _extract_cve_summary(item) for item in payload.get("vulnerabilities", [])
        ]
        results = [r for r in results if r["cve_id"]]

        if cache_row is None:
            cache_row = CveCache(keyword=keyword, response_json=json.dumps(results), fetched_at=now)
            db_session.add(cache_row)
        else:
            cache_row.response_json = json.dumps(results)
            cache_row.fetched_at = now
        db_session.commit()
        return results
    except Exception as exc:  # network unavailable, rate-limited, malformed response, etc.
        logger.warning("NVD lookup failed for keyword %r: %s", keyword, exc)
        if cache_row is not None:
            return json.loads(cache_row.response_json)[:max_results]
        return []
