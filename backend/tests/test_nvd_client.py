import json

from app.models import CveCache
from app.vuln import nvd_client


def test_search_nvd_serves_from_fresh_cache_without_network(db_session, monkeypatch):
    cached_results = [
        {"cve_id": "CVE-2016-0777", "description": "desc", "cvss_score": 5.0, "severity": "medium"}
    ]
    db_session.add(CveCache(keyword="OpenSSH 7.2", response_json=json.dumps(cached_results)))
    db_session.commit()

    def fail_get(*args, **kwargs):
        raise AssertionError("should not hit the network when cache is fresh")

    monkeypatch.setattr(nvd_client.httpx, "get", fail_get)

    results = nvd_client.search_nvd(db_session, "OpenSSH 7.2")
    assert results == cached_results


def test_search_nvd_falls_back_to_empty_on_network_failure(db_session, monkeypatch):
    def raise_get(*args, **kwargs):
        raise ConnectionError("no network available in this sandbox")

    monkeypatch.setattr(nvd_client.httpx, "get", raise_get)
    monkeypatch.setattr(nvd_client._rate_limiter, "wait", lambda: None)

    results = nvd_client.search_nvd(db_session, "totally-unseen-keyword")
    assert results == []


def test_search_nvd_falls_back_to_stale_cache_on_failure(db_session, monkeypatch):
    import datetime

    stale_results = [{"cve_id": "CVE-1999-0001", "description": "old", "cvss_score": 3.0, "severity": "low"}]
    cache = CveCache(keyword="stale-keyword", response_json=json.dumps(stale_results))
    cache.fetched_at = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
    db_session.add(cache)
    db_session.commit()

    def raise_get(*args, **kwargs):
        raise ConnectionError("no network available")

    monkeypatch.setattr(nvd_client.httpx, "get", raise_get)
    monkeypatch.setattr(nvd_client._rate_limiter, "wait", lambda: None)

    results = nvd_client.search_nvd(db_session, "stale-keyword")
    assert results == stale_results


def test_extract_cve_summary_prefers_cvss_v31():
    item = {
        "cve": {
            "id": "CVE-2024-9999",
            "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
            "metrics": {
                "cvssMetricV31": [
                    {"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                ]
            },
        }
    }
    summary = nvd_client._extract_cve_summary(item)
    assert summary["cve_id"] == "CVE-2024-9999"
    assert summary["cvss_score"] == 7.5
    assert summary["severity"] == "high"
