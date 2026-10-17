"""ingest/osv_client.py — CVSS extraction and severity enrichment helpers."""

from __future__ import annotations

# GAP 1: add real HTTP query_batch against api.osv.dev/v1/querybatch
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from config import settings


# ── Severity label maps ────────────────────────────────────────────────────

_TEXT_TO_SCORE: dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
}


def extract_cvss(vuln: dict) -> float:
    """
    Extract a numeric CVSS score from an OSV vulnerability dict.

    Checks database_specific.cvss first (float), then falls back to
    database_specific.severity as a text label.  Returns 0.0 if neither exists.
    """
    db_specific = vuln.get("database_specific", {})

    # Numeric CVSS takes priority
    raw_cvss = db_specific.get("cvss")
    if raw_cvss is not None:
        try:
            return float(raw_cvss)
        except (TypeError, ValueError):
            pass

    # Text severity label fallback
    severity_text = db_specific.get("severity")
    if severity_text and isinstance(severity_text, str):
        return _TEXT_TO_SCORE.get(severity_text.upper(), 0.0)

    return 0.0


def cvss_to_severity(score: float) -> str:
    """
    Map a numeric CVSS score to a severity label string.

    Boundaries (inclusive lower end):
      CRITICAL >= 9.0
      HIGH     >= 7.0
      MEDIUM   >= 4.0
      LOW      >= 1.0
      NONE     otherwise
    """
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 1.0:
        return "LOW"
    return "NONE"


class OSVClient:
    """Minimal OSV client that enriches vulnerability dicts with score/severity."""

    def _enrich(self, vulns: list[dict]) -> list[dict]:
        """
        Add _cvss_score and _severity keys to each vulnerability dict in place.

        Args:
            vulns: List of raw OSV vulnerability dicts.

        Returns:
            The same list with _cvss_score (float) and _severity (str) added.
        """
        for vuln in vulns:
            score = extract_cvss(vuln)
            vuln["_cvss_score"] = score
            vuln["_severity"] = cvss_to_severity(score)
        return vulns

    BASE_URL = "https://api.osv.dev/v1/querybatch"

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=8))
    def query_batch(self, packages: list[dict]) -> list[list[dict]]:
        """
        POST to OSV API in batches of 1000 (OSV limit).
        packages: list of {"name": str, "version": str, "ecosystem": str}
        Returns: list of vuln lists, one per package in same order as input.
        Each vuln list is already enriched via self._enrich().
        """
        results: list[list[dict]] = []
        batch_size = 1000
        for i in range(0, len(packages), batch_size):
            batch = packages[i:i + batch_size]
            queries = [
                {"package": {"name": p["name"], "version": p["version"], "ecosystem": p["ecosystem"]}}
                for p in batch
            ]
            payload = {"queries": queries}
            with httpx.Client(timeout=settings.osv_timeout_seconds) as client:
                response = client.post(self.BASE_URL, json=payload)
                response.raise_for_status()
            data = response.json()
            for item in data.get("results", []):
                vulns = item.get("vulns", [])
                self._enrich(vulns)
                results.append(vulns)
        # Pad with empty lists if API returned fewer results
        while len(results) < len(packages):
            results.append([])
        return results
