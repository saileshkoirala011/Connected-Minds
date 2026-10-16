"""ingest/osv_client.py — CVSS extraction and severity enrichment helpers."""

from __future__ import annotations


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
