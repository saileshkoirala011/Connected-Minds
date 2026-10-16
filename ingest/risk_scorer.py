"""ingest/risk_scorer.py — score packages from CVSS data and graph-derived factors."""

from __future__ import annotations

from dataclasses import dataclass
from ingest.osv_client import extract_cvss


@dataclass
class RiskFactors:
    """Input factors used to compute a composite risk score."""

    max_cvss: float = 0.0
    vuln_count: int = 0
    blast_radius: int = 0
    max_depth: int = 0


def severity_label(score: float) -> str:
    """
    Map a numeric risk score to a severity label string.

    Boundaries:
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


class RiskScorer:
    """Compute composite risk scores from vulnerability and graph factors."""

    def score(self, factors: RiskFactors) -> float:
        """
        Weighted composite risk score, capped at 10.0.

        Weights:
          max_cvss     × 0.50
          vuln_count   × 2.0  (capped contribution at vuln_count/10, max 1.0)
          blast_radius × 2.0  (capped contribution at blast_radius/100, max 1.0)
          max_depth    × 1.0  (capped contribution at max_depth/10, max 1.0)
        """
        raw = (
            factors.max_cvss * 0.50
            + min(factors.vuln_count / 10, 1.0) * 2.0
            + min(factors.blast_radius / 100, 1.0) * 2.0
            + min(factors.max_depth / 10, 1.0) * 1.0
        )
        return min(raw, 10.0)

    def score_from_vulns(
        self,
        vulns: list[dict],
        blast_radius: int,
    ) -> tuple[float, RiskFactors]:
        """
        Compute score and factors from a list of enriched vulnerability dicts.

        Reads _cvss_score from each vuln (defaults to 0.0 if absent).
        Sets max_depth=0 (graph depth not available here).

        Args:
            vulns:        List of vulnerability dicts (post _enrich).
            blast_radius: Number of files exposed to this package.

        Returns:
            (score, RiskFactors) tuple.
        """
        scores = [float(v.get("_cvss_score", 0.0)) if "_cvss_score" in v else extract_cvss(v) for v in vulns]
        max_cvss = max(scores, default=0.0)
        factors = RiskFactors(
            max_cvss=max_cvss,
            vuln_count=len(vulns),
            blast_radius=blast_radius,
            max_depth=0,
        )
        return self.score(factors), factors
