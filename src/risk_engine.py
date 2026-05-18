"""
risk_engine.py — Composite risk scoring and Top-5 ranking for TawasolPay.

Scoring model (6 dimensions, CVSS as tiebreaker only):
  1. Internet exposure          — 20%
  2. Active exploit available   — 20%
  3. Threat actor campaign match— 20%
  4. Ransomware association     — 15%
  5. Business service criticality— 15%
  6. Missing compensating controls— 10%
  CVSS tiebreaker               — normalised 0-1, used only to break ties

Each dimension returns a 0.0–1.0 score; combined weighted total is 0.0–1.0.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional
import pandas as pd

logger = logging.getLogger(__name__)

# ── Weights ────────────────────────────────────────────────────────────────
WEIGHTS = {
    "internet_exposure":    0.20,
    "exploit_available":    0.20,
    "threat_actor_match":   0.20,
    "ransomware":           0.15,
    "business_criticality": 0.15,
    "missing_controls":     0.10,
}

# Business impact → score mapping
IMPACT_SCORE = {
    "critical": 1.0,
    "high":     0.75,
    "medium":   0.50,
    "low":      0.25,
}

# Revenue impact → score mapping
REVENUE_SCORE = {
    "critical": 1.0,
    "high":     0.75,
    "medium":   0.50,
    "low":      0.25,
}


@dataclass
class RiskEntry:
    rank: int
    vuln_id: str
    asset_id: str
    asset_name: str
    asset_type: str
    vulnerability_name: str
    cve: str
    cvss: float
    severity: str
    days_open: int
    business_service: str
    internet_exposed: bool
    exploit_available: bool
    patch_available: bool
    edr_installed: bool
    threat_actors: list[str] = field(default_factory=list)
    campaign_names: list[str] = field(default_factory=list)
    ransomware_linked: bool = False
    composite_score: float = 0.0
    score_breakdown: dict = field(default_factory=dict)
    is_kev: bool = False
    kev_ransomware: bool = False
    nist_control_id: str = ""
    nist_control_title: str = ""
    nist_control_text: str = ""
    explanation: str = ""
    recommended_action: str = ""
    data_classification: str = ""
    location: str = ""
    environment: str = ""


def _business_criticality_score(service_name: str, biz_df: pd.DataFrame) -> float:
    """Score 0–1 from business_services data for a given service name."""
    if biz_df is None or biz_df.empty:
        return 0.5
    row = biz_df[biz_df["business_service"].str.lower() == service_name.lower()]
    if row.empty:
        return 0.5
    row = row.iloc[0]
    impact_str = str(row.get("business_impact", "")).lower()
    revenue_str = str(row.get("revenue_impact", "")).lower()

    # Parse impact
    if "critical" in impact_str:
        impact_val = 1.0
    elif "high" in impact_str:
        impact_val = 0.75
    elif "medium" in impact_str:
        impact_val = 0.50
    else:
        impact_val = 0.25

    # Parse revenue
    revenue_val = REVENUE_SCORE.get(revenue_str.strip(), 0.5)

    # Average of impact and revenue
    return (impact_val + revenue_val) / 2


def _missing_controls_score(edr_installed: bool, patch_available: bool) -> float:
    """
    Score increases when compensating controls are absent.
    No EDR + No patch available = 1.0 (worst)
    EDR + Patch available = 0.0 (best)
    """
    score = 0.0
    if not edr_installed:
        score += 0.5
    if not patch_available:
        score += 0.5
    return score


def compute_composite_score(
    vuln_row: pd.Series,
    asset_row: pd.Series,
    ti_matches: pd.DataFrame,
    biz_df: pd.DataFrame,
) -> tuple[float, dict, list[str], list[str], bool]:
    """
    Returns (composite_score, breakdown_dict, threat_actors, campaign_names, ransomware_linked)
    """
    breakdown = {}

    # 1. Internet exposure
    internet_score = 1.0 if asset_row.get("internet_exposed", False) else 0.0
    breakdown["internet_exposure"] = round(internet_score, 3)

    # 2. Active exploit available
    exploit_score = 1.0 if vuln_row.get("exploit_available", False) else 0.0
    breakdown["exploit_available"] = round(exploit_score, 3)

    # 3. Threat actor campaign match
    threat_actors = []
    campaign_names = []
    ransomware_linked = False
    if not ti_matches.empty:
        threat_actor_score = 1.0
        threat_actors = ti_matches["threat_actor"].dropna().unique().tolist()
        campaign_names = ti_matches["campaign_name"].dropna().unique().tolist()
        ransomware_linked = ti_matches["ransomware_association"].any()
    else:
        threat_actor_score = 0.0
    breakdown["threat_actor_match"] = round(threat_actor_score, 3)

    # 4. Ransomware association
    ransomware_score = 1.0 if ransomware_linked else 0.0
    breakdown["ransomware"] = round(ransomware_score, 3)

    # 5. Business service criticality
    service = str(asset_row.get("business_service", ""))
    biz_score = _business_criticality_score(service, biz_df)
    breakdown["business_criticality"] = round(biz_score, 3)

    # 6. Missing compensating controls
    edr = bool(asset_row.get("edr_installed", True))
    patch = bool(vuln_row.get("patch_available", True))
    controls_score = _missing_controls_score(edr, patch)
    breakdown["missing_controls"] = round(controls_score, 3)

    # Composite weighted sum
    composite = (
        WEIGHTS["internet_exposure"]    * internet_score +
        WEIGHTS["exploit_available"]    * exploit_score +
        WEIGHTS["threat_actor_match"]   * threat_actor_score +
        WEIGHTS["ransomware"]           * ransomware_score +
        WEIGHTS["business_criticality"] * biz_score +
        WEIGHTS["missing_controls"]     * controls_score
    )

    # CVSS tiebreaker: add a tiny fractional component (max 0.05 boost)
    cvss = float(vuln_row.get("cvss", 0))
    composite += (cvss / 10.0) * 0.05

    breakdown["cvss_tiebreaker"] = round((cvss / 10.0) * 0.05, 4)
    breakdown["composite_total"] = round(composite, 4)

    return composite, breakdown, threat_actors, campaign_names, ransomware_linked


def rank_top5(
    assets_df: pd.DataFrame,
    vulns_df: pd.DataFrame,
    ti_df: pd.DataFrame,
    biz_df: pd.DataFrame,
    kev_cves: set[str] | None = None,
    kev_ransomware_cves: set[str] | None = None,
) -> list[RiskEntry]:
    """
    Join assets ↔ vulns ↔ threat_intel, compute composite scores, return top-5.
    """
    kev_cves = kev_cves or set()
    kev_ransomware_cves = kev_ransomware_cves or set()

    scored_rows = []

    for _, vuln in vulns_df.iterrows():
        asset_id = vuln["asset_id"]
        asset_rows = assets_df[assets_df["asset_id"] == asset_id]
        if asset_rows.empty:
            logger.warning(f"Asset {asset_id} not found for vuln {vuln['vuln_id']}")
            continue
        asset = asset_rows.iloc[0]

        cve_id = str(vuln.get("cve", "")).strip()

        # Find matching threat intelligence (by CVE or control ID)
        ti_matches = ti_df[ti_df["matched_cve_or_control"].str.strip() == cve_id]

        composite, breakdown, threat_actors, campaigns, ransomware = compute_composite_score(
            vuln, asset, ti_matches, biz_df
        )

        # KEV enrichment
        is_kev = cve_id in kev_cves
        kev_ransomware = cve_id in kev_ransomware_cves

        # If KEV has ransomware flag, update ransomware in breakdown
        if kev_ransomware and not ransomware:
            ransomware = True
            additional = WEIGHTS["ransomware"] * 1.0
            composite += additional
            breakdown["ransomware"] = 1.0
            breakdown["composite_total"] = round(composite, 4)

        scored_rows.append({
            "vuln_id": str(vuln["vuln_id"]),
            "asset_id": str(asset_id),
            "asset_name": str(asset["asset_name"]),
            "asset_type": str(asset["asset_type"]),
            "vulnerability_name": str(vuln["vulnerability_name"]),
            "cve": str(cve_id),
            "cvss": float(vuln["cvss"]),
            "severity": str(vuln["severity"]),
            "days_open": int(vuln["days_open"]),
            "business_service": str(asset.get("business_service", "")),
            "internet_exposed": bool(asset["internet_exposed"]),
            "exploit_available": bool(vuln["exploit_available"]),
            "patch_available": bool(vuln["patch_available"]),
            "edr_installed": bool(asset["edr_installed"]),
            "threat_actors": [str(a) for a in threat_actors],
            "campaign_names": [str(c) for c in campaigns],
            "ransomware_linked": bool(ransomware),
            "composite_score": float(composite),
            "score_breakdown": {k: float(v) for k, v in breakdown.items()},
            "is_kev": bool(is_kev),
            "kev_ransomware": bool(kev_ransomware),
            "data_classification": str(asset.get("data_classification", "")),
            "location": str(asset.get("location", "")),
            "environment": str(asset.get("environment", "")),
        })

    if not scored_rows:
        logger.warning("No vulnerabilities scored!")
        return []

    # Sort by composite score descending; CVSS already embedded as tiebreaker
    scored_rows.sort(key=lambda x: x["composite_score"], reverse=True)

    # Deduplicate: prefer highest-score entry per (asset_id + cve)
    seen = set()
    deduped = []
    for row in scored_rows:
        key = (row["asset_id"], row["cve"])
        if key not in seen:
            seen.add(key)
            deduped.append(row)

    top5_raw = deduped[:5]

    results = []
    for rank_idx, row in enumerate(top5_raw, start=1):
        entry = RiskEntry(
            rank=rank_idx,
            **{k: v for k, v in row.items()}
        )
        results.append(entry)

    logger.info(f"Top-5 risks identified. Top score: {results[0].composite_score:.3f}")
    return results
