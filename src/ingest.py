"""
ingest.py — Load and validate all CSV datasets for TawasolPay Risk Assistant.
Returns clean, typed DataFrames ready for the risk engine.
"""

import os
import logging
import pandas as pd
from pathlib import Path

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))


def _load_csv(filename: str, required_cols: list[str]) -> pd.DataFrame:
    """Load a CSV file and validate required columns exist."""
    path = DATA_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Required data file not found: {path}")
    df = pd.read_csv(path, encoding="utf-8")
    df.columns = df.columns.str.strip()
    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        raise ValueError(f"{filename} is missing columns: {missing}")
    logger.info(f"Loaded {filename}: {len(df)} rows")
    return df


def load_assets() -> pd.DataFrame:
    df = _load_csv("assets.csv", [
        "asset_id", "asset_name", "asset_type", "environment",
        "internet_exposed", "criticality", "edr_installed",
        "business_service", "data_classification", "location"
    ])
    df["internet_exposed"] = df["internet_exposed"].str.strip().str.lower().eq("yes")
    df["edr_installed"] = df["edr_installed"].str.strip().str.lower().eq("yes")
    return df


def load_vulnerabilities() -> pd.DataFrame:
    df = _load_csv("vulnerabilities.csv", [
        "vuln_id", "asset_id", "vulnerability_name", "cve",
        "severity", "cvss", "exploit_available", "patch_available",
        "days_open", "status"
    ])
    df["exploit_available"] = df["exploit_available"].str.strip().str.lower().eq("yes")
    df["patch_available"] = df["patch_available"].str.strip().str.lower().eq("yes")
    df["cvss"] = pd.to_numeric(df["cvss"], errors="coerce").fillna(0.0)
    df["days_open"] = pd.to_numeric(df["days_open"], errors="coerce").fillna(0)
    # Only open vulnerabilities
    df = df[df["status"].str.lower() == "open"].copy()
    return df


def load_threat_intelligence() -> pd.DataFrame:
    df = _load_csv("threat_intelligence.csv", [
        "intel_id", "threat_actor", "campaign_name",
        "matched_cve_or_control", "ransomware_association", "confidence"
    ])
    df["ransomware_association"] = df["ransomware_association"].str.strip().str.lower().eq("yes")
    return df


def load_business_services() -> pd.DataFrame:
    df = _load_csv("business_services.csv", [
        "business_service", "business_impact", "revenue_impact",
        "customer_facing", "compliance_scope", "rto_hours"
    ])
    return df


def load_remediation_guidance() -> pd.DataFrame:
    df = _load_csv("remediation_guidance.csv", [
        "finding_type", "recommended_action", "priority_hint"
    ])
    return df


def load_all() -> dict[str, pd.DataFrame]:
    """Load all datasets and return as a dict."""
    return {
        "assets": load_assets(),
        "vulnerabilities": load_vulnerabilities(),
        "threat_intel": load_threat_intelligence(),
        "business_services": load_business_services(),
        "remediation": load_remediation_guidance(),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    data = load_all()
    for name, df in data.items():
        print(f"{name}: {df.shape}")
