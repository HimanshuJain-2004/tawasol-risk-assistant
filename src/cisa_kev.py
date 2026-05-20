import json
import logging
import os
import time
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_PATH = Path(os.getenv("DATA_DIR", "./data")) / "kev_cache.json"
CACHE_TTL_SECONDS = 86400  # 24 hours


def _is_cache_fresh() -> bool:
    if not CACHE_PATH.exists():
        return False
    age = time.time() - CACHE_PATH.stat().st_mtime
    return age < CACHE_TTL_SECONDS


def fetch_kev() -> dict:
    if _is_cache_fresh():
        logger.info("Loading KEV catalog from local cache.")
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    logger.info("Fetching fresh KEV catalog from CISA...")
    try:
        resp = requests.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
        logger.info(f"KEV catalog fetched: {len(data.get('vulnerabilities', []))} entries.")
        return data
    except Exception as e:
        logger.warning(f"Failed to fetch KEV catalog: {e}. Trying local cache...")
        if CACHE_PATH.exists():
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        logger.error("No KEV cache available and network fetch failed.")
        return {"vulnerabilities": []}


def get_kev_sets() -> tuple[set[str], set[str]]:
    data = fetch_kev()
    vulns = data.get("vulnerabilities", [])

    kev_cves: set[str] = set()
    kev_ransomware_cves: set[str] = set()

    for v in vulns:
        cve_id = v.get("cveID", "").strip()
        if cve_id:
            kev_cves.add(cve_id)
            ransomware = v.get("knownRansomwareCampaignUse", "").strip().lower()
            if ransomware == "known":
                kev_ransomware_cves.add(cve_id)

    logger.info(
        f"KEV sets built: {len(kev_cves)} total CVEs, "
        f"{len(kev_ransomware_cves)} with ransomware association."
    )
    return kev_cves, kev_ransomware_cves
