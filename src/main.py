"""
main.py — FastAPI backend for TawasolPay Cyber Risk Assistant.

Endpoints:
  GET /            → serve UI dashboard
  GET /api/risks   → return top-5 ranked risks as JSON
  GET /api/health  → liveness check
  GET /api/threat-report → return synthetic threat report markdown
  POST /api/report → generate markdown/plain-text board report
"""

import json
import logging
import os
import sys
from dataclasses import asdict
from pathlib import Path

from dotenv import load_dotenv

# Load .env before any other imports that check env vars
load_dotenv(Path(__file__).parent.parent / ".env")

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

# Ensure src/ is in path when running from project root
sys.path.insert(0, str(Path(__file__).parent))

from ingest import load_all
from risk_engine import rank_top5, RiskEntry
from rag_pipeline import retrieve_nist_control, is_indexed, build_index
from llm_synthesis import generate_explanation
from cisa_kev import get_kev_sets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="TawasolPay Cyber Risk Assistant",
    description="AI-powered risk prioritisation dashboard for CISO board briefings.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
STATIC_DIR = Path(__file__).parent.parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ── Cache ──────────────────────────────────────────────────────────────────
_cached_risks: list[RiskEntry] | None = None
_cache_built = False


def _ensure_rag_indexed():
    """Build RAG index if not already done."""
    nist_path = Path(os.getenv("DATA_DIR", "./data")) / "nist_800_53_controls.csv"
    if nist_path.exists() and not is_indexed():
        logger.info("Building NIST RAG index...")
        try:
            n = build_index(nist_path)
            logger.info(f"RAG index built: {n} controls")
        except Exception as e:
            logger.warning(f"RAG indexing failed: {e}")
    elif not nist_path.exists():
        logger.warning(
            "NIST CSV not found. Run setup.py to download. "
            "Falling back to built-in control summaries."
        )


def _build_risks() -> list[RiskEntry]:
    global _cached_risks, _cache_built
    if _cache_built and _cached_risks is not None:
        return _cached_risks

    logger.info("Loading datasets...")
    data = load_all()

    logger.info("Fetching CISA KEV catalog...")
    try:
        kev_cves, kev_ransomware_cves = get_kev_sets()
    except Exception as e:
        logger.warning(f"KEV fetch failed: {e}. Proceeding without KEV enrichment.")
        kev_cves, kev_ransomware_cves = set(), set()

    logger.info("Running risk scoring engine...")
    top5 = rank_top5(
        assets_df=data["assets"],
        vulns_df=data["vulnerabilities"],
        ti_df=data["threat_intel"],
        biz_df=data["business_services"],
        kev_cves=kev_cves,
        kev_ransomware_cves=kev_ransomware_cves,
    )

    _ensure_rag_indexed()

    logger.info("Retrieving NIST controls and generating explanations...")
    for risk in top5:
        # Build semantic query for RAG
        query = (
            f"Remediation for {risk.vulnerability_name} on {risk.asset_type}. "
            f"flaw remediation, patch management, vulnerability scanning, "
            f"{'ransomware incident handling' if risk.ransomware_linked else 'security control'}"
        )
        fallback_kw = [
            risk.vulnerability_name.lower(),
            risk.asset_type.lower(),
        ]

        nist = retrieve_nist_control(query, top_k=3, fallback_keywords=fallback_kw)
        risk.nist_control_id = nist["control_id"]
        risk.nist_control_title = nist["title"]
        risk.nist_control_text = nist["text"]

        # Find recommended action from remediation_guidance
        rem_df = data["remediation"]
        rem_match = None
        vuln_lower = risk.vulnerability_name.lower()
        for _, rem_row in rem_df.iterrows():
            finding_type_lower = str(rem_row["finding_type"]).lower()
            # Fuzzy keyword match
            keywords = finding_type_lower.replace("—", " ").split()
            if any(kw in vuln_lower for kw in keywords if len(kw) > 3):
                rem_match = rem_row
                break
        if rem_match is not None:
            risk.recommended_action = str(rem_match["recommended_action"])
        else:
            risk.recommended_action = "Apply available patches and review access controls."

        # Generate plain-English explanation
        risk.explanation = generate_explanation(risk, nist)

    _cached_risks = top5
    _cache_built = True
    logger.info("Risk pipeline complete.")
    return top5


@app.on_event("startup")
async def startup_event():
    """Pre-warm the pipeline in the background so it doesn't block port binding."""
    logger.info("Server starting — kicking off background pre-warm...")
    import asyncio
    try:
        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, _build_risks)
        logger.info("Background pipeline warm-up initiated.")
    except Exception as e:
        logger.error(f"Failed to initiate background warm-up: {e}")


@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    """Serve the main dashboard HTML."""
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="UI not found")
    return HTMLResponse(content=index_path.read_text(encoding="utf-8"))


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "TawasolPay Cyber Risk Assistant"}


@app.get("/api/risks")
async def get_risks():
    """Return top-5 ranked cyber risks as JSON."""
    from fastapi.responses import Response
    try:
        risks = _build_risks()
        payload = json.dumps(
            {"risks": [_serialize_risk(r) for r in risks]},
            default=_json_default
        )
        return Response(content=payload, media_type="application/json")
    except Exception as e:
        logger.exception("Error building risks")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/threat-report")
async def get_threat_report():
    """Return the synthetic MDR threat report as markdown."""
    report_path = Path(os.getenv("DATA_DIR", "./data")) / "synthetic_threat_report.md"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Threat report not found")
    return PlainTextResponse(content=report_path.read_text(encoding="utf-8"))


@app.post("/api/report")
async def generate_board_report():
    """Generate a full markdown board report from the top-5 risks."""
    try:
        risks = _build_risks()
        report = _build_markdown_report(risks)
        return PlainTextResponse(content=report, media_type="text/markdown")
    except Exception as e:
        logger.exception("Error generating report")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/refresh")
async def refresh_risks():
    """Force a re-computation of the risk pipeline (clears cache)."""
    global _cached_risks, _cache_built
    _cached_risks = None
    _cache_built = False
    try:
        risks = _build_risks()
        return JSONResponse(content={"message": "Risks refreshed", "count": len(risks)})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _json_default(obj):
    """JSON serializer for objects not serializable by default json module."""
    if hasattr(obj, "item"):  # numpy scalar (bool_, int64, float64, etc.)
        return obj.item()
    if hasattr(obj, "tolist"):  # numpy array
        return obj.tolist()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _serialize_risk(r: RiskEntry) -> dict:
    d = asdict(r)
    # Convert numpy types to Python native (pandas booleans come as numpy.bool_)
    def _fix(v):
        if hasattr(v, "item"):  # numpy scalar
            return v.item()
        if isinstance(v, dict):
            return {k: _fix(val) for k, val in v.items()}
        if isinstance(v, list):
            return [_fix(i) for i in v]
        return v
    d = {k: _fix(v) for k, v in d.items()}
    d["composite_score"] = round(r.composite_score, 3)
    return d


def _build_markdown_report(risks: list[RiskEntry]) -> str:
    lines = [
        "# TawasolPay — Cyber Risk Board Briefing",
        "",
        "**Classification: CONFIDENTIAL** | Generated by AI Cyber Risk Assistant",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "The following five vulnerabilities represent the highest-priority cyber risks to TawasolPay "
        "based on a composite scoring model weighting internet exposure, active exploitation, "
        "threat actor campaigns, ransomware association, and business criticality.",
        "",
        "---",
        "",
    ]

    for risk in risks:
        actors = ", ".join(risk.threat_actors) if risk.threat_actors else "No specific actor matched"
        campaigns = ", ".join(risk.campaign_names) if risk.campaign_names else "N/A"
        kev_badge = "✅ CISA KEV Listed" if risk.is_kev else "⚠️ Not in KEV"
        ransomware_badge = "🔴 RANSOMWARE LINKED" if risk.ransomware_linked else ""

        lines += [
            f"## Risk #{risk.rank}: {risk.vulnerability_name}",
            "",
            f"**Asset:** {risk.asset_name} ({risk.asset_type})  ",
            f"**CVE:** {risk.cve} | **CVSS:** {risk.cvss} | **Severity:** {risk.severity}  ",
            f"**Business Service:** {risk.business_service}  ",
            f"**Composite Risk Score:** {risk.composite_score:.3f} / 1.050  ",
            f"**Threat Actors:** {actors} (Campaign: {campaigns})  ",
            f"**Status:** {kev_badge} {ransomware_badge}  ",
            f"**Days Open:** {risk.days_open}  ",
            "",
            "### Business Impact",
            "",
            risk.explanation,
            "",
            "### Recommended Action",
            "",
            risk.recommended_action,
            "",
            f"### NIST SP 800-53 Control: {risk.nist_control_id} — {risk.nist_control_title}",
            "",
            f"> {risk.nist_control_text[:500]}...",
            "",
            "### Score Breakdown",
            "",
        ]

        breakdown = risk.score_breakdown
        lines += [
            f"| Factor | Score | Weight |",
            f"|--------|-------|--------|",
            f"| Internet Exposure | {breakdown.get('internet_exposure', 0):.2f} | 20% |",
            f"| Active Exploit | {breakdown.get('exploit_available', 0):.2f} | 20% |",
            f"| Threat Actor Match | {breakdown.get('threat_actor_match', 0):.2f} | 20% |",
            f"| Ransomware Association | {breakdown.get('ransomware', 0):.2f} | 15% |",
            f"| Business Criticality | {breakdown.get('business_criticality', 0):.2f} | 15% |",
            f"| Missing Controls | {breakdown.get('missing_controls', 0):.2f} | 10% |",
            f"| CVSS Tiebreaker | {breakdown.get('cvss_tiebreaker', 0):.4f} | — |",
            f"| **Total** | **{risk.composite_score:.4f}** | |",
            "",
            "---",
            "",
        ]

    lines += [
        "## System Limitations",
        "",
        "1. **CVE with no KEV entry**: Synthetic CVEs (CVE-SYN-*) will not match the CISA KEV catalog.",
        "2. **NIST control retrieval**: Semantic similarity may not always return the most precise control — keyword fallback is applied.",
        "3. **Temporal scoring**: `days_open` is not currently weighted — long-standing risks may be underweighted vs. fresh critical findings.",
        "",
        "---",
        "*Report generated by TawasolPay AI Cyber Risk Assistant — For internal use only.*",
    ]

    return "\n".join(lines)
