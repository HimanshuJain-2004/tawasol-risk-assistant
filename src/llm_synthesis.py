import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from risk_engine import RiskEntry

logger = logging.getLogger(__name__)

GROQ_MODEL = "llama-3.1-8b-instant"

_groq_client = None


def _get_groq_client():
    global _groq_client
    if _groq_client is None:
        api_key = os.getenv("GROQ_API_KEY", "")
        if not api_key or api_key.startswith("gsk_your"):
            raise ValueError("GROQ_API_KEY not set or is placeholder")
        from groq import Groq
        _groq_client = Groq(api_key=api_key)
    return _groq_client


def _llm_enabled() -> bool:
    use_llm = os.getenv("USE_LLM", "true").lower() == "true"
    api_key = os.getenv("GROQ_API_KEY", "")
    return use_llm and bool(api_key) and not api_key.startswith("gsk_your")


def _build_prompt(risk, nist_text: str) -> str:
    actors = ", ".join(risk.threat_actors) if risk.threat_actors else "Unknown"
    campaigns = ", ".join(risk.campaign_names) if risk.campaign_names else "N/A"
    kev_note = (
        "This CVE is listed in the CISA Known Exploited Vulnerabilities catalog — confirming it is actively exploited."
        if risk.is_kev else
        "This CVE is not currently in the CISA KEV catalog."
    )
    syn_note = " (synthetic/scenario CVE — used for assessment purposes)" \
        if any(x in risk.cve for x in ("SYN", "CTRL", "CICD", "K8S", "CLOUD", "CONTAINER", "PHISH", "SUPPLY")) \
        else ""

    return f"""You are a senior cybersecurity analyst writing a CISO board briefing for TawasolPay, a fintech payments company.

Write a concise, professional 3-4 sentence explanation of the following cyber risk. Use plain English for a board audience — no jargon, no bullet points. Focus on business impact and financial/reputational risk, not technical details.

RISK CONTEXT:
- Asset: {risk.asset_name} ({risk.asset_type})
- Vulnerability: {risk.vulnerability_name}
- CVE: {risk.cve}{syn_note}
- CVSS Score: {risk.cvss} / 10.0
- Business Service at Risk: {risk.business_service}
- Internet Exposed: {"Yes — directly reachable from the internet" if risk.internet_exposed else "No — internal asset"}
- Active Exploit: {"Yes — exploits are publicly available" if risk.exploit_available else "No"}
- Threat Actors: {actors} (Campaign: {campaigns})
- Ransomware Linked: {"Yes — ransomware groups are actively using this" if risk.ransomware_linked else "No"}
- Data Classification: {risk.data_classification}
- Days Open: {risk.days_open} days unpatched
- {kev_note}

RELEVANT NIST SP 800-53 REV 5 CONTROL:
{nist_text[:600]}

Write the board-level explanation now (3-4 sentences, plain English, no headers, no bullet points):"""


def _template_explanation(risk) -> str:
    actor_str = f"Threat actor {risk.threat_actors[0]}" if risk.threat_actors else "An active threat actor"
    ransomware_str = " — a ransomware-associated campaign" if risk.ransomware_linked else ""
    kev_str = (
        " This vulnerability appears on the CISA Known Exploited Vulnerabilities list, confirming active exploitation in the wild."
        if risk.is_kev else ""
    )
    days_str = f" The vulnerability has been open for {risk.days_open} days without remediation." if risk.days_open > 0 else ""
    internet_str = ", which is directly accessible from the internet," if risk.internet_exposed else ""

    return (
        f"The {risk.vulnerability_name} vulnerability (CVSS {risk.cvss}) on {risk.asset_name}{internet_str} "
        f"poses a critical risk to the {risk.business_service} business service. "
        f"{actor_str} is actively exploiting this weakness{ransomware_str}.{kev_str}{days_str} "
        f"Immediate remediation is required to prevent potential compromise of {risk.data_classification} data."
    ).strip()


def generate_explanation(risk, nist_control: dict) -> str:
    if not _llm_enabled():
        logger.info(f"Using template explanation for {risk.vuln_id} (LLM disabled or no key).")
        return _template_explanation(risk)

    nist_text = nist_control.get("text", "")
    prompt = _build_prompt(risk, nist_text)

    try:
        client = _get_groq_client()
        chat = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.25,
            max_tokens=320,
        )
        explanation = chat.choices[0].message.content.strip()
        logger.info(f"✅ LLM (Groq) explanation generated for {risk.vuln_id}")
        return explanation
    except Exception as e:
        logger.warning(f"Groq API call failed for {risk.vuln_id}: {e}. Falling back to template.")
        return _template_explanation(risk)
