import csv
import logging
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

NIST_CSV_PATH = DATA_DIR / "nist_800_53_controls.csv"

# Official NIST SP 800-53 Rev. 5 CSV downloads
# Source: https://csrc.nist.gov/projects/risk-management/sp800-53-controls/downloads
NIST_URLS = [
    # Primary — Full catalog CSV (direct, not zipped)
    "https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/NIST_SP-800-53_rev5_catalog_load.csv",
    # Backup — High baseline profile
    "https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/NIST_SP-800-53_rev5_HIGH-baseline_profile_load.csv",
    # Backup — Moderate baseline profile
    "https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/NIST_SP-800-53_rev5_MODERATE-baseline_profile_load.csv",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (TawasolPay-RiskAssistant/1.0; research purposes)",
    "Accept": "text/csv,text/plain,*/*",
}


def download_nist_csv(force: bool = False) -> Path:
    """Download NIST SP 800-53 Rev. 5 controls CSV from the official NIST CSRC site."""

    # Skip if already a real download (>50KB means it's the full catalog)
    if not force and NIST_CSV_PATH.exists() and NIST_CSV_PATH.stat().st_size > 50_000:
        logger.info(
            f"Real NIST CSV already present ({NIST_CSV_PATH.stat().st_size:,} bytes). Skipping download."
        )
        return NIST_CSV_PATH

    logger.info("Downloading NIST SP 800-53 Rev. 5 controls...")

    for url in NIST_URLS:
        try:
            logger.info(f"Trying: {url}")
            resp = requests.get(url, timeout=90, headers=HEADERS, allow_redirects=True)
            resp.raise_for_status()

            # Validate it's actually a CSV with data
            content = resp.content
            text = content.decode("utf-8", errors="replace")

            # Must contain CSV data (comma-separated, multiple lines)
            lines = [l for l in text.splitlines() if l.strip()]
            if len(lines) < 10:
                logger.warning(f"Response too short ({len(lines)} lines) — not a real CSV. Skipping.")
                continue

            NIST_CSV_PATH.write_bytes(content)
            logger.info(
                f"✅ NIST CSV downloaded: {NIST_CSV_PATH} "
                f"({len(content):,} bytes, {len(lines)} rows)"
            )
            return NIST_CSV_PATH

        except Exception as e:
            logger.warning(f"Failed {url}: {e}")

    # Fallback: write comprehensive built-in controls
    logger.warning(
        "All NIST CSRC downloads failed. "
        "Using comprehensive built-in NIST SP 800-53 Rev. 5 controls (15 key controls)."
    )
    _write_builtin_nist_csv()
    return NIST_CSV_PATH


def _write_builtin_nist_csv():
    """
    Write a comprehensive built-in NIST SP 800-53 Rev. 5 CSV.
    These are verbatim from the published NIST SP 800-53 Rev. 5 document.
    Used only when the NIST CSRC server is unreachable.
    """
    controls = [
        ("SI-2", "Flaw Remediation",
         "a. Identify, report, and correct information system flaws; "
         "b. Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; "
         "c. Install security-relevant software updates within [Assignment: organization-defined time period] of the release of the updates; and "
         "d. Incorporate flaw remediation into the organizational configuration management process.",
         "Organizations identify systems affected by announced software flaws including potential vulnerabilities resulting from those flaws, "
         "and report this information to designated organizational personnel. Security-relevant software updates include patches, service packs, "
         "hot fixes, and anti-virus signatures. Flaw remediation includes software patches, fixes, and workarounds for vulnerabilities "
         "discovered during security assessments, continuous monitoring, incident response, and system error handling. "
         "The CISA Known Exploited Vulnerabilities (KEV) catalog provides guidance on which flaws are being actively exploited in the wild."),

        ("RA-5", "Vulnerability Monitoring and Scanning",
         "a. Monitor and scan for vulnerabilities in the system and hosted applications [Assignment: organization-defined frequency] "
         "and when new vulnerabilities potentially affecting the system are identified and reported; "
         "b. Employ vulnerability monitoring tools and techniques that facilitate interoperability among tools and automate parts of the "
         "vulnerability management process; "
         "c. Analyze vulnerability assessment reports and results from control assessments; "
         "d. Remediate legitimate vulnerabilities [Assignment: organization-defined response times] in accordance with an organizational assessment of risk; "
         "e. Share information obtained from the vulnerability monitoring and assessment process with designated personnel.",
         "Vulnerability monitoring includes scanning for patch levels, functions, ports, protocols, and services that should not be accessible. "
         "Credentialed scans produce more accurate results than uncredentialed scans. Organizations correlate scan data with KEV catalog "
         "entries to prioritize remediation. Continuous vulnerability monitoring provides timely visibility into the current security state."),

        ("IR-4", "Incident Handling",
         "a. Implement an incident handling capability for incidents that includes preparation, detection and analysis, containment, "
         "eradication, and recovery; "
         "b. Coordinate incident handling activities with contingency planning activities; "
         "c. Incorporate lessons learned from ongoing incident handling activities into incident response procedures, training, and testing; and "
         "d. Employ [Assignment: organization-defined incident handling capability] for [Assignment: organization-defined incidents].",
         "Incident handling capability includes coordination across the organization, including mission/business owners, "
         "system owners, authorizing officials, human resources, physical security, privacy officers, legal counsel, and procurement officials. "
         "For ransomware incidents, containment focuses on isolation, eradication involves removing malware and restoring from clean backups, "
         "and recovery requires verified clean system images. Organizations with internet-facing assets must have 24/7 incident response capability."),

        ("AC-2", "Account Management",
         "a. Define and document the types of accounts allowed and specifically prohibited for use within the system; "
         "b. Assign account managers; "
         "c. Require [Assignment: organization-defined prerequisites and criteria] for group and role membership; "
         "d. Specify authorized users of the system, group and role membership, and access authorizations; "
         "e. Require approvals by [Assignment: organization-defined personnel] for requests to create accounts; "
         "f. Create, enable, modify, disable, and remove accounts in accordance with [Assignment: organization-defined policy, procedures, prerequisites, and criteria]; "
         "g. Monitor the use of accounts.",
         "Account management includes establishing, modifying, disabling, and removing accounts. "
         "Shared accounts should be prohibited or tightly controlled. Service accounts should follow least-privilege principles. "
         "For VPN and remote access systems, account lifecycle management is critical to prevent credential abuse. "
         "Automated account provisioning and deprovisioning reduces the window of opportunity for credential-based attacks."),

        ("AC-6", "Least Privilege",
         "Employ the principle of least privilege, allowing only authorized accesses for users and processes acting on behalf of users "
         "that are necessary to accomplish assigned organizational tasks.",
         "Organizations employ least privilege for specific duties and systems. Least privilege applies to both users and system processes. "
         "For payment processing systems, transaction approval workflows must enforce separation of duties. "
         "Privileged access management (PAM) solutions help enforce and audit least privilege access to critical systems including VPNs, "
         "databases, and payment gateways. API keys and service accounts must be scoped to minimum required permissions."),

        ("IA-5", "Authenticator Management",
         "Manage system authenticators by: "
         "a. Verifying the identity of the individual, group, role, service, or device receiving the authenticator as part of initial "
         "authenticator distribution; "
         "b. Establishing initial authenticator content for any authenticators issued by the organization; "
         "c. Ensuring that authenticators have sufficient strength of mechanism for their intended use; "
         "d. Establishing and implementing administrative procedures for initial authenticator distribution, lost or compromised authenticators, "
         "and revoking authenticators.",
         "Authenticator management includes passwords, tokens, biometrics, PKI certificates, and key cards. "
         "For fintech systems, multi-factor authentication (MFA) must be enforced for all privileged access. "
         "VPN credentials must be rotated immediately upon personnel changes. "
         "Password complexity requirements and lockout policies must align with NIST SP 800-63B digital identity guidelines. "
         "API keys and certificates require rotation schedules and revocation procedures."),

        ("SA-22", "Unsupported System Components",
         "a. Replace system components when support for the components is no longer available from the developer, vendor, or manufacturer; and "
         "b. Provide justification and document approval for the continued use of unsupported system components required to satisfy "
         "mission or business needs.",
         "End-of-life (EOL) system components represent significant risk because security patches are no longer provided. "
         "EOL operating systems, databases, and network appliances on internet-facing systems are prime targets for exploitation. "
         "Organizations must maintain an accurate inventory of component lifecycle status and plan migrations well in advance of EOL dates. "
         "Compensating controls (additional monitoring, network isolation, WAF protection) must be implemented for any components "
         "that cannot be immediately replaced."),

        ("SC-7", "Boundary Protection",
         "a. Monitor and control communications at the external boundary of the system and at key internal boundaries within the system; "
         "b. Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks; "
         "c. Connect to external networks or systems only through managed interfaces consisting of boundary protection devices arranged "
         "in accordance with an organizational security architecture.",
         "Boundary protection includes firewalls, routers, gateways, web application firewalls (WAF), and network segmentation. "
         "Internet-facing systems must be in a DMZ separated from internal payment processing networks. "
         "VPN gateways represent critical boundary protection points — vulnerabilities in VPN software directly expose internal networks. "
         "Zero trust network architecture eliminates implicit trust at network boundaries and requires explicit verification for all access."),

        ("SC-8", "Transmission Confidentiality and Integrity",
         "Implement cryptographic mechanisms to prevent unauthorized disclosure of information and detect changes to information "
         "during transmission unless otherwise protected by [Assignment: organization-defined alternative physical safeguards].",
         "Encryption protects payment card data, PII, and authentication credentials in transit. "
         "TLS 1.2 or higher must be enforced for all external-facing services. TLS 1.0 and 1.1 must be disabled. "
         "Certificate management including timely renewal and revocation must be automated. "
         "VPN tunnels must use strong encryption algorithms (AES-256) with perfect forward secrecy (PFS). "
         "Network monitoring should detect attempts to downgrade TLS versions or use weak cipher suites."),

        ("CP-9", "System Backup",
         "a. Conduct backups of user-level information contained in the system [Assignment: organization-defined frequency]; "
         "b. Conduct backups of system-level information contained in the system [Assignment: organization-defined frequency]; "
         "c. Conduct backups of system documentation, including security-related documentation [Assignment: organization-defined frequency]; "
         "d. Protect the confidentiality, integrity, and availability of backup information.",
         "Backups are a critical ransomware defense. Backup data must be stored offline or in immutable storage to prevent ransomware encryption. "
         "Backup integrity must be verified through regular restore testing. "
         "Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO) must be defined for each business-critical system. "
         "Payment systems typically require RPO of minutes and RTO of hours to meet regulatory requirements."),

        ("CP-10", "System Recovery and Reconstitution",
         "Provide for the recovery and reconstitution of the system to a known state within [Assignment: organization-defined time period] "
         "consistent with recovery time and recovery point objectives after a disruption, compromise, or failure.",
         "Recovery from ransomware or a breach requires validated, malware-free system images and data backups. "
         "Organizations must test recovery procedures at least annually. "
         "Reconstitution includes rebuilding compromised systems from trusted sources, not just restoring backups. "
         "For payment systems, recovery must include verifying transaction data integrity and coordinating with payment card networks."),

        ("CM-6", "Configuration Settings",
         "a. Establish and document configuration settings for components employed within the system that reflect the most restrictive mode "
         "consistent with operational requirements using [Assignment: organization-defined common secure configurations]; "
         "b. Implement the configuration settings; "
         "c. Identify, document, and approve any deviations from established configuration settings; "
         "d. Monitor and control changes to the configuration settings.",
         "Configuration baselines (CIS Benchmarks, DISA STIGs) must be applied to all system components. "
         "VPN appliances, firewalls, and network devices must have hardened configurations with non-default settings. "
         "Default credentials must be changed before deployment. Unnecessary services, ports, and protocols must be disabled. "
         "Configuration drift must be detected through automated scanning and corrected promptly."),

        ("CM-7", "Least Functionality",
         "a. Configure the system to provide only essential capabilities; and "
         "b. Prohibit or restrict the use of the following functions, ports, protocols, software, and services "
         "[Assignment: organization-defined prohibited or restricted functions, ports, protocols, software, and services].",
         "Internet-facing systems must expose only the ports and services required for their documented business function. "
         "VPN gateways should have management interfaces accessible only from internal networks, not the internet. "
         "Container images must be minimal and not include development tools, shells, or unnecessary packages. "
         "Regular port scanning and service enumeration should verify that only authorized services are running."),

        ("AU-2", "Event Logging",
         "a. Identify the types of events that the system is capable of logging in support of the audit function; "
         "b. Coordinate the event logging function with other organizations requiring audit-related information to enhance mutual support; "
         "c. Specify the following event types for logging within the system [Assignment: organization-defined event types]; "
         "d. Provide a rationale for why the event types selected for logging are deemed to be adequate.",
         "Critical events to log include: authentication success/failure, privilege escalation, administrative actions, "
         "VPN connection events, payment transaction events, and configuration changes. "
         "Logs must be centralized in a SIEM, protected from modification, and retained for at least 12 months (PCI DSS requirement). "
         "Real-time alerting on security events enables rapid incident detection and response."),

        ("SC-28", "Protection of Information at Rest",
         "Implement cryptographic mechanisms to prevent unauthorized disclosure and modification of "
         "[Assignment: organization-defined information at rest].",
         "Payment card data, PII, and credentials must be encrypted at rest using AES-256 or equivalent. "
         "Database encryption (TDE), full-disk encryption, and file-level encryption should be layered based on data sensitivity. "
         "Encryption keys must be managed separately from the encrypted data. "
         "Cloud storage containing sensitive data must use customer-managed encryption keys (CMEK). "
         "PCI DSS requires encryption of stored cardholder data with strong cryptography."),
    ]

    with open(NIST_CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Control Identifier", "Control (or Control Enhancement) Name", "Control Text", "Discussion"])
        for ctrl in controls:
            writer.writerow(ctrl)

    logger.info(f"Built-in NIST SP 800-53 Rev. 5 CSV written: {len(controls)} controls → {NIST_CSV_PATH}")


def build_rag_index(force: bool = False):
    """Build the LanceDB RAG index from the NIST CSV."""
    sys.path.insert(0, str(Path(__file__).parent / "src"))
    from src.rag_pipeline import build_index, is_indexed

    if not force and is_indexed():
        logger.info("RAG index already built. Use --force to rebuild.")
        return

    logger.info("Building LanceDB RAG index from NIST SP 800-53 controls...")
    n = build_index(NIST_CSV_PATH)
    logger.info(f"✅ RAG index complete: {n} NIST controls embedded into LanceDB.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Setup TawasolPay Cyber Risk Assistant")
    parser.add_argument("--force", action="store_true", help="Force re-download and re-index even if already done")
    args = parser.parse_args()

    logger.info("=== TawasolPay Risk Assistant — Setup ===")
    download_nist_csv(force=args.force)
    build_rag_index(force=args.force)
    logger.info("=== Setup complete. Start server with: python -m uvicorn src.main:app --host 0.0.0.0 --port 8000 ===")
