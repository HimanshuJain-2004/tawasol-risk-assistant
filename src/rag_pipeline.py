"""
rag_pipeline.py — LanceDB + sentence-transformers RAG for NIST SP 800-53 Rev. 5.

Embeds NIST control descriptions into a persistent local vector store.
For each risk, retrieves the most semantically relevant NIST control.

Key design decision:
  - NIST 800-53 prose descriptions → RAG (semantic similarity needed)
  - CSV/structured data (assets, vulns, threat intel) → pandas (exact match faster)

Uses LanceDB (pure Python, no C++ required) as the vector store.
"""

import csv
import logging
import os
import numpy as np
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

LANCEDB_DIR = Path(os.getenv("CHROMA_DIR", "./chroma_db"))  # reuse config key for compatibility
TABLE_NAME = "nist_800_53_rev5"
NIST_CSV_PATH = Path(os.getenv("DATA_DIR", "./data")) / "nist_800_53_controls.csv"

# Controlled vocabulary fallback: map vulnerability keywords → NIST control IDs
FALLBACK_CONTROLS = {
    "patch":          "SI-2",
    "flaw":           "SI-2",
    "vulnerability":  "RA-5",
    "scan":           "RA-5",
    "exploit":        "SI-2",
    "ransomware":     "IR-4",
    "incident":       "IR-4",
    "authentication": "IA-5",
    "credential":     "IA-5",
    "access":         "AC-2",
    "account":        "AC-2",
    "vpn":            "SC-8",
    "encryption":     "SC-28",
    "backup":         "CP-9",
    "recovery":       "CP-10",
    "eol":            "SA-22",
    "end-of-life":    "SA-22",
    "unsupported":    "SA-22",
    "container":      "CM-7",
    "configuration":  "CM-6",
    "privilege":      "AC-6",
    "firewall":       "SC-7",
    "network":        "SC-7",
    "logging":        "AU-2",
    "audit":          "AU-2",
}

_embed_model = None
_lancedb_conn = None
_table = None


def _get_embed_model():
    global _embed_model
    if _embed_model is None:
        from sentence_transformers import SentenceTransformer
        logger.info("Loading sentence-transformers model (all-MiniLM-L6-v2)...")
        _embed_model = SentenceTransformer("all-MiniLM-L6-v2")
    return _embed_model


def _get_db():
    global _lancedb_conn
    if _lancedb_conn is None:
        import lancedb
        LANCEDB_DIR.mkdir(parents=True, exist_ok=True)
        _lancedb_conn = lancedb.connect(str(LANCEDB_DIR))
    return _lancedb_conn


def is_indexed() -> bool:
    """Check if the NIST table already has documents."""
    try:
        db = _get_db()
        tbl = db.open_table(TABLE_NAME)
        count = tbl.count_rows()
        logger.info(f"NIST LanceDB table exists with {count} documents.")
        return count > 0
    except Exception:
        return False


def build_index(nist_csv_path: Optional[Path] = None) -> int:
    """
    Read NIST 800-53 CSV and embed all controls into LanceDB.
    Returns number of documents embedded.
    """
    csv_path = nist_csv_path or NIST_CSV_PATH
    if not csv_path.exists():
        raise FileNotFoundError(
            f"NIST CSV not found at {csv_path}. "
            "Run setup.py first to download NIST SP 800-53 Rev. 5."
        )

    model = _get_embed_model()
    db = _get_db()

    # Parse CSV
    records = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            control_id = (
                row.get("Control Identifier") or
                row.get("control_id") or
                row.get("identifier") or
                row.get("ID") or ""
            ).strip()
            title = (
                row.get("Control (or Control Enhancement) Name") or
                row.get("title") or
                row.get("name") or
                row.get("Name") or ""
            ).strip()
            discussion = (
                row.get("Discussion") or
                row.get("discussion") or
                row.get("description") or
                row.get("Supplemental Guidance") or ""
            ).strip()
            statement = (
                row.get("Control Text") or
                row.get("control_text") or
                row.get("statement") or
                row.get("Control") or ""
            ).strip()

            if not control_id:
                continue

            text = f"Control {control_id}: {title}\n{statement}\n{discussion}".strip()
            if len(text) < 20:
                continue

            records.append({
                "control_id": control_id,
                "title": title,
                "text": text,
                "statement": statement[:500],
            })

    if not records:
        raise ValueError("No NIST controls parsed from CSV. Check column format.")

    logger.info(f"Embedding {len(records)} NIST controls...")
    texts = [r["text"] for r in records]

    # Batch embedding
    batch_size = 64
    all_embeddings = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i+batch_size]
        embs = model.encode(batch, show_progress_bar=False)
        all_embeddings.extend(embs.tolist())
        logger.info(f"Embedded {min(i+batch_size, len(texts))}/{len(texts)} controls")

    # Build LanceDB records
    import pyarrow as pa
    lance_records = []
    for rec, emb in zip(records, all_embeddings):
        lance_records.append({
            "control_id": rec["control_id"],
            "title": rec["title"],
            "text": rec["text"],
            "statement": rec["statement"],
            "vector": emb,
        })

    # Create or overwrite table
    try:
        db.drop_table(TABLE_NAME)
    except Exception:
        pass

    global _table
    _table = db.create_table(TABLE_NAME, data=lance_records)
    logger.info(f"NIST LanceDB index built: {len(lance_records)} controls embedded.")
    return len(lance_records)


def _get_table():
    global _table
    if _table is None:
        db = _get_db()
        try:
            _table = db.open_table(TABLE_NAME)
        except Exception as e:
            raise RuntimeError(
                f"NIST table not found. Run setup.py first. Error: {e}"
            )
    return _table


def retrieve_nist_control(
    query: str,
    top_k: int = 3,
    fallback_keywords: Optional[list[str]] = None,
) -> dict:
    """
    Retrieve the most relevant NIST SP 800-53 control for a given query string.

    Returns dict with keys: control_id, title, text
    Falls back to controlled vocabulary if retrieval fails.
    """
    try:
        model = _get_embed_model()
        query_vec = model.encode([query])[0].tolist()
        tbl = _get_table()
        results = tbl.search(query_vec).limit(top_k).to_list()

        if results:
            best = results[0]
            return {
                "control_id": best.get("control_id", "Unknown"),
                "title": best.get("title", ""),
                "text": best.get("text", ""),
            }
    except Exception as e:
        logger.warning(f"RAG retrieval failed: {e}. Using fallback.")

    return _fallback_control(fallback_keywords or [query.lower()])


def _fallback_control(keywords: list[str]) -> dict:
    """Return a fallback NIST control based on keyword matching."""
    text_lower = " ".join(keywords).lower()
    for keyword, control_id in FALLBACK_CONTROLS.items():
        if keyword in text_lower:
            return {
                "control_id": control_id,
                "title": _NIST_TITLES.get(control_id, "Security Control"),
                "text": _NIST_SUMMARIES.get(control_id, "See NIST SP 800-53 Rev. 5 for full guidance."),
            }
    return {
        "control_id": "SI-2",
        "title": "Flaw Remediation",
        "text": _NIST_SUMMARIES["SI-2"],
    }


# Built-in summaries (used when RAG not available or as part of retrieval)
_NIST_TITLES = {
    "SI-2":  "Flaw Remediation",
    "RA-5":  "Vulnerability Monitoring and Scanning",
    "IR-4":  "Incident Handling",
    "AC-2":  "Account Management",
    "AC-6":  "Least Privilege",
    "IA-5":  "Authenticator Management",
    "SA-22": "Unsupported System Components",
    "SC-7":  "Boundary Protection",
    "SC-8":  "Transmission Confidentiality and Integrity",
    "SC-28": "Protection of Information at Rest",
    "CP-9":  "System Backup",
    "CP-10": "System Recovery and Reconstitution",
    "CM-6":  "Configuration Settings",
    "CM-7":  "Least Functionality",
    "AU-2":  "Event Logging",
}

_NIST_SUMMARIES = {
    "SI-2": (
        "SI-2 Flaw Remediation: The organization identifies, reports, and corrects system flaws; "
        "tests software updates for effectiveness and potential side effects before installation; "
        "and installs security-relevant software updates within organizationally defined time periods. "
        "Automated mechanisms may be used to determine the state of system components with regard to flaw remediation."
    ),
    "RA-5": (
        "RA-5 Vulnerability Monitoring and Scanning: The organization scans for vulnerabilities in the "
        "system and hosted applications at defined frequencies; employs vulnerability scanning tools and "
        "techniques that facilitate interoperability; analyzes vulnerability scan reports; remediates "
        "legitimate vulnerabilities within defined response times; shares information obtained from the "
        "vulnerability scanning process with designated personnel."
    ),
    "IR-4": (
        "IR-4 Incident Handling: The organization implements an incident handling capability that includes "
        "preparation, detection and analysis, containment, eradication, and recovery; coordinates incident "
        "handling activities; and incorporates lessons learned from ongoing incident handling activities."
    ),
    "AC-2": (
        "AC-2 Account Management: The organization manages system accounts, including establishing, "
        "activating, modifying, reviewing, disabling, and removing accounts; requires approvals for "
        "account requests; monitors accounts for atypical use; and notifies account managers when "
        "accounts are no longer required."
    ),
    "AC-6": (
        "AC-6 Least Privilege: The organization employs the principle of least privilege, allowing only "
        "authorized accesses for users and processes which are necessary to accomplish assigned tasks. "
        "Authorizes access to systems based on a valid access authorization."
    ),
    "IA-5": (
        "IA-5 Authenticator Management: The organization manages system authenticators by verifying the "
        "identity of the individual receiving the authenticator; establishing administrative procedures "
        "for initial authenticator distribution; requiring users to change authenticators; and protecting "
        "authenticator content from unauthorized disclosure and modification."
    ),
    "SA-22": (
        "SA-22 Unsupported System Components: The organization replaces system components when support "
        "for the components is no longer available from the developer, vendor, or manufacturer; and "
        "provides justification and documents approval for the continued use of unsupported system "
        "components required to satisfy mission/business needs."
    ),
    "SC-7": (
        "SC-7 Boundary Protection: The system monitors and controls communications at the external "
        "boundary of the system and at key internal boundaries; implements subnetworks for publicly "
        "accessible system components that are physically or logically separated from internal networks; "
        "and connects to external networks or systems only through managed interfaces."
    ),
    "SC-8": (
        "SC-8 Transmission Confidentiality and Integrity: The system implements cryptographic mechanisms "
        "to prevent unauthorized disclosure of information during transmission unless otherwise protected "
        "by alternative physical safeguards."
    ),
    "SC-28": (
        "SC-28 Protection of Information at Rest: The system implements cryptographic mechanisms to prevent "
        "unauthorized disclosure and modification of information at rest unless otherwise protected by "
        "alternative physical safeguards."
    ),
    "CP-9": (
        "CP-9 System Backup: The organization conducts backups of user-level information, system-level "
        "information, and system documentation; protects the confidentiality, integrity, and availability "
        "of backup information; and tests backup information periodically to verify media reliability."
    ),
    "CP-10": (
        "CP-10 System Recovery and Reconstitution: The organization provides for the recovery and "
        "reconstitution of the system to a known state after a disruption, compromise, or failure; "
        "and implements transaction recovery for systems that are transaction-based."
    ),
    "CM-6": (
        "CM-6 Configuration Settings: The organization establishes and documents configuration settings "
        "for information technology products employed within the system that reflect the most restrictive "
        "mode consistent with operational requirements; implements the configuration settings; identifies, "
        "documents, and approves any deviations from established configuration settings."
    ),
    "CM-7": (
        "CM-7 Least Functionality: The organization configures the system to provide only essential "
        "capabilities; prohibits or restricts the use of functions, ports, protocols, and services "
        "not required to fulfill mission/business functions; reviews the system periodically to identify "
        "and eliminate unnecessary functions, ports, protocols, and services."
    ),
    "AU-2": (
        "AU-2 Event Logging: The organization identifies the types of events that the system is capable "
        "of logging in support of the audit function; coordinates the event logging function with other "
        "organizations; and provides a rationale for why the event types selected for logging are deemed "
        "to be adequate to support after-the-fact investigations of security incidents."
    ),
}
