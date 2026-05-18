# TawasolPay AI-Powered Cyber Risk Assistant

> An AI-powered cyber risk prioritisation dashboard for CISO board briefings.  
> Composite risk scoring · NIST SP 800-53 RAG retrieval · Groq LLM synthesis · Dark-mode web UI

---

## Quick Start (Local)

```bash
# 1. Clone / enter the project directory
cd tawasol-risk-assistant

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env and set: GROQ_API_KEY=gsk_xxxxxxxxxxxx

# 4. Download NIST SP 800-53 CSV + build ChromaDB RAG index
python setup.py

# 5. Start the server
uvicorn src.main:app --reload

# 6. Open the dashboard
# → http://localhost:8000
```

---

## Architecture

```
assets.csv + vulnerabilities.csv + threat_intelligence.csv
+ business_services.csv + remediation_guidance.csv
        │
        ▼
Pandas Joins (exact-match structured queries)
        │
        ▼
Composite Risk Scoring Engine (6 weighted factors)
        │
        ▼
Top-5 Risks Selected
        │
        ├──► ChromaDB + sentence-transformers (RAG)
        │    NIST SP 800-53 Rev.5 controls → semantic retrieval
        │
        ├──► CISA KEV catalog (live fetch + cache)
        │    CVE cross-reference → active exploitation confirmation
        │
        ▼
Groq Llama-3 LLM → plain-English board explanation
        │
        ▼
FastAPI /api/risks → JSON → Dark-mode dashboard
```

---

## Risk Scoring Model

| Factor | Weight | Source |
|--------|--------|--------|
| Internet exposure | **20%** | `assets.csv → internet_exposed` |
| Active exploit available | **20%** | `vulnerabilities.csv → exploit_available` |
| Threat actor campaign match | **20%** | `threat_intelligence.csv` CVE join |
| Ransomware association | **15%** | `threat_intelligence.csv → ransomware_association` |
| Business service criticality | **15%** | `business_services.csv → business_impact + revenue_impact` |
| Missing compensating controls | **10%** | No EDR + No patch available |
| CVSS tiebreaker | **+5% max** | Used only to break ties |

**Why not CVSS-primary?** A CVSS 8 on an internet-exposed payment gateway with an active ransomware campaign correctly outranks a CVSS 10 on an isolated internal dev box. Business risk ≠ technical severity.

---

## Data Split: What Goes to RAG vs. Structured Query

### Embedded (RAG) — NIST SP 800-53
**Why RAG:** NIST control descriptions are long-form prose documents (300–2000 words per control). The question "what control covers flaw remediation for internet-facing assets?" has no exact-match answer in the text — it requires **semantic similarity search**. You can't `WHERE control_text = "patch management"`.

### Structured Query (Pandas) — All CSV Files
**Why Pandas:** Assets, vulnerabilities, threat intel, and business services have **exact typed fields** — CVE IDs, boolean flags, categorical values. Exact joins and filters are:
- More accurate (no false positives from semantic drift)
- Faster (microseconds vs. milliseconds)
- More explainable (auditable join logic)

Embedding a row like `{"cvss": 9.8, "internet_exposed": "Yes"}` into a vector would lose precision compared to `df[df.internet_exposed == True]`.

**CISA KEV** is also structured (exact CVE ID match) — fetched live and cached, not embedded.

---

## Known Failure Modes

### 1. CVE with No KEV Entry
If a real CVE ID in `vulnerabilities.csv` has no match in the CISA KEV catalog, the system will not flag it as actively exploited even if it is. **Mitigation:** Fall back to `exploit_available` field in `vulnerabilities.csv`; log a warning when a real CVE ID has no KEV match.

### 2. Synthetic CVE IDs Treated as Real
CVEs prefixed `CVE-SYN-`, `CTRL-SYN-`, etc. are synthetic and won't match KEV. **Mitigation:** The system detects these prefixes and explicitly labels them as "Synthetic CVE" in the UI output. They are not treated as confirmed KEV entries.

### 3. NIST Control Retrieval Mismatch
If the semantic query for a vulnerability doesn't match the best NIST control (e.g., a container escape mapping to AC-2 Account Management instead of CM-7 Least Functionality), the guidance will be technically correct but not optimal. **Mitigation:** A controlled vocabulary fallback maps vulnerability keywords directly to specific NIST control IDs when retrieval confidence may be low.

---

## One Improvement: Temporal Scoring Decay

Currently, `days_open` is not weighted in the composite score. A vulnerability open for 365 days (like A-1034's EOL Windows Server) scores identically to a fresh 5-day-old vulnerability with the same technical attributes.

**Proposed improvement:** Add an urgency multiplier that increases composite score logarithmically with age:

```python
import math
urgency_multiplier = 1 + (math.log1p(days_open) / math.log1p(365)) * 0.2
composite_score *= urgency_multiplier
```

This would differentiate "known but ignored" long-tail risks from fresh critical findings, improving prioritisation accuracy especially for EOL asset tracking.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard UI |
| GET | `/api/risks` | Top-5 risks as JSON |
| GET | `/api/health` | Liveness check |
| GET | `/api/threat-report` | MDR threat report (markdown) |
| POST | `/api/report` | Generate full board report (markdown download) |
| POST | `/api/refresh` | Force re-run of pipeline (clears cache) |

---

## Deploy to Render

1. Push this directory to a GitHub repository
2. Create a new **Web Service** on [Render](https://render.com)
3. Connect your GitHub repo
4. Render will auto-detect `render.yaml` and configure the service
5. In **Environment Variables**, add:
   - `GROQ_API_KEY` = `gsk_xxxxxxxxxxxxxxxxxxxx`
6. Deploy — your dashboard will be live at `https://tawasol-risk-assistant.onrender.com`

> **Note:** Free tier Render instances spin down after inactivity. First request after sleep may take 30–60 seconds.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| Backend | FastAPI + uvicorn |
| Frontend | Vanilla HTML/CSS/JS |
| Data | Pandas |
| Vector Store | ChromaDB (local persistent) |
| Embeddings | sentence-transformers/all-MiniLM-L6-v2 |
| LLM | Groq API (Llama-3.1-8b-instant) |
| NIST Data | NIST CSRC CSV download |
| CISA KEV | CISA official JSON feed (cached) |
| Deployment | Render (Docker or Python runtime) |

---

*TawasolPay AI Cyber Risk Assistant — Synthetic data, for assessment purposes only.*
