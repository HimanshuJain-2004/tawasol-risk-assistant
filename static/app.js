/**
 * app.js — TawasolPay Cyber Risk Dashboard Frontend
 * Fetches risk data from FastAPI, renders rich cybersecurity cards.
 */

"use strict";

const API_BASE = "";  // same origin

// ── Clock ────────────────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById("clock").textContent =
    now.toLocaleTimeString("en-GB", { hour12: false }) + " " +
    now.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
}
setInterval(updateClock, 1000);
updateClock();

// ── Toast ────────────────────────────────────────────────────────────────
let toastTimer = null;
function showToast(msg, icon = "ℹ️") {
  const el = document.getElementById("toast");
  el.innerHTML = `<span>${icon}</span><span>${msg}</span>`;
  el.classList.add("show");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 3500);
}

// ── Utilities ────────────────────────────────────────────────────────────
function scoreToPercent(score) {
  // Max possible score ≈ 1.05 (with CVSS tiebreaker)
  return Math.min(100, (score / 1.05) * 100).toFixed(1);
}

function severityColor(severity) {
  const s = (severity || "").toLowerCase();
  if (s === "critical") return "red";
  if (s === "high")     return "orange";
  if (s === "medium")   return "yellow";
  return "green";
}

function assetIcon(assetType) {
  const t = (assetType || "").toLowerCase();
  if (t.includes("vpn"))        return "🔒";
  if (t.includes("api"))        return "⚡";
  if (t.includes("web"))        return "🌐";
  if (t.includes("database"))   return "🗄️";
  if (t.includes("kubernetes")) return "☸️";
  if (t.includes("build") || t.includes("jenkins")) return "🔧";
  if (t.includes("load"))       return "⚖️";
  if (t.includes("endpoint"))   return "💻";
  if (t.includes("mail"))       return "📧";
  if (t.includes("firewall"))   return "🛡️";
  return "🖥️";
}

function isSyntheticCVE(cve) {
  return /^(CVE-SYN|CTRL-SYN|CICD-SYN|K8S-SYN|CLOUD-SYN|CONTAINER-SYN|PHISH-SYN|SUPPLY-SYN|SOCIAL-SYN|SIM-SYN|CRED-SYN|INSIDER-SYN)/.test(cve);
}

// ── Render Risk Card ─────────────────────────────────────────────────────
function renderRiskCard(risk) {
  const pct = scoreToPercent(risk.composite_score);
  const severityCol = severityColor(risk.severity);
  const icon = assetIcon(risk.asset_type);
  const synthetic = isSyntheticCVE(risk.cve);

  // Badges
  let badges = "";
  if (risk.internet_exposed)  badges += `<span class="badge badge-red">🌐 Internet Exposed</span>`;
  if (risk.exploit_available) badges += `<span class="badge badge-orange">⚡ Active Exploit</span>`;
  if (risk.ransomware_linked) badges += `<span class="badge badge-red">🔴 Ransomware</span>`;
  if (risk.is_kev)            badges += `<span class="badge badge-yellow">📋 CISA KEV</span>`;

  risk.threat_actors.forEach(actor => {
    badges += `<span class="badge badge-purple">🎭 ${actor}</span>`;
  });

  if (!risk.edr_installed)   badges += `<span class="badge badge-gray">⚠️ No EDR</span>`;
  if (!risk.patch_available) badges += `<span class="badge badge-gray">⚠️ No Patch</span>`;
  if (synthetic)             badges += `<span class="badge badge-blue">🔬 Synthetic CVE</span>`;

  // Score breakdown bars
  const bd = risk.score_breakdown;
  const breakdownRows = [
    { label: "Internet Exposure",  key: "internet_exposure",   weight: "20%" },
    { label: "Active Exploit",     key: "exploit_available",   weight: "20%" },
    { label: "Threat Actor Match", key: "threat_actor_match",  weight: "20%" },
    { label: "Ransomware",         key: "ransomware",          weight: "15%" },
    { label: "Biz Criticality",   key: "business_criticality", weight: "15%" },
    { label: "Missing Controls",   key: "missing_controls",    weight: "10%" },
  ].map(r => `
    <div class="breakdown-row">
      <div class="breakdown-label">${r.label} <span style="color:var(--text-muted)">(${r.weight})</span></div>
      <div class="breakdown-bar-track">
        <div class="breakdown-bar-fill" style="width:${(bd[r.key] || 0)*100}%"></div>
      </div>
      <div class="breakdown-val">${((bd[r.key] || 0)).toFixed(2)}</div>
    </div>
  `).join("");

  const campaigns = risk.campaign_names.length > 0
    ? risk.campaign_names.join(", ")
    : "No campaign match";

  const nistText = risk.nist_control_text
    ? risk.nist_control_text.substring(0, 350) + (risk.nist_control_text.length > 350 ? "…" : "")
    : "See NIST SP 800-53 Rev. 5 for guidance.";

  const cardId = `card-${risk.vuln_id}`;
  const detailsId = `details-${risk.vuln_id}`;
  const expandBtnId = `expand-${risk.vuln_id}`;

  return `
  <article class="risk-card rank-${risk.rank}" id="${cardId}" tabindex="0" aria-label="Risk ${risk.rank}: ${risk.vulnerability_name}">
    <div class="card-header">
      <div class="rank-badge">#${risk.rank}</div>
      <div class="card-title-group">
        <div class="card-vuln-name">${escHtml(risk.vulnerability_name)}</div>
        <div class="card-asset">
          <span class="asset-icon">${icon}</span>
          <span>${escHtml(risk.asset_name)}</span>
          <span style="color:var(--text-muted)">·</span>
          <span style="color:var(--accent-cyan)">${escHtml(risk.business_service)}</span>
        </div>
      </div>
      <div class="card-score-group">
        <div class="score-value">${risk.composite_score.toFixed(3)}</div>
        <div class="score-label">RISK SCORE</div>
      </div>
    </div>

    <div class="score-bar-wrap">
      <div class="score-bar-track">
        <div class="score-bar-fill" style="width:0%" data-target="${pct}"></div>
      </div>
    </div>

    <div class="badges-row">${badges}</div>

    <div class="metrics-grid">
      <div class="metric-item">
        <div class="metric-label">CVE / ID</div>
        <div class="metric-value" style="font-size:0.75rem">${escHtml(risk.cve)}</div>
      </div>
      <div class="metric-item">
        <div class="metric-label">CVSS</div>
        <div class="metric-value ${severityCol}">${risk.cvss}</div>
      </div>
      <div class="metric-item">
        <div class="metric-label">Severity</div>
        <div class="metric-value ${severityCol}">${escHtml(risk.severity)}</div>
      </div>
      <div class="metric-item">
        <div class="metric-label">Days Open</div>
        <div class="metric-value ${risk.days_open > 90 ? 'red' : risk.days_open > 30 ? 'orange' : 'green'}">${risk.days_open}d</div>
      </div>
    </div>

    <button class="card-expand-btn" id="${expandBtnId}" onclick="toggleDetails('${detailsId}', '${expandBtnId}')">
      <span>▼</span>
      <span class="expand-icon" id="icon-${detailsId}">View Details</span>
    </button>

    <div class="card-details" id="${detailsId}">
      <hr class="details-divider" />

      <div class="explanation-box">
        <div class="explanation-label">🧠 Board-Level Explanation</div>
        <div class="explanation-text">${escHtml(risk.explanation || "Explanation not available.")}</div>
      </div>

      <div class="nist-box">
        <div class="nist-header">
          <div class="nist-label">📘 NIST SP 800-53 Rev.5 Control</div>
          <div class="nist-control-id">${escHtml(risk.nist_control_id)}</div>
        </div>
        <div class="nist-title">${escHtml(risk.nist_control_title)}</div>
        <div class="nist-text">${escHtml(nistText)}</div>
      </div>

      <div class="action-box">
        <div class="action-label">✅ Recommended Action</div>
        <div class="action-text">${escHtml(risk.recommended_action || "Apply available patches and review access controls.")}</div>
      </div>

      <div style="margin-bottom:0.75rem">
        <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);margin-bottom:10px">
          📊 Score Breakdown
        </div>
        <div class="breakdown-grid">
          ${breakdownRows}
        </div>
      </div>

      <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.5rem">
        Campaign: <span style="color:var(--text-secondary)">${escHtml(campaigns)}</span>
        &nbsp;·&nbsp; Environment: <span style="color:var(--text-secondary)">${escHtml(risk.environment)}</span>
        &nbsp;·&nbsp; Location: <span style="color:var(--text-secondary)">${escHtml(risk.location)}</span>
        &nbsp;·&nbsp; Data: <span style="color:var(--text-secondary)">${escHtml(risk.data_classification)}</span>
      </div>
    </div>
  </article>
  `;
}

function toggleDetails(detailsId, btnId) {
  const details = document.getElementById(detailsId);
  const icon = document.getElementById(`icon-${detailsId}`);
  const btn = document.getElementById(btnId);

  const isOpen = details.classList.contains("open");
  details.classList.toggle("open");
  if (isOpen) {
    btn.querySelector("span").textContent = "▼";
    icon.textContent = "View Details";
  } else {
    btn.querySelector("span").textContent = "▲";
    icon.textContent = "Hide Details";
    // Animate score bars
    setTimeout(() => animateBars(details), 50);
  }
}

function animateBars(container) {
  container.querySelectorAll(".breakdown-bar-fill").forEach(bar => {
    const target = parseFloat(bar.getAttribute("data-target") || bar.style.width) || 0;
    bar.style.width = bar.style.width || "0%";
  });
}

function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── Load Risks ────────────────────────────────────────────────────────────
async function loadRisks() {
  const container = document.getElementById("risks-container");
  container.innerHTML = `
    <div class="loading-state" id="loading">
      <div class="spinner"></div>
      <div class="loading-text">Analysing threat landscape…</div>
      <div class="loading-sub">Running risk scoring engine + NIST RAG retrieval</div>
    </div>`;

  try {
    const resp = await fetch(`${API_BASE}/api/risks`);
    if (!resp.ok) throw new Error(`Server error: ${resp.status}`);
    const data = await resp.json();
    const risks = data.risks || [];

    if (risks.length === 0) {
      container.innerHTML = `<div class="error-state">⚠️ No risks returned. Check data files and server logs.</div>`;
      return;
    }

    renderRisks(risks);
    updateStats(risks);
    updateCampaigns(risks);

  } catch (err) {
    console.error("Failed to load risks:", err);
    container.innerHTML = `
      <div class="error-state">
        <div style="font-size:2rem;margin-bottom:0.5rem">❌</div>
        <div style="font-weight:600;margin-bottom:0.5rem">Failed to load risk data</div>
        <div style="font-size:0.8rem;color:var(--text-muted)">${escHtml(err.message)}</div>
        <button onclick="loadRisks()" style="margin-top:1rem;padding:8px 16px;background:var(--accent-blue);border:none;border-radius:6px;color:white;cursor:pointer;">Retry</button>
      </div>`;
    showToast("Failed to load risks — check server", "❌");
  }
}

function renderRisks(risks) {
  const container = document.getElementById("risks-container");
  container.innerHTML = `<div class="risks-list">${risks.map(renderRiskCard).join("")}</div>`;

  // Animate score bars after render
  requestAnimationFrame(() => {
    document.querySelectorAll(".score-bar-fill[data-target]").forEach(bar => {
      const target = bar.getAttribute("data-target");
      setTimeout(() => { bar.style.width = target + "%"; }, 100);
    });
  });
}

function updateStats(risks) {
  document.getElementById("stat-critical").textContent =
    risks.filter(r => r.severity === "Critical").length;
  document.getElementById("stat-ransomware").textContent =
    risks.filter(r => r.ransomware_linked).length;
  document.getElementById("stat-internet").textContent =
    risks.filter(r => r.internet_exposed).length;
  document.getElementById("stat-kev").textContent =
    risks.filter(r => r.is_kev).length;
}

function updateCampaigns(risks) {
  const campaignList = document.getElementById("campaign-list");

  // Collect unique campaigns
  const seen = new Set();
  const campaigns = [];
  risks.forEach(r => {
    r.threat_actors.forEach((actor, i) => {
      const campaign = r.campaign_names[i] || "Unknown Campaign";
      const key = actor + campaign;
      if (!seen.has(key)) {
        seen.add(key);
        campaigns.push({ actor, campaign, ransomware: r.ransomware_linked });
      }
    });
  });

  if (campaigns.length === 0) {
    campaignList.innerHTML = `<div style="padding:8px;color:var(--text-muted);font-size:0.8rem;">No active campaigns matched in top risks.</div>`;
    return;
  }

  campaignList.innerHTML = campaigns.map(c => `
    <div class="campaign-item">
      <div class="campaign-actor">🎭 ${escHtml(c.actor)}</div>
      <div class="campaign-name">"${escHtml(c.campaign)}"</div>
      <div class="campaign-tags">
        ${c.ransomware ? `<span class="badge badge-red" style="font-size:0.68rem">🔴 Ransomware</span>` : ""}
        <span class="badge badge-blue" style="font-size:0.68rem">Active</span>
      </div>
    </div>
  `).join("");
}

// ── Load Threat Report ────────────────────────────────────────────────────
async function loadThreatReport() {
  try {
    const resp = await fetch(`${API_BASE}/api/threat-report`);
    if (!resp.ok) return;
    const text = await resp.text();
    // Extract executive overview paragraph
    const match = text.match(/## Executive Overview\s+([\s\S]*?)(?=---|\n##)/);
    if (match) {
      const summary = match[1].trim().replace(/\*\*([^*]+)\*\*/g, "$1").substring(0, 500);
      document.getElementById("threat-summary-text").textContent = summary + (summary.length >= 500 ? "…" : "");
    }
  } catch (e) {
    document.getElementById("threat-summary-text").textContent = "Unable to load threat report.";
  }
}

// ── Refresh ───────────────────────────────────────────────────────────────
async function refreshRisks() {
  const btn = document.getElementById("btn-refresh");
  btn.disabled = true;
  btn.textContent = "↻ Refreshing…";

  try {
    await fetch(`${API_BASE}/api/refresh`, { method: "POST" });
    showToast("Risks refreshed successfully", "✅");
    await loadRisks();
  } catch (e) {
    showToast("Refresh failed — see console", "❌");
  } finally {
    btn.disabled = false;
    btn.innerHTML = "<span>↻</span> Refresh";
  }
}

// ── Download Report ───────────────────────────────────────────────────────
async function downloadReport() {
  const btn = document.getElementById("btn-report");
  btn.disabled = true;
  btn.textContent = "⏳ Generating…";

  try {
    const resp = await fetch(`${API_BASE}/api/report`, { method: "POST" });
    if (!resp.ok) throw new Error("Report generation failed");
    const text = await resp.text();

    // Download as .md file
    const blob = new Blob([text], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `TawasolPay_Board_Risk_Report_${new Date().toISOString().slice(0,10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("Board report downloaded", "📄");
  } catch (e) {
    showToast("Report download failed", "❌");
  } finally {
    btn.disabled = false;
    btn.innerHTML = "📄 Export Board Report";
  }
}

// ── Init ──────────────────────────────────────────────────────────────────
(async function init() {
  await Promise.all([loadRisks(), loadThreatReport()]);
})();
