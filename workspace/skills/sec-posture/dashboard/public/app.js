// sec-posture live dashboard client. No frameworks — Chart.js (vendored) + SSE.

const DOMAIN_SHORT = ["Secrets", "Credentials", "File Perms", "Access & Config", "Incident Readiness"];
const TIER = { green: "#2fbf71", amber: "#f5a524", red: "#ef4444" };
const SEV_RANK = { crit: 0, warn: 1, info: 2 };
const SEV_LABEL = { crit: "🔴 Crit", warn: "🟡 Warn", info: "🟢 Info" };

function tierOf(score) {
  return score >= 90 ? "green" : score >= 70 ? "amber" : "red";
}
function gradeOf(overall) {
  return overall >= 90 ? "A" : overall >= 80 ? "B" : overall >= 70 ? "C" : overall >= 60 ? "D" : "F";
}
function hexToRgba(hex, alpha) {
  const n = parseInt(hex.slice(1), 16);
  const r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
  return `rgba(${r},${g},${b},${alpha})`;
}
// interpolate a fill color that shifts green -> amber -> red as `overall` drops
function overallFillHex(overall) {
  const mix = (hexA, hexB, t) => {
    const pa = parseInt(hexA.slice(1), 16), pb = parseInt(hexB.slice(1), 16);
    const ar = (pa >> 16) & 255, ag = (pa >> 8) & 255, ab = pa & 255;
    const br = (pb >> 16) & 255, bg = (pb >> 8) & 255, bb = pb & 255;
    const r = Math.round(ar + (br - ar) * t), g = Math.round(ag + (bg - ag) * t), bch = Math.round(ab + (bb - ab) * t);
    return `#${[r, g, bch].map((x) => x.toString(16).padStart(2, "0")).join("")}`;
  };
  if (overall >= 90) return TIER.green;
  if (overall >= 70) return mix(TIER.amber, TIER.green, (overall - 70) / 20);
  return mix(TIER.red, TIER.amber, Math.max(0, overall) / 70);
}

let chart = null;
let trendChart = null;
let latestPosture = null;
let latestHistory = null;
let currentFixes = [];
let recentAutoFixes = []; // session-only; durable record lives in memory/YYYY-MM-DD.md
const analystCache = new Map(); // findingKey -> rationale text (avoid re-calling Cooper on re-expand)

function ensureChart(scores) {
  const ctx = document.getElementById("radar").getContext("2d");
  const overall = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);

  chart = new Chart(ctx, {
    type: "radar",
    data: {
      labels: DOMAIN_SHORT,
      datasets: [
        {
          label: "Domain score",
          data: scores,
          pointBackgroundColor: scores.map((s) => TIER[tierOf(s)]),
          pointBorderColor: scores.map((s) => TIER[tierOf(s)]),
          pointRadius: 5,
          pointHoverRadius: 7,
          borderWidth: 2,
          segment: {
            borderColor: (segCtx) => {
              const s = scores[segCtx.p1DataIndex];
              return TIER[tierOf(s)];
            },
          },
          backgroundColor: (barCtx) => {
            const area = barCtx.chart.chartArea;
            if (!area) return hexToRgba(overallFillHex(overall), 0.18);
            const c = barCtx.chart.ctx;
            const cx = (area.left + area.right) / 2;
            const cy = (area.top + area.bottom) / 2;
            const r = Math.max(area.right - area.left, area.bottom - area.top) / 2;
            const grad = c.createRadialGradient(cx, cy, 0, cx, cy, r);
            const base = overallFillHex(overall);
            grad.addColorStop(0, hexToRgba(base, 0.06));
            grad.addColorStop(1, hexToRgba(base, 0.38));
            return grad;
          },
        },
      ],
    },
    options: {
      responsive: true,
      animation: { duration: 600, easing: "easeOutQuart" },
      plugins: { legend: { display: false }, tooltip: { callbacks: {
        label: (item) => ` ${item.formattedValue}/100`,
      } } },
      scales: {
        r: {
          min: 0,
          max: 100,
          ticks: { stepSize: 20, color: "#8a97a8", backdropColor: "transparent", font: { size: 10 } },
          grid: { color: "rgba(138,151,168,0.18)" },
          angleLines: { color: "rgba(138,151,168,0.25)" },
          pointLabels: { color: "#e8edf3", font: { size: 12, weight: "600" } },
        },
      },
    },
  });
}

function updateChart(scores) {
  const overall = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  if (!chart) return ensureChart(scores);
  const ds = chart.data.datasets[0];
  ds.data = scores;
  ds.pointBackgroundColor = scores.map((s) => TIER[tierOf(s)]);
  ds.pointBorderColor = scores.map((s) => TIER[tierOf(s)]);
  chart.update(); // scriptable backgroundColor/segment re-evaluate against the new `overall`
  void overall;
}

function fmtWhen(iso) {
  return new Date(iso).toLocaleString("en-US", {
    timeZone: "America/Chicago",
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short",
  });
}
function relTime(iso) {
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

function topFinding(domain) {
  if (!domain.findings.length) return null;
  return [...domain.findings].sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity])[0];
}

// ---------------------------------------------------------------------------
// Trend line — overall score across every scan that has a JSON snapshot
// ---------------------------------------------------------------------------

function renderTrend(history) {
  const canvas = document.getElementById("trend");
  const placeholder = document.getElementById("trend-placeholder");
  if (!history || history.length < 2) {
    canvas.classList.add("hidden");
    placeholder.classList.remove("hidden");
    return;
  }
  canvas.classList.remove("hidden");
  placeholder.classList.add("hidden");

  const labels = history.map((h) =>
    new Date(h.generatedAt).toLocaleString("en-US", {
      timeZone: "America/Chicago",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }),
  );
  const scores = history.map((h) => h.overall);
  const colors = scores.map((s) => TIER[tierOf(s)]);

  if (!trendChart) {
    trendChart = new Chart(canvas.getContext("2d"), {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Overall score",
            data: scores,
            borderColor: "#3fb1e5",
            backgroundColor: "rgba(63,177,229,0.12)",
            pointBackgroundColor: colors,
            pointBorderColor: colors,
            pointRadius: 4,
            pointHoverRadius: 6,
            tension: 0.25,
            fill: true,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 500 },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: (item) => ` ${item.formattedValue}/100` } },
        },
        scales: {
          x: {
            ticks: { color: "#8a97a8", font: { size: 10 }, maxRotation: 0, autoSkip: true },
            grid: { color: "rgba(138,151,168,0.1)" },
          },
          y: {
            min: 0,
            max: 100,
            ticks: { stepSize: 25, color: "#8a97a8", font: { size: 10 } },
            grid: { color: "rgba(138,151,168,0.1)" },
          },
        },
      },
    });
  } else {
    trendChart.data.labels = labels;
    trendChart.data.datasets[0].data = scores;
    trendChart.data.datasets[0].pointBackgroundColor = colors;
    trendChart.data.datasets[0].pointBorderColor = colors;
    trendChart.update();
  }
}

// ---------------------------------------------------------------------------
// Diff since last scan — compares the last two history entries' findings
// ---------------------------------------------------------------------------

function findingKey(f) {
  return `${f.severity}::${f.title}::${f.source}`;
}

function computeDeltas(history) {
  if (!history || history.length < 2) return null;
  const curr = history[history.length - 1];
  const prev = history[history.length - 2];
  return curr.domains.map((d, i) => {
    const p = prev.domains[i];
    const delta = d.score - p.score;
    if (delta === 0) return { name: d.name, delta: 0, reason: null };

    const prevKeys = new Set(p.findings.map(findingKey));
    const currKeys = new Set(d.findings.map(findingKey));
    const appeared = d.findings.filter((f) => !prevKeys.has(findingKey(f)));
    const resolved = p.findings.filter((f) => !currKeys.has(findingKey(f)));

    let reason;
    if (appeared.length && resolved.length) {
      reason = `new: ${appeared[0].title} · resolved: ${resolved[0].title}`;
    } else if (appeared.length) {
      reason = `new finding: ${appeared[0].title} (${appeared[0].source})`;
    } else if (resolved.length) {
      reason = `resolved: ${resolved[0].title} (was ${resolved[0].source})`;
    } else {
      reason = "scoring changed (no finding-level cause detected)";
    }
    return { name: d.name, delta, reason };
  });
}

function renderDomainChips(posture, deltas) {
  const chipsEl = document.getElementById("domain-chips");
  chipsEl.innerHTML = posture.domains
    .map((d, i) => {
      const dd = deltas ? deltas[i] : null;
      let deltaHtml = "";
      if (dd && dd.delta !== 0) {
        const up = dd.delta > 0;
        deltaHtml = `<span class="delta ${up ? "up" : "down"}">${up ? "▲" : "▼"}${Math.abs(dd.delta)}</span>`;
      }
      return `<div class="chip"><span class="chip-name">${escapeHtml(DOMAIN_SHORT[i])}</span><span class="chip-score">${d.score}</span>${deltaHtml}</div>`;
    })
    .join("");

  const sinceEl = document.getElementById("since-last");
  if (!deltas) {
    sinceEl.innerHTML = ""; // no prior scan — omit cleanly, no "N/A" clutter
    return;
  }
  const changed = deltas.filter((d) => d.delta !== 0);
  sinceEl.innerHTML = changed.length
    ? changed
        .map((d) => {
          const up = d.delta > 0;
          return `<div class="row"><b class="${up ? "up" : "down"}">${up ? "▲" : "▼"}${Math.abs(d.delta)}</b> ${escapeHtml(d.name)} — ${escapeHtml(d.reason)}</div>`;
        })
        .join("")
    : `<div class="none">No change since last scan.</div>`;
}

function loadHistory() {
  fetch("/api/history")
    .then((r) => (r.ok ? r.json() : []))
    .then((history) => {
      latestHistory = history;
      renderTrend(history);
      if (latestPosture) renderDomainChips(latestPosture, computeDeltas(history));
    })
    .catch(() => {});
}

// ---------------------------------------------------------------------------
// Remediation queue — display + copy-to-clipboard only, never executes
// ---------------------------------------------------------------------------

function renderRemediation(posture) {
  const el = document.getElementById("remediation-list");
  currentFixes = posture.domains
    .flatMap((d) => d.findings.filter((f) => f.fix).map((f) => ({ domain: d.name, severity: f.severity, ...f.fix })))
    .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);

  el.innerHTML = currentFixes.length
    ? currentFixes
        .map((f, i) => {
          const tierClass = f.tier === "auto-safe" ? "auto-safe" : f.severity;
          const tierLabel = f.tier === "auto-safe" ? "AUTO-SAFE" : "CONFIRM-REQUIRED";
          return `<div class="remediation-card ${tierClass}">
        <div class="rc-head">
          <h4>${escapeHtml(f.title)} <span class="tier-pill ${f.tier}">${tierLabel}</span></h4>
          <span class="rc-domain">${escapeHtml(f.domain)}</span>
        </div>
        <div class="risk">Risk: ${escapeHtml(f.risk)}</div>
        <div class="risk">Why this tier: ${escapeHtml(f.tierReason)}</div>
        <pre>${escapeHtml(f.command)}</pre>
        <div class="rc-actions">
          <button class="copy-btn" data-idx="${i}" type="button">${f.guided ? "Copy guidance" : "Copy command"}</button>
          ${
            f.tier === "auto-safe"
              ? `<span class="risk">Applied automatically on scan — see "Recently Auto-Fixed" above once it runs.</span>`
              : `<button class="confirm-btn" data-idx="${i}" type="button">Confirm &amp; Apply in chat</button>`
          }
        </div>
      </div>`;
        })
        .join("")
    : `<div class="none">Nothing to remediate right now.</div>`;
}

document.getElementById("remediation-list").addEventListener("click", async (e) => {
  const copyBtn = e.target.closest(".copy-btn");
  const confirmBtn = e.target.closest(".confirm-btn");

  if (copyBtn) {
    const fix = currentFixes[Number(copyBtn.dataset.idx)];
    if (!fix) return;
    const original = copyBtn.textContent;
    try {
      await navigator.clipboard.writeText(fix.command);
      copyBtn.textContent = "Copied!";
      copyBtn.classList.add("copied");
    } catch {
      copyBtn.textContent = "Copy failed";
    }
    setTimeout(() => {
      copyBtn.textContent = original;
      copyBtn.classList.remove("copied");
    }, 1500);
  }

  if (confirmBtn) {
    const idx = Number(confirmBtn.dataset.idx);
    chatInput.value = `apply fix ${idx + 1}`;
    chatInput.focus();
    document.querySelector(".chat-panel").scrollIntoView({ behavior: "smooth", block: "start" });
  }
});

// ---------------------------------------------------------------------------
// Recently Auto-Fixed — populated from SSE "remediation" events (session-only;
// the durable record is the memory/YYYY-MM-DD.md entry the Remediation Agent
// wrote before this event was ever broadcast).
// ---------------------------------------------------------------------------

function renderAutoFixPanel() {
  const panel = document.getElementById("autofix-panel");
  const list = document.getElementById("autofix-list");
  if (!recentAutoFixes.length) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  list.innerHTML = recentAutoFixes
    .map(
      (r) => `<div class="autofix-card">
        <div class="af-head">
          <h4>${escapeHtml(r.title)} <span class="af-badge">✓ Fixed automatically</span></h4>
          <span class="af-time">${escapeHtml(r.time)}</span>
        </div>
        <div class="af-diff">Before: ${escapeHtml(String(r.before))} → After: ${escapeHtml(String(r.after))}${r.noop ? " (already compliant)" : ""}</div>
        <div class="af-log">Logged to ${escapeHtml(r.logPath ?? "memory/")}</div>
      </div>`,
    )
    .join("");
}

function render(posture) {
  latestPosture = posture;
  const scores = posture.domains.map((d) => d.score);
  const overall = posture.overall;

  document.getElementById("hdr-host").textContent = posture.host;
  document.getElementById("hdr-overall").textContent = overall;
  document.getElementById("hdr-grade").textContent = posture.grade ?? gradeOf(overall);
  const bubble = document.getElementById("hdr-gradebubble");
  bubble.className = "gradebubble " + tierOf(overall);
  document.getElementById("hdr-lastscan").dataset.iso = posture.generatedAt;
  tickLastScanned();

  updateChart(scores);
  renderDomainChips(posture, computeDeltas(latestHistory));
  renderRemediation(posture);

  // Areas of concern
  const concernsEl = document.getElementById("concerns");
  const concerns = posture.domains.filter((d) => d.score < 90).sort((a, b) => a.score - b.score);
  if (!concerns.length) {
    concernsEl.innerHTML = `<div class="all-clear">All 5 domains ≥ 90. Nothing below the "strong" tier right now.</div>`;
  } else {
    concernsEl.innerHTML = concerns
      .map((d) => {
        const tf = topFinding(d);
        const band = tierOf(d.score);
        return `<div class="concern-card ${band}">
          <h3>${d.name} <span class="pill">${d.score}/100</span></h3>
          ${tf ? `<div class="finding">${escapeHtml(tf.title)}</div><div class="source">${escapeHtml(tf.source)}</div>`
               : `<div class="finding">No specific finding recorded.</div>`}
        </div>`;
      })
      .join("");
  }

  // Findings table
  const rows = posture.domains
    .flatMap((d) => d.findings.map((f) => ({ ...f, domainName: d.name })))
    .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
  const tbody = document.getElementById("findings-body");
  tbody.innerHTML = rows.length
    ? rows
        .map((f) => {
          const key = findingKey(f);
          return `<tr class="finding-row">
        <td class="sev ${f.severity}">${SEV_LABEL[f.severity]}</td>
        <td>${escapeHtml(f.domainName)}</td>
        <td>${escapeHtml(f.title)}</td>
        <td><code>${escapeHtml(f.source)}</code></td>
        <td><code>${escapeHtml(f.evidence)}</code></td>
        <td><button class="trace-toggle" data-key="${escapeHtml(key)}" type="button">▸ Trace</button></td>
      </tr>
      <tr class="trace-detail" data-key-detail="${escapeHtml(key)}">
        <td colspan="6">${renderTraceStages(f)}</td>
      </tr>`;
        })
        .join("")
    : `<tr><td colspan="6" style="text-align:center;color:var(--muted)">No findings — every domain clean.</td></tr>`;
}

// ---------------------------------------------------------------------------
// Agent Trace — Scanner (instant) -> Analyst (lazy, real Cooper call) ->
// Remediation Agent (instant, hardcoded tier decision). "Show your work."
// ---------------------------------------------------------------------------

function renderTraceStages(f) {
  const tierHtml = f.fix
    ? `<span class="tier-pill ${f.fix.tier}">${f.fix.tier === "auto-safe" ? "AUTO-SAFE" : "CONFIRM-REQUIRED"}</span>`
    : `<span class="tier-pill confirm-required" style="background:transparent;color:var(--muted)">no fix</span>`;
  return `<div class="trace">
    <div class="trace-stage">
      <b>1 · Scanner found</b>
      <div class="body">${escapeHtml(f.title)} — ${escapeHtml(f.detail)}<br><code>${escapeHtml(f.source)}</code> · <code>${escapeHtml(f.evidence)}</code></div>
    </div>
    <div class="trace-stage" data-analyst-for="${escapeHtml(findingKey(f))}">
      <b>2 · Analyst assessed</b>
      <div class="body analyst-loading">Not yet loaded — expand to ask Cooper for a rationale.</div>
    </div>
    <div class="trace-stage">
      <b>3 · Remediation Agent decided ${tierHtml}</b>
      <div class="body">${f.fix ? escapeHtml(f.fix.tierReason) : "No actionable fix for this finding — nothing for the Remediation Agent to classify."}</div>
    </div>
  </div>`;
}

document.getElementById("findings-body").addEventListener("click", async (e) => {
  const btn = e.target.closest(".trace-toggle");
  if (!btn) return;
  const key = btn.dataset.key;
  const detailRow = document.querySelector(`.trace-detail[data-key-detail="${CSS.escape(key)}"]`);
  if (!detailRow) return;

  const nowOpen = !detailRow.classList.contains("open");
  detailRow.classList.toggle("open", nowOpen);
  btn.classList.toggle("open", nowOpen);
  btn.textContent = nowOpen ? "▾ Trace" : "▸ Trace";
  if (!nowOpen) return;

  if (analystCache.has(key)) {
    setAnalystBody(key, analystCache.get(key));
    return;
  }
  setAnalystBody(key, null, true); // loading state

  try {
    const r = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ findingKey: key }),
    });
    const body = await r.json();
    if (!r.ok) {
      const msg = `Analyst call failed: ${body.error ?? "unknown error"}`;
      analystCache.set(key, msg);
      setAnalystBody(key, msg);
      return;
    }
    analystCache.set(key, body.rationale);
    setAnalystBody(key, body.rationale);
  } catch (err) {
    const msg = `Network error reaching the Analyst Agent: ${String(err)}`;
    analystCache.set(key, msg);
    setAnalystBody(key, msg);
  }
});

function setAnalystBody(key, text, loading = false) {
  const stage = document.querySelector(`[data-analyst-for="${CSS.escape(key)}"] .body`);
  if (!stage) return;
  if (loading) {
    stage.className = "body analyst-loading";
    stage.textContent = "Cooper is reasoning about this finding…";
  } else {
    stage.className = "body";
    stage.textContent = text;
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function tickLastScanned() {
  const el = document.getElementById("hdr-lastscan");
  const iso = el.dataset.iso;
  if (!iso) return;
  el.textContent = `Last scanned: ${fmtWhen(iso)} (${relTime(iso)})`;
}
setInterval(tickLastScanned, 1000);

// ---------------------------------------------------------------------------
// SSE — live posture + scan lifecycle
// ---------------------------------------------------------------------------

function connectEvents() {
  const dot = document.getElementById("hdr-connection");
  const es = new EventSource("/api/events");
  es.onopen = () => { dot.classList.remove("down"); };
  es.onerror = () => { dot.classList.add("down"); };
  es.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);
    if (msg.type === "posture") {
      render(msg.data);
      loadHistory(); // a new scan may have just landed a fresh reports/*.json snapshot
    } else if (msg.type === "remediation") {
      const time = new Date().toLocaleTimeString("en-US", { timeZone: "America/Chicago", hour: "2-digit", minute: "2-digit", second: "2-digit" });
      for (const r of msg.applied) {
        recentAutoFixes.unshift({
          title: r.title,
          domain: r.domain,
          before: r.before,
          after: r.after,
          noop: !!r.noop,
          logPath: r.logPath,
          time,
        });
      }
      renderAutoFixPanel();
    } else if (msg.type === "scan-status") {
      const overlay = document.getElementById("chart-loading");
      const btn = document.getElementById("btn-scan");
      if (msg.status === "running") {
        overlay.classList.remove("hidden");
        btn.disabled = true;
        btn.textContent = "Scanning…";
      } else {
        overlay.classList.add("hidden");
        btn.disabled = false;
        btn.textContent = "Run New Scan";
        if (msg.status === "error") alert(`Scan failed: ${msg.message}`);
      }
    }
  };
}
connectEvents();

document.getElementById("btn-scan").addEventListener("click", async () => {
  try {
    const r = await fetch("/api/scan", { method: "POST" });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      alert(`Could not start scan: ${body.error ?? r.statusText}`);
    }
  } catch (e) {
    alert(`Could not reach the dashboard server: ${e}`);
  }
});

// ---------------------------------------------------------------------------
// Chat -> real Cooper agent
// ---------------------------------------------------------------------------

const chatLog = document.getElementById("chat-log");
const chatForm = document.getElementById("chat-form");
const chatInput = document.getElementById("chat-input");

function addMsg(cls, html) {
  const div = document.createElement("div");
  div.className = `chat-msg ${cls}`;
  div.innerHTML = html;
  chatLog.appendChild(div);
  chatLog.scrollTop = chatLog.scrollHeight;
  return div;
}

chatForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const message = chatInput.value.trim();
  if (!message) return;
  chatInput.value = "";
  chatInput.disabled = true;
  chatForm.querySelector("button").disabled = true;

  addMsg("user", escapeHtml(message));
  const thinking = addMsg("thinking", "Cooper is thinking…");

  try {
    const r = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });
    const body = await r.json();
    thinking.remove();
    if (!r.ok) {
      addMsg(
        "error",
        `Cooper couldn't respond.\n${escapeHtml(body.error ?? "unknown error")}` +
          (body.detail ? `\n${escapeHtml(body.detail)}` : ""),
      );
    } else {
      let html = escapeHtml(body.reply);
      if (body.groundedFix) {
        html += `<span class="tag">grounded in Remediation Queue item "${escapeHtml(body.groundedFix.title)}" (${escapeHtml(body.groundedFix.tier)}) · session ${escapeHtml(body.sessionId ?? "")} · ${body.durationMs}ms</span>`;
      } else if (body.groundedDomain) {
        html += `<span class="tag">grounded in a fresh scan of ${escapeHtml(body.groundedDomain)} (${body.groundedScore}/100) · session ${escapeHtml(body.sessionId ?? "")} · ${body.durationMs}ms</span>`;
      } else if (body.sessionId) {
        html += `<span class="tag">session ${escapeHtml(body.sessionId)} · ${body.durationMs}ms</span>`;
      }
      addMsg("assistant", html);
    }
  } catch (err) {
    thinking.remove();
    addMsg("error", `Network error reaching the dashboard server: ${escapeHtml(String(err))}`);
  } finally {
    chatInput.disabled = false;
    chatForm.querySelector("button").disabled = false;
    chatInput.focus();
  }
});

// Initial paint from a plain fetch, in case SSE hasn't delivered yet.
fetch("/api/posture")
  .then((r) => (r.ok ? r.json() : null))
  .then((data) => { if (data) render(data); })
  .catch(() => {});
loadHistory();
