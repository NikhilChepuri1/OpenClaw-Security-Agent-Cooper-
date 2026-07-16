#!/usr/bin/env node
/**
 * sec-posture Analyst Agent eval suite.
 *
 * Calls the REAL /api/analyze endpoint on the running sec-posture dashboard
 * server (real openclaw agent call — Cooper, not a mock) for each hand-
 * authored case in cases.json, classifies the Analyst's actual verdict from
 * its free-text rationale, and scores it against the expected label.
 *
 * Each case gets its own fresh session key (sec-posture-eval-<runId>-<caseId>)
 * so cases can't anchor on each other's judgments, and so none of this ever
 * lands in the real, ongoing "sec-posture-dashboard" conversation Nikhil
 * actually reads. Findings are sent inline ({ domain, finding }) — this
 * suite never reads or writes the live posture.json, so a scan this suite
 * didn't run can never end up on someone's open dashboard tab.
 *
 * Honesty rule: if a call errors or times out, that case is recorded as
 * ERROR with the real error detail — never backfilled with a plausible-
 * looking rationale. Accuracy is computed over scored cases only, and the
 * error count is always reported alongside it, never hidden in the average.
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CASES_PATH = join(__dirname, "cases.json");
const REPORT_HTML_PATH = join(__dirname, "eval-report.html");

const PORT = Number(process.env.SEC_POSTURE_PORT ?? 18790);
const BASE_URL = `http://127.0.0.1:${PORT}`;
const CONCURRENCY = 4; // keeps 10 cases well under the 2-minute target
const CASE_TIMEOUT_MS = 120_000;

const VALID_VERDICTS = ["real-risk", "false-positive", "borderline"];

// ---------------------------------------------------------------------------
// Verdict classifier — parses the Analyst's free-text rationale into one of
// VALID_VERDICTS (or "unclear" if none of the signals fire). This is a
// heuristic, not a certainty: the full rationale text is always kept in the
// results file and printed in the table specifically so a human can
// override this classification by reading what Cooper actually said,
// instead of trusting the heuristic blindly.
// ---------------------------------------------------------------------------
function classifyVerdict(rationale) {
  const t = rationale.toLowerCase();

  // Caught by manual review of the first real run (2026-07-16): naive
  // substring matching on "false positive" fires even when the text reads
  // "NOT a false positive" — the exact opposite signal. Strip any negated
  // occurrence before running the false-positive check at all, and treat
  // "under-scored" as an explicit real-risk signal (it means the Analyst
  // thinks the finding deserves a HIGHER severity, the opposite of a false
  // positive) so it can't be shadowed by an unrelated later match.
  const negatedFpPattern = /\b(not|isn'?t|is not)\b[\s\w]{0,20}false positive/;
  const tWithoutNegatedFp = t.replace(negatedFpPattern, "");

  const falsePositiveSignals = [
    "false positive", "not a real risk", "not a real threat", "over-scored",
    "overscored", "over scored", "downgrade", "isn't a real risk",
    "isn't actually a risk", "is not a real risk", "no real risk",
    "not actually a risk", "not actually sensitive", "safe to close",
    "no action needed", "not a credential", "not a secret",
    "isn't a credential", "isn't a secret", "not sensitive",
  ];
  // Hedged/nuanced language that weighs both sides without necessarily
  // using the word "borderline" — e.g. "X is defensible ... but I'd bump
  // it", "plausibly under/over-scored". Caught by manual review: a real
  // borderline-shaped rationale ("info is defensible on a single-user Mac,
  // but ... I'd bump this") scored "unclear" under the original list
  // because it never used the word "borderline" itself.
  const borderlineSignals = [
    "borderline", "reasonable people could disagree",
    "reasonable analysts could disagree", "reasonable reviewers",
    "reasonable analysts", "could go either way", "genuinely context-dependent",
    "context-dependent", "judgment call", "could be argued either way",
    "case for both", "lean either way", "split", "toss-up",
    "plausibly under-scored", "plausibly over-scored",
    "plausibly under scored", "plausibly over scored", "worth debating",
    "arguable", "i'd bump this", "i would bump this",
  ];
  const agreeSignals = [
    "agreed", "agree —", "agree -", "agree,", "agree.", "hold it",
    "correct call", "no downgrade", "severity is right", "severity is correct",
    "is the right call", "is warranted", "rightly flagged", "correctly flagged",
    "hold the severity", "keep it at", "warrants the", "under-scored",
    "under scored", "not a false positive", "isn't a false positive",
  ];

  const hasFp = falsePositiveSignals.some((s) => tWithoutNegatedFp.includes(s));
  const hasBorderline = borderlineSignals.some((s) => t.includes(s));
  const hasAgree = agreeSignals.some((s) => t.includes(s));

  // Borderline language is the strongest, least ambiguous signal when
  // present — check it first regardless of what else fires.
  if (hasBorderline) return "borderline";
  if (hasFp && !hasAgree) return "false-positive";
  if (hasAgree) return "real-risk";
  return "unclear";
}

// expected vs actual -> outcome. "reasonable-disagreement" covers the two
// directions where landing on "borderline" (or vice versa) is a defensible
// analyst position, not an error. "genuine-miss" is reserved for the two
// dangerous directions: dismissing a real risk, or falling for a false-
// positive trap.
function scoreOutcome(expected, actual) {
  if (actual === "unclear") return "unclear";
  if (actual === expected) return "match";
  if (actual === "borderline" || expected === "borderline") return "reasonable-disagreement";
  return "genuine-miss"; // real-risk <-> false-positive in either direction
}

async function callAnalyze(runId, testCase) {
  const sessionKey = `sec-posture-eval-${runId}-${testCase.id}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CASE_TIMEOUT_MS);
  const startedAt = Date.now();
  try {
    const res = await fetch(`${BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: testCase.domain, finding: testCase.finding, sessionKey }),
      signal: controller.signal,
    });
    const wallMs = Date.now() - startedAt;
    const body = await res.json().catch(() => null);
    if (!res.ok || !body || typeof body.rationale !== "string") {
      return {
        id: testCase.id,
        error: body?.error ?? `HTTP ${res.status}`,
        wallMs,
      };
    }
    return {
      id: testCase.id,
      rationale: body.rationale,
      sessionId: body.sessionId ?? null,
      durationMs: body.durationMs ?? null,
      wallMs,
    };
  } catch (err) {
    return {
      id: testCase.id,
      error: err.name === "AbortError" ? `timed out after ${CASE_TIMEOUT_MS}ms` : String(err.message ?? err),
      wallMs: Date.now() - startedAt,
    };
  } finally {
    clearTimeout(timer);
  }
}

async function runWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  async function lane() {
    while (next < items.length) {
      const idx = next++;
      results[idx] = await worker(items[idx], idx);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, lane));
  return results;
}

function pad(str, len) {
  str = String(str);
  return str.length >= len ? str.slice(0, len - 1) + "…" : str + " ".repeat(len - str.length);
}

async function main() {
  const t0 = Date.now();
  const runId = new Date().toISOString().replace(/[:.]/g, "-");

  // Fail loudly and immediately if the dashboard server isn't reachable —
  // this is a "no fabricated results" suite; it does not fall back to a
  // mock if the real thing isn't up.
  try {
    const health = await fetch(`${BASE_URL}/api/posture`, { signal: AbortSignal.timeout(5000) });
    if (!health.ok && health.status !== 404) {
      throw new Error(`unexpected status ${health.status}`);
    }
  } catch (err) {
    console.error(`\nFATAL: sec-posture dashboard server not reachable at ${BASE_URL}`);
    console.error(`  (${err.message ?? err})`);
    console.error(`  Start it with: cd dashboard && npm start\n`);
    process.exit(1);
  }

  const { cases } = JSON.parse(readFileSync(CASES_PATH, "utf8"));
  console.log(`\nsec-posture Analyst Agent eval — ${cases.length} cases, concurrency ${CONCURRENCY}, target <2min\n`);

  const raw = await runWithConcurrency(cases, CONCURRENCY, (tc) => callAnalyze(runId, tc));

  const rows = raw.map((r) => {
    const tc = cases.find((c) => c.id === r.id);
    if (r.error) {
      return { ...tc, actual: null, outcome: "error", errorDetail: r.error, rationale: null, wallMs: r.wallMs };
    }
    const actual = classifyVerdict(r.rationale);
    const outcome = scoreOutcome(tc.expectedVerdict, actual);
    return {
      ...tc,
      actual,
      outcome,
      rationale: r.rationale,
      sessionId: r.sessionId,
      durationMs: r.durationMs,
      wallMs: r.wallMs,
    };
  });

  const scored = rows.filter((r) => r.outcome !== "error");
  const errored = rows.filter((r) => r.outcome === "error");
  const matches = scored.filter((r) => r.outcome === "match");
  const reasonable = scored.filter((r) => r.outcome === "reasonable-disagreement");
  const misses = scored.filter((r) => r.outcome === "genuine-miss");
  const unclear = scored.filter((r) => r.outcome === "unclear");

  const accuracyPct = scored.length
    ? Math.round(((matches.length + reasonable.length) / scored.length) * 1000) / 10
    : null;

  // ---- console table -------------------------------------------------
  console.log(pad("ID", 22) + pad("Domain", 22) + pad("Expected", 15) + pad("Actual", 15) + pad("Outcome", 22) + "Rationale snippet");
  console.log("-".repeat(140));
  for (const r of rows) {
    const snippet = r.outcome === "error"
      ? `ERROR: ${r.errorDetail}`
      : (r.rationale ?? "").replace(/\s+/g, " ").slice(0, 60) + "…";
    console.log(
      pad(r.id, 22) + pad(r.domain, 22) + pad(r.expectedVerdict, 15) + pad(r.actual ?? "—", 15) + pad(r.outcome, 22) + snippet
    );
  }
  console.log("-".repeat(140));

  const totalWallMs = Date.now() - t0;
  console.log(`\nRun time: ${(totalWallMs / 1000).toFixed(1)}s for ${cases.length} cases (concurrency ${CONCURRENCY})`);

  if (errored.length > 0) {
    console.log(`\n⚠ ${errored.length}/${cases.length} case(s) ERRORED — excluded from accuracy, NOT counted as pass or fail:`);
    for (const r of errored) console.log(`  - ${r.id}: ${r.errorDetail}`);
  }

  if (accuracyPct === null) {
    console.log(`\nAccuracy: N/A — every case errored, nothing was actually scored.`);
  } else {
    console.log(
      `\nAccuracy: ${accuracyPct}% (${matches.length} exact match + ${reasonable.length} reasonable disagreement) / ${scored.length} scored` +
        (errored.length ? ` [${errored.length} errored, excluded]` : "")
    );
  }

  if (unclear.length > 0) {
    console.log(`\n${unclear.length} case(s) the classifier could not confidently read — needs manual review of the rationale:`);
    for (const r of unclear) console.log(`  - ${r.id}: "${(r.rationale ?? "").slice(0, 150)}..."`);
  }

  if (misses.length === 0) {
    console.log(`\nNo genuine misses this run.`);
  } else {
    console.log(`\n${misses.length} GENUINE MISS(ES) — full detail:\n`);
    for (const r of misses) {
      console.log(`  [${r.id}] ${r.domain} — expected "${r.expectedVerdict}", Analyst said "${r.actual}"`);
      console.log(`    Finding: ${r.finding.title} — ${r.finding.detail}`);
      console.log(`    Why expected is correct: ${r.rationale ? cases.find((c) => c.id === r.id).rationale : ""}`);
      console.log(`    Analyst's full rationale:\n      ${(r.rationale ?? "").replace(/\n/g, "\n      ")}\n`);
    }
  }

  // ---- write historical results JSON (same pattern as posture reports) --
  const resultsPath = join(__dirname, `results-${runId}.json`);
  const resultsPayload = {
    runId,
    generatedAt: new Date().toISOString(),
    baseUrl: BASE_URL,
    totalCases: cases.length,
    scoredCases: scored.length,
    erroredCases: errored.length,
    accuracyPct,
    counts: {
      match: matches.length,
      reasonableDisagreement: reasonable.length,
      genuineMiss: misses.length,
      unclear: unclear.length,
      error: errored.length,
    },
    totalWallMs,
    rows: rows.map((r) => ({
      id: r.id,
      domain: r.domain,
      expectedVerdict: r.expectedVerdict,
      caseRationale: cases.find((c) => c.id === r.id).rationale,
      finding: r.finding,
      outcome: r.outcome,
      actualVerdict: r.actual,
      analystRationale: r.rationale,
      sessionId: r.sessionId ?? null,
      durationMs: r.durationMs ?? null,
      wallMs: r.wallMs,
      errorDetail: r.errorDetail ?? null,
    })),
  };
  mkdirSync(__dirname, { recursive: true });
  writeFileSync(resultsPath, JSON.stringify(resultsPayload, null, 2));
  console.log(`\nResults written: ${resultsPath}`);

  const reportHtml = renderReportHtml(resultsPayload);
  writeFileSync(REPORT_HTML_PATH, reportHtml);
  console.log(`Report written: ${REPORT_HTML_PATH}`);

  process.exit(misses.length > 0 || errored.length > 0 ? 1 : 0);
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

const OUTCOME_LABEL = {
  match: "Match",
  "reasonable-disagreement": "Reasonable disagreement",
  "genuine-miss": "MISS",
  unclear: "Unclear (needs review)",
  error: "ERROR",
};
const OUTCOME_CLASS = {
  match: "ok",
  "reasonable-disagreement": "warn",
  "genuine-miss": "miss",
  unclear: "warn",
  error: "miss",
};

function renderReportHtml(payload) {
  const missRows = payload.rows.filter((r) => r.outcome === "genuine-miss");
  const errorRows = payload.rows.filter((r) => r.outcome === "error");

  const calloutHtml =
    missRows.length === 0 && errorRows.length === 0
      ? `<div class="callout ok"><strong>Zero misses, zero errors this run.</strong> All ${payload.scoredCases} scored cases matched or were a defensible disagreement. This does not mean the suite is too easy — see the case table below for what was actually tested, including 3 deliberate false-positive traps and 3 borderline cases.</div>`
      : `<div class="callout bad"><strong>${missRows.length} genuine miss(es), ${errorRows.length} error(s) this run.</strong> Listed in full below — not hidden.</div>`;

  const missDetailHtml = missRows.length
    ? `<section><h2>Genuine misses — full detail</h2>${missRows
        .map(
          (r) => `<div class="miss-detail">
        <div class="miss-head">${esc(r.id)} · ${esc(r.domain)} — expected <b>${esc(r.expectedVerdict)}</b>, Analyst said <b>${esc(r.actualVerdict)}</b></div>
        <div class="miss-finding"><b>${esc(r.finding.title)}</b> — ${esc(r.finding.detail)}</div>
        <div class="miss-why"><i>Why expected is correct:</i> ${esc(r.caseRationale)}</div>
        <div class="miss-rationale"><i>Analyst's full rationale:</i><br>${esc(r.analystRationale).replace(/\n/g, "<br>")}</div>
      </div>`
        )
        .join("")}</section>`
    : "";

  const errorDetailHtml = errorRows.length
    ? `<section><h2>Errored calls — full detail</h2>${errorRows
        .map((r) => `<div class="miss-detail"><div class="miss-head">${esc(r.id)} · ${esc(r.domain)}</div><div class="miss-rationale">${esc(r.errorDetail)}</div></div>`)
        .join("")}</section>`
    : "";

  const rowsHtml = payload.rows
    .map(
      (r) => `<tr>
      <td>${esc(r.id)}</td>
      <td>${esc(r.domain)}</td>
      <td>${esc(r.expectedVerdict)}</td>
      <td>${esc(r.actualVerdict ?? "—")}</td>
      <td><span class="pill ${OUTCOME_CLASS[r.outcome]}">${esc(OUTCOME_LABEL[r.outcome])}</span></td>
      <td class="snippet">${esc(r.outcome === "error" ? r.errorDetail : (r.analystRationale ?? "").slice(0, 160))}${r.analystRationale && r.analystRationale.length > 160 ? "…" : ""}</td>
    </tr>`
    )
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>sec-posture — Analyst Agent Eval</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{
  --bg:#0b0e12; --panel:#12161c; --panel2:#181d25; --ink:#e8edf3; --muted:#8a97a8;
  --line:#232a35; --green:#2fbf71; --amber:#f5a524; --red:#ef4444;
  --greenbg:rgba(47,191,113,.12); --amberbg:rgba(245,165,36,.12); --redbg:rgba(239,68,68,.12);
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --accent:#3fb1e5;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 var(--sans);padding:28px 20px 60px}
.wrap{max-width:1080px;margin:0 auto}
header{padding:20px 24px;background:var(--panel);border:1px solid var(--line);border-radius:16px;margin-bottom:16px}
.brand{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:0 0 4px}
h1{margin:0;font-size:21px;font-weight:650}
.meta{color:var(--muted);font-size:13px;margin-top:6px}
.scorebar{display:flex;gap:14px;flex-wrap:wrap;margin-top:14px}
.score{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:10px 16px;min-width:120px}
.score .num{font-size:24px;font-weight:750}
.score .lbl{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
section{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px 22px;margin-top:16px}
section h2{margin:0 0 12px;font-size:15px}
.callout{border-radius:12px;padding:14px 16px;font-size:14px;margin-top:16px}
.callout.ok{background:var(--greenbg);border:1px solid var(--green);color:var(--ink)}
.callout.bad{background:var(--redbg);border:1px solid var(--red);color:var(--ink)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
.snippet{color:var(--muted);font-family:var(--mono);font-size:12px;max-width:360px}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.pill.ok{background:var(--greenbg);color:var(--green)}
.pill.warn{background:var(--amberbg);color:var(--amber)}
.pill.miss{background:var(--redbg);color:var(--red)}
.miss-detail{border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:12px;background:var(--panel2)}
.miss-head{font-weight:700;margin-bottom:6px}
.miss-finding{color:var(--muted);margin-bottom:6px;font-size:13px}
.miss-why{color:var(--amber);margin-bottom:8px;font-size:13px}
.miss-rationale{font-size:13px;font-family:var(--mono);white-space:pre-wrap}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:24px}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <p class="brand">sec-posture · Agent Eval</p>
    <h1>Analyst Agent Eval — ${esc(payload.runId)}</h1>
    <p class="meta">Generated ${esc(payload.generatedAt)} · ${payload.totalCases} cases · ${(payload.totalWallMs / 1000).toFixed(1)}s run time</p>
    <div class="scorebar">
      <div class="score"><div class="num">${payload.accuracyPct === null ? "N/A" : payload.accuracyPct + "%"}</div><div class="lbl">Accuracy</div></div>
      <div class="score"><div class="num">${payload.counts.match}</div><div class="lbl">Exact match</div></div>
      <div class="score"><div class="num">${payload.counts.reasonableDisagreement}</div><div class="lbl">Reasonable disagreement</div></div>
      <div class="score"><div class="num">${payload.counts.genuineMiss}</div><div class="lbl">Genuine miss</div></div>
      <div class="score"><div class="num">${payload.counts.error}</div><div class="lbl">Errored</div></div>
    </div>
    ${calloutHtml}
  </header>

  <section>
    <h2>Case-by-case results</h2>
    <table>
      <thead><tr><th>ID</th><th>Domain</th><th>Expected</th><th>Analyst said</th><th>Outcome</th><th>Rationale snippet</th></tr></thead>
      <tbody>${rowsHtml}</tbody>
    </table>
  </section>

  ${missDetailHtml}
  ${errorDetailHtml}

  <footer>sec-posture Analyst Agent eval · scoring is heuristic (rationale text classification) — read the full rationale for any case before trusting the label.</footer>
</div>
</body>
</html>`;
}

main().catch((err) => {
  console.error("FATAL: eval run crashed:", err);
  process.exit(1);
});
