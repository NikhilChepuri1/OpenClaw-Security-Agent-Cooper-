#!/usr/bin/env node
/**
 * sec-posture dashboard server — local-only (127.0.0.1), fronts:
 *   - the static dashboard UI (public/)
 *   - posture.json as a live feed over SSE (polls the file for mtime changes)
 *   - "Run New Scan" -> spawns the real scan.ts (full 5-domain run)
 *   - Chat -> spawns the REAL OpenClaw agent ("Cooper" / agent "main") via
 *     `openclaw agent --json`. No mock, no canned replies. If the agent
 *     invocation fails, the client is told the truth — never a fabricated
 *     Cooper-sounding fallback.
 *
 * Everything here is read-only w.r.t. the machine's security posture: the
 * only writes are the scan.ts artifacts (which scan.ts itself owns) and the
 * agent's own session file (which is the point — a real conversation).
 */

import { execFile } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { applyAutoFix } from "./remediation-agent.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SKILL_DIR = dirname(__dirname); // .../skills/sec-posture
const SCAN_TS = join(SKILL_DIR, "scan.ts");
const POSTURE_JSON = join(SKILL_DIR, "posture.json");
const REPORTS_DIR = join(SKILL_DIR, "reports");

const PORT = Number(process.env.SEC_POSTURE_PORT ?? 18790);
const HOST = "127.0.0.1";
const AGENT_ID = "main"; // the "Cooper" identity — see IDENTITY.md/SOUL.md
const SESSION_KEY = "sec-posture-dashboard"; // dedicated, continuous chat session
const AGENT_TIMEOUT_MS = 120_000;

// Widen PATH so `openclaw`/`node` resolve regardless of how this server was launched.
const CHILD_ENV = {
  ...process.env,
  PATH: `/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:${process.env.PATH ?? ""}`,
};

function run(cmd, args, { timeout = 30_000 } = {}) {
  return new Promise((resolve) => {
    execFile(
      cmd,
      args,
      { env: CHILD_ENV, timeout, maxBuffer: 32 * 1024 * 1024 },
      (error, stdout, stderr) => {
        resolve({ error, stdout: stdout ?? "", stderr: stderr ?? "" });
      },
    );
  });
}

// `openclaw agent --json` on the currently-installed CLI (2026.7.1) nests the
// reply under `result.payloads[0].text` / `result.meta...` — verified live
// 2026-07-16. Both call sites below previously read `parsed.payloads`/
// `parsed.meta` (one level too shallow), which meant every /api/analyze and
// /api/chat call silently 502'd with "no text payload" regardless of what
// Cooper actually said. This centralizes the extraction so there's one place
// to fix if the CLI's envelope shape changes again, instead of two.
function extractAgentReply(parsed) {
  const result = parsed?.result ?? parsed; // tolerate either shape defensively
  const text = result?.payloads?.[0]?.text;
  return {
    text: typeof text === "string" ? text : null,
    sessionId: result?.meta?.agentMeta?.sessionId ?? null,
    durationMs: result?.meta?.durationMs ?? null,
    transport: result?.meta?.transport ?? null,
  };
}

// ---------------------------------------------------------------------------
// Domain detection for chat grounding (mirrors scan.ts's resolveDomain)
// ---------------------------------------------------------------------------

const DOMAINS = [
  "Secret Exposure",
  "Credential Hygiene",
  "File Permission Health",
  "Access & Config Safety",
  "Incident Readiness",
];
const DOMAIN_KEYWORDS = [
  ["secret", "exposure", "leak"],
  ["credential", "hygiene", "password", "token"],
  ["permission", "file perm", "ssh", "perm"],
  ["access", "config", "firewall", "network", "listen", "port", "airplay", "gateway"],
  ["incident", "readiness", "log", "memory", "guardrail", "audit"],
];
function detectDomain(message) {
  const v = message.toLowerCase();
  const idx = DOMAIN_KEYWORDS.findIndex((words) => words.some((w) => v.includes(w)));
  return idx >= 0 ? idx : null;
}

// Same flatten+sort the dashboard client uses for its Remediation Queue cards
// (severity crit→warn→info, domain order, then in-domain order) — kept
// identical on both sides so "apply fix 3" in chat means the same finding as
// the 3rd card on screen.
const SEV_RANK = { crit: 0, warn: 1, info: 2 };
function orderedFixes(posture) {
  return posture.domains
    .flatMap((d) => d.findings.filter((f) => f.fix).map((f) => ({ domain: d.name, ...f })))
    .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
}

function findingKey(f) {
  return `${f.severity}::${f.title}::${f.source}`;
}

// ---------------------------------------------------------------------------
// Remediation Agent — applies every AUTO-SAFE finding from a fresh scan.
// Deterministic, hardcoded, model-free (see remediation-agent.mjs) — this is
// just the glue that finds eligible findings and calls the real executor.
// ---------------------------------------------------------------------------

function runRemediationPass(posture) {
  const applied = [];
  for (const domain of posture.domains) {
    for (const f of domain.findings) {
      if (f.fix?.tier !== "auto-safe") continue;
      const result = applyAutoFix(f.fix, { findingTitle: f.title, domainName: domain.name });
      applied.push({
        domain: domain.name,
        title: f.title,
        severity: f.severity,
        tierReason: f.fix.tierReason,
        ...result,
      });
    }
  }
  return applied;
}

// ---------------------------------------------------------------------------
// SSE hub — broadcasts posture updates + scan lifecycle to every open tab
// ---------------------------------------------------------------------------

const sseClients = new Set();
function broadcast(event) {
  const payload = `data: ${JSON.stringify(event)}\n\n`;
  for (const res of sseClients) res.write(payload);
}

let lastMtimeMs = 0;
function readPosture() {
  if (!existsSync(POSTURE_JSON)) return null;
  return JSON.parse(readFileSync(POSTURE_JSON, "utf8"));
}
function checkForPostureChange() {
  if (!existsSync(POSTURE_JSON)) return;
  const mtimeMs = statSync(POSTURE_JSON).mtimeMs;
  if (mtimeMs !== lastMtimeMs) {
    lastMtimeMs = mtimeMs;
    broadcast({ type: "posture", data: readPosture() });
  }
}
setInterval(checkForPostureChange, 2000);

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());
app.use(express.static(join(__dirname, "public")));
app.use("/vendor/chart.js", express.static(join(__dirname, "node_modules", "chart.js", "dist")));

app.get("/api/posture", (_req, res) => {
  const data = readPosture();
  if (!data) return res.status(404).json({ error: "posture.json not found — run a scan first" });
  res.json(data);
});

// Full-fidelity scan history (chronological). Each entry is a complete
// posture.json snapshot from that run — the client uses it both for the
// trend line (overall/domain scores over time) and the since-last-scan diff
// (which needs each domain's findings, not just its score). Only scans run
// after the JSON-archive feature was added have a sibling file here; older
// HTML-only archives are silently excluded — there's nothing to diff.
app.get("/api/history", (_req, res) => {
  if (!existsSync(REPORTS_DIR)) return res.json([]);
  const entries = readdirSync(REPORTS_DIR)
    .filter((f) => /^posture-.*\.json$/.test(f))
    .map((f) => {
      try {
        return JSON.parse(readFileSync(join(REPORTS_DIR, f), "utf8"));
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .sort((a, b) => new Date(a.generatedAt) - new Date(b.generatedAt));
  res.json(entries);
});

app.get("/api/events", (req, res) => {
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  res.flushHeaders();
  sseClients.add(res);
  const initial = readPosture();
  if (initial) res.write(`data: ${JSON.stringify({ type: "posture", data: initial })}\n\n`);
  req.on("close", () => sseClients.delete(res));
});

function runScanOnce() {
  return new Promise((resolve) => {
    execFile(
      "node",
      [SCAN_TS],
      { cwd: SKILL_DIR, env: CHILD_ENV, timeout: 60_000, maxBuffer: 16 * 1024 * 1024 },
      (error) => resolve(error ?? null),
    );
  });
}

let scanning = false;
app.post("/api/scan", async (_req, res) => {
  if (scanning) return res.status(409).json({ error: "a scan is already running" });
  scanning = true;
  broadcast({ type: "scan-status", status: "running" });
  res.json({ status: "started" });

  const error = await runScanOnce();
  if (error) {
    scanning = false;
    broadcast({ type: "scan-status", status: "error", message: String(error.message ?? error) });
    return;
  }
  checkForPostureChange(); // pick up the new file immediately, don't wait for the poll tick

  // Remediation Agent pass: auto-apply anything tier'd auto-safe by scan.ts's
  // hardcoded classifier. Capped at exactly one apply-then-rescan cycle per
  // scan trigger — never loops — so a fix that doesn't fully clear its
  // finding can't cause runaway re-scanning.
  const posture = readPosture();
  const applied = posture ? runRemediationPass(posture).filter((r) => r.applied) : [];
  if (applied.length) {
    broadcast({ type: "remediation", applied });
    const rescanError = await runScanOnce();
    if (!rescanError) checkForPostureChange();
  }

  scanning = false;
  broadcast({ type: "scan-status", status: "done" });
});

// ---------------------------------------------------------------------------
// Analyst Agent -> real Cooper call producing a rationale for one finding.
// This is a genuine model call (not templated) but it is advisory only: it
// never mutates the finding's actual severity or the deterministic domain
// score — those stay auditable and reproducible from scan.ts alone. What the
// Analyst says is displayed in the "Agent Trace" panel as its own reasoning
// stage, separate from the Scanner's evidence and the Remediation Agent's
// (hardcoded, non-model) tier decision.
// ---------------------------------------------------------------------------

app.post("/api/analyze", async (req, res) => {
  // Two ways in: the real dashboard UI always sends findingKey (look up the
  // finding in the CURRENT live scan). eval/run-eval.mjs sends an inline
  // { domain, finding } instead — this lets the eval suite exercise this
  // exact endpoint (same prompt-building, same real openclaw agent call)
  // against hand-authored test findings without ever writing to the live
  // posture.json, so a scan the eval didn't run can't end up displayed on
  // someone's open dashboard tab. findingKey lookup behavior is unchanged.
  let domain, finding;
  if (req.body?.finding && typeof req.body.finding === "object") {
    finding = req.body.finding;
    domain = { name: String(req.body?.domain ?? "Unspecified") };
    if (!finding.title || !finding.severity) {
      return res.status(400).json({ error: "inline finding requires at least title and severity" });
    }
  } else {
    const findingKeyParam = String(req.body?.findingKey ?? "");
    if (!findingKeyParam) return res.status(400).json({ error: "findingKey (or an inline finding) is required" });

    const posture = readPosture();
    if (!posture) return res.status(404).json({ error: "posture.json not found — run a scan first" });

    let match = null;
    for (const d of posture.domains) {
      for (const f of d.findings) {
        if (findingKey(f) === findingKeyParam) {
          match = { domain: d, finding: f };
          break;
        }
      }
      if (match) break;
    }
    if (!match) return res.status(404).json({ error: "finding not found in the current scan" });
    ({ domain, finding } = match);
  }

  const prompt =
    `(Analyst Agent request — do not scan, just reason about this ALREADY-COLLECTED finding.)\n\n` +
    `Domain: ${domain.name}\n` +
    `Finding: ${finding.title}\n` +
    `Severity assigned by the scanner: ${finding.severity}\n` +
    `Detail: ${finding.detail}\n` +
    `Source: ${finding.source}\n` +
    `Evidence (masked): ${finding.evidence}\n\n` +
    `In 3-5 sentences: (1) do you agree with the assigned severity, or is this plausibly a false ` +
    `positive / over-scored finding worth downgrading — and why; (2) how should this rank against ` +
    `other findings in priority order; (3) one line of rationale a mentor could read to understand ` +
    `the judgment call. Be direct. If you agree with the severity, say so plainly — don't manufacture ` +
    `disagreement.`;

  // Real dashboard calls never send sessionKey, so this defaults to the
  // same continuous SESSION_KEY as before — unchanged behavior. eval/
  // run-eval.mjs sends its own dedicated key so 10 synthetic test findings
  // don't get appended into the real, ongoing dashboard conversation
  // history that Nikhil actually reads.
  const sessionKeyParam = String(req.body?.sessionKey ?? SESSION_KEY);

  const result = await run(
    "openclaw",
    ["agent", "--agent", AGENT_ID, "--session-key", sessionKeyParam, "--message", prompt, "--json"],
    { timeout: AGENT_TIMEOUT_MS },
  );

  if (result.error) {
    return res.status(502).json({
      error: "Analyst Agent (Cooper) invocation failed",
      detail: String(result.error.message ?? result.error).slice(0, 2000),
    });
  }
  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    return res.status(502).json({ error: "Analyst Agent responded but output wasn't parseable JSON" });
  }
  const reply = extractAgentReply(parsed);
  if (reply.text === null) {
    return res.status(502).json({ error: "Analyst Agent's response had no text payload" });
  }
  res.json({ rationale: reply.text, sessionId: reply.sessionId, durationMs: reply.durationMs });
});

// ---------------------------------------------------------------------------
// Chat -> real Cooper agent turn
// ---------------------------------------------------------------------------

app.post("/api/chat", async (req, res) => {
  const message = String(req.body?.message ?? "").trim();
  if (!message) return res.status(400).json({ error: "message is required" });

  // "apply fix N" -> ground the chat turn in that exact fix's data so Cooper's
  // reply (restate + ask for final confirmation, per its own SOUL.md/AGENTS.md
  // rules) is about the right finding. This never executes anything itself —
  // CONFIRM-REQUIRED fixes only ever go through Cooper talking the human
  // through running the command themselves, exactly as already designed.
  const applyMatch = message.match(/apply\s+fix\s+(\d+)/i);
  let fixGrounding = null;
  if (applyMatch) {
    const posture = readPosture();
    if (posture) {
      const fixes = orderedFixes(posture);
      const idx = Number(applyMatch[1]) - 1;
      if (fixes[idx]) fixGrounding = fixes[idx];
    }
  }

  let grounding = null;
  const domainIdx = detectDomain(message);
  if (domainIdx !== null) {
    const scoped = await run("node", [SCAN_TS, "--domain", String(domainIdx + 1), "--json"], {
      timeout: 30_000,
    });
    if (!scoped.error) {
      try {
        grounding = JSON.parse(scoped.stdout);
      } catch {
        grounding = null; // don't block the chat turn on a parse hiccup — just skip grounding
      }
    }
  }

  let augmented = message;
  if (fixGrounding) {
    augmented =
      `(The human just typed "apply fix ${applyMatch[1]}" in the sec-posture dashboard's Remediation Queue. ` +
      `That queue entry is:\n` +
      `  Domain: ${fixGrounding.domain}\n` +
      `  Finding: ${fixGrounding.title} (severity: ${fixGrounding.severity})\n` +
      `  Tier: ${fixGrounding.fix.tier}${fixGrounding.fix.tier === "confirm-required" ? " — this is gated and requires your restated confirmation before anything runs" : ""}\n` +
      `  Risk: ${fixGrounding.fix.risk}\n` +
      `  Command: ${fixGrounding.fix.command}\n\n` +
      `Per your sec-posture rules: restate exactly what this command will change, restate the risk, ` +
      `and ask for explicit final confirmation before treating this as approved. You do not have a way ` +
      `to execute this yourself from this chat — walk the human through running it.)\n\n${message}`;
  } else if (grounding) {
    const findingLines = grounding.findings
      .map((f) => `  - [${f.severity}] ${f.title} — ${f.source}`)
      .join("\n");
    augmented =
      `(sec-posture just re-ran a fresh read-only scan of "${grounding.domain}" for this question — ` +
      `score ${grounding.score}/100, ${grounding.math}.\n${findingLines || "  (no findings)"}\n\n` +
      `Answer the question below using this fresh evidence, citing sources, per your sec-posture rules.)\n\n${message}`;
  }

  const agentArgs = [
    "agent",
    "--agent",
    AGENT_ID,
    "--session-key",
    SESSION_KEY,
    "--message",
    augmented,
    "--json",
  ];
  const result = await run("openclaw", agentArgs, { timeout: AGENT_TIMEOUT_MS });

  if (result.error) {
    return res.status(502).json({
      error: "Cooper agent invocation failed",
      detail: String(result.error.message ?? result.error).slice(0, 2000),
      stderrTail: result.stderr.slice(-2000),
    });
  }

  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    return res.status(502).json({
      error: "Cooper responded but the output could not be parsed as JSON",
      stdoutTail: result.stdout.slice(-2000),
      stderrTail: result.stderr.slice(-2000),
    });
  }

  const reply = extractAgentReply(parsed);
  if (reply.text === null) {
    return res.status(502).json({
      error: "Cooper's response had no text payload",
      raw: parsed,
    });
  }

  res.json({
    reply: reply.text,
    groundedDomain: grounding ? grounding.domain : null,
    groundedScore: grounding ? grounding.score : null,
    groundedFix: fixGrounding ? { title: fixGrounding.title, tier: fixGrounding.fix.tier } : null,
    sessionId: reply.sessionId,
    durationMs: reply.durationMs,
    transport: reply.transport,
  });
});

const server = createServer(app);
server.listen(PORT, HOST, () => {
  console.log(`sec-posture dashboard: http://${HOST}:${PORT}`);
});
