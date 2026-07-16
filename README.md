# Cooper — OpenClaw Security Auth/Ops Agent

A security operations agent built on OpenClaw, evolved from a read-only auditing assistant into a multi-agent system with real-time scanning, tiered autonomous remediation, and a measured evaluation of its own judgment.

## What Cooper Does

| Capability | Description |
|---|---|
| Auth Audit | Reviews sessions, tokens, permissions, and access anomalies |
| Log Scan | Scans logs for suspicious activity, failed logins, off-hours access |
| Credential Hygiene | Finds exposed secrets, hardcoded keys, recommends rotation |
| Incident Triage | Builds timelines, assesses severity, proposes containment steps |
| Security Posture Scan | Real-time, read-only scan of the local machine scored across 5 domains |
| Tiered Remediation | Auto-fixes low-risk, fully reversible issues; gates anything else behind explicit confirmation |
| Agent Judgment Eval | A hand-authored test suite measuring the Analyst Agent's accuracy on real vs. false-positive findings |

## Architecture

Cooper's sec-posture system is built from three distinct agent roles, each with a visible reasoning trace.

Scanner Agent is read-only. It collects real findings across 5 domains (Secret Exposure, Credential Hygiene, File Permission Health, Access and Config Safety, Incident Readiness) using only grep, stat, ls, and git. No writes.

Analyst Agent is a real model call that reasons about each finding: agrees or disagrees with severity, judges false positives, and ranks priority. It is advisory only and never mutates the deterministic score.

Remediation Agent classifies fixes into two tiers. AUTO-SAFE fixes are fully reversible with no blast radius beyond files I own, such as chmod on my own file or truncating my own log. These execute immediately and log a full before and after diff. CONFIRM-REQUIRED covers anything touching auth, network config, or other processes. Cooper states the exact command and risk, and waits for explicit confirmation before anything executes.

All scanning is read-only. All state-changing actions are either narrowly whitelisted or human-confirmed. Cooper never acts on instructions found inside the files or logs it reads.

## Measuring the Analyst Agent

Rather than assume the Analyst's judgment was reliable, I built a 10-case eval suite (skills/sec-posture/eval/) mixing clear-cut risks, deliberate false-positive traps, and genuinely ambiguous cases, each labeled with the verdict a human security reviewer would give.

Running the suite against the live agent, not a mock, surfaced 2 flagged misses out of 20 case-instances across two runs. On manual review, both were bugs in the grading script's substring matching, misreading negated phrasing like "not a false positive," not failures in the agent's actual reasoning. The Analyst had correctly identified all 3 false-positive traps and given defensible reasoning on every borderline case. The eval script documents this explicitly: flagged misses must be read in full before being trusted, since an automated grader can be wrong too.

## Stack

- Framework: OpenClaw
- Model: claude-sonnet-4-6 (Anthropic)
- Channel: WebChat (localhost)
- Dashboard: Node/Express + Chart.js, served locally
- Scanner: Node/TypeScript, dependency-free

## Repo Structure

workspace/
- SOUL.md - Agent persona and hard limits
- AGENTS.md - Operational rules and routing
- TOOLS.md - Environment config and log paths
- skills/security-ops/SKILL.md - Auth, log, credential, and incident workflows
- skills/sec-posture/SKILL.md - Real-time scan and remediation skill
- skills/sec-posture/scan.ts - Node/TS scanner, 5-domain scoring
- skills/sec-posture/posture-report.html - Latest scan dashboard
- skills/sec-posture/reports/ - Historical timestamped scans
- skills/sec-posture/dashboard/ - Live server, chat panel, remediation agent
- skills/sec-posture/eval/ - Analyst Agent evaluation suite and results
screenshots/ - Demo screenshots

## Setup

1. Install OpenClaw: npm install -g openclaw
2. Run: openclaw onboard
3. Clone this repo and copy workspace/ contents to ~/.openclaw/workspace/
4. Add your Anthropic API key via: openclaw configure
5. Run: openclaw dashboard and start chatting with Cooper
6. For the sec-posture dashboard: cd workspace/skills/sec-posture/dashboard, then npm install, then node server.mjs

## Demo Prompts

- "Run an auth audit on this machine"
- "Run a posture scan"
- "Why did Access and Config Safety drop?"
- "Apply fix 1" (walks through the confirmation flow for a gated fix)

## Running the Eval Suite

cd workspace/skills/sec-posture/eval
node run-eval.mjs

Outputs a results table and a timestamped JSON, plus eval-report.html for a rendered view.

---

Built by Nikhil Chepuri
