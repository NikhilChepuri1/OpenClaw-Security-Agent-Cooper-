# Cooper — OpenClaw Security Auth/Ops Agent

A security operations agent built on [OpenClaw](https://github.com/openclaw/openclaw), designed to perform auth auditing, log scanning, credential hygiene checks, and incident triage — all through natural language.

## What Cooper Does

| Workflow | Description |
|---|---|
| Auth Audit | Reviews sessions, tokens, permissions, and access anomalies |
| Log Scan | Scans logs for suspicious activity, failed logins, off-hours access |
| Credential Hygiene | Finds exposed secrets, hardcoded keys, recommends rotation |
| Incident Triage | Builds timelines, assesses severity, proposes containment steps |

## How It Works

Cooper runs as a self-hosted AI agent via the OpenClaw gateway. You interact through WebChat or any connected channel using natural language. Cooper routes security-related requests through the security-ops skill and operates under strict rules: never exposes credentials in output, never executes destructive commands without explicit confirmation, always cites the source for every finding, and logs all actions to daily memory files.

## Stack

- Framework: OpenClaw
- Model: claude-sonnet-4-6 (Anthropic)
- Channel: WebChat (localhost)
- Skills: Custom security-ops skill

## Repo Structureworkspace/

├── SOUL.md                    # Agent persona and hard limits

├── AGENTS.md                  # Operational rules and routing

├── TOOLS.md                   # Environment config and log paths

└── skills/

└── security-ops/

└── SKILL.md           # Security workflows

screenshots/                   # Demo screenshots

## Setup

1. Install OpenClaw: npm install -g openclaw
2. Run: openclaw onboard
3. Clone this repo and copy workspace/ contents to ~/.openclaw/workspace/
4. Add your Anthropic API key via: openclaw configure
5. Run: openclaw dashboard and start chatting with Cooper

## Demo Prompts

- "Run an auth audit on this machine"
- "Scan my logs for suspicious logins in the last 24 hours"
- "Check for hardcoded credentials in this repo"
- "Triage a suspicious login at 2am"

---

Built by Nikhil Chepuri
