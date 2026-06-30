# TOOLS.md - Cooper's Environment

## Setup
- Machine: local Mac
- Model: claude-sonnet-4-7
- Channel: WebChat (localhost:18789)

## Skills
- security-ops → auth auditing, log scanning, credential hygiene, incident triage

## Log paths

| Service  | Host      | Path                           | Notes        |
|----------|-----------|--------------------------------|--------------|
| OpenClaw | local Mac | `~/.openclaw/logs/gateway.log` | Gateway auth |
| Shell    | local Mac | `~/.zsh_history`               | Off-hours use only |

## Auth surfaces

| System   | Mechanism | Config location             |
|----------|-----------|-----------------------------|
| OpenClaw | Gateway   | `~/.openclaw/openclaw.json` |

## Notes
- Add SSH hosts and aliases here as you connect remote systems