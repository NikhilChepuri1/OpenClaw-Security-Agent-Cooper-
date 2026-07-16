#!/usr/bin/env bash
# sec-posture read-only collector. Emits raw evidence per domain. ZERO writes.
# Every known secret pattern is masked to its last 4 chars before printing.
# Usage:  bash scan.sh [scan-root]   (default scan-root = current dir)
set -uo pipefail
ROOT="${1:-.}"

# Mask any known secret token in a stream to ***<last4>.
mask() {
  perl -pe 's/(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|gh[porsu]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{6,}|Bearer\s+[A-Za-z0-9._-]{20,}|"(?:token|secret|apiKey|_authToken|password|aws_secret_access_key)"\s*:\s*")([^"\n]*)/"***".substr($2,-4)/ge' 2>/dev/null || cat
}
sec() { printf '\n===== %s =====\n' "$1"; }

sec "META"
echo "host: $(hostname -s 2>/dev/null)"
echo "scan-root: $ROOT"

sec "DOMAIN 1 — Secret Exposure (working tree)"
grep -rInE 'AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|gh[porsu]_[A-Za-z0-9]{20,}|xox[baprs]-|-----BEGIN[A-Z ]*PRIVATE KEY-----|Bearer [A-Za-z0-9._-]{20,}' \
  --exclude-dir=.git --exclude-dir=node_modules "$ROOT" 2>/dev/null | head -50 | mask || echo "(none)"

sec "DOMAIN 1 — Tracked .env files"
( cd "$ROOT" && git ls-files 2>/dev/null | grep -E '(^|/)\.env(\..+)?$' ) || echo "(no git repo / none)"

sec "DOMAIN 1 — Git history secret probe"
( cd "$ROOT" && git log -p --all 2>/dev/null | grep -nE 'AKIA[0-9A-Z]{16}|gh[porsu]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}' | head -20 | mask ) || echo "(no git repo / none)"

sec "DOMAIN 2 — Credential stores (perms)"
stat -f '%Sp %N' ~/.aws/credentials ~/.netrc ~/.npmrc ~/.git-credentials ~/.docker/config.json ~/.pgpass 2>/dev/null || echo "(none present)"
sec "DOMAIN 2 — Plaintext creds in configs (masked)"
grep -InE '_authToken|password|secret|aws_secret_access_key|_token' ~/.npmrc ~/.netrc ~/.git-credentials 2>/dev/null | mask || echo "(none)"
sec "DOMAIN 2 — openclaw.json secret keys (masked)"
grep -nE '"(token|secret|apiKey|password)"[[:space:]]*:' ~/.openclaw/openclaw.json 2>/dev/null | mask || echo "(none)"

sec "DOMAIN 3 — ~/.ssh listing"
ls -la ~/.ssh 2>/dev/null || echo "(no ~/.ssh)"
sec "DOMAIN 3 — private key perms (expect 600)"
for f in ~/.ssh/id_* ~/.ssh/*.pem; do [ -f "$f" ] && [[ "$f" != *.pub ]] && stat -f '%Lp %N' "$f"; done 2>/dev/null || echo "(no keys)"
sec "DOMAIN 3 — sensitive file perms"
stat -f '%Lp %N' ~/.aws/credentials ~/.netrc ~/.git-credentials ~/.openclaw/openclaw.json ~/.ssh/config 2>/dev/null || echo "(none)"

sec "DOMAIN 4 — gateway bind / dangerous flags"
grep -nE '"bind"|"mode"|"allowInsecureAuth"|"port"' ~/.openclaw/openclaw.json 2>/dev/null || echo "(no openclaw.json)"
sec "DOMAIN 4 — non-loopback listeners"
lsof -iTCP -sTCP:LISTEN -nP 2>/dev/null | grep -vE '127\.0\.0\.1|\[::1\]' | head -20 || echo "(none / lsof unavailable)"
sec "DOMAIN 4 — sshd_config"
grep -InE '^\s*(PasswordAuthentication|PermitRootLogin|PermitEmptyPasswords)' /etc/ssh/sshd_config 2>/dev/null || echo "(no sshd_config / defaults)"

sec "DOMAIN 5 — logging"
ls -la ~/.openclaw/logs/ 2>/dev/null | head; stat -f '%Sm %N' ~/.openclaw/logs/gateway.log 2>/dev/null || echo "(no gateway log)"
sec "DOMAIN 5 — audit trail (memory/)"
ls -1 "$ROOT"/memory/*.md 2>/dev/null | tail -5 || echo "(no memory dir)"
sec "DOMAIN 5 — confirmation gates"
grep -cnE 'confirmation|destructive|trash > rm|explicit' "$ROOT"/AGENTS.md "$ROOT"/SOUL.md 2>/dev/null || echo "(guardrail files missing)"

sec "DONE"
