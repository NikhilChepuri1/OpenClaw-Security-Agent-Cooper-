#!/usr/bin/env node
/**
 * sec-posture scanner — Cooper's read-only local security posture scan.
 *
 * Runs a REAL read-only inspection of this machine, scores it 0-100 across 5
 * domains, and renders a self-contained HTML dashboard. Node 25 executes this
 * TypeScript file directly (native type stripping) — no build step, no deps.
 *
 *   node scan.ts                 # scan + write report
 *   node scan.ts --open          # scan, write report, open it in the browser
 *   node scan.ts --json          # also print machine-readable JSON to stdout
 *   node scan.ts --root <dir>    # override the secret-exposure scan root
 *
 * NON-NEGOTIABLES (see SKILL.md):
 *   - Read-only while scanning. The ONLY writes are the report artifacts.
 *   - Every secret is masked to its last 4 chars before it is ever printed.
 *   - Every finding cites a source (file:line, config key, or command).
 */

import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir, hostname } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Types & scoring model
// ---------------------------------------------------------------------------

type Severity = "crit" | "warn" | "info";
type Tier = "auto-safe" | "confirm-required";

/**
 * The exhaustive, hardcoded set of actions the Remediation Agent is ever
 * allowed to execute automatically. This union IS the safety boundary — the
 * executor (dashboard/remediation-agent.mjs) re-validates against this same
 * narrow shape independently before touching anything. Nothing outside these
 * three kinds can ever be tier "auto-safe"; see classifyFix call sites below,
 * every one of which is a `grep -n "autoSafeFix("` away from being audited.
 */
type AutoFix =
  | { kind: "chmod"; target: string; mode: "600" }
  | { kind: "gitignore-append"; target: string; pattern: string }
  | { kind: "truncate-log"; target: string };

interface Finding {
  domain: number;
  severity: Severity;
  title: string;
  detail: string;
  source: string; // cited: file:line, config key, or command
  evidence: string; // already masked
  fix?: {
    title: string;
    risk: string;
    command: string;
    guided?: boolean;
    tier: Tier;
    tierReason: string;
    autoFix?: AutoFix;
  };
}

/** AUTO-SAFE: fully reversible, blast radius limited to a file we own. */
function autoSafeFix(tierReason: string, autoFix: AutoFix) {
  return { tier: "auto-safe" as const, tierReason, autoFix };
}
/** CONFIRM-REQUIRED: the default. Touches auth/network/other-owned state, or is irreversible. */
function confirmRequiredFix(tierReason: string) {
  return { tier: "confirm-required" as const, tierReason };
}

const DEDUCTION: Record<Severity, number> = { crit: 40, warn: 15, info: 5 };
const SEV_LABEL: Record<Severity, string> = {
  crit: "🔴 Crit",
  warn: "🟡 Warn",
  info: "🟢 Info",
};

const HOME = homedir();
const CONFIG_PATH = join(HOME, ".openclaw", "openclaw.json");
const WORKSPACE = join(HOME, ".openclaw", "workspace");
const SKILL_DIR = dirname(fileURLToPath(import.meta.url));

const DOMAINS = [
  "Secret Exposure",
  "Credential Hygiene",
  "File Permission Health",
  "Access & Config Safety",
  "Incident Readiness",
];

// ---------------------------------------------------------------------------
// Read-only helpers
// ---------------------------------------------------------------------------

/** Run a command read-only; never throw. Returns stdout (trimmed) or "". */
function sh(cmd: string, args: string[], cwd?: string): string {
  try {
    return execFileSync(cmd, args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      maxBuffer: 64 * 1024 * 1024,
      timeout: 60_000,
    }).trim();
  } catch (e: any) {
    // Non-zero exit (e.g. grep "no match") is expected; return whatever stdout we got.
    return (e?.stdout ? String(e.stdout) : "").trim();
  }
}

/** Mask a secret to ***<last4>. Values <=4 chars become ****. */
function mask(secret: string): string {
  const s = secret.trim();
  if (s.length <= 4) return "****";
  return "***" + s.slice(-4);
}

/** Mask every known secret-shaped token inside an arbitrary string. */
const SECRET_TOKEN =
  /(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|gh[porsu]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{6,}|Bearer\s+[A-Za-z0-9._-]{20,})/g;
function maskLine(line: string): string {
  return line.replace(SECRET_TOKEN, (m) => mask(m));
}

/** octal "other" permission bits of a path, or -1 if absent. */
function otherPerm(path: string): number {
  try {
    return statSync(path).mode & 0o007;
  } catch {
    return -1;
  }
}
function permOctal(path: string): string | null {
  try {
    return (statSync(path).mode & 0o777).toString(8).padStart(3, "0");
  } catch {
    return null;
  }
}
function fileSize(path: string): number {
  try {
    return statSync(path).size;
  } catch {
    return -1;
  }
}
const human = (bytes: number) =>
  bytes < 0
    ? "n/a"
    : bytes < 1024
    ? `${bytes} B`
    : bytes < 1024 ** 2
    ? `${(bytes / 1024).toFixed(0)} KB`
    : bytes < 1024 ** 3
    ? `${(bytes / 1024 ** 2).toFixed(0)} MB`
    : `${(bytes / 1024 ** 3).toFixed(1)} GB`;

/** Find the 1-based line number of the first line matching `needle`. */
function lineOf(text: string, needle: RegExp): number {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) if (needle.test(lines[i])) return i + 1;
  return 0;
}

// ---------------------------------------------------------------------------
// Domain 1 — Secret Exposure
// ---------------------------------------------------------------------------

function scanSecretExposure(root: string): Finding[] {
  const findings: Finding[] = [];
  const pattern =
    "AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|gh[porsu]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{6,}|-----BEGIN[A-Z ]*PRIVATE KEY-----|Bearer [A-Za-z0-9._-]{20,}";

  // Working tree: which files contain secret-shaped strings?
  const files = sh("grep", [
    "-rIlE",
    pattern,
    "--exclude-dir=.git",
    "--exclude-dir=node_modules",
    root,
  ])
    .split("\n")
    .filter(Boolean);

  for (const f of files) {
    const hit = sh("grep", ["-nIE", pattern, f]).split("\n").filter(Boolean)[0] ?? "";
    findings.push({
      domain: 1,
      severity: "warn",
      title: "Secret-shaped string in working tree",
      detail:
        "A token matching a live-secret pattern was found in a tracked file. Verify whether it is a real credential or a documented pattern before dismissing.",
      source: hit ? `${f}:${hit.split(":")[0]}` : f,
      evidence: maskLine(hit.replace(/^\d+:/, "").slice(0, 80)),
      fix: {
        title: "Remove or rotate the exposed secret",
        risk: "A live credential committed to a file is readable by anyone with repo access.",
        command: `# verify it is live, then remove from the file and rotate at the provider\n$EDITOR ${f}`,
        guided: true,
        ...confirmRequiredFix("Touches a possibly-live credential — must be verified and rotated by a human, never auto-edited."),
      },
    });
  }

  // Tracked .env files are a finding in themselves.
  const isGit = sh("git", ["rev-parse", "--is-inside-work-tree"], root) === "true";
  if (isGit) {
    const envFiles = sh("git", ["ls-files"], root)
      .split("\n")
      .filter((l) => /(^|\/)\.env(\..+)?$/.test(l));
    for (const env of envFiles) {
      findings.push({
        domain: 1,
        severity: "warn",
        title: "Tracked .env file",
        detail: "A .env file is committed to version control. These routinely carry live secrets.",
        source: `git ls-files → ${env}`,
        evidence: env,
        fix: {
          title: "Untrack the .env and ignore it",
          risk: "Secrets in a tracked .env persist in history even after deletion.",
          command: `git rm --cached ${env} && printf '\\n.env\\n' >> ${join(root, ".gitignore")}`,
          // Deliberately NOT auto-safe: the .gitignore line alone doesn't clear this
          // finding (the file is already tracked), and the real fix (`git rm --cached`)
          // mutates the git index — ambiguous enough to default to confirm-required.
          ...confirmRequiredFix("Untracking requires a git index mutation (git rm --cached) — not a pure file-permission/log change."),
        },
      });
    }

    // Git history probe (only if there are commits).
    const commits = Number(sh("git", ["rev-list", "--all", "--count"], root) || "0");
    if (commits > 0) {
      const histRaw = sh("bash", [
        "-c",
        `cd ${JSON.stringify(root)} && git log -p --all 2>/dev/null | grep -aInE 'AKIA[0-9A-Z]{16}|gh[porsu]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}' | head -5`,
      ]);
      if (histRaw) {
        findings.push({
          domain: 1,
          severity: "crit",
          title: "Secret in git history",
          detail:
            "A secret-shaped blob exists in git history even if removed from HEAD. History rewrite + rotation required.",
          source: "git log -p --all",
          evidence: maskLine(histRaw.split("\n")[0].slice(0, 80)),
          fix: {
            title: "Purge from history and rotate",
            risk: "Secrets in history are recoverable from any clone.",
            command: "# rotate the secret at its provider, then rewrite history (git filter-repo)",
            guided: true,
            ...confirmRequiredFix("History rewrite + live credential rotation — irreversible and provider-side."),
          },
        });
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Domain 2 — Credential Hygiene
// ---------------------------------------------------------------------------

function scanCredentialHygiene(configText: string, configSecure: boolean): Finding[] {
  const findings: Finding[] = [];

  // Plaintext secrets inside openclaw.json.
  const secretKey = /"(token|secret|apiKey|_authToken|password|aws_secret_access_key)"\s*:\s*"([^"]+)"/;
  configText.split("\n").forEach((line, i) => {
    const m = line.match(secretKey);
    if (m && m[2] && m[2].length > 6 && !m[2].includes("SecretRef") && !m[2].startsWith("$")) {
      findings.push({
        domain: 2,
        severity: configSecure ? "warn" : "crit",
        title: `Plaintext ${m[1]} in config`,
        detail: configSecure
          ? "A long-lived credential is stored unencrypted in the config. Mitigated by 0600 perms + loopback gateway, but a SecretRef/keychain-backed value is stronger."
          : "A long-lived credential is stored unencrypted in a config file that is not owner-only.",
        source: `openclaw.json:${i + 1} · key ${m[1]}`,
        evidence: `"${m[1]}": "${mask(m[2])}"`,
        fix: {
          title: `Rotate / vault the ${m[1]}`,
          risk: "Anyone who can read the config file can read this credential verbatim.",
          command:
            m[1] === "token"
              ? "openclaw gateway auth rotate   # regenerate + rewrite; then confirm services reconnect"
              : "# move to a SecretRef (keychain/1Password) and rotate at the provider",
          guided: true,
          ...confirmRequiredFix("Rotating a live auth credential can disconnect active sessions — needs a human's go-ahead."),
        },
      });
    }
  });

  // Plaintext credential stores in $HOME.
  const stores: Array<[string, RegExp | null]> = [
    [join(HOME, ".git-credentials"), /./],
    [join(HOME, ".netrc"), /password|login/i],
    [join(HOME, ".npmrc"), /_authToken/i],
    [join(HOME, ".aws", "credentials"), /aws_secret_access_key/i],
    [join(HOME, ".pgpass"), /./],
  ];
  for (const [path, probe] of stores) {
    if (!existsSync(path)) continue;
    let hasSecret = true;
    if (probe) {
      try {
        hasSecret = probe.test(readFileSync(path, "utf8"));
      } catch {
        hasSecret = true;
      }
    }
    if (hasSecret) {
      const perm = permOctal(path) ?? "???";
      findings.push({
        domain: 2,
        severity: otherPerm(path) > 0 ? "crit" : "warn",
        title: `Plaintext credential store: ${path.replace(HOME, "~")}`,
        detail: "A well-known plaintext credential file is present on disk.",
        source: `${path.replace(HOME, "~")} (perm ${perm})`,
        evidence: `present · perm ${perm}`,
        fix: {
          title: "Migrate to a credential helper / keychain",
          risk: "Plaintext credentials on disk are read by any process running as you.",
          command: `chmod 600 ${path}   # minimum; prefer a keychain-backed helper`,
          ...autoSafeFix("Chmod-only, on a file already owned by this account — tightens, never widens, access.", {
            kind: "chmod",
            target: path,
            mode: "600",
          }),
        },
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Domain 3 — File Permission Health
// ---------------------------------------------------------------------------

function scanFilePermissions(): Finding[] {
  const findings: Finding[] = [];
  const sshDir = join(HOME, ".ssh");

  if (existsSync(sshDir)) {
    for (const name of readdirSync(sshDir)) {
      const full = join(sshDir, name);
      const isPriv =
        (/^id_/.test(name) && !name.endsWith(".pub")) || name.endsWith(".pem");
      if (!isPriv) continue;
      const perm = permOctal(full);
      if (perm && perm !== "600" && perm !== "400") {
        findings.push({
          domain: 3,
          severity: otherPerm(full) > 0 ? "crit" : "warn",
          title: `Loose permissions on SSH private key`,
          detail: `Private key ${name} is ${perm}; expected 600 or 400.`,
          source: `${full.replace(HOME, "~")} (perm ${perm})`,
          evidence: `perm ${perm}`,
          fix: {
            title: "Tighten key permissions",
            risk: "Other local users/processes can read your private key.",
            command: `chmod 600 ${full}`,
            ...autoSafeFix("Chmod-only, on a private key already owned by this account — tightens, never widens, access.", {
              kind: "chmod",
              target: full,
              mode: "600",
            }),
          },
        });
      }
    }
  }

  // World/group-readable sensitive files.
  const sensitive = [
    CONFIG_PATH,
    join(HOME, ".aws", "credentials"),
    join(HOME, ".netrc"),
    join(HOME, ".git-credentials"),
    join(HOME, ".ssh", "config"),
  ];
  for (const path of sensitive) {
    const other = otherPerm(path);
    if (other > 0) {
      const perm = permOctal(path) ?? "???";
      findings.push({
        domain: 3,
        severity: "warn",
        title: `World/other-readable sensitive file`,
        detail: `${path.replace(HOME, "~")} is readable beyond its owner (perm ${perm}).`,
        source: `${path.replace(HOME, "~")} (perm ${perm})`,
        evidence: `perm ${perm}`,
        fix: {
          title: "Restrict to owner only",
          risk: "Other local accounts can read this file.",
          command: `chmod 600 ${path}`,
          ...autoSafeFix("Chmod-only, on a file already owned by this account — tightens, never widens, access.", {
            kind: "chmod",
            target: path,
            mode: "600",
          }),
        },
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Domain 4 — Access & Config Safety
// ---------------------------------------------------------------------------

function scanAccessConfig(config: any, configText: string): Finding[] {
  const findings: Finding[] = [];
  const gw = config?.gateway ?? {};

  // allowInsecureAuth anywhere in the gateway config.
  const insecure =
    gw?.controlUi?.allowInsecureAuth === true || gw?.auth?.allowInsecureAuth === true;
  if (insecure) {
    findings.push({
      domain: 4,
      severity: "crit",
      title: "Control-UI insecure auth enabled",
      detail: "The gateway accepts insecure authentication — an auth bypass.",
      source: `openclaw.json:${lineOf(configText, /allowInsecureAuth/)} · gateway.controlUi.allowInsecureAuth`,
      evidence: "allowInsecureAuth: true",
      fix: {
        title: "Disable insecure control-UI auth",
        risk: "Weakens or bypasses authentication on the gateway control UI.",
        command:
          "cp ~/.openclaw/openclaw.json ~/.openclaw/openclaw.json.bak && openclaw config set gateway.controlUi.allowInsecureAuth false && launchctl kickstart -k gui/$(id -u)/ai.openclaw.gateway",
        ...confirmRequiredFix("Touches gateway auth config and restarts a live service — never auto-applied."),
      },
    });
  }

  // Gateway bind exposure.
  const bind = String(gw?.bind ?? "").toLowerCase();
  if (bind && !/loopback|127\.0\.0\.1|localhost|::1/.test(bind)) {
    findings.push({
      domain: 4,
      severity: "crit",
      title: "Gateway bound beyond loopback",
      detail: `Gateway bind is "${bind}" — reachable from the network.`,
      source: `openclaw.json:${lineOf(configText, /"bind"/)} · gateway.bind`,
      evidence: `bind: ${bind}`,
      fix: {
        title: "Bind the gateway to loopback",
        risk: "A network-reachable gateway dramatically widens attack surface.",
        command: "openclaw config set gateway.bind loopback && launchctl kickstart -k gui/$(id -u)/ai.openclaw.gateway",
        ...confirmRequiredFix("Touches network-facing gateway config and restarts a live service — never auto-applied."),
      },
    });
  }

  // Listening sockets bound to non-loopback interfaces.
  const lsof = sh("lsof", ["-iTCP", "-sTCP:LISTEN", "-nP"]);
  const exposed = lsof
    .split("\n")
    .slice(1)
    .filter((l) => /\s\*:|\s0\.0\.0\.0:|\s\[::\]:/.test(l))
    .filter((l) => l.trim());

  const seen = new Set<string>();
  const benign: string[] = [];
  const airplayPorts: string[] = []; // one service, may bind several ports
  for (const line of exposed) {
    const cols = line.split(/\s+/);
    const cmd = cols[0] ?? "?";
    const nameCol = cols.find((c) => /\*:|0\.0\.0\.0:|\[::\]:/.test(c)) ?? "";
    const port = nameCol.split(":").pop() ?? "?";
    const key = `${cmd}:${port}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const isAirplay = /ControlCe/i.test(cmd) && (port === "7000" || port === "5000");
    const isKnownConsumer = /rapportd|Spotify|sharingd|Dropbox|Google/i.test(cmd);

    if (isAirplay) {
      if (!airplayPorts.includes(port)) airplayPorts.push(port);
    } else if (isKnownConsumer) {
      benign.push(`${cmd} ${nameCol}`);
    } else {
      findings.push({
        domain: 4,
        severity: "warn",
        title: `Unrecognized service listening on all interfaces`,
        detail: `${cmd} is bound to ${nameCol}. Confirm this service should accept off-host connections.`,
        source: "lsof -iTCP -sTCP:LISTEN -nP",
        evidence: `${cmd} ${nameCol} (LISTEN)`,
        fix: {
          title: "Restrict or disable the listener",
          risk: "Unknown network-facing services are unvetted attack surface.",
          command: `# identify: lsof -nP -iTCP:${port} -sTCP:LISTEN  — then bind to loopback or stop it`,
          guided: true,
          ...confirmRequiredFix("Unidentified network-facing process — stopping the wrong service could break something else."),
        },
      });
    }
  }
  if (airplayPorts.length) {
    const ports = airplayPorts.map((p) => `*:${p}`).join(", ");
    findings.push({
      domain: 4,
      severity: "warn",
      title: "AirPlay Receiver listening on all interfaces",
      detail: `ControlCenter (AirPlay Receiver) is bound to ${ports} — a network-exposed media receiver and a known LAN attack surface.`,
      source: "lsof -iTCP -sTCP:LISTEN -nP",
      evidence: `ControlCe ${ports} (LISTEN)`,
      fix: {
        title: "Turn off AirPlay Receiver (if unused)",
        risk: `Network-exposed receiver on ${ports}.`,
        command:
          "# System Settings → General → AirDrop & Handoff → AirPlay Receiver → Off (no safe headless toggle)",
        guided: true,
        ...confirmRequiredFix("A user-facing system feature toggle with no safe CLI path — a human decides if they use it."),
      },
    });
  }
  if (benign.length) {
    findings.push({
      domain: 4,
      severity: "info",
      title: "Consumer LAN listeners (expected)",
      detail: `Standard Apple/consumer services listening on the LAN: ${benign.join(", ")}. Expected on a personal Mac; no action needed.`,
      source: "lsof -iTCP -sTCP:LISTEN -nP",
      evidence: benign.slice(0, 3).join(" · "),
    });
  }

  // sshd hardening (only matters if Remote Login is on).
  const sshdPath = "/etc/ssh/sshd_config";
  if (existsSync(sshdPath)) {
    const sshd = sh("grep", [
      "-InE",
      "^\\s*(PasswordAuthentication|PermitRootLogin|PermitEmptyPasswords)\\s+",
      sshdPath,
    ]);
    if (/PermitRootLogin\s+yes/i.test(sshd)) {
      findings.push({
        domain: 4,
        severity: "crit",
        title: "SSH permits root login",
        detail: "sshd_config allows direct root login.",
        source: `${sshdPath}`,
        evidence: "PermitRootLogin yes",
        fix: {
          title: "Disable root SSH login",
          risk: "Direct root login removes an accountability + brute-force barrier.",
          command: "# set 'PermitRootLogin no' in /etc/ssh/sshd_config, then reload sshd",
          guided: true,
          ...confirmRequiredFix("System-wide sshd config, needs root — well outside 'a file I own'."),
        },
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Domain 5 — Incident Readiness
// ---------------------------------------------------------------------------

function scanIncidentReadiness(): Finding[] {
  const findings: Finding[] = [];
  const logsDir = join(HOME, ".openclaw", "logs");

  // Gateway log present & recent?
  const gwLog = join(logsDir, "gateway.log");
  if (!existsSync(gwLog)) {
    findings.push({
      domain: 5,
      severity: "warn",
      title: "No gateway log",
      detail: "gateway.log is absent — no operational audit trail for the gateway.",
      source: `${gwLog.replace(HOME, "~")}`,
      evidence: "missing",
    });
  }

  // Unbounded error log.
  const errLog = join(logsDir, "gateway.err.log");
  const errSize = fileSize(errLog);
  if (errSize > 100 * 1024 ** 2) {
    findings.push({
      domain: 5,
      severity: "info",
      title: "Unrotated error log",
      detail: `gateway.err.log is ${human(errSize)} with no rotation — disk pressure and slow forensics.`,
      source: `${errLog.replace(HOME, "~")}`,
      evidence: human(errSize),
      fix: {
        title: "Archive & rotate the error log",
        risk: "Unbounded log growth; slower incident review.",
        command: `trash ${errLog}   # recoverable; gateway recreates it`,
        ...autoSafeFix("Truncates a log file this account owns; a snapshot of its tail is captured before truncation.", {
          kind: "truncate-log",
          target: errLog,
        }),
      },
    });
  }

  // Audit trail: daily memory notes.
  const memDir = join(WORKSPACE, "memory");
  const dailyNotes = existsSync(memDir)
    ? readdirSync(memDir).filter((f) => /^\d{4}-\d{2}-\d{2}.*\.md$/.test(f))
    : [];
  if (dailyNotes.length === 0) {
    findings.push({
      domain: 5,
      severity: "warn",
      title: "No memory audit trail",
      detail: "No dated memory notes found — scan/fix history is not being recorded.",
      source: `${memDir.replace(HOME, "~")}`,
      evidence: "0 daily notes",
    });
  }

  // Guardrails present.
  for (const g of ["AGENTS.md", "SOUL.md"]) {
    const gp = join(WORKSPACE, g);
    if (!existsSync(gp)) {
      findings.push({
        domain: 5,
        severity: "crit",
        title: `Missing guardrail file: ${g}`,
        detail: `${g} defines the agent's hard rules and confirmation gates. Its absence removes the safety contract.`,
        source: `${gp.replace(HOME, "~")}`,
        evidence: "missing",
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

function domainScore(findings: Finding[]): number {
  return Math.max(0, 100 - findings.reduce((s, f) => s + DEDUCTION[f.severity], 0));
}
function band(score: number): "green" | "amber" | "red" {
  return score >= 80 ? "green" : score >= 50 ? "amber" : "red";
}
function grade(overall: number): string {
  return overall >= 90 ? "A" : overall >= 80 ? "B" : overall >= 70 ? "C" : overall >= 60 ? "D" : "F";
}
function mathFor(findings: Finding[]): string {
  if (!findings.length) return "100 (no findings)";
  const parts = findings.map((f) => `${DEDUCTION[f.severity]} (${f.title})`).join(" − ");
  return `100 − ${parts} = ${domainScore(findings)}`;
}

// ---------------------------------------------------------------------------
// HTML dashboard
// ---------------------------------------------------------------------------

const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function renderHtml(
  domainFindings: Finding[][],
  scores: number[],
  overall: number,
  when: Date,
  host: string,
): string {
  const gradeLetter = grade(overall);
  const gradeBand = band(overall);
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone: "America/Chicago",
    weekday: "long",
    month: "long",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  }).format(when);

  const cards = DOMAINS.map((name, i) => {
    const s = scores[i];
    const b = band(s);
    const n = domainFindings[i].length;
    return `    <div class="card ${b}">
      <h3>${i + 1} · ${esc(name)}</h3>
      <div class="score"><b>${s}</b><span>/100</span></div>
      <div class="bar"><i style="width:${s}%"></i></div>
      <div class="fcount">${n} finding${n === 1 ? "" : "s"} · <span class="pill ${b}">${b}</span></div>
    </div>`;
  }).join("\n");

  const allFindings = domainFindings.flat().sort((a, b) => {
    const order = { crit: 0, warn: 1, info: 2 };
    return order[a.severity] - order[b.severity];
  });

  const rows = allFindings.length
    ? allFindings
        .map(
          (f) => `        <tr>
          <td class="sev ${f.severity === "crit" ? "c" : f.severity === "warn" ? "w" : "i"}">${SEV_LABEL[f.severity]}</td>
          <td>${esc(DOMAINS[f.domain - 1])}</td>
          <td><b>${esc(f.title)}.</b> ${esc(f.detail)}</td>
          <td><code>${esc(f.source)}</code></td>
          <td><code>${esc(f.evidence)}</code></td>
        </tr>`,
        )
        .join("\n")
    : `        <tr><td colspan="5" style="text-align:center;color:var(--muted)">No findings — every domain clean.</td></tr>`;

  const fixes = allFindings.filter((f) => f.fix);
  const queue = fixes.length
    ? fixes
        .map(
          (f) => `      <li class="${f.severity === "crit" ? "" : f.severity === "warn" ? "w" : "i"}">
        <h4>${esc(f.fix!.title)}</h4>
        <p class="risk">Risk: ${esc(f.fix!.risk)}</p>
        <pre>${esc(f.fix!.command)}</pre>
        <span class="apply">${f.fix!.guided ? "Guided — " : "Run with "}<code>apply fix N</code>${f.fix!.guided ? " walks you through it" : ""}</span>
      </li>`,
        )
        .join("\n")
    : `      <li class="i"><h4>Nothing to remediate</h4><p class="risk">No findings produced a fix. Re-scan after any config change.</p></li>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Posture — ${esc(fmt)}</title>
<style>
  :root{
    --bg:#0f1216; --panel:#171b21; --panel2:#1d222a; --ink:#e8edf3; --muted:#93a0b0;
    --line:#2a313b; --green:#2fbf71; --amber:#f5a524; --red:#ef4444;
    --greenbg:rgba(47,191,113,.12); --amberbg:rgba(245,165,36,.12); --redbg:rgba(239,68,68,.12);
    --gradecolor:var(--${gradeBand === "green" ? "green" : gradeBand === "amber" ? "amber" : "red"});
    --gradebg:var(--${gradeBand === "green" ? "greenbg" : gradeBand === "amber" ? "amberbg" : "redbg"});
  }
  @media (prefers-color-scheme:light){
    :root{--bg:#f4f6f9;--panel:#fff;--panel2:#f7f9fc;--ink:#16202b;--muted:#5c6b7a;--line:#e2e8f0;
      --greenbg:rgba(47,191,113,.10);--amberbg:rgba(245,165,36,.12);--redbg:rgba(239,68,68,.10);}
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    -webkit-font-smoothing:antialiased;padding:32px 20px 60px}
  .wrap{max-width:960px;margin:0 auto}
  header{display:flex;flex-wrap:wrap;align-items:center;gap:20px;justify-content:space-between;
    padding:22px 26px;background:var(--panel);border:1px solid var(--line);border-radius:16px}
  .brand{font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:0 0 4px}
  h1{margin:0;font-size:22px;font-weight:650}
  .meta{color:var(--muted);font-size:13px;margin-top:6px}
  .grade{display:flex;align-items:center;gap:16px}
  .gradebubble{width:92px;height:92px;border-radius:50%;display:grid;place-items:center;
    font-size:44px;font-weight:800;border:3px solid var(--gradecolor);color:var(--gradecolor);background:var(--gradebg)}
  .gradebubble small{display:block;font-size:11px;font-weight:600;letter-spacing:.1em;color:var(--muted)}
  .overall{text-align:right}
  .overall .num{font-size:30px;font-weight:750}
  .overall .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.1em}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:14px;margin:22px 0}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 16px 14px;
    position:relative;overflow:hidden}
  .card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:5px}
  .card.green::before{background:var(--green)} .card.amber::before{background:var(--amber)} .card.red::before{background:var(--red)}
  .card h3{margin:0 0 10px;font-size:13px;font-weight:600;color:var(--muted);padding-left:6px}
  .score{display:flex;align-items:baseline;gap:6px;padding-left:6px}
  .score b{font-size:34px;font-weight:780;line-height:1}
  .score span{color:var(--muted);font-size:13px}
  .bar{height:6px;border-radius:99px;background:var(--panel2);margin:12px 0 8px;overflow:hidden}
  .bar i{display:block;height:100%;border-radius:99px}
  .green .bar i{background:var(--green)} .amber .bar i{background:var(--amber)} .red .bar i{background:var(--red)}
  .fcount{font-size:12px;color:var(--muted);padding-left:6px}
  .pill{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;text-transform:uppercase;letter-spacing:.04em}
  .pill.green{background:var(--greenbg);color:var(--green)} .pill.amber{background:var(--amberbg);color:var(--amber)} .pill.red{background:var(--redbg);color:var(--red)}
  section{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px 24px;margin-top:22px}
  section h2{margin:0 0 14px;font-size:16px}
  .scroll{overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:13.5px;min-width:640px}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
  td code{background:var(--panel2);padding:1px 6px;border-radius:6px;font-size:12.5px;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .sev{font-weight:700;white-space:nowrap}
  .sev.c{color:var(--red)} .sev.w{color:var(--amber)} .sev.i{color:var(--muted)}
  .rem{counter-reset:r;padding-left:0}
  .rem li{list-style:none;background:var(--panel2);border:1px solid var(--line);border-radius:12px;
    padding:14px 16px 14px 52px;margin-bottom:12px;position:relative}
  .rem li::before{counter-increment:r;content:counter(r);position:absolute;left:14px;top:14px;
    width:26px;height:26px;border-radius:50%;background:var(--red);color:#fff;font-weight:700;
    display:grid;place-items:center;font-size:13px}
  .rem li.w::before{background:var(--amber)} .rem li.i::before{background:var(--muted)}
  .rem h4{margin:0 0 4px;font-size:14px}
  .rem .risk{color:var(--muted);font-size:13px;margin:0 0 8px}
  .rem pre{margin:0;background:var(--bg);border:1px solid var(--line);border-radius:8px;
    padding:9px 12px;overflow-x:auto;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;white-space:pre-wrap}
  .apply{display:inline-block;margin-top:6px;font-size:12px;color:var(--muted)}
  .apply code{background:var(--bg);padding:1px 6px;border-radius:5px}
  footer{color:var(--muted);font-size:12px;text-align:center;margin-top:26px;line-height:1.7}
  .note{font-size:12px;color:var(--muted);margin-top:10px}
</style>
</head>
<body>
<div class="wrap">

  <header>
    <div>
      <p class="brand">Cooper · sec-posture</p>
      <h1>Local Security Posture Report</h1>
      <div class="meta">Host <b>${esc(host)}</b> · ${esc(fmt)} · read-only scan</div>
    </div>
    <div class="grade">
      <div class="overall">
        <div class="num">${overall}<span style="font-size:16px;color:var(--muted)">/100</span></div>
        <div class="lbl">Overall</div>
      </div>
      <div class="gradebubble"><span>${gradeLetter}<small>GRADE</small></span></div>
    </div>
  </header>

  <div class="cards">
${cards}
  </div>

  <section>
    <h2>Findings <span style="color:var(--muted);font-weight:400;font-size:13px">— every row cited to source, secrets masked</span></h2>
    <div class="scroll">
    <table>
      <thead><tr><th>Sev</th><th>Domain</th><th>Finding</th><th>Source</th><th>Evidence (masked)</th></tr></thead>
      <tbody>
${rows}
      </tbody>
    </table>
    </div>
  </section>

  <section>
    <h2>Staged Remediation Queue <span style="color:var(--muted);font-weight:400;font-size:13px">— nothing runs until you say so</span></h2>
    <ol class="rem">
${queue}
    </ol>
  </section>

  <footer>
    Generated by Cooper · <b>sec-posture</b> (Node/TS scanner) · read-only scan, secrets masked to last 4 chars.<br>
    Scoring: each domain 100 − Σ(🔴 40 / 🟡 15 / 🟢 5). Overall = mean of 5 domains → A≥90 · B 80–89 · C 70–79 · D 60–69 · F&lt;60.<br>
    No fix has been executed. Confirmation required before any change.
  </footer>

</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

/**
 * Resolve a --domain value (1-based index or keyword) to a 0-based domain index.
 * Keywords are intentionally loose so a chat message like "audit credential
 * hygiene" can be mapped without the caller knowing the numbering.
 */
function resolveDomain(value: string): number | null {
  const v = value.trim().toLowerCase();
  if (/^[1-5]$/.test(v)) return Number(v) - 1;
  const keywords: string[][] = [
    ["secret", "exposure", "leak"],
    ["credential", "hygiene", "password", "token"],
    ["permission", "file", "ssh", "perm"],
    ["access", "config", "firewall", "network", "listen", "port", "airplay", "gateway"],
    ["incident", "readiness", "log", "memory", "guardrail", "audit"],
  ];
  const idx = keywords.findIndex((words) => words.some((w) => v.includes(w)));
  return idx >= 0 ? idx : null;
}

/** Run exactly one domain's collector — used for chat-grounded, scoped re-scans. */
function runSingleDomain(
  idx: number,
  scanRoot: string,
  configText: string,
  config: any,
  configSecure: boolean,
): Finding[] {
  switch (idx) {
    case 0:
      return scanSecretExposure(scanRoot);
    case 1:
      return scanCredentialHygiene(configText, configSecure);
    case 2:
      return scanFilePermissions();
    case 3:
      return scanAccessConfig(config, configText);
    case 4:
      return scanIncidentReadiness();
    default:
      throw new Error(`invalid domain index ${idx}`);
  }
}

function main() {
  const args = process.argv.slice(2);
  const wantJson = args.includes("--json");
  const rootIdx = args.indexOf("--root");
  const scanRoot = rootIdx >= 0 ? args[rootIdx + 1] : WORKSPACE;
  const domainIdx = args.indexOf("--domain");

  const configText = existsSync(CONFIG_PATH) ? readFileSync(CONFIG_PATH, "utf8") : "{}";
  let config: any = {};
  try {
    config = JSON.parse(configText);
  } catch {
    /* tolerate comments/trailing commas: fall back to regex-only checks */
  }
  const configSecure = otherPerm(CONFIG_PATH) <= 0; // owner-only?

  // --domain <1-5|keyword>: run ONE domain's read-only collector and print its
  // result. Used by the dashboard chat server to hand Cooper fresh evidence
  // before answering a domain-specific question. Deliberately does NOT touch
  // posture-report.html / posture.json / reports/ — those are the canonical
  // 5-domain artifacts, and a partial run has no business overwriting them.
  if (domainIdx >= 0) {
    const resolved = resolveDomain(args[domainIdx + 1] ?? "");
    if (resolved === null) {
      console.error(`Unknown --domain value "${args[domainIdx + 1]}". Expected 1-5 or a domain keyword.`);
      process.exit(1);
    }
    const findings = runSingleDomain(resolved, scanRoot, configText, config, configSecure);
    const score = domainScore(findings);
    const result = {
      domain: DOMAINS[resolved],
      domainIndex: resolved + 1,
      score,
      band: band(score),
      math: mathFor(findings),
      findings: findings.map((f) => ({
        severity: f.severity,
        title: f.title,
        detail: f.detail,
        source: f.source,
        evidence: f.evidence,
      })),
      scannedAt: new Date().toISOString(),
    };
    if (wantJson) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(`${result.domain}: ${score}/100 (${result.band}) — ${result.math}`);
      for (const f of result.findings) console.log(`  - ${f.severity} · ${f.title} · ${f.source}`);
    }
    return;
  }

  const domainFindings: Finding[][] = [
    scanSecretExposure(scanRoot),
    scanCredentialHygiene(configText, configSecure),
    scanFilePermissions(),
    scanAccessConfig(config, configText),
    scanIncidentReadiness(),
  ];

  const scores = domainFindings.map(domainScore);
  const overall = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  const when = new Date();
  const host = sh("hostname", ["-s"]) || hostname();

  // ---- artifacts ----
  const html = renderHtml(domainFindings, scores, overall, when, host);
  const latest = join(SKILL_DIR, "posture-report.html");
  writeFileSync(latest, html);

  const reportsDir = join(SKILL_DIR, "reports");
  mkdirSync(reportsDir, { recursive: true });
  const stamp = new Intl.DateTimeFormat("sv-SE", {
    timeZone: "America/Chicago",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  })
    .format(when)
    .replace(" ", "-")
    .replace(":", "");
  const archive = join(reportsDir, `posture-${stamp}.html`);
  writeFileSync(archive, html);

  const jsonSummary = {
    host,
    generatedAt: when.toISOString(),
    overall,
    grade: grade(overall),
    domains: DOMAINS.map((name, i) => ({
      name,
      score: scores[i],
      band: band(scores[i]),
      math: mathFor(domainFindings[i]),
      findings: domainFindings[i].map((f) => ({
        severity: f.severity,
        title: f.title,
        detail: f.detail,
        source: f.source,
        evidence: f.evidence,
        fix: f.fix
          ? {
              title: f.fix.title,
              risk: f.fix.risk,
              command: f.fix.command,
              guided: !!f.fix.guided,
              tier: f.fix.tier,
              tierReason: f.fix.tierReason,
              autoFix: f.fix.autoFix ?? null,
            }
          : null,
      })),
    })),
    reportPath: latest,
    archivePath: archive,
  };
  writeFileSync(join(SKILL_DIR, "posture.json"), JSON.stringify(jsonSummary, null, 2));

  // Timestamped JSON snapshot alongside the HTML archive — this is what powers
  // the dashboard's scan-history trend line and since-last-scan diff. Written
  // going forward; older archives that predate this field simply have no
  // JSON sibling and are excluded from history (nothing to diff against).
  writeFileSync(join(reportsDir, `posture-${stamp}.json`), JSON.stringify(jsonSummary, null, 2));

  // ---- compact chat table ----
  const pad = (s: string, n: number) => s.padEnd(n);
  const badge = (b: string) => (b === "green" ? "🟢" : b === "amber" ? "🟡" : "🔴");
  console.log("");
  console.log(`  Cooper · sec-posture — read-only scan of ${host}`);
  console.log("  " + "─".repeat(46));
  console.log(`  ${pad("Domain", 26)}${pad("Score", 7)}Band`);
  DOMAINS.forEach((name, i) => {
    console.log(`  ${pad(name, 26)}${pad(String(scores[i]), 7)}${badge(band(scores[i]))}`);
  });
  console.log("  " + "─".repeat(46));
  console.log(`  ${pad("OVERALL", 26)}${pad(String(overall), 7)}${grade(overall)}`);
  console.log("");
  console.log(`  Findings: ${domainFindings.flat().length} · Report: ${latest}`);
  console.log(`  Archive:  ${archive}`);
  console.log("");

  if (wantJson) console.log(JSON.stringify(jsonSummary, null, 2));

  // Render in the browser (macOS `open`). Read-only w.r.t. the machine's posture.
  if (args.includes("--open")) {
    try {
      execFileSync("open", [latest], { stdio: "ignore" });
      console.log(`  Opened ${latest} in the default browser.`);
    } catch {
      console.log(`  Could not auto-open; open manually: ${latest}`);
    }
  }
}

main();
