#!/usr/bin/env node
/**
 * Remediation Agent — executes ONLY the narrow, hardcoded AUTO-SAFE actions
 * classified by scan.ts (see `autoSafeFix(...)` call sites there — that grep
 * is the complete list of what can ever be auto-executed). This module is
 * deliberately NOT model-driven: classification and execution are both plain
 * code, re-validated independently here (defense in depth) so a bug or a
 * mislabeled finding in scan.ts can't widen what gets executed.
 *
 * Every applied fix is logged to memory/YYYY-MM-DD.md with a full before/after
 * diff BEFORE the function returns — the log write happens synchronously in
 * the same call that performs the mutation, so there is no window where a
 * change exists but isn't yet recorded.
 *
 * Three whitelisted kinds only:
 *   chmod            - tighten permissions on a small fixed set of paths we own
 *   truncate-log      - truncate exactly one known gateway log path, in place
 *   gitignore-append   - append a validated .env-family pattern to a workspace .gitignore
 * Anything else throws rather than silently no-op'ing — a new kind must be
 * added here explicitly, on purpose, never inferred.
 */

import { execFileSync } from "node:child_process";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, sep } from "node:path";

const HOME = homedir();
const WORKSPACE = join(HOME, ".openclaw", "workspace");
const MEMORY_DIR = join(WORKSPACE, "memory");

// ---------------------------------------------------------------------------
// Whitelists — re-validated here independently of whatever scan.ts labeled.
// ---------------------------------------------------------------------------

const FIXED_CHMOD_PATHS = new Set(
  [
    join(HOME, ".openclaw", "openclaw.json"),
    join(HOME, ".aws", "credentials"),
    join(HOME, ".netrc"),
    join(HOME, ".git-credentials"),
    join(HOME, ".ssh", "config"),
    join(HOME, ".npmrc"),
    join(HOME, ".pgpass"),
  ].map((p) => safeRealpath(p) ?? p),
);

function safeRealpath(p) {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}

function isAllowedChmodTarget(realTarget) {
  if (!realTarget.startsWith(HOME + sep)) return false;
  if (FIXED_CHMOD_PATHS.has(realTarget)) return true;
  const sshDir = join(HOME, ".ssh") + sep;
  if (realTarget.startsWith(sshDir)) {
    const name = realTarget.slice(sshDir.length);
    if (/^id_[^/]*$/.test(name) && !name.endsWith(".pub")) return true;
    if (name.endsWith(".pem")) return true;
  }
  return false;
}

const ALLOWED_TRUNCATE_LOG_TARGET = join(HOME, ".openclaw", "logs", "gateway.err.log");

function isAllowedGitignoreAppend(target, pattern) {
  if (!/^\.env(\..+)?$/.test(pattern)) return false;
  if (basename(target) !== ".gitignore") return false;
  const dir = safeRealpath(dirname(target));
  if (!dir) return false;
  return dir === WORKSPACE || dir.startsWith(WORKSPACE + sep);
}

// ---------------------------------------------------------------------------
// Logging — synchronous, completes before the caller gets control back.
// ---------------------------------------------------------------------------

function todayStamp() {
  return new Intl.DateTimeFormat("sv-SE", {
    timeZone: "America/Chicago",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date());
}
function nowStamp() {
  return new Intl.DateTimeFormat("en-US", {
    timeZone: "America/Chicago",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date());
}

function logAutoFix({ findingTitle, domainName, kind, target, before, after, note, tailSnapshot }) {
  mkdirSync(MEMORY_DIR, { recursive: true });
  const file = join(MEMORY_DIR, `${todayStamp()}.md`);
  const lines = [
    "",
    `### AUTO-FIX applied — ${findingTitle} (${domainName}) — ${nowStamp()} CDT`,
    `- Applied automatically by the Remediation Agent (AUTO-SAFE tier, \`${kind}\`) — no human confirmation required, per the hardcoded policy in scan.ts.`,
    `- **Before:** ${before}`,
    `- **After:**  ${after}`,
    note ? `- Note: ${note}` : null,
    tailSnapshot
      ? `- Tail of the file before truncation (last 50 lines, preserved for audit):\n\`\`\`\n${tailSnapshot.trim()}\n\`\`\``
      : null,
    `- Target: \`${target}\``,
    "",
  ]
    .filter((l) => l !== null)
    .join("\n");
  appendFileSync(file, lines);
  return file;
}

// ---------------------------------------------------------------------------
// The three whitelisted executors
// ---------------------------------------------------------------------------

function applyChmod(autoFix, ctx) {
  const { target, mode } = autoFix;
  const real = safeRealpath(target);
  if (!real) return { applied: false, error: `target does not exist: ${target}` };
  if (!isAllowedChmodTarget(real)) {
    return { applied: false, error: `target failed executor whitelist re-validation: ${real}` };
  }
  const before = (statSync(real).mode & 0o777).toString(8).padStart(3, "0");
  if (before === mode) {
    const logPath = logAutoFix({
      ...ctx,
      kind: "chmod",
      target: real,
      before,
      after: before,
      note: "already compliant — no change needed",
    });
    return { applied: true, noop: true, before, after: before, logPath, timestamp: new Date().toISOString() };
  }
  chmodSync(real, parseInt(mode, 8));
  const after = (statSync(real).mode & 0o777).toString(8).padStart(3, "0");
  const logPath = logAutoFix({ ...ctx, kind: "chmod", target: real, before, after });
  return { applied: true, before, after, logPath, timestamp: new Date().toISOString() };
}

function applyTruncateLog(autoFix, ctx) {
  const { target } = autoFix;
  if (target !== ALLOWED_TRUNCATE_LOG_TARGET) {
    return { applied: false, error: `target not in truncate-log allowlist: ${target}` };
  }
  if (!existsSync(target)) return { applied: false, error: "target does not exist" };
  const beforeSize = statSync(target).size;
  let tail = "";
  try {
    tail = execFileSync("tail", ["-n", "50", target], { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 });
  } catch {
    /* best-effort snapshot; truncation proceeds regardless */
  }
  writeFileSync(target, ""); // truncate in place — keeps the inode/fd valid for any writer holding it open
  const afterSize = statSync(target).size;
  const logPath = logAutoFix({
    ...ctx,
    kind: "truncate-log",
    target,
    before: `${beforeSize} bytes`,
    after: `${afterSize} bytes`,
    tailSnapshot: tail,
  });
  return { applied: true, before: beforeSize, after: afterSize, logPath, timestamp: new Date().toISOString() };
}

function applyGitignoreAppend(autoFix, ctx) {
  const { target, pattern } = autoFix;
  if (!isAllowedGitignoreAppend(target, pattern)) {
    return { applied: false, error: "gitignore target/pattern failed executor whitelist re-validation" };
  }
  const before = existsSync(target) ? readFileSync(target, "utf8") : "";
  if (before.split("\n").some((l) => l.trim() === pattern)) {
    const logPath = logAutoFix({
      ...ctx,
      kind: "gitignore-append",
      target,
      before: "(pattern already present)",
      after: "(no change — idempotent)",
    });
    return { applied: true, noop: true, logPath, timestamp: new Date().toISOString() };
  }
  const after = before + (before === "" || before.endsWith("\n") ? "" : "\n") + pattern + "\n";
  writeFileSync(target, after);
  const logPath = logAutoFix({
    ...ctx,
    kind: "gitignore-append",
    target,
    before: before || "(empty/missing)",
    after,
  });
  return { applied: true, logPath, timestamp: new Date().toISOString() };
}

/**
 * Apply one AUTO-SAFE finding's fix. `ctx` carries { findingTitle, domainName }
 * for the log entry. Never throws — returns { applied:false, error } on any
 * failure or whitelist rejection, so a caller can loop over many findings
 * without one bad entry aborting the rest.
 */
export function applyAutoFix(fix, ctx) {
  if (!fix?.autoFix) return { applied: false, error: "finding has no autoFix descriptor" };
  try {
    switch (fix.autoFix.kind) {
      case "chmod":
        return applyChmod(fix.autoFix, ctx);
      case "truncate-log":
        return applyTruncateLog(fix.autoFix, ctx);
      case "gitignore-append":
        return applyGitignoreAppend(fix.autoFix, ctx);
      default:
        return { applied: false, error: `unknown autoFix kind: ${fix.autoFix.kind}` };
    }
  } catch (err) {
    return { applied: false, error: String(err?.message ?? err) };
  }
}
