#!/usr/bin/env node
/**
 * vaultcheck — Security auditing tool that scans repos for accidentally committed secrets and API keys
 * Usage: node src/vaultcheck.js <command> [path] [options]
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Secret patterns ──────────────────────────────────────────────────────────
const PATTERNS = [
  { id: 'aws-key',         severity: 'CRITICAL', label: 'AWS Access Key ID',          re: /AKIA[0-9A-Z]{16}/g },
  { id: 'aws-secret',      severity: 'CRITICAL', label: 'AWS Secret Access Key',      re: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g },
  { id: 'github-token',    severity: 'CRITICAL', label: 'GitHub Personal Access Token', re: /ghp_[A-Za-z0-9]{36}/g },
  { id: 'github-oauth',    severity: 'CRITICAL', label: 'GitHub OAuth Token',          re: /gho_[A-Za-z0-9]{36}/g },
  { id: 'github-app',      severity: 'HIGH',     label: 'GitHub App Token',            re: /ghs_[A-Za-z0-9]{36}/g },
  { id: 'slack-token',     severity: 'HIGH',     label: 'Slack Bot Token',             re: /xox[baprs]-[0-9A-Za-z\-]{10,}/g },
  { id: 'slack-webhook',   severity: 'HIGH',     label: 'Slack Webhook URL',           re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]+/g },
  { id: 'stripe-key',      severity: 'CRITICAL', label: 'Stripe Secret Key',           re: /sk_live_[A-Za-z0-9]{24,}/g },
  { id: 'stripe-pub',      severity: 'LOW',      label: 'Stripe Publishable Key',      re: /pk_live_[A-Za-z0-9]{24,}/g },
  { id: 'twilio-sid',      severity: 'HIGH',     label: 'Twilio Account SID',          re: /AC[a-z0-9]{32}/g },
  { id: 'twilio-token',    severity: 'HIGH',     label: 'Twilio Auth Token',           re: /SK[a-z0-9]{32}/g },
  { id: 'sendgrid',        severity: 'HIGH',     label: 'SendGrid API Key',            re: /SG\.[A-Za-z0-9\-_.]{22}\.[A-Za-z0-9\-_.]{43}/g },
  { id: 'google-api',      severity: 'HIGH',     label: 'Google API Key',              re: /AIza[0-9A-Za-z\-_]{35}/g },
  { id: 'google-oauth',    severity: 'HIGH',     label: 'Google OAuth Client Secret',  re: /GOCSPX-[A-Za-z0-9\-_]{28}/g },
  { id: 'heroku-key',      severity: 'HIGH',     label: 'Heroku API Key',              re: /[hH]eroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g },
  { id: 'jwt',             severity: 'MEDIUM',   label: 'JWT Token',                  re: /eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*/g },
  { id: 'private-key',     severity: 'CRITICAL', label: 'Private Key Block',           re: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { id: 'generic-secret',  severity: 'MEDIUM',   label: 'Generic Secret Assignment',  re: /(?:secret|password|passwd|pwd|api_key|apikey|access_token|auth_token)\s*[:=]\s*["'][^"'\s]{8,}["']/gi },
  { id: 'generic-token',   severity: 'LOW',      label: 'Generic Token Assignment',   re: /(?:token|bearer)\s*[:=]\s*["'][A-Za-z0-9+/=\-_.]{16,}["']/gi },
  { id: 'conn-string',     severity: 'HIGH',     label: 'Database Connection String', re: /(mongodb|mysql|postgres|redis):\/\/[^"'\s]+:[^"'\s]+@[^"'\s]+/gi },
  { id: 'basic-auth-url',  severity: 'HIGH',     label: 'HTTP Basic Auth in URL',     re: /https?:\/\/[^:@\s]+:[^@\s]+@[a-zA-Z0-9.\-]+/g },
];

const SKIP_DIRS = new Set(['.git', 'node_modules', '.next', 'dist', 'build', '__pycache__', '.venv', 'venv', '.nyc_output', 'coverage']);
const SKIP_EXTS = new Set(['.png','.jpg','.jpeg','.gif','.svg','.ico','.woff','.woff2','.ttf','.eot','.mp4','.mp3','.pdf','.zip','.gz','.tar','.lock','.sum']);
const SKIP_FILES = new Set(['.gitignore','.env.example','.env.sample','.env.template','vaultcheck-report.json']);

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const SEVERITY_COLOR = { CRITICAL: '\x1b[31m', HIGH: '\x1b[33m', MEDIUM: '\x1b[36m', LOW: '\x1b[37m' };
const NC = '\x1b[0m'; const BOLD = '\x1b[1m'; const GREEN = '\x1b[32m'; const DIM = '\x1b[2m';

// ── File walking ──────────────────────────────────────────────────────────────
function* walkDir(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) { yield* walkDir(full); }
    else if (e.isFile()) { yield full; }
  }
}

function shouldScanFile(filePath) {
  const base = path.basename(filePath);
  const ext  = path.extname(filePath).toLowerCase();
  if (SKIP_FILES.has(base)) return false;
  if (SKIP_EXTS.has(ext)) return false;
  try { const stat = fs.statSync(filePath); if (stat.size > 1024 * 1024) return false; } catch { return false; }
  return true;
}

// ── Scanner ───────────────────────────────────────────────────────────────────
function scanFile(filePath) {
  if (!shouldScanFile(filePath)) return [];
  let content;
  try { content = fs.readFileSync(filePath, 'utf8'); } catch { return []; }
  const findings = [];
  const lines = content.split('\n');
  for (const pat of PATTERNS) {
    pat.re.lastIndex = 0;
    let m;
    while ((m = pat.re.exec(content)) !== null) {
      const lineNum = content.slice(0, m.index).split('\n').length;
      const lineText = lines[lineNum - 1] || '';
      const value = m[0];
      // Skip if it looks like a placeholder
      if (/your|example|placeholder|xxx+|test|dummy|fake|sample/i.test(value)) continue;
      findings.push({
        file: filePath,
        line: lineNum,
        col: m.index - content.lastIndexOf('\n', m.index - 1),
        severity: pat.severity,
        label: pat.label,
        id: pat.id,
        snippet: lineText.trim().slice(0, 120),
        match: value.slice(0, 40) + (value.length > 40 ? '...' : ''),
      });
    }
  }
  return findings;
}

function scanPath(targetPath) {
  const stat = fs.statSync(targetPath);
  const findings = [];
  let scanned = 0;
  if (stat.isFile()) {
    findings.push(...scanFile(targetPath)); scanned = 1;
  } else {
    for (const f of walkDir(targetPath)) {
      findings.push(...scanFile(f)); scanned++;
    }
  }
  return { findings, scanned };
}

// ── Commands ──────────────────────────────────────────────────────────────────
function scanCommand(targetPath, opts = {}) {
  const resolved = path.resolve(targetPath || '.');
  console.log(`\n${BOLD}🔐 vaultcheck — Secret Scanner${NC}`);
  console.log(`Scanning: ${resolved}\n`);

  const { findings, scanned } = scanPath(resolved);

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  if (findings.length === 0) {
    console.log(`${GREEN}✅ Clean! No secrets detected in ${scanned} file(s).${NC}\n`);
    return;
  }

  const bySev = {};
  for (const f of findings) {
    if (!bySev[f.severity]) bySev[f.severity] = [];
    bySev[f.severity].push(f);
  }

  for (const sev of ['CRITICAL','HIGH','MEDIUM','LOW']) {
    if (!bySev[sev]) continue;
    const col = SEVERITY_COLOR[sev];
    console.log(`${col}${BOLD}── ${sev} (${bySev[sev].length}) ${'─'.repeat(40 - sev.length)}${NC}`);
    for (const f of bySev[sev]) {
      console.log(`  ${col}${BOLD}[${f.severity}]${NC} ${f.label}`);
      console.log(`  ${DIM}File:${NC}    ${f.file}:${f.line}`);
      console.log(`  ${DIM}Match:${NC}   ${f.match}`);
      console.log(`  ${DIM}Snippet:${NC} ${f.snippet}`);
      console.log('');
    }
  }

  const summary = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) summary[f.severity]++;

  console.log('─'.repeat(50));
  console.log(`${BOLD}Files scanned: ${scanned} | Secrets found: ${findings.length}${NC}`);
  console.log(`  Critical: ${summary.CRITICAL}  High: ${summary.HIGH}  Medium: ${summary.MEDIUM}  Low: ${summary.LOW}`);

  if (opts.output) {
    const report = { scannedAt: new Date().toISOString(), scanned, total: findings.length, summary, findings };
    fs.writeFileSync(opts.output, JSON.stringify(report, null, 2));
    console.log(`\n📄 Report saved: ${opts.output}`);
  }

  if (!opts.noExit && summary.CRITICAL > 0) process.exit(1);
}

function listPatternsCommand() {
  console.log(`\n${BOLD}🔐 vaultcheck — Detection Patterns${NC}\n`);
  for (const sev of ['CRITICAL','HIGH','MEDIUM','LOW']) {
    const col = SEVERITY_COLOR[sev];
    const pats = PATTERNS.filter(p => p.severity === sev);
    console.log(`${col}${BOLD}${sev}${NC}`);
    pats.forEach(p => console.log(`  • ${p.label}  ${DIM}(${p.id})${NC}`));
    console.log('');
  }
}

function auditGitHistoryCommand(targetPath) {
  console.log(`\n${BOLD}🔍 vaultcheck — Git History Audit${NC}`);
  console.log('Note: This checks only the working tree. For full git history scanning,');
  console.log('      consider tools like git-secrets or truffleHog.\n');
  scanCommand(targetPath, { noExit: true });
}

// ── CLI ───────────────────────────────────────────────────────────────────────
const [,, cmd, arg1, ...rest] = process.argv;

if (!cmd || cmd === 'help') {
  console.log('vaultcheck — Secret & API Key Scanner\n');
  console.log('Commands:');
  console.log('  scan [path]              Scan a file or directory (default: current dir)');
  console.log('  scan [path] --out file   Save JSON report to file');
  console.log('  patterns                 List all detection patterns');
  console.log('  audit [path]             Audit mode (no exit code on findings)');
  console.log('\nExamples:');
  console.log('  node src/vaultcheck.js scan .');
  console.log('  node src/vaultcheck.js scan src/ --out report.json');
  console.log('  node src/vaultcheck.js patterns');
  process.exit(0);
}

if (cmd === 'scan') {
  const outIdx = rest.indexOf('--out');
  const output = outIdx !== -1 ? rest[outIdx + 1] : null;
  scanCommand(arg1 || '.', { output });
} else if (cmd === 'patterns') {
  listPatternsCommand();
} else if (cmd === 'audit') {
  auditGitHistoryCommand(arg1 || '.');
} else {
  console.error(`Unknown command: ${cmd}. Run 'node src/vaultcheck.js help'`);
  process.exit(1);
}
