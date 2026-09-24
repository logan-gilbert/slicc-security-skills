// sbr-scan — static scan of a delivered EDS repo (port of run_static_checks.py).
//
// Usage: sbr-scan --repo <vfs-path> [--out <dir>] [--source-url <repo url>]
//   --repo  repo in the VFS: `mount /mnt/site` (local folder) or `git clone <url> /workspace/site`
//   --out   output dir (default /workspace/security-review-out); writes <out>/findings.json
//
// Mechanical checks resolve to pass/fail; judgment checks come back as `review`
// with candidate evidence for sbr-adjudicate. Matched secret values are masked.

const fs = require('fs');
const cli = require('sliccy:cli');
const { exec } = require('sliccy:exec');
const lib = require('./sbr-lib.js');

const { flags } = process.argv.parseFlags();
if (flags.help || !flags.repo) {
  cli.help('Usage: sbr-scan --repo <vfs-path> [--out <dir>] [--source-url <repo url>]');
  process.exit(flags.help ? 0 : 2);
}
const REPO = lib.stripSlash(String(flags.repo));
const OUT = lib.stripSlash(String(flags.out || '/workspace/security-review-out'));
if (!(await fs.exists(REPO))) cli.die(`repo not found: ${REPO}`);

const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', 'build', '.next', 'coverage', 'vendor', '.cache']);
const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', '.json', '.jsonc', '.html', '.htm',
  '.css', '.yaml', '.yml', '.md', '.env']);
const MAX_BYTES = 2 * 1024 * 1024;

const SECRET_LITERALS = [
  ['Private key block', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/],
  ['AWS access key id', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z\-_]{35}\b/],
  ['Slack token', /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/],
  ['GitHub token', /\bgh[pousr]_[0-9A-Za-z]{36,}\b/],
  ['Generic bearer JWT', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
];
const SECRET_ASSIGN = /([A-Za-z0-9_]*(?:api[_-]?key|secret|passwd|password|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|signing[_-]?key)[A-Za-z0-9_]*)\s*[:=]\s*(["'])([^"']{8,})\2/i;
const PLACEHOLDER = /(your[_-]?|example|placeholder|change[_-]?me|xxx+|<[^>]+>|\$\{|process\.env|env\.|import\.meta|dummy|redacted|todo|fixme|test|sample|\bnull\b|\.\.\.)/i;
const DOM_SINK = /\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval)\s*[(=]|\.innerHTML/;
const DOM_SINK_NAME = /(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval)/;
const CSP_RE = /content-security-policy/i;
const CORS_WILDCARD = /access-control-allow-origin['"]?\s*[:,]?\s*['"]\*['"]/i;
const EXTERNAL_SCRIPT = /<script\b[^>]*\bsrc\s*=\s*["'](https?:\/\/[^"']+)["'][^>]*>/gis;
const INTEGRITY = /\bintegrity\s*=/i;
const TOKEN_IN_URL = /[?&](?:token|access_token|api_key|apikey|secret|password|auth)=/i;
const CONSOLE_SECRET = /console\.(log|info|debug|warn)\s*\([^)]*(token|secret|password|api[_-]?key|authorization)/i;
const ERROR_LEAK = /(\.stack\b|err(?:or)?\.message)\s*[),;]?.*(res(?:ponse)?|return|body|json|send)/i;
const AUTH_HINT = /(oauth|ims|verifyjwt|getsession|__host-|authorization|fail.?closed|401|403|deny)/i;
const SEC_HEADERS = {
  'X-Content-Type-Options': /x-content-type-options/i,
  'Referrer-Policy': /referrer-policy/i,
  'Strict-Transport-Security': /strict-transport-security/i,
  'Permissions-Policy': /permissions-policy/i,
  'Frame protection': /x-frame-options|frame-ancestors/i,
};
const SEC09_EXCLUDE = new Set(['package.json', 'package-lock.json', 'checklist.json', 'tsconfig.json', '.renovaterc.json']);

const rel = (p) => p.slice(REPO.length + 1);
const base = (p) => p.slice(p.lastIndexOf('/') + 1);
const ext = (p) => {
  const b = base(p);
  const i = b.lastIndexOf('.');
  return i > 0 ? b.slice(i).toLowerCase() : '';
};
const isComment = (line) => /^\s*(\/\/|\*|#|<!--)/.test(line);
const isScanned = (p) => {
  const b = base(p);
  return CODE_EXT.has(ext(p)) || b.startsWith('.env') || b.includes('.dev.vars') || b.endsWith('.pem');
};

const { checklist, order } = await lib.loadChecklist();
const res = {};
for (const id of order) res[id] = { status: null, evidence: [], auto_note: '' };
const add = (id, file, line, snippet, note) => res[id].evidence.push(lib.ev(file, line, snippet, note));

// Agent/editor worktrees duplicate the whole codebase and would double every finding.
const SKIP_PATH = (p) => /\/\.(claude|agents|cursor|codex)\/worktrees$|\/\.worktrees$/.test(p);
const allFiles = await lib.walk(REPO, SKIP_DIRS, MAX_BYTES, SKIP_PATH);
const files = allFiles.filter(isScanned);
const headerHits = new Set();
const authSignals = [];

for (const path of files) {
  const r = rel(path);
  const name = base(path);
  const isExample = name.includes('.example') || name.endsWith('.sample');
  let text;
  try {
    text = await fs.readFile(path);
  } catch {
    continue;
  }
  const lines = String(text).split(/\r?\n/);
  const isCodeForAuth = /\.(js|ts|mjs)$/.test(name);

  lines.forEach((line, idx) => {
    const n = idx + 1;
    const comment = isComment(line);

    if (!isExample) {
      for (const [label, rx] of SECRET_LITERALS) {
        const m = rx.exec(line);
        if (m) add('SEC-01', r, n, line.replace(m[0], lib.maskValue(m[0])), label);
      }
      if (!comment) {
        const m = SECRET_ASSIGN.exec(line);
        if (m && m[3].trim() && !PLACEHOLDER.test(m[3])) {
          add('SEC-01', r, n, line.replace(m[3], lib.maskValue(m[3])), `assignment to secret-named var: ${m[1]}`);
        }
      }
    }
    if (!comment && DOM_SINK.test(line)) {
      const s = DOM_SINK_NAME.exec(line);
      add('SEC-03', r, n, line, `${s ? s[1] : 'dom'} sink`);
    }
    if (CSP_RE.test(line)) add('SEC-04', r, n, line, 'CSP reference');
    for (const [h, rx] of Object.entries(SEC_HEADERS)) if (rx.test(line)) headerHits.add(h);
    if (!comment && CORS_WILDCARD.test(line)) add('SEC-06', r, n, line, 'wildcard/broad CORS origin');
    if (!comment && TOKEN_IN_URL.test(line)) add('SEC-10', r, n, lib.redactQueryTokens(line), 'secret-like value in URL query');
    if (!comment && CONSOLE_SECRET.test(line)) add('SEC-10', r, n, line, 'secret-like value logged');
    if (!comment && ERROR_LEAK.test(line)) add('SEC-13', r, n, line, 'error detail may reach client');
    if (isCodeForAuth && AUTH_HINT.test(line)) authSignals.push(lib.ev(r, n, line, 'auth-related'));
  });

  if (/\.html?$/i.test(name)) {
    const joined = lines.join('\n');
    for (const m of joined.matchAll(EXTERNAL_SCRIPT)) {
      if (!INTEGRITY.test(m[0])) {
        const lineNo = joined.slice(0, m.index).split('\n').length;
        add('SEC-07', r, lineNo, m[0].slice(0, 200), `external script without integrity: ${m[1]}`);
      }
    }
  }
}

function judged(id, some, none) {
  const f = res[id];
  f.status = f.evidence.length ? 'review' : 'pass';
  f.auto_note = f.evidence.length ? some(f.evidence.length) : none;
}

judged('SEC-01', (n) => `${n} candidate secret(s) — confirm each is a real live secret before reporting.`,
  'No hardcoded secrets matched high-signal patterns.');

// SEC-02: aggregate every .gitignore (sub-Workers keep their own), flag only files that exist.
const gitignored = [];
for (const p of allFiles.filter((p) => base(p) === '.gitignore')) gitignored.push(String(await fs.readFile(p)));
const ignoredText = gitignored.join('\n');
const present = {
  '.env': allFiles.some((p) => base(p) === '.env' || (base(p).startsWith('.env.') && !base(p).includes('.example'))),
  '.dev.vars': allFiles.some((p) => base(p) === '.dev.vars'),
  '*.pem': allFiles.some((p) => base(p).endsWith('.pem')),
};
const notIgnored = Object.keys(present).filter((k) => present[k] && !ignoredText.includes(k));
const ls = await exec(`cd ${lib.shq(REPO)} && git ls-files`);
const rev = await exec(`cd ${lib.shq(REPO)} && git rev-parse --short HEAD`);
const commit = rev.exitCode === 0 && /^[0-9a-f]{4,40}$/i.test(rev.stdout.trim()) ? rev.stdout.trim() : '';
const tracked = ls.exitCode === 0
  ? ls.stdout.split('\n').filter((f) => {
    const b = base(f);
    return b === '.env' || (b.startsWith('.env.') && !b.endsWith('.example')) || b === '.dev.vars' || f.endsWith('.pem');
  })
  : [];
if (notIgnored.length) add('SEC-02', '.gitignore', 0, '', `secret file(s) present but not gitignored: ${notIgnored.join(', ')}`);
for (const f of tracked) add('SEC-02', f, 0, '', 'secret file is tracked in git');
res['SEC-02'].status = tracked.length ? 'fail' : notIgnored.length ? 'review' : 'pass';
res['SEC-02'].auto_note = tracked.length ? 'Tracked secret files present in git.'
  : notIgnored.length ? `Secret file(s) present but not gitignored: ${notIgnored.join(', ')}`
    : ls.exitCode === 0 ? 'Secret files gitignored; none tracked.'
      : 'Secret files gitignored; not a git checkout, so tracked-file state was not checked.';

judged('SEC-03', (n) => `${n} DOM sink(s) to review for untrusted data.`, 'No DOM HTML sinks found.');

res['SEC-04'].status = res['SEC-04'].evidence.length ? 'pass' : 'fail';
res['SEC-04'].auto_note = res['SEC-04'].evidence.length ? 'CSP definition found in code (live check is authoritative).'
  : 'No Content-Security-Policy found in code/config (verify via live check).';

const missingHeaders = Object.keys(SEC_HEADERS).filter((h) => !headerHits.has(h));
res['SEC-05'].status = 'review';
res['SEC-05'].evidence = [lib.ev('(static scan)', 0, `present in code: ${[...headerHits].sort().join(', ') || 'none'}`,
  `missing in code: ${missingHeaders.join(', ') || 'none'}`)];
res['SEC-05'].auto_note = 'Static discovery only — run sbr-live / sbr-browse (authoritative).';

judged('SEC-06', (n) => `${n} wildcard CORS site(s) — confirm dev/preview-only vs production.`, 'No wildcard CORS origins found.');

res['SEC-07'].status = res['SEC-07'].evidence.length ? 'fail' : 'pass';
res['SEC-07'].auto_note = res['SEC-07'].evidence.length ? `${res['SEC-07'].evidence.length} external script(s) without SRI.`
  : 'No external scripts without integrity found in HTML.';

res['SEC-08'].status = 'skipped';
res['SEC-08'].auto_note = 'Run sbr-deps to audit package-lock.json.';

const dataFiles = allFiles.map(rel).filter((p) => p.endsWith('.json') && !SEC09_EXCLUDE.has(base(p))
  && !/(^|\/)(node_modules|scripts|\.github)\//.test(p)).sort();
res['SEC-09'].evidence = dataFiles.slice(0, 40).map((p) => lib.ev(p, 0, '', 'published data file to review for PII'));
res['SEC-09'].status = dataFiles.length ? 'review' : 'pass';
res['SEC-09'].auto_note = dataFiles.length
  ? `${dataFiles.length} content/data JSON file(s) to review for sensitive fields${dataFiles.length > 40 ? ' (first 40 listed)' : ''}.`
  : 'No candidate published data files found.';

judged('SEC-10', (n) => `${n} potential token-leak site(s).`, 'No token-in-URL / secret-logging patterns found.');

res['SEC-11'].status = 'skipped';
res['SEC-11'].auto_note = 'Requires the live checks (sbr-live, sbr-browse).';

res['SEC-12'].evidence = authSignals.slice(0, 40);
res['SEC-12'].status = 'review';
res['SEC-12'].auto_note = authSignals.length
  ? `${authSignals.length} auth-related reference(s)${authSignals.length > 40 ? ' (first 40 listed)' : ''} — confirm gating matches intent (public vs gated) and fails closed.`
  : 'No auth code detected — confirm whether the site is intended to be public.';

judged('SEC-13', (n) => `${n} spot(s) where error detail may reach the client.`, 'No obvious error-detail leakage patterns found.');

res['SEC-14'].status = 'skipped';
res['SEC-14'].auto_note = 'Requires the browser check (sbr-browse).';

await lib.mkdirp(OUT);
const findingsPath = `${OUT}/findings.json`;
const doc = {
  checks: res,
  checklist: { name: checklist.meta.name, version: checklist.meta.version },
  target_repo: REPO,
  target_repo_url: flags['source-url'] ? String(flags['source-url']) : undefined,
  target_commit: commit || undefined,
  target_github: lib.parseGithubRepo(flags['source-url']) || lib.parseGithubRepo(await lib.gitOriginUrl(REPO)) || undefined,
  review_date: new Date().toISOString().slice(0, 10),
  files_scanned: files.length,
};
await lib.writeJson(findingsPath, doc);
lib.printSummary(res, order);
console.log(`\nScanned ${files.length} file(s). Wrote ${findingsPath}`);
