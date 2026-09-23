// Shared helpers for the security-baseline-review commands (not itself a command: .js, not .jsh).
const fs = require('fs');
const { exec } = require('sliccy:exec');
const skill = require('sliccy:skill');

const ROOT = skill.root;
const CHECKLIST_PATH = `${ROOT}/checklist.json`;
const TEMPLATES = `${ROOT}/templates`;

const STATUS_RANK = { fail: 0, review: 1, pass: 2, skipped: 3 };
const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

const CORE_HEADERS = [
  'strict-transport-security',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
];
const HEADER_LABELS = {
  'strict-transport-security': 'Strict-Transport-Security',
  'x-content-type-options': 'X-Content-Type-Options',
  'referrer-policy': 'Referrer-Policy',
  'permissions-policy': 'Permissions-Policy',
  'x-frame-options': 'X-Frame-Options',
  'content-security-policy': 'Content-Security-Policy',
};
const FRAME_MISSING = 'frame protection (X-Frame-Options / CSP frame-ancestors)';

const SESSION_COOKIE = /(sess|sid|auth|token|jwt|ims|login|__host-|__secure-|connect\.sid|remember)/i;
const TOKEN_KEYS = 'token|access_token|id_token|refresh_token|api_key|apikey|secret|password|auth';
const TOKEN_QUERY = new RegExp(`([?&](?:${TOKEN_KEYS})=)([^&#\\s'"]+)`, 'gi');
const TOKEN_IN_QUERY = new RegExp(`[?&](?:${TOKEN_KEYS})=[^&#\\s'"]+`, 'i');

async function readJson(path) {
  return JSON.parse(await fs.readFile(path));
}

async function writeJson(path, obj) {
  await fs.writeFile(path, JSON.stringify(obj, null, 2) + '\n');
}

async function loadChecklist() {
  const checklist = await readJson(CHECKLIST_PATH);
  const meta = {};
  for (const c of checklist.checks) meta[c.id] = c;
  return { checklist, meta, order: checklist.checks.map((c) => c.id) };
}

async function loadFindings(path) {
  if (await fs.exists(path)) return readJson(path);
  return { checks: {} };
}

function stripSlash(p) {
  return p.length > 1 ? p.replace(/\/+$/, '') : p;
}

function dirname(p) {
  const i = p.lastIndexOf('/');
  return i <= 0 ? '/' : p.slice(0, i);
}

function shq(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

// The async fs.mkdir bridge ignores { recursive }.
async function mkdirp(dir) {
  const r = await exec.spawn(['mkdir', '-p', dir]);
  if (r.exitCode !== 0) throw new Error(`mkdir -p ${dir}: ${r.stderr.trim()}`);
}

function ev(file, line, snippet, note) {
  return { file, line: line || 0, snippet: String(snippet || '').trim().slice(0, 240), note: note || '' };
}

function maskValue(v) {
  const s = String(v);
  if (s.length <= 6) return '[redacted]';
  return `${s.slice(0, 4)}…[${s.length} chars redacted]`;
}

function redactQueryTokens(s) {
  return String(s).replace(TOKEN_QUERY, (_, key) => `${key}[redacted]`);
}

function combineStatus(a, b) {
  if (!a || a === 'skipped') return b || a;
  if (!b || b === 'skipped') return a;
  return STATUS_RANK[a] <= STATUS_RANK[b] ? a : b;
}

// New evidence invalidates any earlier adjudication, so both modes clear it.
function mergeFinding(doc, id, f, mode, source) {
  doc.checks = doc.checks || {};
  const old = doc.checks[id];
  if (!old || mode === 'replace') {
    doc.checks[id] = {
      status: f.status || 'skipped',
      evidence: f.evidence || [],
      auto_note: f.auto_note || '',
      sources: [source || 'static'],
    };
    return;
  }
  doc.checks[id] = {
    status: combineStatus(old.status, f.status),
    evidence: [...(old.evidence || []), ...(f.evidence || [])],
    auto_note: [old.auto_note, f.auto_note].filter(Boolean).join(' | '),
    sources: [...new Set([...(old.sources || ['static']), source || 'static'])],
  };
}

// Live results supersede a static-only finding but combine with other live results.
function liveMode(doc, id) {
  const sources = (doc.checks && doc.checks[id] && doc.checks[id].sources) || ['static'];
  return sources.some((s) => s !== 'static') ? 'combine' : 'replace';
}

function lowerHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h || {})) out[k.toLowerCase()] = v;
  return out;
}

function parseCsp(csp) {
  const dirs = {};
  for (const part of String(csp || '').split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length) dirs[tokens[0].toLowerCase()] = tokens.slice(1);
  }
  return dirs;
}

function analyzeCsp(csp) {
  const dirs = parseCsp(csp);
  const weaknesses = [];
  const script = dirs['script-src'] || dirs['default-src'];
  if (!script) {
    weaknesses.push('no script-src/default-src (scripts unrestricted)');
  } else {
    const nonceOrHash = script.some((v) => /^'(nonce-|sha(256|384|512)-)/i.test(v));
    const strictDynamic = script.includes("'strict-dynamic'");
    if (script.includes("'unsafe-inline'") && !nonceOrHash) weaknesses.push("script-src allows 'unsafe-inline' without nonce/hash");
    if (script.includes("'unsafe-eval'")) weaknesses.push("script-src allows 'unsafe-eval'");
    if (script.some((v) => ['*', 'https:', 'http:', 'data:'].includes(v))) weaknesses.push('script-src allows a wildcard/scheme source');
    if (!nonceOrHash && !strictDynamic) weaknesses.push('script-src is a host allowlist (no nonce/hash/strict-dynamic)');
  }
  const defaultNone = (dirs['default-src'] || []).includes("'none'");
  if (!dirs['object-src'] && !defaultNone) weaknesses.push('object-src not restricted');
  if (!dirs['base-uri']) weaknesses.push('base-uri not set');
  if (!dirs['frame-ancestors']) weaknesses.push('frame-ancestors not set');
  return { weaknesses, trustedTypes: 'require-trusted-types-for' in dirs };
}

// A meta-tag CSP enforces script policy but browsers ignore frame-ancestors in it.
function analyzeHeaders(rawHeaders, metaCsp) {
  const h = lowerHeaders(rawHeaders);
  const csp = h['content-security-policy'] || '';
  const effectiveCsp = csp || metaCsp || '';
  const missing = CORE_HEADERS.filter((k) => !h[k]).map((k) => HEADER_LABELS[k]);
  const frameOk = !!h['x-frame-options'] || /frame-ancestors/i.test(csp);
  if (!frameOk) missing.push(FRAME_MISSING);
  const present = Object.keys(HEADER_LABELS).filter((k) => h[k]).map((k) => HEADER_LABELS[k]);
  return {
    csp,
    metaCsp: metaCsp || '',
    reportOnly: h['content-security-policy-report-only'] || '',
    hsts: h['strict-transport-security'] || '',
    missing,
    present,
    cspAnalysis: effectiveCsp ? analyzeCsp(effectiveCsp) : null,
  };
}

async function walk(root, skipDirs, maxBytes) {
  const out = [];
  async function visit(dir) {
    let names;
    try {
      names = await fs.readDir(dir);
    } catch {
      return;
    }
    for (const name of [...names].sort()) {
      const p = `${dir}/${name}`;
      let st;
      try {
        st = await fs.stat(p);
      } catch {
        continue;
      }
      if (st.isDirectory) {
        if (!skipDirs.has(name)) await visit(p);
      } else if (st.isFile && (!maxBytes || st.size <= maxBytes)) {
        out.push(p);
      }
    }
  }
  await visit(stripSlash(root));
  return out;
}

async function pw(args) {
  return exec.spawn(['playwright-cli', ...args]);
}

async function openTab(url) {
  const r = await pw(['open', url || 'about:blank']);
  const m = /targetId:\s*([^\]\s]+)/.exec(`${r.stdout}\n${r.stderr}`);
  if (r.exitCode !== 0 || !m) throw new Error(`playwright-cli open failed: ${(r.stderr || r.stdout).trim()}`);
  return m[1];
}

async function closeTab(tab) {
  await pw(['tab-close', `--tab=${tab}`]);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function computeDiff(baseDoc, curDoc, meta) {
  const RANK = { fail: 0, review: 1, skipped: 2, pass: 3 };
  const base = (baseDoc && baseDoc.checks) || {};
  const cur = (curDoc && curDoc.checks) || {};
  const label = (id) => ({ id, title: (meta[id] || {}).title || id, severity: (meta[id] || {}).severity || '' });
  const d = { regressions: [], fixes: [], added: [], removed: [], unchanged_count: 0 };
  for (const id of [...new Set([...Object.keys(base), ...Object.keys(cur)])].sort()) {
    const b = base[id];
    const c = cur[id];
    if (!b) d.added.push({ ...label(id), to: c.status });
    else if (!c) d.removed.push({ ...label(id), from: b.status });
    else if (b.status === c.status) d.unchanged_count++;
    else {
      const entry = { ...label(id), from: b.status, to: c.status };
      ((RANK[c.status] ?? 2) < (RANK[b.status] ?? 2) ? d.regressions : d.fixes).push(entry);
    }
  }
  d.baseline_date = (baseDoc && baseDoc.review_date) || '';
  return d;
}

function printSummary(checks, ids) {
  for (const id of ids) {
    const f = checks[id];
    if (f) console.log(`${id.padEnd(8)} ${String(f.status).padEnd(8)} ${f.auto_note || ''}`);
  }
}

module.exports = {
  ROOT,
  TEMPLATES,
  SEV_ORDER,
  SESSION_COOKIE,
  TOKEN_IN_QUERY,
  FRAME_MISSING,
  readJson,
  writeJson,
  loadChecklist,
  loadFindings,
  stripSlash,
  dirname,
  shq,
  mkdirp,
  ev,
  maskValue,
  redactQueryTokens,
  combineStatus,
  mergeFinding,
  liveMode,
  lowerHeaders,
  analyzeHeaders,
  walk,
  pw,
  openTab,
  closeTab,
  sleep,
  computeDiff,
  printSummary,
};
