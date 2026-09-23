// sbr-live — HTTP checks against the live URL through SLICC's fetch transport (no browser tab).
//
// Usage: sbr-live --url <https://site> [--out <dir>]
//
// Resolves SEC-04/05 for the base URL (authoritative over the static scan), the
// HTTPS/HSTS half of SEC-11, and a SEC-13 error probe (one GET for a path that
// does not exist). GET requests only; no payloads.
// CORS is not tested here: the CLI fetch proxy strips upstream access-control-*
// headers, so sbr-browse probes CORS from a real tab instead.

const cli = require('sliccy:cli');
const lib = require('./sbr-lib.js');

const { flags } = process.argv.parseFlags();
if (flags.help || !flags.url) {
  cli.help('Usage: sbr-live --url <https://site> [--out <dir>]');
  process.exit(flags.help ? 0 : 2);
}
const URL_IN = String(flags.url);
const OUT = lib.stripSlash(String(flags.out || '/workspace/security-review-out'));
const findingsPath = `${OUT}/findings.json`;
let target;
try {
  target = new URL(URL_IN);
} catch {
  cli.die(`invalid --url: ${URL_IN}`);
}

const STACK_PATTERNS = [
  [/\bat [\w$.<>[\] ]+ \((?:\/|file:|webpack:|node:)[^)]*:\d+:\d+\)/, 'JavaScript stack frame'],
  [/Traceback \(most recent call last\)/, 'Python traceback'],
  [/\bnode_modules\//, 'server path (node_modules)'],
  [/\/var\/task\/|\/opt\/buildhome\/|[A-Z]:\\{1,2}(?:Users|inetpub|Windows|Program Files)\b/, 'server filesystem path'],
  [/\b(TypeError|ReferenceError|SyntaxError|RangeError): /, 'raw JS error message'],
  [/Exception in thread|\bat [a-z]+\.[\w.$]+\([\w]+\.java:\d+\)/, 'Java exception'],
  [/"stack"\s*:\s*"/, 'serialized stack in JSON'],
];

async function get(url) {
  const r = await fetch(url, { method: 'GET', redirect: 'follow' });
  if (r.headers.get('x-proxy-error')) {
    let msg = `HTTP ${r.status}`;
    try {
      msg = (await r.json()).error || msg;
    } catch {
      /* non-JSON proxy error */
    }
    throw new Error(msg);
  }
  const headers = {};
  r.headers.forEach((v, k) => {
    headers[k.toLowerCase()] = v;
  });
  return { status: r.status, headers, text: () => r.text() };
}

const findings = {};
let base = null;
let err = null;
try {
  base = await get(target.href);
} catch (e) {
  err = e.message;
}

if (err) {
  const note = `Live fetch failed: ${err}`;
  for (const id of ['SEC-04', 'SEC-05']) findings[id] = { status: 'skipped', evidence: [], auto_note: note };
} else {
  const a = lib.analyzeHeaders(base.headers, '');
  const loc = `(live) ${target.href}`;
  const cspEv = [lib.ev(loc, 0, a.csp || 'no Content-Security-Policy header', `HTTP ${base.status} response header`)];
  if (!a.csp && a.reportOnly) cspEv.push(lib.ev(loc, 0, a.reportOnly, 'Content-Security-Policy-Report-Only is NOT enforced'));
  if (a.cspAnalysis) for (const w of a.cspAnalysis.weaknesses) cspEv.push(lib.ev(loc, 0, '', `CSP weakness: ${w}`));
  findings['SEC-04'] = {
    status: a.csp ? 'pass' : 'fail',
    evidence: cspEv,
    auto_note: a.csp ? `CSP present on base URL${a.cspAnalysis.weaknesses.length ? ` (${a.cspAnalysis.weaknesses.length} weakness(es) noted)` : ''}.`
      : 'No CSP header on base URL (sbr-browse also checks meta-tag CSP).',
  };
  findings['SEC-05'] = {
    status: a.missing.length ? 'fail' : 'pass',
    evidence: [lib.ev(loc, 0, `present: ${a.present.join(', ') || 'none'}`, `missing: ${a.missing.join(', ') || 'none'}`)],
    auto_note: a.missing.length ? `Missing on base URL: ${a.missing.join(', ')}` : 'All core security headers present on base URL.',
  };
}

if (target.protocol !== 'https:') {
  findings['SEC-11'] = { status: 'fail', evidence: [], auto_note: 'URL is not https:// — transport security cannot be confirmed.' };
} else if (err) {
  const certish = /cert|ssl|tls|self.signed|expired|unable to verify/i.test(err);
  findings['SEC-11'] = {
    status: certish ? 'fail' : 'skipped',
    evidence: [lib.ev(`(live) ${target.host}`, 0, err, certish ? 'TLS certificate rejected' : 'fetch failed')],
    auto_note: certish ? 'HTTPS certificate was rejected.' : `HTTPS not verified: ${err}`,
  };
} else {
  const hsts = base.headers['strict-transport-security'] || '';
  const maxAge = Number((/max-age=(\d+)/i.exec(hsts) || [])[1] || 0);
  const ev11 = [lib.ev(`(live) ${target.host}`, 0, 'HTTPS certificate accepted (expiry not visible from SLICC)', 'TLS certificate')];
  ev11.push(lib.ev(`(live) ${target.host}`, 0, hsts || 'no Strict-Transport-Security header', 'HSTS'));
  findings['SEC-11'] = {
    status: hsts && maxAge > 0 ? 'pass' : 'review',
    evidence: ev11,
    auto_note: hsts && maxAge > 0 ? `HTTPS served with an accepted certificate and HSTS (max-age ${maxAge}).`
      : 'HTTPS served with an accepted certificate but no HSTS — http→https enforcement not proven (see sbr-browse).',
  };
}

if (!err) {
  const probe = new URL(`/sbr-probe-not-found-${Date.now().toString(36)}`, target.origin).href;
  try {
    const r = await get(probe);
    const body = String(await r.text()).slice(0, 65536);
    const hits = STACK_PATTERNS.filter(([rx]) => rx.test(body));
    const ev13 = [lib.ev(`(live) ${probe}`, 0, `HTTP ${r.status}, ${body.length} byte(s) inspected`, 'error-page probe')];
    for (const [rx, label] of hits) ev13.push(lib.ev(`(live) ${probe}`, 0, (rx.exec(body) || [''])[0], `leak: ${label}`));
    findings['SEC-13'] = {
      status: hits.length ? 'fail' : 'pass',
      evidence: ev13,
      auto_note: hits.length ? `Error response for a missing path leaks internal detail (${hits.map((h) => h[1]).join(', ')}).`
        : `Error response for a missing path (HTTP ${r.status}) shows no internal detail.`,
    };
  } catch (e) {
    findings['SEC-13'] = { status: 'skipped', evidence: [], auto_note: `Error probe failed: ${e.message}` };
  }
}

await lib.mkdirp(OUT);
const doc = await lib.loadFindings(findingsPath);
for (const [id, f] of Object.entries(findings)) {
  const mode = id === 'SEC-13' ? 'combine' : lib.liveMode(doc, id);
  lib.mergeFinding(doc, id, f, mode, 'live');
}
doc.live_url = target.href;
await lib.writeJson(findingsPath, doc);
lib.printSummary(doc.checks, Object.keys(findings));
console.log(`\nMerged live results into ${findingsPath}`);
