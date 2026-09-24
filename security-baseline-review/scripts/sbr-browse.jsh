// sbr-browse — browser-observed checks in real tabs (the part the Claude skill could not do).
//
// Usage: sbr-browse --url <https://site> [--out <dir>] [--pages /a,/b] [--max-pages 5]
//                   [--protected /api/me,/private] [--api https://api.site/x] [--settle-ms 2500] [--no-probes]
//                   [--login] [--login-timeout 300] [--state <auth-state.json>] [--app-host <host>]
//
//   --pages          extra paths/URLs to review (base URL is always first)
//   --max-pages      crawl budget; same-origin links from the base page fill any spare slots
//   --protected      URLs that should require the reviewer's session (SEC-12 comparison)
//   --api            extra endpoints for the SEC-06 CORS probe
//   --no-probes      observation only: skip the CORS, protected-URL and http:// probes
//   --login          open the site in the foreground and wait for you to sign in before scanning;
//                    the session is saved to <out>/auth-state.json for --state on later runs
//   --login-timeout  seconds to wait for sign-in (default 300)
//   --state          restore a saved session (playwright-cli state-save file) instead of signing in
//   --app-host       host the app is served from after sign-in (default: the --url host)
//
// Pages that end on any other host (e.g. the identity provider) are skipped, never scored.
// Probes are GET-only and never send payloads. Crawling skips logout/delete-style links.

const cli = require('sliccy:cli');
const browser = require('sliccy:browser');
const lib = require('./sbr-lib.js');

const { flags } = process.argv.parseFlags();
if (flags.help || !flags.url) {
  cli.help('Usage: sbr-browse --url <https://site> [--out <dir>] [--pages /a,/b] [--max-pages 5] [--protected /x,/y] [--api <url,...>] [--settle-ms 2500] [--no-probes] [--login] [--login-timeout 300] [--state <file>] [--app-host <host>]');
  process.exit(flags.help ? 0 : 2);
}
let target;
try {
  target = new URL(String(flags.url));
} catch {
  cli.die(`invalid --url: ${flags.url}`);
}
const OUT = lib.stripSlash(String(flags.out || '/workspace/security-review-out'));
const findingsPath = `${OUT}/findings.json`;
const MAX_PAGES = Math.max(1, Number(flags['max-pages'] || 5));
const SETTLE_MS = Math.max(0, Number(flags['settle-ms'] || 2500));
const PROBES = !flags['no-probes'];
const LOGIN = !!flags.login;
const LOGIN_TIMEOUT_MS = Math.max(30, Number(flags['login-timeout'] || 300)) * 1000;
const STATE = flags.state ? String(flags.state) : null;
const APP_HOST = String(flags['app-host'] || target.host).toLowerCase();
const APP_HOSTNAME = APP_HOST.split(':')[0];
const list = (v) => (v ? String(v).split(',').map((s) => s.trim()).filter(Boolean) : []);
const abs = (u) => new URL(u, target.origin).href;
const noHash = (u) => String(u).split('#')[0];
const hostOf = (u) => {
  try {
    return new URL(u).host.toLowerCase();
  } catch {
    return '';
  }
};
const cookieForApp = (c) => {
  const d = String(c.domain || '').replace(/^\./, '').toLowerCase();
  return !!d && (APP_HOSTNAME === d || APP_HOSTNAME.endsWith(`.${d}`));
};
const UNSAFE_LINK = /(log-?out|sign-?out|logoff|delete|remove|unsubscribe|revoke|destroy)/i;

function parseRequests(stdout) {
  const out = [];
  for (const line of String(stdout).split('\n')) {
    const m = /^(\d+) (\S+) (\S+) → (\S+)$/.exec(line.trim());
    if (m) out.push({ index: Number(m[1]), method: m[2], url: m[3], status: m[4] });
  }
  return out;
}

function parseHeaderLines(stdout) {
  const h = {};
  for (const line of String(stdout).split('\n')) {
    const i = line.indexOf(':');
    if (i > 0) h[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  return h;
}

function parseCookies(stdout) {
  const out = [];
  for (const line of String(stdout).split('\n')) {
    const parts = line.split('\t');
    const eq = parts[0].indexOf('=');
    if (parts.length < 5 || eq <= 0) continue;
    const kv = Object.fromEntries(parts.slice(1).map((p) => [p.slice(0, p.indexOf('=')), p.slice(p.indexOf('=') + 1)]));
    out.push({ name: parts[0].slice(0, eq), domain: kv.Domain, path: kv.Path, secure: kv.Secure === 'true', httpOnly: kv.HttpOnly === 'true' });
  }
  return out;
}

async function evalJson(tab, fn) {
  const v = await browser.eval(tab, fn);
  return typeof v === 'string' ? JSON.parse(v) : v;
}

async function tryFetch(tab, url, credentials) {
  try {
    const r = await browser.fetch(tab, url, { credentials, responseType: 'text', timeoutMs: 15000 });
    if (!r || !r.status) return { ok: false, error: (r && r.error) || 'blocked (no readable response)' };
    return { ok: true, status: r.status, url: r.url || url, redirected: !!r.redirected, size: String(r.body || '').length };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

const pages = [];
const requestUrls = new Set();
const apiCandidates = new Set();
const cspViolations = [];
let cookies = [];
let storageKeys = [];
let httpProbe = null;
const corsResults = [];
const protectedResults = [];

async function currentHref(tab) {
  try {
    return noHash(await browser.eval(tab, () => location.href));
  } catch {
    return '';
  }
}

// Only reads location.href, so the user can sign in without the script fighting them for the page.
async function waitForLogin(tab) {
  console.log(`Sign in to ${target.host} in the tab that just opened. Waiting up to ${LOGIN_TIMEOUT_MS / 1000}s for a return to ${APP_HOST}…`);
  const deadline = Date.now() + LOGIN_TIMEOUT_MS;
  let leftApp = false;
  let onAppSince = 0;
  while (Date.now() < deadline) {
    await lib.sleep(3000);
    const href = await currentHref(tab);
    const host = hostOf(href);
    if (!host) continue;
    if (host !== APP_HOST) {
      leftApp = true;
      onAppSince = 0;
      continue;
    }
    onAppSince = onAppSince || Date.now();
    // Already signed in: no redirect happens, so require a short stable period instead.
    if (leftApp || Date.now() - onAppSince >= 8000) {
      await lib.sleep(SETTLE_MS);
      await lib.mkdirp(OUT);
      const statePath = `${OUT}/auth-state.json`;
      const s = await lib.pw(['state-save', `--tab=${tab}`, `--filename=${statePath}`]);
      console.log(s.exitCode === 0
        ? `Signed in. Session saved to ${statePath} — it holds live session cookies; delete it after the review.`
        : 'Signed in (session could not be saved; --state will not be available).');
      return;
    }
  }
  throw new Error(`Timed out after ${LOGIN_TIMEOUT_MS / 1000}s waiting for sign-in to return to ${APP_HOST}. Re-run with a longer --login-timeout or check --app-host.`);
}

async function restoreSession(tab) {
  const r = await lib.pw(['state-load', STATE, `--tab=${tab}`]);
  if (r.exitCode !== 0) throw new Error(`state-load ${STATE} failed: ${(r.stderr || r.stdout).trim()}`);
  await lib.pw(['goto', `--tab=${tab}`, target.href]);
  await lib.sleep(SETTLE_MS);
  if (hostOf(await currentHref(tab)) !== APP_HOST && !LOGIN) {
    throw new Error(`Saved session in ${STATE} did not reach ${APP_HOST} (expired?). Re-run with --login.`);
  }
}

const tab = await lib.openTab(LOGIN || STATE ? target.href : 'about:blank', LOGIN ? ['--foreground'] : []);
let probeTab = null;
try {
  if (STATE) await restoreSession(tab);
  if (LOGIN) await waitForLogin(tab);
  // Armed only after sign-in so identity-provider traffic never enters the capture.
  await lib.pw(['requests', `--tab=${tab}`, '--clear']);
  const queue = [target.href, ...list(flags.pages).map(abs)];
  const seen = new Set();
  let linksCollected = false;

  for (let i = 0; i < queue.length && pages.length < MAX_PAGES; i++) {
    const url = noHash(queue[i]);
    if (seen.has(url)) continue;
    seen.add(url);
    const g = await lib.pw(['goto', `--tab=${tab}`, url]);
    if (g.exitCode !== 0) {
      pages.push({ url, error: (g.stderr || g.stdout).trim().slice(0, 200) });
      continue;
    }
    await lib.sleep(SETTLE_MS);
    const href = await currentHref(tab);
    if (hostOf(href) !== APP_HOST) {
      pages.push({ url, finalUrl: href, error: `ended on ${hostOf(href) || 'an unknown page'}, not ${APP_HOST} (sign-in page?)` });
      await lib.pw(['requests', `--tab=${tab}`, '--clear']);
      continue;
    }
    const all = parseRequests((await lib.pw(['requests', `--tab=${tab}`, '--static'])).stdout);
    const dynamic = new Set(parseRequests((await lib.pw(['requests', `--tab=${tab}`])).stdout).map((r) => r.index));
    for (const r of all) requestUrls.add(r.url);
    for (const r of all) {
      if (dynamic.has(r.index) && r.method === 'GET' && new URL(r.url).host === target.host && noHash(r.url) !== href) {
        apiCandidates.add(r.url);
      }
    }
    const docReq = [...all].reverse().find((r) => noHash(r.url) === href && r.status !== 'pending');
    const headers = docReq
      ? parseHeaderLines((await lib.pw(['response-headers', `--tab=${tab}`, String(docReq.index)])).stdout)
      : null;
    if (headers) delete headers['set-cookie'];
    const metaCsp = await browser.eval(tab, () => {
      const m = document.querySelector('meta[http-equiv="Content-Security-Policy" i]');
      return m ? m.content : '';
    });
    const resources = await evalJson(tab, () => JSON.stringify([
      ...[...document.querySelectorAll('script[src]')].map((s) => ({ kind: 'script', url: s.src, integrity: s.integrity || '' })),
      ...[...document.querySelectorAll('link[rel~="stylesheet"][href]')].map((l) => ({ kind: 'stylesheet', url: l.href, integrity: l.integrity || '' })),
    ]));
    pages.push({ url, finalUrl: href, status: docReq ? docReq.status : null, headers, metaCsp: String(metaCsp || ''), resources });

    if (!linksCollected) {
      linksCollected = true;
      const links = await evalJson(tab, () => JSON.stringify([...new Set([...document.querySelectorAll('a[href]')]
        .map((a) => a.href.split('#')[0]).filter((h) => h.startsWith(`${location.origin}/`)))]));
      for (const l of links) if (!UNSAFE_LINK.test(l) && !/\.(pdf|zip|png|jpe?g|svg|mp4|docx?|xlsx?)$/i.test(l)) queue.push(l);
    }
    const cons = await lib.pw(['console', `--tab=${tab}`, 'error', '--clear']);
    for (const line of String(cons.stdout).split('\n')) {
      if (/Content.Security.Policy|Refused to (load|execute|apply|connect|frame|evaluate)/i.test(line)) cspViolations.push(`${url}: ${line.trim()}`);
    }
    await lib.pw(['requests', `--tab=${tab}`, '--clear']);
  }

  const ok = pages.filter((p) => !p.error);
  if (ok.length) {
    await lib.pw(['goto', `--tab=${tab}`, target.href]);
    cookies = parseCookies((await lib.pw(['cookie-list', `--tab=${tab}`])).stdout).filter(cookieForApp);
    storageKeys = await evalJson(tab, () => {
      try {
        return JSON.stringify(Object.keys(localStorage));
      } catch {
        return '[]';
      }
    });
  }

  if (PROBES && ok.length) {
    for (const u of list(flags.protected).map(abs)) {
      protectedResults.push({ url: u, anon: await tryFetch(tab, u, 'omit'), authed: await tryFetch(tab, u, 'include') });
    }
    probeTab = await lib.openTab('about:blank');
    const endpoints = [target.href, ...list(flags.api).map(abs), ...[...apiCandidates].slice(0, 10)];
    for (const u of [...new Set(endpoints)]) {
      corsResults.push({ url: u, anon: await tryFetch(probeTab, u, 'omit'), creds: await tryFetch(probeTab, u, 'include') });
    }
    if (target.protocol === 'https:') {
      const httpUrl = `http://${target.host}${target.pathname}${target.search}`;
      const g = await lib.pw(['goto', `--tab=${tab}`, httpUrl]);
      httpProbe = g.exitCode === 0
        ? { from: httpUrl, to: noHash(await browser.eval(tab, () => location.href)) }
        : { from: httpUrl, error: (g.stderr || g.stdout).trim().slice(0, 200) };
    }
  }
} finally {
  if (!flags['keep-tab']) {
    await lib.closeTab(tab);
    if (probeTab) await lib.closeTab(probeTab);
  }
}

const ok = pages.filter((p) => !p.error);
const findings = {};
const loc = (p) => `(browser) ${p.finalUrl || p.url}`;

if (!ok.length) {
  const offHost = pages.some((p) => /sign-in page/.test(p.error || ''));
  const note = `No page on ${APP_HOST} loaded in the browser (${pages.map((p) => p.error).join('; ') || 'unknown error'}).${offHost && !LOGIN ? ' The site redirected to sign-in: re-run with --login.' : ''}`;
  for (const id of ['SEC-04', 'SEC-05', 'SEC-14']) findings[id] = { status: 'skipped', evidence: [], auto_note: note };
} else {
  const analyses = ok.map((p) => ({ p, a: p.headers ? lib.analyzeHeaders(p.headers, p.metaCsp) : null }));

  const ev4 = [];
  const noCsp = [];
  const weak = new Set();
  let ttPages = 0;
  for (const { p, a } of analyses) {
    if (!a) {
      ev4.push(lib.ev(loc(p), 0, '', 'document response headers not captured'));
      continue;
    }
    if (a.csp) ev4.push(lib.ev(loc(p), 0, a.csp, 'CSP header'));
    else if (a.metaCsp) ev4.push(lib.ev(loc(p), 0, a.metaCsp, 'CSP via <meta> only (frame-ancestors is ignored in meta)'));
    else {
      noCsp.push(p.finalUrl);
      ev4.push(lib.ev(loc(p), 0, a.reportOnly ? `report-only: ${a.reportOnly}` : 'no CSP', 'no enforced CSP'));
    }
    if (a.cspAnalysis) {
      a.cspAnalysis.weaknesses.forEach((w) => weak.add(w));
      if (a.cspAnalysis.trustedTypes) ttPages++;
    }
  }
  for (const w of weak) ev4.push(lib.ev('(browser) CSP analysis', 0, '', `CSP weakness: ${w}`));
  for (const v of cspViolations.slice(0, 10)) ev4.push(lib.ev('(browser) console', 0, v, 'CSP violation reported by the browser'));
  const captured = analyses.filter((x) => x.a).length;
  findings['SEC-04'] = {
    status: !captured ? 'skipped' : noCsp.length ? 'fail' : 'pass',
    evidence: ev4,
    auto_note: !captured ? 'Document headers were not captured in the browser.'
      : noCsp.length ? `${noCsp.length}/${captured} page(s) have no enforced CSP.` : `Enforced CSP on all ${captured} page(s) reviewed.`,
  };

  const ev5 = [];
  let missingPages = 0;
  for (const { p, a } of analyses) {
    if (!a) continue;
    if (a.missing.length) missingPages++;
    ev5.push(lib.ev(loc(p), 0, `present: ${a.present.join(', ') || 'none'}`, `missing: ${a.missing.join(', ') || 'none'}`));
  }
  findings['SEC-05'] = {
    status: !captured ? 'skipped' : missingPages ? 'fail' : 'pass',
    evidence: ev5,
    auto_note: !captured ? 'Document headers were not captured in the browser.'
      : missingPages ? `${missingPages}/${captured} page(s) missing core security headers.` : `Core security headers present on all ${captured} page(s).`,
  };

  findings['SEC-03'] = {
    evidence: [lib.ev('(browser) CSP analysis', 0, `Trusted Types enforced on ${ttPages}/${captured} page(s)`,
      ttPages === captured && captured ? 'sinks are constrained by Trusted Types' : 'sinks are not constrained by Trusted Types')],
    auto_note: `Trusted Types enforced on ${ttPages}/${captured} page(s).`,
  };

  const noSri = [];
  const seenRes = new Set();
  for (const p of ok) {
    const origin = new URL(p.finalUrl).origin;
    for (const r of p.resources || []) {
      if (seenRes.has(r.url)) continue;
      seenRes.add(r.url);
      if (/^https?:/.test(r.url) && new URL(r.url).origin !== origin && !r.integrity) noSri.push({ p, r });
    }
  }
  findings['SEC-07'] = {
    status: noSri.length ? 'fail' : 'pass',
    evidence: noSri.slice(0, 25).map(({ p, r }) => lib.ev(loc(p), 0, lib.redactQueryTokens(r.url), `cross-origin ${r.kind} loaded without integrity`)),
    auto_note: noSri.length ? `${noSri.length} cross-origin resource(s) loaded at runtime without SRI.` : 'All cross-origin scripts/styles loaded at runtime carry SRI.',
  };

  const leaks = [...requestUrls].filter((u) => lib.TOKEN_IN_QUERY.test(u));
  const tokenKeys = (storageKeys || []).filter((k) => /(token|jwt|auth|session|secret|apikey|api_key)/i.test(k));
  const ev10 = leaks.slice(0, 20).map((u) => lib.ev('(browser) request URL', 0, lib.redactQueryTokens(u),
    new URL(u).host === target.host ? 'secret-like query parameter (first-party)' : 'secret-like query parameter sent to a third party'));
  for (const k of tokenKeys) ev10.push(lib.ev('(browser) localStorage', 0, k, 'token-like key readable by any script on the origin'));
  findings['SEC-10'] = {
    status: ev10.length ? 'review' : 'pass',
    evidence: ev10,
    auto_note: `${requestUrls.size} request URL(s) scanned: ${leaks.length} with secret-like query parameters; ${tokenKeys.length} token-like localStorage key(s).`,
  };

  const sessionCookies = cookies.filter((c) => lib.SESSION_COOKIE.test(c.name));
  const weakCookies = sessionCookies.filter((c) => !c.secure || !c.httpOnly);
  findings['SEC-14'] = {
    status: weakCookies.length ? 'fail' : 'pass',
    evidence: cookies.slice(0, 30).map((c) => lib.ev(`(browser) cookie ${c.name}`, 0,
      `Domain=${c.domain} Path=${c.path} Secure=${c.secure} HttpOnly=${c.httpOnly}`,
      lib.SESSION_COOKIE.test(c.name) ? (!c.secure || !c.httpOnly ? 'session-like cookie missing Secure/HttpOnly' : 'session-like cookie') : 'non-session cookie')),
    auto_note: !cookies.length ? 'No cookies were set for the site during the review.'
      : weakCookies.length ? `${weakCookies.length}/${sessionCookies.length} session-like cookie(s) lack Secure or HttpOnly (values not recorded).`
        : `${cookies.length} cookie(s); ${sessionCookies.length} session-like, all Secure + HttpOnly (values not recorded).`,
  };
}

if (corsResults.length) {
  const credOpen = corsResults.filter((c) => c.creds.ok);
  const anonOpen = corsResults.filter((c) => c.anon.ok);
  findings['SEC-06'] = {
    status: credOpen.length ? 'fail' : 'pass',
    evidence: corsResults.map((c) => lib.ev(`(probe) ${lib.redactQueryTokens(c.url)}`, 0,
      `from origin null: without credentials ${c.anon.ok ? `readable (HTTP ${c.anon.status})` : 'blocked'}; with credentials ${c.creds.ok ? `readable (HTTP ${c.creds.status})` : 'blocked'}`,
      c.creds.ok ? 'credentialed cross-origin read allowed from an unrelated origin' : c.anon.ok ? 'public cross-origin read (fine for public content)' : 'cross-origin read blocked')),
    auto_note: `${corsResults.length} endpoint(s) probed from an unrelated origin: ${credOpen.length} allow credentialed reads, ${anonOpen.length} allow anonymous reads.`,
  };
}

if (protectedResults.length) {
  const blocked = (r, u) => !r.ok || r.status === 401 || r.status === 403 || (r.redirected && new URL(r.url).pathname !== new URL(u).pathname);
  const open = protectedResults.filter((x) => !blocked(x.anon, x.url));
  const describe = (r) => (r.ok ? `HTTP ${r.status}${r.redirected ? ` → ${new URL(r.url).pathname}` : ''}, ${r.size} byte(s)` : `blocked (${r.error})`);
  const unauthedReviewer = protectedResults.every((x) => blocked(x.authed, x.url));
  findings['SEC-12'] = {
    status: open.length ? 'review' : 'pass',
    evidence: protectedResults.map((x) => lib.ev(`(probe) ${lib.redactQueryTokens(x.url)}`, 0,
      `without session: ${describe(x.anon)}; with session: ${describe(x.authed)}`,
      blocked(x.anon, x.url) ? 'denied without session' : 'served without session — confirm this is intended')),
    auto_note: `${protectedResults.length} protected URL(s) compared: ${open.length} served without the session.${unauthedReviewer ? ' The reviewer session was not authenticated either — log in first for a meaningful comparison.' : ''}`,
  };
}

if (httpProbe) {
  const hstsSeen = ok.some((p) => p.headers && p.headers['strict-transport-security']);
  const upgraded = httpProbe.to && httpProbe.to.startsWith('https://');
  findings['SEC-11'] = {
    status: httpProbe.error ? 'review' : !upgraded ? 'fail' : hstsSeen ? 'pass' : 'review',
    evidence: [lib.ev(`(browser) ${httpProbe.from}`, 0, httpProbe.error || `resolved to ${httpProbe.to}`, 'http:// navigation')],
    auto_note: httpProbe.error ? `http:// navigation failed: ${httpProbe.error}`
      : !upgraded ? 'http:// is served without moving to https://.'
        : hstsSeen ? 'http:// ends on https:// and HSTS is sent.'
          : 'http:// ended on https://, but without HSTS this may be the browser auto-upgrading rather than the server redirecting.',
  };
}

await lib.mkdirp(`${OUT}/browse`);
await lib.writeJson(`${OUT}/browse/pages.json`, { pages, cors: corsResults, protected: protectedResults, http: httpProbe });
const doc = await lib.loadFindings(findingsPath);
const LIVE_OWNED = new Set(['SEC-04', 'SEC-05', 'SEC-11', 'SEC-14']);
for (const [id, f] of Object.entries(findings)) {
  lib.mergeFinding(doc, id, f, LIVE_OWNED.has(id) ? lib.liveMode(doc, id) : 'combine', 'browser');
}
doc.live_url = doc.live_url || target.href;
doc.pages_reviewed = ok.map((p) => p.finalUrl);
doc.pages_skipped = pages.filter((p) => p.error).map((p) => ({ url: p.url, reason: p.error }));
await lib.writeJson(findingsPath, doc);
lib.printSummary(doc.checks, Object.keys(findings).sort());
console.log(`\nReviewed ${ok.length} page(s) on ${APP_HOST}. Merged into ${findingsPath}`);
for (const p of pages.filter((x) => x.error)) console.log(`  skipped ${p.url}: ${p.error}`);
