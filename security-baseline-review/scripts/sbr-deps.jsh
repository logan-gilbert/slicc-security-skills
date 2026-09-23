// sbr-deps — SEC-08 dependency audit without npm (SLICC has no `npm audit`).
//
// Usage: sbr-deps --repo <vfs-path> [--out <dir>] [--omit-dev]
//
// Reads package-lock.json (v1, v2 or v3) and posts the installed versions to the
// npm bulk advisory endpoint npm audit itself uses. Merges into <out>/findings.json.

const fs = require('fs');
const cli = require('sliccy:cli');
const lib = require('./sbr-lib.js');

const BULK_URL = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk';
const SEV_RANK = { critical: 0, high: 1, moderate: 2, low: 3, info: 4 };

const { flags } = process.argv.parseFlags();
if (flags.help || !flags.repo) {
  cli.help('Usage: sbr-deps --repo <vfs-path> [--out <dir>] [--omit-dev]');
  process.exit(flags.help ? 0 : 2);
}
const REPO = lib.stripSlash(String(flags.repo));
const OUT = lib.stripSlash(String(flags.out || '/workspace/security-review-out'));
const OMIT_DEV = !!flags['omit-dev'];
const findingsPath = `${OUT}/findings.json`;

function collect(lock) {
  const pkgs = new Map();
  const addPkg = (name, version, dev) => {
    if (!name || !version || (OMIT_DEV && dev)) return;
    const entry = pkgs.get(name) || { versions: new Set(), dev: true };
    entry.versions.add(version);
    entry.dev = entry.dev && !!dev;
    pkgs.set(name, entry);
  };
  if (lock.packages) {
    for (const [key, p] of Object.entries(lock.packages)) {
      if (!key || p.link) continue;
      const name = p.name || key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      addPkg(name, p.version, p.dev);
    }
  } else if (lock.dependencies) {
    const visit = (deps) => {
      for (const [name, d] of Object.entries(deps || {})) {
        addPkg(name, d.version, d.dev);
        visit(d.dependencies);
      }
    };
    visit(lock.dependencies);
  }
  return pkgs;
}

async function finish(finding) {
  await lib.mkdirp(OUT);
  const doc = await lib.loadFindings(findingsPath);
  lib.mergeFinding(doc, 'SEC-08', finding, 'replace', 'deps');
  await lib.writeJson(findingsPath, doc);
  lib.printSummary(doc.checks, ['SEC-08']);
  console.log(`\nMerged into ${findingsPath}`);
}

const lockPath = `${REPO}/package-lock.json`;
if (!(await fs.exists(lockPath))) {
  await finish({ status: 'skipped', evidence: [], auto_note: 'No package-lock.json (no npm dependency tree to audit).' });
  process.exit(0);
}

const pkgs = collect(await lib.readJson(lockPath));
const body = {};
for (const [name, e] of pkgs) body[name] = [...e.versions];

let advisories;
try {
  const r = await fetch(BULK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  advisories = await r.json();
} catch (e) {
  await finish({
    status: 'skipped',
    evidence: [],
    auto_note: `npm advisory endpoint unreachable (${e.message}); ${pkgs.size} package(s) not audited.`,
  });
  process.exit(0);
}

// Count vulnerable packages by their worst advisory, as npm audit's metadata does.
const counts = { critical: 0, high: 0, moderate: 0, low: 0, info: 0 };
const rows = [];
for (const [name, list] of Object.entries(advisories || {})) {
  if (!Array.isArray(list) || !list.length) continue;
  const sorted = [...list].sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
  const worst = sorted[0].severity || 'info';
  counts[worst] = (counts[worst] || 0) + 1;
  const dev = pkgs.get(name)?.dev ? ' (dev only)' : '';
  for (const a of sorted) {
    rows.push({
      rank: SEV_RANK[a.severity] ?? 9,
      ev: lib.ev(`${name}${dev}`, 0, `${a.severity}: ${a.title || ''} — vulnerable ${a.vulnerable_versions || '?'}`,
        a.url || `advisory ${a.id}`),
    });
  }
}
rows.sort((a, b) => a.rank - b.rank);
const summary = `critical ${counts.critical}, high ${counts.high}, moderate ${counts.moderate}, low ${counts.low}`;
const bad = counts.critical + counts.high;
await finish({
  status: bad ? 'fail' : 'pass',
  evidence: [lib.ev('package-lock.json', 0, summary, `${pkgs.size} package(s) audited${OMIT_DEV ? ', dev omitted' : ''}`),
    ...rows.slice(0, 25).map((r) => r.ev)],
  auto_note: bad ? `${bad} package(s) with critical/high advisories — ${summary}.` : `No critical/high advisories (${summary}).`,
});
