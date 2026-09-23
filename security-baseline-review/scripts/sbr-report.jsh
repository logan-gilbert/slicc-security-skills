// sbr-report — render findings.json into the detailed report + customer one-pager (port of build_report.py).
//
// Usage: sbr-report [--out <dir>] --site-name <name> [--org Adobe] [--reviewer <email>] [--date YYYY-MM-DD]
//                   [--baseline <prior findings.json>] [--pdf] [--draft]
//
// Writes security-baseline-review.{html,csv[,pdf]} and security-review-overview.{html[,pdf]} into <out>.
// Refuses to build while a `review` check has no reviewer note (run sbr-adjudicate); --draft overrides
// and stamps the report DRAFT. --pdf prints via a browser tab (CLI/standalone only; not the extension).

const fs = require('fs');
const cli = require('sliccy:cli');
const lib = require('./sbr-lib.js');

const { flags } = process.argv.parseFlags();
if (flags.help || !flags['site-name']) {
  cli.help('Usage: sbr-report [--out <dir>] --site-name <name> [--org Adobe] [--reviewer <email>] [--date YYYY-MM-DD] [--baseline <findings.json>] [--pdf] [--draft]');
  process.exit(flags.help ? 0 : 2);
}
const OUT = lib.stripSlash(String(flags.out || '/workspace/security-review-out'));
const SITE = String(flags['site-name']);
const ORG = String(flags.org || 'Adobe');
const REVIEWER = String(flags.reviewer || '');
const DATE = String(flags.date || new Date().toISOString().slice(0, 10));
const DRAFT = !!flags.draft;

const STATUS_ORDER = { fail: 0, review: 1, pass: 2, skipped: 3 };
const LABEL = { pass: 'Pass', fail: 'Fail', review: 'Needs attention', skipped: 'N/A' };
const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const csvCell = (v) => {
  const s = String(v ?? '');
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
// Single pass so placeholder-looking text inside evidence is never substituted.
const fill = (tpl, map) => String(tpl).replace(/\{\{([A-Z_]+)\}\}/g, (m, k) => (k in map ? map[k] : m));

const { checklist, meta, order } = await lib.loadChecklist();
const findingsPath = `${OUT}/findings.json`;
if (!(await fs.exists(findingsPath))) cli.die(`findings not found: ${findingsPath} (run sbr-scan first)`);
const findings = await lib.readJson(findingsPath);
const fchecks = findings.checks || {};

const unresolved = order.filter((id) => fchecks[id] && fchecks[id].status === 'review' && !fchecks[id].reviewer_note);
if (unresolved.length && !DRAFT) {
  cli.die(`${unresolved.length} check(s) still need adjudication: ${unresolved.join(', ')}. Run sbr-adjudicate (or add a reviewer_note), or pass --draft.`);
}

function evidenceHtml(evidence) {
  if (!evidence || !evidence.length) return '';
  const rows = evidence.slice(0, 25).map((e) => {
    const where = `${e.file || ''}${e.line ? `:${e.line}` : ''}`;
    let block = `<span class="loc">${esc(where)}</span>`;
    if (e.note) block += `  <span class="note"># ${esc(e.note)}</span>`;
    if (e.snippet) block += `\n${esc(e.snippet)}`;
    return `<div class="evidence">${block}</div>`;
  });
  const extra = evidence.length > 25 ? `<p class="small">…and ${evidence.length - 25} more (see findings.json).</p>` : '';
  return rows.join('') + extra;
}

async function changesPanel() {
  if (!flags.baseline) return '';
  const path = String(flags.baseline);
  if (!(await fs.exists(path))) {
    return `<div class='changes'><h3>Changes since last review</h3><p class='small'>Baseline not found at ${esc(path)} — treated as a first review.</p></div>`;
  }
  const d = lib.computeDiff(await lib.readJson(path), findings, meta);
  const group = (cls, title, items) => (items.length
    ? `<div class='grp ${cls}'><div class='lbl'>${esc(title)} (${items.length})</div><ul>${items.map((e) =>
      `<li><span class='id'>${esc(e.id)}</span> ${esc(e.title)} <span class='chg-arrow'>${esc(e.from || '—')} &rarr; ${esc(e.to || '—')}</span></li>`).join('')}</ul></div>`
    : '');
  const body = group('reg', 'Regressions', d.regressions) + group('fix', 'Resolved since last review', d.fixes)
    + group('add', 'New checks', d.added) + group('rem', 'Removed checks', d.removed)
    || "<p class='none'>No status changes since the baseline review.</p>";
  const sub = d.baseline_date ? ` (baseline: ${esc(d.baseline_date)})` : '';
  return `<div class='changes'><h3>Changes since last review${sub}</h3>${body}<p class='small'>Unchanged checks: ${d.unchanged_count}.</p></div>`;
}

const counts = { pass: 0, fail: 0, review: 0, skipped: 0 };
const summaryRows = [];
const cards = [];
const sorted = [...order].sort((a, b) => {
  const sa = STATUS_ORDER[(fchecks[a] || {}).status] ?? 3;
  const sb = STATUS_ORDER[(fchecks[b] || {}).status] ?? 3;
  return sa - sb || (lib.SEV_ORDER[meta[a].severity] ?? 5) - (lib.SEV_ORDER[meta[b].severity] ?? 5);
});
for (const id of sorted) {
  const c = meta[id];
  const f = fchecks[id] || { status: 'skipped', evidence: [], auto_note: 'Not run.' };
  const st = STATUS_ORDER[f.status] === undefined ? 'skipped' : f.status;
  counts[st]++;
  summaryRows.push(`<tr><td class='id'>${esc(id)}</td><td>${esc(c.title)}</td><td>${esc(c.category)}</td>`
    + `<td class='sev sev-${esc(c.severity)}'>${esc(c.severity)}</td><td><span class='pill st-${esc(st)}'>${esc(LABEL[st])}</span></td></tr>`);
  const aiTag = String(f.adjudicated_by || '').startsWith('ai') ? "<span class='tag-ai'>AI-assisted</span>" : '';
  cards.push(`<div class='finding'><div class='head'><h3>${esc(id)} &nbsp;·&nbsp; ${esc(c.title)}</h3>`
    + `<span class='pill st-${esc(st)}'>${esc(LABEL[st])}</span></div>`
    + `<div class='cat'>${esc(c.category)} &nbsp;·&nbsp; <span class='sev sev-${esc(c.severity)}'>${esc(c.severity)} severity</span></div>`
    + `<p>${esc(c.description)}</p>`
    + (f.auto_note ? `<p class='small'><strong>Automated result:</strong> ${esc(f.auto_note)}</p>` : '')
    + (f.reviewer_note ? `<p><strong>Reviewer note:</strong>${aiTag} ${esc(f.reviewer_note)}</p>` : '')
    + evidenceHtml(f.evidence)
    + `<div class='remediation'><div class='lbl'>Remediation</div>${esc(c.remediation)}</div></div>`);
}

const draftBanner = DRAFT && unresolved.length
  ? `<div class='disclaimer'><strong>DRAFT — not for customer delivery.</strong> ${unresolved.length} check(s) are not yet adjudicated: ${esc(unresolved.join(', '))}.</div>`
  : '';
const reportHtml = fill(await fs.readFile(`${lib.TEMPLATES}/report.html`), {
  SITE_NAME: esc(DRAFT ? `${SITE} (DRAFT)` : SITE),
  ORG_NAME: esc(ORG),
  REPO: esc(findings.target_repo || '—'),
  LIVE_URL: esc(findings.live_url || '—'),
  REVIEWER: esc(REVIEWER),
  DATE: esc(DATE),
  CHECKLIST_VERSION: esc(checklist.meta.version),
  N_PASS: String(counts.pass),
  N_FAIL: String(counts.fail),
  N_REVIEW: String(counts.review),
  N_SKIP: String(counts.skipped),
  SUMMARY_ROWS: summaryRows.join('\n'),
  DETAIL_CARDS: cards.join('\n'),
  CHANGES_PANEL: draftBanner + (await changesPanel()),
});

const byCat = {};
for (const c of checklist.checks) (byCat[c.category] = byCat[c.category] || []).push(c.title);
const onePagerHtml = fill(await fs.readFile(`${lib.TEMPLATES}/one-pager.html`), {
  SITE_NAME: esc(SITE),
  ORG_NAME: esc(ORG),
  DATE: esc(DATE),
  CHECKLIST_VERSION: esc(checklist.meta.version),
  COVERAGE_LIST: Object.entries(byCat).map(([cat, titles]) => `<li><span class='cat'>${esc(cat)}</span> — ${esc(titles.join('; '))}</li>`).join('\n'),
});

await lib.mkdirp(OUT);
const reportPath = `${OUT}/security-baseline-review.html`;
const onePagerPath = `${OUT}/security-review-overview.html`;
const csvPath = `${OUT}/security-baseline-review.csv`;
await fs.writeFile(reportPath, reportHtml);
await fs.writeFile(onePagerPath, onePagerHtml);
const csv = [['id', 'title', 'category', 'severity', 'method', 'result', 'evidence_count', 'auto_note', 'reviewer_note', 'adjudicated_by']];
for (const id of order) {
  const c = meta[id];
  const f = fchecks[id] || {};
  csv.push([id, c.title, c.category, c.severity, c.method, f.status || 'skipped', (f.evidence || []).length,
    f.auto_note || '', f.reviewer_note || '', f.adjudicated_by || '']);
}
await fs.writeFile(csvPath, csv.map((r) => r.map(csvCell).join(',')).join('\n') + '\n');

// The HTML is self-contained (inline CSS/SVG), so writing it into about:blank renders it faithfully.
async function toPdf(html, pdfPath) {
  const loader = `${OUT}/.sbr-render.js`;
  let tab = null;
  try {
    await fs.writeFile(loader, `document.open();document.write(${JSON.stringify(html)});document.close();'ok'`);
    tab = await lib.openTab('about:blank');
    const w = await lib.pw(['eval-file', `--tab=${tab}`, loader]);
    if (w.exitCode !== 0) throw new Error(w.stderr.trim());
    const p = await lib.pw(['pdf', `--tab=${tab}`, `--filename=${pdfPath}`]);
    if (p.exitCode !== 0) throw new Error((p.stderr || p.stdout).trim());
    return pdfPath;
  } catch (e) {
    console.error(`  (PDF skipped: ${e.message.split('\n')[0]} — print the HTML to PDF from the browser instead.)`);
    return null;
  } finally {
    if (tab) await lib.closeTab(tab);
    if (await fs.exists(loader)) await fs.rm(loader);
  }
}

let reportPdf = null;
let onePagerPdf = null;
if (flags.pdf) {
  reportPdf = await toPdf(reportHtml, `${OUT}/security-baseline-review.pdf`);
  if (reportPdf) onePagerPdf = await toPdf(onePagerHtml, `${OUT}/security-review-overview.pdf`);
}

console.log(`Pass ${counts.pass} · Fail ${counts.fail} · Needs attention ${counts.review} · N/A ${counts.skipped}${DRAFT && unresolved.length ? ' · DRAFT' : ''}`);
console.log(`Report HTML:   ${reportPath}`);
console.log(`Report CSV:    ${csvPath}`);
console.log(`Report PDF:    ${reportPdf || '(not generated)'}`);
console.log(`Overview HTML: ${onePagerPath}`);
console.log(`Overview PDF:  ${onePagerPdf || '(not generated)'}`);
const ai = order.filter((id) => String((fchecks[id] || {}).adjudicated_by || '').startsWith('ai'));
if (ai.length) console.log(`\nAI-assisted judgments to confirm before delivery: ${ai.join(', ')}`);
