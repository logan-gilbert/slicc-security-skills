// sbr-diff — console diff of two findings.json files (port of diff_baseline.py).
//
// Usage: sbr-diff --baseline <prior findings.json> [--current <findings.json>] [--out <dir>]

const fs = require('fs');
const cli = require('sliccy:cli');
const lib = require('./sbr-lib.js');

const { flags } = process.argv.parseFlags();
if (flags.help || !flags.baseline) {
  cli.help('Usage: sbr-diff --baseline <prior findings.json> [--current <findings.json>] [--out <dir>]');
  process.exit(flags.help ? 0 : 2);
}
const current = String(flags.current || `${lib.stripSlash(String(flags.out || '/workspace/security-review-out'))}/findings.json`);
for (const p of [String(flags.baseline), current]) if (!(await fs.exists(p))) cli.die(`not found: ${p}`, 2);

const { meta } = await lib.loadChecklist();
const d = lib.computeDiff(await lib.readJson(String(flags.baseline)), await lib.readJson(current), meta);
const show = (title, items) => {
  console.log(`\n${title} (${items.length}):`);
  for (const e of items) console.log(`  ${e.id.padEnd(8)} ${String(e.severity).padEnd(10)} ${e.title}  [${e.from || '—'} -> ${e.to || '—'}]`);
};
console.log(`=== Changes since last review${d.baseline_date ? ` (baseline ${d.baseline_date})` : ''} ===`);
show('REGRESSIONS', d.regressions);
show('FIXES', d.fixes);
show('ADDED', d.added);
show('REMOVED', d.removed);
console.log(`\nUnchanged: ${d.unchanged_count}`);
