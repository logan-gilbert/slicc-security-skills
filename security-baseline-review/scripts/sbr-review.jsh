// sbr-review — run the whole baseline review: scan → deps → live → browse → adjudicate → report.
//
// Usage: sbr-review --repo <vfs-path> --site-name <name> [--url <https://site>] [--out <dir>]
//                   [--org Adobe] [--reviewer <email>] [--baseline <findings.json>] [--pdf]
//                   [--pages /a,/b] [--max-pages 5] [--protected /x,/y] [--api <url,...>] [--no-probes]
//                   [--omit-dev] [--concurrency 4] [--model <id>] [--no-browser] [--no-adjudicate]
//
// Stops at the first failing stage. Starts from a fresh findings.json (sbr-scan rewrites it).

const cli = require('sliccy:cli');
const { exec } = require('sliccy:exec');

const { flags } = process.argv.parseFlags();
if (flags.help || !flags.repo || !flags['site-name']) {
  cli.help('Usage: sbr-review --repo <vfs-path> --site-name <name> [--url <https://site>] [--out <dir>] [--org Adobe] [--reviewer <email>] [--baseline <findings.json>] [--pdf] [--pages ...] [--max-pages 5] [--protected ...] [--api ...] [--no-probes] [--omit-dev] [--concurrency 4] [--model <id>] [--no-browser] [--no-adjudicate]');
  process.exit(flags.help ? 0 : 2);
}
const out = String(flags.out || '/workspace/security-review-out');
const pass = (names) => names.flatMap((n) => {
  if (flags[n] === undefined) return [];
  return flags[n] === true ? [`--${n}`] : [`--${n}`, String(flags[n])];
});

const stages = [['sbr-scan', '--repo', String(flags.repo), '--out', out]];
stages.push(['sbr-deps', '--repo', String(flags.repo), '--out', out, ...pass(['omit-dev'])]);
if (flags.url) {
  stages.push(['sbr-live', '--url', String(flags.url), '--out', out]);
  if (!flags['no-browser']) {
    stages.push(['sbr-browse', '--url', String(flags.url), '--out', out, ...pass(['pages', 'max-pages', 'protected', 'api', 'settle-ms', 'no-probes'])]);
  }
}
if (!flags['no-adjudicate']) stages.push(['sbr-adjudicate', '--out', out, ...pass(['concurrency', 'model'])]);
stages.push(['sbr-report', '--out', out, '--site-name', String(flags['site-name']), ...pass(['org', 'reviewer', 'date', 'baseline', 'pdf'])]);

for (const argv of stages) {
  console.log(`\n▶ ${argv.join(' ')}`);
  const r = await exec.spawn(argv);
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  if (r.exitCode !== 0) cli.die(`${argv[0]} failed (exit ${r.exitCode}); later stages skipped. Fix and re-run from sbr-scan.`, r.exitCode);
}
console.log('\nBaseline review complete. This is a hygiene baseline, not a full audit or penetration test.');
