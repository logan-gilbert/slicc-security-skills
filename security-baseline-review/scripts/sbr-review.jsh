// sbr-review — run the whole baseline review: scan → deps → live → browse → adjudicate → report.
//
// Usage: sbr-review --site-name <name> [--repo <vfs-path> | --repo-url <https://github.com/org/repo> [--ref <branch|tag>] [--keep-clone]]
//                   [--url <https://site>] [--out <dir>]
//                   [--org Adobe] [--reviewer <email>] [--baseline <findings.json>] [--pdf]
//                   [--pages /a,/b] [--max-pages 5] [--protected /x,/y] [--api <url,...>] [--no-probes]
//                   [--login] [--login-timeout 300] [--state <auth-state.json>] [--app-host <host>]
//                   [--omit-dev] [--concurrency 4] [--model <id>] [--no-browser] [--no-adjudicate]
//                   [--draft] [--open]
//
// Stops at the first failing stage. Starts from a fresh findings.json (sbr-scan rewrites it).
// --open opens the HTML report in a browser tab when every stage succeeds.
// --repo-url clones into /workspace/sbr-src/ (private repos: sign in under Settings → Providers → GitHub);
//   the clone is deleted after a successful run unless --keep-clone is given.
// With neither --repo nor --repo-url (but --url), runs a live-only review; code checks show as not run.

const cli = require('sliccy:cli');
const { exec } = require('sliccy:exec');
const lib = require('./sbr-lib.js');

const { flags } = process.argv.parseFlags();
if (flags.help || !flags['site-name'] || (!flags.repo && !flags['repo-url'] && !flags.url)) {
  cli.help('Usage: sbr-review --site-name <name> [--repo <vfs-path> | --repo-url <https://github.com/org/repo> [--ref <branch|tag>] [--keep-clone]] [--url <https://site>] [--out <dir>] [--org Adobe] [--reviewer <email>] [--baseline <findings.json>] [--pdf] [--pages ...] [--max-pages 5] [--protected ...] [--api ...] [--no-probes] [--login] [--login-timeout 300] [--state <file>] [--app-host <host>] [--omit-dev] [--concurrency 4] [--model <id>] [--no-browser] [--no-adjudicate] [--draft] [--open]\nNeeds --repo, --repo-url, or (for a live-only review) --url.');
  process.exit(flags.help ? 0 : 2);
}
if (flags.repo && flags['repo-url']) cli.die('use either --repo or --repo-url, not both', 2);
const out = lib.stripSlash(String(flags.out || '/workspace/security-review-out'));
const pass = (names) => names.flatMap((n) => {
  if (flags[n] === undefined) return [];
  return flags[n] === true ? [`--${n}`] : [`--${n}`, String(flags[n])];
});

let repo = flags.repo ? String(flags.repo) : null;
let repoUrl = null;
let clonePath = null;
if (flags['repo-url']) {
  let u;
  try {
    u = new URL(String(flags['repo-url']));
  } catch {
    cli.die(`invalid --repo-url: ${flags['repo-url']}`, 2);
  }
  if (u.protocol !== 'https:') cli.die('--repo-url must be an https:// URL', 2);
  // A token in the URL would end up in shell history, logs and findings.json.
  if (u.username || u.password) cli.die('--repo-url must not contain credentials; sign in under Settings → Providers → GitHub instead', 2);
  u.hash = '';
  repoUrl = u.href;
  const name = (u.pathname.split('/').filter(Boolean).pop() || 'repo').replace(/\.git$/, '').replace(/[^\w.-]/g, '_');
  clonePath = `/workspace/sbr-src/${name}-${Date.now().toString(36)}`;
  await lib.mkdirp('/workspace/sbr-src');
  const cloneArgv = ['git', 'clone', ...(flags.ref ? ['--branch', String(flags.ref)] : []), repoUrl, clonePath];
  console.log(`\n▶ ${cloneArgv.join(' ')}`);
  const c = await exec.spawn(cloneArgv);
  if (c.stdout) process.stdout.write(c.stdout);
  if (c.exitCode !== 0) {
    if (c.stderr) process.stderr.write(c.stderr);
    await exec.spawn(['rm', '-rf', clonePath]);
    const hint = /40[134]|not found|auth|permission/i.test(`${c.stderr}${c.stdout}`)
      ? ' If the repository is private, sign in under Settings → Providers → GitHub and try again.'
      : '';
    cli.die(`could not clone ${repoUrl}.${hint}`, c.exitCode || 1);
  }
  repo = clonePath;
}

const stages = [];
if (repo) {
  stages.push(['sbr-scan', '--repo', repo, '--out', out, ...(repoUrl ? ['--source-url', repoUrl] : [])]);
  stages.push(['sbr-deps', '--repo', repo, '--out', out, ...pass(['omit-dev'])]);
} else {
  const { checklist } = await lib.loadChecklist();
  await lib.mkdirp(out);
  await lib.writeJson(`${out}/findings.json`, {
    checks: {},
    checklist: { name: checklist.meta.name, version: checklist.meta.version },
    code_access: false,
    review_date: new Date().toISOString().slice(0, 10),
  });
  console.log('\nNo --repo or --repo-url: running a live-only review. Code checks will show as not run.');
}
if (flags.url) {
  stages.push(['sbr-live', '--url', String(flags.url), '--out', out]);
  if (!flags['no-browser']) {
    stages.push(['sbr-browse', '--url', String(flags.url), '--out', out, ...pass(['pages', 'max-pages', 'protected', 'api', 'settle-ms', 'no-probes', 'login', 'login-timeout', 'state', 'app-host'])]);
  }
}
if (!flags['no-adjudicate']) stages.push(['sbr-adjudicate', '--out', out, ...pass(['concurrency', 'model'])]);
stages.push(['sbr-report', '--out', out, '--site-name', String(flags['site-name']), ...pass(['org', 'reviewer', 'date', 'baseline', 'pdf', 'draft'])]);

let failure = null;
for (const argv of stages) {
  console.log(`\n▶ ${argv.map((a) => (/\s/.test(a) ? JSON.stringify(a) : a)).join(' ')}`);
  if (argv[0] === 'sbr-browse' && flags.login) {
    console.log('  A tab will open in the foreground: sign in there. The review continues on its own once you are back on the site.');
  }
  const r = await exec.spawn(argv);
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  if (r.exitCode !== 0) {
    failure = { stage: argv[0], code: r.exitCode };
    break;
  }
}
if (clonePath) {
  // Kept after a failure so individual stages can be re-run against it.
  if (failure || flags['keep-clone']) {
    console.log(`\nClone kept at ${clonePath} — delete it with: rm -rf ${clonePath}`);
  } else {
    await exec.spawn(['rm', '-rf', clonePath]);
    console.log(`\nRemoved temporary clone ${clonePath}`);
  }
}
if (failure) {
  cli.die(`${failure.stage} failed (exit ${failure.code}); later stages skipped. Fix and re-run that stage${clonePath ? ` (use --repo ${clonePath} for code stages)` : ''}.`, failure.code);
}
if (flags.open) {
  const report = `${out.replace(/\/+$/, '')}/security-baseline-review.html`;
  const o = await exec.spawn(['open', report]);
  console.log(o.exitCode === 0 ? `\nOpened ${report}` : `\nReport ready but could not be opened automatically: ${report}`);
}
console.log('\nBaseline review complete. This is a hygiene baseline, not a full audit or penetration test.');
