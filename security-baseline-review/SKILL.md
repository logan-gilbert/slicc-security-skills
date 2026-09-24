---
name: security-baseline-review
description: |
  Use this when the user asks to security-review, security-check, do a baseline or hygiene
  review, or produce a security report for a delivered Adobe Edge Delivery Services (EDS)
  site and its Worker / Content Hub integrations. Covers the static repo scan, dependency
  audit, live and in-browser checks (headers per page, cookies, runtime SRI, token leakage,
  CORS, gating, HTTPS), AI-assisted adjudication, and the branded HTML/CSV/PDF report +
  customer one-pager. A baseline hygiene check, NOT a penetration test or full audit.
allowed-tools: bash, read_file, write_file, edit
---

# Security baseline review (EDS)

Produce a repeatable, defensible **baseline** security-hygiene review of a delivered EDS site
and a customer-facing report. Every report states it is **not** a full audit, penetration test,
or certification; the customer remains responsible for a full independent assessment. Never
overstate results.

The deterministic work lives in `.jsh` commands (auto-discovered by basename). Run them; do not
re-derive their logic in prose.

| Command          | Stage                                                                  | Needs          |
| ---------------- | ---------------------------------------------------------------------- | -------------- |
| `sbr-scan`       | Static repo scan → fresh `findings.json` (SEC-01–13 candidates)         | repo           |
| `sbr-deps`       | SEC-08 via the npm advisory database (replaces `npm audit`)             | repo, network  |
| `sbr-live`       | Base-URL headers, HTTPS + HSTS, error-page probe (proxied fetch)       | URL            |
| `sbr-browse`     | Real-tab checks: per-page headers + meta CSP, cookies, runtime SRI, request-URL token scan, CORS probe, gated-URL comparison, http:// navigation | URL, browser |
| `sbr-adjudicate` | Parallel read-only sub-agents resolve every `review` check             | findings       |
| `sbr-report`     | HTML + CSV (+ PDF with `--pdf`) report and one-pager                   | findings       |
| `sbr-diff`       | Console diff against a prior `findings.json`                           | two findings   |
| `sbr-review`     | Runs all of the above in order, stopping at the first failure          | —              |

All commands take `--out <dir>` (default `/workspace/security-review-out`) and `--help`.

## 1. Gather inputs

Ask for whatever is missing:

- **Repo** (required) — get it into the VFS: `mount /mnt/<site>` (local folder; cone only, needs the
  user's click) or `git clone <url> /workspace/<site>`. For EDS content, `mount --source da://<org>/<repo> /mnt/<site>-content`
  lets you read published sheets for SEC-09.
- **Live URL** (recommended) and **authorization**: confirm the user is authorized to test that
  site. Without explicit confirmation, run `sbr-browse --no-probes` (observation only).
- **Is the site gated?** If so, pass `--login`: the site opens in a foreground tab, the user signs
  in there, and the scan starts once the tab is back on the site (`--login-timeout` seconds, default
  300). The session is saved to `<out>/auth-state.json`; reuse it with `--state <file>`. If the app
  lives on a different host than `--url` after sign-in, pass `--app-host`. Pages that end on any
  other host (e.g. the identity provider) are skipped and listed, never scored. Also ask which URLs
  must require login → `--protected`.
- **Site name**, **org** (default Adobe), **reviewer**, optional **prior findings.json** (`--baseline`).

## 2. Run the review

```bash
sbr-review --repo /mnt/site --url https://site.example --site-name "Site Name" \
  --reviewer me@adobe.com --protected /api/me,/private --login --pdf --open
```

`--open` opens the HTML report in a tab when every stage succeeds.

Or stage by stage (same flags) when you need to inspect or re-run a step. Always restart from
`sbr-scan`: it rewrites `findings.json`, and later stages merge into it.

## 3. Confirm the AI-assisted judgments — required

`sbr-adjudicate` gives each `review` check to its own read-only sub-agent (repo + output dir only,
read commands only, structured output). Results are tagged `adjudicated_by: "ai"` and shown as
*AI-assisted* in the report. Before delivery:

1. Show the user each AI-assisted call (`jq '.checks | to_entries[] | select(.value.adjudicated_by) | {id: .key, status: .value.status, note: .value.reviewer_note}' <out>/findings.json`).
2. Spot-check the cited `file:line`s yourself for every `fail` and every Critical/High check.
3. Edit `findings.json` where you or the user disagree, then re-run `sbr-report`.

`sbr-report` refuses to build while any `review` check lacks a `reviewer_note`; `--draft` overrides
and stamps the report DRAFT (never send a draft to a customer). Use `sbr-adjudicate --dry-run` to
see the exact prompts, `--ids SEC-03` to redo one check.

Calibration: a mature site (strict CSP, secrets in Worker secrets, Trusted Types) should
legitimately PASS. A wall of false positives destroys the report's credibility.

## 4. Report back

Give the pass / fail / needs-attention tally, the top findings (most severe first), changes since
the baseline, which judgments were AI-assisted, and the output paths:
`security-baseline-review.{html,csv,pdf}`, `security-review-overview.{html,pdf}`, `findings.json`
(**retain it as the next review's `--baseline`**), and `browse/pages.json` (raw browser evidence).
Reiterate that this is a baseline, not a full audit.

## Test posture (do not exceed)

Allowed: page loads, observing headers / cookies / requests / DOM, GET requests, one GET for a
non-existent path, cross-origin GETs from an opaque-origin tab, and comparing a protected URL with
and without the reviewer's session. Crawling skips logout/delete-style links.

Never: fuzzing, payloads, brute force, auth bypass attempts, non-GET requests to the target,
load generation, or testing a site the user has not confirmed they may test.

## Known limits (state them if asked)

- **TLS expiry** is not visible from SLICC; SEC-11 records only that the certificate was accepted.
- **http→https**: the fetch proxy always follows redirects, so SEC-11 uses a browser navigation;
  without HSTS it cannot tell a server redirect from the browser auto-upgrading (left as review).
- **SameSite** is not reported by `playwright-cli cookie-list`; SEC-14 checks Secure + HttpOnly only.
  Cookie values are never recorded.
- **CORS** is probed from a real tab because the CLI fetch proxy strips upstream `access-control-*` headers.
- **Runtime DOM-sink tracing** is not done; SEC-03 is static sinks + whether Trusted Types is enforced.
- **PDF** needs CLI/standalone mode (`playwright-cli pdf` is unavailable in the extension); otherwise
  open the HTML and print it.

## Don't

- Don't deliver a report with unconfirmed AI-assisted `fail`s or a DRAFT stamp.
- Don't paste secret values, cookie values, or tokens into notes or chat — evidence is already masked.
- Don't keep or share `auth-state.json`: it holds live session cookies. Delete it after the review.
- Don't hand-edit checks into the scripts; tune `checklist.json` (data) instead.
