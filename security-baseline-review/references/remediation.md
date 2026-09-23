# Remediation guidance (EDS baseline)

Plain-English fixes for each check, for the customer-facing report and for triage.

## SEC-01 · Secrets in committed / client-side code — Critical
Anything shipped to the browser or committed to git is effectively public.
- Move secrets to **Cloudflare Worker secrets** (`wrangler secret put NAME`) or server-side env.
- Front third-party APIs with a Worker/proxy so the browser never holds the credential.
- If a secret was ever committed, **rotate it** and scrub history (`git filter-repo`).

## SEC-02 · Secret files tracked / not gitignored — High
- Add `.env`, `.dev.vars`, `*.pem` to `.gitignore`.
- Ship `.dev.vars.example` / `.env.example` with empty values as documentation.
- Remove any tracked secret file and rotate its contents.

## SEC-03 · DOM XSS sinks — High
- Prefer `createElement` + `textContent` over `innerHTML`.
- If HTML is required, sanitize with a vetted sanitizer or enforce **Trusted Types** via CSP
  (`require-trusted-types-for 'script'`).
- Reserve `innerHTML` for static developer strings; treat every API/URL/user value as hostile.

## SEC-04 · Content Security Policy — High
- Define a CSP (EDS: `head.html` meta with `move-to-http-header="true"`, or via the Worker/CDN).
- Prefer nonces + `strict-dynamic`; set `object-src 'none'`, `base-uri 'self'`, `frame-ancestors`.

## SEC-05 · Security response headers — High
Add via the EDS headers mechanism, the fronting Worker, or the CDN:
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin` (or stricter)
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Permissions-Policy` (disable unused features)
- Clickjacking: `frame-ancestors` in CSP (or `X-Frame-Options: DENY/SAMEORIGIN`)

## SEC-06 · CORS not wildcard in production — Medium
- Use an **exact production allowlist**; keep broad `*.aem.page/live`/localhost matching to
  dev/preview envs only.
- Never treat CORS as authentication — it is a browser convenience, not a server-side gate.

## SEC-07 · Subresource Integrity — Medium
- Add `integrity="sha384-…" crossorigin="anonymous"` to external `<script>`/`<link>`.
- Better: self-host the resource from the site origin.

## SEC-08 · Vulnerable dependencies — Medium
- Run `npm audit` in CI; fix or update high/critical advisories.
- Enable Renovate/Dependabot for automated updates.

## SEC-09 · Sensitive data in published content — Medium
- EDS publishes spreadsheet-backed `.json` and content publicly — remove PII / internal-only
  fields, or move that data behind an authenticated API.

## SEC-10 · Token leakage — Medium
- Send tokens in headers or `HttpOnly` cookies, never in URL query strings.
- Strip secrets from `console.*` logging and analytics payloads.

## SEC-11 · HTTPS + TLS — Low
- Enforce HTTPS and HSTS at the CDN/domain; redirect `http://` → `https://`.
- Keep the certificate valid and current (monitor expiry).

## SEC-12 · Access gating — Info/context
- If the site is meant to be private, enforce auth at the Worker/proxy or origin gate;
  **deny by default** and **fail closed** when auth config is missing.

## SEC-13 · Error handling — Low
- Return generic status codes/messages to clients (400/401/403/500/502).
- Log stack traces and upstream detail **server-side only**, never with secrets.

## SEC-14 · Session cookies — Medium
- Set session/auth cookies with `Secure; HttpOnly; SameSite=Lax` (or `Strict`).
- Prefer the `__Host-` prefix (forces `Secure`, `Path=/`, no `Domain`).
- Never expose session tokens to page scripts (no JS-readable cookies or `localStorage` tokens).
