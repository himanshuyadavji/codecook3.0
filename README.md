# CodeCook

Find the vulnerability. Understand the risk. Fix it before deployment.

CodeCook is a web app that scans pasted or uploaded JavaScript/TypeScript and Python code for common security problems, rates each finding, explains it in plain language and shows a safer version.

## Quick start (Hinglish)

1. Node.js 18 ya naya install karo (https://nodejs.org).
2. Zip extract karo, folder me terminal kholo.
3. `npm start` chalao (koi `npm install` nahi chahiye, kyunki koi dependency use nahi hui).
4. Browser me http://localhost:3000 kholo.
5. Tests: `npm test`.

## Run

```bash
npm start                      # http://127.0.0.1:3000
PORT=8080 HOST=0.0.0.0 npm start   # for a server / container
npm test
```

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | 3000 | Port to listen on |
| `HOST` | 127.0.0.1 | Use `0.0.0.0` when deploying |
| `DATA_DIR` | `./data` | Where saved scan results (history) are written |
| `NODE_ENV` | | Set `production` to add the HSTS header |

## What it does

- Paste code, drop a file, or upload `.js .jsx .mjs .cjs .ts .tsx .py` (max 512 KB).
- Automatic language detection, or choose the language.
- 23 deterministic rules: SQL injection, XSS, hardcoded secrets and known token formats, command injection, dynamic code evaluation, path traversal, weak crypto, predictable randomness, insecure deserialization, disabled TLS verification, debug mode, and unvalidated input.
- Each finding has: severity (Critical, High, Medium, Low, Informational), reason, rule ID and CWE, file and line, evidence, a beginner-friendly explanation (what, why it matters, a safe attack illustration, exploitation conditions, how to fix), your code next to a safer version, and a copy button.
- "Confirmed pattern" (dangerous construct plus dynamic or untrusted data on the same line) is kept separate from "Potential, review" (needs a human to check).
- Dashboard with a severity bar, filters by severity and detection type, JSON report download, and saved scan history with delete (one or all).

## Honest limits

- Rules are line-based text patterns. They do not follow data across lines or files, so they will miss some issues (false negatives) and may flag safe code (false positives). The report says this on every scan.
- Explanations are fixed text per rule family. They are labelled "Rule-based text, not AI". No code is sent to any external service.
- A scan with no findings does not mean code is secure.

## Security design

- Submitted code is only handled as text. It is never executed, imported or evaluated (`test/scanner.test.js` checks this).
- Binary content, unsupported extensions and oversized bodies are rejected with clear errors (400/413/415/422).
- Per-IP rate limit (30 scans/minute), 5-second scan budget, very long lines truncated at 2,000 characters.
- Secret values are masked in evidence and snippets.
- Code is never written to logs or to disk. History stores findings only, under an anonymous ID kept in the browser's localStorage.
- Strict Content-Security-Policy (no inline scripts or styles), `nosniff`, no framing, no referrer. All page content is built with `textContent`, so scanned code cannot inject markup.
- Run behind HTTPS in production (a reverse proxy or your host's TLS).

## API

| Method | Path | Notes |
|---|---|---|
| POST | `/api/scan` | JSON `{ code, filename?, language?: "auto"\|"javascript"\|"python", save?: boolean }`. Returns the full report. |
| GET | `/api/history` | Needs `X-Client-Id` header. Lists saved scan summaries. |
| GET | `/api/history/:scanId` | Full saved report. |
| DELETE | `/api/history/:scanId` | Delete one saved scan. |
| DELETE | `/api/history` | Delete all saved scans for this client. |
| GET | `/api/health` | Status and rule count. |

## Project layout

```
server.js        HTTP server, API, history store, security headers
scanner.js       Rules, explanations, language detection, report builder
public/          index.html, styles.css, app.js, samples.js
test/            node:test suite (npm test)
data/            history.json is created here at runtime
```

## Differences from the PRD

- **No framework or build step.** The PRD proposes React, TypeScript and Semgrep. This version uses plain Node.js and vanilla JavaScript with zero dependencies so it runs anywhere with `npm start`. The scanner is behind a single `scan()` function, so a Semgrep-backed engine or a React front end can replace the parts later.
- **No accounts.** "Signed-in users" is approximated with an anonymous per-browser ID. Real authentication is future work.
- **No LLM layer.** Explanations are rule-based, which keeps results repeatable and private. An optional AI layer would need user consent for external processing, as the PRD requires.
- **Deployment.** History uses a local file, so host it on something with a persistent disk (a VPS, Render, Railway or Fly with a volume). Serverless platforms such as Vercel have no writable persistent disk; use a database there.

## Adding a rule

Add an entry to `RULES` in `scanner.js` with an `id`, `langs`, `family` (explanation text lives in `FAMILIES`), `sev`, `conf` and a `test(line, source)` function. Add a vulnerable and a safe case to `public/samples.js` and `test/scanner.test.js`.
