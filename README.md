# 🍳 CodeCook — Secure Your Code Before It Ships

### Find the vulnerability. Understand the risk. Fix it before deployment.

**CodeCook** is a lightweight, privacy-first static security analyzer for JavaScript, TypeScript, and Python. It helps developers identify potentially dangerous coding patterns, understand their security impact, and discover safer alternatives — before vulnerable code reaches production.

Paste your code, upload a source file, run a scan, and get actionable security findings with evidence, severity ratings, CWE references, and safer code examples.

> **Your code. Your machine. Your privacy.**
> CodeCook analyzes submitted source code as text. It never executes, imports, or evaluates the code being scanned.

---

## ✨ Why CodeCook?

Security tools can be difficult to understand, especially for beginners. CodeCook makes code security more approachable by connecting every finding with three important things:

- **What is wrong?** Identify the potentially insecure coding pattern.
- **Why does it matter?** Understand the risk and possible impact.
- **How do you fix it?** See a safer alternative and remediation guidance.

Whether you're a student learning secure coding or a developer reviewing code before deployment, CodeCook helps make security part of your development workflow.

## 🚀 Features

| Feature | Description |
|---|---|
| Multi-language scanning | JavaScript, TypeScript, and Python |
| Paste or upload | Scan pasted code or supported source files |
| 23 detection rules | Deterministic, rule-based security checks |
| Severity classification | Critical, High, Medium, Low, Informational |
| CWE references | Connect findings to common weakness categories |
| Evidence-based findings | Show affected file, line, and relevant code evidence |
| Beginner-friendly explanations | Understand the issue and its security implications |
| Safer code suggestions | Compare vulnerable patterns with safer alternatives |
| Confidence separation | Separate confirmed patterns from potential findings |
| Interactive dashboard | View, filter, and prioritize findings |
| Scan history | Review and delete previously saved scan summaries |
| JSON export | Download structured scan reports |
| Privacy-first design | No external AI service or code upload required |

## 🛡️ Vulnerability Detection

CodeCook includes 23 deterministic security detection rules covering common insecure coding patterns.

Detection categories include:

- SQL Injection
- Cross-Site Scripting (XSS)
- Hardcoded Secrets and Credentials
- Known Token Formats
- Command Injection
- Dynamic Code Evaluation
- Path Traversal
- Weak Cryptography
- Predictable Randomness
- Insecure Deserialization
- Disabled TLS Certificate Verification
- Debug Mode Exposure
- Unvalidated Input

### Severity Levels

| Severity | Meaning |
|---|---|
| 🔴 Critical | A potentially severe security weakness requiring immediate review |
| 🟠 High | A high-impact security concern |
| 🟡 Medium | A security weakness that should be addressed |
| 🔵 Low | A lower-impact security concern |
| ⚪ Informational | A security observation that may need attention |

Severity is assigned by the detection rules. It should not be interpreted as a verified exploitability assessment.

### Confirmed Pattern vs. Potential Finding

CodeCook distinguishes between two kinds of findings:

**Confirmed Pattern**

A dangerous construct and dynamic or untrusted data appear together on the same line. This increases confidence that the pattern deserves attention, but does not prove that the application is exploitable.

**Potential — Review Required**

A suspicious coding pattern is detected, but additional context is needed to determine whether it represents a real vulnerability.

This distinction helps developers prioritize manual verification and reduce confusion.

## 🖥️ How It Works

```text
Paste Code / Upload File
          |
          v
   Language Detection
          |
          v
  Input Validation
          |
          v
  23 Security Rules
          |
          v
  Finding Classification
          |
          v
  Evidence & Explanation
          |
          v
  Safer Code Suggestions
          |
          v
  Security Dashboard
          |
          v
    JSON Report
```

### Typical Workflow

1. Open CodeCook.
2. Paste JavaScript, TypeScript, or Python code.
3. Alternatively, upload a supported source file.
4. Select automatic language detection or choose a language manually.
5. Start the security scan.
6. Review findings by severity and detection category.
7. Understand the vulnerability and inspect its evidence.
8. Compare the original code with the safer suggestion.
9. Copy the recommended code for further review.
10. Export the report or revisit the scan from history.

## ⚡ Quick Start

### Requirements

- Node.js 18 or newer
- A modern web browser
- No external npm dependencies required

### 1. Download the Project

Download or clone the CodeCook repository.

```bash
git clone <YOUR_REPOSITORY_URL>
```

Replace `<YOUR_REPOSITORY_URL>` with your actual repository URL.

### 2. Enter the Project Directory

```bash
cd codecook
```

### 3. Start the Application

```bash
npm start
```

No `npm install` is required for the current zero-dependency implementation.

### 4. Open CodeCook

Visit:

```text
http://127.0.0.1:3000
```

### 5. Run Tests

```bash
npm test
```

The test suite uses Node.js's built-in test runner.

## ⚙️ Configuration

CodeCook supports the following environment variables:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP server port |
| `HOST` | `127.0.0.1` | Network interface to bind |
| `DATA_DIR` | `./data` | Directory for saved scan history |
| `NODE_ENV` | Unset | Set to `production` to enable HSTS |

### Run on a Custom Port

```bash
PORT=8080 npm start
```

### Run in a Server or Container

```bash
HOST=0.0.0.0 PORT=8080 npm start
```

**Deployment note:** Binding to `0.0.0.0` exposes the server on available network interfaces. Use an appropriately configured firewall and reverse proxy.

## 📂 Supported File Types

CodeCook accepts the following source file extensions:

| Language | Extensions |
|---|---|
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` |
| TypeScript | `.ts`, `.tsx` |
| Python | `.py` |

**Maximum upload size:** 512 KB

Unsupported extensions, binary content, and oversized requests are rejected with appropriate HTTP error responses.

## 📊 Security Dashboard

The dashboard provides an overview of scan results, including:

- Total vulnerabilities detected
- Severity distribution
- Security finding filters
- Detection type filters
- Recent scan history
- Detailed vulnerability reports

Each finding includes:

- Rule ID
- Vulnerability name
- Severity
- CWE reference
- File name
- Line number
- Evidence
- Explanation of the issue
- Potential security impact
- Safe attack illustration
- Exploitation conditions
- Recommended remediation
- Original code and safer alternative

## 🔌 API Reference

CodeCook provides a lightweight HTTP API.

### Base URL

```text
http://127.0.0.1:3000
```

### 1. Scan Source Code

`POST /api/scan`

Submit source code for security analysis.

**Request body:**

```json
{
  "code": "const query = 'SELECT * FROM users WHERE id=' + req.query.id;",
  "filename": "app.js",
  "language": "auto",
  "save": true
}
```

Supported language values:

- `auto`
- `javascript`
- `python`

**Example using cURL:**

```bash
curl -X POST http://127.0.0.1:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "code": "eval(userInput);",
    "filename": "app.js",
    "language": "auto",
    "save": true
  }'
```

### 2. Get Scan History

`GET /api/history`

Requires the `X-Client-Id` header.

```bash
curl http://127.0.0.1:3000/api/history \
  -H "X-Client-Id: YOUR_CLIENT_ID"
```

### 3. Get a Specific Scan

`GET /api/history/:scanId`

Returns the saved report for the specified scan.

```bash
curl http://127.0.0.1:3000/api/history/SCAN_ID \
  -H "X-Client-Id: YOUR_CLIENT_ID"
```

### 4. Delete a Specific Scan

`DELETE /api/history/:scanId`

### 5. Delete All Scans

`DELETE /api/history`

Both deletion endpoints require the appropriate client identity header.

### 6. Health Check

`GET /api/health`

Returns application health information and the configured rule count.

```bash
curl http://127.0.0.1:3000/api/health
```

### HTTP Error Responses

The API uses appropriate HTTP status codes, including:

| Status | Meaning |
|---|---|
| `400` | Invalid request |
| `413` | Request body too large |
| `415` | Unsupported media or content type |
| `422` | Invalid or unsupported input |
| `429` | Rate limit exceeded |
| `500` | Internal server error |

## 🔐 Security & Privacy Architecture

Security is not just what CodeCook detects — it is also how CodeCook handles submitted code.

### Source Code Safety

- Submitted code is handled strictly as text.
- Uploaded code is never executed, imported, or evaluated.
- No dynamic execution of submitted source code.
- Secret values are masked in evidence and code snippets.
- Scanned code is never written to application logs or saved to disk.

### Input Protection

- Maximum source upload size: 512 KB.
- Binary content detection.
- Unsupported file extension rejection.
- Request validation.
- Per-IP rate limiting: 30 scans per minute.
- Five-second scan execution budget.
- Long lines are truncated to 2,000 characters.

### Browser Security

The application uses security headers, including:

- Content Security Policy (CSP)
- `X-Content-Type-Options: nosniff`
- Anti-framing protection
- Referrer restrictions
- HTTP Strict Transport Security (HSTS) in production mode

Page content is rendered using `textContent` to prevent scanned source code from being interpreted as HTML.

### Scan History & Data Handling

- An anonymous browser ID is stored in `localStorage`.
- Saved history contains findings, not the original submitted source code.
- Scan history is stored in the configured data directory.
- Users can delete individual scan records or all records associated with their client ID.

For production deployment, protect the history API against unauthorized access and ensure the reverse proxy correctly handles client identity and rate limiting.

## 🧪 Testing

Run the complete test suite:

```bash
npm test
```

The tests cover important scanner behavior, including:

- Vulnerability detection rules
- Safe and vulnerable code examples
- Language handling
- Input validation
- Error handling
- Source code execution safety

The source-code execution safety tests help verify that submitted code is treated as text rather than executable input.

## 🏗️ Project Structure

```text
CodeCook/
│
├── server.js
│   ├── HTTP server
│   ├── API endpoints
│   ├── Security headers
│   ├── Rate limiting
│   └── Scan history storage
│
├── scanner.js
│   ├── Security detection rules
│   ├── Language detection
│   ├── Vulnerability explanations
│   └── Report generation
│
├── public/
│   ├── index.html
│   ├── styles.css
│   ├── app.js
│   └── samples.js
│
├── test/
│   └── scanner.test.js
│
├── data/
│   └── history.json (created at runtime)
│
├── package.json
└── README.md
```

## ⚠️ Known Limitations

CodeCook is a rule-based static pattern analyzer, not a complete application security testing platform.

Understand these limitations before relying on its reports:

1. **Line-based detection:** Rules inspect individual lines and do not track data flow across multiple lines or files.
2. **False negatives:** Some real vulnerabilities may not match the implemented patterns.
3. **False positives:** Safe code may match a suspicious pattern.
4. **Limited context:** The scanner does not fully understand application architecture, runtime behavior, or business logic.
5. **No runtime testing:** It does not execute applications or verify whether a vulnerability can actually be exploited.
6. **Rule-based explanations:** Explanations are fixed text associated with rule families, not AI-generated analysis.
7. **No external code processing:** Submitted source code is not sent to an external AI service.

> **Important:** A scan with zero findings does not mean your application is secure. Always combine automated checks with manual security review, dependency auditing, and appropriate security testing.

## 🚀 Deployment

CodeCook can run on a VPS or another hosting environment with a persistent writable filesystem.

### Recommended Deployment Setup

```text
User Browser
     |
     v
HTTPS Reverse Proxy
     |
     v
CodeCook Node.js Server
     |
     v
Scanner Engine
     |
     v
Persistent History Storage
```

### Production Checklist

- [ ] Use HTTPS.
- [ ] Set `NODE_ENV=production`.
- [ ] Configure a persistent `DATA_DIR`.
- [ ] Keep Node.js updated.
- [ ] Restrict server network access.
- [ ] Configure reverse-proxy request limits.
- [ ] Back up history data if required.
- [ ] Review logs to ensure submitted source code is not recorded.
- [ ] Test API access controls.
- [ ] Run `npm test` before deployment.

**Hosting compatibility:** VPS, Render, Railway, or Fly.io with persistent storage. Serverless platforms without persistent writable storage require a different history backend, such as a database.

## 🗺️ Roadmap

The following are potential future improvements, not features currently claimed as implemented.

- [ ] More advanced JavaScript and TypeScript analysis.
- [ ] Python-specific security rule expansion.
- [ ] Cross-file analysis.
- [ ] Data-flow and taint analysis.
- [ ] Dependency vulnerability analysis.
- [ ] SARIF report export.
- [ ] PDF security reports.
- [ ] GitHub integration.
- [ ] CI/CD security checks.
- [ ] Optional AI-assisted remediation with explicit user consent.
- [ ] Additional programming language support.
- [ ] Authentication and team-based scan history.

## 🤝 Contributing

Contributions are welcome!

If you want to improve CodeCook:

1. Fork the repository.
2. Create a feature branch.
3. Add or improve a detection rule.
4. Include vulnerable and safe test cases.
5. Run the test suite.
6. Submit a pull request with a clear description.

### Adding a New Detection Rule

Add a rule entry to `RULES` inside `scanner.js`.

Each rule should define:

- `id`
- `langs`
- `family`
- `sev`
- `conf`
- `test(line, source)`

Also add relevant vulnerable and safe examples to:

- `public/samples.js`
- `test/scanner.test.js`

A good security rule should be specific, explainable, tested, and mindful of false positives.

## 📜 License

Add your chosen open-source license before publishing this repository. If you choose MIT, include the official MIT license text in a `LICENSE` file.

## 💡 Project Philosophy

CodeCook follows three simple principles:

**Detect responsibly. Explain clearly. Fix confidently.**

Security should not be something developers think about only after deployment. It should be part of the coding process from the beginning.

---

<p align="center">

### 🍳 CodeCook

**Find the vulnerability. Understand the risk. Fix it before deployment.**

Built to make secure coding easier for everyone.

</p>
