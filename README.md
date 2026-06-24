# LNO Privilege Compliance Scanner

> **Automated Windows privilege & access auditing with risk scoring, native ISO 27001 Annex A mapping, and executive-ready findings.**
> Built for ISO 27001 lead auditors, security engineers, and IT administrators who need to answer **"who can access what"** — in audit language, not raw telemetry.

![Risk Score](https://img.shields.io/badge/Risk%20Score-61/100-yellow)
![ISO 27001](https://img.shields.io/badge/ISO%2027001-Annex%20A%20Native-blue)
![Node](https://img.shields.io/badge/Node.js-v20%2B-green)
![Zero Infrastructure](https://img.shields.io/badge/Zero%20Infrastructure-Single%20Binary-brightgreen)

<p align="center">
  <img src="logo.svg" alt="LNO Logo" width="500">
</p>

---

## Why This Exists

Most Windows security tools fall into two camps: **enterprise-grade platforms** that require massive infrastructure (Wazuh, Microsoft Defender for Identity) or **technical dumps** that overwhelm non-technical stakeholders (raw Event IDs, sysmon logs, CIS benchmark scripts).

LNO Privilege Compliance Scanner sits in the unoccupied middle ground — a **lightweight, compliance-native tool** that translates Windows internals directly into ISO 27001 audit evidence.

It's designed for one specific job: giving a CTO, IT auditor, or compliance officer a **single-page answer** to the question *"how secure is this Windows endpoint, really?"* — backed by technical depth when they drill down.

---

## Why LNO Privilege Compliance Scanner? (Not Just Another Wazuh/PingCastle)

If you're evaluating this against Wazuh SCA or PingCastle, you're right to ask the question. Here is why this tool exists as a distinct alternative:

### 1. Zero Complex Infrastructure

| Platform | Infrastructure Required | Time to Value |
|----------|----------------------|---------------|
| **Wazuh** | ELK stack / OpenSearch + agents + dashboards | Days to weeks |
| **PingCastle** | .NET runtime + SQL Server Express (optional) | Hours to days |
| **LNO Privilege Compliance Scanner** | Node.js + `npm install` | **Under 60 seconds** |

LNO Privilege Compliance Scanner runs entirely on the endpoint being assessed. There is no server to provision, no SIEM to configure, no agents to deploy. It is purpose-built for:

- **Fast assessment** of a critical endpoint before a go-live
- **Air-gapped environments** where downloading container images is impossible
- **Pre-audit health checks** where you need answers in minutes, not weeks

### 2. Native ISO 27001 Annex A Mapping — Not CIS, Not DISA

Most Windows hardening tools benchmark against **CIS Benchmarks** or **DISA STIGs** — US-centric standards developed for government and military. These are excellent for technical hardening but do not speak the language of compliance audits.

LNO Privilege Compliance Scanner translates every technical finding directly to **ISO 27001:2022 Annex A controls**:

| What a CIS tool says | What LNO Privilege Compliance Scanner says |
|----------------------|------------------------|
| `Ensure 'MinimumPasswordLength' is set to '8'` | **A.5.17** — Weak password policy: HIGH risk |
| `Ensure 'SeDebugPrivilege' is not enabled` | **A.8.2** — Dangerous privilege enabled: HIGH risk |
| `Verify service path does not contain unquoted spaces` | **A.8.2** — Unquoted service path: MEDIUM risk |
| *(no equivalent)* | **A.8.7** — Defender real-time protection disabled: HIGH risk |

This means your compliance team does not need to translate CIS findings into ISO control language. LNO Privilege Compliance Scanner delivers the mapping natively.

### 3. Non-Invasive Executive Dashboard

Enterprise security tools export **raw data**: CSV dumps, JSON blobs, or static HTML that requires weeks of PowerBI training to interpret. Executive stakeholders (CEO, CFO, board members) need **one number they can track over time**.

LNO Privilege Compliance Scanner provides the **Executive Posture Score** — a single 0–100 score that tells leadership how the endpoint is trending. Every finding is color-coded, prioritized, and includes plain-language remediation steps. Technical depth is one click away; the big picture is immediate.

> *"I don't need another log aggregator. I need to know, in 30 seconds, whether my Windows fleet is audit-ready."*

### 4. Enterprise Security Hardening (Phase 1)

| Feature | What It Does | Why It Matters for Audit |
|---------|-------------|------------------------|
| **Dashboard Auth** | Basic auth via `DASHBOARD_USER`/`DASHBOARD_PASS` env vars | Prevents unauthorized viewing of compliance data |
| **API Key Access** | `X-API-Key` header required on all API endpoints | Enables secure programmatic/automation access |
| **Rate Limiting** | Per-IP rate limiting (configurable via `RATE_LIMIT`) | Prevents brute-force and DoS against the API |
| **CSP Headers** | `Content-Security-Policy` on all responses | OWASP Top 10 compliance for web UI |
| **Audit Log** | Every API call logged to `audit.log` with timestamp, IP, action, status | Non-repudiation — who accessed what and when |

---

## Key Features

### 1. Risk Scoring Engine
Prioritizes findings by severity using a configurable weight system. Unique finding types are de-duplicated so scores reflect real risk breadth, not noise.

```
Risk Score = 100 - Σ(severity_weights)
Default weights: Critical=25, High=10, Medium=4, Low=1
Configurable via risk-config.json
```

### 2. Security Findings with ISO 27001 Mapping
Every finding maps to an ISO 27001 Annex A control with remediation guidance:

| Finding | Severity | ISO Control |
|---------|----------|-------------|
| Weak password policy (< 8 chars) | HIGH | A.5.17 |
| SYSTEM service from non-system path | HIGH | A.8.2 |
| World-writable directory on sensitive path | HIGH | A.5.15 |
| LSASS not running as PPL | MEDIUM | A.8.2 |
| Unquoted service paths | LOW* | A.8.2 |

*\*Configurable — see risk-config.json*

### 3. Process Risk Assessment
Evaluates each running process using a composite score (0–100) based on:

- **Owner context** — SYSTEM from user-writable path (+50)
- **Code signing** — Unsigned from user path (+25)
- **Path anomalies** — No executable path (+20)
- **Privilege level** — Running as admin (+10)
- **Memory/thread indicators** — Unsigned + high memory (+10)

### 4. Historical Scan Diff
Compare findings between scan runs to track:

- **New findings** — regressions in security posture
- **Fixed findings** — remediation effectiveness
- **Risk score trend** — improving or deteriorating

### 5. CSV Export for Audit Evidence
One-click export of findings, compliance status, and process data in Excel-compatible CSV format. Ready for auditor review.

### 6. Interactive Dashboard
Dark-mode dashboard with tabbed panels:

- **Findings** — prioritized with severity filters & expandable detail/remediation
- **User & Access** — group memberships, privilege audit, security posture indicators (UAC, LSA, Password, Lockout)
- **Compliance** — 93 ISO 27001:2022 Annex A controls with compliant/non-compliant/not_assessed status
- **Process Risk** — color-coded risk table with search, sortable columns, parent app classification
- **Services** — running services with SYSTEM context, parent app & description lookup
- **Access Control** — users, groups, file ACLs, group membership details
- **Risk Config** — current risk scoring weights, type overrides & suppression rules

---

## ISO 27001:2022 Compliance Assessment — Defensible Position

### Overview

LNO Privilege Compliance Scanner assesses all **93 Annex A controls** (ISO/IEC 27001:2022) across four themes. The scanner applies a **three-tier honesty model** — every control shows its true status with evidence. There are no false claims of coverage.

| Status | Meaning | Count |
|--------|---------|-------|
| **Compliant** | Scanner verified the control: either no violations found, or the control is implemented correctly | Variable (depends on endpoint) |
| **Non-compliant** | Scanner detected specific technical violations with evidence | Variable (depends on endpoint) |
| **Not assessed** | Control is outside the technical scope of endpoint scanning | **63 controls** (always) |

### Why 63 Controls Are Marked "Not Assessed" — And Why This Is Correct

**This is NOT a limitation. This is intellectual honesty.**

No single tool can verify all 93 Annex A controls because ISO 27001 covers **organizational policies, human resources, physical sites, and supplier relationships** — none of which are detectable by endpoint scanning:

| Theme | Total | Verifiable | Not Assessed | Why Not Assessed |
|-------|-------|------------|-------------|------------------|
| **A.5 — Organizational** (37) | 37 | 12 | 25 | Policies, management commitment, supplier agreements, incident response plans, business continuity — **documents and processes**, not technical configurations |
| **A.6 — People** (8) | 8 | 0 | 8 | Background checks, training records, disciplinary processes, remote work policies — **HR functions**, not technical |
| **A.7 — Physical** (14) | 14 | 0 | 14 | Security perimeters, visitor logs, cable routing, equipment maintenance — **physical infrastructure**, not software |
| **A.8 — Technological** (34) | 34 | 18 | 16 | 16 controls are covered but left as not_assessed because they overlap with other frameworks (cryptography A.8.24 is verifiable; key management A.8.17 requires policy review) |
| **Total** | **93** | **30** | **63** | **63 controls are honestly reported as outside scanner scope** |

> **🔴 If a tool claims to "verify all 93 controls" via endpoint scanning alone, it is either lying or misclassifying evidence.** A PowerShell script cannot review your supplier security policy (A.5.19), verify employee background checks (A.6.1), or inspect your server room door locks (A.7.1). LNO Privilege Compliance Scanner tells the truth about what it can and cannot do.

### The 30 Verifiable Controls (Real Technical Evidence)

These **30 controls** are assessed with ACTUAL technical evidence — PowerShell output, WMI queries, registry reads, and `secedit` exports:

| Control | Domain | What the Scanner Actually Checks |
|---------|--------|----------------------------------|
| **A.5.2** | Info security roles | System metadata — identifies user context and privilege level |
| **A.5.9** | Information classification | System info baseline for classification decisions |
| **A.5.12** | Threat intelligence | Running process inventory — detects known vulnerable software |
| **A.5.15** | Access control | User accounts, group memberships, ACL on sensitive paths |
| **A.5.16** | Identity management | Local user enumeration, account status (enabled/disabled/expired) |
| **A.5.17** | Authentication info | Password policy (length, complexity, lockout threshold, expiry) |
| **A.5.18** | Access rights | Privilege audit, dangerous privilege detection (SeDebugPrivilege, etc.) |
| **A.5.31** | Legal & regulatory | Password policy compliance with regulatory requirements |
| **A.5.33** | Protection of records | File ACL on system paths — detects world-writable sensitive data |
| **A.5.34** | Privacy & PII | User data enumeration, ACL on user profile paths |
| **A.5.36** | Compliance with policies | Security policy enforcement via registry/secedit audit |
| **A.5.37** | Documented procedures | Process inventory as evidence of operating procedures |
| **A.8.1** | User endpoint devices | Running processes, installed services, network connections |
| **A.8.2** | Privileged access rights | Admin group membership, dangerous privileges, UAC, LSA protection |
| **A.8.3** | Information access restriction | ACL on sensitive paths, weak registry ACLs |
| **A.8.5** | Secure authentication | Password/complexity/lockout policy, UAC consent prompt |
| **A.8.6** | Capacity management | System memory, process count, handle/thread analysis |
| **A.8.7** | Malware protection | Defender real-time status, unsigned processes, suspicious service paths |
| **A.8.8** | Technical vulnerability | Unquoted service paths, unsigned processes from writable paths |
| **A.8.9** | Configuration management | Service configurations, registry ACLs, startup paths |
| **A.8.15** | Logging | LSA protection (PPL), event log configuration indicators |
| **A.8.16** | Monitoring | Running process/services inventory with risk scoring |
| **A.8.17** | Clock synchronization | System time source (via system info) |
| **A.8.18** | Privileged utility programs | PowerShell, whoami, secedit — controlled execution context |
| **A.8.19** | Malware protection (ops) | Suspicious service detection, unsigned process from temp paths |
| **A.8.20** | Network security | Firewall profile status (Domain/Private/Public), outbound connections |
| **A.8.21** | Network segregation | Network connection inventory — identifies unexpected connections |
| **A.8.22** | Network filtering | Port/connection analysis via netstat output |
| **A.8.24** | Cryptography | Protocol/port analysis for encrypted vs plaintext services |
| **A.8.32** | Change management | Process/service baseline — detects new or modified executables |

Each control assessment includes:
- **Evidence column**: "Scanner verified — no violations detected" (compliant) OR actual finding titles (non_compliant) OR "Requires manual review" (not_assessed)
- **Details column**: For non-compliant controls, shows specific technical details from the scan
- **Severity**: Critical/High/Medium based on the worst finding affecting that control

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│                 │     │                  │     │                 │
│   PowerShell    │────▶│   scanner.js     │────▶│   scan.db       │
│   (WMI/Win32)   │     │   (Node.js)      │     │   (SQLite)      │
│                 │     │                  │     │   ──→ loaded    │
└─────────────────┘     └──────────────────┘     │   into RAM      │
                                                 │   ──→ deleted   │
                                                 │   from disk     │
                                                 └────────┬────────┘
                                                          │
                                                          ▼
                                                 ┌─────────────────┐
                                                 │                 │
                                                 │   server.js     │
                                                 │   (REST API)    │
                                                 │   (in-memory)   │
                                                 │                 │
                                                 └─────────────────┘
                                                          │
                                                          ▼
                                                 ┌─────────────────┐
                                                 │                 │
                                                 │   index.html    │
                                                 │   (Dashboard)   │
                                                 │                 │
                                                 └─────────────────┘
```

### Data Flow
1. **Scanner** queries WMI via PowerShell (temp .ps1 files, auto-deleted)
2. Raw data is analyzed for risk, compliance, and findings
3. Results stored in SQLite database via sql.js (pure JS, no native compilation)
4. **Server** loads scan.db into RAM on start (file kept on disk for restart recovery unless `DELETE_DB_ON_LOAD=true`)
5. All API queries serve from in-memory database — fast, no disk I/O
6. **Dashboard** consumes API and renders interactive UI

### Design Decisions
- **No C++/Go required** — sql.js provides pure WebAssembly SQLite, no native compiler needed
- **No admin rights required** — WMI provides rich data for standard users
- **Self-contained** — single Node.js process, no database server, no external dependencies beyond npm

---

## Installation

```bash
# Clone the repository
git clone https://github.com/dnislno/lno-privilege-compliance-scanner.git
cd LNO-Privilege-Compliance-Scanner-ISO27001

# Install dependencies (sql.js only)
npm install

# Run a scan
node scanner.js

# Start the dashboard
node server.js
# → Open http://localhost:9090
```

**Prerequisites:**
- Node.js v18+ (tested with v20+)
- Windows 10/11 (Windows 7 untested)
- PowerShell 5.1+ (built into Windows)
- No admin rights required for scanning

---

## Usage

### Quick Start
```bash
node scanner.js      # Run security assessment
node server.js       # Start web dashboard at http://localhost:9090
```

### Command Reference
| Command | Description |
|---------|-------------|
| `node scanner.js` | Run full security scan, write results to scan.db |
| `node scanner.js --schedule` | Run scan in scheduled mode (for Windows Task Scheduler) |
| `node server.js` | Start HTTP server on port 9090 |
| `node -e "require('./scanner.js').scan()"` | Programmatic scan invocation |
| `node test.js` | Run integration test suite (server must be running) |

### Environment Configuration
Copy `.env.example` to `.env` and configure:

| Variable | Description | Default |
|----------|-------------|---------|
| `SCAN_TOKEN` | Bearer token for `POST /api/scan/trigger` | `scan_trigger` |
| `DASHBOARD_USER` | Basic auth username for dashboard (set with `DASHBOARD_PASS`) | *(disabled)* |
| `DASHBOARD_PASS` | Basic auth password for dashboard | *(disabled)* |
| `API_KEY` | Required `X-API-Key` header for all API endpoints | *(disabled)* |
| `RATE_LIMIT` | Max requests per minute per IP | `100` |
| `DELETE_DB_ON_LOAD` | Delete `scan.db` from disk after loading into RAM (data lost on restart) | *(disabled)* |

### API Endpoints
| Endpoint | Description |
|----------|-------------|
| `GET /api/overview` | Latest scan summary with severity counts |
| `GET /api/findings?severity=` | Findings (optional severity filter) |
| `GET /api/compliance` | 93 ISO 27001 Annex A control compliance status |
| `GET /api/user` | Current user, group memberships, privileges |
| `GET /api/local-users` | All local user accounts |
| `GET /api/local-groups` | Local groups with members |
| `GET /api/acl?path=` | File system ACL entries (optional path filter) |
| `GET /api/security-policy` | Password/lockout/UAC policy configuration |
| `GET /api/processes` | All processes with risk scores & parent app |
| `GET /api/processes/suspicious` | Processes with risk_score >= 20 |
| `GET /api/processes/detail?pid=` | Process detail + network connections |
| `GET /api/services` | Running services with parent app & description |
| `GET /api/connections` | Network connections |
| `GET /api/system-info` | Host system information |
| `GET /api/scan/latest` | Latest scan metadata |
| `GET /api/risk-config` | Current risk scoring configuration |
| `GET /api/export/findings` | CSV download of findings (Excel-compatible) |
| `GET /api/export/compliance` | CSV download of compliance status |
| `GET /api/export/processes` | CSV download of process risk data |
| `POST /api/scan/trigger` | Trigger a new scan |

---

## Risk Scoring Configuration

Edit `risk-config.json` to customize scoring:

```json
{
  "severity_weights": {
    "critical": 25,
    "high": 10,
    "medium": 4,
    "low": 1
  },
  "type_overrides": {
    "unquoted_service": {
      "severity": "low",
      "weight": 1,
      "note": "Many Windows built-in services have unquoted paths"
    }
  },
  "suppressed_types": [],
  "min_score": 10,
  "max_score": 100
}
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Scanner | Node.js + PowerShell (WMI) |
| Database | SQLite via sql.js (WebAssembly) |
| Server | Node.js HTTP (no Express) |
| Dashboard | Vanilla JS + Tailwind CSS (CDN) |
| Auth | HTTP Basic Auth (env var) + API Key (`X-API-Key` header) |
| Rate Limiter | In-memory sliding window per IP |
| Audit Log | File-based append (`audit.log`) |

---

## Limitations & Roadmap

### Known Limitations
- **No open handle enumeration** — requires admin rights + NtQuerySystemInformation (C++)
- **WMI ExecutablePath empty for SYSTEM processes** — Windows restriction for non-admin users
- **Process owner detection** — WMI GetOwner() can fail for some processes without admin rights
- **Tailwind CSS** — bundled locally (`tailwind.min.js`) with CDN fallback. Works fully air-gapped. First load in browser may still request CDN if local file is missing.
- **63 controls not_assessed** — organizational (A.5), people (A.6), and physical (A.7) controls require manual review. This is by design — the tool is honest about scope limitations.
- **Compliance = negative evidence** — "compliant" status means no finding was detected, not that the control is fully implemented. Always supplement with manual verification for critical controls.
- **In-memory database** — `scan.db` is loaded into RAM on server start for fast API responses. The file is kept on disk by default, so restarting the server preserves scan data. Set `DELETE_DB_ON_LOAD=true` in `.env` to delete the file after loading (zero data at rest, but data is lost on server restart).
- **Single-user server** — server processes one request at a time. Burst requests during scan will timeout.
- **Windows only** — leverages WMI and PowerShell (Win32 API). Linux/macOS not supported.

---

> **This is a stable, final-form release.** No active development roadmap. Open to new feature proposals — submit via [GitHub Issues](https://github.com/dnislno/LNO-Privilege-Compliance-Scanner-ISO27001/issues) as enhancement requests.

---

## Defensible Position: How to Answer Auditor Challenges

### "Why are only 30 out of 93 controls verified?"

**Answer:** "The scanner ONLY verifies controls that are TECHNICALLY VERIFIABLE via endpoint assessment. The remaining 63 controls require evidence that no software tool can provide — policy documents (A.5.x), HR records (A.6.x), or physical site inspection (A.7.x). We present them honestly as 'not_assessed' rather than falsely claiming coverage.

This is identical to how your Statement of Applicability (SoA) works: you document which controls apply to each scope. For the technical scope of 'Windows endpoint security,' 30 controls are applicable and verifiable. The scanner assesses those 30 with actual, repeatable, scripted evidence."

### "Compliant means 'no finding' — isn't that just absence of evidence?"

**Answer:** "That is the standard definition of negative evidence in auditing, and it is ISO-accepted practice. Every vulnerability scanner works the same way: 'no vulnerability found' does not mean 'no vulnerability exists,' it means 'within the scope of this scan, no violation was detected.'

Our tool makes this explicit — the evidence column for compliant controls states 'Scanner verified — no violations detected on this endpoint.' We do not claim 'this control is fully implemented.' We claim 'this endpoint shows no technical violations of this control.'

For critical controls, we always recommend supplementing with manual verification. The scanner is a pre-audit tool, not a certification body."

### "Can this replace a manual audit?"

**Answer:** "No, and it never claims to. This tool is a pre-audit acceleration tool. It automates the ~70% of audit evidence that is technical and repeatable, freeing the auditor to focus on the ~30% that requires judgment, policy review, and physical inspection.

Using this tool, a lead auditor can:
1. Review 30 technical controls in 30 seconds (dashboard overview)
2. Export CSV evidence for audit workpapers in one click
3. Track risk score trends across scan dates
4. Identify which findings are regressions vs improvements
5. Spend audit time on organizational and physical controls instead of technical enumeration"

### "How is this different from running a CIS script?"

**Answer:** "A CIS benchmark script outputs 'pass/fail' against technical hardening rules. It does not tell you which ISO 27001 control each finding violates, what the business impact is, or how to remediate it for compliance.

LNO Privilege Compliance Scanner translates every technical finding directly to Annex A controls with:
- **Remediation guidance** written for auditors, not technicians
- **Risk scoring** that prioritizes by business impact
- **Compliance mapping** that connects technical findings to audit evidence
- **Exportable evidence** formatted for audit workpapers
- **Governance documentation** (ADR, AGRAF, DPRP, UAT) that satisfies ISO documentation requirements"

### Summary: Is This Real Evidence?

**Yes.** Real audit evidence is:
1. **Repeatable** — run `node scanner.js` twice, get consistent results ✓
2. **Verifiable** — 138 integration tests prove the tool does what it claims ✓
3. **Transparent** — all 16 finding rules documented with data provenance ✓
4. **Honest** — 63 controls explicitly marked not_assessed ✓
5. **Exportable** — CSV exports ready for audit workpapers ✓
6. **Governed** — 4 governance documents (ADR, AGRAF, DPRP, UAT) in `dokumen/` ✓
7. **Traceable** — every finding shows exact PowerShell command + field value that triggered it ✓

A tool that satisfies all 7 criteria is, by any reasonable definition, **real evidence for an ISO 27001 audit**.

---

## ISO 27001 Audit Readiness

LNO Privilege Compliance Scanner provides:

1. **93-control mapping with honest status** — every Annex A control assessed as compliant/non_compliant/not_assessed, with evidence
2. **Transparent rule engine** — all 16 finding rules documented in `scanner.js` (`FINDING_DEFS`) with ISO control mappings and data provenance
3. **Configurable risk scoring** — `risk-config.json` allows tailoring to organizational risk appetite
4. **Exportable evidence** — CSV exports of findings, compliance status, and processes for auditor review
5. **Governance documentation** — ADRs, risk assessment framework (AGRAF), data processing policy (DPRP), and UAT matrix included in the `dokumen/` folder
6. **Zero trust architecture** — fully offline, no third-party data transmission, ensuring evidence integrity
7. **Security hardening** — Dashboard auth, API key access, rate limiting, CSP headers, audit logging (all Phase 1 complete)

> *"The best auditors don't just check boxes. They build tools that check boxes automatically."*

---

## Disclaimer

**IMPORTANT — READ BEFORE USE. THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.**

By using this software, you acknowledge and agree that:

1. **No Warranty**: This software is provided "AS IS" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. The entire risk as to the quality and performance of the software is with you.

2. **No Liability**: In no event shall the author (dnislno) or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software. This includes, without limitation, damages for loss of data, loss of profits, system downtime, or security incidents caused by or during the use of this tool.

3. **User Assumes All Risk**: You assume all responsibility and risk for the use of this software. You are solely responsible for ensuring that your use complies with applicable laws, regulations, and organizational policies.

4. **Authorized Use Only**: Only use this tool on systems you own or have explicit written permission to audit. Unauthorized scanning may violate applicable laws including but not limited to the Computer Fraud and Abuse Act (CFAA) and similar regulations in your jurisdiction.

5. **Access Control**: The dashboard binds to **localhost only** (`127.0.0.1:9090`) and is not accessible from the network by default. **Do not expose port 9090 to untrusted networks or the public internet.** You are responsible for implementing appropriate network access controls in production deployments.

6. **Not a Replacement**: This tool supplements, not replaces, professional security audit services. Always engage certified professionals for formal compliance certifications.

7. **ISO 27001**: Compliance mapping is provided as guidance only. Final certification decisions rest with accredited certification bodies.

8. **No Sensitive Data in Repository**: This repository contains no internal IP addresses, API keys, client secrets, or proprietary information. The `scan.db` file is loaded into memory by the server (kept on disk by default for restart recovery; set `DELETE_DB_ON_LOAD=true` to delete after load). Always review any output before sharing or publishing.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**dnislno** — [github.com/dnislno](https://github.com/dnislno)

A lead ISO 27001 auditor who codes. Compliance expertise and software engineering are not mutually exclusive.

> *"The best auditors don't just check boxes. They build tools that check boxes automatically."*

---

### Response to Common Auditor Challenges

> **Auditor:** "This tool only covers 30 out of 93 controls. That's not enough."

**Response:** "No single tool covers 93 controls. A SIEM doesn't verify physical security. An HR system doesn't check firewall rules. We honestly mark 63 controls as not_assessed rather than faking coverage. For the 30 controls we DO verify, we provide scripted, repeatable, exportable evidence — which is more than most manual audits provide for those same controls."

> **Auditor:** "Compliant = no finding? That's absence of evidence."

**Response:** "That's negative evidence, and it's the standard in vulnerability assessment. Nessus, Qualys, and Wazuh all work the same way. We make it explicit in the evidence column that no violations were detected. For critical findings, we always recommend manual verification. The tool accelerates audits — it doesn't replace them."

> **Auditor:** "Anyone can run a PowerShell script."

**Response:** "Exactly. Anyone CAN run the scanner — that's the point. Repeatability is a cornerstone of audit evidence. If an auditor is skeptical, they can run the scanner themselves on the same endpoint and verify the results. Try doing that with a manual audit checklist."

> **Auditor:** "This seems like a toy project, not enterprise grade."

**Response:** "The tool has 138 automated tests, CI/CD pipeline, 8 tagged releases, 4 governance documents (ADR, AGRAF, DPRP, UAT), and security hardening (auth, rate limiting, CSP, audit log). It's documented, tested, and governed — which is more than many enterprise tools can claim for their internal tooling."
