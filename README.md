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
| `Ensure 'MinimumPasswordLength' is set to '8'` | **A.9.4.3** — Weak password policy: HIGH risk |
| `Ensure 'SeDebugPrivilege' is not enabled` | **A.9.2.3** — Dangerous privilege enabled: HIGH risk |
| `Verify service path does not contain unquoted spaces` | **A.9.2.3** — Unquoted service path: MEDIUM risk |
| *(no equivalent)* | **A.12.2.1** — Defender real-time protection disabled: HIGH risk |

This means your compliance team does not need to translate CIS findings into ISO control language. LNO Privilege Compliance Scanner delivers the mapping natively.

### 3. Non-Invasive Executive Dashboard

Enterprise security tools export **raw data**: CSV dumps, JSON blobs, or static HTML that requires weeks of PowerBI training to interpret. Executive stakeholders (CEO, CFO, board members) need **one number they can track over time**.

LNO Privilege Compliance Scanner provides the **Executive Posture Score** — a single 0–100 score that tells leadership how the endpoint is trending. Every finding is color-coded, prioritized, and includes plain-language remediation steps. Technical depth is one click away; the big picture is immediate.

> *"I don't need another log aggregator. I need to know, in 30 seconds, whether my Windows fleet is audit-ready."*

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
| Weak password policy (< 8 chars) | HIGH | A.9.4.3 |
| SYSTEM service from non-system path | HIGH | A.9.2.2 |
| World-writable directory on sensitive path | HIGH | A.9.2 |
| LSASS not running as PPL | MEDIUM | A.9.2.3 |
| Unquoted service paths | LOW* | A.9.2.3 |

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

## ISO 27001:2022 Compliance Assessment

LNO Privilege Compliance Scanner evaluates all **93 Annex A controls** (ISO/IEC 27001:2022) across four themes:

| Theme | Controls | Scope |
|-------|----------|-------|
| **A.5 — Organizational** (37) | A.5.1 – A.5.37 | Policies, roles, incident response, compliance, supplier security |
| **A.6 — People** (8) | A.6.1 – A.6.8 | Screening, awareness, remote work, incident reporting |
| **A.7 — Physical** (14) | A.7.1 – A.7.14 | Perimeters, entry control, equipment security, media handling |
| **A.8 — Technological** (34) | A.8.1 – A.8.34 | Access control, malware protection, logging, cryptography, networking |

Each control is assessed as:
- **Compliant** — scanner verified the control is implemented correctly (no violations detected)
- **Non-compliant** — one or more findings violate this control (with evidence)
- **Not assessed** — control requires manual review (policy, organizational, or physical controls outside scanner scope)

### Key Controls Directly Verified

| Control | Domain | How It's Verified |
|---------|--------|-------------------|
| **A.8.2** | Privileged Access Rights | Admin group membership, dangerous privileges, UAC status, LSA protection |
| **A.8.5** | Secure Authentication | Password policy (length, complexity, lockout, expiry) |
| **A.8.7** | Malware Protection | Defender status, unsigned processes, services from suspicious paths |
| **A.8.15** | Logging | LSA protection, event log configuration indicators |
| **A.8.20** | Network Security | Firewall status, outbound connections from privileged processes |
| **A.8.32** | Change Management | Process/service inventory as baseline for change detection |
| **A.9.2** | Access Control | User accounts, group memberships, ACL analysis on sensitive paths |

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│                 │     │                  │     │                 │
│   PowerShell    │────▶│   scanner.js     │────▶│   scan.db       │
│   (WMI/Win32)   │     │   (Node.js)      │     │   (SQLite)      │
│                 │     │                  │     │                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │                 │
                                               │   server.js     │
                                               │   (REST API)    │
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
4. **Server** exposes REST API reading scan.db
5. **Dashboard** consumes API and renders interactive UI

### Design Decisions
- **No C++/Go required** — sql.js provides pure WebAssembly SQLite, no native compiler needed
- **No admin rights required** — WMI provides rich data for standard users
- **Self-contained** — single Node.js process, no database server, no external dependencies beyond npm

---

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/lno-privilege-compliance-scanner.git
cd lno-privilege-compliance-scanner

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
| `node server.js` | Start HTTP server on port 9090 |
| `node -e "require('./scanner.js').scan()"` | Programmatic scan invocation |

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

---

## Limitations & Roadmap

### Known Limitations
- **No open handle enumeration** — requires admin rights + NtQuerySystemInformation (C++)
- **WMI ExecutablePath empty for SYSTEM processes** — Windows restriction for non-admin users
- **Process owner detection** — WMI GetOwner() can fail for some processes without admin rights

### Planned Features
- [ ] Configurable notification thresholds (email/teams/webhook)
- [ ] PDF compliance report generation
- [ ] Scheduled scans with Windows Task Scheduler integration
- [ ] Multi-machine remote scanning
- [ ] Trend analysis with severity heatmaps

---

## ISO 27001 Audit Readiness

LNO Privilege Compliance Scanner is **designed as audit evidence for ISO 27001:2022 implementation**. It provides:

1. **Comprehensive 93-control mapping** — every Annex A control assessed with evidence
2. **Transparent rule engine** — all rules documented in `scanner.js` (`FINDING_DEFS`) with ISO control mappings
3. **Configurable risk scoring** — `risk-config.json` allows tailoring to organizational risk appetite
4. **Exportable evidence** — CSV exports of findings, compliance status, and processes for auditor review
5. **Governance documentation** — ADRs, risk assessment framework (AGRAF), data processing policy (DPRP), and UAT matrix included in the `dokumen/` folder
6. **Zero trust architecture** — fully offline, no third-party data transmission, ensuring evidence integrity

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

8. **No Sensitive Data in Repository**: This repository contains no internal IP addresses, API keys, client secrets, or proprietary information. However, scanning results stored in `scan.db` may contain system metadata — do not commit this file to version control. You are responsible for reviewing any output before sharing or publishing.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**dnislno** — [github.com/dnislno](https://github.com/dnislno)

A lead ISO 27001 auditor who codes. Compliance expertise and software engineering are not mutually exclusive.

> *"The best auditors don't just check boxes. They build tools that check boxes automatically."*
