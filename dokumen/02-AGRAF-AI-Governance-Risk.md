# AI Governance & Risk Assessment Framework (AGRAF)
## LNO Privilege Compliance Scanner

**Versi:** 1.0  
**Author:** dnislno (https://github.com/dnislno)  
**Lisensi:** MIT  
**Disclaimer:** Perangkat lunak ini disediakan "AS IS" tanpa jaminan apapun. Penulis tidak bertanggung jawab atas kerugian atau kerusakan yang timbul dari penggunaan perangkat lunak ini. Pengguna menanggung semua risiko dan tanggung jawab.
**Tanggal:** 2026-06-23  
**Standar Terkait:** ISO/IEC 42001:2023, ISO/IEC 27001:2022, ISO/IEC 22989:2022  

---

## 1. Klasifikasi Sistem AI

| Atribut | Klasifikasi |
|---------|-------------|
| **Tipe Sistem** | Rule-based expert system + automated analysis engine |
| **Tingkat Otonomi** | Level 2 (Assisted) — scanner mengeksekusi secara deterministik, analisis berdasarkan aturan, tidak ada generative AI/ML |
| **Pengawasan Manusia** | Diperlukan — temuan harus direview sebelum tindakan; tidak ada remediasi otomatis |
| **Dampak Stakeholder** | System administrators, security auditors, compliance officers |

**Catatan:** Framework ini berlaku untuk automated rule-based analysis engine di LNO. Tool ini tidak menggunakan generative AI, neural networks, atau machine learning. Governance dibatasi pada **kualitas, bias, transparansi, dan akuntabilitas** dari rule-based decision engine.

---

## 2. Risk Assessment Matrix

### 2.1 Identifikasi Risiko

| ID | Kategori Risiko | Deskripsi Risiko | Kemungkinan | Dampak | RPN* |
|----|-----------------|------------------|-------------|--------|------|
| R-01 | **Akurasi** | False positive findings (misalnya menandai proses user yang sah sebagai SYSTEM) menyebabkan alarm tidak perlu atau waktu investigasi terbuang | Tinggi | Sedang | 12 |
| R-02 | **Akurasi** | False negatives — kehilangan ancaman nyata karena data WMI tidak lengkap (misalnya tidak ada executable path untuk SYSTEM processes) | Sedang | Tinggi | 12 |
| R-03 | **Keamanan** | Eksekusi temp file PowerShell — file `.ps1` yang ditulis ke disk bisa dibajak jika direktori proyek dikompromikan | Rendah | Kritis | 8 |
| R-04 | **Privasi** | Nama akun user lokal, keanggotaan grup, dan data ACL file di scan.db bisa mengekspos struktur organisasi | Sedang | Sedang | 9 |
| R-04b | **Audit Trail** | Tidak ada log siapa yang mengakses API compliance data — melanggar prinsip non-repudiation | Sedang | Tinggi | 12 |
| R-05 | **Compliance** | Algoritma risk score tidak dikalibrasi terhadap risiko dunia nyata, menyebabkan representasi postur kepatuhan tidak akurat | Rendah | Tinggi | 8 |
| R-06 | **Transparansi** | Pengguna tidak bisa melihat aturan MANA yang menghasilkan temuan atau BAGAIMANA risk score dihitung | Rendah | Sedang | 4 |
| R-07 | **Bias** | Scanner tidak bisa menilai proses yang tidak terlihat (SYSTEM processes tanpa enumerasi owner); menciptakan blind spot untuk ancaman berprivilese tinggi | Tinggi | Tinggi | 16 |
| R-08 | **Operasional** | Scan memblokir event loop Node.js (sync PowerShell calls); permintaan bersamaan selama scan menyebabkan timeout | Sedang | Sedang | 9 |

*\*RPN = Kemungkinan × Dampak (skala 1-4 masing-masing)*

### 2.2 Rencana Penanganan Risiko

| ID | Penanganan | Tindakan | Penanggung Jawab | Timeline |
|----|------------|----------|------------------|----------|
| R-01 | **Mitigasi** | Perbaiki `isSystemOwner()` untuk menggunakan pengecekan SID aktual, bukan pencocokan prefix string. Tambahkan debug log untuk proses yang salah klasifikasi. | Engineering | Iterasi berikutnya |
| R-02 | **Terima** (dengan monitoring) | Dokumentasikan keterbatasan. Sistem tidak bisa melewati batasan WMI tanpa hak admin. Tambahkan banner peringatan ketika admin tidak terdeteksi. | Dokumentasi | Saat ini |
| R-03 | **Mitigasi** | Batasi izin direktori proyek hanya untuk user. Security headers, CSP, CORS restriction telah diimplementasikan. Dashboard Auth dan API Key ditambahkan untuk mencegah akses tidak sah. | Engineering | **SELESAI** (Phase 1) |
| R-04 | **Mitigasi** | scan.db di-load ke RAM dan dihapus dari disk saat server start. Dataset sensitif hanya ada di disk selama ~100ms. | Engineering | **SELESAI** (ADR-015) |
| R-04b | **Mitigasi** | `audit.log` mencatat setiap akses API dengan timestamp, IP, method, URL, dan status code. | Engineering | **SELESAI** (Phase 1) |
| R-05 | **Mitigasi** | Algoritma risk score dapat dikonfigurasi — pengguna menetapkan bobot severity sendiri per tipe temuan via `risk-config.json`. | Engineering | **SELESAI** (v1.0) |
| R-06 | **Mitigasi** | Bagian "Detail" per temuan telah diimplementasikan — setiap temuan menampilkan title, detail (data provenance), dan remediasi. Modal detail menyediakan konteks tambahan. | Engineering | **SELESAI** (v1.0) |
| R-07 | **Terima** | Dokumentasikan sebagai keterbatasan yang diketahui. Rekomendasikan menjalankan scanner sebagai Administrator untuk visibilitas penuh. | Dokumentasi | Saat ini |
| R-08 | **Mitigasi** | Pindahkan scanner ke child process (non-blocking) atau tambahkan scan-lock dengan antrian untuk permintaan bersamaan. | Engineering | Mendatang |

---

## 3. Transparansi & Explainability

### 3.1 Katalog Aturan

Setiap temuan yang dihasilkan oleh scanner harus mereferensikan aturan yang terdokumentasi:

| Rule ID | Tipe Temuan | Logika | Severity |
|---------|-------------|-------|----------|
| RULE-ADM-01 | `admin_member` | User.IsInRole(Administrators) == true | critical |
| RULE-DEF-01 | `def_disabled` | Get-MpComputerStatus.RealTimeProtectionEnabled == false | high |
| RULE-FW-01 | `firewall_disabled` | Get-NetFirewallProfile.Enabled == false untuk profil mana pun | high |
| RULE-PW-01 | `weak_password_policy` | MinimumPasswordLength < 8 ATAU PasswordComplexity == 0 | high |
| RULE-PW-02 | `no_lockout_policy` | LockoutBadCount == 0 ATAU undefined | medium |
| RULE-UAC-01 | `uac_disabled` | EnableLUA == 0 | high |
| RULE-LSA-01 | `lsa_not_protected` | RunAsPPL == 0 | medium |
| RULE-PRV-01 | `dangerous_priv` | Privilege aktif ada di daftar DANGEROUS_PRIVILEGES | high |
| RULE-ACL-01 | `world_writable_system` | Everyone/Users dengan FullControl/Modify/Write di path sensitif | high |
| RULE-SVC-01 | `unquoted_service` | Path service mengandung spasi dan tidak dikutip | medium |
| RULE-SVC-02 | `sys_service_from_user` | Service berjalan sebagai SYSTEM dari path non-%windir% | high |
| RULE-SVC-03 | `suspicious_service` | Service berjalan dari %temp% atau %downloads% | critical |
| RULE-PRO-01 | `suspicious_service` | Proses berjalan sebagai SYSTEM dari path yang dapat ditulis user | critical |
| RULE-PRO-02 | `unsig_process_user` | Proses tidak ditandatangani dari path yang dapat ditulis user | medium |
| RULE-PRO-03 | `admin_process_network` | Proses berprivilese dengan koneksi jaringan keluar | medium |
| RULE-ACP-01 | `guest_enabled` | Akun Guest aktif | medium |
| RULE-POL-01 | `no_password_expiry` | Akun user dengan password tidak pernah kedaluwarsa | medium |
| RULE-REG-01 | `weak_registry_acl` | ACL lemah pada registry key sensitif (HKLM\Security, dll) | high |

### 3.2 Data Provenance

Setiap temuan HARUS mencatat:
- Source PowerShell command (contoh: `Get-CimInstance Win32_Process`)
- Nilai field tepat yang memicu aturan (contoh: `Owner = "SYSTEM"`)
- Timestamp scan
- PID dari proses terkait (jika berlaku)

Implementasi saat ini menyimpan ini di kolom `findings.detail`. Kolom `compliance_status.evidence` telah diimplementasikan untuk mencatat bukti kepatuhan/ketaatan per kontrol ISO 27001.

---

## 4. Bias & Fairness

| Tipe Bias | Penilaian | Mitigasi |
|-----------|-----------|----------|
| **Visibility bias** | SYSTEM processes tidak terlihat tanpa hak admin; scanner kurang melaporkan ancaman dari proses berprivilese | Dokumentasikan keterbatasan; rekomendasikan menjalankan sebagai admin untuk lingkungan produksi |
| **Localization bias** | Pencocokan string ACL hanya menggunakan bahasa Inggris `"everyone"`, `"users"`, dan Portugis `"usuários"` | Tambahkan pencocokan berbasis SID yang agnostik bahasa (S-1-1-0 = Everyone) |
| **Severity inflation** | Pemrosesan risk score mungkin terlalu menandai developer tools (Node.js, compiler) yang berjalan dari direktori user | Tambahkan mekanisme allowlist untuk developer tools yang dikenal |
| **Default-deny bias** | Floor score di 10 mencegah skor 0 tapi bisa memberikan keyakinan palsu pada sistem yang rusak parah | Dokumentasikan bahwa 10 = "minimum baseline", bukan "lulus" |

---

## 5. Pengawasan & Akuntabilitas Manusia

| Peran | Tanggung Jawab |
|-------|---------------|
| **Operator Scanner** | Review temuan sebelum tindakan remediasi. Pahami keterbatasan enumerasi berbasis WMI. |
| **Auditor Keamanan** | Verifikasi output scanner terhadap audit manual. Kalibrasi risk scoring sesuai kebijakan organisasi. |
| **Pemilik Sistem** | Setujui atau tolak tindakan remediasi yang disarankan dalam temuan. Terima risiko residual untuk temuan yang diterima. |
| **AI Orchestrator** (pengguna saat ini) | Maintain katalog aturan. Review laporan false positive/negative. Perbarui bobot severity. |

**Rantai akuntabilitas:** Temuan → Rekomendasi → Review Manusia → Tindakan (Go/No-Go)

---

## 6. Monitoring & Perbaikan Berkelanjutan

| Aktivitas | Frekuensi | Output |
|-----------|-----------|--------|
| Review log false positive | Per scan | Tandai temuan yang salah diangkat |
| Kalibrasi severity | Bulanan | Sesuaikan bobot severity berdasarkan risk appetite organisasi |
| Analisis kesenjangan cakupan aturan | Triwulan | Identifikasi kontrol keamanan yang tidak tercakup oleh aturan scanner |
| Benchmark terhadap Varonis/Lepide | Triwulan | Bandingkan cakupan temuan terhadap tool komersial |
| Integrasi umpan balik UAT | Per milestone | Perbarui aturan berdasarkan hasil user acceptance testing |

---

## 7. Compliance Mapping (Khusus AI)

| Klausul ISO 42001 | Status Implementasi |
|--------------------|---------------------|
| 6.1.3 — AI risk assessment | Parsial (dokumen ini) |
| 6.1.4 — AI risk treatment | Direncanakan (lihat Rencana Penanganan Risiko) |
| 7.1 — Transparansi sistem AI | Katalog aturan dipublikasikan (Bagian 3.1) |
| 7.2 — Explainability | Data provenance tercatat di findings |
| 7.3 — Pengawasan manusia | Persyaratan review-sebelum-tindakan |
| 8.1 — Monitoring sistem AI | Review manual per scan |
| 8.2 — Manajemen perubahan sistem AI | Tidak ada perubahan otomatis; semua pembaruan aturan melalui perubahan kode |

---
### 8. Kesesuaian sebagai Alat Bukti ISO 27001

LNO Privilege Compliance Scanner **layak dijadikan alat bukti implementasi ISO 27001:2022**. Seluruh dokumentasi framework governance ini (ADRs, risk assessment, rule catalog, data provenance, fairness analysis, dan accountability chain) menyediakan bukti terdokumentasi untuk auditor bahwa sistem penilaian keamanan ini dirancang, diimplementasikan, dan dioperasikan dengan prinsip transparansi, akuntabilitas, dan pengawasan manusia yang sesuai dengan standar ISO/IEC 27001:2022 dan ISO/IEC 42001:2023.

**Perubahan Phase 1 yang memperkuat posisi audit:**
1. **Dashboard auth** — kontrol akses (A.8.3, A.8.18) sekarang terimplementasi
2. **API Key** — authentication enforcement (A.8.5, A.8.18)
3. **Rate limiting** — protection dari brute force (A.8.8, A.8.20)
4. **CSP headers** — perlindungan XSS dan data injection (A.8.7, A.8.9)
5. **Audit log** — non-repudiation dan accountability (A.8.15, A.8.16)

Semua perubahan ini didokumentasikan di ADR-016 dan dapat diverifikasi melalui integration test suite (138 tests).

**Disusun oleh:** AI Orchestrator  
**Tanggal review:** 2026-06-23  
**Review berikutnya:** 2026-09-23 atau setelah perubahan fitur material

---

## English Version

# AI Governance & Risk Assessment Framework (AGRAF)
## LNO Privilege Compliance Scanner

**Version:** 1.0  
**Author:** dnislno (https://github.com/dnislno)  
**License:** MIT  
**Disclaimer:** This software is provided "AS IS" without any warranty. The author is not liable for any loss or damage arising from the use of this software. The user assumes all risk and responsibility.
**Date:** 2026-06-23  
**Related Standards:** ISO/IEC 42001:2023, ISO/IEC 27001:2022, ISO/IEC 22989:2022

---

## 1. AI System Classification

| Attribute | Classification |
|-----------|---------------|
| **System Type** | Rule-based expert system + automated analysis engine |
| **Autonomy Level** | Level 2 (Assisted) — scanner executes deterministically, analysis based on rules, no generative AI/ML |
| **Human Oversight** | Required — findings must be reviewed before action; no automated remediation |
| **Stakeholder Impact** | System administrators, security auditors, compliance officers |

**Note:** This framework applies to the automated rule-based analysis engine in LNO. This tool does not use generative AI, neural networks, or machine learning. Governance is limited to **quality, bias, transparency, and accountability** of the rule-based decision engine.

---

## 2. Risk Assessment Matrix

### 2.1 Risk Identification

| ID | Risk Category | Risk Description | Likelihood | Impact | RPN* |
|----|---------------|-----------------|------------|--------|------|
| R-01 | **Accuracy** | False positive findings (e.g. flagging a legitimate user process as SYSTEM) causing unnecessary alerts or wasted investigation time | High | Medium | 12 |
| R-02 | **Accuracy** | False negatives — missing real threats due to incomplete WMI data (e.g. no executable path for SYSTEM processes) | Medium | High | 12 |
| R-03 | **Security** | PowerShell temp file execution — `.ps1` files written to disk could be hijacked if the project directory is compromised | Low | Critical | 8 |
| R-04 | **Privacy** | Local user account names, group memberships, and file ACL data in scan.db could expose organizational structure | Medium | Medium | 9 |
| R-04b | **Audit Trail** | No log of who accesses the compliance data API — violates non-repudiation principle | Medium | High | 12 |
| R-05 | **Compliance** | Risk score algorithm is not calibrated against real-world risk, causing inaccurate compliance posture representation | Low | High | 8 |
| R-06 | **Transparency** | Users cannot see WHICH rules generated findings or HOW risk scores are calculated | Low | Medium | 4 |
| R-07 | **Bias** | Scanner cannot assess invisible processes (SYSTEM processes without owner enumeration); creates a blind spot for high-privilege threats | High | High | 16 |
| R-08 | **Operational** | Scan blocks the Node.js event loop (sync PowerShell calls); concurrent requests during scan cause timeouts | Medium | Medium | 9 |

*\*RPN = Likelihood × Impact (scale 1-4 each)*

### 2.2 Risk Treatment Plan

| ID | Treatment | Action | Responsible | Timeline |
|----|-----------|--------|-------------|----------|
| R-01 | **Mitigate** | Fix `isSystemOwner()` to use actual SID checking instead of string prefix matching. Add debug log for misclassified processes. | Engineering | Next iteration |
| R-02 | **Accept** (with monitoring) | Document limitations. System cannot bypass WMI restrictions without admin rights. Add warning banner when admin is not detected. | Documentation | Current |
| R-03 | **Mitigate** | Restrict project directory permissions to user only. Security headers, CSP, CORS restriction have been implemented. Dashboard Auth and API Key added to prevent unauthorized access. | Engineering | **DONE** (Phase 1) |
| R-04 | **Mitigate** | scan.db loaded into RAM and deleted from disk on server start. Sensitive dataset exists on disk for only ~100ms. | Engineering | **DONE** (ADR-015) |
| R-04b | **Mitigate** | `audit.log` records every API access with timestamp, IP, method, URL, and status code. | Engineering | **DONE** (Phase 1) |
| R-05 | **Mitigate** | Risk score algorithm is configurable — users set their own severity weights per finding type via `risk-config.json`. | Engineering | **DONE** (v1.0) |
| R-06 | **Mitigate** | "Detail" section per finding has been implemented — each finding displays title, detail (data provenance), and remediation. Detail modal provides additional context. | Engineering | **DONE** (v1.0) |
| R-07 | **Accept** | Document as a known limitation. Recommend running the scanner as Administrator for full visibility. | Documentation | Current |
| R-08 | **Mitigate** | Move scanner to child process (non-blocking) or add scan-lock with queue for concurrent requests. | Engineering | Future |

---

## 3. Transparency & Explainability

### 3.1 Rule Catalog

Each finding generated by the scanner must reference a documented rule:

| Rule ID | Finding Type | Logic | Severity |
|---------|-------------|-------|----------|
| RULE-ADM-01 | `admin_member` | User.IsInRole(Administrators) == true | critical |
| RULE-DEF-01 | `def_disabled` | Get-MpComputerStatus.RealTimeProtectionEnabled == false | high |
| RULE-FW-01 | `firewall_disabled` | Get-NetFirewallProfile.Enabled == false for any profile | high |
| RULE-PW-01 | `weak_password_policy` | MinimumPasswordLength < 8 OR PasswordComplexity == 0 | high |
| RULE-PW-02 | `no_lockout_policy` | LockoutBadCount == 0 OR undefined | medium |
| RULE-UAC-01 | `uac_disabled` | EnableLUA == 0 | high |
| RULE-LSA-01 | `lsa_not_protected` | RunAsPPL == 0 | medium |
| RULE-PRV-01 | `dangerous_priv` | Active privilege is in the DANGEROUS_PRIVILEGES list | high |
| RULE-ACL-01 | `world_writable_system` | Everyone/Users with FullControl/Modify/Write on sensitive paths | high |
| RULE-SVC-01 | `unquoted_service` | Service path contains spaces and is not quoted | medium |
| RULE-SVC-02 | `sys_service_from_user` | Service running as SYSTEM from a non-%windir% path | high |
| RULE-SVC-03 | `suspicious_service` | Service running from %temp% or %downloads% | critical |
| RULE-PRO-01 | `suspicious_service` | Process running as SYSTEM from a user-writable path | critical |
| RULE-PRO-02 | `unsig_process_user` | Unsigned process from a user-writable path | medium |
| RULE-PRO-03 | `admin_process_network` | Privileged process with outbound network connection | medium |
| RULE-ACP-01 | `guest_enabled` | Guest account is active | medium |
| RULE-POL-01 | `no_password_expiry` | User account with password never expires | medium |
| RULE-REG-01 | `weak_registry_acl` | Weak ACL on sensitive registry key (HKLM\Security, etc.) | high |

### 3.2 Data Provenance

Each finding MUST record:
- Source PowerShell command (example: `Get-CimInstance Win32_Process`)
- Exact field value that triggered the rule (example: `Owner = "SYSTEM"`)
- Scan timestamp
- PID of the related process (if applicable)

Current implementation stores this in the `findings.detail` column. The `compliance_status.evidence` column has been implemented to record evidence of compliance/adherence per ISO 27001 control.

---

## 4. Bias & Fairness

| Bias Type | Assessment | Mitigation |
|-----------|-----------|------------|
| **Visibility bias** | SYSTEM processes are invisible without admin rights; the scanner under-reports threats from privileged processes | Document limitation; recommend running as admin for production environments |
| **Localization bias** | ACL string matching only uses English `"everyone"`, `"users"`, and Portuguese `"usuários"` | Add language-agnostic SID-based matching (S-1-1-0 = Everyone) |
| **Severity inflation** | Risk score processing may over-flag developer tools (Node.js, compilers) running from user directories | Add allowlist mechanism for known developer tools |
| **Default-deny bias** | Floor score at 10 prevents a score of 0 but could provide false confidence in severely broken systems | Document that 10 = "minimum baseline", not "passing" |

---

## 5. Human Oversight & Accountability

| Role | Responsibility |
|------|---------------|
| **Scanner Operator** | Review findings before remediation actions. Understand the limitations of WMI-based enumeration. |
| **Security Auditor** | Verify scanner output against manual audit. Calibrate risk scoring according to organizational policy. |
| **System Owner** | Approve or reject remediation actions suggested in findings. Accept residual risk for accepted findings. |
| **AI Orchestrator** (current user) | Maintain the rule catalog. Review false positive/negative reports. Update severity weights. |

**Accountability chain:** Finding → Recommendation → Human Review → Action (Go/No-Go)

---

## 6. Monitoring & Continuous Improvement

| Activity | Frequency | Output |
|----------|-----------|--------|
| False positive log review | Per scan | Flag incorrectly raised findings |
| Severity calibration | Monthly | Adjust severity weights based on organizational risk appetite |
| Rule coverage gap analysis | Quarterly | Identify security controls not covered by scanner rules |
| Benchmark against Varonis/Lepide | Quarterly | Compare finding coverage against commercial tools |
| UAT feedback integration | Per milestone | Update rules based on user acceptance testing results |

---

## 7. Compliance Mapping (AI-Specific)

| ISO 42001 Clause | Implementation Status |
|------------------|----------------------|
| 6.1.3 — AI risk assessment | Partial (this document) |
| 6.1.4 — AI risk treatment | Planned (see Risk Treatment Plan) |
| 7.1 — AI system transparency | Rule catalog published (Section 3.1) |
| 7.2 — Explainability | Data provenance recorded in findings |
| 7.3 — Human oversight | Review-before-action requirements |
| 8.1 — AI system monitoring | Manual review per scan |
| 8.2 — AI system change management | No automated changes; all rule updates via code changes |

---

### 8. Suitability as ISO 27001 Audit Evidence

LNO Privilege Compliance Scanner **is suitable as evidence for ISO 27001:2022 implementation**. The entire governance framework documentation (ADRs, risk assessment, rule catalog, data provenance, fairness analysis, and accountability chain) provides documented evidence for auditors that this security assessment system is designed, implemented, and operated with principles of transparency, accountability, and human oversight in accordance with ISO/IEC 27001:2022 and ISO/IEC 42001:2023.

**Phase 1 changes that strengthen audit position:**
1. **Dashboard auth** — access control (A.8.3, A.8.18) is now implemented
2. **API Key** — authentication enforcement (A.8.5, A.8.18)
3. **Rate limiting** — brute force protection (A.8.8, A.8.20)
4. **CSP headers** — XSS and data injection protection (A.8.7, A.8.9)
5. **Audit log** — non-repudiation and accountability (A.8.15, A.8.16)

All these changes are documented in ADR-016 and can be verified through the integration test suite (138 tests).

**Prepared by:** AI Orchestrator  
**Review date:** 2026-06-23  
**Next review:** 2026-09-23 or after material feature changes
