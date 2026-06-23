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
| R-03 | **Mitigasi** | Batasi izin direktori proyek hanya untuk user. Security headers & CORS restriction telah diimplementasikan untuk mencegah data exfiltration. | Engineering | **Sebagian** (security headers selesai, TOCTOU masih risiko residual) |
| R-04 | **Mitigasi** | scan.db harus dienkripsi saat diam (SQLCipher) atau disimpan di direktori temp profil user dengan ACL terbatas. | Engineering | Mendatang |
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

**Disusun oleh:** AI Orchestrator  
**Tanggal review:** 2026-06-23  
**Review berikutnya:** 2026-09-23 atau setelah perubahan fitur material
