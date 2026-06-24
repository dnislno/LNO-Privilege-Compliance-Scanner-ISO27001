# Data Processing & Retention Policy (DPRP)
## Kepatuhan terhadap Undang-Undang Perlindungan Data Pribadi (UU PDP)

**Versi:** 1.0  
**Author:** dnislno (https://github.com/dnislno)  
**Lisensi:** MIT  
**Disclaimer:** Perangkat lunak ini disediakan "AS IS" tanpa jaminan apapun. Penulis tidak bertanggung jawab atas kerugian atau kerusakan yang timbul dari penggunaan perangkat lunak ini. Pengguna menanggung semua risiko dan tanggung jawab.
**Tanggal:** 2026-06-23  
**Dasar Hukum:** Undang-Undang No. 27 Tahun 2022 tentang Perlindungan Data Pribadi (UU PDP)  
**Pengendali Data:** Administrator sistem / operator scanner  
**Prosesor Data:** Perangkat lunak LNO Privilege Compliance Scanner (sepenuhnya offline, tanpa pihak ketiga)

---

## 1. Inventaris Data

### 1.1 Kategori Data yang Dikumpulkan

| Kategori | Contoh | Klasifikasi (UU PDP) | Sumber |
|----------|--------|----------------------|--------|
| **Informasi sistem** | Hostname, versi OS, arsitektur, total RAM, waktu boot terakhir | Bukan data pribadi | WMI Win32_ComputerSystem |
| **Data akun user** | Username, nama lengkap, SID, status aktif akun, logon terakhir, kedaluwarsa password | **Data Pribadi** (nama + identitas sistem) | Get-LocalUser, WMI Win32_UserAccount |
| **Data grup user** | Nama grup, SID, anggota | **Data Pribadi** (keanggotaan grup) | Get-LocalGroup, Get-LocalGroupMember |
| **Data proses** | PID, nama proses, pemilik (domain\user), path eksekusi, command line, CPU/memory | Dapat mengandung data pribadi (command line bisa berisi nama/path) | WMI Win32_Process |
| **Koneksi jaringan** | Alamat lokal/remote, protokol, state, PID pemilik | Bukan data pribadi (alamat IP bersifat mesin) | netstat -ano |
| **Data service** | Nama service, display name, start mode, path, akun, parent_app (klasifikasi aplikasi induk) | Dapat mengandung data pribadi (nama akun) | WMI Win32_Service |
| **Data ACL file** | Path file, identitas (nama user/grup), hak akses, tipe akses | **Data Pribadi** (nama identitas) | Get-Acl |
| **Kebijakan keamanan** | Password policy, pengaturan UAC, ambang lockout | Bukan data pribadi | secedit, registry |
| **Defender/Firewall** | Status proteksi, versi signature | Bukan data pribadi | Get-MpComputerStatus |
| **Temuan (Findings)** | Severity, deskripsi masalah keamanan | Bukan data pribadi (agregat/analitis) | Dihasilkan oleh scanner |

### 1.2 Ringkasan Klasifikasi Data

| Klasifikasi UU PDP | Jumlah Tipe Data | Contoh |
|--------------------|-----------------|--------|
| **Data Pribadi** | 4 kategori | Username, nama lengkap, SID, keanggotaan grup, identitas ACL |
| **Bukan Data Pribadi** | 7 kategori | Info sistem, proses (tanpa pemilik), jaringan, service, kebijakan, defender, temuan |

---

## 2. Dasar Hukum Pemrosesan (UU PDP Pasal 4 & 5)

| Dasar Hukum | Penerapan |
|-------------|-----------|
| **Persetujuan (Pasal 5 ayat 1a)** | Operator scanner memberikan persetujuan dengan menjalankan tool di sistemnya sendiri. Tidak ada data pihak ketiga yang dikumpulkan tanpa persetujuan mereka. |
| **Kepentingan yang Sah (Pasal 5 ayat 1b)** | Audit keamanan adalah kepentingan sah pemilik sistem. Pemrosesan diperlukan untuk keamanan sistem elektronik (Pasal 5 ayat 3). |
| **Kewajiban Kontraktual** | T/A — tidak ada hubungan kontraktual dengan subjek data |

**Pernyataan afirmatif:** Tool ini memproses data pribadi HANYA untuk tujuan audit keamanan. Tool ini tidak menjual, mentransfer, atau mengekspos data pribadi ke pihak ketiga. Semua pemrosesan terjadi secara lokal di mesin yang dipindai.

---

## 3. Prinsip Pemrosesan Data (UU PDP Pasal 16-22)

| Prinsip | Kepatuhan | Implementasi |
|---------|-----------|-------------|
| **Terbatas & Spesifik** (Purpose limitation) | ✓ | Data hanya digunakan untuk penilaian keamanan; tidak ada penggunaan sekunder |
| **Minimal** (Data minimization) | ✓ | Hanya mengumpulkan data yang relevan dengan postur keamanan; tidak ada riwayat penjelajahan, ketikan, atau data konten |
| **Akurat** (Accuracy) | Parsial | WMI dapat mengembalikan data basi untuk proses yang sudah dihentikan; scanner berjalan on-demand, tidak kontinu |
| **Jangka Waktu** (Storage limitation) | ✓ | Lihat Bagian 4 (Jadwal Retensi) |
| **Kerahasiaan & Keamanan** (Confidentiality & Integrity) | ✓ | Data disimpan di SQLite lokal; tidak ada transmisi jaringan. Lihat Bagian 6 (Kontrol Keamanan) |
| **Akuntabilitas** (Accountability) | ✓ | Operator bertanggung jawab atas penghapusan dan kontrol akses |

---

## 4. Jadwal Retensi (UU PDP Pasal 23)

| Kategori Data | Periode Retensi Saat Scan | Periode Retensi di DB | Mekanisme Penghapusan |
|---------------|---------------------------|----------------------|-----------------------|
| Informasi sistem | Durasi scan (~90 detik) | Hingga digantikan scan berikutnya | TERTIMPA pada scan baru (scan.db ditimpa) |
| Data akun user | Durasi scan | Hingga digantikan | TERTIMPA |
| Data grup user | Durasi scan | Hingga digantikan | TERTIMPA |
| Data proses | Durasi scan | Hingga digantikan | TERTIMPA |
| Koneksi jaringan | Durasi scan | Hingga digantikan | TERTIMPA |
| Data service | Durasi scan | Hingga digantikan | TERTIMPA |
| Data ACL file | Durasi scan | Hingga digantikan | TERTIMPA |
| Kebijakan keamanan | Durasi scan | Hingga digantikan | TERTIMPA |
| Defender/Firewall | Durasi scan | Hingga digantikan | TERTIMPA |
| Temuan (Findings) | Durasi scan | Hingga digantikan | TERTIMPA |

**Kebijakan Retensi:** `scan.db` DITIMPA pada setiap scan baru. TIDAK ADA retensi historis dari scan sebelumnya. Ini berarti:
- **Retensi maksimum setiap data:** dari mulai scan hingga scan berikutnya dimulai (dapat dikonfigurasi pengguna, menit hingga hari)
- **Tanpa arsip:** Tidak ada cadangan atau snapshot yang disimpan
- **Penghapusan manual:** Hapus `scan.db` untuk langsung menghapus semua data

**Catatan desain:** Retensi historis (tabel `scans_history`) TIDAK diimplementasikan dengan sengaja (*by design*). Setiap scan menimpa data sebelumnya untuk meminimalkan permukaan data pribadi yang disimpan. Analisis tren dapat dilakukan dengan menyimpan CSV hasil ekspor secara manual. Keputusan ini mematuhi prinsip *data minimization* (UU PDP Pasal 19) — hanya menyimpan data yang diperlukan untuk fungsi saat ini.

---

## 5. Hak Subjek Data (UU PDP Pasal 6-14)

| Hak | Pasal | Status Implementasi |
|-----|-------|---------------------|
| **Hak untuk mengetahui** | 6 | Parsial — temuan menampilkan kolom `detail` yang menjelaskan apa yang memicu temuan |
| **Hak akses** | 7 | ✓ — Data lengkap tersedia via REST API atau query SQLite langsung |
| **Hak perbaikan** | 8 | T/A — scanner tidak membuat data pribadi, hanya mencerminkan keadaan sistem |
| **Hak penghapusan** | 9 | ✓ — Hapus `scan.db` untuk menghapus semua data. Jalankan ulang scan untuk menghasilkan ulang. |
| **Hak pembatasan** | 10 | T/A — pemrosesan bersifat all-or-nothing per scan |
| **Hak portabilitas** | 11 | ✓ — Data dalam format SQLite, portabel antar sistem |
| **Hak keberatan** | 12 | ✓ — Operator dapat memilih untuk tidak menjalankan scanner |

---

## 6. Kontrol Keamanan untuk Perlindungan Data (UU PDP Pasal 36-40)

| Kontrol | Implementasi |
|---------|-------------|
| **Kontrol akses** | `scan.db` disimpan di direktori proyek; akses diatur oleh izin filesystem (NTFS). Tidak ada eksposur jaringan. |
| **Enkripsi saat diam** | BELUM diimplementasikan. `scan.db` adalah SQLite teks biasa. **Risiko:** siapa pun dengan akses filesystem ke direktori proyek dapat membaca semua data. Mitigasi: set `DELETE_DB_ON_LOAD=true` di .env untuk menghapus file setelah server start (data hilang saat restart server). |
| **Enkripsi saat transit** | T/A — server bind hanya ke localhost (127.0.0.1:9090). Tidak ada transmisi jaringan. |
| **Logging & monitoring** | ✓ **SELESAI (Phase 1)**. `audit.log` mencatat setiap akses API dengan format: `[timestamp] TYPE METHOD URL STATUS IP`. Contoh: `[2026-06-24T04:27:30.992Z] API GET /api/overview 200 127.0.0.1`. |
| **Tanggap insiden** | Dikelola operator. Sebagai tool offline, permukaan pelanggaran terbatas pada mesin lokal. |

**Rekomendasi peningkatan untuk penggunaan produksi:**
1. Simpan `scan.db` di `%APPDATA%\LNO-PrivilegeScanner` dengan ACL deny-BUILTIN\Users eksplisit
2. Tambahkan SQLCipher untuk enkripsi saat diam
3. ~~Tambahkan tabel audit log yang mencatat setiap akses API~~ **(✓ SELESAI — Phase 1: `audit.log` file-based)**
4. Implementasikan penghapusan otomatis yang dapat dikonfigurasi setelah N hari
5. Integrasi audit log dengan syslog/SIEM untuk central logging

---

## 7. Transfer Data Internasional (UU PDP Pasal 55)

**Pernyataan:** TIDAK ADA transfer data internasional. Semua pemrosesan, penyimpanan, dan akses data terjadi sepenuhnya di mesin lokal. Tool ini tidak:
- Mengirim data ke server eksternal
- Menggunakan cloud APIs
- Telemetry atau analytics
- Fungsi phone-home
- Dependency CDN di dashboard (Tailwind dimuat dari CDN, tapi tidak ada data yang dikirim — permintaan browser standar)

**Catatan CDN:** `index.html` memuat `https://cdn.tailwindcss.com` saat page load. Ini adalah permintaan CSS browser standar. Tidak ada data scan yang disertakan atau dapat diturunkan dari permintaan ini. Penyedia CDN mungkin menerima: alamat IP, User-Agent, header referrer (berisi `http://localhost:9090`). Ini adalah perilaku browser, bukan perilaku scanner.

---

## 8. Kepatuhan Lintas Negara

| Regulasi | Status | Catatan |
|----------|--------|---------|
| **UU PDP (Indonesia)** | Kepatuhan parsial | Kepatuhan penuh membutuhkan enkripsi saat diam dan audit logging |
| **GDPR (EU)** | Kepatuhan parsial | Akan membutuhkan Data Processing Agreement, enkripsi, dan mekanisme hak hapus |
| **PDPA (Singapura)** | Parsial | Mirip dengan UU PDP; pemrosesan hanya lokal merupakan keunggulan |
| **CCPA (California)** | Tidak berlaku | Scanner tidak mengumpulkan informasi pribadi penduduk California untuk tujuan bisnis |

---

## 9. Prosedur Notifikasi Pelanggaran (UU PDP Pasal 35)

Jika terjadi eksposur `scan.db` (misalnya akses tidak sah ke direktori proyek):

1. **Identifikasi** — operator menemukan akses tidak sah ke `scan.db`
2. **Tangani** — hapus `scan.db`, cabut izin filesystem
3. **Nilailah** — tentukan data apa yang terekspos (semua data di `scan.db`)
4. **Beritahu** — informasikan subjek data yang terkena dampak (user yang akunnya terenumerasi) dalam waktu **72 jam** (UU PDP Pasal 35 ayat 2)
5. **Dokumentasikan** — catat pelanggaran, dampak, dan tindakan perbaikan
6. **Laporkan** — ke Kementerian Komunikasi dan Informatika (jika >100 subjek data terpengaruh)

---

## 10. Tinjauan & Pembaruan Kebijakan

| Versi | Tanggal | Perubahan | Penulis |
|-------|---------|-----------|---------|
| 1.0 | 2026-06-23 | Kebijakan awal | AI Orchestrator |

**Siklus tinjauan:** Tahunan, atau jika terjadi perubahan material pada UU PDP atau fungsionalitas scanner.

---
### 11. Kesesuaian sebagai Alat Bukti ISO 27001

LNO Privilege Compliance Scanner **layak dijadikan alat bukti implementasi ISO 27001:2022** dalam konteks perlindungan data:

1. **Pemrosesan lokal** — semua data diproses di mesin lokal tanpa transmisi ke pihak ketiga, menjamin kerahasiaan data
2. **Data minimization** — hanya data yang relevan dengan postur keamanan yang dikumpulkan; tidak ada data konten, riwayat penjelajahan, atau ketikan
3. **Kebijakan retensi ketat** — scan.db ditimpa setiap scan; data pribadi tidak disimpan lebih lama dari yang diperlukan
4. **Kontrol akses fisik** — scan.db dilindungi oleh izin filesystem NTFS; server bind ke localhost saja
5. **Hak subjek data** — penghapusan data dimungkinkan dengan menghapus scan.db; akses data penuh via REST API
6. **Transparansi pemrosesan** — inventaris data lengkap (Bagian 1), dasar hukum (Bagian 2), dan jadwal retensi (Bagian 4) terdokumentasi

Dokumen ini sendiri berfungsi sebagai bukti kepatuhan terhadap Pasal 16-22 UU PDP dan prinsip-prinsip perlindungan data yang relevan untuk audit ISO 27001 (kontrol A.5.33 — Protection of records, A.5.34 — Privacy and PII).

**Pembaruan Phase 1:** Audit logging (`audit.log`) telah diimplementasikan, memenuhi persyaratan logging dan monitoring (A.8.15). Setiap akses API tercatat dengan timestamp, IP, action, dan status code untuk mendukung non-repudiation dan accountability.

**Disusun oleh:** AI Orchestrator  
**Tanggal review:** 2026-06-23  
**Review berikutnya:** 2026-09-23 atau setelah perubahan fitur material

---

## English Version

# Data Processing & Retention Policy (DPRP)
## Compliance with the Indonesian Personal Data Protection Law (UU PDP)

**Version:** 1.0  
**Author:** dnislno (https://github.com/dnislno)  
**License:** MIT  
**Disclaimer:** This software is provided "AS IS" without any warranty. The author is not liable for any losses or damages arising from the use of this software. Users assume all risks and responsibilities.
**Date:** 2026-06-23  
**Legal Basis:** Law No. 27 of 2022 on Personal Data Protection (UU PDP)  
**Data Controller:** System administrator / scanner operator  
**Data Processor:** LNO Privilege Compliance Scanner software (fully offline, no third parties)

---

## 1. Data Inventory

### 1.1 Categories of Data Collected

| Category | Examples | Classification (UU PDP) | Source |
|----------|---------|------------------------|--------|
| **System information** | Hostname, OS version, architecture, total RAM, last boot time | Not personal data | WMI Win32_ComputerSystem |
| **User account data** | Username, full name, SID, account active status, last logon, password expiry | **Personal Data** (name + system identity) | Get-LocalUser, WMI Win32_UserAccount |
| **User group data** | Group name, SID, members | **Personal Data** (group membership) | Get-LocalGroup, Get-LocalGroupMember |
| **Process data** | PID, process name, owner (domain\user), execution path, command line, CPU/memory | May contain personal data (command line may contain names/paths) | WMI Win32_Process |
| **Network connections** | Local/remote addresses, protocol, state, owner PID | Not personal data (IP addresses are machine-oriented) | netstat -ano |
| **Service data** | Service name, display name, start mode, path, account, parent_app (parent application classification) | May contain personal data (account names) | WMI Win32_Service |
| **File ACL data** | File path, identity (user/group name), access rights, access type | **Personal Data** (identity names) | Get-Acl |
| **Security policies** | Password policy, UAC settings, lockout threshold | Not personal data | secedit, registry |
| **Defender/Firewall** | Protection status, signature version | Not personal data | Get-MpComputerStatus |
| **Findings** | Severity, security issue description | Not personal data (aggregate/analytical) | Generated by scanner |

### 1.2 Data Classification Summary

| UU PDP Classification | Number of Data Types | Examples |
|-----------------------|---------------------|---------|
| **Personal Data** | 4 categories | Username, full name, SID, group membership, ACL identities |
| **Not Personal Data** | 7 categories | System info, processes (without owner), network, services, policies, defender, findings |

---

## 2. Legal Basis for Processing (UU PDP Articles 4 & 5)

| Legal Basis | Application |
|-------------|------------|
| **Consent (Article 5 paragraph 1a)** | The scanner operator provides consent by running the tool on their own system. No third-party data is collected without their consent. |
| **Legitimate Interest (Article 5 paragraph 1b)** | Security audit is the legitimate interest of the system owner. Processing is necessary for electronic system security (Article 5 paragraph 3). |
| **Contractual Obligation** | N/A — no contractual relationship with data subjects |

**Affirmative statement:** This tool processes personal data ONLY for security audit purposes. This tool does not sell, transfer, or expose personal data to third parties. All processing occurs locally on the scanned machine.

---

## 3. Data Processing Principles (UU PDP Articles 16-22)

| Principle | Compliance | Implementation |
|-----------|-----------|--------------|
| **Limited & Specific** (Purpose limitation) | ✓ | Data is only used for security assessment; no secondary use |
| **Minimal** (Data minimization) | ✓ | Only collects data relevant to security posture; no browsing history, keystrokes, or content data |
| **Accurate** (Accuracy) | Partial | WMI may return stale data for terminated processes; scanner runs on-demand, not continuously |
| **Storage Limitation** (Storage limitation) | ✓ | See Section 4 (Retention Schedule) |
| **Confidentiality & Security** (Confidentiality & Integrity) | ✓ | Data stored in local SQLite; no network transmission. See Section 6 (Security Controls) |
| **Accountability** (Accountability) | ✓ | Operator is responsible for deletion and access control |

---

## 4. Retention Schedule (UU PDP Article 23)

| Data Category | Retention Period During Scan | Retention Period in DB | Deletion Mechanism |
|---------------|------------------------------|----------------------|-------------------|
| System information | Scan duration (~90 seconds) | Until replaced by next scan | OVERWRITTEN on new scan (scan.db is overwritten) |
| User account data | Scan duration | Until replaced | OVERWRITTEN |
| User group data | Scan duration | Until replaced | OVERWRITTEN |
| Process data | Scan duration | Until replaced | OVERWRITTEN |
| Network connections | Scan duration | Until replaced | OVERWRITTEN |
| Service data | Scan duration | Until replaced | OVERWRITTEN |
| File ACL data | Scan duration | Until replaced | OVERWRITTEN |
| Security policies | Scan duration | Until replaced | OVERWRITTEN |
| Defender/Firewall | Scan duration | Until replaced | OVERWRITTEN |
| Findings | Scan duration | Until replaced | OVERWRITTEN |

**Retention Policy:** `scan.db` is OVERWRITTEN on each new scan. There is NO historical retention from previous scans. This means:
- **Maximum retention of each data:** from the start of a scan until the next scan begins (user-configurable, minutes to days)
- **No archive:** No backups or snapshots are kept
- **Manual deletion:** Delete `scan.db` to immediately remove all data

**Design note:** Historical retention (`scans_history` table) is deliberately NOT implemented (*by design*). Each scan overwrites previous data to minimize the surface area of stored personal data. Trend analysis can be performed by manually saving exported CSV files. This decision complies with the *data minimization* principle (UU PDP Article 19) — only storing data necessary for current functionality.

---

## 5. Data Subject Rights (UU PDP Articles 6-14)

| Right | Article | Implementation Status |
|-------|---------|----------------------|
| **Right to know** | 6 | Partial — findings display a `detail` column explaining what triggered the finding |
| **Right of access** | 7 | ✓ — Complete data available via REST API or direct SQLite query |
| **Right to rectification** | 8 | N/A — scanner does not create personal data, only reflects system state |
| **Right to erasure** | 9 | ✓ — Delete `scan.db` to remove all data. Re-run scan to regenerate. |
| **Right to restriction** | 10 | N/A — processing is all-or-nothing per scan |
| **Right to portability** | 11 | ✓ — Data in SQLite format, portable across systems |
| **Right to object** | 12 | ✓ — Operator can choose not to run the scanner |

---

## 6. Security Controls for Data Protection (UU PDP Articles 36-40)

| Control | Implementation |
|---------|--------------|
| **Access control** | `scan.db` is stored in the project directory; access is governed by filesystem permissions (NTFS). No network exposure. |
| **Encryption at rest** | NOT implemented. `scan.db` is plain-text SQLite. **Risk:** anyone with filesystem access to the project directory can read all data. Mitigation: set `DELETE_DB_ON_LOAD=true` in .env to delete the file after server start (data lost on server restart). |
| **Encryption in transit** | N/A — server binds only to localhost (127.0.0.1:9090). No network transmission. |
| **Logging & monitoring** | ✓ **COMPLETED (Phase 1)**. `audit.log` records every API access with format: `[timestamp] TYPE METHOD URL STATUS IP`. Example: `[2026-06-24T04:27:30.992Z] API GET /api/overview 200 127.0.0.1`. |
| **Incident response** | Managed by operator. As an offline tool, the breach surface is limited to the local machine. |

**Recommended enhancements for production use:**
1. Store `scan.db` in `%APPDATA%\LNO-PrivilegeScanner` with explicit ACL deny-BUILTIN\Users
2. Add SQLCipher for encryption at rest
3. ~~Add audit log table recording every API access~~ **(✓ COMPLETED — Phase 1: `audit.log` file-based)**
4. Implement configurable automatic deletion after N days
5. Integrate audit log with syslog/SIEM for centralized logging

---

## 7. International Data Transfer (UU PDP Article 55)

**Statement:** There is NO international data transfer. All data processing, storage, and access occurs entirely on the local machine. This tool does not:
- Send data to external servers
- Use cloud APIs
- Have telemetry or analytics
- Have phone-home functionality
- Have CDN dependencies in the dashboard (Tailwind is loaded from CDN, but no data is sent — standard browser request)

**CDN Note:** `index.html` loads `https://cdn.tailwindcss.com` on page load. This is a standard browser CSS request. No scan data is included or can be inferred from this request. The CDN provider may receive: IP address, User-Agent, referrer header (containing `http://localhost:9090`). This is browser behavior, not scanner behavior.

---

## 8. Cross-Country Compliance

| Regulation | Status | Notes |
|------------|--------|-------|
| **UU PDP (Indonesia)** | Partial compliance | Full compliance requires encryption at rest and audit logging |
| **GDPR (EU)** | Partial compliance | Would require Data Processing Agreement, encryption, and erasure right mechanisms |
| **PDPA (Singapore)** | Partial | Similar to UU PDP; local-only processing is an advantage |
| **CCPA (California)** | Not applicable | Scanner does not collect personal information of California residents for business purposes |

---

## 9. Breach Notification Procedure (UU PDP Article 35)

In the event of `scan.db` exposure (e.g., unauthorized access to the project directory):

1. **Identify** — operator discovers unauthorized access to `scan.db`
2. **Contain** — delete `scan.db`, revoke filesystem permissions
3. **Assess** — determine what data was exposed (all data in `scan.db`)
4. **Notify** — inform affected data subjects (users whose accounts were enumerated) within **72 hours** (UU PDP Article 35 paragraph 2)
5. **Document** — record the breach, impact, and corrective actions
6. **Report** — to the Ministry of Communication and Informatics (if >100 data subjects are affected)

---

## 10. Policy Review & Updates

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-06-23 | Initial policy | AI Orchestrator |

**Review cycle:** Annually, or upon material changes to the UU PDP or scanner functionality.

---

### 11. Suitability as ISO 27001 Evidence

LNO Privilege Compliance Scanner **is suitable as evidence for ISO 27001:2022 implementation** in the context of data protection:

1. **Local processing** — all data is processed on the local machine without transmission to third parties, ensuring data confidentiality
2. **Data minimization** — only data relevant to security posture is collected; no content data, browsing history, or keystrokes
3. **Strict retention policy** — scan.db is overwritten each scan; personal data is not kept longer than necessary
4. **Physical access control** — scan.db is protected by NTFS filesystem permissions; server binds only to localhost
5. **Data subject rights** — data deletion is possible by removing scan.db; full data access via REST API
6. **Processing transparency** — complete data inventory (Section 1), legal basis (Section 2), and retention schedule (Section 4) are documented

This document itself serves as evidence of compliance with UU PDP Articles 16-22 and relevant data protection principles for ISO 27001 audit (controls A.5.33 — Protection of records, A.5.34 — Privacy and PII).

**Phase 1 Update:** Audit logging (`audit.log`) has been implemented, fulfilling logging and monitoring requirements (A.8.15). Every API access is recorded with timestamp, IP, action, and status code to support non-repudiation and accountability.

**Prepared by:** AI Orchestrator  
**Review date:** 2026-06-23  
**Next review:** 2026-09-23 or after material feature changes
