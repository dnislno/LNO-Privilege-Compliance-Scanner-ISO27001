# Architecture Decision Record (ADR) & System Design Document (SDD)
## LNO Privilege Compliance Scanner

**Versi:** 1.0  
**Author:** dnislno (https://github.com/dnislno)  
**Lisensi:** MIT  
**Disclaimer:** Perangkat lunak ini disediakan "AS IS" tanpa jaminan apapun. Penulis tidak bertanggung jawab atas kerugian atau kerusakan yang timbul dari penggunaan perangkat lunak ini. Pengguna menanggung semua risiko dan tanggung jawab.
**Tanggal:** 2026-06-23  
**Status:** Disetujui  
**Penulis:** AI Orchestrator + Engineering System

---

## Bagian A: Architecture Decision Record

### ADR-009: Security Headers & CORS Restriction

| Field | Value |
|-------|-------|
| **Keputusan** | Menambahkan security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`) dan membatasi CORS dari `*` ke `http://localhost:9090` |
| **Konteks** | Analisis keamanan eksternal menemukan wildcard CORS memungkinkan data exfiltration via situs malicious di browser korban, dan ketiadaan security headers melanggar standar OWASP minimum. |
| **Alasan** | `*` CORS tidak diperlukan karena dashboard hanya diakses dari localhost. Security headers mencegah clickjacking, MIME-type sniffing, dan referrer leakage. |
| **Status** | **Diterima** |

### ADR-010: Input Validation API

| Field | Value |
|-------|-------|
| **Keputusan** | Menambahkan validasi parameter path (`/api/acl`) dan pid (`/api/processes/detail`) dengan whitelist karakter aman |
| **Konteks** | Endpoint API menerima input pengguna tanpa validasi, membuka risiko path traversal dan injection. |
| **Alasan** | Validasi dini mencegah eksploitasi sebelum mencapai query SQL. Parameterized query sudah ada, tapi validasi input adalah defense-in-depth. |
| **Status** | **Diterima** |

### ADR-011: CSV Formula Injection Prevention

| Field | Value |
|-------|-------|
| **Keputusan** | Menambahkan prefix `\t` untuk nilai CSV yang diawali `=`, `+`, `-`, `@`, atau `|` |
| **Konteks** | CSV export dapat mengeksekusi formula Excel jika nilai dimulai dengan karakter tersebut, memungkinkan DDE/WEBSERVICE injection. |
| **Alasan** | Neutralize via `\t` mencegah interpretasi formula tanpa mengubah data. Sesuai OWASP CSV Injection cheatsheet. |
| **Status** | **Diterima** |

### ADR-012: Scheduled Scan Mode

| Field | Value |
|-------|-------|
| **Keputusan** | Menambahkan parameter `--schedule` untuk mode non-interaktif (exit setelah selesai) |
| **Konteks** | Tool hanya berjalan on-demand; untuk monitoring periodik perlu integrasi Windows Task Scheduler. |
| **Alasan** | Parameter `--schedule` memberikan exit code dan timestamp logging yang compatible dengan Task Scheduler. Tidak perlu Windows Service — tetap ringan. |
| **Status** | **Diterima** |

### ADR-013: Integration Test Suite

| Field | Value |
|-------|-------|
| **Keputusan** | Satu file `test.js` dengan 141 test case untuk integration testing |
| **Konteks** | Tidak ada test sama sekali; setiap perubahan berisiko regression tanpa automated guard. |
| **Alasan** | Integration test lebih bernilai dari unit test untuk tool dengan sedikit modul. Cakupan: semua endpoint, security headers, input validation, CSV format, static files. |
| **Status** | **Diterima** |

### ADR-014: CI/CD Pipeline (GitHub Actions)

| Field | Value |
|-------|-------|
| **Keputusan** | GitHub Actions workflow: lint di Ubuntu + scan & test di Windows |
| **Konteks** | Tidak ada automated quality gate; maturity tool rendah dari perspektif komunitas. |
| **Alasan** | Zero-cost CI yang memberikan visibility ke komunitas. Windows runner menjamin test berjalan di OS target sebenarnya. |
| **Status** | **Diterima** |

### ADR-001: Runtime Platform — Node.js

| Field | Value |
|-------|-------|
| **Keputusan** | Menggunakan Node.js v24 sebagai runtime utama untuk scanner + web server |
| **Konteks** | Tidak ada C++ compiler (MinGW, MSVC, atau Go) yang tersedia di mesin target Windows 11. Python terinstal tapi tanpa psutil. Hanya Node.js v24 + npm yang terkonfirmasi tersedia. |
| **Alasan** | Node.js menyediakan `child_process` native untuk spawning PowerShell, `http` untuk serving, dan `require('sql.js')` untuk SQLite — semuanya tanpa kompilasi native. Menghilangkan dependensi pada compiler toolchain yang tidak ada di target. |
| **Trade-off** | Performa: scanner Node.js menggunakan blocking `execSync` yang membuat proses scan serial. Tidak optimal untuk kecepatan tapi acceptable (scan selesai dalam ~90 detik). |
| **Status** | **Diterima** |

### ADR-002: Data Storage — sql.js (Pure JavaScript SQLite)

| Field | Value |
|-------|-------|
| **Keputusan** | Menggunakan `sql.js` (Emscripten-compiled SQLite) sebagai pengganti `better-sqlite3` atau `sqlite3` |
| **Konteks** | Native SQLite bindings (`better-sqlite3`) membutuhkan kompilasi C++ via `node-gyp`, yang membutuhkan compiler toolchain (MSVC, build-essential) yang tidak ada di target. |
| **Alasan** | `sql.js` adalah pure JavaScript WebAssembly build dari SQLite. Zero native dependencies. Instalasi via `npm install sql.js` tanpa langkah kompilasi. Trade-off: seluruh DB harus di-load ke memory untuk setiap siklus baca/tulis (tidak cocok untuk database >100MB). DB scan saat ini <5MB, masih dalam batas wajar. |
| **Status** | **Diterima** |

### ADR-003: Scanner Data Source — WMI via PowerShell

| Field | Value |
|-------|-------|
| **Keputusan** | Menggunakan `Get-CimInstance Win32_Process` via spawned PowerShell scripts untuk enumerasi proses |
| **Konteks** | Node.js OS APIs langsung (`process.binding`, `fs.readdir` on `/proc`) tidak bisa enumerasi detail proses lengkap (owner, command line, handles) di Windows. Package `ps-list` npm bekerja tapi hanya menyediakan PID/name/memory. |
| **Alasan** | WMI via PowerShell menyediakan: PID, name, owner (domain+user), executable path, command line, parent PID, thread/handle count, CPU time, memory, session ID, read/write operations. Ini adalah sumber data terkaya yang tersedia tanpa hak admin. |
| **Trade-off** | WMI mengembalikan `ExecutablePath` kosong untuk SYSTEM processes (PID 4, smss.exe, csrss.exe) tanpa elevasi admin. Mitigasi: hardcoded `KNOWN_PATHS` lookup untuk SYSTEM binaries yang dikenal. |
| **Status** | **Diterima** |

### ADR-004: Temp PS1 Files untuk Eksekusi PowerShell

| Field | Value |
|-------|-------|
| **Keputusan** | Menulis temporary `.ps1` files ke disk, eksekusi via `powershell -File`, lalu hapus |
| **Konteks** | Inline PowerShell commands via `-Command` membutuhkan escaping yang rumit untuk quotes, `$`, backticks, dan newlines. Complex multi-line scripts dengan embedded JSON rawan error. |
| **Alasan** | Menulis file `.ps1` mengeliminasi masalah escaping sepenuhnya. File adalah verbatim PowerShell script. Eksekusi via `-File` lebih reliable. File ditulis ke project directory dan dihapus di `finally` block. |
| **Security Note** | Temp `.ps1` files adalah **privilege escalation risk** jika attacker mendapatkan akses tulis ke project directory. Mitigasi: (1) file langsung dihapus setelah eksekusi, (2) nama file menggunakan `Date.now() + Math.random()` untuk unpredictability, (3) scanner hanya boleh dijalankan oleh trusted users. |
| **Status** | **Diterima** |

### ADR-005: Port 9090 (Resolusi Konflik)

| Field | Value |
|-------|-------|
| **Keputusan** | Melayani dashboard di port 9090 |
| **Konteks** | Port 8080 sudah digunakan oleh local LLM server (llama-server.exe). Deployment awal menggunakan 8080 dan gagal. |
| **Alasan** | 9090 tidak mungkin bentrok dengan service umum (80, 443, 3000, 5000, 8000, 8080). Didokumentasikan secara eksternal. |
| **Status** | **Diterima** |

### ADR-006: Flat File Structure (Tanpa Subdirektori)

| Field | Value |
|-------|-------|
| **Keputusan** | Semua source file di root direktori proyek |
| **Konteks** | Orchestrator secara eksplisit meminta "all files must be flat in project directory, no subfolders" untuk kesederhanaan. |
| **Alasan** | Meminimalkan kompleksitas path. Single `require('./scanner.js')` bekerja tanpa relative path traversal. Cocok untuk tool fokus dengan 3 source file. |
| **Trade-off** | Tidak scalable untuk proyek besar. Acceptable untuk scope saat ini. |
| **Status** | **Diterima** |

### ADR-007: Dashboard — Static HTML + Tailwind CDN (Tanpa Build)

| Field | Value |
|-------|-------|
| **Keputusan** | Single `index.html` dengan Tailwind CSS dari CDN |
| **Konteks** | Node.js `http` module melayani static files. Tidak ada React, bundler, atau build step yang tersedia atau diinginkan. |
| **Alasan** | Zero build step. Client-side rendering via `fetch()` + DOM manipulation. Tailwind CDN memberikan responsive design tanpa `npm install`. Tab-based navigation dengan JS event delegation. |
| **Trade-off** | Dependency CDN membutuhkan internet untuk load pertama. Semua 12 API call bersifat sequential waterfall per tab. Bukan SPA-grade tapi fungsional lengkap. |
| **Status** | **Diterima** |

### ADR-008: Compliance Mapping ke ISO 27001 (Bukan NIST/PCI-DSS)

| Field | Value |
|-------|-------|
| **Keputusan** | Memetakan security findings ke kontrol ISO/IEC 27001:2022 |
| **Konteks** | Pengguna (orchestrator) adalah ISO 27001/42001 Lead Auditor dengan 4 tahun pengalaman compliance. ISO 27001 adalah framework operasional mereka. |
| **Alasan** | Menyesuaikan output compliance dengan domain expertise pengguna meningkatkan nilai praktis tool. Framework alternatif (NIST CSF, PCI-DSS, CIS) tidak relevan dengan workflow pengguna. |
| **Status** | **Diterima** |

### ADR-015: In-Memory Database with Auto-Cleanup

| Field | Value |
|-------|-------|
| **Keputusan** | DB di-load ke RAM saat server start, file `scan.db` dihapus dari disk. Setelah setiap scan, DB di-reload dan file dihapus lagi. |
| **Konteks** | Audit eksternal (#4) menemukan bahwa `scan.db` menyimpan metadata sistem sensitif (user, ACL, privilege) dalam bentuk unencrypted SQLite di disk selama server menyala. Siapapun dengan akses ke direktori proyek bisa membaca file ini. |
| **Alasan** | Data sensitif hanya perlu ada di disk selama proses scan (~100ms). Setelah di-load ke memory, file tidak diperlukan lagi — menghapusnya menghilangkan risiko persistent storage. sql.js sudah beroperasi dari memory buffer (`new SQL.Database(buf)`), jadi perubahan ini natural. |
| **Trade-off** | (1) Memory: ~1-5MB tambahan untuk hold DB di RAM — tidak signifikan. (2) Server restart kehilangan data — sesuai dengan desain tool sebagai session-based scanner, bukan persistent server. (3) Tidak bisa akses DB dari tool eksternal selama server hidup — ini adalah fitur keamanan, bukan kerugian. |
| **Status** | **Diterima** |

---

## Bagian B: System Design Document

### 1. Ringkasan Sistem

LNO Privilege Compliance Scanner adalah alat penilaian postur keamanan Windows dengan dua komponen:

```
┌──────────────────────────────────────────────────────────────┐
│             LNO Privilege Compliance Scanner                   │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────┐ │
│  │   Scanner     │───>│  SQLite DB (RAM) │<───│   Server     │ │
│  │  (scanner.js) │    │  in-memory       │    │  (server.js) │ │
│  └──────┬───────┘    │  scan.db deleted  │    └──────┬───────┘ │
│         │            └──────────────────┘           │          │
│         │ PowerShell                                 │ HTTP GET │
│         ▼                                           ▼          │
│  ┌──────────────┐                     ┌──────────────────┐     │
│  │  WMI / WMI   │                     │   Web Dashboard  │     │
│  │  netstat /   │                     │  (index.html)    │     │
│  │  secedit /   │                     │  localhost:9090  │     │
│  │  Get-Acl     │                     └──────────────────┘     │
│  └──────────────┘                                             │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

### 2. Alur Data

```
Fase 1: SCAN
─────────────
1. Pengguna klik "Refresh" atau menjalankan `node scanner.js`
2. Scanner memanggil PowerShell scripts secara berurutan:
   a. System Info (WMI Win32_ComputerSystem + Win32_OperatingSystem)
   b. User & Groups (WindowsIdentity.GetCurrent() + Get-LocalUser)
   c. Privileges (whoami /priv)
   d. Security Policy (secedit /export)
   e. Process Risk (WMI Win32_Process + Get-AuthenticodeSignature)
   f. Network Connections (netstat -ano)
   g. Services (WMI Win32_Service)
   h. File ACL (Get-Acl pada 14 path sensitif)
   i. Defender Status (Get-MpComputerStatus)
   j. Firewall Status (Get-NetFirewallProfile)
   k. UAC / LSA Status (pembacaan registry)
3. Findings engine menganalisis data yang terkumpul:
   - User di Administrators → critical finding
   - Weak password policy → high finding
   - Unsigned process dari user path → medium finding
   - Setiap finding: type, severity, category, ISO control, title, detail, remediation
4. Semua data + findings ditulis ke SQLite (scan.db)
5. Latest scan ID dilacak untuk dashboard

Fase 2: SERVE
──────────────
1. HTTP server mendengarkan di port 9090 (127.0.0.1 only)
2. Saat start, server membaca scan.db ke memory, lalu menghapus file dari disk
3. REST API membaca dari in-memory SQLite (RAM), bukan dari file disk
4. API mengembalikan JSON dari scan terakhir yang selesai
5. Dashboard (index.html) memanggil API saat page load
6. Refresh POST → memicu scan baru → DB di-reload dari disk ke memory → file dihapus kembali

Fase 3: RENDER
───────────────
1. Dashboard menampilkan: Risk Score + Severity Counts (7 kartu statistik)
2. Tab bar dengan 7 panel: Findings, User & Access, Compliance (93 Annex A controls), Process Risk, Services, Access Control, Risk Config
3. Setiap panel mengambil data dari endpoint API masing-masing dan render via DOM manipulation
4. Tab Findings: dapat difilter berdasarkan severity (critical/high/medium/all)
5. Setiap tabel di tab Process Risk dan Services dapat diurutkan (sortable columns) dengan klik header
6. Kartu statistik dan beberapa area dapat diklik untuk membuka modal detail
7. Tombol CSV Export tersedia untuk Findings, Compliance, dan Processes
```

### 3. Skema Database (SQLite scan.db)

```
scans                  - Metadata scan + risk score + jumlah findings
  ├── id TEXT PK         (UUID)
  ├── started_at         (ISO 8601)
  ├── finished_at
  ├── status             (running / done)
  ├── findings_count
  └── risk_score         (0-100, dihitung)

system_info            - Informasi host (hostname, OS, RAM, dll)
  ├── scan_id REFERENCES scans(id)
  ├── key TEXT
  └── value TEXT

user_account           - Sesi user saat ini
  ├── scan_id
  ├── user_name
  ├── is_admin           (0/1)
  └── auth_type

user_groups            - Keanggotaan grup user saat ini
  ├── scan_id
  ├── sid TEXT           (S-1-5-32-544, dll)
  ├── name TEXT          (Administrators, Users, dll)
  └── is_builtin         (0/1)

user_privileges        - Output whoami /priv
  ├── scan_id
  ├── name TEXT          (SeDebugPrivilege, dll)
  ├── enabled            (0/1)
  ├── risk TEXT          (high/none/info)
  └── risk_note TEXT

local_users            - Semua akun user lokal
  ├── scan_id
  ├── name, full_name, enabled, password_expires
  ├── last_logon, description, sid

local_groups           - Semua grup lokal
  ├── scan_id, name, description, sid

group_members          - Pemetaan keanggotaan grup
  ├── scan_id, group_name, member_name, member_sid, member_type

processes              - Penilaian risiko per proses (satu baris per proses, diurutkan risk_score DESC)
  ├── scan_id
  ├── pid, name, owner
  ├── cpu_usage REAL, memory_mb REAL
  ├── executable_path, command_line
  ├── ppid, thread_count, handle_count
  ├── is_signed (0/1), signer, signature_status
  ├── risk_score INTEGER (0-100)
  ├── risk_reasons TEXT
  ├── has_network (0/1)
  └── parent_app TEXT   (klasifikasi aplikasi induk — Windows System, Third-Party Application, dll)

services               - Service yang berjalan (diperkaya dengan klasifikasi parent_app)
  ├── scan_id, name, display_name, start_mode
  ├── pid, path_name, start_name
  ├── parent_app TEXT   (Windows System, Microsoft Office, Google Chrome, dll — dari classifyService())
  └── description TEXT  (deskripsi fungsional dari SERVICE_DESC lookup)

connections            - Koneksi jaringan TCP/UDP
  ├── scan_id, protocol, local_addr, remote_addr
  ├── state, pid

acl_entries            - ACL filesystem pada path sensitif
  ├── scan_id, path, identity, rights
  ├── access_type, is_inherited

findings               - Temuan keamanan (prioritas)
  ├── scan_id
  ├── type TEXT          (admin_member, def_disabled, dll)
  ├── severity TEXT      (critical/high/medium/low)
  ├── category TEXT      (privilege_management, access_control, dll)
  ├── iso TEXT           (A.8.2, A.8.7, A.5.17, dll — ISO 27001:2022)
  ├── title, detail, remediation

compliance_status      - Kepatuhan terhadap 93 kontrol Annex A ISO 27001:2022
  ├── scan_id, control TEXT   (A.5.1, A.8.7, dll — 93 kontrol)
  ├── title TEXT        (nama kontrol)
  ├── description TEXT  (deskripsi kontrol dari standar)
  ├── theme TEXT        (Organizational / People / Physical / Technological)
  ├── status TEXT       (compliant / non_compliant / not_assessed)
  ├── severity TEXT     (critical/high/medium/none — ditentukan dari findings yang melanggar)
  ├── evidence TEXT     (judul findings yang melanggar atau "Scanner verified")
  └── details TEXT      (detail temuan untuk non-compliant, atau alasan not_assessed)

security_policy        - Konfigurasi password policy, UAC, LSA
  ├── scan_id
  ├── min_password_length, password_history_size
  ├── max_password_age, lockout_threshold, lockout_duration
  ├── enable_lua, consent_prompt, run_as_ppl
```

### 4. REST API Endpoints

```
GET /api/overview               - Metadata scan + jumlah severity + risk score
GET /api/findings               - Semua findings, diurutkan berdasarkan severity
GET /api/findings?severity=X    - Filter berdasarkan severity
GET /api/compliance             - Status 93 kontrol ISO 27001 Annex A (dengan findings per kontrol, security headers: nosniff, DENY, no-referrer)
GET /api/user                   - User saat ini + groups + privileges
GET /api/local-users            - Akun user lokal
GET /api/local-groups           - Grup dengan anggota
GET /api/acl                    - Entri ACL file (opsional ?path=, dengan validasi input)
GET /api/security-policy        - Kebijakan password/lockout/UAC
GET /api/processes              - Semua proses dengan risk scores + parent_app
GET /api/processes/suspicious   - Proses dengan risk_score >= 20
GET /api/processes/detail?pid=X - Detail proses + koneksi
GET /api/services               - Service yang berjalan (dengan parent_app & description)
GET /api/connections            - Koneksi jaringan
GET /api/system-info            - Informasi sistem host
GET /api/scan/latest            - Metadata scan terbaru
GET /api/risk-config            - Konfigurasi risk scoring saat ini (risk-config.json)
GET /api/export/findings        - CSV Export temuan (BOM untuk Excel)
GET /api/export/compliance      - CSV Export compliance (BOM untuk Excel)
GET /api/export/processes       - CSV Export proses (BOM untuk Excel)
POST /api/scan/trigger          - Memicu scan baru
```

### 5. Algoritma Risk Scoring

```
Risk Score (0-100, semakin tinggi semakin aman):

1. Kumpulkan findings, filter suppressed_types
2. Terapkan type_overrides untuk severity (dari risk-config.json)
3. Deduplikasi berdasarkan type (simpan severity tertinggi per type)
4. Bobot per unique severity (dari risk-config.json, default):
   - critical: -25
   - high: -10
   - medium: -4
   - low: -1
   - info: 0
5. Type overrides dapat menggantikan bobot per finding type
6. risk_score = max(min_score, min(max_score, max_score - total_bobot))
   - Default: min=10, max=100
   - Dapat dikonfigurasi via risk-config.json
7. Floor score di min_score (bukan hardcoded 10)

Contoh: 1 critical + 3 high + 2 medium = 25 + 30 + 8 = 63 deduksi → score 37
Custom: override unquoted_service ke weight=1 (default medium=4)
```

### 6. Pertimbangan Keamanan

| Risiko | Mitigasi |
|--------|----------|
| Injeksi file PowerShell temp | Nama file UUID acak, penghapusan langsung, dijalankan oleh trusted user |
| Akses SQLite DB | Hanya lokal, tidak ada eksposur DB ke jaringan |
| XSS via data API | Dashboard menggunakan `.textContent` bukan `.innerHTML` untuk nilai dari pengguna; `innerHTML` hanya untuk template string tepercaya |
| Eksposur port | Server bind ke `localhost` saja, bukan `0.0.0.0` |
| Data exfiltration via CORS | CORS dibatasi ke `http://localhost:9090`, bukan wildcard `*` |
| Clickjacking / MIME sniffing | Security headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` |
| CSV injection | Formula injection (`=`, `+`, `-`, `@`) di-neutralize dengan prefix `\t` |
| Path traversal / PID injection | Validasi input ketat di parameter `path` dan `pid` |
| WMI sniffing | Traffic WMI lokal ke mesin; scanner tidak melakukan panggilan jaringan |

---

### 7. Inventaris File

| File | Lokasi | Ukuran (est) | Tujuan |
|------|--------|-------------|--------|
| `scanner.js` | `./` | ~37 KB | Koleksi data + analisis keamanan + tulis SQLite |
| `server.js` | `./` | ~5 KB | HTTP server + endpoint REST API |
| `index.html` | `./` | ~15 KB | Dashboard web dengan Tailwind CSS |
| `scan.db` | `./` | ~3-5 MB | Database SQLite dibuat saat runtime |
| `package.json` | `./` | <1 KB | Dependency npm: `sql.js` |
| `risk-config.json` | `./` | <1 KB | Konfigurasi risk scoring (weights, overrides, suppression) |
| `logo.svg` | `./` | <1 KB | Logo dashboard (tampilan header) |
| `favicon.svg` | `./` | <1 KB | Icon browser tab |
| `build.bat` | `./` | <1 KB | Script `npm install` untuk kemudahan |
| `run.bat` | `./` | <1 KB | Script `node server.js` untuk kemudahan |

---
### 8. Kesesuaian sebagai Alat Bukti ISO 27001

LNO Privilege Compliance Scanner **layak dijadikan alat bukti implementasi ISO 27001:2022** karena:

1. **Pemetaan 93 Annex A controls** — seluruh kontrol A.5 (Organizational), A.6 (People), A.7 (Physical), A.8 (Technological) tercakup dengan status compliant / non-compliant / not_assessed
2. **Audit trail lengkap** — setiap temuan mencatat: tipe, severity, kategori, ISO control, judul, detail, dan remediasi
3. **Evidence per kontrol** — kolom `evidence` pada compliance_status mencatat temuan spesifik yang melanggar atau konfirmasi "Scanner verified"
4. **Deteksi perubahan** — setiap scan menghasilkan snapshot baru; diff dapat dilakukan secara manual antar scan
5. **CSV Export** — temuan, compliance, dan proses dapat diekspor dalam format CSV (dengan BOM untuk Excel, formula injection terneutralisasi) sebagai bukti audit
6. **Transparansi aturan** — semua aturan dan bobot terdokumentasi di risk-config.json dan FINDING_DEFS (scanner.js)
7. **Security hardening** — CORS terbatas, security headers, input validation, CSV injection prevention
8. **Quality assurance** — 141 integration tests + CI/CD pipeline (GitHub Actions)
9. **Scheduled scanning** — parameter `--schedule` untuk Windows Task Scheduler
10. **Zero trust architecture** — semua pemrosesan lokal, tanpa transmisi data ke pihak ketiga, menjamin integritas bukti

Tool ini dirancang untuk menjawab pertanyaan auditor: *"Bagaimana Anda tahu bahwa endpoint ini aman? Tunjukkan buktinya."* Dengan satu perintah `node scanner.js`, Anda mendapatkan laporan lengkap yang siap audit.

**Disusun oleh:** AI Orchestrator  
**Tanggal review:** 2026-06-23  
**Review berikutnya:** 2026-09-23 atau setelah perubahan fitur material
