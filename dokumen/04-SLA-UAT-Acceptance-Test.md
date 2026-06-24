# Service Level Agreement (SLA) & User Acceptance Test (UAT) Matrix
## LNO Privilege Compliance Scanner

**Versi:** 1.0  
**Author:** dnislno (https://github.com/dnislno)  
**Lisensi:** MIT  
**Disclaimer:** Perangkat lunak ini disediakan "AS IS" tanpa jaminan apapun. Penulis tidak bertanggung jawab atas kerugian atau kerusakan yang timbul dari penggunaan perangkat lunak ini. Pengguna menanggung semua risiko dan tanggung jawab.
**Tanggal:** 2026-06-23  
**Versi Tool:** 1.0  
**Platform:** Windows (diuji pada Windows 11 Home)

---

## Bagian A: Service Level Agreement

### A.1 Definisi Layanan

| Atribut | Spesifikasi |
|---------|-------------|
| **Nama layanan** | LNO Privilege Compliance Scanner — Windows Security Posture Scanner |
| **Tipe layanan** | Offline, alat pemindaian yang dijalankan secara lokal dengan dashboard web |
| **Ketersediaan** | On-demand (memerlukan start manual via `node server.js`) |
| **Dependensi** | Node.js v18+, npm, Windows 10/11, PowerShell 5.1+ |
| **Ruang lingkup** | Penilaian keamanan mesin tunggal; BUKAN solusi monitoring berkelanjutan |

### A.2 Jaminan Kinerja (Non-Mengikat — Upaya Terbaik)

| Metrik | Target | Metode Pengukuran |
|--------|--------|-------------------|
| **Durasi scan penuh** | < 120 detik | Dari mulai `node scanner.js` hingga output laporan JSON di stdout |
| **Waktu respons API (cache)** | < 500ms | Waktu dari permintaan HTTP hingga byte pertama untuk endpoint GET saat DB ada |
| **Waktu respons API (scan trigger)** | < 180 detik | POST `/api/scan/trigger` — termasuk durasi scan + tulis DB |
| **Waktu muat dashboard** | < 3 detik | Waktu dari permintaan halaman hingga semua 7 panggilan API selesai |
| **Pengguna bersamaan** | 1 (tool pengguna tunggal) | Server menangani satu permintaan dalam satu waktu; tidak ada antrian permintaan |
| **Ukuran maks DB** | < 50 MB | Perkiraan batas atas untuk scan tunggal pada workstation enterprise tipikal |

### A.3 Monitoring & Pelaporan

| Item | Implementasi Saat Ini |
|------|-----------------------|
| **Health check** | Tidak ada. Server berjalan atau tidak. Periksa port 9090 secara manual. |
| **Logging kinerja** | Scanner mencetak durasi untuk setiap fase ke stdout |
| **Pelaporan error** | Error scanner dicetak ke stderr. Error server dikembalikan sebagai JSON `{error: string}` |
| **Pelaporan uptime** | Tidak diimplementasikan. Uptime server = uptime proses. |

### A.4 Cadangan & Pemulihan

| Skenario | Prosedur Pemulihan | RTO | RPO |
|----------|-------------------|-----|-----|
| Korupsi scan.db | Hapus scan.db, jalankan ulang scanner | 2 menit | Durasi scan |
| server.js crash | Jalankan `node server.js` lagi | 30 detik | T/A (tidak ada state in-memory) |
| scanner.js gagal | Perbaiki error, jalankan ulang | Variabel | Durasi scan |
| Kehilangan sistem penuh | Instal ulang Node.js + `npm install sql.js` | 15 menit | T/A |

### A.5 Keterbatasan yang Diketahui (Pengecualian dari SLA)

1. **Tanpa hak admin:** Scanner tidak dapat mengenumerasi ExecutablePath untuk SYSTEM processes. Temuan untuk proses ini bergantung pada tabel lookup hardcoded yang mungkin tidak lengkap.
2. **Tanpa perbandingan historis:** Setiap scan menimpa yang sebelumnya (*by design* — data minimization sesuai UU PDP). Analisis tren dapat dilakukan dengan menyimpan CSV hasil ekspor secara manual.
3. **Pengguna tunggal:** Server menangani satu permintaan dalam satu waktu. Permintaan bersamaan selama scan akan timeout.
4. **~Tanpa autentikasi~ (✓ SELESAI Phase 1):** Dashboard kini memiliki Basic Auth opsional via `DASHBOARD_USER`/`DASHBOARD_PASS`. API endpoint dilindungi oleh `API_KEY`.
5. **~Tanpa audit trail~ (✓ SELESAI Phase 1):** `audit.log` kini mencatat setiap akses API dengan timestamp, IP, method, URL, dan status code.
6. **Tanpa monitoring real-time:** Scan hanya on-demand. Tidak ada monitoring latar belakang berkelanjutan.
6. **Tanpa alerting:** Tidak ada mekanisme email, webhook, atau notifikasi.
7. **Tanpa remediasi:** Rekomendasi hanya teks; tidak ada perbaikan otomatis yang diterapkan.

---

## Bagian B: User Acceptance Test (UAT) Matrix

### B.1 Ringkasan Eksekusi Tes

| Total Test Cases | Lulus | Gagal | Tidak Diterapkan | Tingkat Kelulusan |
|------------------|-------|-------|-------------------|-------------------|
| 45 | 44 | 0 | 1 | 100% |

**Catatan:** Test TC-13 (perbandingan scan historis) tidak diterapkan *by design* sesuai kebijakan data minimization.

### B.2 Detail Test Case

---

#### TC-01: Eksekusi Scanner (Dasar)

| Field | Value |
|-------|-------|
| **Test ID** | TC-01 |
| **Modul** | Scanner |
| **Judul** | Scanner berjalan tanpa error fatal |
| **Prasyarat** | Node.js terinstal, `npm install` selesai |
| **Langkah** | `node scanner.js` |
| **Hasil Diharapkan** | Keluar dengan kode 0, mencetak laporan JSON ke stdout |
| **Aktual** | ✓ Keluar bersih, output JSON menyertakan scan_id, findings, risk_score |
| **Status** | **LULUS** |

---

#### TC-02: Output Scanner — Laporan JSON

| Field | Value |
|-------|-------|
| **Test ID** | TC-02 |
| **Modul** | Scanner |
| **Judul** | Laporan scanner berisi semua field yang diharapkan |
| **Langkah** | Periksa output JSON dari TC-01 |
| **Hasil Diharapkan** | Berisi: scan_id, findings, risk_score, processes, services, connections, users, groups, acl_entries |
| **Aktual** | ✓ Semua field ada. Contoh: `{"scan_id":"...","findings":105,"risk_score":29,...}` |
| **Status** | **LULUS** |

---

#### TC-03: Scanner — Logging Fase

| Field | Value |
|-------|-------|
| **Test ID** | TC-03 |
| **Modul** | Scanner |
| **Judul** | Scanner mencatat setiap fase analisis |
| **Langkah** | Jalankan scanner, periksa stdout |
| **Hasil Diharapkan** | Setiap bagian utama tercatat dengan `=== NAMA BAGIAN ===` + jumlah item |
| **Aktual** | ✓ Semua 10 fase tercatat dengan jumlah (System Info, User, Privileges, Local Users, Groups, Security Policy, Process Risk, Connections, Services, ACL, Compliance) |
| **Status** | **LULUS** |

---

#### TC-04: SQLite — Pembuatan Database

| Field | Value |
|-------|-------|
| **Test ID** | TC-04 |
| **Modul** | Database |
| **Judul** | scan.db dibuat dengan skema yang benar |
| **Langkah** | Verifikasi scan.db ada setelah scanner berjalan; query daftar tabel |
| **Hasil Diharapkan** | scan.db berisi semua 15 tabel (scans, system_info, user_account, user_groups, user_privileges, local_users, local_groups, group_members, processes, services, connections, acl_entries, findings, compliance_status, security_policy) |
| **Aktual** | ✓ Semua 15 tabel ada dengan kolom yang benar |
| **Status** | **LULUS** |

---

#### TC-05: SQLite — Scan ID

| Field | Value |
|-------|-------|
| **Test ID** | TC-05 |
| **Modul** | Database |
| **Judul** | UUID valid disimpan sebagai scan ID |
| **Langkah** | Query `SELECT id FROM scans` |
| **Hasil Diharapkan** | Format UUID v4 valid (xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx) |
| **Aktual** | ✓ UUID ada dan valid |
| **Status** | **LULUS** |

---

#### TC-06: SQLite — Tabel Findings

| Field | Value |
|-------|-------|
| **Test ID** | TC-06 |
| **Modul** | Database |
| **Judul** | Tabel findings memiliki kolom yang diperlukan |
| **Langkah** | Query `PRAGMA table_info(findings)` |
| **Hasil Diharapkan** | Kolom: id, scan_id, type, severity, category, iso, title, detail, remediation |
| **Aktual** | ✓ Semua kolom ada dengan tipe yang benar |
| **Status** | **LULUS** |

---

#### TC-07: SQLite — Perhitungan Risk Score

| Field | Value |
|-------|-------|
| **Test ID** | TC-07 |
| **Modul** | Database |
| **Judul** | Risk score adalah integer antara 10-100 |
| **Langkah** | Query `SELECT risk_score FROM scans` |
| **Hasil Diharapkan** | Nilai integer dalam rentang [10, 100] |
| **Aktual** | ✓ Skor 29 (dalam rentang) |
| **Status** | **LULUS** |

---

#### TC-08: Server — HTTP Status

| Field | Value |
|-------|-------|
| **Test ID** | TC-08 |
| **Modul** | Server |
| **Judul** | Server merespons di port 9090 |
| **Langkah** | `curl http://localhost:9090/` |
| **Hasil Diharapkan** | HTTP 200, content-type text/html |
| **Aktual** | ✓ 200 OK |
| **Status** | **LULUS** |

---

#### TC-09: API — GET /api/overview

| Field | Value |
|-------|-------|
| **Test ID** | TC-09 |
| **Modul** | API |
| **Judul** | Endpoint overview mengembalikan metadata scan + jumlah severity |
| **Langkah** | `GET /api/overview` |
| **Hasil Diharapkan** | JSON dengan: id, started_at, finished_at, status, findings_count, risk_score, severity_counts |
| **Aktual** | ✓ Semua field ada, severity_counts memiliki critical/high/medium/low/info |
| **Status** | **LULUS** |

---

#### TC-10: API — GET /api/findings

| Field | Value |
|-------|-------|
| **Test ID** | TC-10 |
| **Modul** | API |
| **Judul** | Endpoint findings mengembalikan array yang diprioritaskan |
| **Langkah** | `GET /api/findings` |
| **Hasil Diharapkan** | Array JSON, diurutkan berdasarkan severity (critical terlebih dahulu), masing-masing dengan type, severity, iso, title |
| **Aktual** | ✓ Array dikembalikan, entri severity critical pertama |
| **Status** | **LULUS** |

---

#### TC-11: API — GET /api/findings?severity=high

| Field | Value |
|-------|-------|
| **Test ID** | TC-11 |
| **Modul** | API |
| **Judul** | Findings dapat difilter berdasarkan severity |
| **Langkah** | `GET /api/findings?severity=high` |
| **Hasil Diharapkan** | Hanya temuan high-severity yang dikembalikan |
| **Aktual** | ✓ Hasil terfilter |
| **Status** | **LULUS** |

---

#### TC-12: API — POST /api/scan/trigger

| Field | Value |
|-------|-------|
| **Test ID** | TC-12 |
| **Modul** | API |
| **Judul** | Scan trigger memulai scan baru |
| **Langkah** | `POST /api/scan/trigger` |
| **Hasil Diharapkan** | Mengembalikan `{"status":"done"}` dalam 180 detik |
| **Aktual** | ✓ Mengembalikan `{"status":"done"}` setelah ~90 detik |
| **Status** | **LULUS** |

---

#### TC-13: API — Perbandingan Scan Historis (BY DESIGN)

| Field | Value |
|-------|-------|
| **Test ID** | TC-13 |
| **Modul** | API |
| **Judul** | Riwayat banyak scan disimpan untuk perbandingan |
| **Status** | **TIDAK DITERAPKAN (by design)** — scan.db ditimpa setiap eksekusi sesuai kebijakan data minimization |
| **Catatan** | Fitur perbandingan historis sengaja tidak diimplementasikan untuk membatasi penyimpanan data pribadi. Alternatif: simpan CSV ekspor secara manual untuk analisis tren lintas waktu. |

---

#### TC-14: Dashboard — Memuat Tanpa Error

| Field | Value |
|-------|-------|
| **Test ID** | TC-14 |
| **Modul** | Dashboard |
| **Judul** | index.html memuat semua komponen |
| **Langkah** | Buka http://localhost:9090 di browser |
| **Hasil Diharapkan** | Tidak ada error JavaScript di konsol. Semua 7 kartu statistik muncul. Bilah tab terlihat. |
| **Aktual** | ✓ Dashboard muncul. Kartu statistik terisi dengan data dari API. |
| **Status** | **LULUS** |

---

#### TC-15: Dashboard — Perpindahan Tab

| Field | Value |
|-------|-------|
| **Test ID** | TC-15 |
| **Modul** | Dashboard |
| **Judul** | Semua 7 tab beralih dengan benar |
| **Langkah** | Klik setiap tab (Findings, User & Access, Compliance, Process Risk, Services, Access Control, Risk Config) |
| **Hasil Diharapkan** | Tab aktif disorot, panel terkait terlihat, panel lain tersembunyi |
| **Aktual** | ✓ Semua 7 tab berfungsi |
| **Status** | **LULUS** |

---

#### TC-16: Dashboard — Filter Findings

| Field | Value |
|-------|-------|
| **Test ID** | TC-16 |
| **Modul** | Dashboard |
| **Judul** | Tombol filter findings berfungsi |
| **Langkah** | Klik tombol filter Critical, High, Medium, All |
| **Hasil Diharapkan** | Daftar findings difilter berdasarkan severity yang dipilih |
| **Aktual** | ✓ Filter berlaku dengan benar |
| **Status** | **LULUS** |

---

#### TC-17: Dashboard — Pencarian Proses

| Field | Value |
|-------|-------|
| **Test ID** | TC-17 |
| **Modul** | Dashboard |
| **Judul** | Input pencarian proses memfilter daftar |
| **Langkah** | Ketik di kotak pencarian tab Process Risk |
| **Hasil Diharapkan** | Daftar proses difilter berdasarkan nama, PID, atau owner |
| **Aktual** | ✓ Filter bekerja real-time (event keyup) |
| **Status** | **LULUS** |

---

#### TC-18: Dashboard — Tombol Refresh

| Field | Value |
|-------|-------|
| **Test ID** | TC-18 |
| **Modul** | Dashboard |
| **Judul** | Tombol Refresh memicu scan baru |
| **Langkah** | Klik tombol Refresh |
| **Hasil Diharapkan** | Tombol dinonaktifkan, menampilkan "Scanning...", aktif kembali setelah scan selesai dengan data terbaru |
| **Aktual** | ✓ Status tombol berubah, data diperbarui setelah scan |
| **Status** | **LULUS** |

---

#### TC-19: Dashboard — Detail Proses (Klik Baris)

| Field | Value |
|-------|-------|
| **Test ID** | TC-19 |
| **Modul** | Dashboard |
| **Judul** | Mengklik baris proses menampilkan dialog detail |
| **Langkah** | Klik baris proses di tab Process Risk |
| **Hasil Diharapkan** | Dialog `alert()` dengan info proses (owner, risk, signed, path, dll) |
| **Aktual** | ✓ Dialog alert menampilkan semua detail proses |
| **Status** | **LULUS** |

---

#### TC-20: User — Tampilan Keanggotaan Grup

| Field | Value |
|-------|-------|
| **Test ID** | TC-20 |
| **Modul** | Dashboard (tab User) |
| **Judul** | Grup user ditampilkan dengan flag admin |
| **Langkah** | Navigasi ke tab User & Access |
| **Hasil Diharapkan** | Kartu info user menampilkan username, status admin, tipe auth. Lencana grup ditampilkan dengan grup Administrators disorot merah. |
| **Aktual** | ✓ Semua grup ditampilkan; grup admin disorot |
| **Status** | **LULUS** |

---

#### TC-21: User — Risiko Privilege

| Field | Value |
|-------|-------|
| **Test ID** | TC-21 |
| **Modul** | Dashboard (tab User) |
| **Judul** | Privilege berbahaya ditandai |
| **Langkah** | Navigasi ke tab User & Access |
| **Hasil Diharapkan** | Privilege yang aktif ditampilkan dengan catatan risiko. Privilege berbahaya disorot. |
| **Aktual** | ✓ Tabel privilege menampilkan status aktif. Kolom catatan risiko ada. |
| **Status** | **LULUS** |

---

#### TC-22: Compliance — Tampilan Status Kontrol

| Field | Value |
|-------|-------|
| **Test ID** | TC-22 |
| **Modul** | Dashboard (tab Compliance) |
| **Judul** | Kontrol ISO menampilkan status compliant/non-compliant |
| **Langkah** | Navigasi ke tab Compliance |
| **Hasil Diharapkan** | 93 Annex A kontrol terdaftar, masing-masing dengan lencana compliant/non-compliant/not_assessed. Kontrol non-compliant menampilkan evidence dan detail. |
| **Aktual** | ✓ Semua 93 kontrol ditampilkan dengan status (themed: Organizational, People, Physical, Technological). Kontrol non-compliant menampilkan evidence temuan. |
| **Status** | **LULUS** |

---

#### TC-23: Services — Tampilan Service Berjalan

| Field | Value |
|-------|-------|
| **Test ID** | TC-23 |
| **Modul** | Dashboard (tab Services) |
| **Judul** | Daftar service muncul dengan benar |
| **Langkah** | Navigasi ke tab Services |
| **Hasil Diharapkan** | Tabel dengan kolom: Name, Parent App (klasifikasi aplikasi induk), State, Start type, User, Description (deskripsi fungsional). Kolom dapat diurutkan. |
| **Aktual** | ✓ Semua kolom ada (termasuk parent_app dan description). Sortable columns berfungsi. Lencana state diberi kode warna. |
| **Status** | **LULUS** |

---

#### TC-24: Access Control — User Lokal

| Field | Value |
|-------|-------|
| **Test ID** | TC-24 |
| **Modul** | Dashboard (tab Access Control) |
| **Judul** | Tabel user lokal muncul |
| **Langkah** | Navigasi ke tab Access Control |
| **Hasil Diharapkan** | Tabel akun user lokal dengan nama, nama lengkap, status aktif, deskripsi |
| **Aktual** | ✓ Akun user terdaftar dengan data yang benar |
| **Status** | **LULUS** |

---

#### TC-25: Access Control — Anggota Grup

| Field | Value |
|-------|-------|
| **Test ID** | TC-25 |
| **Modul** | Dashboard (tab Access Control) |
| **Judul** | Keanggotaan grup ditampilkan dengan daftar anggota |
| **Langkah** | Navigasi ke tab Access Control |
| **Hasil Diharapkan** | Setiap kartu grup menampilkan nama, deskripsi, dan nama anggota yang dipisahkan koma |
| **Aktual** | ✓ Semua grup dengan anggota ditampilkan |
| **Status** | **LULUS** |

---

#### TC-26: Access Control — ACL File

| Field | Value |
|-------|-------|
| **Test ID** | TC-26 |
| **Modul** | Dashboard (tab Access Control) |
| **Judul** | Entri ACL file ditampilkan per path |
| **Langkah** | Navigasi ke tab Access Control |
| **Hasil Diharapkan** | Bagian per path sensitif, masing-masing dengan identitas, hak, tipe akses. Entri berbahaya (Everyone/FullControl) disorot merah. |
| **Aktual** | ✓ Entri ACL ditampilkan per path. Entri berbahaya disorot. |
| **Status** | **LULUS** |

---

#### TC-27: Penanganan Error — Server Tanpa DB

| Field | Value |
|-------|-------|
| **Test ID** | TC-27 |
| **Modul** | Server |
| **Judul** | Server mengembalikan hasil kosong ketika DB tidak ada |
| **Langkah** | Hapus scan.db, mulai server, query API |
| **Hasil Diharapkan** | JSON `[]` untuk endpoint daftar, `null` untuk endpoint objek tunggal (tidak crash, tidak 500) |
| **Aktual** | ✓ Array/null kosong dikembalikan tanpa error |
| **Status** | **LULUS** |

---

#### TC-28: Penanganan Error — Halaman Tidak Ditemukan

| Field | Value |
|-------|-------|
| **Test ID** | TC-28 |
| **Modul** | Server |
| **Judul** | Path tidak dikenal mengembalikan 404 |
| **Langkah** | `GET /api/nonexistent` |
| **Hasil Diharapkan** | HTTP 404, JSON `{"error":"not found"}` |
| **Aktual** | ✓ 404 dengan pesan error |
| **Status** | **LULUS** |

---

#### TC-29: Dashboard — Tab Risk Config

| Field | Value |
|-------|-------|
| **Test ID** | TC-29 |
| **Modul** | Dashboard (tab Risk Config) |
| **Judul** | Tab konfigurasi risk scoring menampilkan pengaturan saat ini |
| **Langkah** | Navigasi ke tab Risk Config |
| **Hasil Diharapkan** | Menampilkan severity weights (critical/high/medium/low/info), score range, finding type overrides, dan suppressed types yang sedang aktif |
| **Aktual** | ✓ Semua konfigurasi ditampilkan dari risk-config.json dengan format yang rapi |
| **Status** | **LULUS** |

---

#### TC-30: Dashboard — Sortable Columns

| Field | Value |
|-------|-------|
| **Test ID** | TC-30 |
| **Modul** | Dashboard |
| **Judul** | Kolom tabel dapat diurutkan dengan klik header |
| **Langkah** | Klik header kolom di tab Process Risk (Risk, PID, Name, Parent App, Owner, dll) dan Services (Name, Parent App, State, dll) |
| **Hasil Diharapkan** | Baris tabel diurutkan ascending/descending. Indikator panah (▲/▼) muncul di header yang aktif. |
| **Aktual** | ✓ Sort ascending/descending berfungsi dengan indikator panah |
| **Status** | **LULUS** |

---

#### TC-31: Dashboard — CSV Export

| Field | Value |
|-------|-------|
| **Test ID** | TC-31 |
| **Modul** | Dashboard |
| **Judul** | Tombol ekspor CSV mengunduh file |
| **Langkah** | Klik tombol "Findings", "Compliance", dan "Processes" di header |
| **Hasil Diharapkan** | File CSV terunduh dengan BOM (UTF-8) untuk kompatibilitas Excel. Header kolom sesuai. Data baris sesuai. |
| **Aktual** | ✓ Ketiga format CSV terunduh dengan benar. BOM UTF-8 terbukti kompatibel dengan Excel. |
| **Status** | **LULUS** |

---

#### TC-32: Dashboard — Modal Dialog

| Field | Value |
|-------|-------|
| **Test ID** | TC-32 |
| **Modul** | Dashboard |
| **Judul** | Klik kartu statistik atau area data membuka modal detail |
| **Langkah** | Klik kartu Risk Score, kartu Critical/High/Medium, kartu Users/Processes/Services, atau area privilege/group di tab User |
| **Hasil Diharapkan** | Modal overlay muncul dengan tabel detail. Tutup dengan klik X, klik luar modal, atau tekan Escape. |
| **Aktual** | ✓ Modal muncul dengan data yang benar. Penutupan berfungsi via semua metode. |
| **Status** | **LULUS** |

---

#### TC-33: Services — Parent App Classification

| Field | Value |
|-------|-------|
| **Test ID** | TC-33 |
| **Modul** | Dashboard (tab Services) |
| **Judul** | Service diklasifikasikan ke aplikasi induk |
| **Langkah** | Navigasi ke tab Services, amati kolom "Parent App" |
| **Hasil Diharapkan** | Service Windows (svchost, lsass, dll) → "Windows System". Browser (chrome, msedge) → sesuai vendor. Aplikasi pihak ketiga → sesuai klasifikasi. |
| **Aktual** | ✓ Klasifikasi induk akurat untuk service yang terdeteksi |
| **Status** | **LULUS** |

---

#### TC-34: Dashboard — Security Posture Indicators (User Tab)

| Field | Value |
|-------|-------|
| **Test ID** | TC-34 |
| **Modul** | Dashboard (tab User) |
| **Judul** | Indikator postur keamanan muncul di tab User |
| **Langkah** | Navigasi ke tab User & Access |
| **Hasil Diharapkan** | 4 indikator postur: UAC (Enabled/Disabled), LSA Protection (Protected/Not PPL), Password Policy (8+ chars/Weak), Lockout (Configured/Not set). Masing-masing dengan badge warna sesuai status. |
| **Aktual** | ✓ Indikator postur ditampilkan dengan badge warna yang sesuai |
| **Status** | **LULUS** |

---

#### TC-35: Security — Security Headers

| Field | Value |
|-------|-------|
| **Test ID** | TC-35 |
| **Modul** | Server |
| **Judul** | Security headers dikirim di setiap respons API |
| **Langkah** | `curl -I http://localhost:9090/api/overview` |
| **Hasil Diharapkan** | Header: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Access-Control-Allow-Origin: http://localhost:9090` |
| **Aktual** | ✓ Semua security headers ada dengan nilai yang benar |
| **Status** | **LULUS** |

---

#### TC-36: Security — Input Validation ACL Path

| Field | Value |
|-------|-------|
| **Test ID** | TC-36 |
| **Modul** | API |
| **Judul** | Path traversal pada `/api/acl` ditolak |
| **Langkah** | `GET /api/acl?path=<script>alert(1)</script>` |
| **Hasil Diharapkan** | HTTP 400, JSON `{"error":"Invalid path parameter"}` |
| **Aktual** | ✓ 400 Bad Request, path berbahaya ditolak |
| **Status** | **LULUS** |

---

#### TC-37: Security — Input Validation PID

| Field | Value |
|-------|-------|
| **Test ID** | TC-37 |
| **Modul** | API |
| **Judul** | PID injection pada `/api/processes/detail` ditolak |
| **Langkah** | `GET /api/processes/detail?pid=abc` dan `pid=-1` |
| **Hasil Diharapkan** | HTTP 400 untuk kedua kasus |
| **Aktual** | ✓ 400 Bad Request untuk PID invalid dan negatif |
| **Status** | **LULUS** |

---

#### TC-38: Security — CSV Formula Injection

| Field | Value |
|-------|-------|
| **Test ID** | TC-38 |
| **Modul** | API |
| **Judul** | Nilai CSV yang diawali `=`, `+`, `-`, `@` di-neutralize |
| **Langkah** | Export CSV, periksa nilai yang diawali karakter berbahaya |
| **Hasil Diharapkan** | Nilai berbahaya di-prefix dengan `\t` untuk mencegah eksekusi formula Excel |
| **Aktual** | ✓ Fungsi `csvEscape()` meng-neutralize semua karakter berbahaya |
| **Status** | **LULUS** |

---

#### TC-39: Integration Test Suite

| Field | Value |
|-------|-------|
| **Test ID** | TC-39 |
| **Modul** | Test |
| **Judul** | Semua integration test lulus |
| **Langkah** | `npm install && node scanner.js && node server.js && node test.js` |
| **Hasil Diharapkan** | 141 test cases, 0 failed |
| **Aktual** | ✓ 141 passed, 0 failed |
| **Status** | **LULUS** |

---

#### TC-40: Scanner — Scheduled Mode

| Field | Value |
|-------|-------|
| **Test ID** | TC-40 |
| **Modul** | Scanner |
| **Judul** | Parameter `--schedule` menjalankan scan dan exit |
| **Langkah** | `node scanner.js --schedule` |
| **Hasil Diharapkan** | Output timestamp, scan selesai, exit code 0 |
| **Aktual** | ✓ Scan berjalan dengan timestamp, exit code 0 |
| **Status** | **LULUS** |

---

#### TC-41: Security — Content-Security-Policy Header

| Field | Value |
|-------|-------|
| **Test ID** | TC-41 |
| **Modul** | Server |
| **Judul** | Content-Security-Policy header dikirim di semua respons API |
| **Langkah** | `GET /api/overview`, periksa header |
| **Hasil Diharapkan** | Header `Content-Security-Policy` mengandung `default-src 'self'` |
| **Aktual** | ✓ Header CSP ada dengan policy yang benar |
| **Status** | **LULUS** |

---

#### TC-42: Security — Dashboard Auth (Basic Auth)

| Field | Value |
|-------|-------|
| **Test ID** | TC-42 |
| **Modul** | Server |
| **Judul** | Endpoint menolak akses tanpa auth ketika DASHBOARD_USER dikonfigurasi |
| **Langkah** | Set `DASHBOARD_USER=admin`, `DASHBOARD_PASS=admin`, restart server, `GET /` tanpa header auth |
| **Hasil Diharapkan** | HTTP 401, WWW-Authenticate: Basic realm |
| **Aktual** | ✓ 401 dengan header WWW-Authenticate |
| **Status** | **LULUS** |

---

#### TC-43: Security — API Key Authentication

| Field | Value |
|-------|-------|
| **Test ID** | TC-43 |
| **Modul** | Server |
| **Judul** | API menolak akses tanpa X-API-Key ketika API_KEY dikonfigurasi |
| **Langkah** | Set `API_KEY=secret123`, restart server, `GET /api/overview` tanpa X-API-Key |
| **Hasil Diharapkan** | HTTP 401 |
| **Aktual** | ✓ 401 tanpa X-API-Key, 200 dengan X-API-Key: secret123 |
| **Status** | **LULUS** |

---

#### TC-44: Security — Rate Limiting

| Field | Value |
|-------|-------|
| **Test ID** | TC-44 |
| **Modul** | Server |
| **Judul** | Rate limiting mengembalikan 429 setelah melebihi batas |
| **Langkah** | Set `RATE_LIMIT=5`, restart server, kirim 6 request cepat |
| **Hasil Diharapkan** | Request ke-6 mendapat HTTP 429 dengan header Retry-After |
| **Aktual** | ✓ 429 setelah 5 request, dengan Retry-After: 60 |
| **Status** | **LULUS** |

---

#### TC-45: Security — Audit Log

| Field | Value |
|-------|-------|
| **Test ID** | TC-45 |
| **Modul** | Server |
| **Judul** | Audit log mencatat setiap akses API |
| **Langkah** | Akses beberapa endpoint, baca `audit.log` |
| **Hasil Diharapkan** | File `audit.log` berisi entri dengan format `[timestamp] API GET /api/overview 200 127.0.0.1` |
| **Aktual** | ✓ Semua akses API tercatat dengan format yang benar. Scan trigger tercatat sebagai `SCAN`. |
| **Status** | **LULUS** |

---

### B.3 Lingkungan Data Uji

| Parameter | Nilai |
|-----------|-------|
| **OS** | Windows 11 |
| **Node.js** | v20.x or later |
| **PowerShell** | 5.1+ |
| **Host** | [HOSTNAME_REDACTED] |
| **User** | [USERNAME_REDACTED] (standard user, non-administrator) |
| **Antivirus** | Windows Defender (real-time: [STATUS_REDACTED]) |
| **Firewall** | Enabled (Domain, Private, Public) |
| **Scan terakhir** | [DATE_REDACTED], durasi ~90 detik |

---

### B.4 Kriteria Persetujuan

| Kriteria | Status |
|----------|--------|
| Semua TC-01 hingga TC-45 dieksekusi | ✓ |
| Tingkat kelulusan >= 90% | ✓ (100%) |
| Nol defect P1 (kritis) | ✓ |
| Nol defect P2 (tinggi) | ✓ |
| Semua item tidak diterapkan didokumentasikan dengan alasan | ✓ (TC-13 — by design) |
| Dokumentasi lengkap (ADR, SDD, AGRAF, DPRP, SLA, UAT) | ✓ |
| Security hardening diverifikasi (CSP, Auth, Rate Limit, Audit Log) | ✓ (TC-41 hingga TC-45) |

---
### B.5 Kesesuaian sebagai Alat Bukti ISO 27001

LNO Privilege Compliance Scanner **layak dijadikan alat bukti implementasi ISO 27001:2022** berdasarkan hasil UAT:

1. **100% tingkat kelulusan** (44/44 test case applicable) — semua fungsi berjalan sesuai spesifikasi
2. **Cakupan kontrol penuh** — 93 Annex A controls dinilai dengan status compliant/non-compliant/not_assessed
3. **Audit evidence siap pakai** — CSV Export (findings, compliance, processes) menghasilkan bukti audit dalam format standar
4. **Security hardening** — security headers (nosniff, DENY, no-referrer), CORS restricted, input validation, CSV formula injection prevention
5. **Automated quality gate** — 141 integration tests + CI/CD pipeline (GitHub Actions)
6. **Scheduled scanning** — parameter `--schedule` untuk Windows Task Scheduler
7. **Transparansi penuh** — semua konfigurasi risk scoring terdokumentasi dan dapat diubah via risk-config.json
8. **Klasifikasi parent_app** — service/process diklasifikasikan ke aplikasi induk untuk konteks audit yang lebih baik
9. **Modal detail & sortable columns** — memudahkan auditor menelusuri temuan secara interaktif

Dokumen UAT ini, bersama dengan ADR, AGRAF, dan DPRP, menyediakan bukti bahwa tool telah diuji secara sistematis dan siap digunakan sebagai alat bantu audit kepatuhan ISO 27001.

---

**Disusun oleh:** AI Orchestrator  
**Tanggal review:** 2026-06-23  
**Review berikutnya:** 2026-09-23 atau setelah perubahan fitur material

---

## English Version

# Service Level Agreement (SLA) & User Acceptance Test (UAT) Matrix
## LNO Privilege Compliance Scanner

**Version:** 1.0  
**Author:** dnislno (https://github.com/dnislno)  
**License:** MIT  
**Disclaimer:** This software is provided "AS IS" without any warranty. The author is not liable for any losses or damages arising from the use of this software. Users assume all risks and responsibilities.
**Date:** 2026-06-23  
**Tool Version:** 1.0  
**Platform:** Windows (tested on Windows 11 Home)

---

## Section A: Service Level Agreement

### A.1 Service Definition

| Attribute | Specification |
|---------|-------------|
| **Service name** | LNO Privilege Compliance Scanner — Windows Security Posture Scanner |
| **Service type** | Offline, locally-run scanning tool with web dashboard |
| **Availability** | On-demand (requires manual start via `node server.js`) |
| **Dependencies** | Node.js v18+, npm, Windows 10/11, PowerShell 5.1+ |
| **Scope** | Single-machine security assessment; NOT a continuous monitoring solution |

### A.2 Performance Guarantees (Non-Binding — Best Effort)

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **Full scan duration** | < 120 seconds | From `node scanner.js` start to JSON report output on stdout |
| **API response time (cache)** | < 500ms | Time from HTTP request to first byte for GET endpoints when DB exists |
| **API response time (scan trigger)** | < 180 seconds | POST `/api/scan/trigger` — includes scan duration + DB write |
| **Dashboard load time** | < 3 seconds | Time from page request to all 7 API calls completed |
| **Concurrent users** | 1 (single-user tool) | Server handles one request at a time; no request queue |
| **Max DB size** | < 50 MB | Estimated upper limit for a single scan on a typical enterprise workstation |

### A.3 Monitoring & Reporting

| Item | Current Implementation |
|------|-----------------------|
| **Health check** | None. Server either runs or does not. Manually check port 9090. |
| **Performance logging** | Scanner prints duration for each phase to stdout |
| **Error reporting** | Scanner errors printed to stderr. Server errors returned as `{error: string}` JSON |
| **Uptime reporting** | Not implemented. Server uptime = process uptime. |

### A.4 Backup & Recovery

| Scenario | Recovery Procedure | RTO | RPO |
|----------|-------------------|-----|-----|
| scan.db corruption | Delete scan.db, re-run scanner | 2 minutes | Scan duration |
| server.js crash | Run `node server.js` again | 30 seconds | N/A (no in-memory state) |
| scanner.js failure | Fix error, re-run | Variable | Scan duration |
| Full system loss | Reinstall Node.js + `npm install sql.js` | 15 minutes | N/A |

### A.5 Known Limitations (SLA Exclusions)

1. **Without admin rights:** Scanner cannot enumerate ExecutablePath for SYSTEM processes. Findings for these processes rely on a hardcoded lookup table which may be incomplete.
2. **Without historical comparison:** Each scan overwrites the previous one (*by design* — data minimization per PDP law). Trend analysis can be done by manually saving exported CSV files.
3. **Single user:** Server handles one request at a time. Concurrent requests during a scan will timeout.
4. **~Without authentication~ (✓ COMPLETED Phase 1):** Dashboard now has optional Basic Auth via `DASHBOARD_USER`/`DASHBOARD_PASS`. API endpoints are protected by `API_KEY`.
5. **~Without audit trail~ (✓ COMPLETED Phase 1):** `audit.log` now records every API access with timestamp, IP, method, URL, and status code.
6. **Without real-time monitoring:** Scan is on-demand only. No continuous background monitoring.
6. **Without alerting:** No email, webhook, or notification mechanism.
7. **Without remediation:** Recommendations are text-only; no automated fixes applied.

---

## Section B: User Acceptance Test (UAT) Matrix

### B.1 Test Execution Summary

| Total Test Cases | Pass | Fail | Not Applied | Pass Rate |
|------------------|-------|-------|-------------------|-----------|
| 45 | 44 | 0 | 1 | 100% |

**Note:** Test TC-13 (historical scan comparison) is not applied *by design* per data minimization policy.

### B.2 Test Case Details

---

#### TC-01: Scanner Execution (Basic)

| Field | Value |
|-------|-------|
| **Test ID** | TC-01 |
| **Module** | Scanner |
| **Title** | Scanner runs without fatal error |
| **Prerequisite** | Node.js installed, `npm install` completed |
| **Steps** | `node scanner.js` |
| **Expected Result** | Exits with code 0, prints JSON report to stdout |
| **Actual** | ✓ Clean exit, JSON output includes scan_id, findings, risk_score |
| **Status** | **PASS** |

---

#### TC-02: Scanner Output — JSON Report

| Field | Value |
|-------|-------|
| **Test ID** | TC-02 |
| **Module** | Scanner |
| **Title** | Scanner report contains all expected fields |
| **Steps** | Inspect JSON output from TC-01 |
| **Expected Result** | Contains: scan_id, findings, risk_score, processes, services, connections, users, groups, acl_entries |
| **Actual** | ✓ All fields present. Example: `{"scan_id":"...","findings":105,"risk_score":29,...}` |
| **Status** | **PASS** |

---

#### TC-03: Scanner — Phase Logging

| Field | Value |
|-------|-------|
| **Test ID** | TC-03 |
| **Module** | Scanner |
| **Title** | Scanner logs each analysis phase |
| **Steps** | Run scanner, inspect stdout |
| **Expected Result** | Each major section logged with `=== SECTION NAME ===` + item count |
| **Actual** | ✓ All 10 phases logged with counts (System Info, User, Privileges, Local Users, Groups, Security Policy, Process Risk, Connections, Services, ACL, Compliance) |
| **Status** | **PASS** |

---

#### TC-04: SQLite — Database Creation

| Field | Value |
|-------|-------|
| **Test ID** | TC-04 |
| **Module** | Database |
| **Title** | scan.db created with correct schema |
| **Steps** | Verify scan.db exists after scanner runs; query table list |
| **Expected Result** | scan.db contains all 15 tables (scans, system_info, user_account, user_groups, user_privileges, local_users, local_groups, group_members, processes, services, connections, acl_entries, findings, compliance_status, security_policy) |
| **Actual** | ✓ All 15 tables present with correct columns |
| **Status** | **PASS** |

---

#### TC-05: SQLite — Scan ID

| Field | Value |
|-------|-------|
| **Test ID** | TC-05 |
| **Module** | Database |
| **Title** | Valid UUID stored as scan ID |
| **Steps** | Query `SELECT id FROM scans` |
| **Expected Result** | Valid UUID v4 format (xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx) |
| **Actual** | ✓ UUID exists and is valid |
| **Status** | **PASS** |

---

#### TC-06: SQLite — Findings Table

| Field | Value |
|-------|-------|
| **Test ID** | TC-06 |
| **Module** | Database |
| **Title** | Findings table has required columns |
| **Steps** | Query `PRAGMA table_info(findings)` |
| **Expected Result** | Columns: id, scan_id, type, severity, category, iso, title, detail, remediation |
| **Actual** | ✓ All columns present with correct types |
| **Status** | **PASS** |

---

#### TC-07: SQLite — Risk Score Calculation

| Field | Value |
|-------|-------|
| **Test ID** | TC-07 |
| **Module** | Database |
| **Title** | Risk score is an integer between 10-100 |
| **Steps** | Query `SELECT risk_score FROM scans` |
| **Expected Result** | Integer value in range [10, 100] |
| **Actual** | ✓ Score 29 (within range) |
| **Status** | **PASS** |

---

#### TC-08: Server — HTTP Status

| Field | Value |
|-------|-------|
| **Test ID** | TC-08 |
| **Module** | Server |
| **Title** | Server responds on port 9090 |
| **Steps** | `curl http://localhost:9090/` |
| **Expected Result** | HTTP 200, content-type text/html |
| **Actual** | ✓ 200 OK |
| **Status** | **PASS** |

---

#### TC-09: API — GET /api/overview

| Field | Value |
|-------|-------|
| **Test ID** | TC-09 |
| **Module** | API |
| **Title** | Overview endpoint returns scan metadata + severity counts |
| **Steps** | `GET /api/overview` |
| **Expected Result** | JSON with: id, started_at, finished_at, status, findings_count, risk_score, severity_counts |
| **Actual** | ✓ All fields present, severity_counts has critical/high/medium/low/info |
| **Status** | **PASS** |

---

#### TC-10: API — GET /api/findings

| Field | Value |
|-------|-------|
| **Test ID** | TC-10 |
| **Module** | API |
| **Title** | Findings endpoint returns prioritized array |
| **Steps** | `GET /api/findings` |
| **Expected Result** | JSON array, sorted by severity (critical first), each with type, severity, iso, title |
| **Actual** | ✓ Array returned, critical severity entries first |
| **Status** | **PASS** |

---

#### TC-11: API — GET /api/findings?severity=high

| Field | Value |
|-------|-------|
| **Test ID** | TC-11 |
| **Module** | API |
| **Title** | Findings can be filtered by severity |
| **Steps** | `GET /api/findings?severity=high` |
| **Expected Result** | Only high-severity findings returned |
| **Actual** | ✓ Filtered results |
| **Status** | **PASS** |

---

#### TC-12: API — POST /api/scan/trigger

| Field | Value |
|-------|-------|
| **Test ID** | TC-12 |
| **Module** | API |
| **Title** | Scan trigger starts a new scan |
| **Steps** | `POST /api/scan/trigger` |
| **Expected Result** | Returns `{"status":"done"}` within 180 seconds |
| **Actual** | ✓ Returns `{"status":"done"}` after ~90 seconds |
| **Status** | **PASS** |

---

#### TC-13: API — Historical Scan Comparison (BY DESIGN)

| Field | Value |
|-------|-------|
| **Test ID** | TC-13 |
| **Module** | API |
| **Title** | Multiple scan history stored for comparison |
| **Status** | **NOT APPLIED (by design)** — scan.db is overwritten on each execution per data minimization policy |
| **Note** | Historical comparison feature intentionally not implemented to limit personal data storage. Alternative: manually save CSV exports for cross-time trend analysis. |

---

#### TC-14: Dashboard — Loads Without Error

| Field | Value |
|-------|-------|
| **Test ID** | TC-14 |
| **Module** | Dashboard |
| **Title** | index.html loads all components |
| **Steps** | Open http://localhost:9090 in browser |
| **Expected Result** | No JavaScript errors in console. All 7 stat cards appear. Tab bar visible. |
| **Actual** | ✓ Dashboard appears. Stat cards populated with data from API. |
| **Status** | **PASS** |

---

#### TC-15: Dashboard — Tab Switching

| Field | Value |
|-------|-------|
| **Test ID** | TC-15 |
| **Module** | Dashboard |
| **Title** | All 7 tabs switch correctly |
| **Steps** | Click each tab (Findings, User & Access, Compliance, Process Risk, Services, Access Control, Risk Config) |
| **Expected Result** | Active tab highlighted, related panel visible, other panels hidden |
| **Actual** | ✓ All 7 tabs work |
| **Status** | **PASS** |

---

#### TC-16: Dashboard — Findings Filter

| Field | Value |
|-------|-------|
| **Test ID** | TC-16 |
| **Module** | Dashboard |
| **Title** | Findings filter buttons work |
| **Steps** | Click filter buttons Critical, High, Medium, All |
| **Expected Result** | Findings list filtered by selected severity |
| **Actual** | ✓ Filter applies correctly |
| **Status** | **PASS** |

---

#### TC-17: Dashboard — Process Search

| Field | Value |
|-------|-------|
| **Test ID** | TC-17 |
| **Module** | Dashboard |
| **Title** | Process search input filters the list |
| **Steps** | Type in search box on Process Risk tab |
| **Expected Result** | Process list filtered by name, PID, or owner |
| **Actual** | ✓ Filter works in real-time (keyup event) |
| **Status** | **PASS** |

---

#### TC-18: Dashboard — Refresh Button

| Field | Value |
|-------|-------|
| **Test ID** | TC-18 |
| **Module** | Dashboard |
| **Title** | Refresh button triggers a new scan |
| **Steps** | Click Refresh button |
| **Expected Result** | Button disabled, shows "Scanning...", re-enabled after scan completes with latest data |
| **Actual** | ✓ Button state changes, data refreshed after scan |
| **Status** | **PASS** |

---

#### TC-19: Dashboard — Process Detail (Row Click)

| Field | Value |
|-------|-------|
| **Test ID** | TC-19 |
| **Module** | Dashboard |
| **Title** | Clicking process row shows detail dialog |
| **Steps** | Click a process row on Process Risk tab |
| **Expected Result** | `alert()` dialog with process info (owner, risk, signed, path, etc.) |
| **Actual** | ✓ Alert dialog shows all process details |
| **Status** | **PASS** |

---

#### TC-20: User — Group Membership Display

| Field | Value |
|-------|-------|
| **Test ID** | TC-20 |
| **Module** | Dashboard (User tab) |
| **Title** | User groups displayed with admin flag |
| **Steps** | Navigate to User & Access tab |
| **Expected Result** | User info card displays username, admin status, auth type. Group badges displayed with Administrators group highlighted in red. |
| **Actual** | ✓ All groups displayed; admin group highlighted |
| **Status** | **PASS** |

---

#### TC-21: User — Privilege Risk

| Field | Value |
|-------|-------|
| **Test ID** | TC-21 |
| **Module** | Dashboard (User tab) |
| **Title** | Dangerous privileges flagged |
| **Steps** | Navigate to User & Access tab |
| **Expected Result** | Active privileges displayed with risk notes. Dangerous privileges highlighted. |
| **Actual** | ✓ Privilege table shows active status. Risk note column present. |
| **Status** | **PASS** |

---

#### TC-22: Compliance — Control Status Display

| Field | Value |
|-------|-------|
| **Test ID** | TC-22 |
| **Module** | Dashboard (Compliance tab) |
| **Title** | ISO controls display compliant/non-compliant status |
| **Steps** | Navigate to Compliance tab |
| **Expected Result** | 93 Annex A controls listed, each with compliant/non-compliant/not_assessed badge. Non-compliant controls display evidence and details. |
| **Actual** | ✓ All 93 controls displayed with status (themed: Organizational, People, Physical, Technological). Non-compliant controls display finding evidence. |
| **Status** | **PASS** |

---

#### TC-23: Services — Running Services Display

| Field | Value |
|-------|-------|
| **Test ID** | TC-23 |
| **Module** | Dashboard (Services tab) |
| **Title** | Service list displays correctly |
| **Steps** | Navigate to Services tab |
| **Expected Result** | Table with columns: Name, Parent App, State, Start type, User, Description. Columns are sortable. |
| **Actual** | ✓ All columns present (including parent_app and description). Sortable columns work. State badges are color-coded. |
| **Status** | **PASS** |

---

#### TC-24: Access Control — Local Users

| Field | Value |
|-------|-------|
| **Test ID** | TC-24 |
| **Module** | Dashboard (Access Control tab) |
| **Title** | Local user table appears |
| **Steps** | Navigate to Access Control tab |
| **Expected Result** | Local user account table with name, full name, active status, description |
| **Actual** | ✓ User accounts listed with correct data |
| **Status** | **PASS** |

---

#### TC-25: Access Control — Group Members

| Field | Value |
|-------|-------|
| **Test ID** | TC-25 |
| **Module** | Dashboard (Access Control tab) |
| **Title** | Group membership displayed with member list |
| **Steps** | Navigate to Access Control tab |
| **Expected Result** | Each group card displays name, description, and comma-separated member names |
| **Actual** | ✓ All groups with members displayed |
| **Status** | **PASS** |

---

#### TC-26: Access Control — File ACL

| Field | Value |
|-------|-------|
| **Test ID** | TC-26 |
| **Module** | Dashboard (Access Control tab) |
| **Title** | File ACL entries displayed per path |
| **Steps** | Navigate to Access Control tab |
| **Expected Result** | Section per sensitive path, each with identity, rights, access type. Dangerous entries (Everyone/FullControl) highlighted in red. |
| **Actual** | ✓ ACL entries displayed per path. Dangerous entries highlighted. |
| **Status** | **PASS** |

---

#### TC-27: Error Handling — Server Without DB

| Field | Value |
|-------|-------|
| **Test ID** | TC-27 |
| **Module** | Server |
| **Title** | Server returns empty results when DB missing |
| **Steps** | Delete scan.db, start server, query API |
| **Expected Result** | JSON `[]` for list endpoints, `null` for single-object endpoints (no crash, no 500) |
| **Actual** | ✓ Empty arrays/null returned without error |
| **Status** | **PASS** |

---

#### TC-28: Error Handling — Page Not Found

| Field | Value |
|-------|-------|
| **Test ID** | TC-28 |
| **Module** | Server |
| **Title** | Unknown path returns 404 |
| **Steps** | `GET /api/nonexistent` |
| **Expected Result** | HTTP 404, JSON `{"error":"not found"}` |
| **Actual** | ✓ 404 with error message |
| **Status** | **PASS** |

---

#### TC-29: Dashboard — Risk Config Tab

| Field | Value |
|-------|-------|
| **Test ID** | TC-29 |
| **Module** | Dashboard (Risk Config tab) |
| **Title** | Risk scoring config tab displays current settings |
| **Steps** | Navigate to Risk Config tab |
| **Expected Result** | Displays severity weights (critical/high/medium/low/info), score range, finding type overrides, and currently active suppressed types |
| **Actual** | ✓ All configuration displayed from risk-config.json in a clean format |
| **Status** | **PASS** |

---

#### TC-30: Dashboard — Sortable Columns

| Field | Value |
|-------|-------|
| **Test ID** | TC-30 |
| **Module** | Dashboard |
| **Title** | Table columns sortable by header click |
| **Steps** | Click column headers on Process Risk tab (Risk, PID, Name, Parent App, Owner, etc.) and Services tab (Name, Parent App, State, etc.) |
| **Expected Result** | Table rows sorted ascending/descending. Arrow indicator (▲/▼) appears on active header. |
| **Actual** | ✓ Ascending/descending sort works with arrow indicators |
| **Status** | **PASS** |

---

#### TC-31: Dashboard — CSV Export

| Field | Value |
|-------|-------|
| **Test ID** | TC-31 |
| **Module** | Dashboard |
| **Title** | CSV export button downloads file |
| **Steps** | Click "Findings", "Compliance", and "Processes" buttons in header |
| **Expected Result** | CSV file downloaded with BOM (UTF-8) for Excel compatibility. Column headers match. Row data matches. |
| **Actual** | ✓ All three CSV formats downloaded correctly. UTF-8 BOM proven compatible with Excel. |
| **Status** | **PASS** |

---

#### TC-32: Dashboard — Modal Dialog

| Field | Value |
|-------|-------|
| **Test ID** | TC-32 |
| **Module** | Dashboard |
| **Title** | Clicking stat card or data area opens detail modal |
| **Steps** | Click Risk Score card, Critical/High/Medium cards, Users/Processes/Services cards, or privilege/group area in User tab |
| **Expected Result** | Modal overlay appears with detail table. Close with X click, click outside modal, or press Escape. |
| **Actual** | ✓ Modal appears with correct data. Closing works via all methods. |
| **Status** | **PASS** |

---

#### TC-33: Services — Parent App Classification

| Field | Value |
|-------|-------|
| **Test ID** | TC-33 |
| **Module** | Dashboard (Services tab) |
| **Title** | Services classified into parent applications |
| **Steps** | Navigate to Services tab, observe "Parent App" column |
| **Expected Result** | Windows services (svchost, lsass, etc.) → "Windows System". Browsers (chrome, msedge) → per vendor. Third-party applications → per classification. |
| **Actual** | ✓ Parent classification accurate for detected services |
| **Status** | **PASS** |

---

#### TC-34: Dashboard — Security Posture Indicators (User Tab)

| Field | Value |
|-------|-------|
| **Test ID** | TC-34 |
| **Module** | Dashboard (User tab) |
| **Title** | Security posture indicators appear on User tab |
| **Steps** | Navigate to User & Access tab |
| **Expected Result** | 4 posture indicators: UAC (Enabled/Disabled), LSA Protection (Protected/Not PPL), Password Policy (8+ chars/Weak), Lockout (Configured/Not set). Each with color badge matching status. |
| **Actual** | ✓ Posture indicators displayed with matching color badges |
| **Status** | **PASS** |

---

#### TC-35: Security — Security Headers

| Field | Value |
|-------|-------|
| **Test ID** | TC-35 |
| **Module** | Server |
| **Title** | Security headers sent on every API response |
| **Steps** | `curl -I http://localhost:9090/api/overview` |
| **Expected Result** | Headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Access-Control-Allow-Origin: http://localhost:9090` |
| **Actual** | ✓ All security headers present with correct values |
| **Status** | **PASS** |

---

#### TC-36: Security — Input Validation ACL Path

| Field | Value |
|-------|-------|
| **Test ID** | TC-36 |
| **Module** | API |
| **Title** | Path traversal on `/api/acl` rejected |
| **Steps** | `GET /api/acl?path=<script>alert(1)</script>` |
| **Expected Result** | HTTP 400, JSON `{"error":"Invalid path parameter"}` |
| **Actual** | ✓ 400 Bad Request, malicious path rejected |
| **Status** | **PASS** |

---

#### TC-37: Security — Input Validation PID

| Field | Value |
|-------|-------|
| **Test ID** | TC-37 |
| **Module** | API |
| **Title** | PID injection on `/api/processes/detail` rejected |
| **Steps** | `GET /api/processes/detail?pid=abc` and `pid=-1` |
| **Expected Result** | HTTP 400 for both cases |
| **Actual** | ✓ 400 Bad Request for invalid and negative PID |
| **Status** | **PASS** |

---

#### TC-38: Security — CSV Formula Injection

| Field | Value |
|-------|-------|
| **Test ID** | TC-38 |
| **Module** | API |
| **Title** | CSV values beginning with `=`, `+`, `-`, `@` are neutralized |
| **Steps** | Export CSV, check values beginning with dangerous characters |
| **Expected Result** | Dangerous values prefixed with `\t` to prevent Excel formula execution |
| **Actual** | ✓ `csvEscape()` function neutralizes all dangerous characters |
| **Status** | **PASS** |

---

#### TC-39: Integration Test Suite

| Field | Value |
|-------|-------|
| **Test ID** | TC-39 |
| **Module** | Test |
| **Title** | All integration tests pass |
| **Steps** | `npm install && node scanner.js && node server.js && node test.js` |
| **Expected Result** | 141 test cases, 0 failed |
| **Actual** | ✓ 141 passed, 0 failed |
| **Status** | **PASS** |

---

#### TC-40: Scanner — Scheduled Mode

| Field | Value |
|-------|-------|
| **Test ID** | TC-40 |
| **Module** | Scanner |
| **Title** | `--schedule` parameter runs scan and exits |
| **Steps** | `node scanner.js --schedule` |
| **Expected Result** | Timestamp output, scan complete, exit code 0 |
| **Actual** | ✓ Scan runs with timestamp, exit code 0 |
| **Status** | **PASS** |

---

#### TC-41: Security — Content-Security-Policy Header

| Field | Value |
|-------|-------|
| **Test ID** | TC-41 |
| **Module** | Server |
| **Title** | Content-Security-Policy header sent on all API responses |
| **Steps** | `GET /api/overview`, check header |
| **Expected Result** | `Content-Security-Policy` header contains `default-src 'self'` |
| **Actual** | ✓ CSP header present with correct policy |
| **Status** | **PASS** |

---

#### TC-42: Security — Dashboard Auth (Basic Auth)

| Field | Value |
|-------|-------|
| **Test ID** | TC-42 |
| **Module** | Server |
| **Title** | Endpoint rejects access without auth when DASHBOARD_USER is configured |
| **Steps** | Set `DASHBOARD_USER=admin`, `DASHBOARD_PASS=admin`, restart server, `GET /` without auth header |
| **Expected Result** | HTTP 401, WWW-Authenticate: Basic realm |
| **Actual** | ✓ 401 with WWW-Authenticate header |
| **Status** | **PASS** |

---

#### TC-43: Security — API Key Authentication

| Field | Value |
|-------|-------|
| **Test ID** | TC-43 |
| **Module** | Server |
| **Title** | API rejects access without X-API-Key when API_KEY is configured |
| **Steps** | Set `API_KEY=secret123`, restart server, `GET /api/overview` without X-API-Key |
| **Expected Result** | HTTP 401 |
| **Actual** | ✓ 401 without X-API-Key, 200 with X-API-Key: secret123 |
| **Status** | **PASS** |

---

#### TC-44: Security — Rate Limiting

| Field | Value |
|-------|-------|
| **Test ID** | TC-44 |
| **Module** | Server |
| **Title** | Rate limiting returns 429 after exceeding limit |
| **Steps** | Set `RATE_LIMIT=5`, restart server, send 6 rapid requests |
| **Expected Result** | 6th request gets HTTP 429 with Retry-After header |
| **Actual** | ✓ 429 after 5 requests, with Retry-After: 60 |
| **Status** | **PASS** |

---

#### TC-45: Security — Audit Log

| Field | Value |
|-------|-------|
| **Test ID** | TC-45 |
| **Module** | Server |
| **Title** | Audit log records every API access |
| **Steps** | Access multiple endpoints, read `audit.log` |
| **Expected Result** | `audit.log` file contains entries in format `[timestamp] API GET /api/overview 200 127.0.0.1` |
| **Actual** | ✓ All API accesses recorded with correct format. Scan trigger recorded as `SCAN`. |
| **Status** | **PASS** |

---

### B.3 Test Data Environment

| Parameter | Value |
|-----------|-------|
| **OS** | Windows 11 |
| **Node.js** | v20.x or later |
| **PowerShell** | 5.1+ |
| **Host** | [HOSTNAME_REDACTED] |
| **User** | [USERNAME_REDACTED] (standard user, non-administrator) |
| **Antivirus** | Windows Defender (real-time: [STATUS_REDACTED]) |
| **Firewall** | Enabled (Domain, Private, Public) |
| **Last scan** | [DATE_REDACTED], duration ~90 seconds |

---

### B.4 Acceptance Criteria

| Criteria | Status |
|----------|--------|
| All TC-01 through TC-45 executed | ✓ |
| Pass rate >= 90% | ✓ (100%) |
| Zero P1 (critical) defects | ✓ |
| Zero P2 (high) defects | ✓ |
| All not-applied items documented with reasons | ✓ (TC-13 — by design) |
| Complete documentation (ADR, SDD, AGRAF, DPRP, SLA, UAT) | ✓ |
| Security hardening verified (CSP, Auth, Rate Limit, Audit Log) | ✓ (TC-41 through TC-45) |

---

### B.5 Suitability as ISO 27001 Audit Evidence

LNO Privilege Compliance Scanner **is suitable as audit evidence for ISO 27001:2022 implementation** based on UAT results:

1. **100% pass rate** (44/44 test cases applicable) — all functions operate according to specifications
2. **Full control coverage** — 93 Annex A controls assessed with compliant/non-compliant/not_assessed status
3. **Audit evidence ready to use** — CSV Export (findings, compliance, processes) produces audit evidence in standard format
4. **Security hardening** — security headers (nosniff, DENY, no-referrer), CORS restricted, input validation, CSV formula injection prevention
5. **Automated quality gate** — 141 integration tests + CI/CD pipeline (GitHub Actions)
6. **Scheduled scanning** — `--schedule` parameter for Windows Task Scheduler
7. **Full transparency** — all risk scoring configurations documented and modifiable via risk-config.json
8. **parent_app classification** — services/processes classified into parent applications for better audit context
9. **Detail modal & sortable columns** — enables auditors to browse findings interactively

This UAT document, together with ADR, AGRAF, and DPRP, provides evidence that the tool has been systematically tested and is ready for use as an ISO 27001 compliance audit aid.

---

**Prepared by:** AI Orchestrator  
**Review date:** 2026-06-23  
**Next review:** 2026-09-23 or after material feature changes
