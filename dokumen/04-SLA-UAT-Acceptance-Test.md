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
4. **Tanpa autentikasi:** Dashboard tidak memiliki login. Siapa pun dengan akses ke localhost:9090 dapat melihat temuan.
5. **Tanpa monitoring real-time:** Scan hanya on-demand. Tidak ada monitoring latar belakang berkelanjutan.
6. **Tanpa alerting:** Tidak ada mekanisme email, webhook, atau notifikasi.
7. **Tanpa remediasi:** Rekomendasi hanya teks; tidak ada perbaikan otomatis yang diterapkan.

---

## Bagian B: User Acceptance Test (UAT) Matrix

### B.1 Ringkasan Eksekusi Tes

| Total Test Cases | Lulus | Gagal | Tidak Diterapkan | Tingkat Kelulusan |
|------------------|-------|-------|-------------------|-------------------|
| 34 | 33 | 0 | 1 | 100% |

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
| Semua TC-01 hingga TC-34 dieksekusi | ✓ |
| Tingkat kelulusan >= 90% | ✓ (100%) |
| Nol defect P1 (kritis) | ✓ |
| Nol defect P2 (tinggi) | ✓ |
| Semua item tidak diterapkan didokumentasikan dengan alasan | ✓ (TC-13 — by design) |
| Dokumentasi lengkap (ADR, SDD, AGRAF, DPRP, SLA, UAT) | ✓ |

---
### B.5 Kesesuaian sebagai Alat Bukti ISO 27001

LNO Privilege Compliance Scanner **layak dijadikan alat bukti implementasi ISO 27001:2022** berdasarkan hasil UAT:

1. **100% tingkat kelulusan** (33/33 test case applicable) — semua fungsi berjalan sesuai spesifikasi
2. **Cakupan kontrol penuh** — 93 Annex A controls dinilai dengan status compliant/non-compliant/not_assessed
3. **Audit evidence siap pakai** — CSV Export (findings, compliance, processes) menghasilkan bukti audit dalam format standar
4. **Transparansi penuh** — semua konfigurasi risk scoring terdokumentasi dan dapat diubah via risk-config.json
5. **Klasifikasi parent_app** — service/process diklasifikasikan ke aplikasi induk untuk konteks audit yang lebih baik
6. **Modal detail & sortable columns** — memudahkan auditor menelusuri temuan secara interaktif

Dokumen UAT ini, bersama dengan ADR, AGRAF, dan DPRP, menyediakan bukti bahwa tool telah diuji secara sistematis dan siap digunakan sebagai alat bantu audit kepatuhan ISO 27001.

---

**Disusun oleh:** AI Orchestrator  
**Tanggal review:** 2026-06-23  
**Review berikutnya:** 2026-09-23 atau setelah perubahan fitur material
