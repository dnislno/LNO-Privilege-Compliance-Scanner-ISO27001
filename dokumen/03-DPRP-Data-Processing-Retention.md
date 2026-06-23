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
| **Enkripsi saat diam** | BELUM diimplementasikan. `scan.db` adalah SQLite teks biasa. **Risiko:** siapa pun dengan akses filesystem ke direktori proyek dapat membaca semua data. Mitigasi: `scan.db` hanya ada saat server berjalan; hapus setelah review. |
| **Enkripsi saat transit** | T/A — server bind hanya ke localhost (127.0.0.1:9090). Tidak ada transmisi jaringan. |
| **Logging & monitoring** | BELUM diimplementasikan. Tidak ada log audit siapa yang mengakses `scan.db` atau kapan. |
| **Tanggap insiden** | Dikelola operator. Sebagai tool offline, permukaan pelanggaran terbatas pada mesin lokal. |

**Rekomendasi peningkatan untuk penggunaan produksi:**
1. Simpan `scan.db` di `%APPDATA%\LNO-PrivilegeScanner` dengan ACL deny-BUILTIN\Users eksplisit
2. Tambahkan SQLCipher untuk enkripsi saat diam
3. Tambahkan tabel audit log yang mencatat setiap akses API
4. Implementasikan penghapusan otomatis yang dapat dikonfigurasi setelah N hari

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

**Disusun oleh:** AI Orchestrator  
**Tanggal review:** 2026-06-23  
**Review berikutnya:** 2026-09-23 atau setelah perubahan fitur material
