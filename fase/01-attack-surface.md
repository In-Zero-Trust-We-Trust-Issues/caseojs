# Pertemuan 2 — Pemetaan Attack Surface OJS

## Tujuan Pembelajaran
Setelah pertemuan ini, mahasiswa mampu:
1. Mengidentifikasi semua entry point aplikasi OJS
2. Memetakan alur data (data flow) antar komponen OJS
3. Membuat attack surface diagram menggunakan model ancaman (threat model)
4. Mengklasifikasikan aset berdasarkan tingkat kritikal

**Nama Tim** : In Zero Trust, We Trust (Issues)  
**Kelas**    : DevSecOps TIF A  

## Anggota Tim

| No | Nama                   | NIM           |
|----|------------------------|---------------|
| 1  | Yusrizal Harits Firdaus | 235150207111011 |
| 2  | Ananda Fifadlika        | 235150207111045 |
| 3  | Nicolas Quinn B         | 235150207111053 |
| 4  | Ahmad Adzka Najhan      | 235150200111037 |

## Repository

GitHub:  
https://github.com/In-Zero-Trust-We-Trust-Issues/caseojs/edit/main/fase/01-attack-surface.md

---

## 1. Konsep Attack Surface


**Attack surface** adalah totalitas dari semua titik (surface) di mana penyerang yang tidak berwenang dapat mencoba memasukkan data atau mengekstrak data dari sistem.

Komponen attack surface terdiri dari:

```
Attack Surface = Entry Points + Data Stores + Trust Boundaries
```

### Kategori Attack Surface

| Kategori | Contoh pada OJS |
|---|---|
| **Network Attack Surface** | Port terbuka, protokol HTTP/HTTPS |
| **Software Attack Surface** | Form login, upload file, REST API |
| **Human Attack Surface** | Akun admin default, social engineering |
| **Third-party Attack Surface** | Plugin/tema pihak ketiga, library PHP |

### Diagram Attack Surface + Endpoint
<img width="671" height="846" alt="surface attack diagram drawio" src="https://github.com/user-attachments/assets/bed9d4d4-576b-4a5a-b416-c7edea47993a" />

---

## 2. Arsitektur OJS

### 2.1 Komponen Utama OJS

```
┌─────────────────────────────────────────────────────────────────┐
│                        PENGGUNA (Browser)                        │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP/HTTPS
┌──────────────────────────▼──────────────────────────────────────┐
│                    WEB SERVER (Apache/Nginx)                      │
│                  /var/www/html/ojs/index.php                      │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                      APLIKASI OJS (PHP)                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  MVC Layer   │  │  Plugin Sys  │  │  REST API (v1/v2)    │  │
│  │  (Router,    │  │  (Hooks,     │  │  /api/v1/...         │  │
│  │  Controller, │  │   Generic    │  │                      │  │
│  │  Template)   │  │   Plugins)   │  │                      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         └─────────────────┴──────────────────────┘              │
│                           │                                      │
│  ┌────────────────────────▼───────────────────────────────────┐ │
│  │                    DAL (Data Access Layer)                  │ │
│  └────────────────────────┬───────────────────────────────────┘ │
└───────────────────────────┼─────────────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        │                                       │
┌───────▼────────┐                    ┌─────────▼────────┐
│  MySQL/MariaDB │                    │  File System     │
│  (ojs_db)      │                    │  /files/         │
│  - users       │                    │  /public/        │
│  - submissions │                    │  uploads, cache  │
│  - journals    │                    │                  │
└────────────────┘                    └──────────────────┘
```

### 2.2 Peran Pengguna (Trust Levels)

| Peran | Trust Level | Akses |
|---|---|---|
| **Guest / Tidak Login** | Paling rendah | Baca artikel publik |
| **Reader** | Rendah | Unduh artikel + akun profil |
| **Author** | Sedang | Submit naskah, upload file |
| **Reviewer** | Sedang | Review naskah, komentar |
| **Section Editor** | Tinggi | Manage submission, assign reviewer |
| **Editor** | Tinggi | Full editorial workflow |
| **Journal Manager** | Sangat tinggi | Konfigurasi jurnal |
| **Site Administrator** | Tertinggi | Full akses sistem |

---

## 3. Identifikasi Entry Points

### 3.1 Recon — Pengumpulan Informasi Awal

**Langkah 1 — Fingerprinting dengan WhatWeb**
```bash
whatweb http://<IP-VPS>/ojs/
```

Contoh output yang diharapkan:
```
http://<IP-VPS>/ojs/ [200 OK] Apache[2.4.52], 
  PHP[7.4.33], OJS[3.3.0-8], ...
```

**Langkah 2 — Port Scanning dengan Nmap**
```bash
nmap -sV -sC -p- --open <IP-VPS> -oN nmap_scan.txt
```

**Langkah 3 — Directory & File Enumeration**
```bash
# Gobuster — menemukan path tersembunyi
gobuster dir -u http://<IP-VPS>/ojs \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,bak,old,zip \
  -o gobuster_output.txt

# Alternatif dengan ffuf
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -u http://<IP-VPS>/ojs/FUZZ \
  -o ffuf_output.json -of json
```

**Langkah 4 — Identifikasi versi via HTTP Header**
```bash
curl -I http://<IP-VPS>/ojs/
curl -v http://<IP-VPS>/ojs/index.php/index/install 2>&1 | grep -i "x-powered\|server\|ojs"
```

---

### 3.2 Daftar Entry Points OJS

Berikut adalah entry point yang harus diidentifikasi dan didokumentasikan tim:

#### A. Authentication & Session

| No | URL / Endpoint | Method | Deskripsi | Risiko Potensial |
|---|---|---|---|---|
| A1 | `/http://10.34.100.179/ojs/journals/` | GET | Area pengelolaan jurnal yang berhubungan dengan login dan session pengguna | Authentication bypass, session fixation |

#### B. File Upload

| No | URL / Endpoint | Method | Deskripsi | Risiko Potensial |
|---|---|---|---|---|
| B1 | `http://10.34.100.179/ojs/plugins/` | GET | Direktori modul plugin OJS yang berisi ekstensi sistem | Vulnerable plugin exploitation, kemungkinan upload malicious module |
| B2 | `http://10.34.100.179/ojs/public/` | GET | Direktori penyimpanan file publik seperti upload jurnal, gambar, dan asset | File disclosure, upload webshell, path traversal |

#### C. User Input / Reflected Data

| No | URL / Endpoint | Method | Deskripsi | Risiko Potensial |
|---|---|---|---|---|
| C1 | `http://10.34.100.179/ojs/` | GET | Halaman utama aplikasi Open Journal Systems, menjadi front entry seluruh navigasi user dan routing aplikasi | User input reflection, session hijacking, fingerprinting versi OJS |
| C2 | `http://10.34.100.179/ojs/index.php` | GET | Front controller OJS yang menangani parameter routing seperti page, op, dan path | Parameter tampering, XSS, injection melalui query parameter |

#### D. REST API

| No | Endpoint | Method | Deskripsi | Risiko Potensial |
|---|---|---|---|---|
| D1 | `http://10.34.100.179/ojs/api/` | GET | Endpoint REST API yang menyediakan komunikasi data backend dan frontend | API enumeration, unauthorized access, data exposure |

#### E. Admin Panel

| No | URL / Endpoint | Method | Deskripsi | Risiko Potensial |
|---|---|---|---|---|
| E1 | `http://10.34.100.179/ojs/tools/` | GET | Endpoint tools administratif untuk maintenance atau utilitas sistem | Privilege escalation, admin function abuse |
| E2 | `http://10.34.100.179/ojs/site/` | GET | Endpoint konfigurasi site dan pengaturan global aplikasi | Configuration exposure, admin misconfiguration |

---

## 4. Pemetaan Data Flow

### 4.1 Alur Submission Naskah (Berpotensi Vulnerable)

```
Author (Browser)
    │
    │ POST multipart/form-data (file upload)
    ▼
Apache → PHP OJS Controller (SubmissionHandler)
    │
    │ Validasi tipe file? ← [TITIK KRITIS: apakah hanya cek ekstensi?]
    ▼
File disimpan di /var/www/html/ojs/files/journals/1/articles/
    │
    │ Path disimpan di database
    ▼
MySQL: INSERT INTO submission_files ...
    │
    │ File dapat diakses via URL?
    ▼
http://<IP-VPS>/ojs/files/... ← [RISIKO: Direct Object Reference]
```

<img width="452" height="511" alt="Submission drawio" src="https://github.com/user-attachments/assets/d9406030-3723-4ad3-bda4-704fb1db5b77" />


### 4.2 Alur Autentikasi

```
User → POST /login/signIn {username, password}
         │
         ▼
    UserDAO::getByUsername($username)  ← [SQL Injection vector?]
         │
         ▼
    password_verify($password, $hash)
         │
    ┌────┴────┐
  Gagal    Berhasil
    │         │
    ▼         ▼
 Error    SessionManager::createSession()
 msg           │
          Cookie SESSION dikirim
```

<img width="477" height="460" alt="Auth drawio" src="https://github.com/user-attachments/assets/aed08989-90b9-430a-9f63-00d0496e33bc" />

---

## 5. Identifikasi Aset Kritis

Klasifikasikan aset OJS berdasarkan CIA Triad:

| # | Aset | Confidentiality | Integrity | Availability | Nilai Kritis | Ancaman Utama |
|---|---|:---:|:---:|:---:|:---:|---|
| 1 | Data login admin | Tinggi | Tinggi | Sedang | **Kritis** | Credential stuffing, brute force, phishing |
| 2 | Naskah unpublished | Tinggi | Tinggi | Sedang | **Kritis** | Unauthorized access, data exfiltration |
| 3 | File konfigurasi (`config.inc.php`) | Tinggi | Tinggi | Sedang | **Kritis** | Path traversal, directory listing, LFI |
| 4 | Database credentials | Tinggi | Tinggi | Tinggi | **Kritis** | Credential exposure, config file leak |
| 5 | Session token / cookie pengguna | Tinggi | Tinggi | Sedang | **Kritis** | Session hijacking, XSS, CSRF |
| 6 | Backup files (`.tar.gz`, `.sql`) | Tinggi | Tinggi | Sedang | **Kritis** | Exposed backup di public directory |
| 7 | Data reviewer | Sedang | Tinggi | Sedang | **Tinggi** | IDOR, unauthorized disclosure |
| 8 | Artikel published | Rendah | Tinggi | Tinggi | **Tinggi** | Content tampering, defacement, reputational damage |
| 9 | Email SMTP credentials | Tinggi | Sedang | Sedang | **Tinggi** | Email spoofing, password reset abuse |
| 10 | Plugin / theme files | Rendah | Tinggi | Tinggi | **Tinggi** | Webshell injection, RCE via malicious plugin |
| 11 | Upload directory (`/files/`) | Sedang | Tinggi | Tinggi | **Tinggi** | Unrestricted file upload, path traversal |
| 12 | Log file server | Sedang | Tinggi | Sedang | **Tinggi** | Log tampering, evidence destruction, forensic evasion |
 
---
## 6. Threat Model — STRIDE
 
### S — Spoofing (Pemalsuan Identitas)
 
> Attacker berpura-pura menjadi entitas lain (user, admin, sistem) untuk mendapatkan akses tidak sah.
 
| ID | Skenario Ancaman | Entry Point | Aset Terdampak | Likelihood | Impact |
|---|---|---|---|:---:|:---:|
| S1 | Brute force login admin menggunakan wordlist akun jurnal akademik | A1 | Data login admin | Tinggi | Kritis |
| S2 | Session fixation — attacker menetapkan session ID sebelum korban login | A1 | Session token | Sedang | Kritis |
| S3 | Cookie theft via XSS — cookie session dicuri lalu digunakan ulang | C1, C2 | Session token | Sedang | Kritis |
| S4 | API request dipalsukan menggunakan token yang bocor atau kadaluarsa | D1 | Data reviewer, naskah | Sedang | Tinggi |
| S5 | Attacker menyamar sebagai admin melalui manipulasi parameter `role` di query string | C2 | Data login admin | Rendah | Kritis |
 
---
 
### T — Tampering (Modifikasi Data Tidak Sah)
 
> Attacker memodifikasi data dalam transit atau penyimpanan tanpa otorisasi.
 
| ID | Skenario Ancaman | Entry Point | Aset Terdampak | Likelihood | Impact |
|---|---|---|:---:|:---:|:---:|
| T1 | SQL Injection melalui parameter `page`, `op`, atau `path` di front controller | C2 | Database, naskah unpublished | Tinggi | Kritis |
| T2 | Modifikasi metadata artikel (judul, author, DOI) via REST API tanpa validasi otorisasi | D1 | Artikel published | Sedang | Tinggi |
| T3 | Upload plugin berbahaya yang memodifikasi file inti OJS (`config.inc.php`) | B1 | File konfigurasi | Rendah | Kritis |
| T4 | Path traversal pada direktori public untuk menimpa file yang sudah ada | B2 | Upload directory `/files/` | Sedang | Tinggi |
| T5 | Manipulasi parameter form pada halaman submission untuk mengubah status naskah | C2 | Naskah unpublished | Sedang | Kritis |
| T6 | Modifikasi log file melalui admin tools untuk menghapus jejak aktivitas | E1 | Log file server | Rendah | Tinggi |
 
---
 
### R — Repudiation (Penyangkalan Tindakan)
 
> Attacker atau pengguna menyangkal telah melakukan suatu tindakan karena tidak ada bukti yang cukup.
 
| ID | Skenario Ancaman | Entry Point | Aset Terdampak | Likelihood | Impact |
|---|---|---|:---:|:---:|:---:|
| R1 | Penghapusan atau modifikasi log server setelah intrusi berhasil | E1 | Log file server | Sedang | Tinggi |
| R2 | Admin menyangkal perubahan konfigurasi karena tidak ada audit trail | E2 | File konfigurasi | Sedang | Tinggi |
| R3 | Tidak ada log aktivitas API — tindakan lewat REST API tidak tercatat | D1 | Naskah, data reviewer | Tinggi | Tinggi |
| R4 | Upload file berbahaya tanpa pencatatan siapa yang mengupload dan kapan | B1, B2 | Upload directory | Sedang | Sedang |
 
---
 
### I — Information Disclosure (Kebocoran Informasi)
 
> Informasi sensitif terekspos ke pihak yang tidak berhak, baik secara sengaja maupun tidak.
 
| ID | Skenario Ancaman | Entry Point | Aset Terdampak | Likelihood | Impact |
|---|---|---|:---:|:---:|:---:|
| I1 | Verbose error message menampilkan stack trace, path absolut, atau versi OJS | C1, C2 | File konfigurasi | Tinggi | Tinggi |
| I2 | Directory listing aktif pada `/public/` menampilkan seluruh file yang diupload | B2 | Upload directory | Tinggi | Tinggi |
| I3 | API endpoint mengembalikan data reviewer atau naskah unpublished tanpa autentikasi | D1 | Data reviewer, naskah | Sedang | Kritis |
| I4 | File backup (`.sql`, `.tar.gz`) tersimpan di direktori publik dan dapat diakses langsung | B2 | Backup files | Sedang | Kritis |
| I5 | Fingerprinting versi OJS melalui response header, meta tag, atau path default | C1 | Semua aset | Tinggi | Sedang |
| I6 | `config.inc.php` dapat diakses jika konfigurasi server tidak memblokir akses file `.php` di luar webroot | E2 | Database credentials | Rendah | Kritis |
 
---
 
### D — Denial of Service (Gangguan Ketersediaan Layanan)
 
> Attacker membuat sistem tidak tersedia bagi pengguna yang sah.
 
| ID | Skenario Ancaman | Entry Point | Aset Terdampak | Likelihood | Impact |
|---|---|---|:---:|:---:|:---:|
| D1 | Upload file berukuran sangat besar secara berulang untuk menghabiskan disk space | B1, B2 | Upload directory | Sedang | Tinggi |
| D2 | Flood request ke `index.php` dengan parameter berbeda untuk exhausting server resources | C2 | Artikel published | Sedang | Tinggi |
| D3 | Flood request unauthenticated ke REST API endpoint | D1 | Semua aset | Sedang | Tinggi |
| D4 | Submission naskah massal secara otomatis (bot) untuk membebani sistem review | C2 | Naskah unpublished | Rendah | Sedang |
| D5 | Instalasi plugin yang mengandung infinite loop atau memory leak | B1 | Seluruh sistem OJS | Rendah | Kritis |
 
---
 
### E — Elevation of Privilege (Eskalasi Hak Akses)
 
> Attacker mendapatkan hak akses yang lebih tinggi dari yang seharusnya dimiliki.
 
| ID | Skenario Ancaman | Entry Point | Aset Terdampak | Likelihood | Impact |
|---|---|---|:---:|:---:|:---:|
| E1 | Author mengakses fitur Editor/Admin dengan memanipulasi parameter `role` atau `page` | C2 | Naskah unpublished, data reviewer | Sedang | Kritis |
| E2 | Eksploitasi plugin yang memiliki kerentanan privilege escalation bawaan | B1 | Seluruh sistem | Rendah | Kritis |
| E3 | Akses endpoint `/tools/` atau `/site/` tanpa pemeriksaan sesi admin yang valid | E1, E2 | File konfigurasi | Sedang | Kritis |
| E4 | Manipulasi JWT / token API untuk mengubah klaim `role` menjadi `admin` | D1 | Semua aset | Rendah | Kritis |
| E5 | Webshell yang diupload melalui `/public/` atau `/plugins/` memberikan akses OS-level | B1, B2 | Seluruh sistem | Rendah | Kritis |
  
---
 
## Ringkasan Risk Matrix STRIDE
 
| Kategori | Jumlah Skenario | Entry Point Paling Berisiko | Aset Paling Terdampak |
|---|:---:|---|---|
| Spoofing | 5 | A1, C2 | Session token, Data login admin |
| Tampering | 6 | C2, D1 | Database, Naskah unpublished |
| Repudiation | 4 | D1, E1 | Log file, Audit trail API |
| Information Disclosure | 6 | B2, D1 | Backup files, Database credentials |
| Denial of Service | 5 | B1, B2, C2 | Upload directory, Sistem OJS |
| Elevation of Privilege | 5 | B1, B2, E1 | File konfigurasi, Seluruh sistem |
| **Total** | **31** | | |
 
---

## 7. Deliverable Pertemuan 2

| No | Deliverable | Format | Dikumpulkan Via |
|---|---|---|---|
| 1 | Attack surface diagram (arsitektur + entry points) | PNG/SVG (draw.io) | GitHub |
| 2 | Tabel entry points lengkap (isi semua kolom A–E) | MD / Excel | GitHub |
| 3 | Data flow diagram untuk 2 alur kritis | PNG/SVG | GitHub |
| 4 | Tabel aset kritis dengan penilaian CIA | MD | GitHub |
| 5 | Threat model matrix STRIDE | MD / tabel | GitHub |

---

## 8. Pertanyaan Diskusi

1. Bagaimana cara membedakan **attack surface** dan **attack vector**? Berikan contoh pada OJS!
2. Mengapa endpoint upload file (B1–B4) memiliki risiko lebih tinggi dibanding endpoint baca (GET)?
3. Pada alur autentikasi OJS, di titik mana kemungkinan terbesar terjadinya SQL Injection? Jelaskan!
4. Sebutkan minimal 3 informasi sensitif yang mungkin bocor melalui HTTP response headers OJS!

---

## Referensi
- OWASP Testing Guide v4.2 — OTG-INFO (Information Gathering)
- Microsoft STRIDE Threat Model
- OWASP Attack Surface Analysis Cheat Sheet
