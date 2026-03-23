# Pertemuan 1 — Kickoff Case 1: Vulnerability OJS

## Tujuan Pembelajaran
Setelah pertemuan ini, mahasiswa mampu:
1. Mendefinisikan ruang lingkup (scope) vulnerability assessment secara profesional
2. Membentuk tim penguji dengan peran yang jelas
3. Menyiapkan lingkungan VPS dan menginstal OJS versi vulnerable
4. Memahami Rules of Engagement (RoE) dalam pengujian keamanan

---

## 1. Latar Belakang

**Open Journal Systems (OJS)** adalah platform manajemen dan penerbitan jurnal ilmiah open-source yang dikembangkan oleh Public Knowledge Project (PKP). OJS banyak digunakan oleh institusi akademik di seluruh dunia, termasuk perguruan tinggi di Indonesia.

Karena popularitasnya, OJS menjadi target menarik bagi penyerang. Beberapa versi OJS lama memiliki kerentanan kritis yang terdokumentasi di database CVE, antara lain:

| CVE | Versi Terdampak | Jenis Kerentanan | Severity |
|---|---|---|---|
| CVE-2020-28112 | < 3.2.1-2 | Stored XSS | High |
| CVE-2021-27188 | ≤ 3.3.0-6 | Server-Side Request Forgery (SSRF) | High |
| CVE-2022-24822 | ≤ 3.3.0-8 | Open Redirect + XSS | Medium |

> **Catatan Etika:** Seluruh pengujian dilakukan di lingkungan yang telah disetujui (VPS milik kelas). Dilarang keras menguji sistem di luar scope yang ditetapkan.

adapun dalam project ini, kami menggunakan OJS versi 3.3.0.8

---

## 2. Pembentukan Tim

Setiap kelompok terdiri dari **4–5 mahasiswa** dengan pembagian peran sebagai berikut:

| Peran | Jumlah | Tanggung Jawab |
|---|---|---|
| **Project Lead / Scrum Master** | 1 | Koordinasi jadwal, komunikasi, final review laporan |
| **Security Engineer (DAST)** | 1–2 | Menjalankan scanning aktif (ZAP, Nikto, SQLMap) |
| **Security Engineer (SAST)** | 1 | Analisis source code statis (Semgrep, phpcs) |
| **Documentation & Reporting** | 1 | Menulis laporan, risk register, rekomendasi mitigasi |

# Template Daftar Tim

**Nama Tim** : In Zero Trust, We Trust (Issues)  
**Kelas**    : DevSecOps TIF A  

## Anggota Tim

| No | Nama                   | NIM           | Peran                          |
|----|------------------------|---------------|--------------------------------|
| 1  | Yusrizal Harits Firdaus | 235150207111011 | Project Lead / Scrum Master    |
| 2  | Ananda Fifadlika        | 235150207111045 | Security Engineer (DAST)       |
| 3  | Nicolas Quinn B         | 235150207111053 | Security Engineer (SAST)       |
| 4  | Ahmad Adzka Najhan      | 235150200111037 | Documentation & Reporting      |

## Repository

GitHub:  
https://github.com/In-Zero-Trust-We-Trust-Issues/caseojs/blob/main/fase/00-kickoff.md


---

## 3. Scope & Rules of Engagement (RoE)

### 3.1 In-Scope

- Aplikasi OJS yang berjalan di VPS yang diberikan dosen
- URL target: `http://<IP-VPS-TIM>/`
- Port yang diizinkan untuk diuji: 80, 443, 8080
- Semua fitur OJS yang dapat diakses via browser (sebagai guest, author, reviewer, editor)

### 3.2 Out-of-Scope

- Infrastruktur jaringan kampus
- VPS tim lain
- Server PKP (upstream OJS)
- Pengujian DoS / DDoS (dilarang keras)
- Eksploitasi di luar kerentanan yang ditemukan (pivoting ke server lain)

### 3.3 Rules of Engagement

| Aturan | Keterangan |
|---|---|
| Waktu pengujian | selama waktu penugasan |
| Metode | Non-destructive (jangan hapus/ubah data produksi) |
| Dokumentasi | Semua aktivitas harus dicatat (log, screenshot) |
| Pelaporan | Temuan kritis wajib dilaporkan ke dosen dalam 24 jam |
| Etika | Tidak membagikan akses VPS ke pihak luar |

---

## 4. Persiapan Lingkungan VPS

### 4.1 Spesifikasi VPS yang Diberikan

```
OS       : Ubuntu 22.04 LTS
CPU      : 2 vCPU
RAM      : 8 GB
Storage  : 32 GB SSD
```

### 4.2 Instalasi OJS Versi Vulnerable

> Target versi: **OJS 3.3.0-8** (mengandung CVE-2021-27188 dan CVE-2022-24822) atau bisa versi yang lain

**Langkah 1 — Akses VPS via SSH**
```bash
ssh ubuntu@<IP-VPS>
```

**Langkah 2 — Instalasi dependensi**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y apache2 mysql-server php7.4 php7.4-cli \
  php7.4-common php7.4-mysql php7.4-xml php7.4-mbstring \
  php7.4-gd php7.4-curl php7.4-zip php7.4-intl unzip wget
```

**Langkah 3 — Unduh OJS versi vulnerable**
```bash
cd /var/www/html
sudo wget https://pkp.sfu.ca/ojs/download/ojs-3.3.0-8.tar.gz
sudo tar -xzf ojs-3.3.0-8.tar.gz
sudo mv ojs-3.3.0-8 ojs
sudo chown -R www-data:www-data ojs
sudo chmod -R 755 ojs
```

**Langkah 4 — Buat database MySQL**
```bash
sudo mysql -u root -e "
  CREATE DATABASE ojs_db CHARACTER SET utf8mb3;
  CREATE USER 'ojs_user'@'localhost' IDENTIFIED BY 'P@ssw0rd_OJS!';
  GRANT ALL PRIVILEGES ON ojs_db.* TO 'ojs_user'@'localhost';
  FLUSH PRIVILEGES;
"
```

**Langkah 5 — Konfigurasi Apache Virtual Host**
```bash
sudo nano /etc/apache2/sites-available/ojs.conf
```

Isi file konfigurasi:
```apache
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html/ojs
    ServerName <IP-VPS>

    <Directory /var/www/html/ojs>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/ojs_error.log
    CustomLog ${APACHE_LOG_DIR}/ojs_access.log combined
</VirtualHost>
```

```bash
sudo a2ensite ojs.conf
sudo a2enmod rewrite
sudo systemctl restart apache2
```

**Langkah 6 — Selesaikan instalasi via browser**
```
Buka browser → http://<IP-VPS>/ojs/index.php/index/install
Ikuti wizard instalasi dengan data berikut:
  - Database Host    : localhost
  - Database Name    : ojs_db
  - Database User    : ojs_user
  - Database Password: P@ssw0rd_OJS!
  - Admin Username   : admin
  - Admin Password   : Admin@123 (catat dengan baik!)
```

**Langkah 7 — Verifikasi instalasi**
```bash
# Cek versi OJS lewat terminal
curl -s http://localhost/ojs/index.php/index | grep -i "ojs\|version"

```
<img width="1919" height="470" alt="image" src="https://github.com/user-attachments/assets/442fc1d8-5bff-4fea-9164-9ebc0c94f4a9" />



```bash


# Cek log Apache
sudo tail -f /var/log/apache2/ojs_access.log
```
<img width="1919" height="440" alt="image" src="https://github.com/user-attachments/assets/60fe8261-1a19-4ddd-81e1-147007f13ab1" />

---

## 5. Deliverable Pertemuan 1

| No | Deliverable | Format | Dikumpulkan Via |
|---|---|---|---|
| 1 | Dokumen Scope & RoE (ditandatangani tim) | PDF | LMS / GitHub |
| 2 | Daftar anggota tim + peran | MD / PDF | GitHub repo tim |
| 3 | Screenshot OJS berhasil diinstal (menampilkan versi) | PNG | GitHub repo tim |
| 4 | URL VPS aktif | Plain text | LMS |

---

## 6. Pertanyaan Diskusi

1. Mengapa penting mendefinisikan scope sebelum melakukan penetration testing?
2. Apa risiko yang mungkin terjadi jika pengujian dilakukan tanpa Rules of Engagement?
3. Jelaskan perbedaan antara **vulnerability assessment** dan **penetration testing**!
4. Mengapa OJS versi lama masih banyak dipakai di institusi akademik? Apa implikasinya terhadap keamanan?

## 7. Jawaban
1. Agar ketika melakukan pengujian memiliki batasan yang jelas mengenai sistem, jaringan, aplikasi, atau data apa saja yang boleh diuji. nahh dengan adanya scope membantu mencegah aktivitas pengujian yang tidak disengaja , sehingga mengurangi risiko gangguan layanan, kerusakan sistem, atau pelanggaran hukum nantinya. adapun jugaa dengan kita menentukan scope dapat membantu kita untuk memastikan tujuan pengujian lebih terarah
2. yakni kesalahpahaman antara tim penguji dan pemilik sistem terkait metode, waktu, serta batasan pengujian yang diperbolehkan sehingga dapat menyebabkan gangguan layanan, kerusakan sistem, atau bahkan hilangnya data karena tidak ada kesepakatan mengenai teknik pengujian yang aman
3. Vulnerability assessment bertujuan untuk mengidentifikasi dan mendata kelemahan keamanan pada sistem, jaringan, atau aplikasi secara luas menggunakan tools otomatis maupun analisis konfigurasi. Sedangkan, penetration testing bertujuan untuk mensimulasikan serangan nyata dengan mencoba mengeksploitasi kelemahan tersebut guna mengetahui dampak sebenarnya terhadap sistem. Sehingga dapat dikatakan bahwa  vulnerability assessment fokus pada “menemukan potensi celah”, sedangkan penetration testing fokus pada “membuktikan apakah celah tersebut benar-benar bisa dimanfaatkan oleh penyerang.”
4. OJS versi lama masih banyak dipakai di institusi akademik karena faktor keterbatasan sumber daya seperti tenaga teknis, anggaran, dan waktu untuk melakukan proses upgrade serta migrasi data tidah hanya itu beberapa institusi memiliki proses birokrasi yang panjang sehingga pembaruan perangkat lunak tidak dapat dilakukan dengan cepat. Lalu untuk implikasinya terhadap keamanan menurut kami cukup serius karena versi lama biasanya memiliki kerentanan yang sudah diketahui publik dan tidak lagi mendapat patch atau dukungan resmi sehingga membuat sistem lebih rentan terhadap serangan seperti defacement, pencurian data, atau penyusupan malware yang dapat mengganggu integritas dan ketersediaan layanan jurnal
---

## Referensi
- OWASP Testing Guide v4.2 — Chapter: Test Management
- PTES (Penetration Testing Execution Standard) — Pre-engagement Interactions
- PKP OJS Security Advisories: https://pkp.sfu.ca/ojs/
