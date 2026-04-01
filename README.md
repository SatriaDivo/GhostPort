`	ext
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██████╗  ██████╗ ██████╗ ████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║   ██████╔╝██║   ██║██████╔╝   ██║   
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██╔═══╝ ██║   ██║██╔══██╗   ██║   
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
`

# GhostPort

Sebuah perangkat CLI pengintaian jaringan (network reconnaissance) modular dan multi-threaded yang ditulis menggunakan Rust. GhostPort juga berfungsi sebagai **Network Security Analysis Engine** yang otomatis menganalisis hasil scan port dan mendeteksi kerentanan dengan melampirkan payload verifikasi yang aman.

## Fitur

* **Pemindaian Inti (Core Scanning)**
  * Eksekusi multi-threaded untuk enumerasi port secara konkuren
  * *Service fingerprinting* dan deteksi versi
* **Siluman & Penghindaran (Stealth & Evasion)**
  * Profil pemindaian dan mode timing yang dapat dikonfigurasi
  * Pengacakan port dan *packet jitter* untuk meminimalisasi deteksi jaringan
* **Analisis & Intelijen (Analysis & Intelligence)**
  * Klasifikasi intelijen kerentanan berbasis aturan (rule-based)
  * Menghasilkan rekomendasi keamanan, deskripsi tingkat keparahan (severity), serta **safe verification payloads** (PoC non-dekstruktif) untuk memvalidasi kerentanan.
* **Plugin Pengintaian (Reconnaissance Plugins)**
  * Ekosistem modul yang mudah diperluas untuk layanan spesifik (HTTP, SSH, FTP)
  * Pengintaian mendalam HTTP (ekstraksi header, parsing judul halaman, pengujian endpoint)
* **Mesin Ekspor (Export Engine)**
  * Serialisasi format data bawaan untuk output JSON, CSV, dan TXT

## Instalasi

**Prasyarat**
* Toolchain Rust (direkomendasikan versi 1.70.0 ke atas)

**Kompilasi dari source**
`ash
git clone https://github.com/username/ghostport.git
cd ghostport
cargo build --release
`
Binary hasil kompilasi akan dapat diakses melalui path direktori 	arget/release/ghostport.

## Penggunaan & Contoh Command Lengkap

Berikut adalah sekumpulan contoh perintah (*command*) lengkap yang bisa Anda gunakan dengan GhostPort:

**1. Pemindaian Cepat (Top Ports)**
Memindai 20 port yang paling umum digunakan pada target:
`ash
ghostport scan 192.168.1.10 --top-ports
`
*Atau menggunakan domain:*
`ash
ghostport scan scanme.nmap.org --top-ports
`

**2. Pemindaian Penuh dengan Intelligence Analysis (Paling Powerful)**
Memindai top ports, melakukan *banner grabbing*, menjalankan semua plugin pengintaian, dan menampilkan rekomendasi kerentanan langsung di terminal:
`ash
ghostport scan scanme.nmap.org --top-ports --banner --plugins
`

**3. Pemindaian Rentang Port Spesifik**
Memindai port dari 1 hingga 1024:
`ash
ghostport scan 192.168.1.10 -s 1 -e 1024
`
*Atau memindai sekumpulan port tertentu yang dipisah koma:*
`ash
ghostport scan 192.168.1.10 -p 21,22,80,443,3306
`

**4. Mode Siluman (Stealth Mode)**
Menurunkan noise di jaringan untuk menghindari deteksi IDS/IPS (menggunakan mode stealth atau sneaky):
`ash
ghostport scan 192.168.1.10 --top-ports --mode stealth
`

**5. Mode Agresif (Aggressive Mode) & Multi-Threading**
Mempercepat pemindaian dengan mengabaikan stealth, menggunakan 100 threads:
`ash
ghostport scan 192.168.1.10 -s 1 -e 65535 --mode aggressive -t 100
`

**6. Menyimpan Hasil Scan ke JSON (Untuk Analisis)**
Mengekspor hasil scan secara lengkap termasuk data intelijen kerentanan dan payload PoC ke dalam format JSON:
`ash
ghostport scan target.com --top-ports --banner --plugins --format json --output laporan.json
`

**7. Mencetak Raw JSON di Terminal**
Sangat berguna apabila Anda ingin menyambungkan output ke tools CLI lain (jq, dsb):
`ash
ghostport scan 192.168.1.10 --top-ports --json
`

**8. Mengetes Koneksi ke Port Spesifik (Ping/Connect Mode)**
Seperti tool 
c (netcat), mengecek apakah suatu port terbuka tanpa scanning berlebih:
`ash
ghostport connect 192.168.1.10 22
`

## Hasil Output (Analisis Kerentanan)

Contoh struktur output JSON hasil generasi Vulnerability Intelligence & Verification Payload:
`json
{
  "target": "192.168.1.10",
  "results": [
    {
      "ip": "192.168.1.10",
      "port": 80,
      "service": "http",
      "version": "Apache/2.4.7",
      "banner": "HTTP/1.1 200 OK\nServer: Apache/2.4.7",
      "category": "🌐 Web",
      "vulnerabilities": [
        {
          "name": "Vulnerable Apache HTTP Server (Detected 2.4.7)",
          "description": "Server Apache HTTP (<2.4.49) terindikasi rentan.",
          "severity": "Critical",
          "confidence": 95,
          "impact": "Memungkinkan serangan Path Traversal (CVE-2021-41773) untuk membaca file internal server.",
          "recommendation": "Segera patch dan upgrade Apache HTTP Server minimal ke versi 2.4.51+.",
          "verification": {
            "type": "HTTP Request",
            "payload": "curl -v --path-as-is http://<TARGET_IP>/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            "steps": "Kirim payload traversal untuk memvalidasi secara tidak merusak (membaca file lokal saja)",
            "expected_result": "Mendapatkan isi file passwd.",
            "risk_confirmed_if": "Server mengembalikan response isi file /etc/passwd."
          }
        }
      ],
      "plugin_findings": []
    }
  ]
}
`

## Ekstensibilitas

GhostPort dirancang secara khusus untuk bisa diekstensi secara langsung melalui *trait* Plugin. Anda dapat mengimplementasikan logika kustom pengintaian mandiri dengan mendefinisikan *struct* baru, memberikan nilai pada metode *trait* should_run() dan un(), dan meregistrasi modul tersebut ke dalam PluginManager. Pipeline pemindaian GhostPort akan secara otomatis memberikan parameter dan konteks ScanResult ke plugin kustom yang telah dibuat tersebut dan mengelompokkan temuan-temuannya.

## Peringatan (Disclaimer)

Toolkit ini murni disediakan terbatas pada kepentingan audit keamanan yang telah disetujui, diotorisasi secara hukum, dan untuk materi edukasi saja. Menggunakan GhostPort dalam pemindaian ke target tanpa adanya izin konsensual hukum dengan penyedia layanan atau target jaringan terkait yang berlaku adalah perbuatan ilegal. Para perancang maupun kontributor entitas peranti lunak ini tidak mengambil tanggung jawab perihal setiap kejahatan yang disengaja atas penyalahgunaan atau kerusakan dari produk sistem ini secara langsung.

## Lisensi

Proyek aplikasi software GhostPort dilisensikan mendasar sepenuhnya pada Lisensi MIT.
