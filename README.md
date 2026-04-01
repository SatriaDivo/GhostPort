```text
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██████╗  ██████╗ ██████╗ ████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║   ██████╔╝██║   ██║██████╔╝   ██║   
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██╔═══╝ ██║   ██║██╔══██╗   ██║   
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
```

# GhostPort

Sebuah perangkat CLI pengintaian jaringan (network reconnaissance) modular dan multi-threaded yang ditulis menggunakan Rust.

## Fitur

* **Pemindaian Inti (Core Scanning)**
  * Eksekusi multi-threaded untuk enumerasi port secara konkuren
  * *Service fingerprinting* dan deteksi versi
* **Siluman & Penghindaran (Stealth & Evasion)**
  * Profil pemindaian dan mode timing yang dapat dikonfigurasi
  * Pengacakan port dan *packet jitter* untuk meminimalisasi deteksi jaringan
* **Analisis & Intelijen (Analysis & Intelligence)**
  * Klasifikasi intelijen kerentanan berbasis aturan (rule-based)
  * Sistem pelaporan internal terstruktur untuk output deterministik
* **Plugin Pengintaian (Reconnaissance Plugins)**
  * Ekosistem modul yang mudah diperluas untuk layanan spesifik (HTTP, SSH, FTP)
  * Pengintaian mendalam HTTP (ekstraksi header, parsing judul halaman, pengujian endpoint)
* **Mesin Ekspor (Export Engine)**
  * Serialisasi format data bawaan untuk output JSON, CSV, dan TXT

## Arsitektur

GhostPort beroperasi berdasarkan arsitektur berjenjang yang digerakkan oleh pipeline:

1. **Discovery & Scanning**: Memvalidasi ketersediaan host, dilanjutkan dengan pemindaian port TCP secara acak dan konkuren.
2. **Fingerprinting**: Berinteraksi dengan port terbuka untuk mengekstraksi banner layanan dan mengidentifikasi versi perangkat lunak.
3. **Intelligence Layer**: Menganalisis versi perangkat lunak yang diidentifikasi terhadap basis aturan kerentanan lokal.
4. **Plugin Execution**: Merutekan layanan yang telah diidentifikasi ke plugin spesifik-protokol untuk inspeksi mendalam.
5. **Aggregation**: Mengkonsolidasi seluruh temuan ke dalam satu model laporan `ScanReport` utuh sebelum diteruskan ke CLI *renderer* atau mesin ekspor.

## Instalasi

**Prasyarat**
* Toolchain Rust (direkomendasikan versi 1.70.0 ke atas)

**Kompilasi dari source**
```bash
git clone https://github.com/username/ghostport.git
cd ghostport
cargo build --release
```
Binary hasil kompilasi akan dapat diakses melalui path direktori `target/release/ghostport`.

## Penggunaan

**Pemindaian Dasar**
Memindai 20 port yang paling umum digunakan pada IP target:
```bash
ghostport scan 192.168.1.10 --top-ports
```

**Pemindaian Lanjutan**
Memindai rentang port tertentu menggunakan parameter timing *stealth*, mengeksekusi plugin pengintaian, dan mengekspor hasilnya langsung ke format file JSON:
```bash
ghostport scan 192.168.1.10 -s 1 -e 1024 --mode stealth --plugins --format json --output result.json
```

## Referensi CLI

### Perintah Utama
* `scan` - Mengeksekusi pemindaian jaringan ke target yang ditentukan.
* `connect` - Memulai pengetesan koneksi TCP sederhana (serupa netcat) ke port tertentu.

### Flag Penting (Perintah Scan)
* `-s, --start-port <PORT>`: Rentang port awal pemindaian.
* `-e, --end-port <PORT>`: Rentang port akhir pemindaian.
* `--top-ports`: Target spesifik ke 20 port yang paling umum saja.
* `-t, --threads <COUNT>`: Melakukan *override* terhadap jumlah thread bawaan (default).
* `-m, --mode <MODE>`: Mengatur template mode *timing* dan *stealth* (contoh: `aggressive`, `balanced`, `stealth`).
* `--banner`: Mengaktifkan ekstraksi *banner grabbing*.
* `--plugins`: Mengaktifkan eksekusi plugin *deep reconnaissance* berdasarkan tipe protokol.
* `--json`: Mencetak hasil dalam bentuk raw JSON via standard output (stdout).
* `-o, --output <FILE>`: Menentukan *file path* destinasi khusus ketika mengekspor laporan pemindaian.
* `-f, --format <FORMAT>`: Format tipe ekspor yang dihendaki (`txt`, `csv`, atau `json`).

## Hasil Output

Contoh struktur output JSON:
```json
{
  "target": "192.168.1.10",
  "results": [
    {
      "ip": "192.168.1.10",
      "port": 80,
      "service": "http",
      "version": "Apache/2.4.41",
      "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41",
      "category": "Web",
      "warnings": [
        "Apache version < 2.4.49 is vulnerable to path traversal (CVE-2021-41773)"
      ],
      "plugin_findings": [
        "[HttpPlugin] endpoints: Found /admin (200 OK)",
        "[HttpPlugin] title: Internal Dashboard"
      ]
    }
  ]
}
```

## Ekstensibilitas

GhostPort dirancang secara khusus untuk bisa diekstensi secara langsung melalui *trait* `Plugin`. Anda dapat mengimplementasikan logika kustom pengintaian mandiri dengan mendefinisikan *struct* baru, memberikan nilai pada metode *trait* `should_run()` dan `run()`, dan meregistrasi modul tersebut ke dalam `PluginManager`. Pipeline pemindaian GhostPort akan secara otomatis memberikan parameter dan konteks `ScanResult` ke plugin kustom yang telah dibuat tersebut dan mengelompokkan temuan-temuannya.

## Peringatan (Disclaimer)

Toolkit ini murni disediakan terbatas pada kepentingan audit keamanan yang telah disetujui, diotorisasi secara hukum, dan untuk materi edukasi saja. Menggunakan GhostPort dalam pemindaian ke target tanpa adanya izin konsensual hukum dengan penyedia layanan atau target jaringan terkait yang berlaku adalah perbuatan ilegal. Para perancang maupun kontributor entitas peranti lunak ini tidak mengambil tanggung jawab perihal setiap kejahatan yang disengaja atas penyalahgunaan atau kerusakan dari produk sistem ini secara langsung.

## Lisensi

Proyek aplikasi software GhostPort dilisensikan mendasar sepenuhnya pada Lisensi MIT.
