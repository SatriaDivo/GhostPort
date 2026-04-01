# GhostPort v3.0

```
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██████╗  ██████╗ ██████╗ ████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║   ██████╔╝██║   ██║██████╔╝   ██║   
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██╔═══╝ ██║   ██║██╔══██╗   ██║   
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
                     v3.0 - 🕵️ Modular Stealth Reconnaissance
```

**Silent Network Recon Toolkit** - Modular Stealth Reconnaissance Framework dengan plugin system, stealth scanning, dan security intelligence. Built with Rust.

## ✨ Features

### 🆕 New in v3.0

- 🕵️ **Stealth Engine** - Random port order, jitter delay, scan modes (stealth/balanced/aggressive)
- 🧩 **Plugin System** - Extensible architecture dengan trait-based plugins
- 📊 **Intelligence Layer** - Service classification dan risk analysis
- 🔌 **Built-in Plugins** - HTTP Recon, SSH Analyzer, FTP Analyzer

### Core Features
- 🚀 **Concurrent Port Scanner** - Multi-threaded dengan worker pool
- 🔍 **Smart Fingerprinting** - Banner grabbing dengan version detection
- 🧪 **Connect Mode** - Netcat-like interactive connection
- 📡 **Host Discovery** - TCP-based ping
- 🌐 **DNS Resolution** - Support hostname dan URL

## 🏗️ Architecture v3.0

GhostPort v3.0 menggunakan **5-stage pipeline architecture**:

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                          GHOSTPORT v3.0 PIPELINE                                     │
├──────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│  ┌────────────────┐   ┌────────────────┐   ┌────────────────┐   ┌────────────────┐  │
│  │   STAGE 1      │   │   STAGE 2      │   │   STAGE 3      │   │   STAGE 4      │  │
│  │ Host Discovery │──▶│  Port Scanner  │──▶│ Fingerprinting │──▶│ Intelligence   │  │
│  │                │   │  + Stealth 🕵️ │   │                │   │    Layer 📊    │  │
│  │ - TCP ping     │   │ - Random order │   │ - Banner grab  │   │ - Categorize   │  │
│  │ - Alive check  │   │ - Jitter delay │   │ - Version parse│   │ - Warnings     │  │
│  └───────┬────────┘   └───────┬────────┘   └───────┬────────┘   └───────┬────────┘  │
│          │                    │                    │                    │           │
│          ▼                    ▼                    ▼                    ▼           │
│     mpsc::channel        StealthEngine        mpsc::channel        ServiceCategory  │
│     ActiveHost           random+jitter        ScanResult           risk warnings    │
│                                                                                      │
│                    ┌────────────────────────────────────────────┐                   │
│                    │              STAGE 5                       │                   │
│                    │         Plugin Execution 🧩                │                   │
│                    │  - HTTP Plugin (title, server, status)     │                   │
│                    │  - SSH Plugin (version, protocol)          │                   │
│                    │  - FTP Plugin (banner, server type)        │                   │
│                    └────────────────────────────────────────────┘                   │
│                                                                                      │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

## 🕵️ Stealth Engine

GhostPort v3.0 memiliki **Stealth Engine** untuk menghindari deteksi IDS/IPS:

### Fitur Stealth:
1. **Random Port Order** - Port di-shuffle sebelum scanning (Fisher-Yates algorithm)
2. **Jitter Delay** - Random delay antar koneksi
3. **Variable Timeout** - Timeout bervariasi untuk menghindari fingerprinting

### Scan Modes:

| Mode | Threads | Delay | Timeout | Use Case |
|------|---------|-------|---------|----------|
| `stealth` | 2 | 1-3s (random) | 5s | Maximum stealth, IDS evasion |
| `balanced` | 30 | 50-200ms (random) | 1.5s | Default, balanced |
| `aggressive` | 150 | 0-20ms (random) | 500ms | Fast scanning |

```bash
# Stealth mode untuk menghindari deteksi
ghostport scan -i 192.168.1.1 -e 1024 --mode stealth

# Aggressive untuk scan cepat
ghostport scan -i 192.168.1.1 -e 1024 --mode aggressive
```

## 🧩 Plugin System

GhostPort menggunakan **trait-based plugin system** yang extensible:

```rust
/// Plugin trait - interface untuk semua plugin
pub trait Plugin: Send + Sync {
    /// Nama plugin
    fn name(&self) -> &str;
    
    /// Apakah plugin ini relevan untuk port tertentu?
    fn should_run(&self, port: u16) -> bool;
    
    /// Jalankan plugin
    fn run(&self, target: &str, port: u16, banner: Option<&str>) -> Option<PluginResult>;
}
```

### Built-in Plugins:

1. **HTTP Plugin** (port 80, 443, 8080, dll)
   - Extract status code
   - Extract Server header
   - Extract HTML title
   - Detect outdated servers

2. **SSH Plugin** (port 22, 2222)
   - Parse SSH protocol version
   - Extract software version
   - Detect outdated OpenSSH

3. **FTP Plugin** (port 21, 2121)
   - Parse FTP banner
   - Detect server type (vsftpd, ProFTPD)
   - Warning cleartext credentials

### List Plugins:
```bash
ghostport plugins
```

### Enable Plugins saat Scan:
```bash
ghostport scan -i 192.168.1.1 -e 1024 -b --plugins
```

## 📦 Installation

### Prerequisites
- Rust 1.70+ (install dari https://rustup.rs)

### Build dari source:

```bash
cd GhostPort

# Build release version
cargo build --release

# Binary: target/release/ghostport.exe (Windows)
# Binary: target/release/ghostport (Linux/macOS)
```

## 🚀 Usage

### Port Scanning

```bash
# Basic scan (ports 1-1024)
ghostport scan -i 192.168.1.1 -e 1024

# Scan dengan hostname
ghostport scan -i google.com -e 1000

# Scan dengan banner grabbing
ghostport scan -i 192.168.1.1 -e 1024 -b

# Stealth mode
ghostport scan -i 192.168.1.1 -e 1024 --mode stealth

# Dengan plugins
ghostport scan -i 192.168.1.1 -e 1024 -b --plugins

# Top ports saja
ghostport scan -i 192.168.1.1 --top-ports

# JSON output
ghostport scan -i 192.168.1.1 -e 1024 --json
```

### Connect Mode (Netcat-like)

```bash
ghostport connect -i 192.168.1.1 -p 80
# Lalu ketik:
# GET / HTTP/1.1
# Host: localhost
# [Enter dua kali]
```

### Host Discovery

```bash
ghostport discover -i 192.168.1.1
ghostport discover -i 192.168.1.1 --mode aggressive
```

### List Plugins

```bash
ghostport plugins
```

## 📋 CLI Reference

```
USAGE:
    ghostport <COMMAND>

COMMANDS:
    scan      🔍 Scan target dengan pipeline stealth
    connect   🔗 Connect ke target (Netcat-like)
    discover  📡 Discover host aktif
    plugins   🧩 List plugin yang tersedia
    help      Help message

SCAN OPTIONS:
    -i, --ip <TARGET>       Target (IP/hostname/URL)
    -s, --start <PORT>      Start port [default: 1]
    -e, --end <PORT>        End port [default: 1024]
    -t, --threads <NUM>     Override thread count
    -b, --banner            Enable banner grabbing
        --mode <MODE>       Scan mode [stealth|balanced|aggressive]
        --top-ports         Scan top 20 ports only
        --plugins           Enable plugin execution
        --json              JSON output
```

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║  GhostPort v3.0.0                                            ║
║  Silent Network Recon Toolkit                                ║
║  🕵️ Modular Stealth Reconnaissance Framework                 ║
╚══════════════════════════════════════════════════════════════╝

[*] Target: example.com (93.184.216.34)
[*] Port Range: 1-1024
[*] Mode: ⚖️ Balanced speed and stealth
[*] Banner Grabbing: ON
[*] Plugins: ON

[*] Stage 1: Host Discovery...
[+] Host is UP (port 80, 125ms)

[*] Stage 2: Port Scanning (Stealth Mode: Balanced)...
[OPEN] 93.184.216.34:22 → SSH (OpenSSH_8.2) 🔐 Remote Access
       └─ SSH-2.0-OpenSSH_8.2
       [SSH Analyzer] Protocol: SSH-2
       [SSH Analyzer] Software: OpenSSH_8.2

[OPEN] 93.184.216.34:80 → nginx (1.21.0) 🌐 Web
       └─ HTTP/1.1 200 OK
       [HTTP Recon] Status: 200 OK
       [HTTP Recon] Server: nginx/1.21.0
       [HTTP Recon] Title: Example Domain

[OPEN] 93.184.216.34:443 → HTTPS 🌐 Web

════════════════════════════════════════════════════════════════
[+] Scan Complete!
[+] Duration: 12.45s
[+] Ports: 1024 scanned, 3 open

[+] Summary:
PORT     SERVICE         VERSION              CATEGORY
────────────────────────────────────────────────────────────────
22       SSH             OpenSSH_8.2          🔐 Remote Access
80       nginx           1.21.0               🌐 Web
443      HTTPS           -                    🌐 Web
```

## 🔧 Extending dengan Custom Plugin

Untuk membuat plugin kustom:

```rust
use ghostport::{Plugin, PluginResult, PluginFinding, FindingSeverity};

pub struct MyCustomPlugin;

impl Plugin for MyCustomPlugin {
    fn name(&self) -> &str {
        "My Custom Plugin"
    }
    
    fn should_run(&self, port: u16) -> bool {
        port == 12345 // Custom port
    }
    
    fn run(&self, target: &str, port: u16, banner: Option<&str>) -> Option<PluginResult> {
        // Your logic here
        Some(PluginResult {
            plugin_name: self.name().to_string(),
            findings: vec![
                PluginFinding {
                    key: "Custom".to_string(),
                    value: "Finding".to_string(),
                    severity: FindingSeverity::Info,
                }
            ],
        })
    }
}

// Register ke PluginManager:
// plugin_manager.register(Box::new(MyCustomPlugin));
```

## 🛡️ Error Handling

- ✅ Invalid IP/hostname rejected dengan clear message
- ✅ Semua network operations memiliki timeout
- ✅ Plugin crash tidak menghentikan program (catch_unwind)
- ✅ Connection errors handled gracefully
- ✅ Tidak panic dalam kondisi normal

## ⚠️ Disclaimer

Tool ini ditujukan untuk **authorized security testing only**. Selalu dapatkan izin sebelum melakukan scanning. Unauthorized network scanning mungkin ilegal di jurisdiksi Anda.

## 📄 License

MIT License - Lihat file LICENSE untuk detail.
