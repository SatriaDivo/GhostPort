# GhostPort

A modular, multi-threaded network reconnaissance CLI tool written in Rust.

## Features

* **Core Scanning**
  * Multi-threaded execution for concurrent port enumeration
  * Service fingerprinting and version detection
* **Stealth & Evasion**
  * Configurable scanning profiles and timing modes
  * Port randomization and packet jitter to reduce detection signatures
* **Analysis & Intelligence**
  * Rule-based vulnerability intelligence matching
  * Structured internal reporting system for deterministic output
* **Reconnaissance Plugins**
  * Extensible module system targeting specific services (HTTP, SSH, FTP)
  * HTTP deep reconnaissance (header extraction, title parsing, endpoint probing)
* **Export Engine**
  * Native data serialization to JSON, CSV, and TXT formats

## Architecture

GhostPort operates on a staged, pipeline-driven architecture:

1. **Discovery & Scanning**: Validates host availability, followed by a concurrent, randomized TCP port scan.
2. **Fingerprinting**: Interrogates open ports to extract service banners and identify software versions.
3. **Intelligence Layer**: Assesses identified versions against a local vulnerability rule-base.
4. **Plugin Execution**: Routes enumerated services to protocol-specific plugins for deeper inspection.
5. **Aggregation**: Centralizes findings into a unified `ScanReport` model before dispatching to the CLI renderer or export engine.

## Installation

**Prerequisites**
* Rust toolchain (1.70.0 or higher recommended)

**Build from source**
```bash
git clone https://github.com/username/ghostport.git
cd ghostport
cargo build --release
```
The compiled binary will be available at `target/release/ghostport`.

## Usage

**Basic Scan**
Scans the top 20 common ports on a target IP address:
```bash
ghostport scan 192.168.1.10 --top-ports
```

**Advanced Scan**
Scans a specific port range utilizing stealth timing, executing deep reconnaissance plugins, and exporting the results to a JSON file:
```bash
ghostport scan 192.168.1.10 -s 1 -e 1024 --mode stealth --plugins --format json --output result.json
```

## CLI Reference

### Commands
* `scan` - Executes a network scan against the specified target.
* `connect` - Initiates a basic TCP connection test to a specific port.

### Important Flags (Scan Command)
* `-s, --start-port <PORT>`: Starting port range.
* `-e, --end-port <PORT>`: Ending port range.
* `--top-ports`: Target the 20 most common ports.
* `-t, --threads <COUNT>`: Override default thread count.
* `-m, --mode <MODE>`: Set timing and stealth templates (e.g., `aggressive`, `normal`, `stealth`).
* `--banner`: Enable banner grabbing.
* `--plugins`: Enable protocol-specific deep reconnaissance plugins.
* `--json`: Output raw JSON to standard output.
* `-o, --output <FILE>`: File path for scan report export.
* `-f, --format <FORMAT>`: Export format (`txt`, `csv`, `json`).

## Output

Example JSON output structure:
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

## Extensibility

GhostPort is designed to be easily extended via the `Plugin` trait. Developers can implement custom reconnaissance logic by defining a new struct, implementing the `should_run()` and `run()` trait methods, and registering the module in the `PluginManager`. The pipeline automatically passes the `ScanResult` context to applicable plugins and aggregates their findings.

## Disclaimer

This tool is provided for authorized security auditing and educational purposes only. Usage of GhostPort for network scanning without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program. 

## License

This project is licensed under the MIT License.
