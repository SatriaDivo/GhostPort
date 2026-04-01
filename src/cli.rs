//! # CLI Module - Command Line Interface
//!
//! Modul ini menangani parsing argumen command line menggunakan clap.
//! Semua subcommand dan opsi didefinisikan di sini.

use clap::{Parser, Subcommand, ValueEnum};

/// Versi aplikasi
pub const VERSION: &str = "3.0.0";

// ============================================================================
// SCAN MODE - Mode untuk stealth scanning
// ============================================================================

/// Mode scanning yang menentukan tingkat stealth
/// 
/// Setiap mode memiliki karakteristik berbeda:
/// - Stealth: Lambat tapi sulit terdeteksi
/// - Balanced: Keseimbangan kecepatan dan stealth
/// - Aggressive: Cepat tapi mudah terdeteksi
#[derive(Debug, Clone, Copy, ValueEnum, Default, PartialEq)]
pub enum ScanMode {
    /// 🕵️ Maximum stealth - random delay tinggi, thread minimal
    Stealth,
    
    /// ⚖️ Balanced - default mode
    #[default]
    Balanced,
    
    /// ⚡ Aggressive - cepat, kurang stealth
    Aggressive,
}

impl ScanMode {
    /// Jumlah thread untuk mode ini
    pub fn threads(&self) -> usize {
        match self {
            ScanMode::Stealth => 2,
            ScanMode::Balanced => 30,
            ScanMode::Aggressive => 150,
        }
    }
    
    /// Range delay (min, max) dalam milidetik
    pub fn delay_range(&self) -> (u64, u64) {
        match self {
            ScanMode::Stealth => (1000, 3000),
            ScanMode::Balanced => (50, 200),
            ScanMode::Aggressive => (0, 20),
        }
    }
    
    /// Timeout koneksi dalam milidetik
    pub fn timeout_ms(&self) -> u64 {
        match self {
            ScanMode::Stealth => 5000,
            ScanMode::Balanced => 1500,
            ScanMode::Aggressive => 500,
        }
    }
    
    /// Deskripsi mode
    pub fn description(&self) -> &'static str {
        match self {
            ScanMode::Stealth => "🕵️ Maximum stealth, random delays",
            ScanMode::Balanced => "⚖️ Balanced speed and stealth",
            ScanMode::Aggressive => "⚡ Maximum speed, minimal stealth",
        }
    }
}

// ============================================================================
// CLI STRUCT - Struktur utama CLI
// ============================================================================

/// GhostPort - Silent Network Recon Toolkit
#[derive(Parser, Debug)]
#[command(
    name = "ghostport",
    author = "GhostPort Team",
    version = VERSION,
    about = "Silent Network Recon Toolkit - Modular Stealth Scanner",
    long_about = None,
    before_help = BANNER,
    after_help = "Examples:\n  ghostport scan -i 192.168.1.1 -e 1000\n  ghostport scan -i 192.168.1.1 --mode stealth -b\n  ghostport connect -i 192.168.1.1 -p 22"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Banner ASCII art untuk CLI
const BANNER: &str = r#"
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██████╗  ██████╗ ██████╗ ████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║   ██████╔╝██║   ██║██████╔╝   ██║   
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██╔═══╝ ██║   ██║██╔══██╗   ██║   
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
                    v3.0 - 🕵️ Modular Stealth Reconnaissance
"#;

// ============================================================================
// SUBCOMMANDS - Perintah yang tersedia
// ============================================================================

/// Subcommand yang tersedia di GhostPort
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// 🔍 Scan target dengan pipeline (discovery → scan → fingerprint → plugins)
    #[command(visible_alias = "s")]
    Scan {
        /// Target: IP address atau hostname
        #[arg(short = 'i', long = "ip", value_name = "TARGET")]
        target: String,

        /// Port awal
        #[arg(short = 's', long = "start", default_value = "1")]
        start_port: u16,

        /// Port akhir
        #[arg(short = 'e', long = "end", default_value = "1024")]
        end_port: u16,

        /// Override jumlah threads
        #[arg(short = 't', long = "threads")]
        threads: Option<usize>,

        /// Aktifkan banner grabbing & fingerprinting
        #[arg(short = 'b', long = "banner")]
        banner: bool,

        /// Mode scanning (stealth/balanced/aggressive)
        #[arg(long = "mode", value_enum, default_value = "balanced")]
        mode: ScanMode,

        /// Scan hanya top common ports
        #[arg(long = "top-ports")]
        top_ports: bool,
        
        /// Aktifkan plugin execution
        #[arg(long = "plugins")]
        plugins: bool,

        /// Output dalam format JSON
        #[arg(long = "json")]
        json: bool,
    },

    /// 🔗 Connect ke target (Netcat-like)
    #[command(visible_alias = "c")]
    Connect {
        /// Target: IP atau hostname
        #[arg(short = 'i', long = "ip", value_name = "TARGET")]
        target: String,

        /// Port tujuan
        #[arg(short = 'p', long = "port")]
        port: u16,
    },

    /// 📡 Discover hosts yang aktif
    #[command(visible_alias = "d")]
    Discover {
        /// Target: IP address
        #[arg(short = 'i', long = "ip", value_name = "TARGET")]
        target: String,

        /// Mode scanning
        #[arg(long = "mode", value_enum, default_value = "balanced")]
        mode: ScanMode,

        /// Output dalam format JSON
        #[arg(long = "json")]
        json: bool,
    },
    
    /// 🧩 List semua plugin yang tersedia
    #[command(visible_alias = "p")]
    Plugins,
}

/// Cetak header CLI
pub fn print_header() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  GhostPort v{:<47} ║", VERSION);
    println!("║  Silent Network Recon Toolkit                                ║");
    println!("║  🕵️ Modular Stealth Reconnaissance Framework                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
}
