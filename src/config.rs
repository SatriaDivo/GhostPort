//! # Config Module - Konfigurasi Aplikasi
//!
//! Modul ini berisi konstanta dan konfigurasi global untuk GhostPort.

use crate::cli::ScanMode;

// ============================================================================
// KONSTANTA GLOBAL
// ============================================================================

/// Ukuran maksimal banner
pub const BANNER_MAX_SIZE: usize = 1024;

/// Port yang digunakan untuk host discovery
pub const DISCOVERY_PORTS: [u16; 4] = [80, 443, 22, 8080];

/// Top 20 common ports untuk quick scan
pub const TOP_PORTS: [u16; 20] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
];

// ============================================================================
// CONFIGURATION STRUCTURES
// ============================================================================

/// Konfigurasi untuk scanner
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub threads: usize,
    pub timeout_ms: u64,
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl ScanConfig {
    /// Buat config dari scan mode
    pub fn from_mode(mode: &ScanMode, threads_override: Option<usize>) -> Self {
        let threads = threads_override.unwrap_or_else(|| mode.threads());
        let (min_delay, max_delay) = mode.delay_range();
        let timeout_ms = mode.timeout_ms();
        
        ScanConfig {
            threads,
            timeout_ms,
            min_delay_ms: min_delay,
            max_delay_ms: max_delay,
        }
    }
}

