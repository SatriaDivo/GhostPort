//! Plugin Trait Definition

use crate::config::PluginResult;

/// Plugin trait - interface untuk semua plugin
pub trait Plugin: Send + Sync {
    /// Nama plugin
    fn name(&self) -> &str;
    
    /// Apakah plugin relevan untuk port ini?
    fn should_run(&self, port: u16) -> bool;
    
    /// Jalankan plugin
    fn run(&self, target: &str, port: u16, banner: Option<&str>) -> Option<PluginResult>;
}
