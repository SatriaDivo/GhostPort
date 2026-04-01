//! Plugin Trait Definition

/// Finding dari plugin
#[derive(Debug, Clone)]
pub struct PluginFinding {
    pub key: String,
    pub value: String,
    pub severity: String,
}

/// Hasil dari plugin execution
#[derive(Debug, Clone)]
pub struct PluginResult {
    pub plugin_name: String,
    pub findings: Vec<PluginFinding>,
}

/// Plugin trait - interface untuk semua plugin
pub trait Plugin: Send + Sync {
    /// Nama plugin
    fn name(&self) -> &str;
    
    /// Apakah plugin relevan untuk port ini?
    fn should_run(&self, port: u16) -> bool;
    
    /// Jalankan plugin
    fn run(&self, target: &str, port: u16, banner: Option<&str>) -> Option<PluginResult>;
}
