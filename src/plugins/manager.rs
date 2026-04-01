//! Plugin Manager

use std::panic;
use crate::plugins::plugin_trait::{Plugin, PluginResult};
use crate::plugins::{http::HttpPlugin, ssh::SshPlugin};

pub struct PluginManager {
    plugins: Vec<Box<dyn Plugin>>,
}

impl PluginManager {
    pub fn new() -> Self {
        let plugins: Vec<Box<dyn Plugin>> = vec![
            Box::new(HttpPlugin::new()),
            Box::new(SshPlugin::new()),
        ];
        PluginManager { plugins }
    }
    
    pub fn execute(&self, target: &str, port: u16, banner: Option<&str>) -> Vec<PluginResult> {
        let mut results = Vec::new();
        
        for plugin in &self.plugins {
            if plugin.should_run(port) {
                let target_clone = target.to_string();
                let banner_clone = banner.map(|s| s.to_string());
                
                let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                    plugin.run(&target_clone, port, banner_clone.as_deref())
                }));
                
                if let Ok(Some(pr)) = result {
                    results.push(pr);
                }
            }
        }
        
        results
    }
    
    pub fn list_plugins(&self) -> Vec<&str> {
        self.plugins.iter().map(|p| p.name()).collect()
    }
}
