//! SSH Plugin

use crate::plugins::plugin_trait::{Plugin, PluginResult, PluginFinding};

const SSH_PORTS: [u16; 2] = [22, 2222];

pub struct SshPlugin;

impl SshPlugin {
    pub fn new() -> Self { SshPlugin }
    
    fn parse_banner(&self, banner: &str) -> (Option<String>, Option<String>) {
        let parts: Vec<&str> = banner.split('-').collect();
        
        let protocol = if parts.len() >= 2 {
            Some(format!("SSH-{}", parts[1]))
        } else { None };
        
        let software = if parts.len() >= 3 {
            Some(parts[2..].join("-").trim().to_string())
        } else { None };
        
        (protocol, software)
    }
    
    fn is_outdated(&self, software: &str) -> bool {
        let lower = software.to_lowercase();
        if lower.contains("openssh_") {
            if let Some(idx) = lower.find("openssh_") {
                let ver = &lower[idx + 8..];
                if let Some(major) = ver.chars().next().and_then(|c| c.to_digit(10)) {
                    return major < 8;
                }
            }
        }
        false
    }
}

impl Plugin for SshPlugin {
    fn name(&self) -> &str { "SSH Analyzer" }
    
    fn should_run(&self, port: u16) -> bool { SSH_PORTS.contains(&port) }
    
    fn run(&self, _target: &str, _port: u16, banner: Option<&str>) -> Option<PluginResult> {
        let banner = banner?;
        
        if !banner.to_uppercase().starts_with("SSH-") { return None; }
        
        let mut findings = Vec::new();
        let (protocol, software) = self.parse_banner(banner);
        
        if let Some(proto) = protocol {
            findings.push(PluginFinding {
                key: "Protocol".to_string(),
                value: proto,
                severity: "Info".to_string(),
            });
        }
        
        if let Some(ref soft) = software {
            let severity = if self.is_outdated(soft) { "High" } else { "Info" };
            findings.push(PluginFinding {
                key: "Software".to_string(),
                value: soft.clone(),
                severity: severity.to_string(),
            });
            
            if self.is_outdated(soft) {
                findings.push(PluginFinding {
                    key: "Warning".to_string(),
                    value: "Outdated SSH version".to_string(),
                    severity: "High".to_string(),
                });
            }
        }
        
        if findings.is_empty() { None } 
        else { Some(PluginResult { plugin_name: self.name().to_string(), findings }) }
    }
}
