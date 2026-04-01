//! HTTP Plugin

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::config::{PluginResult, PluginFinding};
use crate::plugins::Plugin;

const HTTP_PORTS: [u16; 6] = [80, 443, 8080, 8000, 8443, 3000];

pub struct HttpPlugin;

impl HttpPlugin {
    pub fn new() -> Self { HttpPlugin }
    
    fn http_request(&self, target: &str, port: u16) -> Option<(String, HashMap<String, String>, String)> {
        let addr = format!("{}:{}", target, port);
        let mut stream = TcpStream::connect_timeout(
            &addr.parse().ok()?, Duration::from_millis(3000)
        ).ok()?;
        
        stream.set_read_timeout(Some(Duration::from_millis(3000))).ok()?;
        stream.set_write_timeout(Some(Duration::from_millis(2000))).ok()?;
        
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: GhostPort/3.0\r\nConnection: close\r\n\r\n",
            target
        );
        stream.write_all(request.as_bytes()).ok()?;
        
        let mut response = vec![0u8; 4096];
        let n = stream.read(&mut response).ok()?;
        let resp_str = String::from_utf8_lossy(&response[..n]).to_string();
        
        let lines: Vec<&str> = resp_str.lines().collect();
        if lines.is_empty() { return None; }
        
        let status = lines[0].to_string();
        
        let mut headers = HashMap::new();
        for line in &lines[1..] {
            if line.is_empty() { break; }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }
        
        let body = resp_str.find("\r\n\r\n")
            .map(|i| resp_str[i + 4..].to_string())
            .unwrap_or_default();
        
        Some((status, headers, body))
    }
    
    fn extract_title(&self, body: &str) -> Option<String> {
        let lower = body.to_lowercase();
        let start = lower.find("<title>")? + 7;
        let end = lower.find("</title>")?;
        if start < end {
            Some(body[start..end].trim().to_string())
        } else {
            None
        }
    }
}

impl Plugin for HttpPlugin {
    fn name(&self) -> &str { "HTTP Recon" }
    
    fn should_run(&self, port: u16) -> bool { HTTP_PORTS.contains(&port) }
    
    fn run(&self, target: &str, port: u16, _banner: Option<&str>) -> Option<PluginResult> {
        let mut findings = Vec::new();
        
        if let Some((status, headers, body)) = self.http_request(target, port) {
            findings.push(PluginFinding {
                key: "Status".to_string(),
                value: status,
                severity: "Info".to_string(),
            });
            
            if let Some(server) = headers.get("server") {
                findings.push(PluginFinding {
                    key: "Server".to_string(),
                    value: server.clone(),
                    severity: "Info".to_string(),
                });
            }
            
            if let Some(title) = self.extract_title(&body) {
                findings.push(PluginFinding {
                    key: "Title".to_string(),
                    value: title,
                    severity: "Info".to_string(),
                });
            }
        }
        
        if findings.is_empty() { None } 
        else { Some(PluginResult { plugin_name: self.name().to_string(), findings }) }
    }
}
