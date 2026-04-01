//! HTTP Plugin

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::plugins::plugin_trait::{Plugin, PluginResult, PluginFinding};

const HTTP_PORTS: [u16; 6] = [80, 443, 8080, 8000, 8443, 3000];

pub struct HttpPlugin;

impl HttpPlugin {
    pub fn new() -> Self { HttpPlugin }
    
    fn send_http_request(&self, target: &str, port: u16, path: &str) -> Option<(String, HashMap<String, String>, String)> {
        let addr = format!("{}:{}", target, port);
        let mut stream = TcpStream::connect_timeout(
            &addr.parse().ok()?, Duration::from_millis(3000)
        ).ok()?;
        
        stream.set_read_timeout(Some(Duration::from_millis(3000))).ok()?;
        stream.set_write_timeout(Some(Duration::from_millis(2000))).ok()?;
        
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: GhostPort/3.0\r\nConnection: close\r\n\r\n",
            path, target
        );
        stream.write_all(request.as_bytes()).ok()?;
        
        let mut response = vec![0u8; 8192];
        let n = stream.read(&mut response).ok()?;
        let resp_str = String::from_utf8_lossy(&response[..n]).to_string();
        
        let lines: Vec<&str> = resp_str.lines().collect();
        if lines.is_empty() { return None; }
        
        let status_line = lines[0].to_string();
        
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
        
        Some((status_line, headers, body))
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

    fn extract_status_code(&self, status_line: &str) -> Option<u16> {
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() >= 2 {
            parts[1].parse::<u16>().ok()
        } else {
            None
        }
    }
}

impl Plugin for HttpPlugin {
    fn name(&self) -> &str { "HTTP Deep Recon" }
    
    fn should_run(&self, port: u16) -> bool { HTTP_PORTS.contains(&port) }
    
    fn run(&self, target: &str, port: u16, _banner: Option<&str>) -> Option<PluginResult> {
        let mut findings = Vec::new();

        // 1. Unencrypted HTTP Check
        if port == 80 || port == 8080 || port == 8000 {
            findings.push(PluginFinding {
                key: "Security".to_string(),
                value: "Unencrypted HTTP service".to_string(),
                severity: "Warning".to_string(),
            });
        }
        
        // 2. Base HTTP Response Analysis & Title Extraction
        if let Some((status_line, headers, body)) = self.send_http_request(target, port, "/") {
            findings.push(PluginFinding {
                key: "Status".to_string(),
                value: status_line.clone(),
                severity: "Info".to_string(),
            });
            
            if let Some(server) = headers.get("server") {
                findings.push(PluginFinding {
                    key: "Server".to_string(),
                    value: server.clone(),
                    severity: "Info".to_string(),
                });
            }

            if let Some(content_type) = headers.get("content-type") {
                findings.push(PluginFinding {
                    key: "Content-Type".to_string(),
                    value: content_type.clone(),
                    severity: "Info".to_string(),
                });
            }

            if let Some(location) = headers.get("location") {
                findings.push(PluginFinding {
                    key: "Location".to_string(),
                    value: location.clone(),
                    severity: "Info".to_string(),
                });
            }
            
            if let Some(title) = self.extract_title(&body) {
                findings.push(PluginFinding {
                    key: "Title".to_string(),
                    value: format!("\"{}\"", title),
                    severity: "Info".to_string(),
                });
            }

            // 3. Endpoint Discovery
            let endpoints = ["/admin", "/login", "/dashboard", "/api"];
            for ep in endpoints {
                if let Some((ep_status_line, _, _)) = self.send_http_request(target, port, ep) {
                    if let Some(status_code) = self.extract_status_code(&ep_status_line) {
                        if status_code < 400 {
                            findings.push(PluginFinding {
                                key: "Found endpoint".to_string(),
                                value: format!("{} ({})", ep, ep_status_line),
                                severity: "Info".to_string(),
                            });

                            // 4. Exposed Admin Panel Check
                            if ep == "/admin" {
                                findings.push(PluginFinding {
                                    key: "Security".to_string(),
                                    value: "Potential admin panel exposed".to_string(),
                                    severity: "Warning".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
        
        if findings.is_empty() { None } 
        else { Some(PluginResult { plugin_name: self.name().to_string(), findings }) }
    }
}
