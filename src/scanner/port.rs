//! Port Scanner Module - Multi-threaded dengan stealth features

use std::net::{TcpStream, SocketAddr};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::io::{Read, Write};

use rand::seq::SliceRandom;
use rand::Rng;

use crate::utils::report::ScanResult;
use crate::plugins::plugin_trait::PluginResult;
use crate::config::{ScanConfig, BANNER_MAX_SIZE};
use crate::fingerprint::service;
use crate::intelligence::analyzer;
use crate::plugins::manager::PluginManager;

struct PortResult {
    port: u16,
    #[allow(dead_code)]
    latency_ms: u64,
}

pub fn scan_ports(
    target: &str,
    ports: Vec<u16>,
    config: &ScanConfig,
    grab_banner: bool,
    plugin_manager: Option<&PluginManager>,
) -> Vec<ScanResult> {
    // Shuffle ports untuk stealth
    let mut shuffled = ports.clone();
    {
        let mut rng = rand::thread_rng();
        shuffled.shuffle(&mut rng);
    }
    
    let (tx, rx) = mpsc::channel::<PortResult>();
    let port_iter = Arc::new(Mutex::new(shuffled.into_iter()));
    let target_arc = Arc::new(target.to_string());
    
    let mut handles = vec![];
    
    for _ in 0..config.threads {
        let tx = tx.clone();
        let port_iter = Arc::clone(&port_iter);
        let target = Arc::clone(&target_arc);
        let timeout_ms = config.timeout_ms;
        let min_delay = config.min_delay_ms;
        let max_delay = config.max_delay_ms;
        
        let handle = thread::spawn(move || {
            let mut rng = rand::thread_rng();
            
            loop {
                let port = {
                    let mut iter = port_iter.lock().unwrap();
                    iter.next()
                };
                
                let port = match port {
                    Some(p) => p,
                    None => break,
                };
                
                // Random delay untuk stealth
                if max_delay > 0 {
                    let delay = rng.gen_range(min_delay..=max_delay);
                    thread::sleep(Duration::from_millis(delay));
                }
                
                let addr: SocketAddr = match format!("{}:{}", target, port).parse() {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                
                let start = Instant::now();
                
                if TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).is_ok() {
                    let latency = start.elapsed().as_millis() as u64;
                    let _ = tx.send(PortResult { port, latency_ms: latency });
                }
            }
        });
        
        handles.push(handle);
    }
    
    drop(tx);
    
    let mut port_results: Vec<PortResult> = rx.iter().collect();
    
    for h in handles {
        let _ = h.join();
    }
    
    port_results.sort_by_key(|r| r.port);
    
    // Build final results
    let mut results = Vec::new();
    
    for pr in port_results {
        let banner = if grab_banner {
            grab_banner_from_port(target, pr.port, config.timeout_ms)
        } else {
            None
        };
        
        let (svc, ver) = service::detect_service(pr.port, banner.as_deref());
        let category = analyzer::categorize_port(pr.port);
        let warnings = analyzer::analyze_service(pr.port, &svc, banner.as_deref());
        
        let plugin_findings: Vec<String> = if let Some(pm) = plugin_manager {
            let res = pm.execute(target, pr.port, banner.as_deref());
            let mut findings = Vec::new();
            for r in res {
                for f in r.findings {
                    findings.push(format!("[{}] {}: {} ({})", r.plugin_name, f.key, f.value, f.severity));
                }
            }
            findings
        } else {
            vec![]
        };
        
        results.push(ScanResult {
            ip: target.to_string(),
            port: pr.port,
            service: Some(svc),
            version: ver,
            banner,
            category: Some(category),
            warnings,
            plugin_findings,
        });
    }
    
    results
}

fn grab_banner_from_port(target: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let addr: SocketAddr = format!("{}:{}", target, port).parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).ok()?;
    
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    
    let http_ports = [80, 443, 8080, 8000, 8443, 3000, 5000];
    if http_ports.contains(&port) {
        let req = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", target);
        let _ = stream.write_all(req.as_bytes());
    } else {
        let _ = stream.write_all(b"\r\n");
    }
    
    let mut buffer = vec![0u8; BANNER_MAX_SIZE];
    let n = stream.read(&mut buffer).ok()?;
    
    if n == 0 { return None; }
    
    let banner: String = buffer[..n]
        .iter()
        .map(|&b| if b.is_ascii_graphic() || b.is_ascii_whitespace() { b as char } else { '.' })
        .collect();
    
    Some(banner.trim().to_string())
}
