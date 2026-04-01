//! GhostPort v3.0 - Main Entry Point
//!
//! Arsitektur multi-file dengan modul terpisah.

mod cli;
mod config;
mod scanner;
mod fingerprint;
mod intelligence;
mod plugins;
mod utils;

use std::time::Instant;
use clap::Parser;

use cli::{Cli, Commands};
use config::{ScanConfig, ScanResult, ScanSummary, VERSION, TOP_PORTS};
use scanner::stealth::ScanMode;
use plugins::manager::PluginManager;

fn print_header() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  GhostPort v{:<50} ║", VERSION);
    println!("║  Silent Network Recon Toolkit                                ║");
    println!("║  🕵️ Modular Stealth Reconnaissance Framework                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
}

fn main() {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Scan { target, start_port, end_port, threads, banner, mode, top_ports, plugins, json } => {
            if !json { print_header(); }
            
            // Resolve target
            let resolved_ip = match utils::network::resolve_target(&target) {
                Ok(ip) => ip,
                Err(e) => {
                    eprintln!("[!] Error: {}", e);
                    std::process::exit(1);
                }
            };
            
            // Parse scan mode
            let scan_mode: ScanMode = mode.parse().unwrap_or(ScanMode::Balanced);
            let scan_config = ScanConfig::from_mode(&scan_mode, threads);
            
            // Determine port list
            let ports: Vec<u16> = if top_ports {
                TOP_PORTS.to_vec()
            } else {
                (start_port..=end_port).collect()
            };
            
            if !json {
                println!("[*] Target: {} ({})", target, resolved_ip);
                println!("[*] Ports: {}-{} ({} ports)", 
                    ports.first().unwrap_or(&0), 
                    ports.last().unwrap_or(&0), 
                    ports.len()
                );
                println!("[*] Mode: {}", scan_mode);
                println!("[*] Threads: {}", scan_config.threads);
                println!("[*] Banner: {}", if banner { "ON" } else { "OFF" });
                println!("[*] Plugins: {}", if plugins { "ON" } else { "OFF" });
                println!();
                
                println!("[*] Stage 1: Host Discovery...");
                if let Some((port, latency)) = scanner::host::discover_host(&resolved_ip, scan_config.timeout_ms) {
                    println!("[+] Host UP (port {}, {}ms)", port, latency);
                } else {
                    println!("[!] Host appears DOWN, continuing...");
                }
                println!();
                println!("[*] Stage 2: Port Scanning...");
            }
            
            let start_time = Instant::now();
            
            // Initialize plugin manager if enabled
            let plugin_manager = if plugins {
                Some(PluginManager::new())
            } else {
                None
            };
            
            // Run port scan
            let results = scanner::port::scan_ports(
                &resolved_ip, 
                ports.clone(), 
                &scan_config, 
                banner, 
                plugin_manager.as_ref()
            );
            
            let duration = start_time.elapsed();
            
            // Output results
            if json {
                let summary = ScanSummary {
                    target,
                    resolved_ip,
                    ports_scanned: ports.len(),
                    open_ports: results.len(),
                    duration_secs: duration.as_secs_f64(),
                    results: results.clone(),
                };
                println!("{}", serde_json::to_string_pretty(&summary).unwrap_or_default());
            } else {
                // Print each result
                for r in &results {
                    let svc = r.service.as_deref().unwrap_or("Unknown");
                    let ver = r.version.as_deref()
                        .map(|v| format!(" ({})", v))
                        .unwrap_or_default();
                    let cat = r.category.as_deref().unwrap_or("");
                    
                    println!("[OPEN] {}:{} → {}{} {}", r.ip, r.port, svc, ver, cat);
                    
                    // Show banner (first line only, max 60 chars)
                    if let Some(ref b) = r.banner {
                        let short: String = b.lines()
                            .next()
                            .unwrap_or("")
                            .chars()
                            .take(60)
                            .collect();
                        println!("       └─ {}", short);
                    }
                    
                    // Show warnings
                    for w in &r.warnings {
                        println!("       ⚠️  {}", w);
                    }
                    
                    // Show plugin results
                    for pr in &r.plugin_results {
                        for f in &pr.findings {
                            println!("       [{}] {}: {}", pr.plugin_name, f.key, f.value);
                        }
                    }
                }
                
                // Summary
                println!();
                println!("════════════════════════════════════════════════════════════════");
                println!("[+] Scan Complete! Duration: {:.2}s", duration.as_secs_f64());
                println!("[+] Ports: {} scanned, {} open", ports.len(), results.len());
            }
        }
        
        Commands::Connect { target, port } => {
            print_header();
            
            let resolved = match utils::network::resolve_target(&target) {
                Ok(ip) => ip,
                Err(e) => {
                    eprintln!("[!] Error: {}", e);
                    std::process::exit(1);
                }
            };
            
            if let Err(e) = utils::network::connect_interactive(&resolved, port) {
                eprintln!("[!] Connection error: {}", e);
            }
        }
        
        Commands::Discover { target, mode, json } => {
            if !json { print_header(); }
            
            let resolved = match utils::network::resolve_target(&target) {
                Ok(ip) => ip,
                Err(e) => {
                    eprintln!("[!] Error: {}", e);
                    std::process::exit(1);
                }
            };
            
            let scan_mode: ScanMode = mode.parse().unwrap_or(ScanMode::Balanced);
            let config = ScanConfig::from_mode(&scan_mode, None);
            
            if !json {
                println!("[*] Discovering: {}", resolved);
            }
            
            if let Some((port, latency)) = scanner::host::discover_host(&resolved, config.timeout_ms) {
                if json {
                    let result = serde_json::json!({
                        "target": target,
                        "resolved_ip": resolved,
                        "status": "up",
                        "responding_port": port,
                        "latency_ms": latency
                    });
                    println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
                } else {
                    println!("[+] Host is UP (port {}, {}ms)", port, latency);
                }
            } else {
                if json {
                    let result = serde_json::json!({
                        "target": target,
                        "resolved_ip": resolved,
                        "status": "down"
                    });
                    println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
                } else {
                    println!("[-] Host is DOWN or filtered");
                }
            }
        }
        
        Commands::Plugins => {
            print_header();
            
            let manager = PluginManager::new();
            println!("[*] Available Plugins:");
            println!("────────────────────────────────────────────────");
            
            for (i, name) in manager.list_plugins().iter().enumerate() {
                println!("  {}. {}", i + 1, name);
            }
            
            println!();
            println!("[*] Use --plugins flag with scan to enable plugin execution");
        }
    }
}
