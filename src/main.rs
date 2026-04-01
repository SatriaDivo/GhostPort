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

use cli::{Cli, Commands, ScanMode};
use config::{ScanConfig, TOP_PORTS};
use plugins::manager::PluginManager;
use utils::report::{ScanReport, render_cli, export_report};

fn print_header() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  GhostPort v3.0.0                                            ║");
    println!("║  Silent Network Recon Toolkit                                ║");
    println!("║  🕵️ Modular Stealth Reconnaissance Framework                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
}

fn main() {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Scan { target, start_port, end_port, threads, banner, mode, top_ports, plugins, json, output, format } => {
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
            let scan_mode: ScanMode = mode;
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
            
            let report = ScanReport {
                target: target.clone(),
                results,
            };
            
            if json {
                export_report(&report, "json", "stdout");
            } else {
                render_cli(&report, duration.as_secs_f64(), ports.len());
            }
            
            if let Some(path) = output {
                export_report(&report, &format, &path);
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
            
            let scan_mode: ScanMode = mode;
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
