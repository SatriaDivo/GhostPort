//! Host Discovery Module

use std::net::{TcpStream, SocketAddr};
use std::time::{Duration, Instant};
use crate::config::DISCOVERY_PORTS;

/// Discover apakah host aktif
/// Return: Option<(responding_port, latency_ms)>
pub fn discover_host(target: &str, timeout_ms: u64) -> Option<(u16, u128)> {
    for &port in &DISCOVERY_PORTS {
        let addr: SocketAddr = match format!("{}:{}", target, port).parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        
        let start = Instant::now();
        
        if TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).is_ok() {
            let latency = start.elapsed().as_millis();
            return Some((port, latency));
        }
    }
    
    None
}
