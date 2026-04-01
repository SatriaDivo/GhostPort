//! Network Utilities

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;

/// Resolve target ke IP address
pub fn resolve_target(target: &str) -> Result<String, String> {
    let cleaned = target
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_start_matches("ftp://")
        .split('/')
        .next()
        .unwrap_or(target)
        .split(':')
        .next()
        .unwrap_or(target);
    
    if cleaned.parse::<IpAddr>().is_ok() {
        return Ok(cleaned.to_string());
    }
    
    let addr = format!("{}:80", cleaned);
    match addr.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(socket_addr) = addrs.next() {
                Ok(socket_addr.ip().to_string())
            } else {
                Err(format!("Cannot resolve: {}", cleaned))
            }
        }
        Err(e) => Err(format!("DNS failed: {}", e)),
    }
}

/// Connect mode - netcat-like
pub fn connect_interactive(target: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Connecting to {}:{}...", target, port);
    
    let addr = format!("{}:{}", target, port);
    let mut stream = TcpStream::connect_timeout(
        &addr.parse()?,
        Duration::from_secs(10),
    )?;
    
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    
    println!("[+] Connected! Type input (Ctrl+C to exit):");
    println!("────────────────────────────────────────────────");
    
    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());
    
    let mut stream_clone = stream.try_clone()?;
    let read_handle = thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            match stream_clone.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    print!("{}", String::from_utf8_lossy(&buffer[..n]));
                    std::io::Write::flush(&mut std::io::stdout()).ok();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    
    for line in reader.lines() {
        match line {
            Ok(input) => {
                let data = format!("{}\r\n", input);
                if stream.write_all(data.as_bytes()).is_err() { break; }
            }
            Err(_) => break,
        }
    }
    
    let _ = read_handle.join();
    println!("\n[*] Connection closed");
    
    Ok(())
}
