//! Service Detection Module

/// Detect service dari port dan banner
/// Return: (service_name, version)
pub fn detect_service(port: u16, banner: Option<&str>) -> (String, Option<String>) {
    let default_svc = get_default_service(port);
    
    if let Some(b) = banner {
        let lower = b.to_lowercase();
        
        // SSH
        if lower.starts_with("ssh-") {
            if let Some(software) = b.split('-').nth(2) {
                let clean: String = software.split_whitespace().next().unwrap_or(software).to_string();
                return ("SSH".to_string(), Some(clean));
            }
            return ("SSH".to_string(), None);
        }
        
        // HTTP
        if lower.contains("http/") {
            if lower.contains("nginx") {
                let ver = extract_version(&lower, "nginx/");
                return ("nginx".to_string(), ver);
            }
            if lower.contains("apache") {
                let ver = extract_version(&lower, "apache/");
                return ("Apache".to_string(), ver);
            }
            return ("HTTP".to_string(), None);
        }
        
        // FTP
        if lower.starts_with("220") && (lower.contains("ftp") || port == 21) {
            if lower.contains("vsftpd") { return ("vsftpd".to_string(), None); }
            if lower.contains("proftpd") { return ("ProFTPD".to_string(), None); }
            return ("FTP".to_string(), None);
        }
        
        // SMTP
        if lower.starts_with("220") && lower.contains("smtp") {
            return ("SMTP".to_string(), None);
        }
    }
    
    (default_svc.to_string(), None)
}

fn extract_version(text: &str, prefix: &str) -> Option<String> {
    if let Some(idx) = text.find(prefix) {
        let start = idx + prefix.len();
        let ver: String = text[start..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '.')
            .collect();
        if !ver.is_empty() { return Some(ver); }
    }
    None
}

fn get_default_service(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        8080 => "HTTP-Proxy",
        27017 => "MongoDB",
        _ => "Unknown",
    }
}
