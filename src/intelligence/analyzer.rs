//! Intelligence Analyzer Module

/// Kategorisasi port ke service category
pub fn categorize_port(port: u16) -> String {
    match port {
        80 | 443 | 8080 | 8443 | 8000 | 3000 | 5000 => "🌐 Web".to_string(),
        22 | 23 | 3389 | 5900 => "🔐 Remote Access".to_string(),
        3306 | 5432 | 27017 | 6379 | 1433 => "🗄️ Database".to_string(),
        25 | 110 | 143 | 465 | 587 | 993 | 995 => "📧 Mail".to_string(),
        21 | 69 | 445 | 139 => "📁 File Transfer".to_string(),
        53 | 123 | 161 | 389 => "🔌 Infrastructure".to_string(),
        _ => "❓ Unknown".to_string(),
    }
}

/// Analyze service dan generate warnings
pub fn analyze_service(port: u16, service: &str, banner: Option<&str>) -> Vec<String> {
    let mut warnings = Vec::new();
    let svc_lower = service.to_lowercase();
    let banner_lower = banner.unwrap_or("").to_lowercase();
    
    // SSH version check
    if svc_lower.contains("ssh") {
        if banner_lower.contains("openssh_5") || banner_lower.contains("openssh_6") 
           || banner_lower.contains("openssh_4") {
            warnings.push("🟠 Outdated SSH version".to_string());
        }
    }
    
    // Telnet warning
    if port == 23 || svc_lower.contains("telnet") {
        warnings.push("🔴 Telnet is cleartext!".to_string());
    }
    
    // Database exposure
    if matches!(port, 3306 | 5432 | 27017 | 6379) {
        warnings.push("🟡 Database exposed".to_string());
    }
    
    // FTP cleartext
    if port == 21 || svc_lower.contains("ftp") {
        warnings.push("🟡 FTP uses cleartext".to_string());
    }
    
    // VNC
    if port == 5900 || svc_lower.contains("vnc") {
        warnings.push("🟡 VNC exposed".to_string());
    }
    
    warnings
}
