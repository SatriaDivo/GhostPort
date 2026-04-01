//! Vulnerability Database Module

pub struct VulnerabilityRule {
    pub service: &'static str,
    pub max_safe_version: (u32, u32, u32), // Version di bawah ini dianggap rentan (exclusive)
    pub warning_msg: &'static str,
}

pub fn get_rules() -> Vec<VulnerabilityRule> {
    vec![
        VulnerabilityRule {
            service: "openssh",
            max_safe_version: (7, 4, 0),
            warning_msg: "Outdated SSH version (possible vulnerabilities)",
        },
        VulnerabilityRule {
            service: "nginx",
            max_safe_version: (1, 16, 0),
            warning_msg: "Outdated nginx version",
        },
        VulnerabilityRule {
            service: "apache",
            max_safe_version: (2, 4, 49),
            warning_msg: "Known vulnerable Apache version",
        },
        VulnerabilityRule {
            service: "httpd",
            max_safe_version: (2, 4, 49),
            warning_msg: "Known vulnerable Apache version",
        },
        VulnerabilityRule {
            service: "vsftpd",
            max_safe_version: (2, 3, 4),
            warning_msg: "Known vulnerable vsftpd version (backdoor risk)",
        },
        VulnerabilityRule {
            service: "proftpd",
            max_safe_version: (1, 3, 5),
            warning_msg: "Outdated ProFTPD version",
        },
    ]
}

/// Parse versi dari text berdasarkan keyword service
/// Contoh: "Server: nginx/1.14.0" dengan keyword "nginx" -> (1, 14, 0)
fn parse_version(keyword: &str, text: &str) -> Option<(u32, u32, u32)> {
    let lower_text = text.to_lowercase();
    let lower_kw = keyword.to_lowercase();
    
    // Cari index kata service, mulai ekstrak angka setelahnya
    let start_idx = match lower_text.find(&lower_kw) {
        Some(idx) => idx + lower_kw.len(),
        None => 0,
    };
    
    let relevant_text = &text[start_idx..];
    
    let mut parts = Vec::new();
    let mut current_num = String::new();
    
    for c in relevant_text.chars() {
        if c.is_ascii_digit() {
            current_num.push(c);
        } else if c == '.' || c == '_' || c == '-' || c == '/' {
            if !current_num.is_empty() {
                if let Ok(num) = current_num.parse::<u32>() {
                    parts.push(num);
                }
                current_num.clear();
            }
        } else {
            // Hentikan jika ketemu karakter lain tapi kita udah dapat minimal 1 digit awal versi
            if !current_num.is_empty() {
                if let Ok(num) = current_num.parse::<u32>() {
                    parts.push(num);
                }
                current_num.clear();
            }
            if !parts.is_empty() {
                break;
            }
        }
        
        if parts.len() >= 3 {
            break;
        }
    }
    
    if !current_num.is_empty() && parts.len() < 3 {
        if let Ok(num) = current_num.parse::<u32>() {
            parts.push(num);
        }
    }
    
    if parts.is_empty() {
        return None;
    }
    
    let major = *parts.get(0).unwrap_or(&0);
    let minor = *parts.get(1).unwrap_or(&0);
    let patch = *parts.get(2).unwrap_or(&0);
    
    Some((major, minor, patch))
}

pub fn check_vulnerability(service: &str, version: Option<&str>) -> Option<String> {
    let text = match version {
        Some(v) => v,
        None => return Some("Version not detected (unable to verify safety)".to_string()),
    };

    let rules = get_rules();
    let service_lower = service.to_lowercase();
    let text_lower = text.to_lowercase();

    for rule in rules {
        // Cocokkan apakah rule berlaku untuk service yang discan
        if service_lower.contains(rule.service) || text_lower.contains(rule.service) {
            
            // Coba parse versinya
            if let Some(parsed_ver) = parse_version(rule.service, text) {
                // Return tuple comparison checking (major, minor, patch)
                if parsed_ver < rule.max_safe_version {
                    return Some(format!(
                        "{} (Detected: {}.{}.{})",
                        rule.warning_msg, parsed_ver.0, parsed_ver.1, parsed_ver.2
                    ));
                }
            }
        }
    }

    None
}