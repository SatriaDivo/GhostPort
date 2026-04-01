//! Vulnerability Database Module

pub struct VulnerabilityRule {
    pub service: &'static str,
    pub max_safe_version: (u32, u32, u32), // Version di bawah ini dianggap rentan (exclusive)
    pub name: &'static str,
    pub description: &'static str,
    pub severity: &'static str,
    pub confidence: u8,
    pub impact: &'static str,
    pub recommendation: &'static str,
    pub payload_type: &'static str,
    pub payload: &'static str,
    pub steps: &'static str,
    pub expected_result: &'static str,
    pub risk_confirmed_if: &'static str,
}

pub fn get_rules() -> Vec<VulnerabilityRule> {
    vec![
        VulnerabilityRule {
            service: "openssh",
            max_safe_version: (7, 4, 0),
            name: "Outdated SSH version",
            description: "Versi OpenSSH sangat lawas dan rentan terhadap berbagai eksploit.",
            severity: "High",
            confidence: 90,
            impact: "Memungkinkan penyerang melakukan bypass autentikasi atau denial-of-service.",
            recommendation: "Lakukan upgrade daemon OpenSSH ke versi minim >= 7.4.",
            payload_type: "Banner Grabbing",
            payload: "nc -nv <TARGET_IP> 22",
            steps: "Lakukan koneksi raw TCP ke port 22, dan verifikasi header balasan.",
            expected_result: "Menerima String OpenSSH versi lama, contoh: SSH-2.0-OpenSSH_5.3",
            risk_confirmed_if: "Banner mencantumkan versi < 7.4.",
        },
        VulnerabilityRule {
            service: "nginx",
            max_safe_version: (1, 16, 0),
            name: "Outdated NGINX Server",
            description: "Web server nginx berada pada major version usang.",
            severity: "Medium",
            confidence: 85,
            impact: "Rentan terhadap HTTP Request Smuggling atau Buffer Overflow.",
            recommendation: "Lakukan update nginx minimal ke stable release 1.16 atau mainline terbaru.",
            payload_type: "HTTP Request",
            payload: "curl -I -s http://<TARGET_IP>/",
            steps: "Kirim HTTP HEAD request dan inspeksi header `Server:`",
            expected_result: "Menerima balasan dengan header `Server: nginx/1.14.0` atau di bawahnya.",
            risk_confirmed_if: "Versi nginx pada header Server kurang dari 1.16.x.",
        },
        VulnerabilityRule {
            service: "apache",
            max_safe_version: (2, 4, 49),
            name: "Vulnerable Apache HTTP Server",
            description: "Server Apache HTTP (<2.4.49) terindikasi rentan.",
            severity: "Critical",
            confidence: 95,
            impact: "Memungkinkan serangan Path Traversal (CVE-2021-41773) untuk membaca file internal server.",
            recommendation: "Segera patch dan upgrade Apache HTTP Server minimal ke versi 2.4.51+.",
            payload_type: "HTTP Request",
            payload: "curl -v --path-as-is http://<TARGET_IP>/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            steps: "Kirim payload traversal ke endpoint umum seperti /cgi-bin/. Perhatikan bahwa tool GhostPort ini harus dipakai untuk validasi resmi.",
            expected_result: "Disarankan hanya mengeksekusi ini jika memiliki izin; seharusnya mendapatkan HTTP 403 atau 404 dari server aman.",
            risk_confirmed_if: "Server mengembalikan response isi file /etc/passwd.",
        },
        VulnerabilityRule {
            service: "httpd",
            max_safe_version: (2, 4, 49),
            name: "Vulnerable Apache HTTP Server",
            description: "Server Apache HTTP (<2.4.49) terindikasi rentan.",
            severity: "Critical",
            confidence: 95,
            impact: "Memungkinkan serangan Path Traversal (CVE-2021-41773) untuk membaca file internal server.",
            recommendation: "Segera patch dan upgrade Apache HTTP Server minimal ke versi 2.4.51+.",
            payload_type: "HTTP Request",
            payload: "curl -v --path-as-is http://<TARGET_IP>/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            steps: "Kirim payload traversal untuk memvalidasi CVE-2021-41773 secara tidak merusak (membaca file lokal saja)",
            expected_result: "Mendapatkan isi file passwd.",
            risk_confirmed_if: "Server mengembalikan response isi file /etc/passwd.",
        },
        VulnerabilityRule {
            service: "vsftpd",
            max_safe_version: (2, 3, 4),
            name: "vsftpd Backdoor Vulnerability",
            description: "vsftpd 2.3.4 memiliki backdoor yang tereksploitasi luas.",
            severity: "Critical",
            confidence: 99,
            impact: "Hacker dapat memicu eksekusi shell otomatis sebagai root pada port 6200 hanya dengan memasukkan username tertentu.",
            recommendation: "Upgrade vsftpd ke versi modern (> 3.0.x) atau gunakan server SFTP alternatif.",
            payload_type: "TCP Input",
            payload: "ftp <TARGET_IP>; USER user:); PASS pass",
            steps: "Koneksikan ke port FTP dan coba login dengan smiley face pada username untuk melihat apakah port 6200 terbuka.",
            expected_result: "Koneksi biasa akan gagal login, tapi backdoor akan membuka listener root di port 6200.",
            risk_confirmed_if: "Port 6200 terbuka sesaat setelah mencoba login payload smiley.",
        },
        VulnerabilityRule {
            service: "proftpd",
            max_safe_version: (1, 3, 5),
            name: "Outdated ProFTPD Mod_Copy",
            description: "ProFTPD 1.3.5 memiliki modul mod_copy yang rentan.",
            severity: "High",
            confidence: 90,
            impact: "Penyerang tanpa otentikasi dapat melakukan copy-paste file secara acak dan mengeksekusi file PHP backdoor jika DocumentRoot terekspos.",
            recommendation: "Matikan modul mod_copy atau upgrade ProFTPD ke versi minimal 1.3.5b.",
            payload_type: "TCP Input",
            payload: "SITE CPFR /etc/passwd",
            steps: "Mencoba menjalankan instruksi SITE CPFR tanpa login (unauthenticated).",
            expected_result: "Jika rentan, server mengembalikan 350 File or directory exists.",
            risk_confirmed_if: "Menerima Response kode HTTP 350 menandakan file bisa di-copy tanpa login.",
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

pub fn check_vulnerability(service: &str, version: Option<&str>) -> Vec<crate::utils::report::Vulnerability> {
    let mut vulnerabilities = Vec::new();
    let text = match version {
        Some(v) => v,
        None => return vulnerabilities,
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
                    vulnerabilities.push(crate::utils::report::Vulnerability {
                        name: format!("{} (Detected {}.{}.{})", rule.name, parsed_ver.0, parsed_ver.1, parsed_ver.2),
                        description: rule.description.to_string(),
                        severity: rule.severity.to_string(),
                        confidence: rule.confidence,
                        impact: rule.impact.to_string(),
                        recommendation: rule.recommendation.to_string(),
                        verification: crate::utils::report::VerificationPayload {
                            verification_type: rule.payload_type.to_string(),
                            payload: rule.payload.to_string(),
                            steps: rule.steps.to_string(),
                            expected_result: rule.expected_result.to_string(),
                            risk_confirmed_if: rule.risk_confirmed_if.to_string(),
                        }
                    });
                }
            }
        }
    }

    vulnerabilities
}