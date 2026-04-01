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
pub fn analyze_service(port: u16, service: &str, banner: Option<&str>) -> Vec<crate::utils::report::Vulnerability> {
    let mut vulnerabilities = Vec::new();
    let svc_lower = service.to_lowercase();
    let banner_lower = banner.unwrap_or("").to_lowercase();
    
    // SSH version check
    if svc_lower.contains("ssh") {
        if banner_lower.contains("openssh_5") || banner_lower.contains("openssh_6") 
           || banner_lower.contains("openssh_4") {
            vulnerabilities.push(crate::utils::report::Vulnerability {
                name: "Outdated SSH version".to_string(),
                description: "Terdeteksi daemon OpenSSH lawas (versi 4/5/6) terekspos ke publik.".to_string(),
                severity: "High".to_string(),
                confidence: 90,
                impact: "Kerentanan pada protokol dapat dimanfaatkan untuk DoS atau membocorkan data parsial user enumeration.".to_string(),
                recommendation: "Lakukan upgrade daemon ke versi modern >= 7.x dan pastikan autentikasi berbasis key.".to_string(),
                verification: crate::utils::report::VerificationPayload {
                    verification_type: "Banner Grabbing".to_string(),
                    payload: format!("nc -nv <TARGET_IP> {}", port),
                    steps: "Kirim koneksi ke port SSH dan analisis output string identifikasinya".to_string(),
                    expected_result: "String balasan menunjukkan OpenSSH veri 4,5,6".to_string(),
                    risk_confirmed_if: "Versi software sesuai namun belum disembunyikan".to_string(),
                },
            });
        }
    }
    
    // Telnet warning
    if port == 23 || svc_lower.contains("telnet") {
        vulnerabilities.push(crate::utils::report::Vulnerability {
            name: "Telnet is in use (Cleartext Protocol)".to_string(),
            description: "Protokol Telnet tidak mendukung enkripsi. Data dikirim dalam format plain-text.".to_string(),
            severity: "High".to_string(),
            confidence: 100,
            impact: "Aktor jaringan (man-in-the-middle) dapat menyadap lalu lintas jaringan dan mencuri password autentikasi.".to_string(),
            recommendation: "Segera matikan layanan Telnet dan bermigrasi sepenuhnya ke protokol terenkripsi (SSH).".to_string(),
            verification: crate::utils::report::VerificationPayload {
                verification_type: "Credential Sniffing (Passive)".to_string(),
                payload: "Wireshark / tcpdump -i <interface> port 23".to_string(),
                steps: "Monitor packet jaringan saat login admin terjadi.".to_string(),
                expected_result: "Password terlihat dalam format clear-text.".to_string(),
                risk_confirmed_if: "Kredensial valid dapat disadap dan dimanfaatkan.".to_string(),
            },
        });
    }
    
    // Database exposure
    if matches!(port, 3306 | 5432 | 27017 | 6379) {
        vulnerabilities.push(crate::utils::report::Vulnerability {
            name: "Exposed Database Port".to_string(),
            description: format!("Layanan database (default) terpapar pada port {}.", port),
            severity: "High".to_string(),
            confidence: 100,
            impact: "Visibilitas database eksternal membuka risiko serangan Brute Force, DoS, atau eksploitasi Remote Code Execution (RCE).".to_string(),
            recommendation: "Tutup port database dari publik (firewall/WAF). Pastikan instance hanya menerima koneksi dari IP aplikasi yang diizinkan (internal).".to_string(),
            verification: crate::utils::report::VerificationPayload {
                verification_type: "Service Probe".to_string(),
                payload: format!("nc -vz <TARGET_IP> {}", port),
                steps: "Check apakah koneksi jaringan bisa terbentuk tanpa authentikasi firewall.".to_string(),
                expected_result: "Connection Succeeded.".to_string(),
                risk_confirmed_if: "Penyerang dari jaringan luar (internet publik) dapat melakukan initiate connection.".to_string(),
            },
        });
    }
    
    // FTP cleartext
    if port == 21 || svc_lower.contains("ftp") {
        vulnerabilities.push(crate::utils::report::Vulnerability {
            name: "FTP uses cleartext communication".to_string(),
            description: "Protokol File Transfer (FTP) reguler mengindikasikan koneksi tidak terenkripsi (port 21).".to_string(),
            severity: "High".to_string(),
            confidence: 90,
            impact: "Pertukaran kredensial maupun transfer file (Command/Data) terancam bocor via network sniffing.".to_string(),
            recommendation: "Mengkonfigurasi layanan agar memakai FTP over TLS/SSL (FTPS) atau integrasikan file transfer (SFTP).".to_string(),
            verification: crate::utils::report::VerificationPayload {
                verification_type: "Anonymous Try".to_string(),
                payload: format!("ftp <TARGET_IP> {} ; prompt: Anonymous", port),
                steps: "Coba login sebagai Anonymous user, jika gagal evaluasi apakah packet sniffer dapat membaca plaintext transfer.".to_string(),
                expected_result: "Anonymous login success ATAU packet cleartext ter-capture.".to_string(),
                risk_confirmed_if: "Mendapat akses masuk ke FTP server pubik.".to_string(),
            },
        });
    }
    
    // VNC
    if port == 5900 || svc_lower.contains("vnc") {
        vulnerabilities.push(crate::utils::report::Vulnerability {
            name: "VNC Service Exposed".to_string(),
            description: "Akses graphical desktop control VNC ditemukan terekspos secara eksternal.".to_string(),
            severity: "High".to_string(),
            confidence: 85,
            impact: "VNC umumnya mudah disusupi menggunakan credential stuffing atau brute force password yang lemah.".to_string(),
            recommendation: "Batasi akses ke VNC (lewat tunneling via VPN atau SSH) serta aktifkan strong authentication.".to_string(),
            verification: crate::utils::report::VerificationPayload {
                verification_type: "Brute Force Warning".to_string(),
                payload: "vncviewer <TARGET_IP>:5900".to_string(),
                steps: "Coba lakukan koneksi dengan password standar seperti 'password'/'123456'".to_string(),
                expected_result: "Dapat berinteraksi dengan Desktop Environment user.".to_string(),
                risk_confirmed_if: "User authentication lemah.".to_string(),
            },
        });
    }
    
    // Rule-Based Vulnerability Intelligence
    let mut db_vulns = crate::intelligence::vuln_db::check_vulnerability(service, banner);
    vulnerabilities.append(&mut db_vulns);
    
    vulnerabilities
}
