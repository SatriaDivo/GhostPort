//! Report Module

use std::fs::File;
use std::io::Write;

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub ip: String,
    pub port: u16,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub category: Option<String>,
    pub warnings: Vec<String>,
    pub plugin_findings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ScanReport {
    pub target: String,
    pub results: Vec<ScanResult>,
}

pub fn render_cli(report: &ScanReport, duration_secs: f64, ports_scanned_count: usize) {
    for r in &report.results {
        let svc = r.service.as_deref().unwrap_or("Unknown");
        let ver = r.version.as_deref()
            .map(|v| format!(" ({})", v))
            .unwrap_or_default();
        let cat = r.category.as_deref().unwrap_or("");
        
        println!("[OPEN] {}:{} → {}{} {}", r.ip, r.port, svc, ver, cat);
        
        if let Some(ref b) = r.banner {
            // Tampilkan baris pertama saja dari banner
            let short: String = b.lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(60)
                .collect();
            println!("       └─ {}", short);
        }
        
        for w in &r.warnings {
            println!("       ⚠️  {}", w);
        }
        
        for p in &r.plugin_findings {
            println!("       {}", p);
        }
        println!();
    }
    
    println!("════════════════════════════════════════════════════════════════");
    println!("[+] Scan Complete! Duration: {:.2}s", duration_secs);
    let open_count = report.results.len();
    println!("[+] Ports: {} scanned, {} open", ports_scanned_count, open_count);
}

pub fn export_report(report: &ScanReport, format_opt: &str, path: &str) {
    let mut is_stdout = false;
    let mut file = if path == "stdout" {
        is_stdout = true;
        // Kita hanya pakai dummy karena kalau stdout kita tidak nulis ke file
        None
    } else {
        match File::create(path) {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("[!] Gagal membuat file export '{}': {}", path, e);
                return;
            }
        }
    };

    let f = format_opt.to_lowercase();
    let fmt = if !["json", "csv", "txt"].contains(&f.as_str()) {
        eprintln!("[!] Format '{}' tidak valid, fallback ke 'txt'", f);
        "txt"
    } else {
        f.as_str()
    };

    match fmt {
        "json" => {
            let mut json = String::new();
            json.push_str("{\n");
            json.push_str(&format!("  \"target\": \"{}\",\n", escape_json(&report.target)));
            json.push_str("  \"results\": [\n");
            
            for (i, r) in report.results.iter().enumerate() {
                json.push_str("    {\n");
                json.push_str(&format!("      \"ip\": \"{}\",\n", escape_json(&r.ip)));
                json.push_str(&format!("      \"port\": {},\n", r.port));
                
                if let Some(s) = &r.service {
                    json.push_str(&format!("      \"service\": \"{}\",\n", escape_json(s)));
                } else {
                    json.push_str("      \"service\": null,\n");
                }
                
                if let Some(v) = &r.version {
                    json.push_str(&format!("      \"version\": \"{}\",\n", escape_json(v)));
                } else {
                    json.push_str("      \"version\": null,\n");
                }
                
                if let Some(b) = &r.banner {
                    json.push_str(&format!("      \"banner\": \"{}\",\n", escape_json(b)));
                } else {
                    json.push_str("      \"banner\": null,\n");
                }

                if let Some(c) = &r.category {
                    json.push_str(&format!("      \"category\": \"{}\",\n", escape_json(c)));
                } else {
                    json.push_str("      \"category\": null,\n");
                }
                
                // Array fields
                json.push_str("      \"warnings\": [");
                let w_str: Vec<String> = r.warnings.iter().map(|w| format!("\"{}\"", escape_json(w))).collect();
                json.push_str(&w_str.join(", "));
                json.push_str("],\n");

                json.push_str("      \"plugin_findings\": [");
                let pf_str: Vec<String> = r.plugin_findings.iter().map(|p| format!("\"{}\"", escape_json(p))).collect();
                json.push_str(&pf_str.join(", "));
                json.push_str("]\n");
                
                if i < report.results.len() - 1 {
                    json.push_str("    },\n");
                } else {
                    json.push_str("    }\n");
                }
            }
            
            json.push_str("  ]\n}");
            if is_stdout {
                println!("{}", json);
            } else if let Some(mut f) = file {
                if let Err(e) = f.write_all(json.as_bytes()) {
                    eprintln!("[!] Gagal menulis ke file output: {}", e);
                } else {
                    println!("[+] Berhasil export ke {} (Format: JSON)", path);
                }
            }
        },
        "csv" => {
            let mut csv = String::new();
            csv.push_str("ip,port,service,version,category,warnings,plugin_findings\n");
            
            for r in &report.results {
                let ip = escape_csv(&r.ip);
                let port = r.port.to_string();
                let svc = escape_csv(r.service.as_deref().unwrap_or(""));
                let ver = escape_csv(r.version.as_deref().unwrap_or(""));
                let cat = escape_csv(r.category.as_deref().unwrap_or(""));
                let warn = escape_csv(&r.warnings.join("; "));
                let pf = escape_csv(&r.plugin_findings.join("; "));
                
                csv.push_str(&format!("{},{},{},{},{},{},{}\n", ip, port, svc, ver, cat, warn, pf));
            }
            
            if is_stdout {
                println!("{}", csv);
            } else if let Some(mut f) = file {
                if let Err(e) = f.write_all(csv.as_bytes()) {
                    eprintln!("[!] Gagal menulis ke file output: {}", e);
                } else {
                    println!("[+] Berhasil export ke {} (Format: CSV)", path);
                }
            }
        },
        _ => {
            // txt format
            let mut txt = String::new();
            txt.push_str(&format!("Scan Report for {}\n", report.target));
            txt.push_str("==============================================\n\n");
            
            for r in &report.results {
                let svc = r.service.as_deref().unwrap_or("Unknown");
                txt.push_str(&format!("[OPEN] {}:{} -> {}\n", r.ip, r.port, svc));
                
                if let Some(v) = &r.version {
                    txt.push_str(&format!("       Version: {}\n", v));
                }
                if let Some(c) = &r.category {
                    txt.push_str(&format!("       Category: {}\n", c));
                }
                if let Some(b) = &r.banner {
                    txt.push_str(&format!("       Banner: {}\n", b.replace('\n', " ")));
                }
                for w in &r.warnings {
                    txt.push_str(&format!("       Warning: {}\n", w));
                }
                for pf in &r.plugin_findings {
                    txt.push_str(&format!("       Plugin: {}\n", pf));
                }
                txt.push('\n');
            }
            
            if is_stdout {
                println!("{}", txt);
            } else if let Some(mut f) = file {
                if let Err(e) = f.write_all(txt.as_bytes()) {
                    eprintln!("[!] Gagal menulis ke file output: {}", e);
                } else {
                    println!("[+] Berhasil export ke {} (Format: TXT)", path);
                }
            }
        }
    }
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r")
}

fn escape_csv(s: &str) -> String {
    let escaped = s.replace('"', "\"\"");
    if escaped.contains(',') || escaped.contains('"') || escaped.contains('\n') || escaped.contains('\r') {
        format!("\"{}\"", escaped)
    } else {
        escaped
    }
}