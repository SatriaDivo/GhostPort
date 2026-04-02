//! Report Module

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;

use printpdf::{Base64OrRaw, GeneratePdfOptions, PdfDocument, PdfSaveOptions};

#[derive(Clone, Debug)]
pub struct VerificationPayload {
    pub verification_type: String,
    pub payload: String,
    pub steps: String,
    pub expected_result: String,
    pub risk_confirmed_if: String,
}

#[derive(Clone, Debug)]
pub struct Vulnerability {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub confidence: u8,
    pub impact: String,
    pub recommendation: String,
    pub verification: VerificationPayload,
}

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub ip: String,
    pub port: u16,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub category: Option<String>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub plugin_findings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ScanReport {
    pub target: String,
    pub results: Vec<ScanResult>,
}

pub fn generate_scan_report(results: Vec<Vulnerability>, target_ip: &str, port: u16) {
    use colored::*;
    
    for vuln in results {
        let severity_text = vuln.severity.clone();
        
        // Colorize severity
        let severity_colored = match severity_text.to_uppercase().as_str() {
            "CRITICAL" => severity_text.red().bold(),
            "HIGH" => severity_text.red(),
            "MEDIUM" => severity_text.yellow(),
            "LOW" => severity_text.blue(),
            _ => severity_text.normal(),
        };

        println!("[{}] {}", severity_colored, vuln.name.bold());
        println!("{} {}", "Deskripsi:".bold(), vuln.description);
        
        let mut final_payload = vuln.verification.payload.clone();
        final_payload = final_payload.replace("<TARGET_IP>", target_ip);
        final_payload = final_payload.replace("<PORT>", &port.to_string());
        
        println!("{} {}", "💡 Rekomendasi Payload PoC:".yellow().bold(), final_payload.cyan());
        println!();
    }
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
        
        for v in &r.vulnerabilities {
            println!("       ⚠️  [VULN] {}", v.name);
            println!("           └─ Deskripsi : {}", v.description);
            println!("           └─ Severity  : {} | Confidence: {}%", v.severity, v.confidence);
            println!("           └─ Dampak    : {}", v.impact);
            println!("           └─ Solusi    : {}", v.recommendation);
            println!("           └─ Verifikasi: [{}] {}", v.verification.verification_type, v.verification.payload);
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
    let is_stdout = path == "stdout";
    let fmt = format_opt.to_lowercase();

    match fmt.as_str() {
        "json" => {
            let file = if is_stdout {
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
                json.push_str("      \"vulnerabilities\": [\n");
                for (vi, vuln) in r.vulnerabilities.iter().enumerate() {
                    json.push_str("        {\n");
                    json.push_str(&format!("          \"name\": \"{}\",\n", escape_json(&vuln.name)));
                    json.push_str(&format!("          \"description\": \"{}\",\n", escape_json(&vuln.description)));
                    json.push_str(&format!("          \"severity\": \"{}\",\n", escape_json(&vuln.severity)));
                    json.push_str(&format!("          \"confidence\": {},\n", vuln.confidence));
                    json.push_str(&format!("          \"impact\": \"{}\",\n", escape_json(&vuln.impact)));
                    json.push_str(&format!("          \"recommendation\": \"{}\",\n", escape_json(&vuln.recommendation)));
                    
                    json.push_str("          \"verification\": {\n");
                    json.push_str(&format!("            \"type\": \"{}\",\n", escape_json(&vuln.verification.verification_type)));
                    json.push_str(&format!("            \"payload\": \"{}\",\n", escape_json(&vuln.verification.payload)));
                    json.push_str(&format!("            \"steps\": \"{}\",\n", escape_json(&vuln.verification.steps)));
                    json.push_str(&format!("            \"expected_result\": \"{}\",\n", escape_json(&vuln.verification.expected_result)));
                    json.push_str(&format!("            \"risk_confirmed_if\": \"{}\"\n", escape_json(&vuln.verification.risk_confirmed_if)));
                    json.push_str("          }\n");
                    
                    if vi < r.vulnerabilities.len() - 1 {
                        json.push_str("        },\n");
                    } else {
                        json.push_str("        }\n");
                    }
                }
                json.push_str("      ],\n");

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
        }
        "csv" => {
            let file = if is_stdout {
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

            let mut csv = String::new();
            csv.push_str("ip,port,service,version,category,vulnerabilities,plugin_findings\n");
            
            for r in &report.results {
                let ip = escape_csv(&r.ip);
                let port = r.port.to_string();
                let svc = escape_csv(r.service.as_deref().unwrap_or(""));
                let ver = escape_csv(r.version.as_deref().unwrap_or(""));
                let cat = escape_csv(r.category.as_deref().unwrap_or(""));
                let vuln_str = escape_csv(&r.vulnerabilities.iter().map(|v| format!("{}: {}", v.name, v.recommendation)).collect::<Vec<_>>().join("; "));
                let pf = escape_csv(&r.plugin_findings.join("; "));
                
                csv.push_str(&format!("{},{},{},{},{},{},{}\n", ip, port, svc, ver, cat, vuln_str, pf));
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
        }
        "html" => {
            let html = build_html_report(report);

            if is_stdout {
                println!("{}", html);
                return;
            }

            let mut file = match File::create(path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[!] Gagal membuat file export '{}': {}", path, e);
                    return;
                }
            };

            if let Err(e) = file.write_all(html.as_bytes()) {
                eprintln!("[!] Gagal menulis ke file output: {}", e);
            } else {
                println!("[+] Berhasil export ke {} (Format: HTML)", path);
            }
        }
        "pdf" => {
            if is_stdout {
                eprintln!("[!] Format PDF tidak mendukung stdout. Gunakan output file.");
                return;
            }

            let html = build_html_report(report);
            let mut warnings = Vec::new();
            let options = GeneratePdfOptions::default();

            let fonts: BTreeMap<String, Base64OrRaw> = BTreeMap::new();
            let images: BTreeMap<String, Base64OrRaw> = BTreeMap::new();

            let pdf_result = PdfDocument::from_html(&html, &images, &fonts, &options, &mut warnings);
            let pdf = match pdf_result {
                Ok(doc) => doc,
                Err(e) => {
                    eprintln!("[!] Gagal generate PDF: {}", e);
                    return;
                }
            };

            let save_options = PdfSaveOptions::default();
            let bytes = pdf.save(&save_options, &mut warnings);

            match File::create(path) {
                Ok(mut file) => {
                    if let Err(e) = file.write_all(&bytes) {
                        eprintln!("[!] Gagal menulis PDF ke file output: {}", e);
                    } else {
                        println!("[+] Berhasil export ke {} (Format: PDF)", path);
                    }
                }
                Err(e) => {
                    eprintln!("[!] Gagal membuat file export '{}': {}", path, e);
                }
            }
        }
        "txt" => {
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
                for v in &r.vulnerabilities {
                    txt.push_str(&format!("       [VULN] {} (Severity: {})\n", v.name, v.severity));
                    txt.push_str(&format!("         - Deskripsi : {}\n", v.description));
                    txt.push_str(&format!("         - Dampak    : {}\n", v.impact));
                    txt.push_str(&format!("         - Solusi    : {}\n", v.recommendation));
                    txt.push_str(&format!("         - Verifikasi: [{}] {}\n", v.verification.verification_type, v.verification.payload));
                }
                for pf in &r.plugin_findings {
                    txt.push_str(&format!("       Plugin: {}\n", pf));
                }
                txt.push('\n');
            }
            
            if is_stdout {
                println!("{}", txt);
            } else {
                match File::create(path) {
                    Ok(mut f) => {
                        if let Err(e) = f.write_all(txt.as_bytes()) {
                            eprintln!("[!] Gagal menulis ke file output: {}", e);
                        } else {
                            println!("[+] Berhasil export ke {} (Format: TXT)", path);
                        }
                    }
                    Err(e) => {
                        eprintln!("[!] Gagal membuat file export '{}': {}", path, e);
                    }
                }
            }
        }
        _ => {
            eprintln!("[!] Format '{}' tidak valid, fallback ke 'txt'", fmt);
            export_report(report, "txt", path);
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

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn severity_class(severity: &str) -> &'static str {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => "severity-critical",
        "HIGH" => "severity-high",
        "MEDIUM" => "severity-medium",
        "LOW" => "severity-low",
        _ => "severity-info",
    }
}

fn build_html_report(report: &ScanReport) -> String {
    let open_count = report.results.len();
    let vuln_count: usize = report.results.iter().map(|result| result.vulnerabilities.len()).sum();
    let plugin_count: usize = report.results.iter().map(|result| result.plugin_findings.len()).sum();

    let mut html = String::new();
    html.push_str(r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GhostPort Scan Report</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:radial-gradient(circle at top,#14213d 0,#0b1220 40%,#050816 100%);color:#e5eefc;line-height:1.6}
.wrap{max-width:1200px;margin:0 auto;padding:40px 20px 56px}
.hero{background:linear-gradient(135deg,rgba(40,68,122,.9),rgba(10,16,31,.95));border:1px solid rgba(255,255,255,.08);border-radius:24px;padding:32px;box-shadow:0 24px 80px rgba(0,0,0,.35)}
.eyebrow{letter-spacing:.18em;text-transform:uppercase;font-size:12px;color:#90b4ff}
.title{margin:10px 0 8px;font-size:42px;line-height:1.1}
.subtitle{margin:0;color:#bfd1f5;max-width:780px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin:22px 0 0}
.card{background:rgba(8,14,28,.78);border:1px solid rgba(255,255,255,.08);border-radius:20px;padding:18px 20px;backdrop-filter:blur(8px)}
.stat-label{font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:#8ca3d1}
.stat-value{font-size:28px;font-weight:700;margin-top:4px}
.section{margin-top:28px}
.section h2{margin:0 0 14px;font-size:24px}
.result{margin-bottom:18px;border:1px solid rgba(255,255,255,.08);border-radius:20px;overflow:hidden;background:rgba(7,12,24,.86)}
.result-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;padding:18px 20px;background:linear-gradient(90deg,rgba(32,54,95,.75),rgba(14,20,34,.85));border-bottom:1px solid rgba(255,255,255,.08)}
.endpoint{font-size:18px;font-weight:700}
.meta{color:#a9bddf;font-size:13px}
.pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em}
.severity-critical{background:rgba(255,66,66,.16);color:#ff8a8a}
.severity-high{background:rgba(255,124,58,.16);color:#ffb089}
.severity-medium{background:rgba(255,196,61,.16);color:#ffd86f}
.severity-low{background:rgba(96,180,255,.16);color:#9bd0ff}
.severity-info{background:rgba(155,175,255,.16);color:#c7d4ff}
.result-body{padding:18px 20px}
.mono{background:#08101e;border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:14px 16px;overflow:auto;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px;color:#dce8ff;white-space:pre-wrap;word-break:break-word}
.kv{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:14px 0}
.kv .item{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:14px;padding:12px 14px}
.kv .k{font-size:12px;color:#86a0cc;text-transform:uppercase;letter-spacing:.1em}
.kv .v{margin-top:4px;font-weight:600}
.vulns{display:grid;gap:14px;margin-top:16px}
.vuln{border:1px solid rgba(255,255,255,.08);border-radius:18px;padding:16px;background:rgba(255,255,255,.03)}
.vuln h3{margin:0 0 8px;font-size:18px}
.vuln p{margin:6px 0 0;color:#cfe0ff}
.label{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:#86a0cc;margin-top:12px;margin-bottom:6px}
.footer{margin-top:24px;color:#87a0ca;font-size:13px;text-align:center}
.empty{padding:24px;text-align:center;color:#9eb4dd;border:1px dashed rgba(255,255,255,.12);border-radius:18px;background:rgba(255,255,255,.02)}
@media (max-width:900px){.grid,.kv{grid-template-columns:1fr 1fr}.title{font-size:34px}}
@media (max-width:640px){.grid,.kv{grid-template-columns:1fr}.hero,.result-head,.result-body{padding:18px}.title{font-size:28px}}
</style>
</head>
<body>
<div class="wrap">
<section class="hero">
<div class="eyebrow">GhostPort Network Reconnaissance</div>
<h1 class="title">Scan Report</h1>
<p class="subtitle">Generated report for audit review, including open services, vulnerability intelligence, verification payloads, and plugin findings.</p>
<div class="grid">
<div class="card"><div class="stat-label">Target</div><div class="stat-value">"#);
    html.push_str(&escape_html(&report.target));
    html.push_str(&format!(r#"</div></div>
<div class="card"><div class="stat-label">Open Ports</div><div class="stat-value">{}</div></div>
<div class="card"><div class="stat-label">Vulnerabilities</div><div class="stat-value">{}</div></div>
<div class="card"><div class="stat-label">Plugin Findings</div><div class="stat-value">{}</div></div>
</div>
</section>

<section class="section">
<h2>Overview</h2>
<div class="kv">
<div class="item"><div class="k">Services Detected</div><div class="v">{}</div></div>
<div class="item"><div class="k">Report Type</div><div class="v">HTML Audit Report</div></div>
</div>
</section>

{}{}

<div class="footer">GhostPort audit report generated from scan results.</div>
</div>
</body>
</html>
"#, open_count, vuln_count, plugin_count, open_count, build_results_html(report), build_plugins_html(report)));
    html
}

fn build_results_html(report: &ScanReport) -> String {
    if report.results.is_empty() {
        return r#"<section class="section"><div class="empty">No open ports were found for this target.</div></section>"#.to_string();
    }

    let mut html = String::new();
    html.push_str(r#"<section class="section"><h2>Open Services</h2>"#);

    for result in &report.results {
        let service = result.service.as_deref().unwrap_or("Unknown");
        let version = result.version.as_deref().unwrap_or("N/A");
        let category = result.category.as_deref().unwrap_or("N/A");
        let banner = result.banner.as_deref().unwrap_or("No banner captured");

        html.push_str(r#"<article class="result">"#);
        html.push_str(&format!(r#"<div class="result-head"><div><div class="endpoint">{}:{}</div><div class="meta">{} • {}</div></div><div class="pill severity-info">Service Report</div></div><div class="result-body">"#, escape_html(&result.ip), result.port, escape_html(service), escape_html(category)));
        html.push_str(r#"<div class="kv">"#);
        html.push_str(&format!(r#"<div class="item"><div class="k">Version</div><div class="v">{}</div></div>"#, escape_html(version)));
        html.push_str(&format!(r#"<div class="item"><div class="k">Banner</div><div class="v">{}</div></div>"#, escape_html(banner)));
        html.push_str(r#"</div>"#);

        if !result.vulnerabilities.is_empty() {
            html.push_str(r#"<div class="vulns"><h2 style="margin:0 0 2px;font-size:22px;">Vulnerabilities</h2>"#);
            for vuln in &result.vulnerabilities {
                let severity = vuln.severity.to_uppercase();
                let payload = vuln
                    .verification
                    .payload
                    .replace("<TARGET_IP>", &result.ip)
                    .replace("<PORT>", &result.port.to_string());

                html.push_str(r#"<section class="vuln">"#);
                html.push_str(&format!(r#"<div class="pill {}">{}</div>"#, severity_class(&severity), escape_html(&severity)));
                html.push_str(&format!(r#"<h3>{}</h3>"#, escape_html(&vuln.name)));
                html.push_str(&format!(r#"<p>{}</p>"#, escape_html(&vuln.description)));
                html.push_str(r#"<div class="kv">"#);
                html.push_str(&format!(r#"<div class="item"><div class="k">Confidence</div><div class="v">{}%</div></div>"#, vuln.confidence));
                html.push_str(&format!(r#"<div class="item"><div class="k">Impact</div><div class="v">{}</div></div>"#, escape_html(&vuln.impact)));
                html.push_str(&format!(r#"<div class="item"><div class="k">Recommendation</div><div class="v">{}</div></div>"#, escape_html(&vuln.recommendation)));
                html.push_str(&format!(r#"<div class="item"><div class="k">Verification Type</div><div class="v">{}</div></div>"#, escape_html(&vuln.verification.verification_type)));
                html.push_str(r#"</div>"#);
                html.push_str(r#"<div class="label">Verification Payload</div><div class="mono">"#);
                html.push_str(&escape_html(&payload));
                html.push_str(r#"</div>"#);
                html.push_str(&format!(r#"<div class="label">Steps</div><div class="mono">{}</div>"#, escape_html(&vuln.verification.steps)));
                html.push_str(&format!(r#"<div class="label">Expected Result</div><div class="mono">{}</div>"#, escape_html(&vuln.verification.expected_result)));
                html.push_str(&format!(r#"<div class="label">Risk Confirmed If</div><div class="mono">{}</div>"#, escape_html(&vuln.verification.risk_confirmed_if)));
                html.push_str(r#"</section>"#);
            }
            html.push_str(r#"</div>"#);
        }

        if !result.plugin_findings.is_empty() {
            html.push_str(r#"<div class="label">Plugin Findings</div><div class="mono">"#);
            for finding in &result.plugin_findings {
                html.push_str(&escape_html(finding));
                html.push_str("<br>");
            }
            html.push_str(r#"</div>"#);
        }

        html.push_str(r#"</div></article>"#);
    }

    html.push_str(r#"</section>"#);
    html
}

fn build_plugins_html(_report: &ScanReport) -> String {

    String::new()
}