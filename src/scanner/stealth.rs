//! Stealth Engine Module

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanMode {
    Stealth,
    Balanced,
    Aggressive,
}

impl std::str::FromStr for ScanMode {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "stealth" => Ok(ScanMode::Stealth),
            "balanced" => Ok(ScanMode::Balanced),
            "aggressive" => Ok(ScanMode::Aggressive),
            _ => Err(format!("Unknown mode: {}", s)),
        }
    }
}

impl std::fmt::Display for ScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanMode::Stealth => write!(f, "🕵️ Stealth"),
            ScanMode::Balanced => write!(f, "⚖️ Balanced"),
            ScanMode::Aggressive => write!(f, "⚡ Aggressive"),
        }
    }
}
