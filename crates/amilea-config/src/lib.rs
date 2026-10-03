//! Import external emulator configuration without inheriting emulator runtime policy.

use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportStatus { Supported, Ignored, Unsupported, Unknown }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedOption {
    pub key: String,
    pub value: String,
    pub status: ImportStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsUaeConfig {
    pub amiga_model: Option<String>,
    pub chip_memory_kib: Option<u32>,
    pub kickstart_file: Option<String>,
    pub options: BTreeMap<String, String>,
    pub diagnostics: Vec<ImportedOption>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("line {line}: expected key = value")]
    InvalidLine { line: usize },
    #[error("line {line}: invalid integer for {key}")]
    InvalidInteger { line: usize, key: String },
}

pub fn parse_fs_uae(input: &str) -> Result<FsUaeConfig, ConfigError> {
    let mut config=FsUaeConfig::default();
    for (index, raw) in input.lines().enumerate() {
        let line=index+1;
        let trimmed=raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') { continue; }
        let (key,value)=trimmed.split_once('=').ok_or(ConfigError::InvalidLine { line })?;
        let key=key.trim().to_ascii_lowercase();
        let value=value.trim().to_string();
        let status=match key.as_str() {
            "amiga_model" => { config.amiga_model=Some(value.clone()); ImportStatus::Supported }
            "chip_memory" => {
                config.chip_memory_kib=Some(value.parse().map_err(|_| ConfigError::InvalidInteger { line, key:key.clone() })?);
                ImportStatus::Supported
            }
            "kickstart_file" => { config.kickstart_file=Some(value.clone()); ImportStatus::Supported }
            "fullscreen" | "window_width" | "window_height" => ImportStatus::Ignored,
            key if key.starts_with("uae_") => ImportStatus::Unsupported,
            _ => ImportStatus::Unknown,
        };
        config.options.insert(key.clone(),value.clone());
        config.diagnostics.push(ImportedOption { key, value, status });
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_machine_memory_and_rom_reference() {
        let config=parse_fs_uae("# A500\namiga_model = A500\nchip_memory = 512\nkickstart_file = Kickstarts/kick13.rom\n").unwrap();
        assert_eq!(config.amiga_model.as_deref(),Some("A500"));
        assert_eq!(config.chip_memory_kib,Some(512));
        assert_eq!(config.kickstart_file.as_deref(),Some("Kickstarts/kick13.rom"));
    }

    #[test]
    fn preserves_ignored_unsupported_and_unknown_options_for_explanation() {
        let config=parse_fs_uae("fullscreen = 0\nuae_cpu_speed = max\nmystery = yes\n").unwrap();
        assert_eq!(config.diagnostics[0].status,ImportStatus::Ignored);
        assert_eq!(config.diagnostics[1].status,ImportStatus::Unsupported);
        assert_eq!(config.diagnostics[2].status,ImportStatus::Unknown);
        assert_eq!(config.options["uae_cpu_speed"],"max");
    }

    #[test]
    fn rejects_malformed_lines_and_bad_numbers() {
        assert_eq!(parse_fs_uae("amiga_model A500"),Err(ConfigError::InvalidLine{line:1}));
        assert_eq!(parse_fs_uae("chip_memory = lots"),Err(ConfigError::InvalidInteger{line:1,key:"chip_memory".into()}));
    }
}
