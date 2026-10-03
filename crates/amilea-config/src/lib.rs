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


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuModel { M68000, M68010, M68020, M68030, M68040, M68060 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chipset { Ocs, Ecs, Aga }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoStandard { Pal, Ntsc }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RomReference { pub path: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmileaMachineConfig {
    pub model: String,
    pub cpu: CpuModel,
    pub chipset: Chipset,
    pub video: VideoStandard,
    pub chip_memory_kib: u32,
    pub slow_memory_kib: u32,
    pub fast_memory_kib: u32,
    pub rom: Option<RomReference>,
}

impl Default for AmileaMachineConfig {
    fn default() -> Self {
        Self { model:"A500".into(), cpu:CpuModel::M68000, chipset:Chipset::Ocs,
            video:VideoStandard::Pal, chip_memory_kib:512, slow_memory_kib:0,
            fast_memory_kib:0, rom:None }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NormalizeError {
    #[error("unsupported Amiga model {model}")]
    UnsupportedModel { model: String },
}

impl FsUaeConfig {
    pub fn normalize(&self) -> Result<AmileaMachineConfig, NormalizeError> {
        let model=self.amiga_model.as_deref().unwrap_or("A500").to_ascii_uppercase();
        let mut out=match model.as_str() {
            "A500" => AmileaMachineConfig::default(),
            "A500+" | "A500PLUS" => AmileaMachineConfig {
                model:"A500+".into(), chipset:Chipset::Ecs, chip_memory_kib:1024,
                ..AmileaMachineConfig::default()
            },
            "A1200" => AmileaMachineConfig {
                model:"A1200".into(), cpu:CpuModel::M68020, chipset:Chipset::Aga,
                chip_memory_kib:2048, ..AmileaMachineConfig::default()
            },
            _ => return Err(NormalizeError::UnsupportedModel { model }),
        };
        if let Some(kib)=self.chip_memory_kib { out.chip_memory_kib=kib; }
        out.rom=self.kickstart_file.as_ref().map(|path| RomReference { path:path.clone() });
        Ok(out)
    }
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
    fn normalizes_fs_uae_a500_to_native_machine_config() {
        let imported=parse_fs_uae("amiga_model = A500\nchip_memory = 1024\nkickstart_file = roms/kick.rom\n").unwrap();
        let machine=imported.normalize().unwrap();
        assert_eq!(machine.model,"A500");
        assert_eq!(machine.cpu,CpuModel::M68000);
        assert_eq!(machine.chipset,Chipset::Ocs);
        assert_eq!(machine.video,VideoStandard::Pal);
        assert_eq!(machine.chip_memory_kib,1024);
        assert_eq!(machine.rom,Some(RomReference{path:"roms/kick.rom".into()}));
    }

    #[test]
    fn normalizes_common_model_defaults_without_fs_uae_leaking_downstream() {
        let a500p=parse_fs_uae("amiga_model=A500+").unwrap().normalize().unwrap();
        assert_eq!((a500p.cpu,a500p.chipset,a500p.chip_memory_kib),(CpuModel::M68000,Chipset::Ecs,1024));
        let a1200=parse_fs_uae("amiga_model=A1200").unwrap().normalize().unwrap();
        assert_eq!((a1200.cpu,a1200.chipset,a1200.chip_memory_kib),(CpuModel::M68020,Chipset::Aga,2048));
    }

    #[test]
    fn normalization_rejects_unknown_machine_model_explicitly() {
        let imported=parse_fs_uae("amiga_model=A9999").unwrap();
        assert_eq!(imported.normalize(),Err(NormalizeError::UnsupportedModel{model:"A9999".into()}));
    }

    #[test]
    fn rejects_malformed_lines_and_bad_numbers() {
        assert_eq!(parse_fs_uae("amiga_model A500"),Err(ConfigError::InvalidLine{line:1}));
        assert_eq!(parse_fs_uae("chip_memory = lots"),Err(ConfigError::InvalidInteger{line:1,key:"chip_memory".into()}));
    }
}
