use amilea_config::{
    parse_fs_uae, Chipset as ImportedChipset, CpuModel as ImportedCpuModel, ImportStatus,
    VideoStandard as ImportedVideoStandard,
};
use amilea_core::{
    Amilea, Chipset, CpuModel, MachineConfig, VideoStandard,
};
use std::path::Path;

fn main() {
    let args=std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str)==Some("config") && args.get(1).map(String::as_str)==Some("explain") {
        let path=args.get(2).expect("usage: amilea config explain <file.fs-uae>");
        explain_config(Path::new(path));
        return;
    }

    let (config,cycles)=if args.first().map(String::as_str)==Some("run") && args.get(1).map(String::as_str)==Some("--fs-uae") {
        let path=args.get(2).expect("usage: amilea run --fs-uae <file.fs-uae> [cycles]");
        let cycles=args.get(3).map(String::as_str).unwrap_or("1000000").parse::<u64>().expect("cycles must be an integer");
        (runtime_config(Path::new(path)),cycles)
    } else {
        let cycles=args.first().map(String::as_str).unwrap_or("1000000").parse::<u64>()
            .expect("usage: amilea [cycles] | amilea run --fs-uae <file.fs-uae> [cycles] | amilea config explain <file.fs-uae>");
        (MachineConfig::default(),cycles)
    };
    let mut machine=Amilea::new(config);
    machine.run_cycles(cycles);
    println!("Amilea M0");
    println!("cycles={}",machine.cycle());
    println!("state={}",hex(&machine.state_hash()));
}


fn runtime_config(path:&Path)->MachineConfig {
    let input=std::fs::read_to_string(path).unwrap_or_else(|e|panic!("{}: {e}",path.display()));
    let imported=parse_fs_uae(&input).unwrap_or_else(|e|panic!("{}: {e}",path.display()));
    let dir=path.parent().unwrap_or_else(||Path::new("."));
    let machine=imported.normalize_at(dir).unwrap_or_else(|e|panic!("{}: {e}",path.display()));
    MachineConfig {
        cpu:match machine.cpu {
            ImportedCpuModel::M68000=>CpuModel::M68000,
            ImportedCpuModel::M68010=>CpuModel::M68010,
            ImportedCpuModel::M68020=>CpuModel::M68020,
            ImportedCpuModel::M68030=>CpuModel::M68030,
            ImportedCpuModel::M68040=>CpuModel::M68040,
            ImportedCpuModel::M68060=>CpuModel::M68060,
        },
        chipset:match machine.chipset {
            ImportedChipset::Ocs=>Chipset::Ocs,
            ImportedChipset::Ecs=>Chipset::Ecs,
            ImportedChipset::Aga=>Chipset::Aga,
        },
        video:match machine.video {
            ImportedVideoStandard::Pal=>VideoStandard::Pal,
            ImportedVideoStandard::Ntsc=>VideoStandard::Ntsc,
        },
        chip_ram_bytes:kib_to_bytes(machine.chip_memory_kib,"chip"),
        slow_ram_bytes:kib_to_bytes(machine.slow_memory_kib,"slow"),
        fast_ram_bytes:kib_to_bytes(machine.fast_memory_kib,"fast"),
    }
}

fn kib_to_bytes(kib:u32,kind:&str)->usize {
    usize::try_from(u64::from(kib)*1024).unwrap_or_else(|_|panic!("{kind} memory size does not fit this host"))
}

fn explain_config(path:&Path) {
    let input=std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}",path.display()));
    let imported=parse_fs_uae(&input).unwrap_or_else(|e| panic!("{}: {e}",path.display()));
    let dir=path.parent().unwrap_or_else(|| Path::new("."));
    let machine=imported.normalize_at(dir).unwrap_or_else(|e| panic!("{}: {e}",path.display()));

    println!("source={}",path.display());
    for option in &imported.diagnostics {
        println!("option {} = {} [{}]",option.key,option.value,status(option.status));
    }
    println!("machine.model={}",machine.model);
    println!("machine.cpu={:?}",machine.cpu);
    println!("machine.chipset={:?}",machine.chipset);
    println!("machine.video={:?}",machine.video);
    println!("memory.chip_kib={}",machine.chip_memory_kib);
    println!("memory.slow_kib={}",machine.slow_memory_kib);
    println!("memory.fast_kib={}",machine.fast_memory_kib);
    if let Some(rom)=machine.rom { println!("rom={}",rom.path); }
    for floppy in machine.floppies { println!("floppy.{}={}",floppy.drive,floppy.path); }
    for drive in machine.hard_drives { println!("hard_drive.{}.{:?}={}",drive.index,drive.kind,drive.path); }
}

fn status(status:ImportStatus)->&'static str {
    match status {
        ImportStatus::Supported=>"supported",
        ImportStatus::Ignored=>"ignored",
        ImportStatus::Unsupported=>"unsupported",
        ImportStatus::Unknown=>"unknown",
    }
}

fn hex(bytes:&[u8])->String { bytes.iter().map(|b|format!("{b:02x}")).collect() }
