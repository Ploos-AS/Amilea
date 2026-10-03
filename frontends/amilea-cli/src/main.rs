use amilea_config::{parse_fs_uae, ImportStatus};
use amilea_core::{Amilea, MachineConfig};
use std::path::Path;

fn main() {
    let args=std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str)==Some("config") && args.get(1).map(String::as_str)==Some("explain") {
        let path=args.get(2).expect("usage: amilea config explain <file.fs-uae>");
        explain_config(Path::new(path));
        return;
    }

    let cycles=args.first().map(String::as_str).unwrap_or("1000000").parse::<u64>()
        .expect("usage: amilea [cycles] | amilea config explain <file.fs-uae>");
    let mut machine=Amilea::new(MachineConfig::default());
    machine.run_cycles(cycles);
    println!("Amilea M0");
    println!("cycles={}",machine.cycle());
    println!("state={}",hex(&machine.state_hash()));
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
