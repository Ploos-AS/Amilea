use amilea_core::{Amilea, MachineConfig};

fn main() {
    let cycles = std::env::args()
        .nth(1)
        .as_deref()
        .unwrap_or("1000000")
        .parse::<u64>()
        .expect("usage: amilea [cycles]");

    let mut machine = Amilea::new(MachineConfig::default());
    machine.run_cycles(cycles);

    println!("Amilea M0");
    println!("cycles={}", machine.cycle());
    println!("state={}", hex(&machine.state_hash()));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
