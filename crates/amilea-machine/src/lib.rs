//! Integrated deterministic Amiga machine plumbing.
//!
//! This layer owns the CPU-visible bus topology and hardware signals.
//! It is intentionally small while chipset devices are still being added.

use amilea_bus::{AddressSpace, BusSignal, OverlayBus, RamBus, Rom};
use amilea_cia::CiaA;
use amilea_m68k::{Cpu, CpuError};

pub struct AmigaMachine {
    pub cpu: Cpu,
    bus: OverlayBus<AddressSpace, Rom>,
    overlay: BusSignal,
}

impl AmigaMachine {
    pub fn a500_with_rom(rom: Vec<u8>) -> Result<Self, amilea_bus::BusError> {
        let overlay=BusSignal::new(true);
        let mut base=AddressSpace::new();
        base.map(0x000000,0x080000,RamBus::new(0x080000))?;
        base.map(0xbfe000,0x300,CiaA::with_overlay_signal(overlay.clone()))?;
        base.map(0xf80000,rom.len() as u32,Rom::new(0xf80000,rom.clone()))?;
        let overlay_rom=Rom::new(0,rom);
        Ok(Self {
            cpu:Cpu::default(),
            bus:OverlayBus::with_signal(base,overlay_rom,0x080000,overlay.clone()),
            overlay,
        })
    }

    pub fn reset(&mut self)->Result<(),CpuError> { self.cpu.reset(&mut self.bus) }
    pub fn step(&mut self)->Result<u32,CpuError> { self.cpu.step(&mut self.bus) }
    pub fn overlay_enabled(&self)->bool { self.overlay.get() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_resets_from_rom_overlay() {
        let mut rom=vec![0u8;0x20];
        rom[0..4].copy_from_slice(&0x0008_0000u32.to_be_bytes());
        rom[4..8].copy_from_slice(&0x00f8_0008u32.to_be_bytes());
        rom[8..10].copy_from_slice(&0x4e71u16.to_be_bytes());
        let mut machine=AmigaMachine::a500_with_rom(rom).unwrap();
        machine.reset().unwrap();
        assert_eq!(machine.cpu.pc,0x00f8_0008);
        assert!(machine.overlay_enabled());
        assert_eq!(machine.step().unwrap(),4);
    }
}
