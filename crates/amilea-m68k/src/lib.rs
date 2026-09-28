//! Minimal deterministic Motorola 68000 execution boundary for Amilea M1.

use amilea_bus::{Bus, BusError};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpu {
    pub d: [u32; 8],
    pub a: [u32; 8],
    pub pc: u32,
    pub sr: u16,
    pub stopped: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CpuError {
    #[error(transparent)]
    Bus(#[from] BusError),
    #[error("illegal opcode {opcode:#06x} at {pc:#08x}")]
    IllegalOpcode { pc: u32, opcode: u16 },
}

impl Default for Cpu {
    fn default() -> Self {
        Self {
            d: [0; 8],
            a: [0; 8],
            pc: 0,
            sr: 0x2700,
            stopped: false,
        }
    }
}

impl Cpu {
    pub fn reset<B: Bus>(&mut self, bus: &B) -> Result<(), CpuError> {
        self.d = [0; 8];
        self.a = [0; 8];
        self.sr = 0x2700;
        self.stopped = false;
        self.a[7] = bus.read32(0)?;
        self.pc = bus.read32(4)?;
        Ok(())
    }

    /// Execute one M1 instruction and return its 68000 cycle count.
    pub fn step<B: Bus>(&mut self, bus: &mut B) -> Result<u32, CpuError> {
        let pc = self.pc;
        let opcode = bus.read16(pc)?;
        self.pc = self.pc.wrapping_add(2) & 0x00ff_ffff;

        match opcode {
            0x4e71 => Ok(4), // NOP
            0x7000..=0x70ff => {
                // MOVEQ #imm8,D0
                self.d[0] = (opcode as u8 as i8 as i32) as u32;
                Ok(4)
            }
            0x4e72 => {
                let new_sr = bus.read16(self.pc)?;
                self.pc = self.pc.wrapping_add(2) & 0x00ff_ffff;
                self.sr = new_sr;
                self.stopped = true;
                Ok(4)
            }
            _ => Err(CpuError::IllegalOpcode { pc, opcode }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amilea_bus::RamBus;

    #[test]
    fn reset_loads_initial_ssp_and_pc() {
        let mut bus = RamBus::new(0x2000);
        bus.write32(0, 0x0000_1000).unwrap();
        bus.write32(4, 0x0000_0100).unwrap();

        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();

        assert_eq!(cpu.a[7], 0x1000);
        assert_eq!(cpu.pc, 0x100);
        assert_eq!(cpu.sr, 0x2700);
    }

    #[test]
    fn executes_deterministic_boot_slice() {
        let mut bus = RamBus::new(0x2000);
        bus.write32(0, 0x0000_1000).unwrap();
        bus.write32(4, 0x0000_0100).unwrap();
        bus.write16(0x100, 0x707f).unwrap(); // MOVEQ #127,D0
        bus.write16(0x102, 0x4e71).unwrap(); // NOP
        bus.write16(0x104, 0x4e72).unwrap(); // STOP
        bus.write16(0x106, 0x2700).unwrap();

        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();

        let mut cycles = 0;
        while !cpu.stopped {
            cycles += cpu.step(&mut bus).unwrap();
        }

        assert_eq!(cpu.d[0], 127);
        assert_eq!(cpu.pc, 0x108);
        assert_eq!(cycles, 12);
    }
}
