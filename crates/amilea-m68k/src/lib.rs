//! Deterministic Motorola 68000 execution boundary for Amilea M1.

use amilea_bus::{Bus, BusError};
use thiserror::Error;

const CCR_N: u16 = 0x08;
const CCR_Z: u16 = 0x04;

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
        Self { d: [0; 8], a: [0; 8], pc: 0, sr: 0x2700, stopped: false }
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

    pub fn step<B: Bus>(&mut self, bus: &mut B) -> Result<u32, CpuError> {
        let instruction_pc = self.pc;
        let opcode = self.fetch16(bus)?;

        match opcode {
            0x4e71 => Ok(4),
            0x4e75 => {
                self.pc = self.pop32(bus)?;
                Ok(16)
            }
            0x4e72 => {
                self.sr = self.fetch16(bus)?;
                self.stopped = true;
                Ok(4)
            }
            0x4eb9 => {
                let target = self.fetch32(bus)? & 0x00ff_ffff;
                let return_pc = self.pc;
                self.push32(bus, return_pc)?;
                self.pc = target;
                Ok(20)
            }
            0x6000..=0x60ff => {
                let displacement = self.branch_displacement(bus, opcode)?;
                self.pc = add_displacement(self.pc, displacement);
                Ok(10)
            }
            0x6100..=0x61ff => {
                let displacement = self.branch_displacement(bus, opcode)?;
                let return_pc = self.pc;
                self.push32(bus, return_pc)?;
                self.pc = add_displacement(self.pc, displacement);
                Ok(18)
            }
            0x7000..=0x7fff => {
                let register = ((opcode >> 9) & 7) as usize;
                let value = (opcode as u8 as i8 as i32) as u32;
                self.d[register] = value;
                self.set_nz32(value);
                Ok(4)
            }
            _ => Err(CpuError::IllegalOpcode { pc: instruction_pc, opcode }),
        }
    }

    fn fetch16<B: Bus>(&mut self, bus: &B) -> Result<u16, CpuError> {
        let value = bus.read16(self.pc)?;
        self.pc = (self.pc + 2) & 0x00ff_ffff;
        Ok(value)
    }

    fn fetch32<B: Bus>(&mut self, bus: &B) -> Result<u32, CpuError> {
        let value = bus.read32(self.pc)?;
        self.pc = (self.pc + 4) & 0x00ff_ffff;
        Ok(value)
    }

    fn push32<B: Bus>(&mut self, bus: &mut B, value: u32) -> Result<(), CpuError> {
        self.a[7] = self.a[7].wrapping_sub(4) & 0x00ff_ffff;
        bus.write32(self.a[7], value)?;
        Ok(())
    }

    fn pop32<B: Bus>(&mut self, bus: &B) -> Result<u32, CpuError> {
        let value = bus.read32(self.a[7])?;
        self.a[7] = self.a[7].wrapping_add(4) & 0x00ff_ffff;
        Ok(value)
    }

    fn branch_displacement<B: Bus>(&mut self, bus: &B, opcode: u16) -> Result<i32, CpuError> {
        let short = opcode as u8 as i8;
        if short == 0 {
            Ok(self.fetch16(bus)? as i16 as i32)
        } else {
            Ok(short as i32)
        }
    }

    fn set_nz32(&mut self, value: u32) {
        self.sr &= !(CCR_N | CCR_Z);
        if value == 0 { self.sr |= CCR_Z; }
        if value & 0x8000_0000 != 0 { self.sr |= CCR_N; }
    }
}

fn add_displacement(pc: u32, displacement: i32) -> u32 {
    pc.wrapping_add(displacement as u32) & 0x00ff_ffff
}

#[cfg(test)]
mod tests {
    use super::*;
    use amilea_bus::RamBus;

    fn boot_bus() -> RamBus {
        let mut bus = RamBus::new(0x4000);
        bus.write32(0, 0x0000_3000).unwrap();
        bus.write32(4, 0x0000_0100).unwrap();
        bus
    }

    #[test]
    fn reset_loads_initial_ssp_and_pc() {
        let bus = boot_bus();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        assert_eq!(cpu.a[7], 0x3000);
        assert_eq!(cpu.pc, 0x100);
        assert_eq!(cpu.sr, 0x2700);
    }

    #[test]
    fn moveq_targets_all_data_registers_and_sets_nz() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x72ff).unwrap(); // MOVEQ #-1,D1
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        assert_eq!(cpu.step(&mut bus).unwrap(), 4);
        assert_eq!(cpu.d[1], 0xffff_ffff);
        assert_ne!(cpu.sr & CCR_N, 0);
        assert_eq!(cpu.sr & CCR_Z, 0);
    }

    #[test]
    fn bsr_and_rts_round_trip_stack_and_pc() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x6104).unwrap(); // BSR.s -> 0x106
        bus.write16(0x102, 0x7007).unwrap(); // MOVEQ #7,D0
        bus.write16(0x104, 0x6004).unwrap(); // BRA.s -> 0x10a
        bus.write16(0x106, 0x7209).unwrap(); // MOVEQ #9,D1
        bus.write16(0x108, 0x4e75).unwrap(); // RTS
        bus.write16(0x10a, 0x4e72).unwrap();
        bus.write16(0x10c, 0x2700).unwrap();

        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        let initial_sp = cpu.a[7];
        while !cpu.stopped {
            cpu.step(&mut bus).unwrap();
        }

        assert_eq!(cpu.d[0], 7);
        assert_eq!(cpu.d[1], 9);
        assert_eq!(cpu.a[7], initial_sp);
        assert_eq!(cpu.pc, 0x10e);
    }

    #[test]
    fn jsr_absolute_long_and_rts_work() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x4eb9).unwrap();
        bus.write32(0x102, 0x0000_0200).unwrap();
        bus.write16(0x106, 0x4e72).unwrap();
        bus.write16(0x108, 0x2700).unwrap();
        bus.write16(0x200, 0x747f).unwrap(); // MOVEQ #127,D2
        bus.write16(0x202, 0x4e75).unwrap();

        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        let initial_sp = cpu.a[7];
        while !cpu.stopped {
            cpu.step(&mut bus).unwrap();
        }

        assert_eq!(cpu.d[2], 127);
        assert_eq!(cpu.a[7], initial_sp);
    }
}
