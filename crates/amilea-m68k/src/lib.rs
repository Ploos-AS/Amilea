//! Deterministic Motorola 68000 execution boundary for Amilea M1.

use amilea_bus::{Bus, BusError};
use thiserror::Error;

const CCR_N: u16 = 0x08;
const CCR_Z: u16 = 0x04;
const SR_SUPERVISOR: u16 = 0x2000;

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
            0x4e75 => { self.pc = self.pop32(bus)?; Ok(16) }
            0x4e73 => {
                self.sr = self.pop16(bus)?;
                self.pc = self.pop32(bus)?;
                Ok(20)
            }
            0x4e72 => {
                self.sr = self.fetch16(bus)?;
                self.stopped = true;
                Ok(4)
            }
            0x4e40..=0x4e4f => {
                let vector = 32 + (opcode & 0x000f) as u8;
                self.enter_exception(bus, vector, self.pc)?;
                Ok(34)
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
            _ => {
                self.enter_exception(bus, 4, instruction_pc)?;
                Ok(34)
            }
        }
    }

    pub fn interrupt<B: Bus>(&mut self, bus: &mut B, level: u8, vector: u8) -> Result<u32, CpuError> {
        let level = level.min(7);
        let mask = ((self.sr >> 8) & 7) as u8;
        if level <= mask && level != 7 {
            return Ok(0);
        }
        self.stopped = false;
        let saved_pc = self.pc;
        let saved_sr = self.sr;
        self.sr = (self.sr & !0x0700) | ((level as u16) << 8);
        self.enter_exception_with_sr(bus, vector, saved_pc, saved_sr)?;
        Ok(44)
    }

    fn enter_exception<B: Bus>(&mut self, bus: &mut B, vector: u8, saved_pc: u32) -> Result<(), CpuError> {
        let saved_sr = self.sr;
        self.enter_exception_with_sr(bus, vector, saved_pc, saved_sr)
    }

    fn enter_exception_with_sr<B: Bus>(&mut self, bus: &mut B, vector: u8, saved_pc: u32, saved_sr: u16) -> Result<(), CpuError> {
        self.sr |= SR_SUPERVISOR;
        self.push32(bus, saved_pc)?;
        self.push16(bus, saved_sr)?;
        self.pc = bus.read32((vector as u32) * 4)? & 0x00ff_ffff;
        Ok(())
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

    fn push16<B: Bus>(&mut self, bus: &mut B, value: u16) -> Result<(), CpuError> {
        self.a[7] = self.a[7].wrapping_sub(2) & 0x00ff_ffff;
        bus.write16(self.a[7], value)?;
        Ok(())
    }

    fn pop16<B: Bus>(&mut self, bus: &B) -> Result<u16, CpuError> {
        let value = bus.read16(self.a[7])?;
        self.a[7] = self.a[7].wrapping_add(2) & 0x00ff_ffff;
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
        if short == 0 { Ok(self.fetch16(bus)? as i16 as i32) } else { Ok(short as i32) }
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
    fn trap_enters_vector_and_rte_restores_context() {
        let mut bus = boot_bus();
        bus.write32(32 * 4, 0x200).unwrap();
        bus.write16(0x100, 0x4e40).unwrap();
        bus.write16(0x102, 0x4e72).unwrap();
        bus.write16(0x104, 0x2700).unwrap();
        bus.write16(0x200, 0x7209).unwrap();
        bus.write16(0x202, 0x4e73).unwrap();

        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        let sp = cpu.a[7];
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x200);
        cpu.step(&mut bus).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x102);
        assert_eq!(cpu.a[7], sp);
        assert_eq!(cpu.d[1], 9);
    }

    #[test]
    fn illegal_instruction_uses_vector_four() {
        let mut bus = boot_bus();
        bus.write32(4 * 4, 0x240).unwrap();
        bus.write16(0x100, 0xffff).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        assert_eq!(cpu.step(&mut bus).unwrap(), 34);
        assert_eq!(cpu.pc, 0x240);
        assert_eq!(bus.read32(cpu.a[7] + 2).unwrap(), 0x100);
    }

    #[test]
    fn interrupt_obeys_mask_and_wakes_stop() {
        let mut bus = boot_bus();
        bus.write32(27 * 4, 0x280).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.sr = 0x2000;
        cpu.stopped = true;
        assert_eq!(cpu.interrupt(&mut bus, 3, 27).unwrap(), 44);
        assert_eq!(cpu.pc, 0x280);
        assert!(!cpu.stopped);
        assert_eq!((cpu.sr >> 8) & 7, 3);
    }

    #[test]
    fn masked_interrupt_is_ignored() {
        let mut bus = boot_bus();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.sr = 0x2500;
        assert_eq!(cpu.interrupt(&mut bus, 3, 27).unwrap(), 0);
        assert_eq!(cpu.pc, 0x100);
    }
}
