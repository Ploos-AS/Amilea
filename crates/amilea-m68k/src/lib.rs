//! Deterministic Motorola 68000 execution boundary for Amilea M1.

use amilea_bus::{Bus, BusError};
use thiserror::Error;

const CCR_X: u16 = 0x10;
const CCR_N: u16 = 0x08;
const CCR_Z: u16 = 0x04;
const SR_SUPERVISOR: u16 = 0x2000;
const CCR_V: u16 = 0x02;
const CCR_C: u16 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Size { Byte, Word, Long }

impl Size {
    fn mask(self) -> u32 { match self { Self::Byte => 0xff, Self::Word => 0xffff, Self::Long => u32::MAX } }
    fn sign(self) -> u32 { match self { Self::Byte => 0x80, Self::Word => 0x8000, Self::Long => 0x8000_0000 } }
    fn bytes(self, reg: usize) -> u32 { match self { Self::Byte if reg == 7 => 2, Self::Byte => 1, Self::Word => 2, Self::Long => 4 } }
}

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
        let opcode = match bus.read16(self.pc) {
            Ok(opcode) => {
                self.pc = (self.pc + 2) & 0x00ff_ffff;
                opcode
            }
            Err(fault) => {
                let (vector, address) = match fault {
                    BusError::AddressError { address } => (3, address),
                    BusError::Unmapped { address } => (2, address),
                };
                self.enter_access_fault(bus, vector, instruction_pc, 0, address, true, true)?;
                return Ok(50);
            }
        };

        match opcode {
            0x4200..=0x42bf => {
                let size = decode_size((opcode >> 6) & 3).unwrap();
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                self.write_ea(bus, size, mode, reg, 0)?;
                self.set_logic_flags(size, 0);
                Ok(4)
            }
            0x4a00..=0x4abf => {
                let size = decode_size((opcode >> 6) & 3).unwrap();
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                let value = self.read_ea(bus, size, mode, reg)?;
                self.set_logic_flags(size, value);
                Ok(4)
            }
            0x9000..=0x9fff | 0xb000..=0xbfff | 0xd000..=0xdfff => {
                let top = opcode >> 12;
                let opmode = ((opcode >> 6) & 7) as u8;
                let dn = ((opcode >> 9) & 7) as usize;
                if opmode > 2 {
                    self.enter_exception(bus, 4, instruction_pc)?;
                    return Ok(34);
                }
                let size = decode_size(opmode as u16).unwrap();
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                let src = self.read_ea(bus, size, mode, reg)?;
                let dst = self.d[dn] & size.mask();
                let result = match top {
                    0x9 => self.alu_sub(size, dst, src, true),
                    0xb => self.alu_sub(size, dst, src, false),
                    0xd => self.alu_add(size, dst, src),
                    _ => unreachable!(),
                };
                if top != 0xb {
                    let mask = size.mask();
                    self.d[dn] = (self.d[dn] & !mask) | (result & mask);
                }
                Ok(4)
            }
            0x41c0..=0x4fc0 if opcode & 0x01c0 == 0x01c0 => {
                let dst = ((opcode >> 9) & 7) as usize;
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                self.a[dst] = self.ea_address(bus, mode, reg)?;
                Ok(4)
            }
            0x1000..=0x3fff => {
                let size = match opcode >> 12 { 1 => Size::Byte, 2 => Size::Long, 3 => Size::Word, _ => unreachable!() };
                let src_mode = ((opcode >> 3) & 7) as u8;
                let src_reg = (opcode & 7) as usize;
                let dst_mode = ((opcode >> 6) & 7) as u8;
                let dst_reg = ((opcode >> 9) & 7) as usize;
                if dst_mode == 1 {
                    if size == Size::Byte {
                        self.enter_exception(bus, 4, instruction_pc)?;
                        return Ok(34);
                    }
                    let value = self.read_ea(bus, size, src_mode, src_reg)?;
                    self.a[dst_reg] = if size == Size::Word {
                        value as u16 as i16 as i32 as u32
                    } else {
                        value
                    };
                    return Ok(4);
                }
                if size == Size::Byte && src_mode == 1 {
                    self.enter_exception(bus, 4, instruction_pc)?;
                    return Ok(34);
                }
                let value = self.read_ea(bus, size, src_mode, src_reg)?;
                self.write_ea(bus, size, dst_mode, dst_reg, value)?;
                self.set_move_flags(size, value);
                Ok(4)
            }
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

    fn enter_access_fault<B: Bus>(
        &mut self,
        bus: &mut B,
        vector: u8,
        saved_pc: u32,
        instruction: u16,
        fault_address: u32,
        read: bool,
        instruction_access: bool,
    ) -> Result<(), CpuError> {
        let saved_sr = self.sr;
        self.sr |= SR_SUPERVISOR;
        let function_code = if saved_sr & SR_SUPERVISOR != 0 {
            if instruction_access { 6 } else { 5 }
        } else if instruction_access { 2 } else { 1 };
        let mut ssw = function_code;
        if read { ssw |= 1 << 4; }
        if !instruction_access { ssw |= 1 << 3; }

        self.push32(bus, saved_pc)?;
        self.push16(bus, saved_sr)?;
        self.push16(bus, instruction)?;
        self.push32(bus, fault_address)?;
        self.push16(bus, ssw)?;
        self.pc = bus.read32((vector as u32) * 4)? & 0x00ff_ffff;
        Ok(())
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

    fn indexed_address<B: Bus>(&mut self, bus: &B, base: u32) -> Result<u32, CpuError> {
        let extension = self.fetch16(bus)?;
        let index_reg = ((extension >> 12) & 7) as usize;
        let index = if extension & 0x8000 != 0 { self.a[index_reg] } else { self.d[index_reg] };
        let index = if extension & 0x0800 != 0 { index } else { index as u16 as i16 as i32 as u32 };
        let displacement = extension as u8 as i8 as i32;
        Ok(add_displacement(base.wrapping_add(index) & 0x00ff_ffff, displacement))
    }

    fn ea_address<B: Bus>(&mut self, bus: &B, mode: u8, reg: usize) -> Result<u32, CpuError> {
        Ok(match mode {
            2 => self.a[reg],
            5 => {
                let displacement = self.fetch16(bus)? as i16 as i32;
                add_displacement(self.a[reg], displacement)
            }
            6 => {
                let base = self.a[reg];
                self.indexed_address(bus, base)?
            }
            7 if reg == 0 => self.fetch16(bus)? as i16 as i32 as u32 & 0x00ff_ffff,
            7 if reg == 1 => self.fetch32(bus)? & 0x00ff_ffff,
            7 if reg == 2 => {
                let base = self.pc;
                let displacement = self.fetch16(bus)? as i16 as i32;
                add_displacement(base, displacement)
            }
            7 if reg == 3 => {
                let base = self.pc;
                self.indexed_address(bus, base)?
            }
            _ => return Err(BusError::Unmapped { address: self.pc }.into()),
        })
    }

    fn read_ea<B: Bus>(&mut self, bus: &B, size: Size, mode: u8, reg: usize) -> Result<u32, CpuError> {
        let value = match mode {
            0 => self.d[reg] & size.mask(),
            1 => self.a[reg] & size.mask(),
            2 => self.read_mem(bus, size, self.a[reg])?,
            3 => {
                let address = self.a[reg];
                let value = self.read_mem(bus, size, address)?;
                self.a[reg] = (self.a[reg] + size.bytes(reg)) & 0x00ff_ffff;
                value
            }
            4 => {
                self.a[reg] = self.a[reg].wrapping_sub(size.bytes(reg)) & 0x00ff_ffff;
                self.read_mem(bus, size, self.a[reg])?
            }
            5 => {
                let displacement = self.fetch16(bus)? as i16 as i32;
                let address = add_displacement(self.a[reg], displacement);
                self.read_mem(bus, size, address)?
            }
            6 => {
                let base = self.a[reg];
                let address = self.indexed_address(bus, base)?;
                self.read_mem(bus, size, address)?
            }
            7 if reg == 0 => {
                let address = self.fetch16(bus)? as i16 as i32 as u32 & 0x00ff_ffff;
                self.read_mem(bus, size, address)?
            }
            7 if reg == 1 => {
                let address = self.fetch32(bus)? & 0x00ff_ffff;
                self.read_mem(bus, size, address)?
            }
            7 if reg == 2 => {
                let base = self.pc;
                let displacement = self.fetch16(bus)? as i16 as i32;
                self.read_mem(bus, size, add_displacement(base, displacement))?
            }
            7 if reg == 3 => {
                let base = self.pc;
                let address = self.indexed_address(bus, base)?;
                self.read_mem(bus, size, address)?
            }
            7 if reg == 4 => match size {
                Size::Byte => self.fetch16(bus)? as u8 as u32,
                Size::Word => self.fetch16(bus)? as u32,
                Size::Long => self.fetch32(bus)?,
            },
            _ => return Err(BusError::Unmapped { address: self.pc }.into()),
        };
        Ok(value)
    }

    fn write_ea<B: Bus>(&mut self, bus: &mut B, size: Size, mode: u8, reg: usize, value: u32) -> Result<(), CpuError> {
        match mode {
            0 => {
                let mask = size.mask();
                self.d[reg] = (self.d[reg] & !mask) | (value & mask);
            }
            2 => self.write_mem(bus, size, self.a[reg], value)?,
            3 => {
                let address = self.a[reg];
                self.write_mem(bus, size, address, value)?;
                self.a[reg] = (self.a[reg] + size.bytes(reg)) & 0x00ff_ffff;
            }
            4 => {
                self.a[reg] = self.a[reg].wrapping_sub(size.bytes(reg)) & 0x00ff_ffff;
                self.write_mem(bus, size, self.a[reg], value)?;
            }
            5 => {
                let displacement = self.fetch16(bus)? as i16 as i32;
                let address = add_displacement(self.a[reg], displacement);
                self.write_mem(bus, size, address, value)?;
            }
            7 if reg == 0 => {
                let address = self.fetch16(bus)? as i16 as i32 as u32 & 0x00ff_ffff;
                self.write_mem(bus, size, address, value)?;
            }
            7 if reg == 1 => {
                let address = self.fetch32(bus)? & 0x00ff_ffff;
                self.write_mem(bus, size, address, value)?;
            }
            _ => return Err(BusError::Unmapped { address: self.pc }.into()),
        }
        Ok(())
    }

    fn read_mem<B: Bus>(&self, bus: &B, size: Size, address: u32) -> Result<u32, CpuError> {
        Ok(match size {
            Size::Byte => bus.read8(address)? as u32,
            Size::Word => bus.read16(address)? as u32,
            Size::Long => bus.read32(address)?,
        })
    }

    fn write_mem<B: Bus>(&self, bus: &mut B, size: Size, address: u32, value: u32) -> Result<(), CpuError> {
        match size {
            Size::Byte => bus.write8(address, value as u8)?,
            Size::Word => bus.write16(address, value as u16)?,
            Size::Long => bus.write32(address, value)?,
        }
        Ok(())
    }

    fn set_logic_flags(&mut self, size: Size, value: u32) {
        self.sr &= !(CCR_N | CCR_Z | CCR_V | CCR_C);
        let value = value & size.mask();
        if value == 0 { self.sr |= CCR_Z; }
        if value & size.sign() != 0 { self.sr |= CCR_N; }
    }

    fn alu_add(&mut self, size: Size, dst: u32, src: u32) -> u32 {
        let mask = size.mask();
        let sign = size.sign();
        let a = dst & mask;
        let b = src & mask;
        let result = a.wrapping_add(b) & mask;
        self.sr &= !(CCR_X | CCR_N | CCR_Z | CCR_V | CCR_C);
        if result == 0 { self.sr |= CCR_Z; }
        if result & sign != 0 { self.sr |= CCR_N; }
        if (!(a ^ b) & (a ^ result) & sign) != 0 { self.sr |= CCR_V; }
        let carry = if size == Size::Long { (a as u64 + b as u64) > u32::MAX as u64 } else { a + b > mask };
        if carry { self.sr |= CCR_C | CCR_X; }
        result
    }

    fn alu_sub(&mut self, size: Size, dst: u32, src: u32, update_x: bool) -> u32 {
        let mask = size.mask();
        let sign = size.sign();
        let a = dst & mask;
        let b = src & mask;
        let result = a.wrapping_sub(b) & mask;
        let old_x = self.sr & CCR_X;
        self.sr &= !(CCR_X | CCR_N | CCR_Z | CCR_V | CCR_C);
        if result == 0 { self.sr |= CCR_Z; }
        if result & sign != 0 { self.sr |= CCR_N; }
        if ((a ^ b) & (a ^ result) & sign) != 0 { self.sr |= CCR_V; }
        if b > a {
            self.sr |= CCR_C;
            if update_x { self.sr |= CCR_X; }
        } else if !update_x {
            self.sr |= old_x;
        }
        result
    }

    fn set_move_flags(&mut self, size: Size, value: u32) {
        self.sr &= !(CCR_N | CCR_Z | CCR_V | CCR_C);
        let value = value & size.mask();
        if value == 0 { self.sr |= CCR_Z; }
        if value & size.sign() != 0 { self.sr |= CCR_N; }
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

fn decode_size(bits: u16) -> Option<Size> {
    match bits { 0 => Some(Size::Byte), 1 => Some(Size::Word), 2 => Some(Size::Long), _ => None }
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
    fn odd_instruction_fetch_enters_address_error_vector() {
        let mut bus = boot_bus();
        bus.write32(3 * 4, 0x2c0).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.pc = 0x101;
        let initial_sp = cpu.a[7];

        assert_eq!(cpu.step(&mut bus).unwrap(), 50);
        assert_eq!(cpu.pc, 0x2c0);
        assert_eq!(cpu.a[7], initial_sp - 14);
        assert_eq!(bus.read32(cpu.a[7] + 2).unwrap(), 0x101);
        assert_eq!(bus.read16(cpu.a[7] + 6).unwrap(), 0);
        assert_eq!(bus.read32(cpu.a[7] + 10).unwrap(), 0x101);
        assert_eq!(bus.read16(cpu.a[7]).unwrap() & 0x001f, 0x0016);
    }

    #[test]
    fn unmapped_instruction_fetch_enters_bus_error_vector() {
        let mut bus = boot_bus();
        bus.write32(2 * 4, 0x2a0).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.pc = 0x8000;

        assert_eq!(cpu.step(&mut bus).unwrap(), 50);
        assert_eq!(cpu.pc, 0x2a0);
        assert_eq!(bus.read32(cpu.a[7] + 2).unwrap(), 0x8000);
    }

    #[test]
    fn move_long_register_to_memory_and_back() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x2080).unwrap(); // MOVE.L D0,(A0)
        bus.write16(0x102, 0x2210).unwrap(); // MOVE.L (A0),D1
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.d[0] = 0x1234_abcd;
        cpu.a[0] = 0x500;
        cpu.step(&mut bus).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read32(0x500).unwrap(), 0x1234_abcd);
        assert_eq!(cpu.d[1], 0x1234_abcd);
    }

    #[test]
    fn move_byte_postincrement_a7_advances_two_bytes() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x101f).unwrap(); // MOVE.B (A7)+,D0
        bus.write8(0x3000, 0x80).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0x80);
        assert_eq!(cpu.a[7], 0x3002);
        assert_ne!(cpu.sr & CCR_N, 0);
    }

    #[test]
    fn move_word_with_displacement_uses_shared_ea_engine() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x3168).unwrap(); // MOVE.W 4(A0),8(A0)
        bus.write16(0x102, 4).unwrap();
        bus.write16(0x104, 8).unwrap();
        bus.write16(0x504, 0xbeef).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read16(0x508).unwrap(), 0xbeef);
        assert_eq!(cpu.pc, 0x106);
    }

    #[test]
    fn move_immediate_and_movea_word_work() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x203c).unwrap(); // MOVE.L #imm,D0
        bus.write32(0x102, 0x1234_5678).unwrap();
        bus.write16(0x106, 0x327c).unwrap(); // MOVEA.W #$ff00,A1
        bus.write16(0x108, 0xff00).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.step(&mut bus).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], 0x1234_5678);
        assert_eq!(cpu.a[1], 0xffff_ff00);
    }

    #[test]
    fn pc_relative_and_indexed_sources_work() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x303a).unwrap(); // MOVE.W d16(PC),D0
        bus.write16(0x102, 0x000c).unwrap(); // base 0x102 -> 0x10e
        bus.write16(0x104, 0x3230).unwrap(); // MOVE.W d8(A0,D1.W),D1
        bus.write16(0x106, 0x1004).unwrap(); // D1.W + 4
        bus.write16(0x10e, 0x1234).unwrap();
        bus.write16(0x506, 0xabcd).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.d[1] = 2;
        cpu.step(&mut bus).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xffff, 0x1234);
        assert_eq!(cpu.d[1] & 0xffff, 0xabcd);
    }

    #[test]
    fn lea_pc_relative_calculates_address_without_reading_operand() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x43fa).unwrap(); // LEA d16(PC),A1
        bus.write16(0x102, 0x0010).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.a[1], 0x112);
    }

    #[test]
    fn add_sub_cmp_share_correct_flag_primitives() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xd001).unwrap(); // ADD.B D1,D0
        bus.write16(0x102, 0x9001).unwrap(); // SUB.B D1,D0
        bus.write16(0x104, 0xb001).unwrap(); // CMP.B D1,D0
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.d[0] = 0x7f;
        cpu.d[1] = 1;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0x80);
        assert_ne!(cpu.sr & CCR_V, 0);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0x7f);
        let before = cpu.d[0];
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], before);
    }

    #[test]
    fn clr_and_tst_use_ea_and_preserve_x() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x4210).unwrap(); // CLR.B (A0)
        bus.write16(0x102, 0x4a10).unwrap(); // TST.B (A0)
        bus.write8(0x500, 0x80).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.sr |= CCR_X;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read8(0x500).unwrap(), 0);
        assert_ne!(cpu.sr & CCR_Z, 0);
        assert_ne!(cpu.sr & CCR_X, 0);
        cpu.step(&mut bus).unwrap();
        assert_ne!(cpu.sr & CCR_Z, 0);
        assert_ne!(cpu.sr & CCR_X, 0);
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
