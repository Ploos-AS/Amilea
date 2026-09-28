//! Deterministic Motorola 68000 execution boundary for Amilea M1.

use amilea_bus::{Bus, BusError};
use thiserror::Error;

const CCR_X: u16 = 0x10;
const CCR_N: u16 = 0x08;
const CCR_Z: u16 = 0x04;
const SR_TRACE: u16 = 0x8000;
const SR_SUPERVISOR: u16 = 0x2000;
const CCR_V: u16 = 0x02;
const CCR_C: u16 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Size { Byte, Word, Long }

#[derive(Debug, Clone, Copy)]
enum RmwTarget { DataReg(usize), Memory(u32) }

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
    pub usp: u32,
    pub ssp: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CpuError {
    #[error(transparent)]
    Bus(#[from] BusError),
    #[error("68000 opcode {opcode:#06x} is not implemented")]
    UnimplementedOpcode { opcode: u16 },
    #[error("68000 data access fault: {fault}")]
    DataAccess { fault: BusError, read: bool },
}

impl Default for Cpu {
    fn default() -> Self {
        Self { d: [0; 8], a: [0; 8], pc: 0, sr: 0x2700, stopped: false, usp: 0, ssp: 0 }
    }
}

impl Cpu {
    pub fn reset<B: Bus>(&mut self, bus: &B) -> Result<(), CpuError> {
        self.d = [0; 8];
        self.a = [0; 8];
        self.sr = 0x2700;
        self.stopped = false;
        self.ssp = bus.read32(0)?;
        self.usp = 0;
        self.a[7] = self.ssp;
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

        let result = match opcode {
            0x0000..=0x0cff if opcode & 0x0f00 != 0x0800 => {
                let family = opcode & 0x0f00;
                let size_bits = (opcode >> 6) & 3;
                if size_bits == 3 {
                    self.enter_exception(bus, 4, instruction_pc)?;
                    return Ok(34);
                }
                let size = decode_size(size_bits).unwrap();
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                let immediate = match size {
                    Size::Byte => self.fetch16(bus)? as u8 as u32,
                    Size::Word => self.fetch16(bus)? as u32,
                    Size::Long => self.fetch32(bus)?,
                };
                let target = self.resolve_rmw(bus, size, mode, reg)?;
                let dst = self.read_rmw(bus, size, target)?;
                let result = match family {
                    0x0000 => { let r = dst | immediate; self.set_logic_flags(size, r); r }
                    0x0200 => { let r = dst & immediate; self.set_logic_flags(size, r); r }
                    0x0400 => self.alu_sub(size, dst, immediate, true),
                    0x0600 => self.alu_add(size, dst, immediate),
                    0x0a00 => { let r = dst ^ immediate; self.set_logic_flags(size, r); r }
                    0x0c00 => {
                        self.alu_sub(size, dst, immediate, false);
                        return Ok(4);
                    }
                    _ => {
                        self.enter_exception(bus, 4, instruction_pc)?;
                        return Ok(34);
                    }
                };
                self.write_rmw(bus, size, target, result)?;
                Ok(4)
            }
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
            // Overlapping 68000 encodings must never fall through to the generic ALU decoder.
            // Keep them explicit until their instruction families are implemented.
            0x8100..=0x81ff if opcode & 0x01f0 == 0x0100 => Err(CpuError::UnimplementedOpcode { opcode }), // SBCD
            0xc100..=0xc1ff if opcode & 0x01f0 == 0x0100 => Err(CpuError::UnimplementedOpcode { opcode }), // ABCD
            0x9100..=0x91ff if opcode & 0x0130 == 0x0100 => self.exec_addx_subx(bus, opcode, false),
            0xd100..=0xd1ff if opcode & 0x0130 == 0x0100 => self.exec_addx_subx(bus, opcode, true),
            0xb108..=0xb1ff if opcode & 0x0138 == 0x0108 => self.exec_cmpm(bus, opcode),
            0xc140..=0xc1ff if matches!(opcode & 0x01f8, 0x0140 | 0x0148 | 0x0188) => Err(CpuError::UnimplementedOpcode { opcode }), // EXG
            0x80c0..=0x80ff | 0x81c0..=0x81ff => Err(CpuError::UnimplementedOpcode { opcode }), // DIVU/DIVS
            0xc0c0..=0xc0ff | 0xc1c0..=0xc1ff => Err(CpuError::UnimplementedOpcode { opcode }), // MULU/MULS
            0x8000..=0x8fff | 0x9000..=0x9fff | 0xb000..=0xbfff | 0xc000..=0xcfff | 0xd000..=0xdfff => {
                let top = opcode >> 12;
                let opmode = ((opcode >> 6) & 7) as u8;
                let dn = ((opcode >> 9) & 7) as usize;
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;

                if matches!(top, 0x9 | 0xb | 0xd) && matches!(opmode, 3 | 7) {
                    let size = if opmode == 3 { Size::Word } else { Size::Long };
                    let raw = self.read_ea(bus, size, mode, reg)?;
                    let src = if size == Size::Word { raw as u16 as i16 as i32 as u32 } else { raw };
                    if top == 0xb {
                        self.alu_sub(Size::Long, self.a[dn], src, false);
                    } else if top == 0x9 {
                        self.a[dn] = self.a[dn].wrapping_sub(src);
                    } else {
                        self.a[dn] = self.a[dn].wrapping_add(src);
                    }
                    return Ok(4);
                }

                if matches!(opmode, 4 | 5 | 6) {
                    let size = decode_size((opmode - 4) as u16).unwrap();
                    let src = self.d[dn] & size.mask();
                    let target = self.resolve_rmw(bus, size, mode, reg)?;
                    let dst = self.read_rmw(bus, size, target)?;
                    let result = match top {
                        0x8 => { let r = dst | src; self.set_logic_flags(size, r); r }
                        0x9 => self.alu_sub(size, dst, src, true),
                        0xb => { let r = dst ^ src; self.set_logic_flags(size, r); r }
                        0xc => { let r = dst & src; self.set_logic_flags(size, r); r }
                        0xd => self.alu_add(size, dst, src),
                        _ => unreachable!(),
                    };
                    self.write_rmw(bus, size, target, result)?;
                    return Ok(4);
                }
                if opmode > 2 {
                    self.enter_exception(bus, 4, instruction_pc)?;
                    return Ok(34);
                }
                let size = decode_size(opmode as u16).unwrap();
                let src = self.read_ea(bus, size, mode, reg)?;
                let dst = self.d[dn] & size.mask();
                let result = match top {
                    0x8 => { let r = dst | src; self.set_logic_flags(size, r); r }
                    0x9 => self.alu_sub(size, dst, src, true),
                    0xb => self.alu_sub(size, dst, src, false),
                    0xc => { let r = dst & src; self.set_logic_flags(size, r); r }
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
            0x4840..=0x4847 => {
                let reg = (opcode & 7) as usize;
                self.d[reg] = self.d[reg].rotate_left(16);
                self.set_logic_flags(Size::Long, self.d[reg]);
                Ok(4)
            }
            0x4848..=0x487f => {
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                let address = self.ea_address(bus, mode, reg)?;
                self.push32(bus, address)?;
                Ok(12)
            }
            0x4880..=0x4887 => {
                let reg = (opcode & 7) as usize;
                let value = self.d[reg] as u8 as i8 as i16 as u16 as u32;
                self.d[reg] = (self.d[reg] & 0xffff_0000) | value;
                self.set_logic_flags(Size::Word, value);
                Ok(4)
            }
            0x48c0..=0x48c7 => {
                let reg = (opcode & 7) as usize;
                let value = self.d[reg] as u16 as i16 as i32 as u32;
                self.d[reg] = value;
                self.set_logic_flags(Size::Long, value);
                Ok(4)
            }
            0x4e50..=0x4e57 => {
                let reg = (opcode & 7) as usize;
                let displacement = self.fetch16(bus)? as i16 as i32;
                let old = self.a[reg];
                self.push32(bus, old)?;
                self.a[reg] = self.a[7];
                self.a[7] = add_displacement(self.a[7], displacement);
                Ok(16)
            }
            0x4e58..=0x4e5f => {
                let reg = (opcode & 7) as usize;
                self.a[7] = self.a[reg];
                self.a[reg] = self.pop32(bus)?;
                Ok(12)
            }
            0x4e80..=0x4ebf => {
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                let target = self.ea_address(bus, mode, reg)?;
                let return_pc = self.pc;
                self.push32(bus, return_pc)?;
                self.pc = target;
                Ok(16)
            }
            0x4ec0..=0x4eff => {
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                self.pc = self.ea_address(bus, mode, reg)?;
                Ok(8)
            }
            0x4e71 => Ok(4),
            0x4e75 => { self.pc = self.pop32(bus)?; Ok(16) }
            0x4e60..=0x4e67 => {
                if !self.supervisor() {
                    self.enter_exception(bus, 8, instruction_pc)?;
                    return Ok(34);
                }
                let reg = (opcode & 7) as usize;
                self.usp = self.a[reg];
                Ok(4)
            }
            0x4e68..=0x4e6f => {
                if !self.supervisor() {
                    self.enter_exception(bus, 8, instruction_pc)?;
                    return Ok(34);
                }
                let reg = (opcode & 7) as usize;
                self.a[reg] = self.usp;
                Ok(4)
            }
            0x4e73 => {
                if !self.supervisor() {
                    self.enter_exception(bus, 8, instruction_pc)?;
                    return Ok(34);
                }
                let restored_sr = self.pop16(bus)?;
                let restored_pc = self.pop32(bus)?;
                self.set_sr(restored_sr);
                self.pc = restored_pc;
                Ok(20)
            }
            0x4e72 => {
                if !self.supervisor() {
                    self.enter_exception(bus, 8, instruction_pc)?;
                    return Ok(34);
                }
                let new_sr = self.fetch16(bus)?;
                self.set_sr(new_sr);
                self.stopped = true;
                Ok(4)
            }
            0x4e40..=0x4e4f => {
                let vector = 32 + (opcode & 0x000f) as u8;
                self.enter_exception(bus, vector, self.pc)?;
                Ok(34)
            }
            0x6000..=0x6fff => {
                let condition = ((opcode >> 8) & 0x0f) as u8;
                let short = opcode as u8 as i8;
                let base = self.pc;
                let displacement = if short == 0 {
                    self.fetch16(bus)? as i16 as i32
                } else {
                    short as i32
                };
                if condition == 0 {
                    self.pc = add_displacement(base, displacement);
                    Ok(10)
                } else if condition == 1 {
                    let return_pc = self.pc;
                    self.push32(bus, return_pc)?;
                    self.pc = add_displacement(base, displacement);
                    Ok(18)
                } else if self.condition_true(condition) {
                    self.pc = add_displacement(base, displacement);
                    Ok(10)
                } else {
                    Ok(if short == 0 { 12 } else { 8 })
                }
            }
            0x50c8..=0x5fcf => {
                let condition = ((opcode >> 8) & 0x0f) as u8;
                let reg = (opcode & 7) as usize;
                let displacement = self.fetch16(bus)? as i16 as i32;
                if self.condition_true(condition) {
                    Ok(12)
                } else {
                    let counter = (self.d[reg] as u16).wrapping_sub(1);
                    self.d[reg] = (self.d[reg] & 0xffff_0000) | counter as u32;
                    if counter != 0xffff {
                        self.pc = add_displacement(self.pc, displacement);
                        Ok(10)
                    } else {
                        Ok(14)
                    }
                }
            }
            0x50c0..=0x5fff if ((opcode >> 6) & 3) == 3 => {
                let condition = ((opcode >> 8) & 0x0f) as u8;
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                let value = if self.condition_true(condition) { 0xff } else { 0x00 };
                self.write_ea(bus, Size::Byte, mode, reg, value)?;
                Ok(4)
            }
            0x7000..=0x7fff => {
                let register = ((opcode >> 9) & 7) as usize;
                let value = (opcode as u8 as i8 as i32) as u32;
                self.d[register] = value;
                self.set_nz32(value);
                Ok(4)
            }
            0x4afc => {
                self.enter_exception(bus, 4, instruction_pc)?;
                Ok(34)
            }
            0xa000..=0xafff => {
                self.enter_exception(bus, 10, instruction_pc)?;
                Ok(34)
            }
            0xf000..=0xffff => {
                self.enter_exception(bus, 11, instruction_pc)?;
                Ok(34)
            }
            _ => Err(CpuError::UnimplementedOpcode { opcode }),

        };
        match result {
            Err(CpuError::DataAccess { fault, read }) => {
                let (vector, address) = match fault {
                    BusError::AddressError { address } => (3, address),
                    BusError::Unmapped { address } => (2, address),
                };
                self.enter_access_fault(bus, vector, instruction_pc, opcode, address, read, false)?;
                Ok(50)
            }
            other => other,
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
        self.enter_supervisor();
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
        self.enter_supervisor();
        self.push32(bus, saved_pc)?;
        self.push16(bus, saved_sr)?;
        self.pc = bus.read32((vector as u32) * 4)? & 0x00ff_ffff;
        Ok(())
    }

    fn supervisor(&self) -> bool { self.sr & SR_SUPERVISOR != 0 }

    fn enter_supervisor(&mut self) {
        if !self.supervisor() {
            self.usp = self.a[7];
            self.a[7] = self.ssp;
        }
        self.sr = (self.sr | SR_SUPERVISOR) & !SR_TRACE;
    }

    fn set_sr(&mut self, value: u16) {
        let was_supervisor = self.supervisor();
        let will_supervisor = value & SR_SUPERVISOR != 0;
        if was_supervisor && !will_supervisor {
            self.ssp = self.a[7];
            self.a[7] = self.usp;
        } else if !was_supervisor && will_supervisor {
            self.usp = self.a[7];
            self.a[7] = self.ssp;
        }
        self.sr = value;
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

    fn exec_addx_subx<B: Bus>(&mut self, bus: &mut B, opcode: u16, add: bool) -> Result<u32, CpuError> {
        let size_bits = (opcode >> 6) & 3;
        let size = decode_size(size_bits).ok_or(CpuError::UnimplementedOpcode { opcode })?;
        let dst_reg = ((opcode >> 9) & 7) as usize;
        let src_reg = (opcode & 7) as usize;
        let memory = opcode & 0x0008 != 0;
        let x = if self.sr & CCR_X != 0 { 1u64 } else { 0 };
        let (src, dst, src_addr, dst_addr) = if memory {
            self.a[src_reg] = self.a[src_reg].wrapping_sub(size.bytes(src_reg)) & 0x00ff_ffff;
            let sa = self.a[src_reg];
            self.a[dst_reg] = self.a[dst_reg].wrapping_sub(size.bytes(dst_reg)) & 0x00ff_ffff;
            let da = self.a[dst_reg];
            (self.read_mem(bus, size, sa)?, self.read_mem(bus, size, da)?, Some(sa), Some(da))
        } else {
            (self.d[src_reg] & size.mask(), self.d[dst_reg] & size.mask(), None, None)
        };
        let mask = size.mask() as u64;
        let sign = size.sign();
        let old_z = self.sr & CCR_Z != 0;
        let (result, carry, overflow) = if add {
            let wide = dst as u64 + src as u64 + x;
            let r = (wide & mask) as u32;
            let ov = (!(dst ^ src) & (dst ^ r) & sign) != 0;
            (r, wide > mask, ov)
        } else {
            let subtrahend = src as u64 + x;
            let r = (dst as u64).wrapping_sub(subtrahend) as u32 & size.mask();
            let ov = ((dst ^ src) & (dst ^ r) & sign) != 0;
            (r, (dst as u64) < subtrahend, ov)
        };
        self.sr &= !(CCR_X | CCR_N | CCR_Z | CCR_V | CCR_C);
        if result & sign != 0 { self.sr |= CCR_N; }
        if result == 0 && old_z { self.sr |= CCR_Z; }
        if overflow { self.sr |= CCR_V; }
        if carry { self.sr |= CCR_C | CCR_X; }
        if let Some(address) = dst_addr {
            self.write_mem(bus, size, address, result)?;
        } else {
            let mask32 = size.mask();
            self.d[dst_reg] = (self.d[dst_reg] & !mask32) | result;
        }
        let _ = src_addr;
        Ok(if memory { 18 } else if size == Size::Long { 8 } else { 4 })
    }

    fn exec_cmpm<B: Bus>(&mut self, bus: &B, opcode: u16) -> Result<u32, CpuError> {
        let size = decode_size((opcode >> 6) & 3).ok_or(CpuError::UnimplementedOpcode { opcode })?;
        let dst_reg = ((opcode >> 9) & 7) as usize;
        let src_reg = (opcode & 7) as usize;
        let src_addr = self.a[src_reg];
        let src = self.read_mem(bus, size, src_addr)?;
        self.a[src_reg] = self.a[src_reg].wrapping_add(size.bytes(src_reg)) & 0x00ff_ffff;
        let dst_addr = self.a[dst_reg];
        let dst = self.read_mem(bus, size, dst_addr)?;
        self.a[dst_reg] = self.a[dst_reg].wrapping_add(size.bytes(dst_reg)) & 0x00ff_ffff;
        self.alu_sub(size, dst, src, false);
        Ok(12)
    }

    fn resolve_rmw<B: Bus>(&mut self, bus: &B, size: Size, mode: u8, reg: usize) -> Result<RmwTarget, CpuError> {
        Ok(match mode {
            0 => RmwTarget::DataReg(reg),
            2 => RmwTarget::Memory(self.a[reg]),
            3 => {
                let address = self.a[reg];
                self.a[reg] = self.a[reg].wrapping_add(size.bytes(reg)) & 0x00ff_ffff;
                RmwTarget::Memory(address)
            }
            4 => {
                self.a[reg] = self.a[reg].wrapping_sub(size.bytes(reg)) & 0x00ff_ffff;
                RmwTarget::Memory(self.a[reg])
            }
            5 => {
                let displacement = self.fetch16(bus)? as i16 as i32;
                RmwTarget::Memory(add_displacement(self.a[reg], displacement))
            }
            6 => {
                let base = self.a[reg];
                RmwTarget::Memory(self.indexed_address(bus, base)?)
            }
            7 if reg == 0 => RmwTarget::Memory(self.fetch16(bus)? as i16 as i32 as u32 & 0x00ff_ffff),
            7 if reg == 1 => RmwTarget::Memory(self.fetch32(bus)? & 0x00ff_ffff),
            _ => return Err(CpuError::UnimplementedOpcode { opcode: 0 }),
        })
    }

    fn read_rmw<B: Bus>(&self, bus: &B, size: Size, target: RmwTarget) -> Result<u32, CpuError> {
        match target {
            RmwTarget::DataReg(reg) => Ok(self.d[reg] & size.mask()),
            RmwTarget::Memory(address) => self.read_mem(bus, size, address),
        }
    }

    fn write_rmw<B: Bus>(&mut self, bus: &mut B, size: Size, target: RmwTarget, value: u32) -> Result<(), CpuError> {
        match target {
            RmwTarget::DataReg(reg) => {
                let mask = size.mask();
                self.d[reg] = (self.d[reg] & !mask) | (value & mask);
                Ok(())
            }
            RmwTarget::Memory(address) => self.write_mem(bus, size, address, value),
        }
    }

    fn read_mem<B: Bus>(&self, bus: &B, size: Size, address: u32) -> Result<u32, CpuError> {
        let result = match size {
            Size::Byte => bus.read8(address).map(|value| value as u32),
            Size::Word => bus.read16(address).map(|value| value as u32),
            Size::Long => bus.read32(address),
        };
        result.map_err(|fault| CpuError::DataAccess { fault, read: true })
    }

    fn write_mem<B: Bus>(&self, bus: &mut B, size: Size, address: u32, value: u32) -> Result<(), CpuError> {
        let result = match size {
            Size::Byte => bus.write8(address, value as u8),
            Size::Word => bus.write16(address, value as u16),
            Size::Long => bus.write32(address, value),
        };
        result.map_err(|fault| CpuError::DataAccess { fault, read: false })
    }

    fn condition_true(&self, condition: u8) -> bool {
        let c = self.sr & CCR_C != 0;
        let v = self.sr & CCR_V != 0;
        let z = self.sr & CCR_Z != 0;
        let n = self.sr & CCR_N != 0;
        match condition & 0x0f {
            0 => true,
            1 => false,
            2 => !c && !z,
            3 => c || z,
            4 => !c,
            5 => c,
            6 => !z,
            7 => z,
            8 => !v,
            9 => v,
            10 => !n,
            11 => n,
            12 => n == v,
            13 => n != v,
            14 => !z && n == v,
            15 => z || n != v,
            _ => unreachable!(),
        }
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
        self.sr &= !(CCR_N | CCR_Z | CCR_V | CCR_C);
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
        bus.write16(0x100, 0x4afc).unwrap();
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
    fn address_arithmetic_sign_extends_word_without_changing_ccr() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xd2fc).unwrap(); // ADDA.W #$ffff,A1
        bus.write16(0x102, 0xffff).unwrap();
        bus.write16(0x104, 0x95fc).unwrap(); // SUBA.W #1,A2
        bus.write16(0x106, 1).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[1] = 0x1000;
        cpu.a[2] = 0x1000;
        let sr = cpu.sr;
        cpu.step(&mut bus).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.a[1], 0x0fff);
        assert_eq!(cpu.a[2], 0x0fff);
        assert_eq!(cpu.sr, sr);
    }

    #[test]
    fn cmpa_sets_long_flags_and_does_not_modify_address_register() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xb3fc).unwrap(); // CMPA.W #$ffff,A1
        bus.write16(0x102, 0xffff).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[1] = 0xffff_ffff;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.a[1], 0xffff_ffff);
        assert_ne!(cpu.sr & CCR_Z, 0);
    }

    #[test]
    fn or_and_update_data_register_and_logic_flags() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x8001).unwrap(); // OR.B D1,D0
        bus.write16(0x102, 0xc001).unwrap(); // AND.B D1,D0
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.d[0] = 0xf0;
        cpu.d[1] = 0x0f;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0xff);
        assert_ne!(cpu.sr & CCR_N, 0);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0x0f);
        assert_eq!(cpu.sr & (CCR_N | CCR_Z | CCR_V | CCR_C), 0);
    }

    #[test]
    fn immediate_alu_family_operates_on_data_registers() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x0600).unwrap(); // ADDI.B #1,D0
        bus.write16(0x102, 1).unwrap();
        bus.write16(0x104, 0x0400).unwrap(); // SUBI.B #1,D0
        bus.write16(0x106, 1).unwrap();
        bus.write16(0x108, 0x0c00).unwrap(); // CMPI.B #$7f,D0
        bus.write16(0x10a, 0x7f).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.d[0] = 0x7f;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0x80);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0x7f);
        cpu.step(&mut bus).unwrap();
        assert_ne!(cpu.sr & CCR_Z, 0);
    }

    #[test]
    fn immediate_logic_and_eor_to_memory_use_ea_engine() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x0010).unwrap(); // ORI.B #$0f,(A0)
        bus.write16(0x102, 0x000f).unwrap();
        bus.write16(0x104, 0x0210).unwrap(); // ANDI.B #$3f,(A0)
        bus.write16(0x106, 0x003f).unwrap();
        bus.write16(0x108, 0xb110).unwrap(); // EOR.B D0,(A0)
        bus.write8(0x500, 0xf0).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.d[0] = 0x0f;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read8(0x500).unwrap(), 0xff);
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read8(0x500).unwrap(), 0x3f);
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read8(0x500).unwrap(), 0x30);
    }

    #[test]
    fn add_and_sub_data_register_to_memory_are_supported() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xd110).unwrap(); // ADD.B D0,(A0)
        bus.write16(0x102, 0x9310).unwrap(); // SUB.B D1,(A0)
        bus.write8(0x500, 10).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.d[0] = 5;
        cpu.d[1] = 3;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read8(0x500).unwrap(), 15);
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read8(0x500).unwrap(), 12);
    }

    #[test]
    fn bcc_uses_shared_condition_engine() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x6702).unwrap(); // BEQ.S +2
        bus.write16(0x102, 0x7001).unwrap(); // MOVEQ #1,D0
        bus.write16(0x104, 0x7002).unwrap(); // MOVEQ #2,D0
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.sr |= CCR_Z;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x104);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], 2);
    }

    #[test]
    fn dbcc_decrements_low_word_until_minus_one() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x51c8).unwrap(); // DBF D0,-4
        bus.write16(0x102, 0xfffc).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.d[0] = 1;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xffff, 0);
        assert_eq!(cpu.pc, 0x100);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xffff, 0xffff);
        assert_eq!(cpu.pc, 0x104);
    }

    #[test]
    fn scc_writes_ff_or_zero_without_changing_ccr() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x57c0).unwrap(); // SEQ D0
        bus.write16(0x102, 0x56c1).unwrap(); // SNE D1
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.sr |= CCR_Z;
        let sr = cpu.sr;
        cpu.step(&mut bus).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0xff);
        assert_eq!(cpu.d[1] & 0xff, 0x00);
        assert_eq!(cpu.sr, sr);
    }

    #[test]
    fn signed_conditions_use_n_xor_v() {
        let mut cpu = Cpu::default();
        cpu.sr = CCR_N | CCR_V;
        assert!(cpu.condition_true(12)); // GE
        assert!(cpu.condition_true(14)); // GT when Z clear
        cpu.sr = CCR_N;
        assert!(cpu.condition_true(13)); // LT
        assert!(cpu.condition_true(15)); // LE
    }

    #[test]
    fn jsr_and_jmp_use_general_control_addressing() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x4e90).unwrap(); // JSR (A0)
        bus.write16(0x200, 0x4ed1).unwrap(); // JMP (A1)
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x200;
        cpu.a[1] = 0x300;
        let sp = cpu.a[7];
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x200);
        assert_eq!(bus.read32(sp - 4).unwrap(), 0x102);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x300);
    }

    #[test]
    fn link_and_unlk_create_and_remove_stack_frame() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x4e56).unwrap(); // LINK A6,#-16
        bus.write16(0x102, 0xfff0).unwrap();
        bus.write16(0x104, 0x4e5e).unwrap(); // UNLK A6
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[6] = 0x1234;
        let sp = cpu.a[7];
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.a[6], sp - 4);
        assert_eq!(cpu.a[7], sp - 20);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.a[6], 0x1234);
        assert_eq!(cpu.a[7], sp);
    }

    #[test]
    fn pea_pushes_effective_address_not_contents() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x4868).unwrap(); // PEA 8(A0)
        bus.write16(0x102, 8).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x500;
        let sp = cpu.a[7];
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read32(sp - 4).unwrap(), 0x508);
    }

    #[test]
    fn swap_and_ext_update_nzvc_and_preserve_x() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x4840).unwrap(); // SWAP D0
        bus.write16(0x102, 0x4881).unwrap(); // EXT.W D1
        bus.write16(0x104, 0x48c1).unwrap(); // EXT.L D1
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.sr |= CCR_X;
        cpu.d[0] = 0x1234_8000;
        cpu.d[1] = 0x0000_0080;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], 0x8000_1234);
        assert_ne!(cpu.sr & CCR_N, 0);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[1] & 0xffff, 0xff80);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[1], 0xffff_ff80);
        assert_ne!(cpu.sr & CCR_X, 0);
    }

    #[test]
    fn user_exception_switches_to_ssp_and_rte_restores_usp() {
        let mut bus = boot_bus();
        bus.write32(32 * 4, 0x200).unwrap();
        bus.write16(0x100, 0x4e40).unwrap(); // TRAP #0
        bus.write16(0x200, 0x4e73).unwrap(); // RTE
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.ssp = 0x3000;
        cpu.usp = 0x2800;
        cpu.a[7] = cpu.usp;
        cpu.sr = 0x0000;
        cpu.step(&mut bus).unwrap();
        assert!(cpu.supervisor());
        assert_eq!(cpu.usp, 0x2800);
        assert_eq!(cpu.a[7], 0x2ffa);
        cpu.step(&mut bus).unwrap();
        assert!(!cpu.supervisor());
        assert_eq!(cpu.a[7], 0x2800);
        assert_eq!(cpu.ssp, 0x3000);
        assert_eq!(cpu.pc, 0x102);
    }

    #[test]
    fn privileged_instructions_trap_from_user_mode() {
        let mut bus = boot_bus();
        bus.write32(8 * 4, 0x240).unwrap();
        bus.write16(0x100, 0x4e72).unwrap(); // STOP
        bus.write16(0x102, 0x2700).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.ssp = 0x3000;
        cpu.usp = 0x2800;
        cpu.a[7] = cpu.usp;
        cpu.sr = 0;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x240);
        assert!(!cpu.stopped);
        assert_eq!(cpu.a[7], 0x2ffa);
    }

    #[test]
    fn move_usp_roundtrips_in_supervisor_mode() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x4e60).unwrap(); // MOVE A0,USP
        bus.write16(0x102, 0x4e69).unwrap(); // MOVE USP,A1
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x1234_5678;
        cpu.step(&mut bus).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.usp, 0x1234_5678);
        assert_eq!(cpu.a[1], 0x1234_5678);
    }

    #[test]
    fn line_a_and_line_f_use_architectural_vectors() {
        let mut bus = boot_bus();
        bus.write32(10 * 4, 0x220).unwrap();
        bus.write32(11 * 4, 0x240).unwrap();
        bus.write16(0x100, 0xa123).unwrap();
        bus.write16(0x102, 0xf123).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x220);
        cpu.a[7] = 0x3000;
        cpu.pc = 0x102;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x240);
    }

    #[test]
    fn unimplemented_opcode_is_host_error_not_guest_illegal() {
        let mut bus = boot_bus();
        bus.write32(4 * 4, 0x240).unwrap();
        bus.write16(0x100, 0x4e76).unwrap(); // TRAPV: valid 68000, not implemented yet
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        assert_eq!(cpu.step(&mut bus), Err(CpuError::UnimplementedOpcode { opcode: 0x4e76 }));
        assert_eq!(cpu.pc, 0x102);
    }

    #[test]
    fn exception_clears_live_trace_bit_but_stacks_original_sr() {
        let mut bus = boot_bus();
        bus.write32(32 * 4, 0x200).unwrap();
        bus.write16(0x100, 0x4e40).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.sr |= SR_TRACE;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.sr & SR_TRACE, 0);
        assert_ne!(bus.read16(cpu.a[7]).unwrap() & SR_TRACE, 0);
    }

    #[test]
    fn moveq_clears_v_and_c_but_preserves_x() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x7001).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.sr |= CCR_X | CCR_V | CCR_C;
        cpu.step(&mut bus).unwrap();
        assert_ne!(cpu.sr & CCR_X, 0);
        assert_eq!(cpu.sr & (CCR_V | CCR_C), 0);
    }

    #[test]
    fn odd_data_read_enters_address_error_vector() {
        let mut bus = boot_bus();
        bus.write32(3 * 4, 0x2c0).unwrap();
        bus.write16(0x100, 0x3010).unwrap(); // MOVE.W (A0),D0
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x501;
        let sp = cpu.a[7];
        assert_eq!(cpu.step(&mut bus).unwrap(), 50);
        assert_eq!(cpu.pc, 0x2c0);
        assert_eq!(cpu.a[7], sp - 14);
        assert_eq!(bus.read16(cpu.a[7] + 6).unwrap(), 0x3010);
        assert_eq!(bus.read32(cpu.a[7] + 10).unwrap(), 0x501);
        assert_ne!(bus.read16(cpu.a[7]).unwrap() & (1 << 4), 0);
    }

    #[test]
    fn odd_data_write_enters_address_error_vector_as_write() {
        let mut bus = boot_bus();
        bus.write32(3 * 4, 0x2c0).unwrap();
        bus.write16(0x100, 0x3080).unwrap(); // MOVE.W D0,(A0)
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x501;
        cpu.d[0] = 0x1234;
        assert_eq!(cpu.step(&mut bus).unwrap(), 50);
        assert_eq!(cpu.pc, 0x2c0);
        assert_eq!(bus.read32(cpu.a[7] + 10).unwrap(), 0x501);
        assert_eq!(bus.read16(cpu.a[7]).unwrap() & (1 << 4), 0);
    }

    #[test]
    fn unmapped_data_read_enters_bus_error_vector() {
        let mut bus = boot_bus();
        bus.write32(2 * 4, 0x2a0).unwrap();
        bus.write16(0x100, 0x2010).unwrap(); // MOVE.L (A0),D0
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x8000;
        assert_eq!(cpu.step(&mut bus).unwrap(), 50);
        assert_eq!(cpu.pc, 0x2a0);
        assert_eq!(bus.read32(cpu.a[7] + 10).unwrap(), 0x8000);
    }

    #[test]
    fn rmw_postincrement_updates_address_once() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xd118).unwrap(); // ADD.B D0,(A0)+
        bus.write8(0x500, 10).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.d[0] = 5;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read8(0x500).unwrap(), 15);
        assert_eq!(cpu.a[0], 0x501);
    }

    #[test]
    fn rmw_predecrement_updates_address_once() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x9361).unwrap(); // SUB.W D1,-(A1)
        bus.write16(0x4fe, 10).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[1] = 0x500;
        cpu.d[1] = 3;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read16(0x4fe).unwrap(), 7);
        assert_eq!(cpu.a[1], 0x4fe);
    }

    #[test]
    fn rmw_displacement_consumes_extension_once() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xd168).unwrap(); // ADD.W D0,4(A0)
        bus.write16(0x102, 4).unwrap();
        bus.write16(0x504, 10).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.d[0] = 5;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read16(0x504).unwrap(), 15);
        assert_eq!(cpu.pc, 0x104);
    }

    #[test]
    fn immediate_rmw_postincrement_resolves_once() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x0618).unwrap(); // ADDI.B #1,(A0)+
        bus.write16(0x102, 1).unwrap();
        bus.write8(0x500, 4).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read8(0x500).unwrap(), 5);
        assert_eq!(cpu.a[0], 0x501);
        assert_eq!(cpu.pc, 0x104);
    }

    #[test]
    fn addx_and_subx_use_extend_and_sticky_zero() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xd101).unwrap(); // ADDX.B D1,D0
        bus.write16(0x102, 0x9101).unwrap(); // SUBX.B D1,D0
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.d[0] = 0xff;
        cpu.d[1] = 0;
        cpu.sr = CCR_X | CCR_Z;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0);
        assert_ne!(cpu.sr & CCR_X, 0);
        assert_ne!(cpu.sr & CCR_Z, 0);
        cpu.d[1] = 0;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0xff);
        assert_ne!(cpu.sr & CCR_X, 0);
        assert_eq!(cpu.sr & CCR_Z, 0);
    }

    #[test]
    fn addx_memory_predecrements_each_operand_once() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xd109).unwrap(); // ADDX.B -(A1),-(A0)
        bus.write8(0x4ff, 2).unwrap();
        bus.write8(0x5ff, 3).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.a[1] = 0x600;
        cpu.sr = 0;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.a[0], 0x4ff);
        assert_eq!(cpu.a[1], 0x5ff);
        assert_eq!(bus.read8(0x4ff).unwrap(), 5);
    }

    #[test]
    fn cmpm_postincrements_both_operands_and_preserves_x() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xb149).unwrap(); // CMPM.W (A1)+,(A0)+
        bus.write16(0x500, 0x1234).unwrap();
        bus.write16(0x600, 0x1234).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.a[1] = 0x600;
        cpu.sr = CCR_X;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.a[0], 0x502);
        assert_eq!(cpu.a[1], 0x602);
        assert_ne!(cpu.sr & CCR_Z, 0);
        assert_ne!(cpu.sr & CCR_X, 0);
    }


    #[test]
    fn overlapping_alu_encodings_do_not_execute_as_generic_operations() {
        for opcode in [
            0x8100u16, // SBCD D0,D0
            0xc100,    // ABCD D0,D0
            0xc140,    // EXG D0,D0
            0x80c0,    // DIVU.W D0,D0
            0x81c0,    // DIVS.W D0,D0
            0xc0c0,    // MULU.W D0,D0
            0xc1c0,    // MULS.W D0,D0
        ] {
            let mut bus = boot_bus();
            bus.write16(0x100, opcode).unwrap();
            let mut cpu = Cpu::default();
            cpu.reset(&bus).unwrap();
            let before = cpu.clone();
            assert_eq!(
                cpu.step(&mut bus),
                Err(CpuError::UnimplementedOpcode { opcode }),
                "opcode {opcode:#06x}"
            );
            assert_eq!(cpu.d, before.d, "opcode {opcode:#06x} changed D registers");
            assert_eq!(cpu.a, before.a, "opcode {opcode:#06x} changed A registers");
        }
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
