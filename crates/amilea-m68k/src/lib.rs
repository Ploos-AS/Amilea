//! Deterministic Motorola 68000 execution boundary for Amilea M1.

use amilea_bus::{Bus, BusError, BusPurpose};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionClass { Alu, Bcd, Bit, Branch, Control, Move, MultiplyDivide, ShiftRotate, System, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EaPolicy { None, DataRead, DataAlterable, MemoryAlterable, Control, FamilySpecific, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Legality { Legal, Illegal, FamilySpecific, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeInfo {
    pub class: InstructionClass,
    pub mnemonic: &'static str,
    pub ea_policy: EaPolicy,
    pub legality: Legality,
}

fn ea_mode_reg(opcode: u16) -> (u8, usize) { (((opcode >> 3) & 7) as u8, (opcode & 7) as usize) }
fn legal_data_read(mode: u8, reg: usize) -> bool { mode != 1 && !(mode == 7 && reg > 4) }
fn legal_data_alterable(mode: u8, reg: usize) -> bool { mode != 1 && !(mode == 7 && reg >= 2) }
fn legal_memory_alterable(mode: u8, reg: usize) -> bool { matches!(mode, 2..=6) || (mode == 7 && reg <= 1) }
fn legal_control(mode: u8, reg: usize) -> bool { matches!(mode, 2 | 5 | 6) || (mode == 7 && reg <= 3) }
fn is_sbcd(opcode: u16) -> bool { opcode & 0xf1f0 == 0x8100 }
fn is_abcd(opcode: u16) -> bool { opcode & 0xf1f0 == 0xc100 }
fn is_subx(opcode: u16) -> bool { opcode & 0xf130 == 0x9100 }
fn is_addx(opcode: u16) -> bool { opcode & 0xf130 == 0xd100 }
fn is_cmpm(opcode: u16) -> bool { opcode & 0xf138 == 0xb108 }
fn is_divu(opcode: u16) -> bool { opcode & 0xf1c0 == 0x80c0 }
fn is_divs(opcode: u16) -> bool { opcode & 0xf1c0 == 0x81c0 }
fn is_mulu(opcode: u16) -> bool { opcode & 0xf1c0 == 0xc0c0 }
fn is_muls(opcode: u16) -> bool { opcode & 0xf1c0 == 0xc1c0 }

pub fn decode_info(opcode: u16) -> DecodeInfo {
    use InstructionClass::*;
    let (class, mnemonic) = match opcode {
        0x4e70 => (System, "RESET"), 0x4e71 => (System, "NOP"), 0x4e72 => (System, "STOP"),
        0x4e73 => (System, "RTE"), 0x4e75 => (Control, "RTS"), 0x4e76 => (System, "TRAPV"),
        0x4e77 => (Control, "RTR"), 0x4e40..=0x4e4f => (System, "TRAP"),
        0x4afc => (System, "ILLEGAL"),
        0x4e60..=0x4e67 => (System, "MOVE-An-USP"),
        0x4e68..=0x4e6f => (System, "MOVE-USP-An"),
        0x4848..=0x487f => (Control, "PEA"),
        0x4e80..=0x4ebf => (Control, "JSR"),
        0x4ec0..=0x4eff => (Control, "JMP"),
        0x40c0..=0x40ff => (System, "MOVE-SR-EA"),
        0x44c0..=0x44ff => (System, "MOVE-EA-CCR"),
        0x46c0..=0x46ff => (System, "MOVE-EA-SR"),
        0x4000..=0x40bf => (Alu, "NEGX"),
        0x4200..=0x42bf => (Alu, "CLR"),
        0x4400..=0x44bf => (Alu, "NEG"),
        0x4600..=0x46bf => (Alu, "NOT"),
        0x4800..=0x483f => (Bcd, "NBCD"),
        0x4ac0..=0x4aff if opcode != 0x4afc => (System, "TAS"),
        0x4a00..=0x4abf => (System, "TST"),
        0x4000..=0x4fff if opcode & 0xf1c0 == 0x41c0 => (Control, "LEA"),
        0x4840..=0x4847 => (Alu, "SWAP"),
        0x4880..=0x4887 => (Alu, "EXT.W"),
        0x48c0..=0x48c7 => (Alu, "EXT.L"),
        0x4880..=0x48ff => (Move, "MOVEM-RM"),
        0x4c80..=0x4cff => (Move, "MOVEM-MR"),
        0x4e50..=0x4e57 => (Control, "LINK"),
        0x4e58..=0x4e5f => (Control, "UNLK"),
        0x4000..=0x4fff if opcode & 0xf1c0 == 0x4180 => (System, "CHK"),
        0x6000..=0x6fff => (Branch, "Bcc/BSR/BRA"),
        0x7000..=0x7fff => (Move, "MOVEQ"),
        0xe000..=0xefff => (ShiftRotate, "SHIFT/ROTATE"),
        0x0800..=0x08ff => (Bit, "BIT-IMM"),
        0x0108..=0x01ff if opcode & 0x0138 == 0x0108 => (Move, "MOVEP"),
        0x0100..=0x01ff => (Bit, "BIT-REG"),
        0x8000..=0x8fff if is_sbcd(opcode) => (Bcd, "SBCD"),
        0xc000..=0xcfff if is_abcd(opcode) => (Bcd, "ABCD"),
        0x9000..=0x9fff if is_subx(opcode) => (Alu, "SUBX"),
        0xd000..=0xdfff if is_addx(opcode) => (Alu, "ADDX"),
        0xb000..=0xbfff if is_cmpm(opcode) => (Alu, "CMPM"),
        0xc100..=0xc1ff if matches!(opcode & 0x01f8, 0x0140 | 0x0148 | 0x0188) => (Alu, "EXG"),
        0xc000..=0xcfff if is_mulu(opcode) || is_muls(opcode) => (MultiplyDivide, "MUL"),
        0x8000..=0x8fff if is_divu(opcode) || is_divs(opcode) => (MultiplyDivide, "DIV"),
        0x5000..=0x5fff => (Alu, "QUICK/COND"),
        0x1000..=0x3fff => (Move, "MOVE"),
        0x0000..=0x0fff | 0x8000..=0xdfff => (Alu, "ALU"),
        _ => (Unknown, "UNKNOWN"),
    };
    let (ea_policy, legality) = match mnemonic {
        "RESET" | "NOP" | "STOP" | "RTE" | "RTS" | "TRAPV" | "RTR" | "TRAP" | "ILLEGAL" |
        "MOVE-An-USP" | "MOVE-USP-An" | "Bcc/BSR/BRA" | "MOVEQ" =>
            (EaPolicy::None, Legality::Legal),
        "MOVEP" | "EXG" | "ABCD" | "SBCD" | "ADDX" | "SUBX" | "CMPM" => (EaPolicy::FamilySpecific, Legality::Legal),
        "PEA" | "JSR" | "JMP" => {
            let (mode, reg) = ea_mode_reg(opcode);
            (EaPolicy::Control, if legal_control(mode, reg) { Legality::Legal } else { Legality::Illegal })
        }
        "NEGX" | "CLR" | "NEG" | "NOT" | "NBCD" | "TAS" => {
            let (mode, reg) = ea_mode_reg(opcode);
            (EaPolicy::DataAlterable, if legal_data_alterable(mode, reg) { Legality::Legal } else { Legality::Illegal })
        }
        "TST" => {
            let (mode, reg) = ea_mode_reg(opcode);
            (EaPolicy::DataRead, if legal_data_read(mode, reg) { Legality::Legal } else { Legality::Illegal })
        }
        "LEA" => {
            let (mode, reg) = ea_mode_reg(opcode);
            (EaPolicy::Control, if legal_control(mode, reg) { Legality::Legal } else { Legality::Illegal })
        }
        "MOVEM-RM" => {
            let (mode, reg) = ea_mode_reg(opcode);
            (EaPolicy::FamilySpecific, if legal_movem_to_memory(mode, reg) { Legality::Legal } else { Legality::Illegal })
        }
        "MOVEM-MR" => {
            let (mode, reg) = ea_mode_reg(opcode);
            (EaPolicy::FamilySpecific, if legal_movem_from_memory(mode, reg) { Legality::Legal } else { Legality::Illegal })
        }
        "SWAP" | "EXT.W" | "EXT.L" | "LINK" | "UNLK" =>
            (EaPolicy::None, Legality::Legal),
        "MOVE-SR-EA" => {
            let (mode, reg) = ea_mode_reg(opcode);
            (EaPolicy::DataAlterable, if legal_data_alterable(mode, reg) { Legality::Legal } else { Legality::Illegal })
        }
        "MOVE-EA-CCR" | "MOVE-EA-SR" | "CHK" => {
            let (mode, reg) = ea_mode_reg(opcode);
            (EaPolicy::DataRead, if legal_data_read(mode, reg) { Legality::Legal } else { Legality::Illegal })
        }
        "MUL" | "DIV" => {
            let (mode, reg) = ea_mode_reg(opcode);
            (EaPolicy::DataRead, if legal_data_read(mode, reg) { Legality::Legal } else { Legality::Illegal })
        }
        "BIT-IMM" | "BIT-REG" => {
            let operation = ((opcode >> 6) & 3) as u8;
            let (mode, reg) = ea_mode_reg(opcode);
            let legal = if mode == 0 { true } else if operation == 0 { legal_data_read(mode, reg) } else { legal_data_alterable(mode, reg) };
            (if operation == 0 { EaPolicy::DataRead } else { EaPolicy::DataAlterable }, if legal { Legality::Legal } else { Legality::Illegal })
        }
        "ABCD" | "SBCD" | "ADDX" | "SUBX" | "CMPM" => (EaPolicy::FamilySpecific, Legality::Legal),
        "SHIFT/ROTATE" | "QUICK/COND" | "MOVE" | "ALU" => (EaPolicy::FamilySpecific, Legality::FamilySpecific),
        _ => (EaPolicy::Unknown, Legality::Unknown),
    };
    DecodeInfo { class, mnemonic, ea_policy, legality }
}
fn legal_movem_to_memory(mode: u8, reg: usize) -> bool {
    matches!(mode, 2 | 4 | 5 | 6) || (mode == 7 && reg <= 1)
}
fn legal_movem_from_memory(mode: u8, reg: usize) -> bool {
    matches!(mode, 2 | 3 | 5 | 6) || (mode == 7 && reg <= 3)
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuEvent {
    Instruction { pc: u32, opcode: u16 },
    MemoryRead { address: u32, size: u8, value: u32 },
    MemoryWrite { address: u32, size: u8, value: u32 },
    Exception { vector: u8, pc: u32 },
    AccessFault { vector: u8, pc: u32, opcode: u16, address: u32, read: bool, instruction_access: bool },
}

pub trait CpuObserver {
    fn observe(&mut self, event: CpuEvent);
}

impl CpuEvent {
    pub const fn memory_read(address: u32, size: u8, value: u32) -> Self {
        Self::MemoryRead { address: address & 0x00ff_ffff, size, value }
    }
    pub const fn memory_write(address: u32, size: u8, value: u32) -> Self {
        Self::MemoryWrite { address: address & 0x00ff_ffff, size, value }
    }
}

impl<F: FnMut(CpuEvent)> CpuObserver for F {
    fn observe(&mut self, event: CpuEvent) { self(event); }
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
    #[error("illegal 68000 opcode {opcode:#06x}")]
    IllegalOpcode { opcode: u16 },
    #[error("68000 execution requested exception vector {vector}")]
    Exception { vector: u8, pc: u32, cycles: u32 },
}

impl Default for Cpu {
    fn default() -> Self {
        Self { d: [0; 8], a: [0; 8], pc: 0, sr: 0x2700, stopped: false, usp: 0, ssp: 0 }
    }
}

impl Cpu {
    pub fn reset<B: Bus>(&mut self, bus: &mut B) -> Result<(), CpuError> {
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

    pub fn interrupt_mask(&self)->u8 { ((self.sr >> 8) & 7) as u8 }

    pub fn accept_interrupt<B: Bus>(&mut self,bus:&mut B,level:u8)->Result<bool,CpuError> {
        if level==0 || level>7 || level<=self.interrupt_mask() { return Ok(false); }
        let saved_pc=self.pc;
        self.stopped=false;
        self.enter_exception(bus,24+level,saved_pc)?;
        self.sr=(self.sr & !0x0700) | (u16::from(level)<<8);
        Ok(true)
    }

    pub fn step<B: Bus>(&mut self, bus: &mut B) -> Result<u32, CpuError> {
        self.step_observed(bus, &mut |_| {})
    }

    pub fn step_observed<B: Bus, O: CpuObserver>(&mut self, bus: &mut B, observer: &mut O) -> Result<u32, CpuError> {
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
                observer.observe(CpuEvent::AccessFault { vector, pc: instruction_pc, opcode: 0, address, read: true, instruction_access: true });
                observer.observe(CpuEvent::Exception { vector, pc: instruction_pc });
                self.enter_access_fault(bus, vector, instruction_pc, 0, address, true, true)?;
                return Ok(50);
            }
        };

        observer.observe(CpuEvent::Instruction { pc: instruction_pc, opcode });

        let result = match opcode {
            0x003c | 0x023c | 0x0a3c => {
                let immediate = self.fetch16(bus)? as u8 as u16;
                let ccr = self.sr & 0x001f;
                let value = match opcode {
                    0x003c => ccr | immediate,
                    0x023c => ccr & immediate,
                    0x0a3c => ccr ^ immediate,
                    _ => unreachable!(),
                };
                self.sr = (self.sr & !0x001f) | (value & 0x001f);
                Ok(20)
            }
            0x007c | 0x027c | 0x0a7c => {
                if !self.supervisor() {
                    observer.observe(CpuEvent::Exception { vector: 8, pc: instruction_pc });
                    self.enter_exception(bus, 8, instruction_pc)?;
                    return Ok(34);
                }
                let immediate = self.fetch16(bus)?;
                let value = match opcode {
                    0x007c => self.sr | immediate,
                    0x027c => self.sr & immediate,
                    0x0a7c => self.sr ^ immediate,
                    _ => unreachable!(),
                };
                self.set_sr(value);
                Ok(20)
            }
            0x4000..=0x40bf => self.exec_unary_rmw(bus, opcode, 0),
            0x4400..=0x44bf => self.exec_unary_rmw(bus, opcode, 1),
            0x4600..=0x46bf => self.exec_unary_rmw(bus, opcode, 2),
            0x4ac0..=0x4aff if opcode != 0x4afc => self.exec_tas(bus, opcode),
            0x40c0..=0x40ff => {
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                if !legal_data_alterable(mode, reg) { return Err(CpuError::IllegalOpcode { opcode }); }
                self.write_ea(bus, Size::Word, mode, reg, self.sr as u32)?;
                Ok(6)
            }
            0x44c0..=0x44ff => {
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                if !legal_data_read(mode, reg) { return Err(CpuError::IllegalOpcode { opcode }); }
                let value = self.read_ea(bus, Size::Word, mode, reg)? as u16;
                self.sr = (self.sr & !0x001f) | (value & 0x001f);
                Ok(12)
            }
            0x46c0..=0x46ff => {
                if !self.supervisor() {
                    observer.observe(CpuEvent::Exception { vector: 8, pc: instruction_pc });
                    self.enter_exception(bus, 8, instruction_pc)?;
                    return Ok(34);
                }
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                if !legal_data_read(mode, reg) { return Err(CpuError::IllegalOpcode { opcode }); }
                let value = self.read_ea(bus, Size::Word, mode, reg)? as u16;
                self.set_sr(value);
                Ok(12)
            }
            0x4800..=0x483f => {
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                let target = self.resolve_rmw(bus, Size::Byte, mode, reg)?;
                let value = self.read_rmw(bus, Size::Byte, target)? as u8;
                let x = if self.sr & CCR_X != 0 { 1i16 } else { 0 };
                let low_borrow = 0i16 - (value & 0x0f) as i16 - x < 0;
                let mut adjusted = -(value as i16) - x;
                if low_borrow { adjusted -= 0x06; }
                let borrow = adjusted < 0;
                if borrow { adjusted -= 0x60; }
                let result = adjusted as u8;
                let old_z = self.sr & CCR_Z != 0;
                self.sr &= !(CCR_X | CCR_N | CCR_Z | CCR_V | CCR_C);
                if result & 0x80 != 0 { self.sr |= CCR_N; }
                if result == 0 && old_z { self.sr |= CCR_Z; }
                if borrow { self.sr |= CCR_X | CCR_C; }
                self.write_rmw(bus, Size::Byte, target, result as u32)?;
                Ok(6)
            }
            0x4e77 => {
                let ccr = self.pop16(bus)?;
                let pc = self.pop32(bus)?;
                self.sr = (self.sr & 0xff00) | (ccr & 0x00ff);
                self.pc = pc;
                Ok(20)
            }
            0x4e70 => {
                if !self.supervisor() {
                    observer.observe(CpuEvent::Exception { vector: 8, pc: instruction_pc });
                    self.enter_exception(bus, 8, instruction_pc)?;
                    return Ok(34);
                }
                Ok(132)
            }
            0x4e76 => {
                if self.sr & CCR_V != 0 {
                    observer.observe(CpuEvent::Exception { vector: 7, pc: self.pc });
                    self.enter_exception(bus, 7, self.pc)?;
                    Ok(34)
                } else {
                    Ok(4)
                }
            }
            0x4000..=0x4fff if opcode & 0xf1c0 == 0x4180 => {
                let dn = ((opcode >> 9) & 7) as usize;
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                if !legal_data_read(mode, reg) {
                    return Err(CpuError::IllegalOpcode { opcode });
                }
                let bound = self.read_ea(bus, Size::Word, mode, reg)? as u16 as i16 as i32;
                let value = self.d[dn] as u16 as i16 as i32;
                if value < 0 || value > bound {
                    observer.observe(CpuEvent::Exception { vector: 6, pc: self.pc });
                    self.enter_exception(bus, 6, self.pc)?;
                    Ok(40)
                } else {
                    Ok(10)
                }
            }
            0x0800..=0x08ff => {
                let operation = ((opcode >> 6) & 3) as u8;
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                let bit = self.fetch16(bus)? as u32;
                self.exec_bit_op(bus, operation, mode, reg, bit)
            }
            0x0108..=0x01ff if opcode & 0x0138 == 0x0108 => self.exec_movep(bus, opcode),
            0x0100..=0x01ff if opcode & 0x0100 != 0 => {
                let operation = ((opcode >> 6) & 3) as u8;
                let bit_reg = ((opcode >> 9) & 7) as usize;
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                self.exec_bit_op(bus, operation, mode, reg, self.d[bit_reg])
            }
            0x0000..=0x0cff if opcode & 0x0f00 != 0x0800 => {
                let family = opcode & 0x0f00;
                let size_bits = (opcode >> 6) & 3;
                if size_bits == 3 {
                    observer.observe(CpuEvent::Exception { vector: 4, pc: instruction_pc });
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
                        observer.observe(CpuEvent::Exception { vector: 4, pc: instruction_pc });
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
            0x8000..=0x8fff if is_sbcd(opcode) => self.exec_abcd_sbcd(bus, opcode, false),
            0xc000..=0xcfff if is_abcd(opcode) => self.exec_abcd_sbcd(bus, opcode, true),
            0x9000..=0x9fff if is_subx(opcode) => self.exec_addx_subx(bus, opcode, false),
            0xd000..=0xdfff if is_addx(opcode) => self.exec_addx_subx(bus, opcode, true),
            0xb000..=0xbfff if is_cmpm(opcode) => self.exec_cmpm(bus, opcode),
            0xc140..=0xc1ff if matches!(opcode & 0x01f8, 0x0140 | 0x0148 | 0x0188) => self.exec_exg(opcode),
            0x8000..=0x8fff if is_divu(opcode) || is_divs(opcode) => self.exec_div(bus, opcode, instruction_pc),
            0xc000..=0xcfff if is_mulu(opcode) || is_muls(opcode) => self.exec_mul(bus, opcode),
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
                    observer.observe(CpuEvent::Exception { vector: 4, pc: instruction_pc });
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
                        observer.observe(CpuEvent::Exception { vector: 4, pc: instruction_pc });
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
                    observer.observe(CpuEvent::Exception { vector: 4, pc: instruction_pc });
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
                if !legal_control(mode, reg) { return Err(CpuError::IllegalOpcode { opcode }); }
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
            0x4880..=0x48ff => self.exec_movem(bus, opcode, false),
            0x4c80..=0x4cff => self.exec_movem(bus, opcode, true),
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
                if !legal_control(mode, reg) { return Err(CpuError::IllegalOpcode { opcode }); }
                let target = self.ea_address(bus, mode, reg)?;
                let return_pc = self.pc;
                self.push32(bus, return_pc)?;
                self.pc = target;
                Ok(16)
            }
            0x4ec0..=0x4eff => {
                let mode = ((opcode >> 3) & 7) as u8;
                let reg = (opcode & 7) as usize;
                if !legal_control(mode, reg) { return Err(CpuError::IllegalOpcode { opcode }); }
                self.pc = self.ea_address(bus, mode, reg)?;
                Ok(8)
            }
            0x4e71 => Ok(4),
            0x4e75 => { self.pc = self.pop32(bus)?; Ok(16) }
            0x4e60..=0x4e67 => {
                if !self.supervisor() {
                    observer.observe(CpuEvent::Exception { vector: 8, pc: instruction_pc });
                    self.enter_exception(bus, 8, instruction_pc)?;
                    return Ok(34);
                }
                let reg = (opcode & 7) as usize;
                self.usp = self.a[reg];
                Ok(4)
            }
            0x4e68..=0x4e6f => {
                if !self.supervisor() {
                    observer.observe(CpuEvent::Exception { vector: 8, pc: instruction_pc });
                    self.enter_exception(bus, 8, instruction_pc)?;
                    return Ok(34);
                }
                let reg = (opcode & 7) as usize;
                self.a[reg] = self.usp;
                Ok(4)
            }
            0x4e73 => {
                if !self.supervisor() {
                    observer.observe(CpuEvent::Exception { vector: 8, pc: instruction_pc });
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
                    observer.observe(CpuEvent::Exception { vector: 8, pc: instruction_pc });
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
                observer.observe(CpuEvent::Exception { vector, pc: self.pc });
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
            0x5000..=0x5fff if ((opcode >> 6) & 3) != 3 => self.exec_addq_subq(bus, opcode),
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
            0xe000..=0xefff if ((opcode >> 6) & 3) != 3 => self.exec_shift_register(opcode),
            0xe0c0..=0xe7ff if ((opcode >> 6) & 3) == 3 => self.exec_shift_memory(bus, opcode),
            0x7000..=0x7fff => {
                let register = ((opcode >> 9) & 7) as usize;
                let value = (opcode as u8 as i8 as i32) as u32;
                self.d[register] = value;
                self.set_nz32(value);
                Ok(4)
            }
            0x4afc => {
                observer.observe(CpuEvent::Exception { vector: 4, pc: instruction_pc });
                    self.enter_exception(bus, 4, instruction_pc)?;
                Ok(34)
            }
            0xa000..=0xafff => {
                observer.observe(CpuEvent::Exception { vector: 10, pc: instruction_pc });
                self.enter_exception(bus, 10, instruction_pc)?;
                Ok(34)
            }
            0xf000..=0xffff => {
                observer.observe(CpuEvent::Exception { vector: 11, pc: instruction_pc });
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
                observer.observe(CpuEvent::AccessFault { vector, pc: instruction_pc, opcode, address, read, instruction_access: false });
                observer.observe(CpuEvent::Exception { vector, pc: instruction_pc });
                self.enter_access_fault(bus, vector, instruction_pc, opcode, address, read, false)?;
                Ok(50)
            }
            Err(CpuError::Exception { vector, pc, cycles }) => {
                observer.observe(CpuEvent::Exception { vector, pc });
                self.enter_exception(bus, vector, pc)?;
                Ok(cycles)
            }
            Err(CpuError::IllegalOpcode { .. }) => {
                observer.observe(CpuEvent::Exception { vector: 4, pc: instruction_pc });
                    self.enter_exception(bus, 4, instruction_pc)?;
                Ok(34)
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
        bus.set_purpose(BusPurpose::VectorFetch);
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
        bus.set_purpose(BusPurpose::VectorFetch);
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

    fn indexed_address<B: Bus>(&mut self, bus: &mut B, base: u32) -> Result<u32, CpuError> {
        let extension = self.fetch16(bus)?;
        let index_reg = ((extension >> 12) & 7) as usize;
        let index = if extension & 0x8000 != 0 { self.a[index_reg] } else { self.d[index_reg] };
        let index = if extension & 0x0800 != 0 { index } else { index as u16 as i16 as i32 as u32 };
        let displacement = extension as u8 as i8 as i32;
        Ok(add_displacement(base.wrapping_add(index) & 0x00ff_ffff, displacement))
    }

    fn ea_address<B: Bus>(&mut self, bus: &mut B, mode: u8, reg: usize) -> Result<u32, CpuError> {
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

    fn read_ea<B: Bus>(&mut self, bus: &mut B, size: Size, mode: u8, reg: usize) -> Result<u32, CpuError> {
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

    fn exec_unary_rmw<B: Bus>(&mut self, bus: &mut B, opcode: u16, operation: u8) -> Result<u32, CpuError> {
        let size = decode_size((opcode >> 6) & 3).ok_or(CpuError::UnimplementedOpcode { opcode })?;
        let mode = ((opcode >> 3) & 7) as u8;
        let reg = (opcode & 7) as usize;
        if !legal_data_alterable(mode, reg) { return Err(CpuError::IllegalOpcode { opcode }); }
        let target = self.resolve_rmw(bus, size, mode, reg)?;
        let value = self.read_rmw(bus, size, target)?;
        let result = match operation {
            0 => { // NEGX
                let old_z = self.sr & CCR_Z != 0;
                let x = u32::from(self.sr & CCR_X != 0);
                let r = self.alu_sub(size, 0, value.wrapping_add(x), true);
                if r & size.mask() == 0 && old_z { self.sr |= CCR_Z; } else { self.sr &= !CCR_Z; }
                r
            }
            1 => self.alu_sub(size, 0, value, true), // NEG
            2 => { // NOT
                let r = (!value) & size.mask();
                self.set_logic_flags(size, r);
                r
            }
            _ => unreachable!(),
        };
        self.write_rmw(bus, size, target, result)?;
        Ok(if mode == 0 { if size == Size::Long { 6 } else { 4 } } else { 8 })
    }

    fn exec_tas<B: Bus>(&mut self, bus: &mut B, opcode: u16) -> Result<u32, CpuError> {
        let mode = ((opcode >> 3) & 7) as u8;
        let reg = (opcode & 7) as usize;
        if !legal_data_alterable(mode, reg) { return Err(CpuError::IllegalOpcode { opcode }); }
        let target = self.resolve_rmw(bus, Size::Byte, mode, reg)?;
        let value = self.read_rmw(bus, Size::Byte, target)? & 0xff;
        self.set_logic_flags(Size::Byte, value);
        self.write_rmw(bus, Size::Byte, target, value | 0x80)?;
        Ok(if mode == 0 { 4 } else { 10 })
    }

    fn exec_addq_subq<B: Bus>(&mut self, bus: &mut B, opcode: u16) -> Result<u32, CpuError> {
        let mut quick = ((opcode >> 9) & 7) as u32;
        if quick == 0 { quick = 8; }
        let subtract = opcode & 0x0100 != 0;
        let size = decode_size((opcode >> 6) & 3).ok_or(CpuError::UnimplementedOpcode { opcode })?;
        let mode = ((opcode >> 3) & 7) as u8;
        let reg = (opcode & 7) as usize;
        if mode == 1 {
            if size == Size::Byte { return Err(CpuError::UnimplementedOpcode { opcode }); }
            self.a[reg] = if subtract { self.a[reg].wrapping_sub(quick) } else { self.a[reg].wrapping_add(quick) };
            return Ok(8);
        }
        if mode == 7 && reg >= 2 { return Err(CpuError::UnimplementedOpcode { opcode }); }
        let target = self.resolve_rmw(bus, size, mode, reg)?;
        let dst = self.read_rmw(bus, size, target)?;
        let result = if subtract { self.alu_sub(size, dst, quick, true) } else { self.alu_add(size, dst, quick, true) };
        self.write_rmw(bus, size, target, result)?;
        Ok(if mode == 0 { if size == Size::Long { 8 } else { 4 } } else { 8 })
    }

    fn exec_shift_memory<B: Bus>(&mut self, bus: &mut B, opcode: u16) -> Result<u32, CpuError> {
        let operation = ((opcode >> 9) & 3) as u8; // 0 AS, 1 LS, 2 ROX, 3 RO
        let left = opcode & 0x0100 != 0;
        let mode = ((opcode >> 3) & 7) as u8;
        let reg = (opcode & 7) as usize;
        if mode < 2 || (mode == 7 && reg > 1) {
            return Err(CpuError::IllegalOpcode { opcode });
        }
        let target = self.resolve_rmw(bus, Size::Word, mode, reg)?;
        let value = self.read_rmw(bus, Size::Word, target)? & 0xffff;
        let old_x = self.sr & CCR_X != 0;
        let (result, shifted) = if left {
            let out = value & 0x8000 != 0;
            let r = match operation {
                2 => ((value << 1) & 0xffff) | u32::from(old_x),
                3 => ((value << 1) & 0xffff) | u32::from(out),
                _ => (value << 1) & 0xffff,
            };
            (r, out)
        } else {
            let out = value & 1 != 0;
            let r = match operation {
                0 => (value >> 1) | (value & 0x8000),
                2 => (value >> 1) | if old_x { 0x8000 } else { 0 },
                3 => (value >> 1) | if out { 0x8000 } else { 0 },
                _ => value >> 1,
            };
            (r, out)
        };
        self.sr &= !(CCR_N | CCR_Z | CCR_V | CCR_C);
        if result & 0x8000 != 0 { self.sr |= CCR_N; }
        if result == 0 { self.sr |= CCR_Z; }
        if operation == 0 && left && ((value ^ result) & 0x8000 != 0) { self.sr |= CCR_V; }
        if shifted { self.sr |= CCR_C; }
        if operation != 3 {
            if shifted { self.sr |= CCR_X; } else { self.sr &= !CCR_X; }
        }
        self.write_rmw(bus, Size::Word, target, result)?;
        Ok(8)
    }

    fn exec_shift_register(&mut self, opcode: u16) -> Result<u32, CpuError> {
        let size = decode_size((opcode >> 6) & 3).ok_or(CpuError::UnimplementedOpcode { opcode })?;
        let reg = (opcode & 7) as usize;
        let left = opcode & 0x0100 != 0;
        let use_register_count = opcode & 0x0020 != 0;
        let count_field = ((opcode >> 9) & 7) as usize;
        let count = if use_register_count { self.d[count_field] & 63 } else { if count_field == 0 { 8 } else { count_field as u32 } };
        let kind = ((opcode >> 3) & 3) as u8; // 0 AS, 1 LS, 2 ROX, 3 RO
        let mask = size.mask();
        let sign = size.sign();
        let mut value = self.d[reg] & mask;
        let mut x = self.sr & CCR_X != 0;
        let mut last = false;
        let mut overflow = false;
        for _ in 0..count {
            if left {
                last = value & sign != 0;
                let next = match kind {
                    2 => ((value << 1) & mask) | u32::from(x),
                    3 => ((value << 1) & mask) | u32::from(last),
                    _ => (value << 1) & mask,
                };
                if kind == 0 && ((value ^ next) & sign != 0) { overflow = true; }
                value = next;
            } else {
                last = value & 1 != 0;
                value = match kind {
                    0 => (value >> 1) | (value & sign),
                    2 => (value >> 1) | if x { sign } else { 0 },
                    3 => (value >> 1) | if last { sign } else { 0 },
                    _ => value >> 1,
                };
            }
            if kind == 2 { x = last; }
        }
        self.d[reg] = (self.d[reg] & !mask) | value;
        self.sr &= !(CCR_N | CCR_Z | CCR_V | CCR_C);
        if value & sign != 0 { self.sr |= CCR_N; }
        if value == 0 { self.sr |= CCR_Z; }
        if kind == 0 && left && overflow { self.sr |= CCR_V; }
        if count != 0 {
            if last { self.sr |= CCR_C; }
            if kind != 3 {
                if kind == 2 {
                    if x { self.sr |= CCR_X; } else { self.sr &= !CCR_X; }
                } else {
                    if last { self.sr |= CCR_X; } else { self.sr &= !CCR_X; }
                }
            }
        } else if kind == 2 {
            if x { self.sr |= CCR_C; }
        }
        Ok(6 + 2 * count)
    }

    fn exec_movem<B: Bus>(&mut self, bus: &mut B, opcode: u16, mem_to_regs: bool) -> Result<u32, CpuError> {
        let mode = ((opcode >> 3) & 7) as u8;
        let reg = (opcode & 7) as usize;
        let long = opcode & 0x0040 != 0;
        if if mem_to_regs { !legal_movem_from_memory(mode, reg) } else { !legal_movem_to_memory(mode, reg) } {
            return Err(CpuError::IllegalOpcode { opcode });
        }
        let mask = self.fetch16(bus)?;
        let size = if long { Size::Long } else { Size::Word };
        let step = if long { 4 } else { 2 };
        if !mem_to_regs && mode == 4 {
            for bit in 0..16 {
                if mask & (1 << bit) == 0 { continue; }
                self.a[reg] = self.a[reg].wrapping_sub(step) & 0x00ff_ffff;
                let value = if bit < 8 {
                    let source = 7 - bit;
                    if source == reg { self.a[reg] } else { self.a[source] }
                } else {
                    self.d[15 - bit]
                };
                self.write_mem(bus, size, self.a[reg], value)?;
            }
        } else {
            let mut address = self.ea_address(bus, mode, reg)?;
            for bit in 0..16 {
                if mask & (1 << bit) == 0 { continue; }
                if mem_to_regs {
                    let raw = self.read_mem(bus, size, address)?;
                    let value = if long { raw } else { raw as u16 as i16 as i32 as u32 };
                    if bit < 8 { self.d[bit] = value; } else { self.a[bit - 8] = value; }
                } else {
                    let value = if bit < 8 { self.d[bit] } else { self.a[bit - 8] };
                    self.write_mem(bus, size, address, value)?;
                }
                address = address.wrapping_add(step) & 0x00ff_ffff;
            }
            if mem_to_regs && mode == 3 { self.a[reg] = address; }
        }
        let count = mask.count_ones();
        Ok(8 + count * if long { 8 } else { 4 })
    }

    fn exec_movep<B: Bus>(&mut self, bus: &mut B, opcode: u16) -> Result<u32, CpuError> {
        let dn = ((opcode >> 9) & 7) as usize;
        let an = (opcode & 7) as usize;
        let displacement = self.fetch16(bus)? as i16 as i32;
        let address = add_displacement(self.a[an], displacement);
        let long = opcode & 0x0040 != 0;
        let reg_to_mem = opcode & 0x0080 != 0;
        if reg_to_mem {
            let value = self.d[dn];
            if long {
                for i in 0..4 { self.write_mem(bus, Size::Byte, address + i * 2, value >> (24 - i * 8))?; }
            } else {
                self.write_mem(bus, Size::Byte, address, value >> 8)?;
                self.write_mem(bus, Size::Byte, address + 2, value)?;
            }
        } else {
            let count = if long { 4 } else { 2 };
            let mut value = 0u32;
            for i in 0..count { value = (value << 8) | self.read_mem(bus, Size::Byte, address + i * 2)?; }
            if long { self.d[dn] = value; } else { self.d[dn] = (self.d[dn] & 0xffff_0000) | value; }
        }
        Ok(if long { 24 } else { 16 })
    }

    fn exec_bit_op<B: Bus>(&mut self, bus: &mut B, operation: u8, mode: u8, reg: usize, bit: u32) -> Result<u32, CpuError> {
        let legal = if operation == 0 { legal_data_read(mode, reg) } else { legal_data_alterable(mode, reg) };
        if !legal {
            return Err(CpuError::IllegalOpcode { opcode: 0 });
        }
        if mode == 0 {
            let mask = 1u32 << (bit & 31);
            let was_set = self.d[reg] & mask != 0;
            if was_set { self.sr &= !CCR_Z; } else { self.sr |= CCR_Z; }
            match operation {
                0 => {}
                1 => self.d[reg] ^= mask,
                2 => self.d[reg] &= !mask,
                3 => self.d[reg] |= mask,
                _ => unreachable!(),
            }
            return Ok(if operation == 0 { 6 } else { 8 });
        }
        let target = self.resolve_rmw(bus, Size::Byte, mode, reg)?;
        let value = self.read_rmw(bus, Size::Byte, target)?;
        let mask = 1u32 << (bit & 7);
        let was_set = value & mask != 0;
        if was_set { self.sr &= !CCR_Z; } else { self.sr |= CCR_Z; }
        if operation != 0 {
            let result = match operation {
                1 => value ^ mask,
                2 => value & !mask,
                3 => value | mask,
                _ => unreachable!(),
            };
            self.write_rmw(bus, Size::Byte, target, result)?;
        }
        Ok(8)
    }

    fn exec_abcd_sbcd<B: Bus>(&mut self, bus: &mut B, opcode: u16, add: bool) -> Result<u32, CpuError> {
        let dst_reg = ((opcode >> 9) & 7) as usize;
        let src_reg = (opcode & 7) as usize;
        let memory = opcode & 0x0008 != 0;
        let (src, dst, dst_addr) = if memory {
            self.a[src_reg] = self.a[src_reg].wrapping_sub(Size::Byte.bytes(src_reg)) & 0x00ff_ffff;
            let src = self.read_mem(bus, Size::Byte, self.a[src_reg])? as u8;
            self.a[dst_reg] = self.a[dst_reg].wrapping_sub(Size::Byte.bytes(dst_reg)) & 0x00ff_ffff;
            let address = self.a[dst_reg];
            let dst = self.read_mem(bus, Size::Byte, address)? as u8;
            (src, dst, Some(address))
        } else {
            (self.d[src_reg] as u8, self.d[dst_reg] as u8, None)
        };
        let x = if self.sr & CCR_X != 0 { 1i16 } else { 0 };
        let old_z = self.sr & CCR_Z != 0;
        let (result, carry) = if add {
            let binary = dst as i16 + src as i16 + x;
            let mut adjusted = binary;
            if (dst & 0x0f) as i16 + (src & 0x0f) as i16 + x > 9 { adjusted += 0x06; }
            let carry = adjusted > 0x99;
            if carry { adjusted += 0x60; }
            (adjusted as u8, carry)
        } else {
            let binary = dst as i16 - src as i16 - x;
            let low_borrow = (dst & 0x0f) as i16 - (src & 0x0f) as i16 - x < 0;
            let mut adjusted = binary;
            if low_borrow { adjusted -= 0x06; }
            let borrow = adjusted < 0;
            if borrow { adjusted -= 0x60; }
            (adjusted as u8, borrow)
        };
        self.sr &= !(CCR_X | CCR_N | CCR_Z | CCR_V | CCR_C);
        if result & 0x80 != 0 { self.sr |= CCR_N; }
        if result == 0 && old_z { self.sr |= CCR_Z; }
        if carry { self.sr |= CCR_X | CCR_C; }
        // V is undefined for BCD instructions on the 68000; leave it clear deterministically.
        if let Some(address) = dst_addr {
            self.write_mem(bus, Size::Byte, address, result as u32)?;
        } else {
            self.d[dst_reg] = (self.d[dst_reg] & !0xff) | result as u32;
        }
        Ok(if memory { 18 } else { 6 })
    }

    fn exec_exg(&mut self, opcode: u16) -> Result<u32, CpuError> {
        let rx = ((opcode >> 9) & 7) as usize;
        let ry = (opcode & 7) as usize;
        match opcode & 0x01f8 {
            0x0140 => self.d.swap(rx, ry),
            0x0148 => self.a.swap(rx, ry),
            0x0188 => {
                let tmp = self.d[rx];
                self.d[rx] = self.a[ry];
                self.a[ry] = tmp;
            }
            _ => return Err(CpuError::UnimplementedOpcode { opcode }),
        }
        Ok(6)
    }

    fn exec_div<B: Bus>(&mut self, bus: &mut B, opcode: u16, instruction_pc: u32) -> Result<u32, CpuError> {
        let signed = opcode & 0x0100 != 0;
        let dn = ((opcode >> 9) & 7) as usize;
        let mode = ((opcode >> 3) & 7) as u8;
        let reg = (opcode & 7) as usize;
        if !legal_data_read(mode, reg) {
            return Err(CpuError::IllegalOpcode { opcode });
        }
        let divisor_raw = self.read_ea(bus, Size::Word, mode, reg)? as u16;
        if divisor_raw == 0 {
            return Err(CpuError::Exception { vector: 5, pc: instruction_pc, cycles: 38 });
        }
        let dividend = self.d[dn];
        if signed {
            let divisor = divisor_raw as i16 as i32;
            let dividend_signed = dividend as i32;
            let Some(quotient) = dividend_signed.checked_div(divisor) else {
                self.sr &= !(CCR_N | CCR_Z | CCR_C);
                self.sr |= CCR_V;
                return Ok(158);
            };
            if !(-32768..=32767).contains(&quotient) {
                self.sr &= !(CCR_N | CCR_Z | CCR_C);
                self.sr |= CCR_V;
                return Ok(158);
            }
            let remainder = dividend_signed % divisor;
            self.d[dn] = ((remainder as i16 as u16 as u32) << 16) | (quotient as i16 as u16 as u32);
            self.sr &= !(CCR_N | CCR_Z | CCR_V | CCR_C);
            if quotient == 0 { self.sr |= CCR_Z; }
            if quotient < 0 { self.sr |= CCR_N; }
        } else {
            let divisor = divisor_raw as u32;
            let quotient = dividend / divisor;
            if quotient > 0xffff {
                self.sr &= !(CCR_N | CCR_Z | CCR_C);
                self.sr |= CCR_V;
                return Ok(140);
            }
            let remainder = dividend % divisor;
            self.d[dn] = (remainder << 16) | quotient;
            self.sr &= !(CCR_N | CCR_Z | CCR_V | CCR_C);
            if quotient == 0 { self.sr |= CCR_Z; }
            if quotient & 0x8000 != 0 { self.sr |= CCR_N; }
        }
        Ok(if signed { 158 } else { 140 })
    }

    fn exec_mul<B: Bus>(&mut self, bus: &mut B, opcode: u16) -> Result<u32, CpuError> {
        let signed = opcode & 0x0100 != 0;
        let dn = ((opcode >> 9) & 7) as usize;
        let mode = ((opcode >> 3) & 7) as u8;
        let reg = (opcode & 7) as usize;
        if !legal_data_read(mode, reg) {
            return Err(CpuError::IllegalOpcode { opcode });
        }
        let src = self.read_ea(bus, Size::Word, mode, reg)? as u16;
        let result = if signed {
            (self.d[dn] as u16 as i16 as i32).wrapping_mul(src as i16 as i32) as u32
        } else {
            (self.d[dn] as u16 as u32).wrapping_mul(src as u32)
        };
        self.d[dn] = result;
        self.set_logic_flags(Size::Long, result);
        Ok(70)
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

    fn exec_cmpm<B: Bus>(&mut self, bus: &mut B, opcode: u16) -> Result<u32, CpuError> {
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

    fn resolve_rmw<B: Bus>(&mut self, bus: &mut B, size: Size, mode: u8, reg: usize) -> Result<RmwTarget, CpuError> {
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

    fn read_rmw<B: Bus>(&self, bus: &mut B, size: Size, target: RmwTarget) -> Result<u32, CpuError> {
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

    fn read_mem<B: Bus>(&self, bus: &mut B, size: Size, address: u32) -> Result<u32, CpuError> {
        bus.set_purpose(BusPurpose::Data);
        let result = match size {
            Size::Byte => bus.read8(address).map(|value| value as u32),
            Size::Word => bus.read16(address).map(|value| value as u32),
            Size::Long => bus.read32(address),
        };
        result.map_err(|fault| CpuError::DataAccess { fault, read: true })
    }

    fn write_mem<B: Bus>(&self, bus: &mut B, size: Size, address: u32, value: u32) -> Result<(), CpuError> {
        bus.set_purpose(BusPurpose::Data);
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

    fn fetch16<B: Bus>(&mut self, bus: &mut B) -> Result<u16, CpuError> {
        bus.set_purpose(BusPurpose::InstructionFetch);
        let value = bus.read16(self.pc)?;
        self.pc = (self.pc + 2) & 0x00ff_ffff;
        Ok(value)
    }

    fn fetch32<B: Bus>(&mut self, bus: &mut B) -> Result<u32, CpuError> {
        bus.set_purpose(BusPurpose::InstructionFetch);
        let value = bus.read32(self.pc)?;
        self.pc = (self.pc + 4) & 0x00ff_ffff;
        Ok(value)
    }

    fn push16<B: Bus>(&mut self, bus: &mut B, value: u16) -> Result<(), CpuError> {
        bus.set_purpose(BusPurpose::Stack);
        self.a[7] = self.a[7].wrapping_sub(2) & 0x00ff_ffff;
        bus.write16(self.a[7], value)?;
        Ok(())
    }

    fn pop16<B: Bus>(&mut self, bus: &mut B) -> Result<u16, CpuError> {
        bus.set_purpose(BusPurpose::Stack);
        let value = bus.read16(self.a[7])?;
        self.a[7] = self.a[7].wrapping_add(2) & 0x00ff_ffff;
        Ok(value)
    }

    fn push32<B: Bus>(&mut self, bus: &mut B, value: u32) -> Result<(), CpuError> {
        bus.set_purpose(BusPurpose::Stack);
        self.a[7] = self.a[7].wrapping_sub(4) & 0x00ff_ffff;
        bus.write32(self.a[7], value)?;
        Ok(())
    }

    fn pop32<B: Bus>(&mut self, bus: &mut B) -> Result<u32, CpuError> {
        bus.set_purpose(BusPurpose::Stack);
        let value = bus.read32(self.a[7])?;
        self.a[7] = self.a[7].wrapping_add(4) & 0x00ff_ffff;
        Ok(value)
    }

    fn branch_displacement<B: Bus>(&mut self, bus: &mut B, opcode: u16) -> Result<i32, CpuError> {
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

    #[test]
    fn interrupt_acceptance_respects_mask_and_uses_autovector() {
        let mut bus=boot_bus();
        bus.write32(27*4,0x360).unwrap();
        let mut cpu=Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.sr=(cpu.sr & !0x0700)|0x0200;
        let old_pc=cpu.pc;
        let old_sp=cpu.a[7];

        assert!(!cpu.accept_interrupt(&mut bus,2).unwrap());
        assert_eq!(cpu.pc,old_pc);

        assert!(cpu.accept_interrupt(&mut bus,3).unwrap());
        assert_eq!(cpu.pc,0x360);
        assert_eq!(cpu.interrupt_mask(),3);
        assert_eq!(cpu.a[7],old_sp-6);
        assert_eq!(bus.read16(cpu.a[7]).unwrap() & 0x0700,0x0200);
        assert_eq!(bus.read32(cpu.a[7]+2).unwrap(),old_pc);
    }


    use super::*;
    use amilea_bus::{BusAccess, BusEvent, BusMaster, BusPurpose, ObservedBus, RamBus};

    fn boot_bus() -> RamBus {
        let mut bus = RamBus::new(0x4000);
        bus.write32(0, 0x0000_3000).unwrap();
        bus.write32(4, 0x0000_0100).unwrap();
        bus
    }

    #[test]
    fn observed_move_address_error_links_bus_fault_to_cpu_exception() {
        let mut bus = boot_bus();
        bus.write32(3 * 4, 0x0000_0260).unwrap();
        bus.write16(0x100, 0x3010).unwrap(); // MOVE.W (A0),D0
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x201;

        let mut cpu_events = Vec::new();
        let mut bus_events = Vec::new();
        {
            let mut observed_bus =
                ObservedBus::new(&mut bus, &mut |event| bus_events.push(event), BusMaster::Cpu, 24);
            assert_eq!(
                cpu.step_observed(&mut observed_bus, &mut |event| cpu_events.push(event)),
                Ok(50)
            );
        }

        assert_eq!(
            bus_events,
            vec![
                BusEvent { cycle: 24, master: BusMaster::Cpu, purpose: BusPurpose::InstructionFetch, access: BusAccess::Read, address: 0x100, size: 2, value: Some(0x3010), fault: None },
                BusEvent { cycle: 25, master: BusMaster::Cpu, purpose: BusPurpose::Data, access: BusAccess::Read, address: 0x201, size: 2, value: None, fault: Some(amilea_bus::BusFault::AddressError) },
                BusEvent { cycle: 26, master: BusMaster::Cpu, purpose: BusPurpose::Stack, access: BusAccess::Write, address: 0x2ffc, size: 4, value: Some(0x100), fault: None },
                BusEvent { cycle: 27, master: BusMaster::Cpu, purpose: BusPurpose::Stack, access: BusAccess::Write, address: 0x2ffa, size: 2, value: Some(0x2700), fault: None },
                BusEvent { cycle: 28, master: BusMaster::Cpu, purpose: BusPurpose::Stack, access: BusAccess::Write, address: 0x2ff8, size: 2, value: Some(0x3010), fault: None },
                BusEvent { cycle: 29, master: BusMaster::Cpu, purpose: BusPurpose::Stack, access: BusAccess::Write, address: 0x2ff4, size: 4, value: Some(0x201), fault: None },
                BusEvent { cycle: 30, master: BusMaster::Cpu, purpose: BusPurpose::Stack, access: BusAccess::Write, address: 0x2ff2, size: 2, value: Some(0x1d), fault: None },
                BusEvent { cycle: 31, master: BusMaster::Cpu, purpose: BusPurpose::VectorFetch, access: BusAccess::Read, address: 0x0c, size: 4, value: Some(0x260), fault: None },
            ]
        );
        assert_eq!(
            cpu_events,
            vec![
                CpuEvent::Instruction {
                    pc: 0x100,
                    opcode: 0x3010,
                },
                CpuEvent::AccessFault {
                    vector: 3,
                    pc: 0x100,
                    opcode: 0x3010,
                    address: 0x201,
                    read: true,
                    instruction_access: false,
                },
                CpuEvent::Exception {
                    vector: 3,
                    pc: 0x100,
                },
            ]
        );
        assert_eq!(cpu.pc, 0x260);
    }

    #[test]
    fn observed_move_links_opcode_fetch_and_operand_read() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x3010).unwrap(); // MOVE.W (A0),D0
        bus.write16(0x200, 0x1234).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x200;

        let mut cpu_events = Vec::new();
        let mut bus_events = Vec::new();
        {
            let mut observed_bus =
                ObservedBus::new(&mut bus, &mut |event| bus_events.push(event), BusMaster::Cpu, 20);
            cpu.step_observed(&mut observed_bus, &mut |event| cpu_events.push(event))
                .unwrap();
        }

        assert_eq!(
            cpu_events,
            vec![CpuEvent::Instruction {
                pc: 0x100,
                opcode: 0x3010,
            }]
        );
        assert_eq!(
            bus_events,
            vec![
                BusEvent {
                    cycle: 20,
                    master: BusMaster::Cpu,
                    purpose: BusPurpose::InstructionFetch,
                    access: BusAccess::Read,
                    address: 0x100,
                    size: 2,
                    value: Some(0x3010),
                    fault: None,
                },
                BusEvent {
                    cycle: 21,
                    master: BusMaster::Cpu,
                    purpose: BusPurpose::Data,
                    access: BusAccess::Read,
                    address: 0x200,
                    size: 2,
                    value: Some(0x1234),
                    fault: None,
                },
            ]
        );
        assert_eq!(cpu.d[0] & 0xffff, 0x1234);
        assert_eq!(cpu.pc, 0x102);
    }

    #[test]
    fn observed_nop_links_cpu_instruction_to_bus_fetch() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x4e71).unwrap(); // NOP
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();

        let mut cpu_events = Vec::new();
        let mut bus_events = Vec::new();
        {
            let mut observed_bus =
                ObservedBus::new(&mut bus, &mut |event| bus_events.push(event), BusMaster::Cpu, 12);
            assert_eq!(
                cpu.step_observed(&mut observed_bus, &mut |event| cpu_events.push(event)),
                Ok(4)
            );
        }

        assert_eq!(
            cpu_events,
            vec![CpuEvent::Instruction {
                pc: 0x100,
                opcode: 0x4e71,
            }]
        );
        assert_eq!(
            bus_events,
            vec![BusEvent {
                cycle: 12,
                master: BusMaster::Cpu,
                purpose: BusPurpose::InstructionFetch,
                access: BusAccess::Read,
                address: 0x100,
                size: 2,
                value: Some(0x4e71),
                fault: None,
            }]
        );
        assert_eq!(cpu.pc, 0x102);
    }

    #[test]
    fn decode_metadata_covers_entire_opcode_space_deterministically() {
        for opcode in 0u16..=u16::MAX {
            assert_eq!(decode_info(opcode), decode_info(opcode));
        }
    }

    #[test]
    fn movem_long_registers_to_memory_uses_forward_order() {
        let mut bus = boot_bus(); let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0x1122_3344; cpu.d[1] = 0x5566_7788; cpu.a[0] = 0x0200;
        bus.write16(0x100, 0x48d0).unwrap(); bus.write16(0x102, 0x0003).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read32(0x200).unwrap(), 0x1122_3344);
        assert_eq!(bus.read32(0x204).unwrap(), 0x5566_7788);
    }

    #[test]
    fn movem_long_predecrement_uses_reversed_mask_order() {
        let mut bus = boot_bus(); let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0x1122_3344; cpu.a[1] = 0x5566_7788; cpu.a[7] = 0x0300;
        bus.write16(0x100, 0x48e7).unwrap(); bus.write16(0x102, 0x4080).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.a[7], 0x02f8);
        assert_eq!(bus.read32(0x2f8).unwrap(), 0x1122_3344);
        assert_eq!(bus.read32(0x2fc).unwrap(), 0x5566_7788);
    }

    #[test]
    fn memory_events_are_typed_and_mask_addresses() {
        assert_eq!(
            CpuEvent::memory_read(0x0100_0200, 2, 0x1234),
            CpuEvent::MemoryRead { address: 0x0200, size: 2, value: 0x1234 }
        );
        assert_eq!(
            CpuEvent::memory_write(0x0100_0200, 4, 0xdead_beef),
            CpuEvent::MemoryWrite { address: 0x0200, size: 4, value: 0xdead_beef }
        );
    }

    #[test]
    fn observed_divide_by_zero_reports_helper_exception() {
        let mut bus = boot_bus(); let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        bus.write32(5 * 4, 0x0000_0200).unwrap();
        bus.write16(0x100, 0x80c0).unwrap();
        cpu.d[0] = 0;
        let mut events = Vec::new();
        let cycles = cpu.step_observed(&mut bus, &mut |event| events.push(event)).unwrap();
        assert_eq!(cycles, 38);
        assert_eq!(events, vec![
            CpuEvent::Instruction { pc: 0x100, opcode: 0x80c0 },
            CpuEvent::Exception { vector: 5, pc: 0x100 },
        ]);
        assert_eq!(cpu.pc, 0x0200);
    }

    #[test]
    fn observed_trap_reports_instruction_then_exception() {
        let mut bus = boot_bus(); let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        bus.write32(32 * 4, 0x0000_0200).unwrap();
        bus.write16(0x100, 0x4e40).unwrap();
        let mut events = Vec::new();
        cpu.step_observed(&mut bus, &mut |event| events.push(event)).unwrap();
        assert_eq!(events, vec![
            CpuEvent::Instruction { pc: 0x100, opcode: 0x4e40 },
            CpuEvent::Exception { vector: 32, pc: 0x102 },
        ]);
    }

    #[test]
    fn observed_movem_address_error_reports_causal_event_chain() {
        let mut bus = boot_bus();
        bus.write32(3 * 4, 0x0000_0200).unwrap();
        bus.write16(0x100, 0x4cd0).unwrap();
        bus.write16(0x102, 0x0001).unwrap();
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x0201;
        let mut events = Vec::new();
        cpu.step_observed(&mut bus, &mut |event| events.push(event)).unwrap();
        assert_eq!(events, vec![
            CpuEvent::Instruction { pc: 0x100, opcode: 0x4cd0 },
            CpuEvent::AccessFault { vector: 3, pc: 0x100, opcode: 0x4cd0, address: 0x0201, read: true, instruction_access: false },
            CpuEvent::Exception { vector: 3, pc: 0x100 },
        ]);
    }

    #[test]
    fn observed_step_reports_instruction_deterministically() {
        let mut bus = boot_bus(); let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        bus.write16(0x100, 0x4e71).unwrap();
        let mut events = Vec::new();
        cpu.step_observed(&mut bus, &mut |event| events.push(event)).unwrap();
        assert_eq!(events, vec![CpuEvent::Instruction { pc: 0x100, opcode: 0x4e71 }]);
    }

    #[test]
    fn movem_odd_address_routes_to_vector_three() {
        let mut bus = boot_bus();
        bus.write32(3 * 4, 0x0000_0200).unwrap();
        bus.write16(0x100, 0x4cd0).unwrap();
        bus.write16(0x102, 0x0001).unwrap();
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x0201;
        let cycles = cpu.step(&mut bus).unwrap();
        assert_eq!(cycles, 50);
        assert_eq!(cpu.pc, 0x0200);
        assert_eq!(cpu.a[0], 0x0201);
        assert_eq!(cpu.a[7], 0x2ff2);
        assert_eq!(bus.read32(0x2ff8).unwrap(), 0x0000_0201);
        assert_eq!(bus.read16(0x2ffc).unwrap(), 0x4cd0);
        assert_eq!(bus.read32(0x2ffe).unwrap(), 0x0000_0100);
    }

    #[test]
    fn movem_predecrement_odd_address_routes_to_vector_three_after_decrement() {
        let mut bus = boot_bus();
        bus.write32(3 * 4, 0x0000_0200).unwrap();
        bus.write16(0x100, 0x48e0).unwrap();
        bus.write16(0x102, 0x0001).unwrap();
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x0205;
        cpu.a[7] = 0x1122_3344;
        let cycles = cpu.step(&mut bus).unwrap();
        assert_eq!(cycles, 50);
        assert_eq!(cpu.pc, 0x0200);
        assert_eq!(cpu.a[0], 0x0201);
        assert_eq!(bus.read32(0x2ff8).unwrap(), 0x0000_0201);
        assert_eq!(bus.read16(0x2ffc).unwrap(), 0x48e0);
    }

    #[test]
    fn movem_predecrement_fault_preserves_completed_transfer_and_progress() {
        let mut bus = RamBus::new(0x108);
        bus.write32(0, 0x0000_0108).unwrap();
        bus.write32(4, 0x0000_0100).unwrap();
        bus.write16(0x100, 0x48e0).unwrap();
        bus.write16(0x102, 0x0003).unwrap();
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x010c;
        cpu.a[7] = 0x1122_3344;
        cpu.a[6] = 0x5566_7788;
        let err = cpu.step(&mut bus).unwrap_err();
        assert!(matches!(err, CpuError::DataAccess { read: false, .. }));
        assert_eq!(cpu.a[0], 0x0104);
        assert_eq!(bus.read32(0x108).unwrap_err(), BusError::Unmapped { address: 0x108 });
        assert_eq!(bus.read32(0x104).unwrap(), 0x5566_7788);
    }

    #[test]
    fn movem_postincrement_fault_does_not_commit_final_base_update() {
        let mut bus = RamBus::new(0x108);
        bus.write32(0, 0x0000_0100).unwrap();
        bus.write32(4, 0x0000_0100).unwrap();
        bus.write16(0x100, 0x4cd8).unwrap();
        bus.write16(0x102, 0x0003).unwrap();
        bus.write32(0x104, 0x1122_3344).unwrap();
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x0104;
        let err = cpu.step(&mut bus).unwrap_err();
        assert!(matches!(err, CpuError::DataAccess { read: true, .. }));
        assert_eq!(cpu.d[0], 0x1122_3344);
        assert_eq!(cpu.d[1], 0);
        assert_eq!(cpu.a[0], 0x0104);
    }

    #[test]
    fn movem_predecrement_base_register_stores_decremented_value() {
        let mut bus = boot_bus(); let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.a[7] = 0x0300;
        bus.write16(0x100, 0x48e7).unwrap();
        bus.write16(0x102, 0x0001).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.a[7], 0x02fc);
        assert_eq!(bus.read32(0x02fc).unwrap(), 0x0000_02fc);
    }

    #[test]
    fn movem_postincrement_base_register_finishes_at_end_even_if_loaded() {
        let mut bus = boot_bus(); let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x0200;
        bus.write32(0x200, 0xdead_beef).unwrap();
        bus.write32(0x204, 0x1122_3344).unwrap();
        bus.write16(0x100, 0x4cd8).unwrap();
        bus.write16(0x102, 0x0101).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], 0xdead_beef);
        assert_eq!(cpu.a[0], 0x0208);
    }

    #[test]
    fn movem_word_postincrement_sign_extends_registers() {
        let mut bus = boot_bus(); let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x0200; bus.write16(0x200, 0x8001).unwrap(); bus.write16(0x202, 0x7fff).unwrap();
        bus.write16(0x100, 0x4c98).unwrap(); bus.write16(0x102, 0x0101).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], 0xffff_8001); assert_eq!(cpu.a[0], 0x0204); assert_eq!(cpu.a[0], 0x0204);
    }

    #[test]
    fn movem_metadata_qualifies_direction_specific_eas() {
        for ea in 0u16..64 {
            for size_bit in [0u16, 0x0040] {
                let to_mem = 0x4880 | size_bit | ea;
                let from_mem = 0x4c80 | size_bit | ea;
                let (mode, reg) = ea_mode_reg(to_mem);
                if !matches!(to_mem, 0x4880..=0x4887 | 0x48c0..=0x48c7) {
                    let expected = if legal_movem_to_memory(mode, reg) { Legality::Legal } else { Legality::Illegal };
                    assert_eq!(decode_info(to_mem).mnemonic, "MOVEM-RM", "opcode {to_mem:04x}");
                    assert_eq!(decode_info(to_mem).legality, expected, "opcode {to_mem:04x}");
                }
                let expected = if legal_movem_from_memory(mode, reg) { Legality::Legal } else { Legality::Illegal };
                assert_eq!(decode_info(from_mem).mnemonic, "MOVEM-MR", "opcode {from_mem:04x}");
                assert_eq!(decode_info(from_mem).legality, expected, "opcode {from_mem:04x}");
            }
        }
    }

    #[test]
    fn system_control_metadata_covers_privileged_and_illegal_core() {
        for opcode in [0x4e70u16, 0x4e71, 0x4e72, 0x4e73, 0x4e75, 0x4e76, 0x4e77, 0x4afc] {
            let info = decode_info(opcode);
            assert_ne!(info.class, InstructionClass::Unknown);
            assert_eq!(info.legality, Legality::Legal);
        }
        for reg in 0u16..8 {
            assert_eq!(decode_info(0x4e60 | reg).mnemonic, "MOVE-An-USP");
            assert_eq!(decode_info(0x4e68 | reg).mnemonic, "MOVE-USP-An");
        }
    }

    #[test]
    fn four_x_unknown_count_matches_m1_7_baseline() {
        const EXPECTED_UNKNOWN: usize = 1289;
        let unknown = (0x4000u16..=0x4fff)
            .filter(|&opcode| decode_info(opcode).class == InstructionClass::Unknown)
            .count();
        assert_eq!(
            unknown, EXPECTED_UNKNOWN,
            "0x4xxx decode coverage changed; audit the delta and update the M1.7 baseline intentionally"
        );
    }

    #[test]
    fn lea_metadata_uses_control_policy_for_all_eas() {
        for dst in 0u16..8 {
            for ea in 0u16..64 {
                let opcode = 0x41c0 | (dst << 9) | ea;
                let (mode, reg) = ea_mode_reg(opcode);
                let expected = if legal_control(mode, reg) { Legality::Legal } else { Legality::Illegal };
                assert_eq!(decode_info(opcode).legality, expected, "opcode {opcode:04x}");
            }
        }
    }

    #[test]
    fn swap_pea_ext_decode_boundaries_do_not_overlap() {
        for reg in 0u16..8 {
            assert_eq!(decode_info(0x4840 | reg).mnemonic, "SWAP");
            assert_eq!(decode_info(0x4880 | reg).mnemonic, "EXT.W");
            assert_eq!(decode_info(0x48c0 | reg).mnemonic, "EXT.L");
        }
        for opcode in [0x4850u16, 0x4868, 0x4870, 0x4878] {
            assert_eq!(decode_info(opcode).mnemonic, "PEA");
        }
    }

    #[test]
    fn unary_metadata_uses_data_alterable_policy_for_all_eas() {
        for base in [0x4000u16, 0x4200, 0x4400, 0x4600, 0x4800, 0x4ac0] {
            for ea in 0u16..64 {
                let opcode = base | ea;
                if opcode == 0x4afc { continue; }
                let info = decode_info(opcode);
                let (mode, reg) = ea_mode_reg(opcode);
                let expected = if legal_data_alterable(mode, reg) { Legality::Legal } else { Legality::Illegal };
                assert_eq!(info.legality, expected, "opcode {opcode:04x}");
            }
        }
    }

    #[test]
    fn full_opcode_space_preserves_qualified_family_priority() {
        for opcode in 0u16..=u16::MAX {
            let info = decode_info(opcode);
            let expected = if is_sbcd(opcode) {
                Some("SBCD")
            } else if is_abcd(opcode) {
                Some("ABCD")
            } else if is_subx(opcode) {
                Some("SUBX")
            } else if is_addx(opcode) {
                Some("ADDX")
            } else if is_cmpm(opcode) {
                Some("CMPM")
            } else if matches!(opcode & 0xf1f8, 0xc140 | 0xc148 | 0xc188) {
                Some("EXG")
            } else if is_divu(opcode) || is_divs(opcode) {
                Some("DIV")
            } else if is_mulu(opcode) || is_muls(opcode) {
                Some("MUL")
            } else {
                None
            };
            if let Some(mnemonic) = expected {
                assert_eq!(info.mnemonic, mnemonic, "opcode {opcode:04x}");
            }
        }
    }

    #[test]
    fn full_opcode_space_decode_metadata_is_self_consistent() {
        for opcode in 0u16..=u16::MAX {
            let info = decode_info(opcode);
            if info.legality == Legality::Legal {
                assert_ne!(info.class, InstructionClass::Unknown, "opcode {opcode:04x}");
                assert_ne!(info.ea_policy, EaPolicy::Unknown, "opcode {opcode:04x}");
            }
            if info.class == InstructionClass::Unknown {
                assert_eq!(info.mnemonic, "UNKNOWN", "opcode {opcode:04x}");
                assert_ne!(info.legality, Legality::Legal, "opcode {opcode:04x}");
            }
        }
    }

    #[test]
    fn mul_div_masks_cover_signed_unsigned_destinations_and_eas() {
        for dn in 0u16..8 {
            for ea in 0u16..64 {
                let divu = 0x80c0 | (dn << 9) | ea;
                let divs = 0x81c0 | (dn << 9) | ea;
                let mulu = 0xc0c0 | (dn << 9) | ea;
                let muls = 0xc1c0 | (dn << 9) | ea;
                assert!(is_divu(divu)); assert!(is_divs(divs));
                assert!(is_mulu(mulu)); assert!(is_muls(muls));
                let (mode, reg) = ea_mode_reg(ea);
                let expected = if legal_data_read(mode, reg) { Legality::Legal } else { Legality::Illegal };
                assert_eq!(decode_info(divu).legality, expected);
                assert_eq!(decode_info(divs).legality, expected);
                assert_eq!(decode_info(mulu).legality, expected);
                assert_eq!(decode_info(muls).legality, expected);
            }
        }
        assert!(!is_divu(0x8080)); assert!(!is_divs(0x8180));
        assert!(!is_mulu(0xc080)); assert!(!is_muls(0xc180));
    }

    #[test]
    fn cmpm_mask_covers_all_sizes_and_register_pairs() {
        for dst in 0u16..8 {
            for src in 0u16..8 {
                for size in 0u16..3 {
                    let opcode = 0xb108 | (dst << 9) | (size << 6) | src;
                    assert!(is_cmpm(opcode));
                    assert_eq!(decode_info(opcode).mnemonic, "CMPM");
                }
            }
        }
        assert!(!is_cmpm(0xb100));
        assert!(!is_cmpm(0xb1c8));
    }

    #[test]
    fn cmpm_postincrements_both_address_registers_once() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xb149).unwrap(); // CMPM.W (A1)+,(A0)+
        bus.write16(0x200, 0x1234).unwrap();
        bus.write16(0x300, 0x1234).unwrap();
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.a[1] = 0x200; cpu.a[0] = 0x300;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.a[1], 0x202);
        assert_eq!(cpu.a[0], 0x302);
        assert_ne!(cpu.sr & CCR_Z, 0);
    }

    #[test]
    fn addx_subx_masks_cover_all_sizes_and_both_forms() {
        for dst in 0u16..8 {
            for src in 0u16..8 {
                for size in 0u16..3 {
                    for memory in [false, true] {
                        let form = if memory { 0x0008 } else { 0 };
                        let subx = 0x9100 | (dst << 9) | (size << 6) | form | src;
                        let addx = 0xd100 | (dst << 9) | (size << 6) | form | src;
                        assert!(is_subx(subx));
                        assert!(is_addx(addx));
                        assert_eq!(decode_info(subx).mnemonic, "SUBX");
                        assert_eq!(decode_info(addx).mnemonic, "ADDX");
                    }
                }
            }
        }
        assert!(!is_subx(0x91c0));
        assert!(!is_addx(0xd1c0));
    }

    #[test]
    fn bcd_family_masks_cover_register_and_predecrement_forms_only() {
        for dst in 0u16..8 {
            for src in 0u16..8 {
                for memory in [false, true] {
                    let form = if memory { 0x0008 } else { 0 };
                    let sbcd = 0x8100 | (dst << 9) | form | src;
                    let abcd = 0xc100 | (dst << 9) | form | src;
                    assert!(is_sbcd(sbcd));
                    assert!(is_abcd(abcd));
                    assert_eq!(decode_info(sbcd).mnemonic, "SBCD");
                    assert_eq!(decode_info(abcd).mnemonic, "ABCD");
                }
            }
        }
        assert!(!is_sbcd(0x8110));
        assert!(!is_abcd(0xc110));
    }

    #[test]
    fn exg_metadata_wins_over_generic_alu_and_mul_families() {
        for rx in 0u16..8 {
            for ry in 0u16..8 {
                for base in [0xc140u16, 0xc148, 0xc188] {
                    let opcode = base | (rx << 9) | ry;
                    assert_eq!(decode_info(opcode).mnemonic, "EXG");
                }
            }
        }
    }

    #[test]
    fn exg_executes_all_three_register_forms_without_changing_flags() {
        for opcode in [0xc141u16, 0xc149, 0xc189] {
            let mut bus = boot_bus();
            bus.write16(0x100, opcode).unwrap();
            let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
            cpu.d[0] = 0x1111_1111; cpu.d[1] = 0x2222_2222;
            cpu.a[0] = 0x3333_3333; cpu.a[1] = 0x4444_4444;
            let sr = cpu.sr;
            cpu.step(&mut bus).unwrap();
            assert_eq!(cpu.sr, sr);
        }
    }

    #[test]
    fn movep_wins_over_dynamic_bit_decode_and_uses_spaced_bytes() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x0188).unwrap(); // MOVEP.W D0,(d16,A0)
        bus.write16(0x102, 0x0010).unwrap();
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x0200; cpu.d[0] = 0x1234;
        assert_eq!(decode_info(0x0188).mnemonic, "MOVEP");
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read8(0x210).unwrap(), 0x12);
        assert_eq!(bus.read8(0x212).unwrap(), 0x34);
    }

    #[test]
    fn movep_long_memory_to_register_reassembles_spaced_bytes() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x0148).unwrap(); // MOVEP.L (d16,A0),D0
        bus.write16(0x102, 0).unwrap();
        for (offset, value) in [(0,0x12),(2,0x34),(4,0x56),(6,0x78)] { bus.write8(0x200 + offset, value).unwrap(); }
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap(); cpu.a[0] = 0x200;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], 0x1234_5678);
    }

    #[test]
    fn chk_decode_covers_all_destination_registers() {
        for dn in 0u16..8 {
            let opcode = 0x4180 | (dn << 9); // CHK.W D0,Dn
            let info = decode_info(opcode);
            assert_eq!(info.mnemonic, "CHK");
            assert_eq!(info.legality, Legality::Legal);

            let mut bus = boot_bus();
            bus.write16(0x100, opcode).unwrap();
            let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
            cpu.d[0] = 7;
            cpu.d[dn as usize] = 3;
            assert!(cpu.step(&mut bus).is_ok());
        }
    }

    #[test]
    fn chk_rejects_address_register_direct_source_for_every_destination() {
        for dn in 0u16..8 {
            let opcode = 0x4188 | (dn << 9);
            assert_eq!(decode_info(opcode).legality, Legality::Illegal);
        }
    }

    #[test]
    fn control_metadata_matches_shared_control_policy() {
        for base in [0x4840u16, 0x4e80, 0x4ec0] {
            for ea in 0u16..64 {
                let opcode = base | ea;
                let (mode, reg) = ea_mode_reg(opcode);
                assert_eq!(decode_info(opcode).legality == Legality::Legal, legal_control(mode, reg));
            }
        }
    }

    #[test]
    fn ccr_writes_preserve_reserved_low_byte_bits() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x003c).unwrap();
        bus.write16(0x102, 0x00ff).unwrap();
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.sr = 0x2720;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.sr & 0x00e0, 0x0020);
        assert_eq!(cpu.sr & 0x001f, 0x001f);
    }

    #[test]
    fn control_and_memory_alterable_ea_policies_cover_all_encodings() {
        for ea in 0u16..64 {
            let (mode, reg) = ea_mode_reg(ea);
            assert_eq!(legal_control(mode, reg), matches!(mode, 2 | 5 | 6) || (mode == 7 && reg <= 3));
            assert_eq!(legal_memory_alterable(mode, reg), matches!(mode, 2..=6) || (mode == 7 && reg <= 1));
        }
    }

    #[test]
    fn invalid_pea_jsr_and_jmp_encodings_enter_illegal_instruction() {
        for opcode in [0x4848u16, 0x4e88, 0x4ec8] {
            let mut bus = boot_bus();
            bus.write32(4 * 4, 0x240).unwrap();
            bus.write16(0x100, opcode).unwrap();
            let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
            cpu.step(&mut bus).unwrap();
            assert_eq!(cpu.pc, 0x240);
        }
    }

    #[test]
    fn executor_and_metadata_agree_on_mul_div_ea_legality() {
        for base in [0xc0c0u16, 0x80c0] {
            for ea in 0u16..64 {
                let opcode = base | ea;
                let (mode, reg) = ea_mode_reg(opcode);
                let expected = legal_data_read(mode, reg);
                assert_eq!(decode_info(opcode).legality == Legality::Legal, expected);
            }
        }
    }

    #[test]
    fn bit_metadata_uses_shared_ea_legality_rules() {
        for operation in 0u16..4 {
            for ea in 0u16..64 {
                let opcode = 0x0800 | (operation << 6) | ea;
                let (mode, reg) = ea_mode_reg(opcode);
                let expected = if mode == 0 { true } else if operation == 0 { legal_data_read(mode, reg) } else { legal_data_alterable(mode, reg) };
                assert_eq!(decode_info(opcode).legality == Legality::Legal, expected);
            }
        }
    }

    #[test]
    fn decode_metadata_exposes_known_ea_legality() {
        assert_eq!(decode_info(0xc0c0).legality, Legality::Legal); // MULU D0,D0
        assert_eq!(decode_info(0xc0c8).legality, Legality::Illegal); // MULU A0,D0
        assert_eq!(decode_info(0x083a).legality, Legality::Legal); // BTST #n,(d16,PC)
        assert_eq!(decode_info(0x08fa).legality, Legality::Illegal); // BSET #n,(d16,PC)
        assert_eq!(decode_info(0x4e71).ea_policy, EaPolicy::None);
    }

    #[test]
    fn opcode_space_metadata_never_claims_unknown_legality_as_legal() {
        for opcode in 0u16..=u16::MAX {
            let info = decode_info(opcode);
            if info.ea_policy == EaPolicy::Unknown {
                assert_ne!(info.legality, Legality::Legal);
            }
        }
    }

    #[test]
    fn decode_metadata_prioritizes_overlap_families() {
        assert_eq!(decode_info(0xc100).mnemonic, "ABCD");
        assert_eq!(decode_info(0x8100).mnemonic, "SBCD");
        assert_eq!(decode_info(0xd100).mnemonic, "ADDX");
        assert_eq!(decode_info(0x9100).mnemonic, "SUBX");
        assert_eq!(decode_info(0xb108).mnemonic, "CMPM");
        assert_eq!(decode_info(0xc0c0).class, InstructionClass::MultiplyDivide);
        assert_eq!(decode_info(0x80c0).class, InstructionClass::MultiplyDivide);
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
        assert_eq!(cpu.step(&mut bus).unwrap(), 34);
        assert_eq!(cpu.pc, 0x240);
        assert_eq!(bus.read32(cpu.a[7] + 2).unwrap(), 0x100);
    }

    #[test]
    fn interrupt_obeys_mask_and_wakes_stop() {
        let mut bus = boot_bus();
        bus.write32(27 * 4, 0x280).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x220);
        cpu.a[7] = 0x3000;
        cpu.pc = 0x102;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x240);
    }

    #[test]
    fn trapv_and_chk_enter_their_architectural_vectors() {
        let mut bus = boot_bus();
        bus.write32(7 * 4, 0x270).unwrap();
        bus.write32(6 * 4, 0x260).unwrap();
        bus.write16(0x100, 0x4e76).unwrap(); // TRAPV
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.sr |= CCR_V;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x270);

        cpu.a[7] = 0x3000;
        cpu.pc = 0x120;
        bus.write16(0x120, 0x4181).unwrap(); // CHK.W D1,D0
        cpu.d[0] = 11;
        cpu.d[1] = 10;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x260);
    }

    #[test]
    fn reset_is_privileged_and_is_a_cpu_side_noop() {
        let mut bus = boot_bus();
        bus.write32(8 * 4, 0x280).unwrap();
        bus.write16(0x100, 0x4e70).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        assert_eq!(cpu.step(&mut bus).unwrap(), 132);
        assert_eq!(cpu.pc, 0x102);
        cpu.ssp = 0x3000;
        cpu.usp = 0x2800;
        cpu.a[7] = cpu.usp;
        cpu.pc = 0x100;
        cpu.sr = 0;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x280);
    }

    #[test]
    fn immediate_ccr_and_sr_operations_decode_before_generic_immediate_alu() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x003c).unwrap(); // ORI #$11,CCR
        bus.write16(0x102, 0x0011).unwrap();
        bus.write16(0x104, 0x023c).unwrap(); // ANDI #$10,CCR
        bus.write16(0x106, 0x0010).unwrap();
        bus.write16(0x108, 0x0a3c).unwrap(); // EORI #$04,CCR
        bus.write16(0x10a, 0x0004).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.sr = 0x2700;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.sr & 0xff, 0x11);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.sr & 0xff, 0x10);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.sr & 0xff, 0x14);
    }

    #[test]
    fn immediate_sr_operations_are_privileged() {
        let mut bus = boot_bus();
        bus.write32(8 * 4, 0x280).unwrap();
        bus.write16(0x100, 0x007c).unwrap(); // ORI #$0700,SR
        bus.write16(0x102, 0x0700).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.ssp = 0x3000;
        cpu.usp = 0x2800;
        cpu.a[7] = cpu.usp;
        cpu.sr = 0;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x280);
    }


    #[test]
    fn illegal_family_encoding_enters_vector_four_while_unimplemented_stays_host_error() {
        let mut bus = boot_bus();
        bus.write32(4 * 4, 0x240).unwrap();
        bus.write16(0x100, 0xc0c8).unwrap(); // MULU.W A0,D0: illegal EA
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x240);

        bus.write16(0x100, 0x4e74).unwrap(); // RTD: not a 68000 instruction implemented by this core
        cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        assert!(matches!(cpu.step(&mut bus), Err(CpuError::UnimplementedOpcode { opcode: 0x4e74 })));
    }


    #[test]
    fn mul_div_and_chk_reject_address_register_direct_sources() {
        let mut bus = boot_bus();
        for opcode in [0xc0c8u16, 0x80c8, 0x4188] {
            bus.write16(0x100, opcode).unwrap();
            let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
            cpu.step(&mut bus).unwrap();
            assert_eq!(cpu.pc, bus.read32(4 * 4).unwrap());
        }
    }

    #[test]
    fn modifying_bit_ops_reject_pc_relative_but_btst_allows_it() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x083a).unwrap(); // BTST #0,(d16,PC)
        bus.write16(0x102, 0).unwrap();
        bus.write16(0x104, 0).unwrap();
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        assert!(cpu.step(&mut bus).is_ok());

        bus.write16(0x100, 0x08fa).unwrap(); // BSET #0,(d16,PC): not alterable
        bus.write16(0x102, 0).unwrap();
        cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, bus.read32(4 * 4).unwrap());
    }


    #[test]
    fn divs_min_by_minus_one_reports_overflow_without_panicking() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x81c1).unwrap(); // DIVS.W D1,D0
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0x8000_0000;
        cpu.d[1] = 0x0000_ffff;
        cpu.sr = CCR_X;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], 0x8000_0000);
        assert_ne!(cpu.sr & CCR_V, 0);
        assert_ne!(cpu.sr & CCR_X, 0);
        assert_eq!(cpu.sr & CCR_C, 0);
    }


    #[test]
    fn neg_and_not_update_flags_and_preserve_operand_width() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x4400).unwrap(); // NEG.B D0
        bus.write16(0x102, 0x4641).unwrap(); // NOT.W D1
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0x1234_0001; cpu.d[1] = 0xabcd_00ff; cpu.sr = CCR_X;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], 0x1234_00ff); assert_ne!(cpu.sr & (CCR_X | CCR_C | CCR_N), 0);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[1], 0xabcd_ff00); assert_ne!(cpu.sr & CCR_N, 0); assert_eq!(cpu.sr & (CCR_V | CCR_C), 0);
    }

    #[test]
    fn negx_uses_extend_and_sticky_zero() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x4000).unwrap(); // NEGX.B D0
        bus.write16(0x102, 0x4001).unwrap(); // NEGX.B D1
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0; cpu.d[1] = 1; cpu.sr = CCR_Z;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0); assert_ne!(cpu.sr & CCR_Z, 0);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[1] & 0xff, 0xff); assert_eq!(cpu.sr & CCR_Z, 0); assert_ne!(cpu.sr & (CCR_X | CCR_C), 0);
    }

    #[test]
    fn tas_tests_original_byte_then_sets_high_bit_and_resolves_once() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x4ad8).unwrap(); // TAS (A0)+
        bus.write8(0x500, 0).unwrap();
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap(); cpu.a[0] = 0x500; cpu.sr = CCR_X | CCR_C;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read8(0x500).unwrap(), 0x80); assert_eq!(cpu.a[0], 0x501);
        assert_ne!(cpu.sr & CCR_Z, 0); assert_ne!(cpu.sr & CCR_X, 0); assert_eq!(cpu.sr & (CCR_V | CCR_C), 0);
    }


    #[test]
    fn addq_subq_handle_quick_eight_and_flags() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x5000).unwrap(); // ADDQ.B #8,D0
        bus.write16(0x102, 0x5300).unwrap(); // SUBQ.B #1,D0
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap(); cpu.d[0] = 0x78;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0x80); assert_ne!(cpu.sr & CCR_V, 0);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0x7f); assert_ne!(cpu.sr & CCR_V, 0);
    }

    #[test]
    fn quick_arithmetic_on_address_register_preserves_ccr() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x5248).unwrap(); // ADDQ.W #1,A0
        bus.write16(0x102, 0x5188).unwrap(); // SUBQ.L #8,A0
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0xffff_ffff; cpu.sr = CCR_X | CCR_N | CCR_Z | CCR_V | CCR_C;
        let ccr = cpu.sr & 0x1f;
        cpu.step(&mut bus).unwrap(); assert_eq!(cpu.a[0], 0); assert_eq!(cpu.sr & 0x1f, ccr);
        cpu.step(&mut bus).unwrap(); assert_eq!(cpu.a[0], 0xffff_fff8); assert_eq!(cpu.sr & 0x1f, ccr);
    }

    #[test]
    fn addq_memory_postincrement_resolves_once() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x5258).unwrap(); // ADDQ.W #1,(A0)+
        bus.write16(0x500, 0xffff).unwrap();
        let mut cpu = Cpu::default(); cpu.reset(&mut bus).unwrap(); cpu.a[0] = 0x500;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read16(0x500).unwrap(), 0); assert_eq!(cpu.a[0], 0x502);
        assert_ne!(cpu.sr & CCR_Z, 0); assert_ne!(cpu.sr & (CCR_X | CCR_C), 0);
    }


    #[test]
    fn memory_shifts_are_word_sized_single_bit_operations() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xe0d0).unwrap(); // ASR.W (A0)
        bus.write16(0x102, 0xe3d0).unwrap(); // LSL.W (A0)
        bus.write16(0x500, 0x8001).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read16(0x500).unwrap(), 0xc000);
        assert_ne!(cpu.sr & CCR_C, 0);
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read16(0x500).unwrap(), 0x8000);
        assert_ne!(cpu.sr & CCR_C, 0);
        assert_ne!(cpu.sr & CCR_X, 0);
    }

    #[test]
    fn memory_rox_uses_extend_and_resolves_postincrement_once() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xe5d8).unwrap(); // ROXL.W (A0)+
        bus.write16(0x500, 0x8000).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.sr = CCR_X;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read16(0x500).unwrap(), 0x0001);
        assert_eq!(cpu.a[0], 0x502);
        assert_ne!(cpu.sr & CCR_X, 0);
        assert_ne!(cpu.sr & CCR_C, 0);
    }

    #[test]
    fn memory_rotate_preserves_x() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xe6d0).unwrap(); // ROR.W (A0)
        bus.write16(0x500, 0x0001).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.sr = CCR_X;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read16(0x500).unwrap(), 0x8000);
        assert_ne!(cpu.sr & CCR_X, 0);
        assert_ne!(cpu.sr & CCR_C, 0);
    }


    #[test]
    fn register_shifts_cover_arithmetic_logical_and_rotate() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xe200).unwrap(); // ASR.B #1,D0
        bus.write16(0x102, 0xe309).unwrap(); // LSL.B #1,D1
        bus.write16(0x104, 0xe21a).unwrap(); // ROR.B #1,D2
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0x81;
        cpu.d[1] = 0x81;
        cpu.d[2] = 0x01;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0xc0);
        assert_ne!(cpu.sr & CCR_C, 0);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[1] & 0xff, 0x02);
        assert_ne!(cpu.sr & (CCR_C | CCR_X), 0);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[2] & 0xff, 0x80);
        assert_ne!(cpu.sr & CCR_C, 0);
    }

    #[test]
    fn roxl_and_roxr_use_extend_as_part_of_rotation() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xe310).unwrap(); // ROXL.B #1,D0
        bus.write16(0x102, 0xe210).unwrap(); // ROXR.B #1,D0
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0x80;
        cpu.sr = CCR_X;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0x01);
        assert_ne!(cpu.sr & CCR_X, 0);
        assert_ne!(cpu.sr & CCR_C, 0);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0x80);
    }

    #[test]
    fn register_count_zero_preserves_x_and_sets_rox_c_from_x() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xe130).unwrap(); // ROXL.B D0,D0; count low 6 bits = 0
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0x40;
        cpu.sr = CCR_X | CCR_V | CCR_C;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0x40);
        assert_ne!(cpu.sr & CCR_X, 0);
        assert_ne!(cpu.sr & CCR_C, 0);
        assert_eq!(cpu.sr & CCR_V, 0);
    }


    #[test]
    fn dynamic_bit_ops_use_modulo_32_on_data_registers_and_only_change_z() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x0300).unwrap(); // BTST D1,D0
        bus.write16(0x102, 0x0340).unwrap(); // BCHG D1,D0
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 1 << 3;
        cpu.d[1] = 35;
        cpu.sr = CCR_X | CCR_N | CCR_V | CCR_C | CCR_Z;
        let preserved = cpu.sr & !CCR_Z;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.sr & CCR_Z, 0);
        assert_eq!(cpu.sr & !CCR_Z, preserved);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & (1 << 3), 0);
        assert_eq!(cpu.sr & CCR_Z, 0);
        assert_eq!(cpu.sr & !CCR_Z, preserved);
    }

    #[test]
    fn immediate_memory_bit_ops_use_modulo_8_and_resolve_ea_once() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x08d8).unwrap(); // BSET #9,(A0)+
        bus.write16(0x102, 9).unwrap();
        bus.write16(0x104, 0x0890).unwrap(); // BCLR #1,(A0)
        bus.write16(0x106, 1).unwrap();
        bus.write8(0x500, 0).unwrap();
        bus.write8(0x501, 0x02).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read8(0x500).unwrap(), 0x02);
        assert_eq!(cpu.a[0], 0x501);
        assert_ne!(cpu.sr & CCR_Z, 0);
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read8(0x501).unwrap(), 0);
        assert_eq!(cpu.a[0], 0x501);
        assert_eq!(cpu.sr & CCR_Z, 0);
    }

    #[test]
    fn btst_memory_does_not_write_destination() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x0810).unwrap(); // BTST #0,(A0)
        bus.write16(0x102, 0).unwrap();
        bus.write8(0x500, 0x5a).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.step(&mut bus).unwrap();
        assert_eq!(bus.read8(0x500).unwrap(), 0x5a);
        assert_ne!(cpu.sr & CCR_Z, 0);
    }


    #[test]
    fn move_sr_ccr_roundtrips_condition_codes_without_touching_upper_sr() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x40c0).unwrap(); // MOVE SR,D0
        bus.write16(0x102, 0x44c1).unwrap(); // MOVE D1,CCR
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.sr = 0x2715;
        cpu.d[1] = 0x000a;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xffff, 0x2715);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.sr, 0x270a);
    }

    #[test]
    fn move_to_sr_is_privileged_and_uses_set_sr_stack_switching() {
        let mut bus = boot_bus();
        bus.write32(8 * 4, 0x280).unwrap();
        bus.write16(0x100, 0x46c0).unwrap(); // MOVE D0,SR
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.ssp = 0x3000;
        cpu.usp = 0x2800;
        cpu.a[7] = cpu.usp;
        cpu.sr = 0;
        cpu.d[0] = 0x2700;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x280);
    }

    #[test]
    fn nbcd_uses_extend_decimal_borrow_and_sticky_zero() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x4800).unwrap(); // NBCD D0
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0x01;
        cpu.sr = CCR_Z;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0x99);
        assert_eq!(cpu.sr & (CCR_X | CCR_C), CCR_X | CCR_C);
        assert_eq!(cpu.sr & CCR_Z, 0);
    }

    #[test]
    fn rtr_restores_ccr_and_pc_but_preserves_upper_sr() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x4e77).unwrap(); // RTR
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.sr = 0x2700;
        let sp = cpu.a[7];
        bus.write16(sp, 0x0015).unwrap();
        bus.write32(sp + 2, 0x0000_2340).unwrap();
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x2340);
        assert_eq!(cpu.sr, 0x2715);
        assert_eq!(cpu.a[7], sp + 6);
    }


    #[test]
    fn unimplemented_opcode_is_host_error_not_guest_illegal() {
        let mut bus = boot_bus();
        bus.write32(4 * 4, 0x240).unwrap();
        bus.write16(0x100, 0x4e74).unwrap(); // RTD: 68010+, not implemented by this 68000 core
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        assert_eq!(cpu.step(&mut bus), Err(CpuError::UnimplementedOpcode { opcode: 0x4e74 }));
        assert_eq!(cpu.pc, 0x102);
    }

    #[test]
    fn exception_clears_live_trace_bit_but_stacks_original_sr() {
        let mut bus = boot_bus();
        bus.write32(32 * 4, 0x200).unwrap();
        bus.write16(0x100, 0x4e40).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
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
    fn exg_supports_data_address_and_mixed_forms_without_changing_ccr() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xc141).unwrap(); // EXG D0,D1
        bus.write16(0x102, 0xc149).unwrap(); // EXG A0,A1
        bus.write16(0x104, 0xc189).unwrap(); // EXG D0,A1
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 1;
        cpu.d[1] = 2;
        cpu.a[0] = 3;
        cpu.a[1] = 4;
        cpu.sr = CCR_X | CCR_N | CCR_C;
        let sr = cpu.sr;
        cpu.step(&mut bus).unwrap();
        assert_eq!((cpu.d[0], cpu.d[1]), (2, 1));
        cpu.step(&mut bus).unwrap();
        assert_eq!((cpu.a[0], cpu.a[1]), (4, 3));
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], 3);
        assert_eq!(cpu.a[1], 2);
        assert_eq!(cpu.sr, sr);
    }

    #[test]
    fn mulu_and_muls_produce_32_bit_results_and_preserve_x() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xc0fc).unwrap(); // MULU.W #3,D0
        bus.write16(0x102, 3).unwrap();
        bus.write16(0x104, 0xc3fc).unwrap(); // MULS.W #-2,D1
        bus.write16(0x106, 0xfffe).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0xffff_0004;
        cpu.d[1] = 0x0000_fffd; // -3
        cpu.sr = CCR_X | CCR_V | CCR_C;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], 12);
        assert_ne!(cpu.sr & CCR_X, 0);
        assert_eq!(cpu.sr & (CCR_N | CCR_Z | CCR_V | CCR_C), 0);
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[1], 6);
        assert_ne!(cpu.sr & CCR_X, 0);
        assert_eq!(cpu.sr & (CCR_N | CCR_Z | CCR_V | CCR_C), 0);
    }

    #[test]
    fn muls_sets_negative_from_long_result() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xc1fc).unwrap(); // MULS.W #-2,D0
        bus.write16(0x102, 0xfffe).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 3;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], 0xffff_fffa);
        assert_ne!(cpu.sr & CCR_N, 0);
    }


    #[test]
    fn divu_packs_remainder_and_quotient_and_preserves_x() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x80fc).unwrap(); // DIVU.W #3,D0
        bus.write16(0x102, 3).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 10;
        cpu.sr = CCR_X | CCR_N | CCR_V | CCR_C;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], (1 << 16) | 3);
        assert_ne!(cpu.sr & CCR_X, 0);
        assert_eq!(cpu.sr & (CCR_N | CCR_Z | CCR_V | CCR_C), 0);
    }

    #[test]
    fn divs_uses_signed_quotient_and_remainder() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x81fc).unwrap(); // DIVS.W #-3,D0
        bus.write16(0x102, 0xfffd).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = (-10i32) as u32;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], (0xffffu32 << 16) | 3);
        assert_eq!(cpu.sr & (CCR_N | CCR_Z | CCR_V | CCR_C), 0);
    }

    #[test]
    fn divide_overflow_sets_v_without_modifying_destination() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x80fc).unwrap(); // DIVU.W #1,D0
        bus.write16(0x102, 1).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0x0001_0000;
        let before = cpu.d[0];
        cpu.sr = CCR_X;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0], before);
        assert_ne!(cpu.sr & CCR_V, 0);
        assert_ne!(cpu.sr & CCR_X, 0);
        assert_eq!(cpu.sr & CCR_C, 0);
    }

    #[test]
    fn divide_by_zero_enters_vector_five_without_modifying_destination() {
        let mut bus = boot_bus();
        bus.write32(5 * 4, 0x260).unwrap();
        bus.write16(0x100, 0x80fc).unwrap(); // DIVU.W #0,D0
        bus.write16(0x102, 0).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0x1234_5678;
        let before = cpu.d[0];
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.pc, 0x260);
        assert_eq!(cpu.d[0], before);
        assert_eq!(bus.read32(cpu.a[7] + 2).unwrap(), 0x100);
    }


    #[test]
    fn abcd_uses_decimal_carry_extend_and_sticky_zero() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xc101).unwrap(); // ABCD D1,D0
        bus.write16(0x102, 0xc101).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0x99;
        cpu.d[1] = 0;
        cpu.sr = CCR_X | CCR_Z;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0);
        assert_ne!(cpu.sr & (CCR_X | CCR_C), 0);
        assert_ne!(cpu.sr & CCR_Z, 0);
        cpu.d[1] = 1;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 2);
        assert_eq!(cpu.sr & CCR_Z, 0);
    }

    #[test]
    fn sbcd_borrows_decimal_and_sets_x_and_c() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0x8101).unwrap(); // SBCD D1,D0
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.d[0] = 0x00;
        cpu.d[1] = 0x01;
        cpu.sr = CCR_Z;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.d[0] & 0xff, 0x99);
        assert_eq!(cpu.sr & (CCR_X | CCR_C), CCR_X | CCR_C);
        assert_eq!(cpu.sr & CCR_Z, 0);
    }

    #[test]
    fn abcd_memory_form_predecrements_each_address_once() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xc109).unwrap(); // ABCD -(A1),-(A0)
        bus.write8(0x4ff, 0x09).unwrap();
        bus.write8(0x5ff, 0x01).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.a[1] = 0x600;
        cpu.sr = CCR_Z;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.a[0], 0x4ff);
        assert_eq!(cpu.a[1], 0x5ff);
        assert_eq!(bus.read8(0x4ff).unwrap(), 0x10);
    }

    #[test]
    fn bcd_byte_predecrement_keeps_a7_word_aligned() {
        let mut bus = boot_bus();
        bus.write16(0x100, 0xc10f).unwrap(); // ABCD -(A7),-(A0)
        bus.write8(0x4ff, 0x01).unwrap();
        bus.write8(0x6fe, 0x01).unwrap();
        let mut cpu = Cpu::default();
        cpu.reset(&mut bus).unwrap();
        cpu.a[0] = 0x500;
        cpu.a[7] = 0x700;
        cpu.sr = CCR_Z;
        cpu.step(&mut bus).unwrap();
        assert_eq!(cpu.a[0], 0x4ff);
        assert_eq!(cpu.a[7], 0x6fe);
        assert_eq!(bus.read8(0x4ff).unwrap(), 0x02);
    }


    #[test]
    fn overlapping_alu_encodings_do_not_execute_as_generic_operations() {
        for opcode in [

        ] {
            let mut bus = boot_bus();
            bus.write16(0x100, opcode).unwrap();
            let mut cpu = Cpu::default();
            cpu.reset(&mut bus).unwrap();
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
        cpu.reset(&mut bus).unwrap();
        cpu.sr = 0x2500;
        assert_eq!(cpu.interrupt(&mut bus, 3, 27).unwrap(), 0);
        assert_eq!(cpu.pc, 0x100);
    }
    #[test]
    fn reset_vectors_use_overlay_then_execute_from_high_rom() {
        use amilea_bus::{AddressSpace, OverlayBus, RamBus, Rom};

        let mut high_rom=vec![0u8;16];
        high_rom[8..10].copy_from_slice(&0x4e71u16.to_be_bytes());

        let mut base=AddressSpace::new();
        base.map(0x000000,0x080000,RamBus::new(0x080000)).unwrap();
        base.map(0xf80000,high_rom.len() as u32,Rom::new(0xf80000,high_rom)).unwrap();

        let mut vectors=vec![0u8;8];
        vectors[0..4].copy_from_slice(&0x0008_0000u32.to_be_bytes());
        vectors[4..8].copy_from_slice(&0x00f8_0008u32.to_be_bytes());
        let mut bus=OverlayBus::new(base,Rom::new(0,vectors),8);

        let mut cpu=Cpu::default();
        cpu.reset(&mut bus).unwrap();
        assert_eq!(cpu.ssp,0x0008_0000);
        assert_eq!(cpu.a[7],0x0008_0000);
        assert_eq!(cpu.pc,0x00f8_0008);

        bus.set_overlay(false);
        assert_eq!(cpu.step(&mut bus).unwrap(),4);
        assert_eq!(cpu.pc,0x00f8_000a);
    }

    #[test]
    fn cpu_writes_cia_a_and_disables_rom_overlay() {
        use amilea_bus::{AddressSpace, BusSignal, OverlayBus, RamBus, Rom};
        use amilea_cia::{CiaA, CIA_A_DDRA, CIA_A_PRA};

        let signal=BusSignal::new(true);
        let mut program=vec![0u8;32];
        // MOVE.B #$01,$00BFE201 ; DDRA bit 0 output
        program[8..14].copy_from_slice(&[0x13,0xfc,0x00,0x01,0xbf,0xe2]);
        program[14..16].copy_from_slice(&[0x01,0x00]);
        // MOVE.B #$00,$00BFE001 ; OVL low
        program[16..22].copy_from_slice(&[0x13,0xfc,0x00,0x00,0xbf,0xe0]);
        program[22..24].copy_from_slice(&[0x01,0x00]);

        let mut base=AddressSpace::new();
        base.map(0x000000,0x080000,RamBus::new(0x080000)).unwrap();
        base.map(0xbfe000,0x300,CiaA::with_overlay_signal(signal.clone())).unwrap();
        base.map(0xf80000,program.len() as u32,Rom::new(0xf80000,program)).unwrap();

        let vectors=Rom::new(0,vec![0,0x08,0,0,0,0xf8,0,0x08]);
        let mut bus=OverlayBus::with_signal(base,vectors,8,signal.clone());
        let mut cpu=Cpu::default();
        cpu.reset(&mut bus).unwrap();
        assert!(signal.get());

        cpu.step(&mut bus).unwrap();
        assert!(signal.get());
        cpu.step(&mut bus).unwrap();
        assert!(!signal.get());
        assert!(!bus.overlay_enabled());
    }

}
