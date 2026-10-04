//! Amiga custom-chip register block.
//! Functional Copper, Blitter, bitplane, sprite and audio DMA are added incrementally.

use amilea_bus::{Bus, BusClock, BusError, RasterGeometry};
use std::{cell::RefCell, rc::Rc};

pub const CUSTOM_BASE:u32=0x00df_f000;
pub const CUSTOM_SIZE:u32=0x200;
pub const DMACONR:u32=CUSTOM_BASE+0x002;
pub const VPOSR:u32=CUSTOM_BASE+0x004;
pub const VHPOSR:u32=CUSTOM_BASE+0x006;
pub const INTENAR:u32=CUSTOM_BASE+0x01c;
pub const INTREQR:u32=CUSTOM_BASE+0x01e;
pub const DMACON:u32=CUSTOM_BASE+0x096;
pub const INTENA:u32=CUSTOM_BASE+0x09a;
pub const INTREQ:u32=CUSTOM_BASE+0x09c;

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum InterruptSource { Software, External, DiskSync, SerialReceive, Audio3, Audio2, Audio1, Audio0, Blitter, VerticalBlank, Copper, Ports, Soft, DiskBlock, TransmitBufferEmpty }

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct InterruptRequest { pub source:InterruptSource, pub mask:u16 }

#[derive(Debug,Default)]
struct CustomState { dmacon:u16, intena:u16, intreq:u16, vpos:u16, vhpos:u16, requests:Vec<InterruptRequest> }

#[derive(Debug,Clone)]
pub struct CustomChipHandle(Rc<RefCell<CustomState>>);

impl CustomChipHandle {
    pub fn dmacon(&self)->u16 { self.0.borrow().dmacon }
    pub fn intena(&self)->u16 { self.0.borrow().intena }
    pub fn intreq(&self)->u16 { self.0.borrow().intreq }
    pub fn pending_interrupts(&self)->u16 {
        let state=self.0.borrow();
        if state.intena & 0x4000 != 0 { state.intena & state.intreq & 0x3fff } else { 0 }
    }
    pub fn interrupt_level(&self)->u8 { interrupt_level(self.pending_interrupts()) }
    pub fn interrupt_requests(&self)->Vec<InterruptRequest> { self.0.borrow().requests.clone() }
    pub fn request_interrupt(&self,source:InterruptSource) { let mask=interrupt_source_mask(source); let mut state=self.0.borrow_mut(); state.intreq|=mask; state.requests.push(InterruptRequest{source,mask}); }
}

#[derive(Debug,Clone)]
pub struct CustomChips {
    state:Rc<RefCell<CustomState>>,
    clock:Option<BusClock>,
}

impl Default for CustomChips {
    fn default()->Self { Self { state:Rc::new(RefCell::new(CustomState::default())), clock:None } }
}

impl CustomChips {
    pub fn with_clock(clock:BusClock)->Self { Self { clock:Some(clock), ..Self::default() } }
    pub fn handle(&self)->CustomChipHandle { CustomChipHandle(self.state.clone()) }
    pub fn dmacon(&self)->u16 { self.state.borrow().dmacon }
    pub fn intena(&self)->u16 { self.state.borrow().intena }
    pub fn intreq(&self)->u16 { self.state.borrow().intreq }
    pub fn pending_interrupts(&self)->u16 { self.handle().pending_interrupts() }
    pub fn interrupt_level(&self)->u8 { self.handle().interrupt_level() }
    pub fn set_raster(&mut self,vpos:u16,vhpos:u16) { let mut state=self.state.borrow_mut(); state.vpos=vpos; state.vhpos=vhpos; }

    fn read_reg(&self,address:u32)->Option<u16> {
        let raster=self.clock.as_ref().map(|clock| RasterGeometry::PAL_OCS.position(clock.cycle()));
        match address {
            DMACONR=>Some(self.state.borrow().dmacon),
            INTENAR=>Some(self.state.borrow().intena),
            INTREQR=>Some(self.state.borrow().intreq),
            VPOSR=>Some(raster.map_or(self.state.borrow().vpos,|p|p.line)),
            VHPOSR=>Some(raster.map_or(self.state.borrow().vhpos,|p|p.slot)),
            _=>None,
        }
    }

    fn write_reg(&mut self,address:u32,value:u16)->bool {
        match address {
            DMACON=>{
                let bits=value & 0x7fff;
                let mut state=self.state.borrow_mut();
                if value & 0x8000 != 0 { state.dmacon|=bits; } else { state.dmacon&=!bits; }
                true
            }
            INTENA=>{
                let bits=value & 0x7fff;
                let mut state=self.state.borrow_mut();
                if value & 0x8000 != 0 { state.intena|=bits; } else { state.intena&=!bits; }
                true
            }
            INTREQ=>{
                let bits=value & 0x7fff;
                let mut state=self.state.borrow_mut();
                if value & 0x8000 != 0 { state.intreq|=bits; } else { state.intreq&=!bits; }
                true
            }
            _=>false,
        }
    }
}



pub const fn interrupt_source_mask(source:InterruptSource)->u16 {
    match source {
        InterruptSource::External=>0x2000, InterruptSource::DiskSync=>0x1000,
        InterruptSource::SerialReceive=>0x0800, InterruptSource::Audio3=>0x0400,
        InterruptSource::Audio2=>0x0200, InterruptSource::Audio1=>0x0100,
        InterruptSource::Audio0=>0x0080, InterruptSource::Blitter=>0x0040,
        InterruptSource::VerticalBlank=>0x0020, InterruptSource::Copper=>0x0010,
        InterruptSource::Ports=>0x0008, InterruptSource::Soft=>0x0004,
        InterruptSource::DiskBlock=>0x0002, InterruptSource::TransmitBufferEmpty=>0x0001,
        InterruptSource::Software=>0,
    }
}

pub const fn interrupt_level(pending:u16)->u8 {
    if pending & 0x2000 != 0 { 6 }
    else if pending & 0x1800 != 0 { 5 }
    else if pending & 0x0780 != 0 { 4 }
    else if pending & 0x0070 != 0 { 3 }
    else if pending & 0x0008 != 0 { 2 }
    else if pending & 0x0007 != 0 { 1 }
    else { 0 }
}

impl Bus for CustomChips {
    fn read8(&mut self,address:u32)->Result<u8,BusError> {
        let aligned=address & !1;
        let word=self.read_reg(aligned).ok_or(BusError::Unmapped{address})?;
        Ok(if address & 1 == 0 { (word>>8) as u8 } else { word as u8 })
    }

    fn write8(&mut self,address:u32,value:u8)->Result<(),BusError> {
        let aligned=address & !1;
        let old=self.read_reg(aligned).unwrap_or(0);
        let word=if address & 1 == 0 { (u16::from(value)<<8)|(old&0xff) } else { (old&0xff00)|u16::from(value) };
        if self.write_reg(aligned,word) { Ok(()) } else { Err(BusError::Unmapped{address}) }
    }

    fn read16(&mut self,address:u32)->Result<u16,BusError> {
        if address & 1 != 0 { return Err(BusError::AddressError{address}); }
        self.read_reg(address).ok_or(BusError::Unmapped{address})
    }

    fn write16(&mut self,address:u32,value:u16)->Result<(),BusError> {
        if address & 1 != 0 { return Err(BusError::AddressError{address}); }
        if self.write_reg(address,value) { Ok(()) } else { Err(BusError::Unmapped{address}) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;



    #[test]
    fn pending_sources_map_to_amiga_cpu_interrupt_levels() {
        assert_eq!(interrupt_level(0x0001),1);
        assert_eq!(interrupt_level(0x0008),2);
        assert_eq!(interrupt_level(0x0010),3);
        assert_eq!(interrupt_level(0x0080),4);
        assert_eq!(interrupt_level(0x0800),5);
        assert_eq!(interrupt_level(0x2000),6);
        assert_eq!(interrupt_level(0),0);
        assert_eq!(interrupt_level(0x2081),6);
    }

    #[test]
    fn interrupt_state_uses_set_clear_semantics_and_master_gate() {
        let mut chips=CustomChips::default();
        chips.write16(INTENA,0xc060).unwrap();
        assert_eq!(chips.read16(INTENAR).unwrap(),0x4060);
        chips.write16(INTREQ,0x8060).unwrap();
        assert_eq!(chips.read16(INTREQR).unwrap(),0x0060);
        assert_eq!(chips.pending_interrupts(),0x0060);

        chips.write16(INTENA,0x4000).unwrap();
        assert_eq!(chips.pending_interrupts(),0);
    }

    #[test]
    fn shared_clock_drives_raster_registers() {
        let clock=BusClock::new(0);
        let mut chips=CustomChips::with_clock(clock.clone());
        clock.set(227*12+34);
        assert_eq!(chips.read16(VPOSR).unwrap(),12);
        assert_eq!(chips.read16(VHPOSR).unwrap(),34);
    }

    #[test]
    fn dmacon_uses_amiga_set_clear_semantics() {
        let mut chips=CustomChips::default();
        chips.write16(DMACON,0x8200).unwrap();
        assert_eq!(chips.dmacon(),0x0200);
        chips.write16(DMACON,0x0200).unwrap();
        assert_eq!(chips.dmacon(),0);
    }

    #[test]
    fn raster_registers_are_readable() {
        let mut chips=CustomChips::default();
        chips.set_raster(0x1234,0x5678);
        assert_eq!(chips.read16(VPOSR).unwrap(),0x1234);
        assert_eq!(chips.read16(VHPOSR).unwrap(),0x5678);
    }
    #[test]
    fn word_writes_apply_set_clear_atomically() {
        let mut chips=CustomChips::default();
        chips.write16(DMACON,0x8001).unwrap();
        assert_eq!(chips.dmacon(),0x0001);
        chips.write16(INTENA,0xc001).unwrap();
        assert_eq!(chips.intena(),0x4001);
        chips.write16(INTREQ,0x8001).unwrap();
        assert_eq!(chips.intreq(),0x0001);
    }


}
