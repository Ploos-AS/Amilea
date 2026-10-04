//! Amiga custom-chip register block.
//! Functional Copper, Blitter, bitplane, sprite and audio DMA are added incrementally.

use amilea_bus::{Bus, BusClock, BusError, RasterGeometry};

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

#[derive(Debug,Clone)]
pub struct CustomChips {
    dmacon:u16,
    intena:u16,
    intreq:u16,
    vpos:u16,
    vhpos:u16,
    clock:Option<BusClock>,
}

impl Default for CustomChips {
    fn default()->Self { Self { dmacon:0, intena:0, intreq:0, vpos:0, vhpos:0, clock:None } }
}

impl CustomChips {
    pub fn with_clock(clock:BusClock)->Self { Self { clock:Some(clock), ..Self::default() } }
    pub fn dmacon(&self)->u16 { self.dmacon }
    pub fn intena(&self)->u16 { self.intena }
    pub fn intreq(&self)->u16 { self.intreq }
    pub fn pending_interrupts(&self)->u16 { if self.intena & 0x4000 != 0 { self.intena & self.intreq & 0x3fff } else { 0 } }
    pub fn set_raster(&mut self,vpos:u16,vhpos:u16) { self.vpos=vpos; self.vhpos=vhpos; }

    fn read_reg(&self,address:u32)->Option<u16> {
        let raster=self.clock.as_ref().map(|clock| RasterGeometry::PAL_OCS.position(clock.cycle()));
        match address {
            DMACONR=>Some(self.dmacon),
            INTENAR=>Some(self.intena),
            INTREQR=>Some(self.intreq),
            VPOSR=>Some(raster.map_or(self.vpos,|p|p.line)),
            VHPOSR=>Some(raster.map_or(self.vhpos,|p|p.slot)),
            _=>None,
        }
    }

    fn write_reg(&mut self,address:u32,value:u16)->bool {
        match address {
            DMACON=>{
                let bits=value & 0x7fff;
                if value & 0x8000 != 0 { self.dmacon|=bits; } else { self.dmacon&=!bits; }
                true
            }
            INTENA=>{
                let bits=value & 0x7fff;
                if value & 0x8000 != 0 { self.intena|=bits; } else { self.intena&=!bits; }
                true
            }
            INTREQ=>{
                let bits=value & 0x7fff;
                if value & 0x8000 != 0 { self.intreq|=bits; } else { self.intreq&=!bits; }
                true
            }
            _=>false,
        }
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;


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
}
