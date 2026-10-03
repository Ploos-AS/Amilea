//! Amiga custom-chip register block.
//! Functional Copper, Blitter, bitplane, sprite and audio DMA are added incrementally.

use amilea_bus::{Bus, BusClock, BusError, RasterGeometry};

pub const CUSTOM_BASE:u32=0x00df_f000;
pub const CUSTOM_SIZE:u32=0x200;
pub const DMACONR:u32=CUSTOM_BASE+0x002;
pub const VPOSR:u32=CUSTOM_BASE+0x004;
pub const VHPOSR:u32=CUSTOM_BASE+0x006;
pub const DMACON:u32=CUSTOM_BASE+0x096;

#[derive(Debug,Clone)]
pub struct CustomChips {
    dmacon:u16,
    vpos:u16,
    vhpos:u16,
    clock:Option<BusClock>,
}

impl Default for CustomChips {
    fn default()->Self { Self { dmacon:0, vpos:0, vhpos:0, clock:None } }
}

impl CustomChips {
    pub fn with_clock(clock:BusClock)->Self { Self { clock:Some(clock), ..Self::default() } }
    pub fn dmacon(&self)->u16 { self.dmacon }
    pub fn set_raster(&mut self,vpos:u16,vhpos:u16) { self.vpos=vpos; self.vhpos=vhpos; }

    fn read_reg(&self,address:u32)->Option<u16> {
        let raster=self.clock.as_ref().map(|clock| RasterGeometry::PAL_OCS.position(clock.cycle()));
        match address {
            DMACONR=>Some(self.dmacon),
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
