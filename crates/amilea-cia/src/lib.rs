//! Minimal MOS 8520 CIA-A state needed for Amiga boot plumbing.
//! Timers, TOD, serial and interrupts are intentionally not implemented yet.

use amilea_bus::{Bus, BusError, BusSignal};

pub const CIA_A_PRA: u32 = 0xbfe001;
pub const CIA_A_DDRA: u32 = 0xbfe201;

#[derive(Debug, Clone)]
pub struct CiaA {
    pra: u8,
    ddra: u8,
    overlay: Option<BusSignal>,
}

impl Default for CiaA {
    fn default() -> Self {
        Self { pra: 0xff, ddra: 0x00, overlay: None }
    }
}

impl CiaA {
    pub fn with_overlay_signal(overlay:BusSignal)->Self {
        let cia=Self { pra:0xff, ddra:0x00, overlay:Some(overlay) };
        cia.sync_overlay();
        cia
    }
    fn sync_overlay(&self) {
        if let Some(signal)=&self.overlay { signal.set(self.overlay_enabled()); }
    }
    pub fn pra(&self) -> u8 { self.pra }
    pub fn ddra(&self) -> u8 { self.ddra }
    pub fn write_pra(&mut self, value: u8) { self.pra = value; self.sync_overlay(); }
    pub fn write_ddra(&mut self, value: u8) { self.ddra = value; self.sync_overlay(); }

    /// Logical OVL output used by the machine memory mapper.
    /// Bit 0 only drives OVL when configured as an output.
    pub fn overlay_enabled(&self) -> bool {
        self.ddra & 0x01 == 0 || self.pra & 0x01 != 0
    }
}


impl Bus for CiaA {
    fn read8(&mut self,address:u32)->Result<u8,BusError> {
        match address & 0x00ff_ffff {
            CIA_A_PRA => Ok(self.pra()),
            CIA_A_DDRA => Ok(self.ddra()),
            address => Err(BusError::Unmapped{address}),
        }
    }

    fn write8(&mut self,address:u32,value:u8)->Result<(),BusError> {
        match address & 0x00ff_ffff {
            CIA_A_PRA => { self.write_pra(value); Ok(()) }
            CIA_A_DDRA => { self.write_ddra(value); Ok(()) }
            address => Err(BusError::Unmapped{address}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cia_a_updates_shared_overlay_signal() {
        let signal=BusSignal::new(false);
        let mut cia=CiaA::with_overlay_signal(signal.clone());
        assert!(signal.get());
        cia.write_ddra(0x01);
        cia.write_pra(0x00);
        assert!(!signal.get());
        cia.write_pra(0x01);
        assert!(signal.get());
    }

    #[test]
    fn cia_a_bus_registers_drive_overlay_state() {
        let mut cia=CiaA::default();
        cia.write8(CIA_A_DDRA,0x01).unwrap();
        cia.write8(CIA_A_PRA,0x00).unwrap();
        assert!(!cia.overlay_enabled());
        assert_eq!(cia.read8(CIA_A_DDRA).unwrap(),0x01);
        assert_eq!(cia.read8(CIA_A_PRA).unwrap(),0x00);
    }

    #[test]
    fn unimplemented_cia_register_is_unmapped() {
        let mut cia=CiaA::default();
        assert_eq!(cia.read8(0xbfe101),Err(BusError::Unmapped{address:0xbfe101}));
    }

    #[test]
    fn reset_state_keeps_overlay_enabled() {
        assert!(CiaA::default().overlay_enabled());
    }

    #[test]
    fn port_a_bit_zero_controls_overlay_when_output() {
        let mut cia=CiaA::default();
        cia.write_ddra(0x01);
        cia.write_pra(0x01);
        assert!(cia.overlay_enabled());
        cia.write_pra(0x00);
        assert!(!cia.overlay_enabled());
    }

    #[test]
    fn input_bit_does_not_disable_overlay() {
        let mut cia=CiaA::default();
        cia.write_pra(0x00);
        cia.write_ddra(0x00);
        assert!(cia.overlay_enabled());
    }
}
