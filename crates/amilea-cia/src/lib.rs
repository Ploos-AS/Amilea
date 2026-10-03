//! Minimal MOS 8520 CIA-A state needed for Amiga boot plumbing.
//! Timers, TOD, serial and interrupts are intentionally not implemented yet.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CiaA {
    pra: u8,
    ddra: u8,
}

impl Default for CiaA {
    fn default() -> Self {
        Self { pra: 0xff, ddra: 0x00 }
    }
}

impl CiaA {
    pub fn pra(&self) -> u8 { self.pra }
    pub fn ddra(&self) -> u8 { self.ddra }
    pub fn write_pra(&mut self, value: u8) { self.pra = value; }
    pub fn write_ddra(&mut self, value: u8) { self.ddra = value; }

    /// Logical OVL output used by the machine memory mapper.
    /// Bit 0 only drives OVL when configured as an output.
    pub fn overlay_enabled(&self) -> bool {
        self.ddra & 0x01 == 0 || self.pra & 0x01 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
