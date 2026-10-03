//! Deterministic 24-bit Amiga bus primitives.

use thiserror::Error;

pub const ADDRESS_MASK: u32 = 0x00ff_ffff;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BusError {
    #[error("address {address:#08x} is outside mapped RAM")]
    Unmapped { address: u32 },
    #[error("word/long access at odd address {address:#08x}")]
    AddressError { address: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusMaster {
    Cpu,
    Copper,
    Blitter,
    Bitplane,
    Sprite(u8),
    Audio(u8),
    Disk,
    Refresh,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusEvent {
    pub cycle: u64,
    pub master: BusMaster,
    pub access: BusAccess,
    pub address: u32,
    pub size: u8,
    pub value: Option<u32>,
    pub fault: Option<BusFault>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusFault {
    Unmapped,
    AddressError,
}

impl From<&BusError> for BusFault {
    fn from(error: &BusError) -> Self {
        match error {
            BusError::Unmapped { .. } => Self::Unmapped,
            BusError::AddressError { .. } => Self::AddressError,
        }
    }
}

pub trait BusObserver {
    fn observe(&mut self, event: BusEvent);
}

impl<F: FnMut(BusEvent)> BusObserver for F {
    fn observe(&mut self, event: BusEvent) { self(event); }
}

pub trait Bus {
    fn read8(&mut self, address: u32) -> Result<u8, BusError>;
    fn write8(&mut self, address: u32, value: u8) -> Result<(), BusError>;

    fn read16(&mut self, address: u32) -> Result<u16, BusError> {
        match self.inner.read16(address) {
            Ok(value) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Read, address: mask(address), size: 2, value: Some(value as u32), fault: None });
                Ok(value)
            }
            Err(error) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Read, address: mask(address), size: 2, value: None, fault: Some((&error).into()) });
                Err(error)
            }
        }
    }

    fn read32(&mut self, address: u32) -> Result<u32, BusError> {
        match self.inner.read32(address) {
            Ok(value) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Read, address: mask(address), size: 4, value: Some(value), fault: None });
                Ok(value)
            }
            Err(error) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Read, address: mask(address), size: 4, value: None, fault: Some((&error).into()) });
                Err(error)
            }
        }
    }

    fn write16(&mut self, address: u32, value: u16) -> Result<(), BusError> {
        match self.inner.write16(address, value) {
            Ok(()) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Write, address: mask(address), size: 2, value: Some(value as u32), fault: None });
                Ok(())
            }
            Err(error) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Write, address: mask(address), size: 2, value: Some(value as u32), fault: Some((&error).into()) });
                Err(error)
            }
        }
    }

    fn write32(&mut self, address: u32, value: u32) -> Result<(), BusError> {
        match self.inner.write32(address, value) {
            Ok(()) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Write, address: mask(address), size: 4, value: Some(value), fault: None });
                Ok(())
            }
            Err(error) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Write, address: mask(address), size: 4, value: Some(value), fault: Some((&error).into()) });
                Err(error)
            }
        }
    }

    fn read8(&mut self, address: u32) -> Result<u8, BusError> {
        match self.inner.read8(address) {
            Ok(value) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Read, address: mask(address), size: 1, value: Some(value as u32), fault: None });
                Ok(value)
            }
            Err(error) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Read, address: mask(address), size: 1, value: None, fault: Some((&error).into()) });
                Err(error)
            }
        }
    }

    fn write8(&mut self, address: u32, value: u8) -> Result<(), BusError> {
        match self.inner.write8(address, value) {
            Ok(()) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Write, address: mask(address), size: 1, value: Some(value as u32), fault: None });
                Ok(())
            }
            Err(error) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Write, address: mask(address), size: 1, value: Some(value as u32), fault: Some((&error).into()) });
                Err(error)
            }
        }
    }

    fn read8(&mut self, address: u32) -> Result<u8, BusError> {
        let value = self.inner.read8(address)?;
        self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Read, address: mask(address), size: 1, value: Some(value as u32), fault: None });
        Ok(value)
    }

    fn write8(&mut self, address: u32, value: u8) -> Result<(), BusError> {
        self.inner.write8(address, value)?;
        self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Write, address: mask(address), size: 1, value: Some(value as u32), fault: None });
        Ok(())
    }

    fn read16(&mut self, address: u32) -> Result<u16, BusError> {
        match self.inner.read16(address) {
            Ok(value) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Read, address: mask(address), size: 2, value: Some(value as u32), fault: None });
                Ok(value)
            }
            Err(error) => {
                self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Read, address: mask(address), size: 2, value: None, fault: Some((&error).into()) });
                Err(error)
            }
        }
    }

    fn read32(&mut self, address: u32) -> Result<u32, BusError> {
        let value = self.inner.read32(address)?;
        self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Read, address: mask(address), size: 4, value: Some(value), fault: None });
        Ok(value)
    }

    fn write16(&mut self, address: u32, value: u16) -> Result<(), BusError> {
        self.inner.write16(address, value)?;
        self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Write, address: mask(address), size: 2, value: Some(value as u32), fault: None });
        Ok(())
    }

    fn write32(&mut self, address: u32, value: u32) -> Result<(), BusError> {
        self.inner.write32(address, value)?;
        self.observer.observe(BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Write, address: mask(address), size: 4, value: Some(value), fault: None });
        Ok(())
    }
}

pub const fn mask(address: u32) -> u32 {
    address & ADDRESS_MASK
}

fn require_even(address: u32) -> Result<(), BusError> {
    if address & 1 != 0 {
        Err(BusError::AddressError { address })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_bus_reports_semantic_writes_once() {
        let mut bus = RamBus::new(16);
        let mut events = Vec::new();
        {
            let mut observed = ObservedBus::new(&mut bus, &mut |event| events.push(event), BusMaster::Cpu, 0);
            observed.write32(2, 0x1234_abcd).unwrap();
        }
        assert_eq!(events, vec![BusEvent { cycle: 0, master: BusMaster::Cpu, access: BusAccess::Write, address: 2, size: 4, value: Some(0x1234_abcd), fault: None }]);
        assert_eq!(bus.read32(2).unwrap(), 0x1234_abcd);
    }

    #[test]
    fn observed_bus_records_failed_write_with_attempted_value() {
        let mut bus = RamBus::new(4);
        let mut events = Vec::new();
        {
            let mut observed = ObservedBus::new(&mut bus, &mut |event| events.push(event), BusMaster::Blitter, 91);
            assert_eq!(observed.write32(4, 0xdead_beef), Err(BusError::Unmapped { address: 4 }));
        }
        assert_eq!(events, vec![BusEvent {
            cycle: 91,
            master: BusMaster::Blitter,
            access: BusAccess::Write,
            address: 4,
            size: 4,
            value: Some(0xdead_beef),
            fault: Some(BusFault::Unmapped),
        }]);
    }

    #[test]
    fn observed_bus_records_failed_transfer() {
        let mut bus = RamBus::new(16);
        let mut events = Vec::new();
        {
            let mut observed = ObservedBus::new(&mut bus, &mut |event| events.push(event), BusMaster::Cpu, 77);
            assert_eq!(observed.read16(1), Err(BusError::AddressError { address: 1 }));
        }
        assert_eq!(events, vec![BusEvent {
            cycle: 77,
            master: BusMaster::Cpu,
            access: BusAccess::Read,
            address: 1,
            size: 2,
            value: None,
            fault: Some(BusFault::AddressError),
        }]);
    }

    #[test]
    fn observed_bus_cycle_can_advance_deterministically() {
        let mut bus = RamBus::new(16);
        bus.write16(4, 0xabcd).unwrap();
        let mut events = Vec::new();
        {
            let mut observed = ObservedBus::new(&mut bus, &mut |event| events.push(event), BusMaster::Cpu, 100);
            assert_eq!(observed.read16(4).unwrap(), 0xabcd);
            observed.set_cycle(104);
            observed.write16(6, 0x1234).unwrap();
        }
        assert_eq!(events[0].cycle, 100);
        assert_eq!(events[1].cycle, 104);
    }

    #[test]
    fn observed_bus_preserves_dma_master_identity() {
        let mut bus = RamBus::new(16);
        bus.write16(4, 0xabcd).unwrap();
        let mut events = Vec::new();
        {
            let mut observed = ObservedBus::new(&mut bus, &mut |event| events.push(event), BusMaster::Copper, 42);
            assert_eq!(observed.read16(4).unwrap(), 0xabcd);
        }
        assert_eq!(events, vec![BusEvent { cycle: 42, master: BusMaster::Copper, access: BusAccess::Read, address: 4, size: 2, value: Some(0xabcd), fault: None }]);
    }

    #[test]
    fn observed_bus_reports_semantic_reads_once() {
        let mut bus = RamBus::new(16);
        bus.write32(2, 0x1234_abcd).unwrap();
        let mut events = Vec::new();
        let value = {
            let mut observed = ObservedBus::new(&mut bus, &mut |event| events.push(event), BusMaster::Cpu, 0);
            observed.read32(2).unwrap()
        };
        assert_eq!(value, 0x1234_abcd);
        assert_eq!(events, vec![BusEvent { cycle: self.cycle, master: self.master, access: BusAccess::Read, address: 2, size: 4, value: Some(0x1234_abcd), fault: None }]);
    }

    #[test]
    fn bus_is_big_endian() {
        let mut bus = RamBus::new(16);
        bus.write32(0, 0x1234_abcd).unwrap();
        assert_eq!(bus.read8(0).unwrap(), 0x12);
        assert_eq!(bus.read8(1).unwrap(), 0x34);
        assert_eq!(bus.read16(2).unwrap(), 0xabcd);
        assert_eq!(bus.read32(0).unwrap(), 0x1234_abcd);
    }

    #[test]
    fn odd_word_access_is_address_error() {
        let bus = RamBus::new(16);
        assert_eq!(
            bus.read16(1),
            Err(BusError::AddressError { address: 1 })
        );
    }

    #[test]
    fn addresses_are_24_bit() {
        let mut bus = RamBus::new(16);
        bus.write8(0x0100_0003, 0xaa).unwrap();
        assert_eq!(bus.read8(3).unwrap(), 0xaa);
    }
}
