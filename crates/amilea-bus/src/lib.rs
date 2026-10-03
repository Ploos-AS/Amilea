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
    pub master: BusMaster,
    pub access: BusAccess,
    pub address: u32,
    pub size: u8,
    pub value: u32,
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
        let address = mask(address);
        require_even(address)?;
        Ok(u16::from_be_bytes([
            self.read8(address)?,
            self.read8(mask(address + 1))?,
        ]))
    }

    fn read32(&mut self, address: u32) -> Result<u32, BusError> {
        let address = mask(address);
        require_even(address)?;
        Ok(u32::from_be_bytes([
            self.read8(address)?,
            self.read8(mask(address + 1))?,
            self.read8(mask(address + 2))?,
            self.read8(mask(address + 3))?,
        ]))
    }

    fn write16(&mut self, address: u32, value: u16) -> Result<(), BusError> {
        let address = mask(address);
        require_even(address)?;
        let bytes = value.to_be_bytes();
        self.write8(address, bytes[0])?;
        self.write8(mask(address + 1), bytes[1])
    }

    fn write32(&mut self, address: u32, value: u32) -> Result<(), BusError> {
        let address = mask(address);
        require_even(address)?;
        for (offset, byte) in value.to_be_bytes().into_iter().enumerate() {
            self.write8(mask(address + offset as u32), byte)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RamBus {
    ram: Vec<u8>,
}

impl RamBus {
    pub fn new(size: usize) -> Self {
        Self { ram: vec![0; size] }
    }
}

impl Bus for RamBus {
    fn read8(&mut self, address: u32) -> Result<u8, BusError> {
        let address = mask(address);
        self.ram
            .get(address as usize)
            .copied()
            .ok_or(BusError::Unmapped { address })
    }

    fn write8(&mut self, address: u32, value: u8) -> Result<(), BusError> {
        let address = mask(address);
        let cell = self
            .ram
            .get_mut(address as usize)
            .ok_or(BusError::Unmapped { address })?;
        *cell = value;
        Ok(())
    }
}

pub struct ObservedBus<'a, B, O> {
    inner: &'a mut B,
    observer: &'a mut O,
    master: BusMaster,
}

impl<'a, B, O> ObservedBus<'a, B, O> {
    pub fn new(inner: &'a mut B, observer: &'a mut O, master: BusMaster) -> Self {
        Self { inner, observer, master }
    }
}

impl<B: Bus, O: BusObserver> Bus for ObservedBus<'_, B, O> {
    fn read8(&mut self, address: u32) -> Result<u8, BusError> {
        let value = self.inner.read8(address)?;
        self.observer.observe(BusEvent { master: self.master, access: BusAccess::Read, address: mask(address), size: 1, value: value as u32 });
        Ok(value)
    }

    fn write8(&mut self, address: u32, value: u8) -> Result<(), BusError> {
        self.inner.write8(address, value)?;
        self.observer.observe(BusEvent { master: self.master, access: BusAccess::Write, address: mask(address), size: 1, value: value as u32 });
        Ok(())
    }

    fn read16(&mut self, address: u32) -> Result<u16, BusError> {
        let value = self.inner.read16(address)?;
        self.observer.observe(BusEvent { master: self.master, access: BusAccess::Read, address: mask(address), size: 2, value: value as u32 });
        Ok(value)
    }

    fn read32(&mut self, address: u32) -> Result<u32, BusError> {
        let value = self.inner.read32(address)?;
        self.observer.observe(BusEvent { master: self.master, access: BusAccess::Read, address: mask(address), size: 4, value });
        Ok(value)
    }

    fn write16(&mut self, address: u32, value: u16) -> Result<(), BusError> {
        self.inner.write16(address, value)?;
        self.observer.observe(BusEvent { master: self.master, access: BusAccess::Write, address: mask(address), size: 2, value: value as u32 });
        Ok(())
    }

    fn write32(&mut self, address: u32, value: u32) -> Result<(), BusError> {
        self.inner.write32(address, value)?;
        self.observer.observe(BusEvent { master: self.master, access: BusAccess::Write, address: mask(address), size: 4, value });
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
            let mut observed = ObservedBus::new(&mut bus, &mut |event| events.push(event), BusMaster::Cpu);
            observed.write32(2, 0x1234_abcd).unwrap();
        }
        assert_eq!(events, vec![BusEvent { master: self.master, access: BusAccess::Write, address: 2, size: 4, value: 0x1234_abcd }]);
        assert_eq!(bus.read32(2).unwrap(), 0x1234_abcd);
    }

    #[test]
    fn observed_bus_preserves_dma_master_identity() {
        let mut bus = RamBus::new(16);
        bus.write16(4, 0xabcd).unwrap();
        let mut events = Vec::new();
        {
            let mut observed = ObservedBus::new(&mut bus, &mut |event| events.push(event), BusMaster::Copper);
            assert_eq!(observed.read16(4).unwrap(), 0xabcd);
        }
        assert_eq!(events, vec![BusEvent { master: BusMaster::Copper, access: BusAccess::Read, address: 4, size: 2, value: 0xabcd }]);
    }

    #[test]
    fn observed_bus_reports_semantic_reads_once() {
        let mut bus = RamBus::new(16);
        bus.write32(2, 0x1234_abcd).unwrap();
        let mut events = Vec::new();
        let value = {
            let mut observed = ObservedBus::new(&mut bus, &mut |event| events.push(event), BusMaster::Cpu);
            observed.read32(2).unwrap()
        };
        assert_eq!(value, 0x1234_abcd);
        assert_eq!(events, vec![BusEvent { master: self.master, access: BusAccess::Read, address: 2, size: 4, value: 0x1234_abcd }]);
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
