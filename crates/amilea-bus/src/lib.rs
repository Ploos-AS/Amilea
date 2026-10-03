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
pub enum BusAccess { Read, Write }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusMaster {
    Cpu, Copper, Blitter, Bitplane, Sprite(u8), Audio(u8), Disk, Refresh, Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusPurpose { Unspecified, InstructionFetch, Data, Stack, VectorFetch }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusFault { Unmapped, AddressError }

impl From<&BusError> for BusFault {
    fn from(error: &BusError) -> Self {
        match error {
            BusError::Unmapped { .. } => Self::Unmapped,
            BusError::AddressError { .. } => Self::AddressError,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusEvent {
    pub cycle: u64,
    pub master: BusMaster,
    pub purpose: BusPurpose,
    pub access: BusAccess,
    pub address: u32,
    pub size: u8,
    pub value: Option<u32>,
    pub fault: Option<BusFault>,
}

pub trait BusObserver { fn observe(&mut self, event: BusEvent); }
impl<F: FnMut(BusEvent)> BusObserver for F { fn observe(&mut self, event: BusEvent) { self(event); } }

pub trait Bus {
    fn set_purpose(&mut self, _purpose: BusPurpose) {}
    fn read8(&mut self, address: u32) -> Result<u8, BusError>;
    fn write8(&mut self, address: u32, value: u8) -> Result<(), BusError>;

    fn read16(&mut self, address: u32) -> Result<u16, BusError> {
        let address = mask(address); require_even(address)?;
        Ok(u16::from_be_bytes([self.read8(address)?, self.read8(mask(address + 1))?]))
    }
    fn read32(&mut self, address: u32) -> Result<u32, BusError> {
        let address = mask(address); require_even(address)?;
        Ok(u32::from_be_bytes([
            self.read8(address)?, self.read8(mask(address + 1))?,
            self.read8(mask(address + 2))?, self.read8(mask(address + 3))?,
        ]))
    }
    fn write16(&mut self, address: u32, value: u16) -> Result<(), BusError> {
        let address = mask(address); require_even(address)?;
        let b=value.to_be_bytes(); self.write8(address,b[0])?; self.write8(mask(address+1),b[1])
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), BusError> {
        let address=mask(address); require_even(address)?;
        for (o,b) in value.to_be_bytes().into_iter().enumerate() { self.write8(mask(address+o as u32),b)?; }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RamBus { ram: Vec<u8> }
impl RamBus { pub fn new(size: usize) -> Self { Self { ram: vec![0; size] } } }
impl Bus for RamBus {
    fn read8(&mut self, address:u32)->Result<u8,BusError> {
        let address=mask(address); self.ram.get(address as usize).copied().ok_or(BusError::Unmapped{address})
    }
    fn write8(&mut self,address:u32,value:u8)->Result<(),BusError> {
        let address=mask(address); let cell=self.ram.get_mut(address as usize).ok_or(BusError::Unmapped{address})?; *cell=value; Ok(())
    }
}

pub struct ObservedBus<'a,B,O> {
    inner:&'a mut B, observer:&'a mut O, master:BusMaster, cycle:u64, purpose:BusPurpose,
}
impl<'a,B,O> ObservedBus<'a,B,O> {
    pub fn new(inner:&'a mut B, observer:&'a mut O, master:BusMaster, cycle:u64)->Self {
        Self { inner, observer, master, cycle, purpose:BusPurpose::Unspecified }
    }
    pub fn set_cycle(&mut self, cycle:u64) { self.cycle=cycle; }
    fn take_purpose(&mut self)->BusPurpose { std::mem::replace(&mut self.purpose, BusPurpose::Unspecified) }
}
impl<B:Bus,O:BusObserver> Bus for ObservedBus<'_,B,O> {
    fn set_purpose(&mut self,purpose:BusPurpose){ self.purpose=purpose; }

    fn read8(&mut self,address:u32)->Result<u8,BusError>{
        let purpose=self.take_purpose(); let result=self.inner.read8(address);
        let (value,fault)=match &result { Ok(v)=>(Some(*v as u32),None), Err(e)=>(None,Some(e.into())) };
        self.observer.observe(BusEvent{cycle:self.cycle,master:self.master,purpose,access:BusAccess::Read,address:mask(address),size:1,value,fault}); result
    }
    fn read16(&mut self,address:u32)->Result<u16,BusError>{
        let purpose=self.take_purpose(); let result=self.inner.read16(address);
        let (value,fault)=match &result { Ok(v)=>(Some(*v as u32),None), Err(e)=>(None,Some(e.into())) };
        self.observer.observe(BusEvent{cycle:self.cycle,master:self.master,purpose,access:BusAccess::Read,address:mask(address),size:2,value,fault}); result
    }
    fn read32(&mut self,address:u32)->Result<u32,BusError>{
        let purpose=self.take_purpose(); let result=self.inner.read32(address);
        let (value,fault)=match &result { Ok(v)=>(Some(*v),None), Err(e)=>(None,Some(e.into())) };
        self.observer.observe(BusEvent{cycle:self.cycle,master:self.master,purpose,access:BusAccess::Read,address:mask(address),size:4,value,fault}); result
    }
    fn write8(&mut self,address:u32,value:u8)->Result<(),BusError>{
        let purpose=self.take_purpose(); let result=self.inner.write8(address,value);
        let fault=result.as_ref().err().map(Into::into);
        self.observer.observe(BusEvent{cycle:self.cycle,master:self.master,purpose,access:BusAccess::Write,address:mask(address),size:1,value:Some(value as u32),fault}); result
    }
    fn write16(&mut self,address:u32,value:u16)->Result<(),BusError>{
        let purpose=self.take_purpose(); let result=self.inner.write16(address,value);
        let fault=result.as_ref().err().map(Into::into);
        self.observer.observe(BusEvent{cycle:self.cycle,master:self.master,purpose,access:BusAccess::Write,address:mask(address),size:2,value:Some(value as u32),fault}); result
    }
    fn write32(&mut self,address:u32,value:u32)->Result<(),BusError>{
        let purpose=self.take_purpose(); let result=self.inner.write32(address,value);
        let fault=result.as_ref().err().map(Into::into);
        self.observer.observe(BusEvent{cycle:self.cycle,master:self.master,purpose,access:BusAccess::Write,address:mask(address),size:4,value:Some(value),fault}); result
    }
}

pub const fn mask(address:u32)->u32 { address & ADDRESS_MASK }
fn require_even(address:u32)->Result<(),BusError> {
    if address & 1 != 0 { Err(BusError::AddressError{address}) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_is_big_endian() {
        let mut bus=RamBus::new(16); bus.write32(0,0x1234_abcd).unwrap();
        assert_eq!(bus.read8(0).unwrap(),0x12); assert_eq!(bus.read8(1).unwrap(),0x34);
        assert_eq!(bus.read16(2).unwrap(),0xabcd); assert_eq!(bus.read32(0).unwrap(),0x1234_abcd);
    }

    #[test]
    fn odd_word_access_is_address_error() {
        let mut bus=RamBus::new(16);
        assert_eq!(bus.read16(1),Err(BusError::AddressError{address:1}));
    }

    #[test]
    fn addresses_are_24_bit() {
        let mut bus=RamBus::new(16); bus.write8(0x0100_0003,0xaa).unwrap(); assert_eq!(bus.read8(3).unwrap(),0xaa);
    }

    #[test]
    fn observed_bus_reports_semantic_access_once() {
        let mut bus=RamBus::new(16); bus.write32(2,0x1234_abcd).unwrap(); let mut events=Vec::new();
        { let mut observed=ObservedBus::new(&mut bus,&mut |e| events.push(e),BusMaster::Cpu,7);
          observed.set_purpose(BusPurpose::Data); assert_eq!(observed.read32(2).unwrap(),0x1234_abcd); }
        assert_eq!(events,vec![BusEvent{cycle:7,master:BusMaster::Cpu,purpose:BusPurpose::Data,access:BusAccess::Read,address:2,size:4,value:Some(0x1234_abcd),fault:None}]);
    }

    #[test]
    fn purpose_is_consumed_even_on_fault() {
        let mut bus=RamBus::new(16); let mut events=Vec::new();
        { let mut observed=ObservedBus::new(&mut bus,&mut |e| events.push(e),BusMaster::Cpu,9);
          observed.set_purpose(BusPurpose::Data);
          assert_eq!(observed.read16(1),Err(BusError::AddressError{address:1}));
          assert_eq!(observed.read8(0).unwrap(),0); }
        assert_eq!(events[0].purpose,BusPurpose::Data);
        assert_eq!(events[1].purpose,BusPurpose::Unspecified);
    }

    #[test]
    fn failed_write_preserves_attempted_value() {
        let mut bus=RamBus::new(4); let mut events=Vec::new();
        { let mut observed=ObservedBus::new(&mut bus,&mut |e| events.push(e),BusMaster::Blitter,91);
          assert_eq!(observed.write32(4,0xdead_beef),Err(BusError::Unmapped{address:4})); }
        assert_eq!(events[0].value,Some(0xdead_beef)); assert_eq!(events[0].fault,Some(BusFault::Unmapped));
    }
}
