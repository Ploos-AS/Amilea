//! Deterministic 24-bit Amiga bus primitives.

use std::cell::Cell;
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
pub enum BusSlot {
    Free,
    Reserved(BusMaster),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusSchedule {
    slots: Vec<BusSlot>,
}

impl BusSchedule {
    pub fn new(slots: Vec<BusMaster>) -> Self {
        Self::from_slots(slots.into_iter().map(BusSlot::Reserved).collect())
    }

    pub fn from_slots(slots: Vec<BusSlot>) -> Self {
        assert!(!slots.is_empty(), "bus schedule requires at least one slot");
        Self { slots }
    }

    pub fn cpu_only() -> Self { Self::new(vec![BusMaster::Cpu]) }

    pub fn free() -> Self { Self::from_slots(vec![BusSlot::Free]) }

    pub fn slot(&self, cycle: u64) -> BusSlot {
        self.slots[(cycle % self.slots.len() as u64) as usize]
    }

    pub fn owner(&self, cycle: u64) -> Option<BusMaster> {
        match self.slot(cycle) { BusSlot::Free => None, BusSlot::Reserved(master) => Some(master) }
    }

    pub fn available_to(&self, master: BusMaster, cycle: u64) -> bool {
        matches!(self.slot(cycle), BusSlot::Free | BusSlot::Reserved(m) if m == master)
    }

    pub fn period(&self) -> usize { self.slots.len() }

    pub fn next_cycle_for(&self, master: BusMaster, from_cycle: u64) -> Option<u64> {
        (0..self.slots.len() as u64)
            .map(|offset| from_cycle.wrapping_add(offset))
            .find(|&cycle| self.available_to(master, cycle))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusPurpose { Unspecified, InstructionFetch, Data, Stack, VectorFetch }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusFault { Unmapped, AddressError }

#[derive(Debug, Default)]
pub struct BusClock { cycle: Cell<u64> }

impl BusClock {
    pub const fn new(cycle: u64) -> Self { Self { cycle: Cell::new(cycle) } }
    pub fn cycle(&self) -> u64 { self.cycle.get() }
    pub fn set(&self, cycle: u64) { self.cycle.set(cycle); }
    pub fn advance(&self, cycles: u64) { self.cycle.set(self.cycle.get().wrapping_add(cycles)); }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusTiming {
    Fixed(u64),
    Width { byte: u64, word: u64, long: u64 },
}

impl Default for BusTiming {
    fn default() -> Self { Self::Fixed(1) }
}

impl BusTiming {
    pub const fn cycles(self, size: u8) -> u64 {
        match self {
            Self::Fixed(cycles) => cycles,
            Self::Width { byte, word, long } => match size {
                1 => byte,
                2 => word,
                4 => long,
                _ => 0,
            },
        }
    }
}

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
    inner:&'a mut B, observer:&'a mut O, master:BusMaster, clock:BusClock, shared_clock:Option<&'a BusClock>, schedule:Option<&'a BusSchedule>, timing:BusTiming, purpose:BusPurpose,
}
impl<'a,B,O> ObservedBus<'a,B,O> {
    pub fn new(inner:&'a mut B, observer:&'a mut O, master:BusMaster, cycle:u64)->Self {
        Self { inner, observer, master, clock:BusClock::new(cycle), shared_clock:None, schedule:None, timing: BusTiming::default(), purpose:BusPurpose::Unspecified }
    }
    pub fn with_clock(inner:&'a mut B, observer:&'a mut O, master:BusMaster, clock:&'a BusClock)->Self {
        Self { inner, observer, master, clock:BusClock::default(), shared_clock:Some(clock), schedule:None, timing:BusTiming::default(), purpose:BusPurpose::Unspecified }
    }
    fn current_cycle(&self)->u64 { self.shared_clock.map_or_else(|| self.clock.cycle(), BusClock::cycle) }
    pub fn set_cycle(&mut self, cycle:u64) { if let Some(clock)=self.shared_clock { clock.set(cycle) } else { self.clock.set(cycle) } }
    pub fn set_cycle_step(&mut self, cycle_step:u64) { self.timing=BusTiming::Fixed(cycle_step); }
    pub fn set_timing(&mut self, timing:BusTiming) { self.timing=timing; }
    pub fn set_schedule(&mut self, schedule:&'a BusSchedule) { self.schedule=Some(schedule); }
    fn align_to_owned_slot(&mut self) {
        if let Some(schedule)=self.schedule {
            if let Some(cycle)=schedule.next_cycle_for(self.master,self.current_cycle()) { self.set_cycle(cycle); }
        }
    }
    fn advance_cycle(&mut self, size:u8) { let n=self.timing.cycles(size); if let Some(clock)=self.shared_clock { clock.advance(n) } else { self.clock.advance(n) } }
    fn take_purpose(&mut self)->BusPurpose { std::mem::replace(&mut self.purpose, BusPurpose::Unspecified) }
}
impl<B:Bus,O:BusObserver> Bus for ObservedBus<'_,B,O> {
    fn set_purpose(&mut self,purpose:BusPurpose){ self.purpose=purpose; }

    fn read8(&mut self,address:u32)->Result<u8,BusError>{
        self.align_to_owned_slot(); let purpose=self.take_purpose(); let result=self.inner.read8(address);
        let (value,fault)=match &result { Ok(v)=>(Some(*v as u32),None), Err(e)=>(None,Some(e.into())) };
        self.observer.observe(BusEvent{cycle:self.current_cycle(),master:self.master,purpose,access:BusAccess::Read,address:mask(address),size:1,value,fault}); self.advance_cycle(1); result
    }
    fn read16(&mut self,address:u32)->Result<u16,BusError>{
        self.align_to_owned_slot(); let purpose=self.take_purpose(); let result=self.inner.read16(address);
        let (value,fault)=match &result { Ok(v)=>(Some(*v as u32),None), Err(e)=>(None,Some(e.into())) };
        self.observer.observe(BusEvent{cycle:self.current_cycle(),master:self.master,purpose,access:BusAccess::Read,address:mask(address),size:2,value,fault}); self.advance_cycle(2); result
    }
    fn read32(&mut self,address:u32)->Result<u32,BusError>{
        self.align_to_owned_slot(); let purpose=self.take_purpose(); let result=self.inner.read32(address);
        let (value,fault)=match &result { Ok(v)=>(Some(*v),None), Err(e)=>(None,Some(e.into())) };
        self.observer.observe(BusEvent{cycle:self.current_cycle(),master:self.master,purpose,access:BusAccess::Read,address:mask(address),size:4,value,fault}); self.advance_cycle(4); result
    }
    fn write8(&mut self,address:u32,value:u8)->Result<(),BusError>{
        self.align_to_owned_slot(); let purpose=self.take_purpose(); let result=self.inner.write8(address,value);
        let fault=result.as_ref().err().map(Into::into);
        self.observer.observe(BusEvent{cycle:self.current_cycle(),master:self.master,purpose,access:BusAccess::Write,address:mask(address),size:1,value:Some(value as u32),fault}); self.advance_cycle(1); result
    }
    fn write16(&mut self,address:u32,value:u16)->Result<(),BusError>{
        self.align_to_owned_slot(); let purpose=self.take_purpose(); let result=self.inner.write16(address,value);
        let fault=result.as_ref().err().map(Into::into);
        self.observer.observe(BusEvent{cycle:self.current_cycle(),master:self.master,purpose,access:BusAccess::Write,address:mask(address),size:2,value:Some(value as u32),fault}); self.advance_cycle(2); result
    }
    fn write32(&mut self,address:u32,value:u32)->Result<(),BusError>{
        self.align_to_owned_slot(); let purpose=self.take_purpose(); let result=self.inner.write32(address,value);
        let fault=result.as_ref().err().map(Into::into);
        self.observer.observe(BusEvent{cycle:self.current_cycle(),master:self.master,purpose,access:BusAccess::Write,address:mask(address),size:4,value:Some(value),fault}); self.advance_cycle(4); result
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
        assert_eq!(events[0].cycle,9);
        assert_eq!(events[1].cycle,10);
    }

    #[test]
    fn observed_bus_advances_cycle_per_semantic_transaction() {
        let mut bus=RamBus::new(16); bus.write16(4,0xabcd).unwrap(); let mut events=Vec::new();
        { let mut observed=ObservedBus::new(&mut bus,&mut |e| events.push(e),BusMaster::Cpu,100);
          observed.set_cycle_step(4);
          observed.set_purpose(BusPurpose::InstructionFetch); assert_eq!(observed.read16(4).unwrap(),0xabcd);
          observed.set_purpose(BusPurpose::Data); observed.write16(6,0x1234).unwrap(); }
        assert_eq!(events[0].cycle,100); assert_eq!(events[1].cycle,104);
        assert_eq!(events[0].purpose,BusPurpose::InstructionFetch); assert_eq!(events[1].purpose,BusPurpose::Data);
    }

    #[test]
    fn width_timing_policy_is_explicit_and_deterministic() {
        let mut bus=RamBus::new(16); let mut events=Vec::new();
        { let mut observed=ObservedBus::new(&mut bus,&mut |e| events.push(e),BusMaster::Cpu,40);
          observed.set_timing(BusTiming::Width { byte: 1, word: 2, long: 4 });
          observed.read8(0).unwrap(); observed.read16(2).unwrap(); observed.read32(4).unwrap(); }
        assert_eq!(events.iter().map(|e| e.cycle).collect::<Vec<_>>(),vec![40,41,43]);
    }

    #[test]
    fn masters_share_one_deterministic_clock() {
        let clock=BusClock::new(200); let mut bus=RamBus::new(16); let mut events=Vec::new();
        { let mut cpu=ObservedBus::with_clock(&mut bus,&mut |e| events.push(e),BusMaster::Cpu,&clock); cpu.read16(0).unwrap(); }
        { let mut copper=ObservedBus::with_clock(&mut bus,&mut |e| events.push(e),BusMaster::Copper,&clock); copper.read16(2).unwrap(); }
        assert_eq!(events[0].cycle,200); assert_eq!(events[0].master,BusMaster::Cpu);
        assert_eq!(events[1].cycle,201); assert_eq!(events[1].master,BusMaster::Copper);
        assert_eq!(clock.cycle(),202);
    }

    #[test]
    fn schedule_assigns_repeating_slot_ownership() {
        let schedule=BusSchedule::new(vec![BusMaster::Cpu,BusMaster::Copper,BusMaster::Cpu,BusMaster::Blitter]);
        assert_eq!(schedule.period(),4);
        assert_eq!(schedule.owner(0),Some(BusMaster::Cpu));
        assert_eq!(schedule.owner(1),Some(BusMaster::Copper));
        assert_eq!(schedule.owner(3),Some(BusMaster::Blitter));
        assert_eq!(schedule.owner(5),Some(BusMaster::Copper));
        assert_eq!(schedule.next_cycle_for(BusMaster::Blitter,4),Some(7));
        assert_eq!(schedule.next_cycle_for(BusMaster::Disk,0),None);
    }

    #[test]
    fn cpu_only_schedule_is_deterministic() {
        let schedule=BusSchedule::cpu_only();
        assert_eq!(schedule.owner(0),Some(BusMaster::Cpu));
        assert_eq!(schedule.owner(1_000_000),Some(BusMaster::Cpu));
        assert_eq!(schedule.next_cycle_for(BusMaster::Cpu,123),Some(123));
    }

    #[test]
    fn free_slots_are_available_to_dynamic_masters() {
        let schedule=BusSchedule::from_slots(vec![
            BusSlot::Reserved(BusMaster::Copper),
            BusSlot::Free,
            BusSlot::Reserved(BusMaster::Disk),
            BusSlot::Free,
        ]);
        assert_eq!(schedule.owner(1),None);
        assert!(schedule.available_to(BusMaster::Cpu,1));
        assert!(schedule.available_to(BusMaster::Blitter,1));
        assert!(!schedule.available_to(BusMaster::Cpu,2));
        assert_eq!(schedule.next_cycle_for(BusMaster::Cpu,0),Some(1));
        assert_eq!(schedule.next_cycle_for(BusMaster::Blitter,2),Some(3));
    }

    #[test]
    fn observed_bus_waits_for_owned_schedule_slot() {
        let clock=BusClock::new(0);
        let schedule=BusSchedule::new(vec![BusMaster::Copper,BusMaster::Cpu,BusMaster::Blitter,BusMaster::Cpu]);
        let mut bus=RamBus::new(16); let mut events=Vec::new();
        { let mut cpu=ObservedBus::with_clock(&mut bus,&mut |e| events.push(e),BusMaster::Cpu,&clock);
          cpu.set_schedule(&schedule);
          cpu.read16(0).unwrap();
          cpu.read16(2).unwrap(); }
        assert_eq!(events[0].cycle,1);
        assert_eq!(events[1].cycle,3);
        assert_eq!(clock.cycle(),4);
    }

    #[test]
    fn failed_write_preserves_attempted_value() {
        let mut bus=RamBus::new(4); let mut events=Vec::new();
        { let mut observed=ObservedBus::new(&mut bus,&mut |e| events.push(e),BusMaster::Blitter,91);
          assert_eq!(observed.write32(4,0xdead_beef),Err(BusError::Unmapped{address:4})); }
        assert_eq!(events[0].value,Some(0xdead_beef)); assert_eq!(events[0].fault,Some(BusFault::Unmapped));
    }
}
