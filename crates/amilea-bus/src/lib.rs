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
pub enum SlotClass {
    Dynamic,
    Refresh,
    Disk,
    Audio(u8),
    Sprite(u8),
    Bitplane,
    Copper,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassifiedSlot {
    pub slot: BusSlot,
    pub class: SlotClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusSlot {
    Free,
    Reserved(BusMaster),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArbitrationPolicy {
    priority: Vec<BusMaster>,
}

impl ArbitrationPolicy {
    pub fn new(priority: Vec<BusMaster>) -> Self { Self { priority } }

    pub fn cpu_first() -> Self { Self::new(vec![BusMaster::Cpu, BusMaster::Blitter]) }

    pub fn blitter_first() -> Self { Self::new(vec![BusMaster::Blitter, BusMaster::Cpu]) }

    pub fn winner(&self, requesters: &[BusMaster]) -> Option<BusMaster> {
        self.priority.iter().copied().find(|master| requesters.contains(master))
            .or_else(|| requesters.first().copied())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusArbiter {
    pending: Vec<BusMaster>,
    policy: ArbitrationPolicy,
}

impl BusArbiter {
    pub fn new(policy: ArbitrationPolicy) -> Self { Self { pending: Vec::new(), policy } }

    pub fn request(&mut self, master: BusMaster) {
        if !self.pending.contains(&master) { self.pending.push(master); }
    }

    pub fn cancel(&mut self, master: BusMaster) {
        self.pending.retain(|pending| *pending != master);
    }

    pub fn is_pending(&self, master: BusMaster) -> bool { self.pending.contains(&master) }

    pub fn grant(&mut self, schedule: &BusSchedule, cycle: u64) -> Option<BusMaster> {
        let winner=schedule.grant(cycle,&self.pending,&self.policy)?;
        self.cancel(winner);
        Some(winner)
    }

    pub fn pending(&self) -> &[BusMaster] { &self.pending }

    pub fn grant_next(&mut self, schedule: &BusSchedule, clock: &BusClock) -> Option<BusMaster> {
        if self.pending.is_empty() { return None; }
        let start=clock.cycle();
        for offset in 0..schedule.period() as u64 {
            let cycle=start.wrapping_add(offset);
            if let Some(winner)=self.grant(schedule,cycle) {
                clock.set(cycle);
                return Some(winner);
            }
        }
        None
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScheduleBuildError {
    #[error("slot {slot} is outside scanline")]
    OutOfRange { slot: u16 },
    #[error("slot {slot} is already reserved")]
    Overlap { slot: u16 },
    #[error("invalid slot range {start}..={end}")]
    InvalidRange { start: u16, end: u16 },
}

pub struct PalOcsScheduleBuilder {
    slots: Vec<BusSlot>,
}

impl PalOcsScheduleBuilder {
    pub fn new() -> Self {
        Self { slots: vec![BusSlot::Free; RasterGeometry::PAL_OCS.slots_per_line as usize] }
    }

    pub fn reserve(&mut self, slot: u16, master: BusMaster) -> Result<&mut Self, ScheduleBuildError> {
        let entry=self.slots.get_mut(slot as usize).ok_or(ScheduleBuildError::OutOfRange { slot })?;
        if !matches!(entry, BusSlot::Free) { return Err(ScheduleBuildError::Overlap { slot }); }
        *entry=BusSlot::Reserved(master);
        Ok(self)
    }

    pub fn reserve_range(&mut self, start: u16, end: u16, master: BusMaster) -> Result<&mut Self, ScheduleBuildError> {
        if start > end { return Err(ScheduleBuildError::InvalidRange { start, end }); }
        for slot in start..=end {
            if slot as usize >= self.slots.len() { return Err(ScheduleBuildError::OutOfRange { slot }); }
            if !matches!(self.slots[slot as usize], BusSlot::Free) { return Err(ScheduleBuildError::Overlap { slot }); }
        }
        for slot in start..=end { self.slots[slot as usize]=BusSlot::Reserved(master); }
        Ok(self)
    }

    pub fn build(self) -> BusSchedule { BusSchedule::from_slots(self.slots) }
}

impl Default for PalOcsScheduleBuilder {
    fn default() -> Self { Self::new() }
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

    pub fn classified_slot(&self, cycle: u64) -> ClassifiedSlot {
        let slot=self.slot(cycle);
        let class=match slot {
            BusSlot::Free => SlotClass::Dynamic,
            BusSlot::Reserved(BusMaster::Refresh) => SlotClass::Refresh,
            BusSlot::Reserved(BusMaster::Disk) => SlotClass::Disk,
            BusSlot::Reserved(BusMaster::Audio(channel)) => SlotClass::Audio(channel),
            BusSlot::Reserved(BusMaster::Sprite(sprite)) => SlotClass::Sprite(sprite),
            BusSlot::Reserved(BusMaster::Bitplane) => SlotClass::Bitplane,
            BusSlot::Reserved(BusMaster::Copper) => SlotClass::Copper,
            BusSlot::Reserved(BusMaster::Other(id)) => SlotClass::Other(id),
            BusSlot::Reserved(_) => SlotClass::Dynamic,
        };
        ClassifiedSlot { slot, class }
    }

    pub fn owner(&self, cycle: u64) -> Option<BusMaster> {
        match self.slot(cycle) { BusSlot::Free => None, BusSlot::Reserved(master) => Some(master) }
    }

    pub fn available_to(&self, master: BusMaster, cycle: u64) -> bool {
        matches!(self.slot(cycle), BusSlot::Free | BusSlot::Reserved(m) if m == master)
    }

    pub fn grant(&self, cycle: u64, requesters: &[BusMaster], policy: &ArbitrationPolicy) -> Option<BusMaster> {
        match self.slot(cycle) {
            BusSlot::Reserved(master) => requesters.contains(&master).then_some(master),
            BusSlot::Free => policy.winner(requesters),
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RasterGeometry {
    pub lines_per_frame: u16,
    pub slots_per_line: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RasterPosition {
    pub frame: u64,
    pub line: u16,
    pub slot: u16,
}

impl std::fmt::Display for RasterPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "F{} L{} S{}", self.frame, self.line, self.slot)
    }
}

impl RasterGeometry {
    pub const PAL_OCS: Self = Self { lines_per_frame: 312, slots_per_line: 227 };

    pub const fn slots_per_frame(self) -> u64 {
        self.lines_per_frame as u64 * self.slots_per_line as u64
    }

    pub const fn position(self, cycle: u64) -> RasterPosition {
        let per_frame=self.slots_per_frame();
        let within=cycle % per_frame;
        RasterPosition {
            frame: cycle / per_frame,
            line: (within / self.slots_per_line as u64) as u16,
            slot: (within % self.slots_per_line as u64) as u16,
        }
    }

    pub const fn cycle(self, position: RasterPosition) -> u64 {
        position.frame * self.slots_per_frame()
            + position.line as u64 * self.slots_per_line as u64
            + position.slot as u64
    }
}

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

impl BusEvent {
    pub const fn raster_position(&self, geometry: RasterGeometry) -> RasterPosition {
        geometry.position(self.cycle)
    }
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
pub struct Rom {
    base: u32,
    bytes: Vec<u8>,
}

impl Rom {
    pub fn new(base:u32,bytes:Vec<u8>)->Self { Self { base:mask(base), bytes } }
    pub fn base(&self)->u32 { self.base }
    pub fn len(&self)->usize { self.bytes.len() }
    pub fn is_empty(&self)->bool { self.bytes.is_empty() }
}

impl Bus for Rom {
    fn read8(&mut self,address:u32)->Result<u8,BusError> {
        let address=mask(address);
        let offset=address.wrapping_sub(self.base) as usize;
        self.bytes.get(offset).copied().ok_or(BusError::Unmapped{address})
    }

    fn write8(&mut self,address:u32,_value:u8)->Result<(),BusError> {
        Err(BusError::Unmapped{address:mask(address)})
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

pub struct BusRegion { start:u32, end:u32, bus:Box<dyn Bus> }
pub struct AddressSpace { regions:Vec<BusRegion> }
impl AddressSpace {
    pub fn new()->Self { Self{regions:Vec::new()} }
    pub fn map<B:Bus+'static>(&mut self,start:u32,size:u32,bus:B)->Result<(),BusError> {
        let start=mask(start);
        if size==0{return Err(BusError::Unmapped{address:start});}
        let end=start.checked_add(size-1).filter(|end|*end<=ADDRESS_MASK).ok_or(BusError::Unmapped{address:start})?;
        if self.regions.iter().any(|r|start<=r.end&&end>=r.start){return Err(BusError::Unmapped{address:start});}
        self.regions.push(BusRegion{start,end,bus:Box::new(bus)});
        self.regions.sort_by_key(|r|r.start);
        Ok(())
    }
    fn region_mut(&mut self,address:u32)->Result<&mut BusRegion,BusError>{
        let address=mask(address);
        self.regions.iter_mut().find(|r|address>=r.start&&address<=r.end).ok_or(BusError::Unmapped{address})
    }
}
impl Default for AddressSpace{fn default()->Self{Self::new()}}
impl Bus for AddressSpace{
    fn read8(&mut self,address:u32)->Result<u8,BusError>{let address=mask(address);self.region_mut(address)?.bus.read8(address)}
    fn write8(&mut self,address:u32,value:u8)->Result<(),BusError>{let address=mask(address);self.region_mut(address)?.bus.write8(address,value)}
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
    fn rom_is_read_only_and_mapped_at_explicit_base() {
        let mut rom=Rom::new(0xf80000,vec![0x11,0x22,0x33,0x44]);
        assert_eq!(rom.base(),0xf80000);
        assert_eq!(rom.len(),4);
        assert_eq!(rom.read16(0xf80000).unwrap(),0x1122);
        assert_eq!(rom.read16(0xf80002).unwrap(),0x3344);
        assert_eq!(rom.read8(0xf7ffff),Err(BusError::Unmapped{address:0xf7ffff}));
        assert_eq!(rom.write8(0xf80000,0xaa),Err(BusError::Unmapped{address:0xf80000}));
        assert_eq!(rom.read8(0xf80000).unwrap(),0x11);
    }

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
    fn arbitration_policy_resolves_free_slot_contention() {
        let schedule=BusSchedule::free();
        let requesters=[BusMaster::Cpu,BusMaster::Blitter];
        assert_eq!(schedule.grant(0,&requesters,&ArbitrationPolicy::cpu_first()),Some(BusMaster::Cpu));
        assert_eq!(schedule.grant(0,&requesters,&ArbitrationPolicy::blitter_first()),Some(BusMaster::Blitter));
    }

    #[test]
    fn reserved_slot_ignores_dynamic_priority() {
        let schedule=BusSchedule::new(vec![BusMaster::Disk]);
        let requesters=[BusMaster::Cpu,BusMaster::Blitter,BusMaster::Disk];
        assert_eq!(schedule.grant(0,&requesters,&ArbitrationPolicy::blitter_first()),Some(BusMaster::Disk));
        assert_eq!(schedule.grant(0,&[BusMaster::Cpu,BusMaster::Blitter],&ArbitrationPolicy::blitter_first()),None);
    }

    #[test]
    fn arbiter_keeps_losers_pending_until_later_slot() {
        let schedule=BusSchedule::free();
        let mut arbiter=BusArbiter::new(ArbitrationPolicy::blitter_first());
        arbiter.request(BusMaster::Cpu);
        arbiter.request(BusMaster::Blitter);
        arbiter.request(BusMaster::Cpu);
        assert_eq!(arbiter.pending().len(),2);
        assert_eq!(arbiter.grant(&schedule,0),Some(BusMaster::Blitter));
        assert!(arbiter.is_pending(BusMaster::Cpu));
        assert!(!arbiter.is_pending(BusMaster::Blitter));
        assert_eq!(arbiter.grant(&schedule,1),Some(BusMaster::Cpu));
        assert!(arbiter.pending().is_empty());
    }

    #[test]
    fn arbiter_waits_through_reserved_slot_for_other_master() {
        let schedule=BusSchedule::from_slots(vec![BusSlot::Reserved(BusMaster::Disk),BusSlot::Free]);
        let mut arbiter=BusArbiter::new(ArbitrationPolicy::cpu_first());
        arbiter.request(BusMaster::Cpu);
        assert_eq!(arbiter.grant(&schedule,0),None);
        assert!(arbiter.is_pending(BusMaster::Cpu));
        assert_eq!(arbiter.grant(&schedule,1),Some(BusMaster::Cpu));
    }

    #[test]
    fn arbiter_grant_next_advances_clock_to_first_grantable_slot() {
        let schedule=BusSchedule::from_slots(vec![
            BusSlot::Reserved(BusMaster::Disk),
            BusSlot::Reserved(BusMaster::Copper),
            BusSlot::Free,
            BusSlot::Reserved(BusMaster::Blitter),
        ]);
        let clock=BusClock::new(4);
        let mut arbiter=BusArbiter::new(ArbitrationPolicy::cpu_first());
        arbiter.request(BusMaster::Cpu);
        assert_eq!(arbiter.grant_next(&schedule,&clock),Some(BusMaster::Cpu));
        assert_eq!(clock.cycle(),6);
        assert!(arbiter.pending().is_empty());
    }

    #[test]
    fn arbiter_grant_next_does_not_move_clock_without_possible_grant() {
        let schedule=BusSchedule::new(vec![BusMaster::Disk,BusMaster::Copper]);
        let clock=BusClock::new(10);
        let mut arbiter=BusArbiter::new(ArbitrationPolicy::cpu_first());
        arbiter.request(BusMaster::Cpu);
        assert_eq!(arbiter.grant_next(&schedule,&clock),None);
        assert_eq!(clock.cycle(),10);
        assert!(arbiter.is_pending(BusMaster::Cpu));
    }

    #[test]
    fn pal_raster_geometry_maps_global_cycle_deterministically() {
        let geometry=RasterGeometry::PAL_OCS;
        assert_eq!(geometry.slots_per_frame(),70_824);
        assert_eq!(geometry.position(0),RasterPosition{frame:0,line:0,slot:0});
        assert_eq!(geometry.position(226),RasterPosition{frame:0,line:0,slot:226});
        assert_eq!(geometry.position(227),RasterPosition{frame:0,line:1,slot:0});
        assert_eq!(geometry.position(70_823),RasterPosition{frame:0,line:311,slot:226});
        assert_eq!(geometry.position(70_824),RasterPosition{frame:1,line:0,slot:0});
    }

    #[test]
    fn pal_raster_position_round_trips_to_cycle() {
        let geometry=RasterGeometry::PAL_OCS;
        let position=RasterPosition{frame:12,line:123,slot:45};
        assert_eq!(geometry.position(geometry.cycle(position)),position);
    }

    #[test]
    fn bus_event_derives_pal_raster_position_without_storing_it() {
        let event=BusEvent {
            cycle: 70_824 + 227 * 12 + 34,
            master:BusMaster::Copper,
            purpose:BusPurpose::Data,
            access:BusAccess::Read,
            address:0xdff080,
            size:2,
            value:Some(0x1234),
            fault:None,
        };
        let position=event.raster_position(RasterGeometry::PAL_OCS);
        assert_eq!(position,RasterPosition{frame:1,line:12,slot:34});
        assert_eq!(position.to_string(),"F1 L12 S34");
    }

    #[test]
    fn schedule_classifies_slots_without_changing_ownership() {
        let schedule=BusSchedule::from_slots(vec![
            BusSlot::Reserved(BusMaster::Refresh),
            BusSlot::Reserved(BusMaster::Audio(2)),
            BusSlot::Reserved(BusMaster::Sprite(5)),
            BusSlot::Reserved(BusMaster::Bitplane),
            BusSlot::Reserved(BusMaster::Copper),
            BusSlot::Free,
        ]);
        assert_eq!(schedule.classified_slot(0).class,SlotClass::Refresh);
        assert_eq!(schedule.classified_slot(1).class,SlotClass::Audio(2));
        assert_eq!(schedule.classified_slot(2).class,SlotClass::Sprite(5));
        assert_eq!(schedule.classified_slot(3).class,SlotClass::Bitplane);
        assert_eq!(schedule.classified_slot(4).class,SlotClass::Copper);
        assert_eq!(schedule.classified_slot(5).class,SlotClass::Dynamic);
        assert_eq!(schedule.owner(5),None);
    }

    #[test]
    fn pal_ocs_builder_starts_with_one_dynamic_scanline() {
        let schedule=PalOcsScheduleBuilder::new().build();
        assert_eq!(schedule.period(),227);
        assert_eq!(schedule.owner(0),None);
        assert_eq!(schedule.owner(226),None);
        assert_eq!(schedule.classified_slot(100).class,SlotClass::Dynamic);
    }

    #[test]
    fn pal_ocs_builder_reserves_ranges_and_rejects_overlap() {
        let mut builder=PalOcsScheduleBuilder::new();
        builder.reserve(3,BusMaster::Refresh).unwrap();
        builder.reserve_range(10,13,BusMaster::Disk).unwrap();
        assert_eq!(builder.reserve(12,BusMaster::Copper),Err(ScheduleBuildError::Overlap{slot:12}));
        let schedule=builder.build();
        assert_eq!(schedule.owner(3),Some(BusMaster::Refresh));
        assert_eq!(schedule.classified_slot(11).class,SlotClass::Disk);
        assert_eq!(schedule.owner(14),None);
    }

    #[test]
    fn pal_ocs_builder_rejects_invalid_or_out_of_range_reservations() {
        let mut builder=PalOcsScheduleBuilder::new();
        assert_eq!(builder.reserve(227,BusMaster::Cpu),Err(ScheduleBuildError::OutOfRange{slot:227}));
        assert_eq!(builder.reserve_range(20,19,BusMaster::Disk),Err(ScheduleBuildError::InvalidRange{start:20,end:19}));
        assert_eq!(builder.reserve_range(225,227,BusMaster::Disk),Err(ScheduleBuildError::OutOfRange{slot:227}));
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
