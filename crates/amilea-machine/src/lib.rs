//! Integrated deterministic Amiga machine plumbing.
//!
//! This layer owns the CPU-visible bus topology and hardware signals.
//! It is intentionally small while chipset devices are still being added.

use amilea_bus::{
    AddressSpace, BusClock, BusEvent, BusMaster, BusSignal, ObservedBus, OverlayBus, RamBus, RasterGeometry, RasterPosition, Rom,
};
use amilea_cia::CiaA;
use amilea_chipset::{CustomChipHandle, CustomChips, InterruptSource, CUSTOM_BASE, CUSTOM_SIZE};
use amilea_m68k::{Cpu, CpuError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstructionRecord {
    pub pc:u32,
    pub opcode:u16,
    pub cycle_start:u64,
    pub cycle_end:u64,
    pub bus_event_start:usize,
    pub bus_event_end:usize,
}



#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimedEventKind { Interrupt(InterruptSource) }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedEvent { pub cycle:u64, pub kind:TimedEventKind }


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimedEventPhase { Scheduled, Dispatched }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedEventRecord {
    pub observed_cycle:u64,
    pub event:TimedEvent,
    pub phase:TimedEventPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptDisposition { Masked, Accepted }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptRecord {
    pub cycle:u64,
    pub pc:u32,
    pub level:u8,
    pub cpu_mask:u8,
    pub pending:u16,
    pub disposition:InterruptDisposition,
    pub vector:Option<u8>,
}

pub struct AmigaMachine {
    pub cpu: Cpu,
    bus: OverlayBus<AddressSpace, Rom>,
    overlay: BusSignal,
    clock: BusClock,
    trace: Vec<BusEvent>,
    instructions: Vec<InstructionRecord>,
    custom: CustomChipHandle,
    interrupts: Vec<InterruptRecord>,
    last_vblank_frame: Option<u64>,
    timed_events: Vec<TimedEvent>,
    timed_event_trace: Vec<TimedEventRecord>,
}

impl AmigaMachine {
    pub fn a500_with_rom(rom: Vec<u8>) -> Result<Self, amilea_bus::BusError> {
        let overlay=BusSignal::new(true);
        let clock=BusClock::new(0);
        let overlay_size=rom.len().min(0x080000) as u32;
        let mut base=AddressSpace::new();
        base.map(0x000000,0x080000,RamBus::new(0x080000))?;
        base.map(0xbfe000,0x300,CiaA::with_overlay_signal(overlay.clone()))?;
        let custom_device=CustomChips::with_clock(clock.clone());
        let custom=custom_device.handle();
        base.map(CUSTOM_BASE,CUSTOM_SIZE,custom_device)?;
        base.map(0xf80000,rom.len() as u32,Rom::new(0xf80000,rom.clone()))?;
        let overlay_rom=Rom::new(0,rom);
        Ok(Self {
            cpu:Cpu::default(),
            bus:OverlayBus::with_signal(base,overlay_rom,overlay_size,overlay.clone()),
            overlay,
            clock,
            trace:Vec::new(),
            instructions:Vec::new(),
            custom,
            interrupts:Vec::new(),
            last_vblank_frame:None,
            timed_events:Vec::new(),
            timed_event_trace:Vec::new(),
        })
    }

    pub fn reset(&mut self)->Result<(),CpuError> {
        let trace=&mut self.trace;
        let mut observer=|event:BusEvent| trace.push(event);
        let mut bus=ObservedBus::with_clock(&mut self.bus,&mut observer,BusMaster::Cpu,&self.clock);
        self.cpu.reset(&mut bus)
    }

    fn schedule_timed_event(&mut self,event:TimedEvent) {
        self.timed_event_trace.push(TimedEventRecord {
            observed_cycle:self.clock.cycle(), event, phase:TimedEventPhase::Scheduled,
        });
        let index=self.timed_events.partition_point(|queued|queued.cycle<=event.cycle);
        self.timed_events.insert(index,event);
    }

    fn produce_raster_events(&mut self) {
        let position=RasterGeometry::PAL_OCS.position(self.clock.cycle());
        if position.line==0 && self.last_vblank_frame!=Some(position.frame) {
            self.schedule_timed_event(TimedEvent {
                cycle:self.clock.cycle(),
                kind:TimedEventKind::Interrupt(InterruptSource::VerticalBlank),
            });
            self.last_vblank_frame=Some(position.frame);
        }
    }

    fn dispatch_timed_events(&mut self) {
        let now=self.clock.cycle();
        let ready=self.timed_events.partition_point(|event|event.cycle<=now);
        let events:Vec<_>=self.timed_events.drain(..ready).collect();
        for event in events {
            self.timed_event_trace.push(TimedEventRecord {
                observed_cycle:now, event, phase:TimedEventPhase::Dispatched,
            });
            match event.kind {
                TimedEventKind::Interrupt(source)=>self.custom.request_interrupt(source),
            }
        }
    }

    fn update_timed_events(&mut self) {
        self.produce_raster_events();
        self.dispatch_timed_events();
    }

    pub fn step(&mut self)->Result<u32,CpuError> {
        self.update_timed_events();
        let level=self.custom.interrupt_level();
        if level>0 {
            let cycle=self.clock.cycle();
            let pc=self.cpu.pc;
            let cpu_mask=self.cpu.interrupt_mask();
            let pending=self.custom.pending_interrupts();
            let trace=&mut self.trace;
            let mut observer=|event:BusEvent| trace.push(event);
            let mut bus=ObservedBus::with_clock(&mut self.bus,&mut observer,BusMaster::Cpu,&self.clock);
            let accepted=self.cpu.accept_interrupt(&mut bus,level)?;
            self.interrupts.push(InterruptRecord {
                cycle, pc, level, cpu_mask, pending,
                disposition:if accepted { InterruptDisposition::Accepted } else { InterruptDisposition::Masked },
                vector:accepted.then_some(24+level),
            });
            if accepted { return Ok(0); }
        }
        let pc=self.cpu.pc;
        let cycle_start=self.clock.cycle();
        let bus_event_start=self.trace.len();
        let trace=&mut self.trace;
        let mut observer=|event:BusEvent| trace.push(event);
        let mut bus=ObservedBus::with_clock(&mut self.bus,&mut observer,BusMaster::Cpu,&self.clock);
        let result=self.cpu.step(&mut bus);
        let bus_event_end=self.trace.len();
        if let Some(fetch)=self.trace.get(bus_event_start) {
            if fetch.address==pc && fetch.size==2 {
                if let Some(value)=fetch.value {
                    self.instructions.push(InstructionRecord {
                        pc,
                        opcode:value as u16,
                        cycle_start,
                        cycle_end:self.clock.cycle(),
                        bus_event_start,
                        bus_event_end,
                    });
                }
            }
        }
        result
    }
    pub fn overlay_enabled(&self)->bool { self.overlay.get() }
    pub fn cycle(&self)->u64 { self.clock.cycle() }
    pub fn interrupt_level(&self)->u8 { self.custom.interrupt_level() }
    pub fn bus_trace(&self)->&[BusEvent] { &self.trace }
    pub fn interrupt_trace(&self)->&[InterruptRecord] { &self.interrupts }
    pub fn pending_timed_events(&self)->&[TimedEvent] { &self.timed_events }
    pub fn timed_event_trace(&self)->&[TimedEventRecord] { &self.timed_event_trace }
    pub fn clear_bus_trace(&mut self) {
        self.trace.clear();
        self.instructions.clear();
        self.interrupts.clear();
        self.timed_event_trace.clear();
    }
    pub fn instruction_trace(&self)->&[InstructionRecord] { &self.instructions }
    pub fn instruction_for_bus_event(&self,index:usize)->Option<&InstructionRecord> {
        self.instructions.iter().rev().find(|record|index>=record.bus_event_start && index<record.bus_event_end)
    }
    pub fn bus_event_context(&self,index:usize)->Option<(&BusEvent,Option<&InstructionRecord>)> {
        self.trace.get(index).map(|event|(event,self.instruction_for_bus_event(index)))
    }
    pub fn raster_position(&self,cycle:u64)->RasterPosition { RasterGeometry::PAL_OCS.position(cycle) }
}

#[cfg(test)]
mod tests {
    use super::*;






    #[test]
    fn instruction_record_links_pc_opcode_cycles_and_bus_events() {
        let mut rom=vec![0u8;0x20];
        rom[0..4].copy_from_slice(&0x0008_0000u32.to_be_bytes());
        rom[4..8].copy_from_slice(&0x00f8_0008u32.to_be_bytes());
        rom[8..10].copy_from_slice(&0x4e71u16.to_be_bytes());
        let mut machine=AmigaMachine::a500_with_rom(rom).unwrap();
        machine.reset().unwrap();
        machine.step().unwrap();

        let record=machine.instruction_trace().last().unwrap();
        assert_eq!(record.pc,0x00f8_0008);
        assert_eq!(record.opcode,0x4e71);
        assert_eq!(record.cycle_start,2);
        assert_eq!(record.cycle_end,3);
        assert_eq!(record.bus_event_start,2);
        assert_eq!(record.bus_event_end,3);
        assert_eq!(machine.instruction_for_bus_event(2),Some(record));
    }

    #[test]
    fn trace_cycles_map_to_pal_raster_positions() {
        let rom=vec![0u8;8];
        let machine=AmigaMachine::a500_with_rom(rom).unwrap();
        let position=machine.raster_position(227*12+34);
        assert_eq!(position.line,12);
        assert_eq!(position.slot,34);
    }

    #[test]
    fn machine_retains_ordered_cpu_bus_trace() {
        let mut rom=vec![0u8;0x20];
        rom[0..4].copy_from_slice(&0x0008_0000u32.to_be_bytes());
        rom[4..8].copy_from_slice(&0x00f8_0008u32.to_be_bytes());
        rom[8..10].copy_from_slice(&0x4e71u16.to_be_bytes());
        let mut machine=AmigaMachine::a500_with_rom(rom).unwrap();
        machine.reset().unwrap();
        machine.step().unwrap();

        let trace=machine.bus_trace();
        assert_eq!(trace.len(),3);
        assert_eq!(trace[0].cycle,0);
        assert_eq!(trace[1].cycle,1);
        assert_eq!(trace[2].cycle,2);
        assert!(trace.iter().all(|event|event.master==BusMaster::Cpu));

        machine.clear_bus_trace();
        assert!(machine.bus_trace().is_empty());
        assert_eq!(machine.cycle(),3);
    }

    #[test]
    fn cpu_bus_transactions_advance_machine_clock() {
        let mut rom=vec![0u8;0x20];
        rom[0..4].copy_from_slice(&0x0008_0000u32.to_be_bytes());
        rom[4..8].copy_from_slice(&0x00f8_0008u32.to_be_bytes());
        rom[8..10].copy_from_slice(&0x4e71u16.to_be_bytes());
        let mut machine=AmigaMachine::a500_with_rom(rom).unwrap();
        assert_eq!(machine.cycle(),0);
        machine.reset().unwrap();
        assert_eq!(machine.cycle(),2);
        machine.step().unwrap();
        assert_eq!(machine.cycle(),3);
    }

    #[test]
    fn cpu_can_access_custom_chip_register_space() {
        let mut rom=vec![0u8;0x20];
        rom[0..4].copy_from_slice(&0x0008_0000u32.to_be_bytes());
        rom[4..8].copy_from_slice(&0x00f8_0008u32.to_be_bytes());
        // MOVE.W #$8200,$00DFF096 -- set DMA master bit in register state.
        rom[8..16].copy_from_slice(&[0x33,0xfc,0x82,0x00,0x00,0xdf,0xf0,0x96]);
        let mut machine=AmigaMachine::a500_with_rom(rom).unwrap();
        machine.reset().unwrap();
        machine.step().unwrap();
    }

    #[test]
    fn cpu_program_disables_overlay_through_cia_a() {
        let mut rom=vec![0u8;0x40];
        rom[0..4].copy_from_slice(&0x0008_0000u32.to_be_bytes());
        rom[4..8].copy_from_slice(&0x00f8_0008u32.to_be_bytes());

        // MOVE.B #$01,$00BFE201 -- make CIA-A PA0 an output.
        rom[8..16].copy_from_slice(&[0x13,0xfc,0x00,0x01,0x00,0xbf,0xe2,0x01]);
        // MOVE.B #$00,$00BFE001 -- drive OVL low.
        rom[16..24].copy_from_slice(&[0x13,0xfc,0x00,0x00,0x00,0xbf,0xe0,0x01]);

        let mut machine=AmigaMachine::a500_with_rom(rom).unwrap();
        machine.reset().unwrap();
        assert!(machine.overlay_enabled());

        machine.step().unwrap();
        assert!(machine.overlay_enabled());
        machine.step().unwrap();
        assert!(!machine.overlay_enabled());
    }

    #[test]
    fn machine_resets_from_rom_overlay() {
        let mut rom=vec![0u8;0x20];
        rom[0..4].copy_from_slice(&0x0008_0000u32.to_be_bytes());
        rom[4..8].copy_from_slice(&0x00f8_0008u32.to_be_bytes());
        rom[8..10].copy_from_slice(&0x4e71u16.to_be_bytes());
        let mut machine=AmigaMachine::a500_with_rom(rom).unwrap();
        machine.reset().unwrap();
        assert_eq!(machine.cpu.pc,0x00f8_0008);
        assert!(machine.overlay_enabled());
        assert_eq!(machine.step().unwrap(),4);
    }
}
