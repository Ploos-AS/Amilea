//! Deterministic queries over Amilea bus traces.

use amilea_bus::{BusAccess, BusEvent, BusMaster};

#[derive(Debug, Clone, Default)]
pub struct BusQuery {
    pub cycle_start: Option<u64>,
    pub cycle_end: Option<u64>,
    pub master: Option<BusMaster>,
    pub access: Option<BusAccess>,
    pub address_start: Option<u32>,
    pub address_end: Option<u32>,
}

impl BusQuery {
    pub fn writes_to(address:u32)->Self {
        Self {
            access:Some(BusAccess::Write),
            address_start:Some(address),
            address_end:Some(address),
            ..Self::default()
        }
    }

    pub fn address_range(start:u32,end:u32)->Self {
        Self { address_start:Some(start), address_end:Some(end), ..Self::default() }
    }

    pub fn matches(&self,event:&BusEvent)->bool {
        self.cycle_start.map_or(true,|v|event.cycle>=v)
            && self.cycle_end.map_or(true,|v|event.cycle<=v)
            && self.master.map_or(true,|v|event.master==v)
            && self.access.map_or(true,|v|event.access==v)
            && self.address_start.map_or(true,|v|event.address>=v)
            && self.address_end.map_or(true,|v|event.address<=v)
    }

    pub fn collect<'a>(&self,events:&'a [BusEvent])->Vec<&'a BusEvent> {
        events.iter().filter(|event|self.matches(event)).collect()
    }
}

pub fn last_write(events:&[BusEvent],address:u32)->Option<&BusEvent> {
    events.iter().rev().find(|event| {
        event.access==BusAccess::Write
            && event.address<=address
            && address<event.address.saturating_add(u32::from(event.size))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use amilea_bus::{BusPurpose};

    fn event(cycle:u64,access:BusAccess,address:u32)->BusEvent {
        BusEvent {
            cycle, master:BusMaster::Cpu, purpose:BusPurpose::Data,
            access,address,size:1,value:Some(0x42),fault:None,
        }
    }

    #[test]
    fn filters_custom_chip_writes_in_cycle_window() {
        let events=[
            event(4,BusAccess::Read,0xdff004),
            event(5,BusAccess::Write,0xdff096),
            event(9,BusAccess::Write,0xbfe001),
        ];
        let query=BusQuery {
            cycle_start:Some(5), cycle_end:Some(8),
            access:Some(BusAccess::Write),
            address_start:Some(0xdff000), address_end:Some(0xdff1ff),
            ..BusQuery::default()
        };
        let result=query.collect(&events);
        assert_eq!(result.len(),1);
        assert_eq!(result[0].address,0xdff096);
    }

    #[test]
    fn finds_last_writer_covering_address() {
        let mut wide=event(7,BusAccess::Write,0x1000);
        wide.size=4;
        let events=[event(3,BusAccess::Write,0x1002),wide];
        assert_eq!(last_write(&events,0x1002).unwrap().cycle,7);
        assert!(last_write(&events,0x2000).is_none());
    }
}
