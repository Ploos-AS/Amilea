//! Deterministic queries over Amilea bus traces.

use amilea_bus::{BusAccess, BusEvent, BusMaster};


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterAccess { ReadOnly, WriteOnly, ReadWrite }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterInfo {
    pub address:u32,
    pub device:&'static str,
    pub name:&'static str,
    pub access:RegisterAccess,
}

const REGISTERS:&[RegisterInfo]=&[
    RegisterInfo { address:0x00df_f002, device:"OCS", name:"DMACONR", access:RegisterAccess::ReadOnly },
    RegisterInfo { address:0x00df_f004, device:"OCS", name:"VPOSR", access:RegisterAccess::ReadOnly },
    RegisterInfo { address:0x00df_f006, device:"OCS", name:"VHPOSR", access:RegisterAccess::ReadOnly },
    RegisterInfo { address:0x00df_f096, device:"OCS", name:"DMACON", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00bf_e001, device:"CIA-A", name:"PRA", access:RegisterAccess::ReadWrite },
    RegisterInfo { address:0x00bf_e201, device:"CIA-A", name:"DDRA", access:RegisterAccess::ReadWrite },
];

pub fn register_info(address:u32)->Option<&'static RegisterInfo> {
    REGISTERS.iter().find(|register|register.address==address)
}

pub fn register_name(address:u32)->Option<&'static str> {
    register_info(address).map(|register|register.name)
}


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



#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetClearOperation { Clear, Set }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRegisterValue {
    pub operation:Option<SetClearOperation>,
    pub fields:Vec<&'static str>,
}

const DMACON_BITS:&[(u16,&str)]=&[
    (0x4000,"BBUSY"),
    (0x2000,"BZERO"),
    (0x1000,"BLTPRI"),
    (0x0400,"DMAEN"),
    (0x0200,"BPLEN"),
    (0x0100,"COPEN"),
    (0x0080,"BLTEN"),
    (0x0040,"SPREN"),
    (0x0020,"DSKEN"),
    (0x0010,"AUD3EN"),
    (0x0008,"AUD2EN"),
    (0x0004,"AUD1EN"),
    (0x0002,"AUD0EN"),
    (0x0001,"DSKSYNC"),
];

pub fn decode_register_value(register:&RegisterInfo,value:u32)->DecodedRegisterValue {
    if register.name=="DMACON" || register.name=="DMACONR" {
        let word=value as u16;
        let operation=(register.name=="DMACON").then_some(
            if word & 0x8000 != 0 { SetClearOperation::Set } else { SetClearOperation::Clear }
        );
        let fields=DMACON_BITS.iter()
            .filter_map(|(mask,name)|(word & mask != 0).then_some(*name))
            .collect();
        DecodedRegisterValue { operation, fields }
    } else {
        DecodedRegisterValue { operation:None, fields:Vec::new() }
    }
}


#[derive(Debug, Clone, Copy)]
pub struct ExplainedBusEvent<'a> {
    pub event:&'a BusEvent,
    pub register:Option<&'static RegisterInfo>,
}

pub fn explain_event(event:&BusEvent)->ExplainedBusEvent<'_> {
    ExplainedBusEvent { event, register:register_info(event.address) }
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
    fn decodes_dmacon_set_clear_and_dma_bits() {
        let register=register_info(0x00df_f096).unwrap();
        let decoded=decode_register_value(register,0x8700);
        assert_eq!(decoded.operation,Some(SetClearOperation::Set));
        assert_eq!(decoded.fields,vec!["DMAEN","BPLEN","COPEN"]);

        let decoded=decode_register_value(register,0x0200);
        assert_eq!(decoded.operation,Some(SetClearOperation::Clear));
        assert_eq!(decoded.fields,vec!["BPLEN"]);
    }

    #[test]
    fn explains_register_access_without_changing_raw_event() {
        let event=event(12,BusAccess::Write,0x00df_f096);
        let explained=explain_event(&event);
        assert_eq!(explained.event.cycle,12);
        assert_eq!(explained.register.unwrap().name,"DMACON");
    }

    #[test]
    fn resolves_known_amiga_registers() {
        let dmacon=register_info(0x00df_f096).unwrap();
        assert_eq!(dmacon.device,"OCS");
        assert_eq!(dmacon.name,"DMACON");
        assert_eq!(dmacon.access,RegisterAccess::WriteOnly);

        let cia=register_info(0x00bf_e001).unwrap();
        assert_eq!(cia.device,"CIA-A");
        assert_eq!(cia.name,"PRA");
        assert!(register_info(0x0012_3456).is_none());
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
