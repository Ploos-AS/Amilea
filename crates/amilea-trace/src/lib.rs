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
    RegisterInfo { address:0x00df_f01c, device:"OCS", name:"INTENAR", access:RegisterAccess::ReadOnly },
    RegisterInfo { address:0x00df_f01e, device:"OCS", name:"INTREQR", access:RegisterAccess::ReadOnly },
    RegisterInfo { address:0x00df_f004, device:"OCS", name:"VPOSR", access:RegisterAccess::ReadOnly },
    RegisterInfo { address:0x00df_f006, device:"OCS", name:"VHPOSR", access:RegisterAccess::ReadOnly },
    RegisterInfo { address:0x00dff040, device:"OCS", name:"BLTCON0", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff042, device:"OCS", name:"BLTCON1", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff044, device:"OCS", name:"BLTAFWM", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff046, device:"OCS", name:"BLTALWM", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff048, device:"OCS", name:"BLTCPTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff04a, device:"OCS", name:"BLTCPTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff04c, device:"OCS", name:"BLTBPTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff04e, device:"OCS", name:"BLTBPTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff050, device:"OCS", name:"BLTAPTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff052, device:"OCS", name:"BLTAPTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff054, device:"OCS", name:"BLTDPTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff056, device:"OCS", name:"BLTDPTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff058, device:"OCS", name:"BLTSIZE", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff060, device:"OCS", name:"BLTCMOD", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff062, device:"OCS", name:"BLTBMOD", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff064, device:"OCS", name:"BLTAMOD", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff066, device:"OCS", name:"BLTDMOD", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff080, device:"OCS", name:"COP1LCH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff082, device:"OCS", name:"COP1LCL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff084, device:"OCS", name:"COP2LCH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff086, device:"OCS", name:"COP2LCL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff088, device:"OCS", name:"COPJMP1", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff08a, device:"OCS", name:"COPJMP2", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff08e, device:"OCS", name:"DIWSTRT", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff090, device:"OCS", name:"DIWSTOP", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff092, device:"OCS", name:"DDFSTRT", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff094, device:"OCS", name:"DDFSTOP", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff0e0, device:"OCS", name:"BPL1PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff0e2, device:"OCS", name:"BPL1PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff0e4, device:"OCS", name:"BPL2PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff0e6, device:"OCS", name:"BPL2PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff0e8, device:"OCS", name:"BPL3PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff0ea, device:"OCS", name:"BPL3PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff0ec, device:"OCS", name:"BPL4PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff0ee, device:"OCS", name:"BPL4PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff0f0, device:"OCS", name:"BPL5PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff0f2, device:"OCS", name:"BPL5PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff0f4, device:"OCS", name:"BPL6PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff0f6, device:"OCS", name:"BPL6PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff100, device:"OCS", name:"BPLCON0", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff102, device:"OCS", name:"BPLCON1", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff104, device:"OCS", name:"BPLCON2", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff108, device:"OCS", name:"BPL1MOD", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff10a, device:"OCS", name:"BPL2MOD", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff120, device:"OCS", name:"SPR0PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff122, device:"OCS", name:"SPR0PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff124, device:"OCS", name:"SPR1PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff126, device:"OCS", name:"SPR1PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff128, device:"OCS", name:"SPR2PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff12a, device:"OCS", name:"SPR2PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff12c, device:"OCS", name:"SPR3PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff12e, device:"OCS", name:"SPR3PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff130, device:"OCS", name:"SPR4PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff132, device:"OCS", name:"SPR4PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff134, device:"OCS", name:"SPR5PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff136, device:"OCS", name:"SPR5PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff138, device:"OCS", name:"SPR6PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff13a, device:"OCS", name:"SPR6PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff13c, device:"OCS", name:"SPR7PTH", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff13e, device:"OCS", name:"SPR7PTL", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff180, device:"OCS", name:"COLOR00", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff182, device:"OCS", name:"COLOR01", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff184, device:"OCS", name:"COLOR02", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff186, device:"OCS", name:"COLOR03", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff188, device:"OCS", name:"COLOR04", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff18a, device:"OCS", name:"COLOR05", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff18c, device:"OCS", name:"COLOR06", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff18e, device:"OCS", name:"COLOR07", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff190, device:"OCS", name:"COLOR08", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff192, device:"OCS", name:"COLOR09", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff194, device:"OCS", name:"COLOR10", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff196, device:"OCS", name:"COLOR11", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff198, device:"OCS", name:"COLOR12", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff19a, device:"OCS", name:"COLOR13", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff19c, device:"OCS", name:"COLOR14", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff19e, device:"OCS", name:"COLOR15", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1a0, device:"OCS", name:"COLOR16", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1a2, device:"OCS", name:"COLOR17", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1a4, device:"OCS", name:"COLOR18", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1a6, device:"OCS", name:"COLOR19", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1a8, device:"OCS", name:"COLOR20", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1aa, device:"OCS", name:"COLOR21", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1ac, device:"OCS", name:"COLOR22", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1ae, device:"OCS", name:"COLOR23", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1b0, device:"OCS", name:"COLOR24", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1b2, device:"OCS", name:"COLOR25", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1b4, device:"OCS", name:"COLOR26", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1b6, device:"OCS", name:"COLOR27", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1b8, device:"OCS", name:"COLOR28", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1ba, device:"OCS", name:"COLOR29", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1bc, device:"OCS", name:"COLOR30", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00dff1be, device:"OCS", name:"COLOR31", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00df_f096, device:"OCS", name:"DMACON", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00df_f09a, device:"OCS", name:"INTENA", access:RegisterAccess::WriteOnly },
    RegisterInfo { address:0x00df_f09c, device:"OCS", name:"INTREQ", access:RegisterAccess::WriteOnly },
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
    (0x0400,"BLTPRI"),
    (0x0200,"DMAEN"),
    (0x0100,"BPLEN"),
    (0x0080,"COPEN"),
    (0x0040,"BLTEN"),
    (0x0020,"SPREN"),
    (0x0010,"DSKEN"),
    (0x0008,"AUD3EN"),
    (0x0004,"AUD2EN"),
    (0x0002,"AUD1EN"),
    (0x0001,"AUD0EN"),
];


const INTERRUPT_BITS:&[(u16,&str)]=&[
    (0x4000,"INTEN"),
    (0x2000,"EXTER"),
    (0x1000,"DSKSYN"),
    (0x0800,"RBF"),
    (0x0400,"AUD3"),
    (0x0200,"AUD2"),
    (0x0100,"AUD1"),
    (0x0080,"AUD0"),
    (0x0040,"BLIT"),
    (0x0020,"VERTB"),
    (0x0010,"COPER"),
    (0x0008,"PORTS"),
    (0x0004,"SOFT"),
    (0x0002,"DSKBLK"),
    (0x0001,"TBE"),
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
    } else if matches!(register.name,"INTENA"|"INTENAR"|"INTREQ"|"INTREQR") {
        let word=value as u16;
        let operation=matches!(register.name,"INTENA"|"INTREQ").then_some(
            if word & 0x8000 != 0 { SetClearOperation::Set } else { SetClearOperation::Clear }
        );
        let fields=INTERRUPT_BITS.iter()
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
    fn decodes_interrupt_enable_and_request_bits() {
        let intena=register_info(0x00df_f09a).unwrap();
        let decoded=decode_register_value(intena,0xc060);
        assert_eq!(decoded.operation,Some(SetClearOperation::Set));
        assert_eq!(decoded.fields,vec!["INTEN","BLIT","VERTB"]);

        let intreq=register_info(0x00df_f09c).unwrap();
        let decoded=decode_register_value(intreq,0x0010);
        assert_eq!(decoded.operation,Some(SetClearOperation::Clear));
        assert_eq!(decoded.fields,vec!["COPER"]);

        assert_eq!(register_name(0x00df_f01c),Some("INTENAR"));
        assert_eq!(register_name(0x00df_f01e),Some("INTREQR"));
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
