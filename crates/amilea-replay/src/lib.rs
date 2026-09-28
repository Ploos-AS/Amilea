//! Record/replay primitives for deterministic Amilea executions.

use amilea_core::{Amilea, InputEvent, Snapshot};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimedInput {
    pub cycle: u64,
    pub event: InputEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replay {
    pub version: u32,
    pub initial: Snapshot,
    pub inputs: Vec<TimedInput>,
    pub end_cycle: u64,
}

impl Replay {
    pub const FORMAT_VERSION: u32 = 1;

    pub fn play(&self, machine: &mut Amilea) {
        machine.restore(&self.initial);
        let mut cursor = machine.cycle();
        for input in &self.inputs {
            assert!(input.cycle >= cursor, "replay events must be monotonic");
            machine.run_cycles(input.cycle - cursor);
            machine.inject(input.event.clone());
            cursor = input.cycle;
        }
        assert!(self.end_cycle >= cursor, "end cycle precedes replay input");
        machine.run_cycles(self.end_cycle - cursor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amilea_core::MachineConfig;

    #[test]
    fn replay_is_repeatable() {
        let seed = Amilea::new(MachineConfig::default());
        let replay = Replay {
            version: Replay::FORMAT_VERSION,
            initial: seed.snapshot(),
            inputs: vec![
                TimedInput {
                    cycle: 100,
                    event: InputEvent::SerialRx(42),
                },
                TimedInput {
                    cycle: 250,
                    event: InputEvent::Key {
                        code: 1,
                        pressed: true,
                    },
                },
            ],
            end_cycle: 1_000,
        };

        let mut a = Amilea::new(MachineConfig::default());
        let mut b = Amilea::new(MachineConfig::default());
        replay.play(&mut a);
        replay.play(&mut b);
        assert_eq!(a.state_hash(), b.state_hash());
    }
}
