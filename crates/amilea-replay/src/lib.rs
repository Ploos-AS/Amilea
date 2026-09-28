//! Record/replay primitives for deterministic Amilea executions.

use amilea_core::{Amilea, InputEvent, Snapshot, SnapshotError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReplayError {
    #[error("unsupported replay version {found}; expected {expected}")]
    UnsupportedVersion { found: u32, expected: u32 },
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error("replay input at cycle {cycle} precedes cursor {cursor}")]
    NonMonotonicInput { cycle: u64, cursor: u64 },
    #[error("replay end cycle {end_cycle} precedes cursor {cursor}")]
    EndBeforeCursor { end_cycle: u64, cursor: u64 },
}

impl Replay {
    pub const FORMAT_VERSION: u32 = 1;

    pub fn play(&self, machine: &mut Amilea) -> Result<(), ReplayError> {
        if self.version != Self::FORMAT_VERSION {
            return Err(ReplayError::UnsupportedVersion {
                found: self.version,
                expected: Self::FORMAT_VERSION,
            });
        }

        machine.restore(&self.initial)?;
        let mut cursor = machine.cycle();
        for input in &self.inputs {
            if input.cycle < cursor {
                return Err(ReplayError::NonMonotonicInput {
                    cycle: input.cycle,
                    cursor,
                });
            }
            machine.run_cycles(input.cycle - cursor);
            machine.inject(input.event.clone());
            cursor = input.cycle;
        }
        if self.end_cycle < cursor {
            return Err(ReplayError::EndBeforeCursor {
                end_cycle: self.end_cycle,
                cursor,
            });
        }
        machine.run_cycles(self.end_cycle - cursor);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amilea_core::{MachineConfig, VideoStandard};

    #[test]
    fn replay_is_repeatable_and_restores_machine_profile() {
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
        let mut b = Amilea::new(MachineConfig {
            video: VideoStandard::Ntsc,
            chip_ram_bytes: 1024 * 1024,
        });
        replay.play(&mut a).unwrap();
        replay.play(&mut b).unwrap();
        assert_eq!(a.config(), b.config());
        assert_eq!(a.state_hash(), b.state_hash());
    }

    #[test]
    fn replay_rejects_unknown_format() {
        let seed = Amilea::new(MachineConfig::default());
        let replay = Replay {
            version: Replay::FORMAT_VERSION + 1,
            initial: seed.snapshot(),
            inputs: vec![],
            end_cycle: 0,
        };
        let mut machine = Amilea::new(MachineConfig::default());

        assert_eq!(
            replay.play(&mut machine),
            Err(ReplayError::UnsupportedVersion {
                found: 2,
                expected: 1,
            })
        );
    }
}
