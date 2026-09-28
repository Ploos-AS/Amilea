//! Deterministic, headless execution core for Amilea M0.
//!
//! This crate deliberately owns no GUI, wall clock, threads, filesystem or
//! global mutable state. Everything that can affect execution is explicit.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoStandard {
    Pal,
    Ntsc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineConfig {
    pub video: VideoStandard,
    pub chip_ram_bytes: usize,
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            video: VideoStandard::Pal,
            chip_ram_bytes: 512 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputEvent {
    Key { code: u8, pressed: bool },
    MouseDelta { dx: i16, dy: i16 },
    Joystick { port: u8, state: u8 },
    SerialRx(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub config: MachineConfig,
    pub cycle: u64,
    pub accumulator: u64,
    pub pending_inputs: Vec<InputEvent>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SnapshotError {
    #[error("unsupported snapshot version {found}; expected {expected}")]
    UnsupportedVersion { found: u32, expected: u32 },
}

#[derive(Debug, Clone)]
pub struct Amilea {
    config: MachineConfig,
    cycle: u64,
    accumulator: u64,
    pending_inputs: Vec<InputEvent>,
}

impl Amilea {
    pub const SNAPSHOT_VERSION: u32 = 1;

    pub fn new(config: MachineConfig) -> Self {
        Self {
            accumulator: seed(&config),
            config,
            cycle: 0,
            pending_inputs: Vec::new(),
        }
    }

    pub fn config(&self) -> &MachineConfig {
        &self.config
    }

    pub fn cycle(&self) -> u64 {
        self.cycle
    }

    pub fn inject(&mut self, event: InputEvent) {
        self.pending_inputs.push(event);
    }

    /// Advance an exact number of deterministic master cycles.
    pub fn run_cycles(&mut self, cycles: u64) {
        for _ in 0..cycles {
            for event in self.pending_inputs.drain(..) {
                self.accumulator = mix(self.accumulator, event_word(&event));
            }
            self.accumulator = mix(self.accumulator, self.cycle);
            self.cycle = self.cycle.wrapping_add(1);
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            version: Self::SNAPSHOT_VERSION,
            config: self.config.clone(),
            cycle: self.cycle,
            accumulator: self.accumulator,
            pending_inputs: self.pending_inputs.clone(),
        }
    }

    pub fn restore(&mut self, snapshot: &Snapshot) -> Result<(), SnapshotError> {
        if snapshot.version != Self::SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion {
                found: snapshot.version,
                expected: Self::SNAPSHOT_VERSION,
            });
        }

        self.config = snapshot.config.clone();
        self.cycle = snapshot.cycle;
        self.accumulator = snapshot.accumulator;
        self.pending_inputs = snapshot.pending_inputs.clone();
        Ok(())
    }

    /// Stable digest used by M0 determinism tests and future CI qualification.
    pub fn state_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.cycle.to_le_bytes());
        h.update(self.accumulator.to_le_bytes());
        h.update((self.config.chip_ram_bytes as u64).to_le_bytes());
        h.update([match self.config.video {
            VideoStandard::Pal => 0,
            VideoStandard::Ntsc => 1,
        }]);
        for event in &self.pending_inputs {
            h.update(event_word(event).to_le_bytes());
        }
        h.finalize().into()
    }
}

fn seed(config: &MachineConfig) -> u64 {
    (config.chip_ram_bytes as u64)
        ^ match config.video {
            VideoStandard::Pal => 0x5041_4c00_0000_0001,
            VideoStandard::Ntsc => 0x4e54_5343_0000_0001,
        }
}

fn mix(a: u64, b: u64) -> u64 {
    a.rotate_left(13)
        .wrapping_add(b ^ 0x9e37_79b9_7f4a_7c15)
        .wrapping_mul(0xbf58_476d_1ce4_e5b9)
}

fn event_word(event: &InputEvent) -> u64 {
    match *event {
        InputEvent::Key { code, pressed } => 0x01_0000 | ((code as u64) << 1) | pressed as u64,
        InputEvent::MouseDelta { dx, dy } => {
            0x02_0000_0000 | ((dx as u16 as u64) << 16) | dy as u16 as u64
        }
        InputEvent::Joystick { port, state } => 0x03_0000 | ((port as u64) << 8) | state as u64,
        InputEvent::SerialRx(value) => 0x04_0000 | value as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario(machine: &mut Amilea) {
        machine.run_cycles(10);
        machine.inject(InputEvent::Key {
            code: 0x50,
            pressed: true,
        });
        machine.run_cycles(1_000);
        machine.inject(InputEvent::SerialRx(b'A'));
        machine.run_cycles(99);
    }

    #[test]
    fn identical_input_produces_identical_state() {
        let config = MachineConfig::default();
        let mut a = Amilea::new(config.clone());
        let mut b = Amilea::new(config);
        scenario(&mut a);
        scenario(&mut b);
        assert_eq!(a.state_hash(), b.state_hash());
    }

    #[test]
    fn snapshot_restore_rejoins_same_timeline() {
        let mut original = Amilea::new(MachineConfig::default());
        original.run_cycles(500);
        let checkpoint = original.snapshot();
        original.inject(InputEvent::Joystick {
            port: 1,
            state: 0x11,
        });
        original.run_cycles(500);

        let mut replayed = Amilea::new(MachineConfig {
            video: VideoStandard::Ntsc,
            chip_ram_bytes: 1024 * 1024,
        });
        replayed.restore(&checkpoint).unwrap();
        replayed.inject(InputEvent::Joystick {
            port: 1,
            state: 0x11,
        });
        replayed.run_cycles(500);

        assert_eq!(original.config(), replayed.config());
        assert_eq!(original.state_hash(), replayed.state_hash());
    }

    #[test]
    fn snapshot_rejects_unknown_version_without_mutating_machine() {
        let mut machine = Amilea::new(MachineConfig::default());
        machine.run_cycles(123);
        let before = machine.state_hash();
        let mut snapshot = machine.snapshot();
        snapshot.version += 1;

        assert_eq!(
            machine.restore(&snapshot),
            Err(SnapshotError::UnsupportedVersion {
                found: 2,
                expected: 1,
            })
        );
        assert_eq!(before, machine.state_hash());
    }
}
