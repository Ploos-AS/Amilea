# Amilea

**A deterministic Amiga emulation, analysis and debugging platform written in Rust.**

Amilea is being built as an execution platform first and a desktop emulator second. The core is a headless Rust library with no GUI, wall-clock dependency or global mutable state.

## Design principles

- **Deterministic** — identical machine state and explicit inputs produce identical results.
- **Observable** — execution, bus activity, OS state and devices are designed to be inspectable.
- **Scriptable** — tests and automation are first-class clients of the core.
- **Embeddable** — frontends, servers and tools consume a library API.
- **Reproducible** — snapshots and record/replay are architectural primitives.

## M0 — deterministic execution foundation

M0 establishes the contracts everything else will build on:

- Rust workspace and headless `amilea-core` library.
- Explicit PAL/NTSC machine configuration and external input events.
- Exact master-cycle stepping with no wall-clock synchronization.
- Stable state hashing for deterministic qualification.
- Snapshot/restore primitives.
- `amilea-replay` event timeline and deterministic playback.
- Minimal `amilea` CLI frontend.
- CI gates for formatting, Clippy and tests.

The M0 execution engine is intentionally a scaffold; it does **not** emulate a 68000 or Amiga chipset yet. Those arrive behind the deterministic contracts rather than defining them.

## Try it

```sh
cargo run -p amilea-cli -- 1000000
cargo test --workspace
```

## Initial machine target

The first real hardware target after M0 is intentionally narrow:

- Amiga 500
- PAL first
- Motorola 68000
- OCS
- 512 KiB Chip RAM

The future scheduler/bus architecture will remain cycle-aware from the start so cycle-exact behavior can be introduced incrementally without replacing the execution model.

## Roadmap

- **M0:** deterministic core, state hash, snapshot/replay, CLI, CI.
- **M1:** 68000 execution boundary and deterministic memory/bus model.
- **M2:** CIA, interrupts and cycle-aware scheduler foundation.
- **M3:** OCS DMA/Copper/bitplanes and first observable raster output.
- **Later:** Paula, floppy/flux, OS-aware inspection, semantic breakpoints, reverse debugging, scripting, server/WASM frontends and differential qualification.

## ROMs and copyrighted system software

Amilea does not ship Kickstart ROMs, AmigaOS or other proprietary system software. Tests and tooling must keep copyrighted ROM/system images outside the repository.

## License

Software source is licensed under the MIT License unless a subdirectory states otherwise.
