# xtce-model

[![crates.io](https://img.shields.io/crates/v/xtce-model.svg)](https://crates.io/crates/xtce-model)
[![docs.rs](https://docs.rs/xtce-model/badge.svg)](https://docs.rs/xtce-model)

Reads an XTCE `SpaceSystem` document into `XtceDb`: a flat, index-addressed model that
[`xtce-decode`](https://crates.io/crates/xtce-decode) walks to decode CCSDS packets, and that
[`xtce-codegen`](https://crates.io/crates/xtce-codegen) compiles into static Rust decoders.

Streaming XML through `quick-xml`, an arena behind every entity, and a `u32` newtype instead of
a pointer — which keeps the model `Send + Sync`, makes cloning cheap, and turns following a
reference into an array index.

Models both `TelemetryMetaData` and `CommandMetaData` (including telecommand arguments,
argument assignments, and fixed-value entries). Constructs outside the decodable subset are
still *represented*, so loading a real mission database never fails merely because part of it
is out of scope; the error comes later, from the decoder, at the point a value actually depends
on it.

## Example

```rust,no_run
use xtce_model::XtceDb;

let db = XtceDb::from_path("mission.xml")?;
let stats = db.stats();
println!("{} parameters, {} containers, {} commands", stats.parameters, stats.containers, stats.commands);
# Ok::<(), xtce_model::LoadError>(())
```

Part of [RustSpaceLab/xtce-rs](https://github.com/RustSpaceLab/xtce-rs).
