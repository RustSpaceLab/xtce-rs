# xtce-model

Reads an XTCE `SpaceSystem` document into `XtceDb`: a flat, index-addressed model that
[`xtce-decode`](https://crates.io/crates/xtce-decode) walks to decode CCSDS packets, and that
`xtce-codegen` compiles into static Rust decoders.

Streaming XML through `quick-xml`, an arena behind every entity, and a `u32` newtype instead of
a pointer — which keeps the model `Send + Sync`, makes cloning cheap, and turns following a
reference into an array index.

Only `TelemetryMetaData` is modelled. Constructs outside the decodable subset are still
*represented*, so loading a real mission database never fails merely because part of it is out
of scope; the error comes later, from the decoder, at the point a value actually depends on it.

Part of [RustSpaceLab/xtce-rs](https://github.com/RustSpaceLab/xtce-rs).
