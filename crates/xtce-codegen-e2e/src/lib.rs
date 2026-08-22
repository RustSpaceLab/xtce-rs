//! Generating decoders at build time, and proving they agree with the interpreter.
//!
//! This crate holds no code of its own. Its `build.rs` compiles the bundled mission
//! definitions into Rust with `xtce-codegen` and writes them to `OUT_DIR`; the tests
//! `include!` the result and check it, packet for packet, against `xtce-decode`.
//!
//! It exists for two reasons.
//!
//! **It is the shape a mission actually uses.** A definition is compiled by the build script
//! of the crate that consumes it, not committed. `xtce-codegen`'s own tests keep one small
//! generated decoder in the repository so the output can be *read* in a diff; this crate
//! covers the rest without committing megabytes — the CTIM decoder alone is 94 000 lines,
//! because that definition has 9 493 parameters and every concrete container flattens its
//! whole inheritance chain.
//!
//! **It keeps the generator honest at scale.** A generator that works on a 27-parameter
//! definition and falls over on a real one has not been tested.
