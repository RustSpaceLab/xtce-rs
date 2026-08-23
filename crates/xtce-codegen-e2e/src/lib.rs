//! Generating decoders at build time, and proving they agree with the interpreter.
//!
//! Its `build.rs` compiles the bundled definitions into Rust with `xtce-codegen` and writes
//! them to `OUT_DIR`; this crate includes the result and the tests check it, packet for
//! packet, against `xtce-decode`.
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

//!
//! # Why this crate is `no_std`
//!
//! Generated code names nothing outside `core`, deliberately: a mission includes it in the
//! build of whatever consumes it, and that is often a bare-metal target with no allocator.
//! Saying so in a comment is not a check, and it was not one — a calibration emitter reached
//! `main` calling `f64::powi`, which lives in `std`. Every test passed and the output would
//! not have built for a Cortex-M.
//!
//! So the modules below live in a `#![no_std]` library rather than being `include!`d
//! separately by each test. The tests are their own crates and keep `std`; the generated code
//! is compiled once, here, where a reference to anything outside `core` is a build failure
//! rather than a surprise downstream.
//!
//! This closes half the claim. The other half — that it also *cross-compiles* — needs a
//! target this repository's CI does not build for, and rests on the bare-metal probe in
//! [`xtce-flight`](https://github.com/RustSpaceLab/xtce-flight).

#![no_std]

/// CTIM: 9 493 parameters and 38 concrete containers, the scale case.
#[allow(dead_code, clippy::all, clippy::pedantic)]
pub mod ctim {
    include!(concat!(env!("OUT_DIR"), "/ctim.rs"));
}

/// IDEX: a binary field whose width comes from `PKT_LEN`, with two fields behind it.
#[allow(dead_code, clippy::all, clippy::pedantic)]
pub mod idex {
    include!(concat!(env!("OUT_DIR"), "/idex.rs"));
}

/// SUDA: the same shape as IDEX, over a different mission's packets.
#[allow(dead_code, clippy::all, clippy::pedantic)]
pub mod suda {
    include!(concat!(env!("OUT_DIR"), "/suda.rs"));
}

/// A definition with no packet stream: generating and compiling it is the check.
#[allow(dead_code, clippy::all, clippy::pedantic)]
pub mod udp {
    include!(concat!(env!("OUT_DIR"), "/udp.rs"));
}

/// Every numeric shape the emitter can produce, aligned and off a byte boundary.
#[allow(dead_code, clippy::all, clippy::pedantic)]
pub mod numeric_edges {
    include!(concat!(env!("OUT_DIR"), "/numeric_edges.rs"));
}

/// Polynomial and spline calibrators, over both integer and float encodings.
#[allow(dead_code, clippy::all, clippy::pedantic)]
pub mod calibrators {
    include!(concat!(env!("OUT_DIR"), "/calibrators.rs"));
}

/// A `<BooleanExpression>` that is actually a tree.
#[allow(dead_code, clippy::all, clippy::pedantic)]
pub mod boolean_criteria {
    include!(concat!(env!("OUT_DIR"), "/boolean_criteria.rs"));
}

/// `leastSignificantByteFirst`, aligned, unaligned and not a whole number of bytes.
#[allow(dead_code, clippy::all, clippy::pedantic)]
pub mod byte_order {
    include!(concat!(env!("OUT_DIR"), "/byte_order.rs"));
}

/// Arrays, expanded into one field per element.
#[allow(dead_code, clippy::all, clippy::pedantic)]
pub mod arrays {
    include!(concat!(env!("OUT_DIR"), "/arrays.rs"));
}

/// Aggregates, and arrays and aggregates nested in each other.
#[allow(dead_code, clippy::all, clippy::pedantic)]
pub mod aggregates {
    include!(concat!(env!("OUT_DIR"), "/aggregates.rs"));
}
