//! Decode CCSDS telemetry packets against an XTCE definition.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use xtce_decode::{Decoder, ccsds::PacketIter};
//! use xtce_model::XtceDb;
//!
//! let db = XtceDb::from_path("definition.xml")?;
//! let decoder = Decoder::new(&db)?;
//!
//! let stream = std::fs::read("telemetry.bin")?;
//! for packet in PacketIter::new(&stream, 0) {
//!     let decoded = decoder.decode(packet?.bytes())?;
//!     for (name, value) in decoded.iter_named() {
//!         println!("{name} = {} (raw {})", value.eng, value.raw);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Guarantees
//!
//! * **No panics.** Every failure is a [`DecodeError`]. A corrupt or hostile packet must not
//!   take down a process sitting on a live downlink, so the library code denies `unwrap`,
//!   `expect` and `panic!` outright.
//! * **No allocation for aligned reads.** Byte-aligned binary and string fields borrow
//!   straight from the packet.
//! * **Raw and engineering values are both kept.** XTCE treats them as distinct, restriction
//!   criteria may test either, and differential testing needs both.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::todo, clippy::unimplemented)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// Tests are allowed to assert loudly; the no-panic rule is about library code reached by a
// live downlink, not about test setup.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        // Exact float equality is the assertion, not an accident: these tests check that a
        // calibrator produced a specific bit pattern.
        clippy::float_cmp,
        clippy::unreadable_literal
    )
)]
// This crate exists to reinterpret bit patterns. Every `as` here narrows a field of known
// width, with the mask or width check that makes it exact immediately alongside; and every
// integer-to-float conversion is the one the XTCE data model specifies. Flagging them
// individually would mean an `#[allow]` on almost every line of the hot path.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]

pub mod bits;
pub mod calibrate;
pub mod ccsds;
pub mod charset;
mod decoder;
pub mod error;
pub mod value;

pub use bits::{BitCursor, BitError};
pub use ccsds::{FramingError, PacketIter, SpacePacketBytes};
pub use decoder::Decoder;
pub use error::DecodeError;
pub use value::{DecodedPacket, EngValue, ParameterValue, RawValue};
