//! XTCE telemetry metadata: a streaming XML reader and an arena-backed intermediate
//! representation.
//!
//! This crate turns an XTCE `SpaceSystem` document into [`XtceDb`], a flat, index-addressed
//! model that [`xtce-decode`](https://docs.rs/xtce-decode) walks to decode CCSDS packets and
//! that `xtce-codegen` compiles into static Rust decoders.
//!
//! # Scope
//!
//! Only `TelemetryMetaData` is modelled; see `SUPPORTED.md` in the repository for the exact
//! coverage table. Constructs outside the *decodable* subset are still **represented** —
//! they surface as explicit IR variants and via [`XtceDb::unsupported`] — so that loading a
//! real mission database never fails merely because part of it is out of scope. The error
//! is raised by the decoder, at the point a value actually depends on the construct.
//!
//! # Example
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let db = xtce_model::XtceDb::from_path("testdata/spp/jpss/jpss1_geolocation_xtce_v1.xml")?;
//! println!("{} parameters, {} containers", db.parameters().len(), db.containers().len());
//! # Ok(())
//! # }
//! ```

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
        clippy::float_cmp
    )
)]

pub mod containers;
pub mod db;
pub mod error;
pub mod ids;
pub mod intern;
mod lower;
pub mod types;
pub mod xml;

pub use containers::{
    BooleanExpr, CompareOp, Comparison, ComparisonValue, Condition, Container, Entry, EntryKind,
    Location, LocationReference, MatchCriteria, Operand, SpaceSystem,
};
pub use db::{Stats, Unsupported, XtceDb};
pub use error::{RefKind, XtceError};
pub use ids::{ContainerId, ParamId, SpaceSystemId, Span, TypeId};
pub use intern::{Interner, NameId};
pub use types::{
    BinaryEncoding, ByteOrder, Calibrator, Charset, ContextCalibrator, DataEncoding,
    DiscreteLookup, Enumeration, EnumerationList, FloatCoding, FloatEncoding, IntegerCoding,
    IntegerEncoding, LinearAdjustment, Parameter, ParameterType, PolynomialTerm, SizeSpec, Spline,
    SplinePoint, StringDelimiter, StringEncoding, TypeKind,
};
