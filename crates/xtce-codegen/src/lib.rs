//! Compile an XTCE telemetry definition into a static Rust decoder.
//!
//! This is what distinguishes this project from the other XTCE implementations. They all
//! interpret: walk a container tree, look a parameter up, read its width, advance a cursor.
//! Here the walk happens once, at build time, and what comes out is a `struct` per container
//! whose `decode` is a sequence of loads, shifts and masks with every offset already a
//! literal.
//!
//! # Scope
//!
//! Only layouts that are *fixed at load time* can be compiled: every field at a known offset
//! and width, nothing depending on packet content. Anything else is refused by name through
//! [`CodegenError::Unsupported`] — never quietly handed back to the interpreter. A silent
//! fallback would make a generated-versus-interpreted benchmark meaningless, and would hide
//! from the caller that half their database is not actually compiled.
//!
//! In practice that rules out `LocationInContainerInBits`, `RepeatEntry`, `BooleanExpression`
//! restriction criteria, and calibrators selected by context rather than declared as the
//! default.
//! The interpreted decoder in `xtce-decode` handles all of them and is the fallback the
//! caller chooses explicitly.
//!
//! # Example
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let db = xtce_model::XtceDb::from_path("definition.xml")?;
//! let source = xtce_codegen::generate(&db, &xtce_codegen::Options::default())?;
//! std::fs::write("decoder.rs", source)?;
//! # Ok(())
//! # }
//! ```

#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::todo, clippy::unimplemented)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// Bit offsets and widths are converted between `usize` and `u32` throughout; every value is
// a field offset in a packet that has already been bounded to 64 bits.
#![allow(clippy::cast_possible_truncation)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod emit;
pub mod plan;

use xtce_model::XtceDb;

pub use plan::{Calibration, ContainerPlan, Criterion, Field, Guard, GuardTest, Node, Plan, Repr};

/// What to generate.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Container to start from. Defaults to the database's own default root.
    pub root: Option<String>,
    /// Text recorded in the generated file's header, usually the source path.
    pub source_label: Option<String>,
}

/// Why a definition could not be compiled.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CodegenError {
    /// No container to start from.
    #[error("no container named {name:?}")]
    NoSuchContainer {
        /// The name that was looked up.
        name: String,
    },

    /// The database offers no unambiguous root and none was named.
    #[error("no root container could be chosen automatically; name one explicitly")]
    AmbiguousRoot,

    /// A construct this generator does not compile.
    ///
    /// Deliberately fatal rather than a fallback: the caller must know that a container is
    /// interpreted rather than compiled, because that is the whole difference.
    #[error("cannot compile <{element}> in {container}: {reason}")]
    Unsupported {
        /// The element that stopped compilation.
        element: String,
        /// Where it appeared.
        container: String,
        /// Why it cannot be compiled.
        reason: &'static str,
    },

    /// The database is internally inconsistent.
    #[error("internal: an index in the database does not resolve")]
    DanglingIndex,
}

/// Compiles `db` into Rust source.
///
/// # Errors
///
/// See [`CodegenError`]. In particular, [`CodegenError::Unsupported`] names the element that
/// cannot be compiled and the container it appeared in.
pub fn generate(db: &XtceDb, options: &Options) -> Result<String, CodegenError> {
    let root = match &options.root {
        Some(name) => db
            .find_container(name)
            .ok_or_else(|| CodegenError::NoSuchContainer { name: name.clone() })?,
        None => db
            .default_root_container()
            .ok_or(CodegenError::AmbiguousRoot)?,
    };

    let plan = plan::build(db, root)?;
    let source = options
        .source_label
        .clone()
        .or_else(|| db.source().map(|path| path.display().to_string()))
        .unwrap_or_else(|| "<memory>".to_owned());

    Ok(emit::module(&plan, &source, &plan.root_name.clone()))
}

/// Analyses a definition without generating code, to report what would compile.
///
/// # Errors
///
/// As [`generate`].
pub fn plan(db: &XtceDb, options: &Options) -> Result<Plan, CodegenError> {
    let root = match &options.root {
        Some(name) => db
            .find_container(name)
            .ok_or_else(|| CodegenError::NoSuchContainer { name: name.clone() })?,
        None => db
            .default_root_container()
            .ok_or(CodegenError::AmbiguousRoot)?,
    };
    plan::build(db, root)
}
