//! Errors produced while reading an XTCE document.

use std::fmt;
use std::path::PathBuf;

/// Anything that can go wrong turning an XTCE document into an [`crate::XtceDb`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum XtceError {
    /// The file could not be read.
    #[error("failed to read {path}")]
    Io {
        /// Path that could not be read.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// The document is not well-formed XML.
    #[error(transparent)]
    Parse(#[from] ParseError),

    /// The document is well-formed but not an XTCE `SpaceSystem`.
    #[error("expected a <SpaceSystem> root element, found <{found}>")]
    NotXtce {
        /// The root element actually present.
        found: String,
    },

    /// A required element or attribute is absent.
    #[error("missing {what} at {path}")]
    Missing {
        /// What was expected, e.g. `"name attribute"`.
        what: &'static str,
        /// Element path within the document.
        path: String,
    },

    /// A value is present but cannot be interpreted.
    #[error("invalid {what} {value:?} at {path}: {reason}")]
    Invalid {
        /// What was being interpreted, e.g. `"sizeInBits"`.
        what: &'static str,
        /// The offending text.
        value: String,
        /// Element path within the document.
        path: String,
        /// Why it could not be used.
        reason: String,
    },

    /// A name reference does not resolve to a definition.
    #[error("unresolved {kind} reference {reference:?} at {path}")]
    UnresolvedReference {
        /// Which namespace was searched.
        kind: RefKind,
        /// The reference text as written.
        reference: String,
        /// Element path within the document.
        path: String,
    },

    /// Two definitions share a name in a namespace that requires uniqueness.
    #[error("duplicate {kind} definition {name:?} at {path}")]
    DuplicateDefinition {
        /// Which namespace the clash is in.
        kind: RefKind,
        /// The duplicated name.
        name: String,
        /// Element path of the second definition.
        path: String,
    },

    /// Container inheritance forms a cycle.
    ///
    /// Detected during resolution rather than during decoding, so a malformed database
    /// fails at load time instead of overflowing the stack on the first packet.
    #[error("container inheritance cycle: {}", .chain.join(" -> "))]
    InheritanceCycle {
        /// Container names along the cycle, in order.
        chain: Vec<String>,
    },

    /// An XTCE construct outside this crate's declared scope.
    ///
    /// This is only raised for constructs that cannot be *represented*. Constructs that can
    /// be represented but not decoded are recorded in the IR instead and reported by
    /// [`crate::XtceDb::unsupported`], so loading a real mission database never fails just
    /// because part of it is out of scope.
    #[error("unsupported XTCE construct <{element}> at {path}")]
    Unsupported {
        /// The element that is out of scope.
        element: String,
        /// Element path within the document.
        path: String,
    },

    /// An array entry could not be turned into one parameter per element.
    ///
    /// Loading fails rather than the array being dropped: an entry that does not expand
    /// leaves every field after it at the wrong offset, and a container decoded at the wrong
    /// offsets is worse than one that refuses.
    #[error("cannot expand the array at {path}: {reason}")]
    ArrayNotExpanded {
        /// Why the expansion could not be carried out.
        reason: String,
        /// Element path within the document.
        path: String,
    },
}

/// Which XTCE namespace a reference is resolved in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RefKind {
    /// `parameterRef`, `parameterInstanceRef`.
    Parameter,
    /// `parameterTypeRef`.
    ParameterType,
    /// `containerRef`, `baseContainer`.
    Container,
    /// `metaCommandRef`.
    MetaCommand,
}

impl fmt::Display for RefKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Parameter => "parameter",
            Self::ParameterType => "parameter type",
            Self::Container => "container",
            Self::MetaCommand => "telecommand",
        })
    }
}

/// A low-level XML syntax failure, with the byte offset where it was detected.
#[derive(Debug, thiserror::Error)]
pub struct ParseError {
    kind: ParseErrorKind,
    offset: Option<u64>,
}

impl ParseError {
    pub(crate) fn new(kind: ParseErrorKind) -> Self {
        Self { kind, offset: None }
    }

    pub(crate) fn at_offset(offset: u64, source: impl Into<ParseErrorKind>) -> Self {
        Self {
            kind: source.into(),
            offset: Some(offset),
        }
    }

    /// Byte offset in the input where the failure was detected, when known.
    #[must_use]
    pub fn offset(&self) -> Option<u64> {
        self.offset
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.offset {
            Some(offset) => write!(f, "XML error at byte {offset}: {}", self.kind),
            None => write!(f, "XML error: {}", self.kind),
        }
    }
}

/// The underlying cause of a [`ParseError`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum ParseErrorKind {
    #[error(transparent)]
    Xml(#[from] quick_xml::Error),
    #[error("document contains no elements")]
    EmptyDocument,
}

impl From<quick_xml::encoding::EncodingError> for ParseErrorKind {
    fn from(value: quick_xml::encoding::EncodingError) -> Self {
        Self::Xml(quick_xml::Error::Encoding(value))
    }
}

impl From<quick_xml::events::attributes::AttrError> for ParseErrorKind {
    fn from(value: quick_xml::events::attributes::AttrError) -> Self {
        Self::Xml(quick_xml::Error::InvalidAttr(value))
    }
}
