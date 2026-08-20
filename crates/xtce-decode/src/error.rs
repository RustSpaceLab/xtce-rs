//! Decoding failures.
//!
//! Every one of these is a `Result`, never a panic. A decoder fed a corrupt or hostile
//! packet must keep running: it is typically sitting on a live downlink, and one malformed
//! frame must not take the process with it.

use xtce_model::{ContainerId, ParamId};

use crate::bits::BitError;

/// Anything that can go wrong decoding a packet.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// A field extends past the end of the packet.
    #[error("{parameter}: {source}")]
    Bits {
        /// Name of the parameter being decoded.
        parameter: String,
        /// The underlying bit-cursor failure.
        #[source]
        source: BitError,
    },

    /// The named root container does not exist in the database.
    #[error("no container named {name:?}")]
    NoSuchContainer {
        /// The name that was looked up.
        name: String,
    },

    /// The database offers no unambiguous root container and none was named.
    #[error(
        "no root container could be chosen automatically ({candidates} candidates); name one explicitly"
    )]
    AmbiguousRoot {
        /// How many containers have no base container.
        candidates: usize,
    },

    /// Decoding reached an abstract container whose inheritors all failed their criteria.
    ///
    /// This is the reference implementation's `UnrecognizedPacketTypeError`: the packet is
    /// of a type the definition does not describe.
    #[error("packet not recognised: abstract container {container} has no matching inheritor")]
    UnrecognizedPacket {
        /// Name of the abstract container that ran out of options.
        container: String,
        /// Names of the inheritors that were considered.
        candidates: Vec<String>,
    },

    /// More than one inheritor matched, so the packet type is ambiguous.
    #[error("ambiguous packet type: {} inheritors of {container} all match", .candidates.len())]
    AmbiguousPacket {
        /// Name of the container being specialised.
        container: String,
        /// Names of the inheritors that matched.
        candidates: Vec<String>,
    },

    /// A criterion or dynamic size referenced a parameter that has not been decoded yet.
    ///
    /// XTCE references are positional: a field can only depend on a field that precedes it.
    #[error("{context} references parameter {parameter:?}, which has not been decoded yet")]
    ParameterNotYetDecoded {
        /// Where the reference appeared.
        context: &'static str,
        /// The parameter that was referenced.
        parameter: String,
    },

    /// A comparison's literal cannot be interpreted as the type of the value it is compared
    /// against.
    #[error("cannot compare {parameter} ({value_kind}) against literal {literal:?}")]
    IncomparableValue {
        /// Name of the referenced parameter.
        parameter: String,
        /// What kind of value it held.
        value_kind: &'static str,
        /// The literal as written in the definition.
        literal: String,
    },

    /// The bytes are not valid text in the declared character set.
    #[error("{parameter}: {bytes} byte(s) are not valid {charset}")]
    InvalidText {
        /// Name of the parameter being decoded.
        parameter: String,
        /// Character set that was expected.
        charset: &'static str,
        /// Length of the offending buffer.
        bytes: usize,
    },

    /// A string declares a termination character that does not occur in its buffer.
    #[error("{parameter}: termination character not found in the {bytes}-byte string buffer")]
    UnterminatedString {
        /// Name of the parameter being decoded.
        parameter: String,
        /// Length of the buffer that was searched.
        bytes: usize,
    },

    /// A raw value is outside an enumeration's defined values.
    #[error("{parameter}: raw value {value} is not in the enumeration")]
    UnknownEnumeration {
        /// Name of the parameter being decoded.
        parameter: String,
        /// The raw value that was looked up.
        value: i128,
    },

    /// A calibrator rejected its input.
    #[error("{parameter}: {reason}")]
    Calibration {
        /// Name of the parameter being decoded.
        parameter: String,
        /// Why calibration failed.
        reason: String,
    },

    /// A dynamic size resolved to something unusable.
    #[error("{parameter}: computed field size {bits} bits is not usable")]
    BadFieldSize {
        /// Name of the parameter being decoded.
        parameter: String,
        /// The size that was computed.
        bits: i64,
    },

    /// A `DiscreteLookupList` had no matching entry.
    #[error("{parameter}: no discrete lookup matched")]
    NoDiscreteLookupMatch {
        /// Name of the parameter being decoded.
        parameter: String,
    },

    /// The definition uses a construct this crate models but cannot decode.
    ///
    /// This is the promise `SUPPORTED.md` makes: out-of-scope constructs load without
    /// complaint and fail here, at the exact point a value depends on them.
    #[error("unsupported XTCE construct <{element}> reached while decoding {context}")]
    Unsupported {
        /// The element that is out of scope.
        element: String,
        /// What was being decoded when it was reached.
        context: String,
    },

    /// The database is internally inconsistent — an index does not resolve.
    #[error("internal: {what} index does not resolve")]
    DanglingIndex {
        /// Which kind of index.
        what: &'static str,
    },
}

impl DecodeError {
    pub(crate) fn dangling_parameter(_id: ParamId) -> Self {
        Self::DanglingIndex { what: "parameter" }
    }

    pub(crate) fn dangling_container(_id: ContainerId) -> Self {
        Self::DanglingIndex { what: "container" }
    }
}
