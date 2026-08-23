//! Sequence containers, entry lists and the match criteria that select between them.

use crate::ids::{ContainerId, MetaCommandId, ParamId, SpaceSystemId, Span};
use crate::intern::NameId;

/// A `<xtce:SequenceContainer>`.
#[derive(Clone, Debug)]
pub struct Container {
    /// Container name as written.
    pub name: NameId,
    /// Fully qualified name.
    pub qualified_name: NameId,
    /// The space system that owns this definition.
    pub space_system: SpaceSystemId,
    /// `abstract="true"`: the container may not be the final match for a packet.
    pub is_abstract: bool,
    /// The container this one extends, from `<BaseContainer containerRef=..>`.
    pub base: Option<ContainerId>,
    /// The telecommand this container packs, when it is a `<CommandContainer>`.
    ///
    /// `None` for a telemetry container — and also for a shared one in a
    /// `<CommandContainerSet>`, which belongs to no single command.
    pub command: Option<MetaCommandId>,
    /// Criteria under which this container specialises [`Self::base`]. All must hold.
    pub restriction: Vec<MatchCriteria>,
    /// This container's own entries, as a span of [`crate::XtceDb::entries`].
    ///
    /// Entries live in one shared arena so that decoding a container walks a contiguous
    /// slice rather than chasing a per-container `Vec`.
    pub entries: Span,
    /// Containers that name this one as their base, in document order.
    ///
    /// Filled during resolution. Decoding descends this list, which is the direction the
    /// reference implementation walks and the direction packets are actually discriminated.
    pub inheritors: Vec<ContainerId>,
    /// `shortDescription`, if present.
    pub short_description: Option<NameId>,
    /// `<LongDescription>`, if present.
    pub long_description: Option<NameId>,
}

/// One element of an `<xtce:EntryList>`.
#[derive(Clone, Copy, Debug)]
pub struct Entry {
    /// What the entry contributes.
    pub kind: EntryKind,
    /// Explicit placement, from `<LocationInContainerInBits>`.
    ///
    /// `None` means "immediately after the previous entry", which is the XTCE default and
    /// covers every entry in the bundled test data.
    pub location: Option<Location>,
    /// Fixed repetition count, from `<RepeatEntry><Count><FixedValue>`.
    pub repeat: Option<u32>,
}

/// What an entry contributes to a container.
#[derive(Clone, Copy, Debug)]
pub enum EntryKind {
    /// `<ParameterRefEntry>`: one parameter.
    Parameter(ParamId),
    /// `<ContainerRefEntry>`: the referenced container's entries, inline.
    Container(ContainerId),
    /// `<FixedValueEntry>`: bits the definition fixes, carrying no parameter.
    ///
    /// Only a command container may have one. It is how a telecommand carries its sync
    /// pattern and the header bits the ground does not get to choose — the bits are in the
    /// packet, they are not anybody's value, and nothing reports them.
    FixedValue {
        /// The entry's `name`, if it has one. Optional in the schema, and for diagnostics
        /// only: nothing resolves a reference to it.
        name: Option<NameId>,
        /// The bytes, as a span of [`crate::XtceDb::fixed_values`].
        ///
        /// `binaryValue` is `hexBinary`, so this is what it decodes to. Stored in a shared
        /// arena because an entry is `Copy` and cannot own a `Vec`.
        value: Span,
        /// How many of those bits the entry occupies, from `sizeInBits`.
        ///
        /// May be fewer than the bytes hold, and may be more: XTCE does not require the two
        /// to agree, so the width is the entry's and the bytes are the value.
        size_in_bits: u32,
    },
    /// An entry kind outside this crate's scope, e.g. `<IndirectParameterRefEntry>`.
    ///
    /// Present so the container's shape is preserved; decoding one reports
    /// `XtceError::Unsupported`.
    Unsupported {
        /// The element that put the entry out of scope.
        element: NameId,
    },
}

/// `<xtce:LocationInContainerInBits>`.
#[derive(Clone, Copy, Debug)]
pub struct Location {
    /// What the offset is measured from.
    pub reference: LocationReference,
    /// Signed bit offset from the reference point.
    pub offset_in_bits: i64,
}

/// The anchor of a [`Location`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum LocationReference {
    /// End of the previous entry — the XTCE default.
    #[default]
    PreviousEntry,
    /// Start of the containing container.
    ContainerStart,
    /// End of the containing container.
    ContainerEnd,
    /// Start of the next entry.
    NextEntry,
}

/// Comparison operators usable in match criteria.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompareOp {
    /// `==` / `eq`
    Equal,
    /// `!=` / `neq`
    NotEqual,
    /// `<` / `lt`
    Less,
    /// `<=` / `leq`
    LessOrEqual,
    /// `>` / `gt`
    Greater,
    /// `>=` / `geq`
    GreaterOrEqual,
}

impl CompareOp {
    /// Parses the XML spelling of an operator.
    ///
    /// XTCE mandates entity-escaped forms (`&gt;`), but shipped databases also use the
    /// bash-style words, and an XML parser hands back the unescaped character. All three
    /// spellings are accepted, matching the reference implementation.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "==" | "eq" => Self::Equal,
            "!=" | "neq" => Self::NotEqual,
            "<" | "lt" | "&lt;" => Self::Less,
            "<=" | "leq" | "&lt;=" => Self::LessOrEqual,
            ">" | "gt" | "&gt;" => Self::Greater,
            ">=" | "geq" | "&gt;=" => Self::GreaterOrEqual,
            _ => return None,
        })
    }

    /// Applies the operator to an [`Ordering`](std::cmp::Ordering).
    #[must_use]
    pub const fn matches(self, ordering: std::cmp::Ordering) -> bool {
        use std::cmp::Ordering::{Equal, Greater, Less};
        matches!(
            (self, ordering),
            (Self::Equal, Equal)
                | (Self::NotEqual, Less | Greater)
                | (Self::Less, Less)
                | (Self::LessOrEqual, Less | Equal)
                | (Self::Greater, Greater)
                | (Self::GreaterOrEqual, Greater | Equal)
        )
    }
}

/// A condition on previously decoded parameter values.
#[derive(Clone, Debug)]
pub enum MatchCriteria {
    /// `<xtce:Comparison>`: one parameter against a literal.
    Comparison(Comparison),
    /// `<xtce:BooleanExpression>`: a tree of conditions.
    Boolean(BooleanExpr),
    /// A criterion kind outside this crate's scope, e.g. `<CustomAlgorithm>`.
    ///
    /// Evaluating one reports `XtceError::Unsupported` rather than silently matching or
    /// failing, so an out-of-scope discriminator can never quietly select the wrong
    /// container.
    Unsupported {
        /// The element that put the criterion out of scope.
        element: NameId,
    },
}

/// A comparison literal, pre-coerced at load time.
///
/// XTCE does not type the `value` attribute of a `<Comparison>`, and the reference
/// implementation resolves that by coercing the literal to `type(parsed_value)` on every
/// evaluation — so an enumerated parameter compares as text and an integer one as a number.
/// Which of those applies cannot be known from the schema alone, because a calibrator turns
/// an integer-encoded parameter into a float.
///
/// Rather than predict it, every reading that could apply is computed once here, at load
/// time. Evaluation then picks the one matching the value it actually got, and never parses
/// inside the packet loop.
#[derive(Clone, Copy, Debug)]
pub struct ComparisonValue {
    /// The literal exactly as written, for error messages and text comparisons.
    pub text: NameId,
    /// The literal read as an integer, if it is one.
    pub as_int: Option<i128>,
    /// The literal read as a float, if it is one.
    pub as_float: Option<f64>,
}

impl ComparisonValue {
    /// Pre-coerces a literal.
    #[must_use]
    pub fn new(text: NameId, literal: &str) -> Self {
        let literal = literal.trim();
        Self {
            text,
            as_int: literal.parse::<i128>().ok(),
            as_float: literal.parse::<f64>().ok(),
        }
    }
}

/// `<xtce:Comparison>`.
#[derive(Clone, Copy, Debug)]
pub struct Comparison {
    /// Parameter being tested.
    pub parameter: ParamId,
    /// Operator.
    pub operator: CompareOp,
    /// Required value, pre-coerced to every reading that could apply.
    pub value: ComparisonValue,
    /// Whether to test the calibrated or the raw value.
    pub use_calibrated: bool,
}

/// `<xtce:BooleanExpression>`.
#[derive(Clone, Debug)]
pub enum BooleanExpr {
    /// A single `<Condition>`.
    Condition(Condition),
    /// `<ANDedConditions>`: true when every child is true.
    And(Vec<BooleanExpr>),
    /// `<ORedConditions>`: true when any child is true.
    Or(Vec<BooleanExpr>),
}

/// `<xtce:Condition>`: two operands and an operator.
#[derive(Clone, Copy, Debug)]
pub struct Condition {
    /// Left-hand side; always a parameter reference per the schema.
    pub left: Operand,
    /// Operator.
    pub operator: CompareOp,
    /// Right-hand side; a parameter reference or a literal `<Value>`.
    pub right: Operand,
}

/// One side of a [`Condition`].
#[derive(Clone, Copy, Debug)]
pub enum Operand {
    /// `<ParameterInstanceRef>`.
    Parameter {
        /// The referenced parameter.
        parameter: ParamId,
        /// Whether to read its calibrated or raw value.
        use_calibrated: bool,
    },
    /// `<Value>`, pre-coerced against whatever the other operand turns out to be.
    Literal(ComparisonValue),
}

/// A `<xtce:SpaceSystem>` node.
#[derive(Clone, Debug)]
pub struct SpaceSystem {
    /// Name as written.
    pub name: NameId,
    /// Fully qualified path, e.g. `/Root/Payload`. The root is `/Root`.
    pub qualified_name: NameId,
    /// Enclosing space system, if any.
    pub parent: Option<SpaceSystemId>,
    /// Nested space systems, in document order.
    pub children: Vec<SpaceSystemId>,
}
