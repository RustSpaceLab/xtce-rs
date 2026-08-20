//! Parameter types, data encodings and calibrators.

use crate::ids::{ParamId, TypeId};
use crate::intern::NameId;

/// A `<xtce:*ParameterType>` definition.
#[derive(Clone, Debug)]
pub struct ParameterType {
    /// Type name as written, e.g. `MSN__PARAM_Type`.
    pub name: NameId,
    /// Fully qualified name, e.g. `/Root/MSN__PARAM_Type`.
    pub qualified_name: NameId,
    /// The space system that owns this definition.
    pub space_system: crate::ids::SpaceSystemId,
    /// Engineering units, if declared. XTCE permits compound units, hence a list.
    pub units: Vec<NameId>,
    /// What kind of value this type produces.
    pub kind: TypeKind,
    /// How the value is laid out in the packet.
    pub encoding: DataEncoding,
}

impl ParameterType {
    /// Number of bits this type occupies, when that is fixed at load time.
    ///
    /// `None` means the width depends on packet content — a dynamically sized binary or
    /// string field — and can only be known while decoding.
    #[must_use]
    pub fn fixed_size_in_bits(&self) -> Option<u32> {
        self.encoding.fixed_size_in_bits()
    }
}

/// The semantic family of a parameter type.
#[derive(Clone, Debug)]
pub enum TypeKind {
    /// `IntegerParameterType`.
    Integer,
    /// `FloatParameterType`.
    Float,
    /// `StringParameterType`.
    String,
    /// `BinaryParameterType`.
    Binary,
    /// `BooleanParameterType`.
    ///
    /// XTCE calls this "a restricted form of enumeration", and the reference
    /// implementation derives truthiness from the *raw* value, ignoring the label
    /// attributes. The labels are kept here so callers can render them; see
    /// [`crate::XtceDb::boolean_label`].
    Boolean {
        /// Label for the false value, from `zeroStringValue`.
        zero_label: Option<NameId>,
        /// Label for the true value, from `oneStringValue`.
        one_label: Option<NameId>,
    },
    /// `EnumeratedParameterType`.
    Enumerated(EnumerationList),
    /// `AbsoluteTimeParameterType`.
    AbsoluteTime {
        /// `ReferenceTime/Epoch`, verbatim.
        epoch: Option<NameId>,
        /// `ReferenceTime/OffsetFrom/@parameterRef`, resolved.
        offset_from: Option<ParamId>,
    },
    /// `RelativeTimeParameterType`.
    RelativeTime,
    /// A parameter type this crate models structurally but cannot decode.
    ///
    /// Loading succeeds; decoding a parameter of this type reports
    /// `XtceError::Unsupported` naming the element below.
    Unsupported {
        /// The element name that put this type out of scope.
        element: NameId,
    },
}

impl TypeKind {
    /// A short, stable name for reporting, e.g. in `xtce info`.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Integer => "integer",
            Self::Float => "float",
            Self::String => "string",
            Self::Binary => "binary",
            Self::Boolean { .. } => "boolean",
            Self::Enumerated(_) => "enumerated",
            Self::AbsoluteTime { .. } => "absolute-time",
            Self::RelativeTime => "relative-time",
            Self::Unsupported { .. } => "unsupported",
        }
    }
}

/// The `<xtce:EnumerationList>` of an enumerated parameter type.
///
/// Entries are stored sorted by `value` so that lookup is a binary search rather than a
/// linear scan; enumerations in real databases reach several hundred entries.
#[derive(Clone, Debug, Default)]
pub struct EnumerationList {
    entries: Vec<Enumeration>,
}

/// One `<xtce:Enumeration>`.
#[derive(Clone, Copy, Debug)]
pub struct Enumeration {
    /// The raw encoded value this label applies to.
    pub value: i128,
    /// Inclusive upper bound, from `maxValue`; equal to `value` for a point entry.
    pub max_value: i128,
    /// The label.
    pub label: NameId,
}

impl EnumerationList {
    /// Builds a list from unsorted entries.
    #[must_use]
    pub fn new(mut entries: Vec<Enumeration>) -> Self {
        entries.sort_unstable_by_key(|entry| entry.value);
        Self { entries }
    }

    /// All entries, ordered by value.
    #[must_use]
    pub fn entries(&self) -> &[Enumeration] {
        &self.entries
    }

    /// The label covering `value`, if any.
    ///
    /// Ranged entries (`maxValue`) are honoured, so a value inside `value..=max_value`
    /// matches.
    #[must_use]
    pub fn label_for(&self, value: i128) -> Option<NameId> {
        // `partition_point` finds the last entry whose `value` is <= the query; ranged
        // entries then need only that one bound check.
        let idx = self.entries.partition_point(|entry| entry.value <= value);
        let candidate = self.entries.get(idx.checked_sub(1)?)?;
        (value <= candidate.max_value).then_some(candidate.label)
    }
}

/// Byte order of a multi-byte encoded value.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ByteOrder {
    /// `mostSignificantByteFirst` — big-endian, the CCSDS default.
    #[default]
    MostSignificantFirst,
    /// `leastSignificantByteFirst` — little-endian.
    LeastSignificantFirst,
}

/// How a value is laid out in the packet.
#[derive(Clone, Debug)]
pub enum DataEncoding {
    /// `<xtce:IntegerDataEncoding>`.
    Integer(IntegerEncoding),
    /// `<xtce:FloatDataEncoding>`.
    Float(FloatEncoding),
    /// `<xtce:StringDataEncoding>`.
    String(StringEncoding),
    /// `<xtce:BinaryDataEncoding>`.
    Binary(BinaryEncoding),
    /// No usable encoding was found under the parameter type.
    None,
}

impl DataEncoding {
    /// Width in bits when fixed at load time.
    #[must_use]
    pub fn fixed_size_in_bits(&self) -> Option<u32> {
        match self {
            Self::Integer(encoding) => Some(encoding.size_in_bits),
            Self::Float(encoding) => Some(encoding.size_in_bits),
            Self::String(encoding) => encoding.raw_size.fixed(),
            Self::Binary(encoding) => encoding.size.fixed(),
            Self::None => None,
        }
    }

    /// The default calibrator, if the encoding supports calibration and declares one.
    #[must_use]
    pub fn default_calibrator(&self) -> Option<&Calibrator> {
        match self {
            Self::Integer(encoding) => encoding.default_calibrator.as_ref(),
            Self::Float(encoding) => encoding.default_calibrator.as_ref(),
            Self::String(_) | Self::Binary(_) | Self::None => None,
        }
    }

    /// Context calibrators, in document order.
    #[must_use]
    pub fn context_calibrators(&self) -> &[ContextCalibrator] {
        match self {
            Self::Integer(encoding) => &encoding.context_calibrators,
            Self::Float(encoding) => &encoding.context_calibrators,
            Self::String(_) | Self::Binary(_) | Self::None => &[],
        }
    }
}

/// Integer encodings defined by XTCE 4.3.2.2.5.6.2.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum IntegerCoding {
    /// `unsigned`.
    #[default]
    Unsigned,
    /// `twosComplement`, plus the misspelling `twosCompliment` and the informal `signed`,
    /// both of which occur in shipped mission databases and are accepted by the reference
    /// implementation.
    TwosComplement,
    /// `signMagnitude`: the top bit is the sign, the rest is magnitude.
    SignMagnitude,
    /// `onesComplement`.
    OnesComplement,
}

/// `<xtce:IntegerDataEncoding>`.
#[derive(Clone, Debug)]
pub struct IntegerEncoding {
    /// Field width in bits, 1..=64.
    pub size_in_bits: u32,
    /// How the bits map to an integer.
    pub coding: IntegerCoding,
    /// Byte order for widths above one byte.
    pub byte_order: ByteOrder,
    /// Calibrator applied when no context calibrator matches.
    pub default_calibrator: Option<Calibrator>,
    /// Conditional calibrators, evaluated in document order.
    pub context_calibrators: Vec<ContextCalibrator>,
}

/// Float encodings.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FloatCoding {
    /// `IEEE754` / `IEEE754_1985`, at 16, 32 or 64 bits.
    #[default]
    Ieee754,
    /// `MILSTD_1750A`, always 32 bits.
    MilStd1750A,
}

/// `<xtce:FloatDataEncoding>`.
#[derive(Clone, Debug)]
pub struct FloatEncoding {
    /// Field width in bits.
    pub size_in_bits: u32,
    /// Which float format the bits are in.
    pub coding: FloatCoding,
    /// Byte order.
    pub byte_order: ByteOrder,
    /// Calibrator applied when no context calibrator matches.
    pub default_calibrator: Option<Calibrator>,
    /// Conditional calibrators, evaluated in document order.
    pub context_calibrators: Vec<ContextCalibrator>,
}

/// Character sets XTCE allows for string data.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Charset {
    /// `UTF-8`, the XTCE default.
    #[default]
    Utf8,
    /// `US-ASCII`.
    UsAscii,
    /// `ISO-8859-1` (Latin-1).
    Iso8859_1,
    /// `Windows-1252`.
    Windows1252,
    /// `UTF-16`, `UTF-16BE` or `UTF-16LE`; endianness is carried separately.
    Utf16,
    /// `UTF-32`, `UTF-32BE` or `UTF-32LE`.
    Utf32,
}

impl Charset {
    /// Bytes per code unit.
    #[must_use]
    pub const fn code_unit_bytes(self) -> usize {
        match self {
            Self::Utf8 | Self::UsAscii | Self::Iso8859_1 | Self::Windows1252 => 1,
            Self::Utf16 => 2,
            Self::Utf32 => 4,
        }
    }
}

/// How the *derived* string is delimited inside its raw buffer.
#[derive(Clone, Debug, Default)]
pub enum StringDelimiter {
    /// The whole raw buffer is the string.
    #[default]
    WholeBuffer,
    /// The string ends at the first occurrence of these bytes.
    TerminationChar(Vec<u8>),
    /// The buffer starts with an integer of this many bits giving the string length in bits.
    LeadingSize {
        /// Width of the length prefix, in bits.
        size_in_bits: u32,
    },
}

/// `<xtce:StringDataEncoding>`.
#[derive(Clone, Debug)]
pub struct StringEncoding {
    /// Character set of the decoded text.
    pub charset: Charset,
    /// Byte order, relevant for UTF-16 and UTF-32.
    pub byte_order: ByteOrder,
    /// Size of the raw buffer, including any terminator or length prefix.
    pub raw_size: SizeSpec,
    /// How to find the string inside the raw buffer.
    pub delimiter: StringDelimiter,
}

/// `<xtce:BinaryDataEncoding>`.
#[derive(Clone, Debug)]
pub struct BinaryEncoding {
    /// Size of the binary field.
    pub size: SizeSpec,
}

/// How a variable-width field's size is determined.
#[derive(Clone, Debug)]
pub enum SizeSpec {
    /// A literal bit count from `SizeInBits/FixedValue`.
    Fixed(u32),
    /// A bit count read from another parameter, per `SizeInBits/DynamicValue`.
    Dynamic {
        /// The parameter holding the size.
        parameter: ParamId,
        /// Whether to read its calibrated or raw value.
        use_calibrated: bool,
        /// Optional `slope`/`intercept` conversion, typically bytes to bits.
        adjustment: Option<LinearAdjustment>,
    },
    /// A bit count chosen by the first matching entry of a `DiscreteLookupList`.
    DiscreteLookup(Vec<DiscreteLookup>),
    /// The size could not be modelled; decoding such a field reports the element below.
    Unsupported {
        /// The element that put the size out of scope.
        element: NameId,
    },
}

impl SizeSpec {
    /// The bit count, when it is fixed at load time.
    #[must_use]
    pub const fn fixed(&self) -> Option<u32> {
        match self {
            Self::Fixed(bits) => Some(*bits),
            _ => None,
        }
    }
}

/// `<xtce:LinearAdjustment>`: `slope * x + intercept`.
#[derive(Clone, Copy, Debug)]
pub struct LinearAdjustment {
    /// Multiplier.
    pub slope: f64,
    /// Additive term.
    pub intercept: f64,
}

impl LinearAdjustment {
    /// Applies the adjustment.
    #[must_use]
    pub fn apply(self, value: f64) -> f64 {
        self.slope * value + self.intercept
    }
}

/// One `<xtce:DiscreteLookup>`: a value returned when all its criteria hold.
#[derive(Clone, Debug)]
pub struct DiscreteLookup {
    /// Criteria that must all hold.
    pub criteria: Vec<crate::containers::MatchCriteria>,
    /// The value produced when they do.
    pub value: i64,
}

/// A calibrator converting a raw encoded value into an engineering value.
#[derive(Clone, Debug)]
pub enum Calibrator {
    /// `<xtce:PolynomialCalibrator>`.
    ///
    /// Terms are kept in document order, not sorted by exponent: floating-point addition is
    /// not associative, and the differential tests compare against a reference that
    /// accumulates in document order.
    Polynomial(Vec<PolynomialTerm>),
    /// `<xtce:SplineCalibrator>`.
    Spline(Spline),
    /// A calibrator kind outside this crate's scope, e.g. `MathOperationCalibrator`.
    Unsupported {
        /// The element that put the calibrator out of scope.
        element: NameId,
    },
}

/// One `<xtce:Term>` of a polynomial calibrator.
#[derive(Clone, Copy, Debug)]
pub struct PolynomialTerm {
    /// Multiplier.
    pub coefficient: f64,
    /// Power of the raw value.
    pub exponent: i32,
}

/// `<xtce:SplineCalibrator>`.
#[derive(Clone, Debug)]
pub struct Spline {
    /// 0 for nearest-lower-point, 1 for linear interpolation.
    pub order: u8,
    /// Points sorted by raw value.
    pub points: Vec<SplinePoint>,
    /// Whether queries outside the point range are extrapolated instead of rejected.
    pub extrapolate: bool,
}

/// One `<xtce:SplinePoint>`.
#[derive(Clone, Copy, Debug)]
pub struct SplinePoint {
    /// Raw value.
    pub raw: f64,
    /// Calibrated value.
    pub calibrated: f64,
}

/// `<xtce:ContextCalibrator>`: a calibrator gated on other parameter values.
#[derive(Clone, Debug)]
pub struct ContextCalibrator {
    /// Criteria that must all hold for this calibrator to apply.
    pub criteria: Vec<crate::containers::MatchCriteria>,
    /// The calibrator to apply.
    pub calibrator: Calibrator,
}

/// A `<xtce:Parameter>` definition.
#[derive(Clone, Debug)]
pub struct Parameter {
    /// Parameter name as written.
    pub name: NameId,
    /// Fully qualified name.
    pub qualified_name: NameId,
    /// The space system that owns this definition.
    pub space_system: crate::ids::SpaceSystemId,
    /// The parameter's type.
    pub type_id: TypeId,
    /// `shortDescription`, if present.
    pub short_description: Option<NameId>,
    /// `<LongDescription>`, if present.
    pub long_description: Option<NameId>,
    /// `initialValue`, verbatim, if present.
    pub initial_value: Option<NameId>,
}
