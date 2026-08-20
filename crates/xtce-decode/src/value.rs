//! Decoded parameter values.
//!
//! XTCE separates the *raw* value — the bits as they appear in the packet, interpreted only
//! as far as the data encoding says — from the *engineering* value, which is the raw value
//! after calibration or enumeration lookup. Keeping both is not redundancy: a `Comparison`
//! in a restriction criterion may test either one, and differential testing against another
//! implementation is only meaningful if both are compared.

use std::borrow::Cow;
use std::fmt;

use xtce_model::{ContainerId, ParamId, XtceDb, intern::FxHashMap};

/// A value exactly as encoded in the packet.
#[derive(Clone, Debug, PartialEq)]
pub enum RawValue<'p> {
    /// An unsigned integer field.
    Unsigned(u64),
    /// A signed integer field.
    Signed(i64),
    /// A float field.
    Float(f64),
    /// A binary or string field. Borrowed from the packet when the read was byte-aligned.
    Bytes(Cow<'p, [u8]>),
}

/// A value after calibration, enumeration lookup or text decoding.
#[derive(Clone, Debug, PartialEq)]
pub enum EngValue<'db, 'p> {
    /// An uncalibrated unsigned integer.
    Unsigned(u64),
    /// An uncalibrated signed integer.
    Signed(i64),
    /// A float, either encoded as one or produced by a calibrator.
    Float(f64),
    /// A boolean parameter's value.
    Bool(bool),
    /// An enumeration label, borrowed from the definition.
    Label(&'db str),
    /// Text decoded from the packet.
    Text(Cow<'p, str>),
    /// Binary data.
    Bytes(Cow<'p, [u8]>),
}

impl RawValue<'_> {
    /// The value as an integer, when it is one.
    #[must_use]
    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Self::Unsigned(value) => Some(i128::from(*value)),
            Self::Signed(value) => Some(i128::from(*value)),
            Self::Float(_) | Self::Bytes(_) => None,
        }
    }

    /// The value as a float, when it is numeric.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Unsigned(value) => Some(*value as f64),
            Self::Signed(value) => Some(*value as f64),
            Self::Float(value) => Some(*value),
            Self::Bytes(_) => None,
        }
    }
}

impl EngValue<'_, '_> {
    /// The value as an integer, when it is one.
    ///
    /// Booleans convert to 0 and 1, matching XTCE's definition of a boolean as a restricted
    /// enumeration over an integer encoding.
    #[must_use]
    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Self::Unsigned(value) => Some(i128::from(*value)),
            Self::Signed(value) => Some(i128::from(*value)),
            Self::Bool(value) => Some(i128::from(*value)),
            Self::Float(_) | Self::Label(_) | Self::Text(_) | Self::Bytes(_) => None,
        }
    }

    /// The value as a float, when it is numeric.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Unsigned(value) => Some(*value as f64),
            Self::Signed(value) => Some(*value as f64),
            Self::Float(value) => Some(*value),
            Self::Bool(value) => Some(f64::from(u8::from(*value))),
            Self::Label(_) | Self::Text(_) | Self::Bytes(_) => None,
        }
    }

    /// The value as text, when it is textual.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Label(text) => Some(text),
            Self::Text(text) => Some(text),
            _ => None,
        }
    }
}

impl fmt::Display for RawValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned(value) => write!(f, "{value}"),
            Self::Signed(value) => write!(f, "{value}"),
            Self::Float(value) => write!(f, "{value}"),
            Self::Bytes(bytes) => write_hex(f, bytes),
        }
    }
}

impl fmt::Display for EngValue<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned(value) => write!(f, "{value}"),
            Self::Signed(value) => write!(f, "{value}"),
            Self::Float(value) => write!(f, "{value}"),
            Self::Bool(value) => write!(f, "{value}"),
            Self::Label(text) => write!(f, "{text}"),
            Self::Text(text) => write!(f, "{text}"),
            Self::Bytes(bytes) => write_hex(f, bytes),
        }
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    const PREVIEW: usize = 16;
    for byte in bytes.iter().take(PREVIEW) {
        write!(f, "{byte:02x}")?;
    }
    if bytes.len() > PREVIEW {
        write!(f, "… ({} bytes)", bytes.len())?;
    }
    Ok(())
}

/// One decoded parameter: which parameter, and both of its values.
#[derive(Clone, Debug)]
pub struct ParameterValue<'db, 'p> {
    /// The parameter this value belongs to.
    pub parameter: ParamId,
    /// The bits as they appeared in the packet.
    pub raw: RawValue<'p>,
    /// The value after calibration or lookup.
    pub eng: EngValue<'db, 'p>,
    /// Bit offset of the field within the packet.
    pub bit_offset: usize,
    /// Width of the field, in bits.
    pub bit_width: usize,
}

/// The result of decoding one packet.
///
/// Values are kept in decode order. If a parameter is decoded more than once — which an
/// entry list can do — the later value replaces the earlier one in place, so the packet
/// reads as a map with stable ordering, exactly as the reference implementation's dict does.
pub struct DecodedPacket<'db, 'p> {
    db: &'db XtceDb,
    data: &'p [u8],
    values: Vec<ParameterValue<'db, 'p>>,
    slots: FxHashMap<ParamId, u32>,
    container: ContainerId,
    bits_consumed: usize,
}

impl<'db, 'p> DecodedPacket<'db, 'p> {
    pub(crate) fn new(db: &'db XtceDb, data: &'p [u8], container: ContainerId) -> Self {
        Self {
            db,
            data,
            values: Vec::new(),
            slots: FxHashMap::default(),
            container,
            bits_consumed: 0,
        }
    }

    pub(crate) fn insert(&mut self, value: ParameterValue<'db, 'p>) {
        if let Some(index) = self.slots.get(&value.parameter).copied() {
            if let Some(slot) = self.values.get_mut(index as usize) {
                *slot = value;
            }
        } else {
            let index = u32::try_from(self.values.len()).unwrap_or(u32::MAX);
            self.slots.insert(value.parameter, index);
            self.values.push(value);
        }
    }

    pub(crate) fn set_container(&mut self, container: ContainerId) {
        self.container = container;
    }

    pub(crate) fn set_bits_consumed(&mut self, bits: usize) {
        self.bits_consumed = bits;
    }

    /// The database this packet was decoded against.
    #[must_use]
    pub fn db(&self) -> &'db XtceDb {
        self.db
    }

    /// The packet bytes.
    #[must_use]
    pub fn data(&self) -> &'p [u8] {
        self.data
    }

    /// The most derived container that matched.
    #[must_use]
    pub fn container(&self) -> ContainerId {
        self.container
    }

    /// Bits consumed by the entry lists that ran.
    #[must_use]
    pub fn bits_consumed(&self) -> usize {
        self.bits_consumed
    }

    /// Bits in the packet that no entry claimed.
    ///
    /// Non-zero is not an error — the reference implementation only warns — but it usually
    /// means the definition and the packet disagree, so it is worth surfacing.
    #[must_use]
    pub fn trailing_bits(&self) -> isize {
        self.data.len() as isize * 8 - self.bits_consumed as isize
    }

    /// Decoded values, in decode order.
    #[must_use]
    pub fn values(&self) -> &[ParameterValue<'db, 'p>] {
        &self.values
    }

    /// Number of decoded parameters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether nothing was decoded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// A decoded value by parameter id.
    #[must_use]
    pub fn get(&self, parameter: ParamId) -> Option<&ParameterValue<'db, 'p>> {
        let index = self.slots.get(&parameter).copied()?;
        self.values.get(index as usize)
    }

    /// A decoded value by parameter name.
    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&ParameterValue<'db, 'p>> {
        self.get(self.db.find_parameter(name)?)
    }

    /// Iterates `(name, value)` pairs in decode order.
    pub fn iter_named(&self) -> impl Iterator<Item = (&'db str, &ParameterValue<'db, 'p>)> {
        self.values.iter().map(move |value| {
            let name = self
                .db
                .parameter(value.parameter)
                .map_or("?", |parameter| self.db.name(parameter.name));
            (name, value)
        })
    }
}

impl fmt::Debug for DecodedPacket<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodedPacket")
            .field("container", &self.container)
            .field("values", &self.values.len())
            .field("bits_consumed", &self.bits_consumed)
            .finish_non_exhaustive()
    }
}
