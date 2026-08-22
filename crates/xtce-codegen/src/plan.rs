//! Deciding what can be compiled, and where every bit of it lives.
//!
//! Compilation is only possible when a container's layout is fixed at load time: every field
//! at a known offset, of a known width, with no value depending on packet content. This pass
//! establishes that, computes the offsets, and refuses anything else **by name** — it never
//! falls back to interpretation, because a silent fallback would make the whole comparison
//! meaningless.

use std::collections::HashMap;

use xtce_model::{
    Calibrator, Charset, CompareOp, ContainerId, DataEncoding, EntryKind, FloatCoding,
    IntegerCoding, MatchCriteria, ParamId, SizeSpec, StringDelimiter, TypeKind, XtceDb,
};

use crate::CodegenError;

/// How a field's bits become a value.
#[derive(Clone, Debug, PartialEq)]
pub enum Repr {
    /// Plain unsigned integer.
    Unsigned,
    /// Signed integer, in one of XTCE's three signed codings.
    Signed(IntegerCoding),
    /// IEEE-754 binary16, widened to `f64`.
    Float16,
    /// IEEE-754 binary32, widened to `f64`.
    Float32,
    /// IEEE-754 binary64.
    Float64,
    /// A boolean, true when the raw value is non-zero.
    Bool,
    /// An enumeration: `(value, max_value, label)` sorted by value.
    Enumerated(Vec<(i128, i128, String)>),
    /// Text: the raw buffer plus how to find the string inside it.
    Text {
        /// Character set of the decoded text.
        charset: TextCharset,
        /// How the string is delimited inside its buffer.
        delimiter: TextDelimiter,
    },
    /// A binary field: the bytes as they appear in the packet.
    Binary,
}

/// Character sets the generator can decode without transcoding.
///
/// Both of these validate to a `&str` that borrows the packet. Anything else — Latin-1,
/// Windows-1252, UTF-16, UTF-32 — needs a new allocation per field, which would put an
/// allocator call on the hot path of generated code whose whole purpose is not to have one.
/// Those are refused by name; the interpreter decodes them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TextCharset {
    /// `UTF-8`, validated.
    Utf8,
    /// `US-ASCII`, validated as UTF-8 and additionally checked for the high bit.
    UsAscii,
}

/// How the derived string is delimited inside its raw buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextDelimiter {
    /// The whole buffer is the string.
    WholeBuffer,
    /// The string ends at the first occurrence of these bytes.
    TerminationChar(Vec<u8>),
    /// The buffer starts with a length, in bits, of this width.
    LeadingSize {
        /// Width of the length prefix, in bits.
        size_in_bits: u32,
    },
}

impl Repr {
    /// Whether the value this produces is an integer, which decides how a comparison
    /// literal is read.
    #[must_use]
    pub fn is_integral(&self) -> bool {
        matches!(self, Self::Unsigned | Self::Signed(_) | Self::Bool)
    }

    /// Whether this field borrows from the packet rather than owning a scalar.
    #[must_use]
    pub fn borrows(&self) -> bool {
        matches!(self, Self::Text { .. } | Self::Binary)
    }
}

/// One decoded field in a flattened container.
#[derive(Clone, Debug)]
pub struct Field {
    /// The parameter this field decodes.
    pub parameter: ParamId,
    /// Name as written in the definition.
    pub xtce_name: String,
    /// Name of the generated struct field.
    pub ident: String,
    /// For a text field, the name of the companion field holding the raw buffer.
    ///
    /// XTCE gives a string two values — the buffer as allocated, and the string found inside
    /// it — and both are needed to reproduce the reference exactly, so both are stored.
    pub raw_ident: Option<String>,
    /// Bit offset from the start of the packet.
    pub bit_offset: usize,
    /// Field width in bits.
    pub bit_width: u32,
    /// How the bits become a value.
    pub repr: Repr,
}

/// One concrete container, with its whole inheritance chain flattened.
#[derive(Clone, Debug)]
pub struct ContainerPlan {
    /// Name as written in the definition.
    pub xtce_name: String,
    /// Name of the generated struct.
    pub type_ident: String,
    /// Total width of the flattened layout, in bits.
    pub bit_length: usize,
    /// Fields in decode order.
    pub fields: Vec<Field>,
}

/// One `<Comparison>` from a restriction criterion, resolved to a static bit range.
#[derive(Clone, Debug)]
pub struct Guard {
    /// The parameter being tested, for diagnostics.
    pub xtce_name: String,
    /// Where its value sits in the flattened layout.
    pub bit_offset: usize,
    /// How wide it is.
    pub bit_width: u32,
    /// How to interpret those bits.
    pub repr: Repr,
    /// The operator.
    pub operator: CompareOp,
    /// The literal, already read as an integer.
    pub value: i128,
}

/// A node of the container inheritance tree, as the dispatcher will walk it.
#[derive(Clone, Debug)]
pub struct Node {
    /// Name as written in the definition.
    pub xtce_name: String,
    /// Whether a packet may stop here.
    pub is_abstract: bool,
    /// Index into [`Plan::containers`] when a packet may stop here.
    pub plan: Option<usize>,
    /// Inheritors, each with the criteria that select it.
    pub children: Vec<(Vec<Guard>, Node)>,
}

/// Everything the emitter needs.
#[derive(Clone, Debug)]
pub struct Plan {
    /// The root the dispatcher starts from.
    pub root: Node,
    /// Every container a packet can be decoded as.
    pub containers: Vec<ContainerPlan>,
    /// Name of the root container, for diagnostics.
    pub root_name: String,
}

/// Analyses `db` from `root`, or explains what stopped it.
///
/// # Errors
///
/// Returns [`CodegenError::Unsupported`] naming the element that cannot be compiled, or
/// [`CodegenError::NoSuchContainer`] if the root does not exist.
pub fn build(db: &XtceDb, root: ContainerId) -> Result<Plan, CodegenError> {
    let mut builder = Builder {
        db,
        containers: Vec::new(),
        idents: HashMap::new(),
    };
    let root_name = builder.container_name(root)?.to_owned();
    let node = builder.node(root, &[], 0, 0)?;
    Ok(Plan {
        root: node,
        containers: builder.containers,
        root_name,
    })
}

struct Builder<'db> {
    db: &'db XtceDb,
    containers: Vec<ContainerPlan>,
    /// Generated type names already used, so two containers cannot collide after
    /// sanitisation.
    idents: HashMap<String, usize>,
}

/// Guards against a `<ContainerRefEntry>` cycle, matching the decoder's own limit.
const MAX_DEPTH: usize = 64;

impl<'db> Builder<'db> {
    fn container_name(&self, id: ContainerId) -> Result<&'db str, CodegenError> {
        self.db
            .container(id)
            .map(|container| self.db.name(container.name))
            .ok_or(CodegenError::DanglingIndex)
    }

    /// Builds one node of the dispatch tree, and the plan for it if it is concrete.
    fn node(
        &mut self,
        id: ContainerId,
        inherited: &[Field],
        bit_offset: usize,
        depth: usize,
    ) -> Result<Node, CodegenError> {
        if depth > MAX_DEPTH {
            return Err(CodegenError::Unsupported {
                element: "SequenceContainer".to_owned(),
                container: self.container_name(id)?.to_owned(),
                reason: "inheritance nests deeper than this generator will follow",
            });
        }

        let container = self.db.container(id).ok_or(CodegenError::DanglingIndex)?;
        let name = self.db.name(container.name).to_owned();

        let mut fields = inherited.to_vec();
        let mut offset = bit_offset;
        self.flatten(id, &mut fields, &mut offset, 0)?;
        assign_unique_idents(&mut fields);

        let plan = if container.is_abstract {
            None
        } else {
            let type_ident = self.unique_type_ident(&name);
            self.containers.push(ContainerPlan {
                xtce_name: name.clone(),
                type_ident,
                bit_length: offset,
                fields: fields.clone(),
            });
            Some(self.containers.len() - 1)
        };

        let mut children = Vec::new();
        for &inheritor in &container.inheritors {
            let guards = self.guards(inheritor, &fields)?;
            children.push((guards, self.node(inheritor, &fields, offset, depth + 1)?));
        }

        Ok(Node {
            xtce_name: name,
            is_abstract: container.is_abstract,
            plan,
            children,
        })
    }

    /// Appends a container's own entries to `fields`, expanding container references.
    fn flatten(
        &mut self,
        id: ContainerId,
        fields: &mut Vec<Field>,
        offset: &mut usize,
        depth: usize,
    ) -> Result<(), CodegenError> {
        if depth > MAX_DEPTH {
            return Err(CodegenError::Unsupported {
                element: "ContainerRefEntry".to_owned(),
                container: self.container_name(id)?.to_owned(),
                reason: "entry lists reference each other in a cycle",
            });
        }
        let container_name = self.container_name(id)?.to_owned();

        for entry in self.db.container_entries(id) {
            if entry.location.is_some() {
                return Err(CodegenError::Unsupported {
                    element: "LocationInContainerInBits".to_owned(),
                    container: container_name.clone(),
                    reason: "explicit placement is not compiled; the interpreter handles it",
                });
            }
            let repeat = entry.repeat.unwrap_or(1);

            match entry.kind {
                EntryKind::Container(child) => {
                    for _ in 0..repeat {
                        self.flatten(child, fields, offset, depth + 1)?;
                    }
                }
                EntryKind::Unsupported { element } => {
                    return Err(CodegenError::Unsupported {
                        element: self.db.name(element).to_owned(),
                        container: container_name.clone(),
                        reason: "entry kind is outside the modelled subset",
                    });
                }
                EntryKind::Parameter(parameter) => {
                    if repeat != 1 {
                        // A repeated parameter overwrites itself; only the cursor advance
                        // survives, which a struct field cannot express.
                        return Err(CodegenError::Unsupported {
                            element: "RepeatEntry".to_owned(),
                            container: container_name.clone(),
                            reason: "a repeated parameter has no single value to store",
                        });
                    }
                    let field = self.field(parameter, *offset, &container_name)?;
                    *offset += field.bit_width as usize;
                    fields.push(field);
                }
            }
        }
        Ok(())
    }

    fn field(
        &mut self,
        parameter: ParamId,
        bit_offset: usize,
        container: &str,
    ) -> Result<Field, CodegenError> {
        let param = self
            .db
            .parameter(parameter)
            .ok_or(CodegenError::DanglingIndex)?;
        let xtce_name = self.db.name(param.name).to_owned();
        let ty = self
            .db
            .parameter_type(param.type_id)
            .ok_or(CodegenError::DanglingIndex)?;

        let refuse = |element: &str, reason: &'static str| CodegenError::Unsupported {
            element: element.to_owned(),
            container: format!("{container}/{xtce_name}"),
            reason,
        };

        if ty.encoding.default_calibrator().is_some()
            || !ty.encoding.context_calibrators().is_empty()
        {
            // Calibration is arithmetic this generator could emit, but the interpreted path
            // sums polynomial terms in document order with exact integer powers, and any
            // difference in the last bit would be a silent divergence. Out of scope until
            // the emitted arithmetic is proved identical.
            return Err(refuse("Calibrator", "calibration is not compiled yet"));
        }
        if let Some(Calibrator::Unsupported { .. }) = ty.encoding.default_calibrator() {
            return Err(refuse(
                "Calibrator",
                "calibrator kind is outside the subset",
            ));
        }

        let (bit_width, numeric) = encoding_repr(&ty.encoding, &refuse)?;
        let repr = self.kind_repr(ty, numeric, &refuse)?;

        if repr.borrows() {
            // Text and binary fields are handed out as slices of the packet. That is only
            // possible when the field starts on a byte boundary and is a whole number of
            // bytes; otherwise every byte would have to be shifted into a new buffer, which
            // means allocating, which is what this generator exists to avoid. The
            // interpreter handles the unaligned case.
            if bit_offset % 8 != 0 || bit_width % 8 != 0 {
                return Err(refuse(
                    "sizeInBits",
                    "the field is not byte-aligned, so it cannot be borrowed from the packet",
                ));
            }
            if bit_width == 0 {
                return Err(refuse("sizeInBits", "the field is empty"));
            }
        } else if bit_width == 0 || bit_width > 64 {
            return Err(refuse(
                "sizeInBits",
                "only numeric fields of 1 to 64 bits are compiled",
            ));
        }

        Ok(Field {
            parameter,
            ident: field_ident(&xtce_name),
            raw_ident: None,
            xtce_name,
            bit_offset,
            bit_width,
            repr,
        })
    }

    /// The parameter type can override how the encoded number is presented.
    fn kind_repr(
        &self,
        ty: &xtce_model::ParameterType,
        numeric: Repr,
        refuse: &impl Fn(&str, &'static str) -> CodegenError,
    ) -> Result<Repr, CodegenError> {
        if numeric.borrows() && !matches!(ty.kind, TypeKind::String | TypeKind::Binary) {
            return Err(refuse(
                ty.kind.label(),
                "a numeric or enumerated type over a string or binary encoding is not compiled",
            ));
        }

        Ok(match &ty.kind {
            TypeKind::Integer | TypeKind::Float | TypeKind::AbsoluteTime { .. } => numeric,
            TypeKind::Boolean { .. } => Repr::Bool,
            TypeKind::Enumerated(list) => {
                if !numeric.is_integral() {
                    return Err(refuse(
                        "EnumeratedParameterType",
                        "an enumeration over a float encoding is not compiled",
                    ));
                }
                Repr::Enumerated(
                    list.entries()
                        .iter()
                        .map(|entry| {
                            (
                                entry.value,
                                entry.max_value,
                                self.db.name(entry.label).to_owned(),
                            )
                        })
                        .collect(),
                )
            }
            // A string or binary parameter type must actually carry the matching encoding.
            // XTCE does not enforce that, and the reference implementation would decode the
            // mismatch as bytes; rather than guess, this refuses and names the mismatch.
            TypeKind::String => match numeric {
                Repr::Text { .. } => numeric,
                _ => {
                    return Err(refuse(
                        "StringParameterType",
                        "the type is a string but its encoding is not a StringDataEncoding",
                    ));
                }
            },
            TypeKind::Binary => match numeric {
                Repr::Binary => numeric,
                _ => {
                    return Err(refuse(
                        "BinaryParameterType",
                        "the type is binary but its encoding is not a BinaryDataEncoding",
                    ));
                }
            },
            TypeKind::Unsupported { element } => {
                return Err(refuse(
                    self.db.name(*element),
                    "the parameter type is outside the modelled subset",
                ));
            }
            TypeKind::RelativeTime => {
                return Err(refuse(
                    ty.kind.label(),
                    "the parameter type is not compiled yet",
                ));
            }
        })
    }
}

/// The width of a string or binary field, when it is fixed at load time.
fn fixed_width(
    size: &SizeSpec,
    element: &str,
    refuse: &impl Fn(&str, &'static str) -> CodegenError,
) -> Result<u32, CodegenError> {
    match size {
        SizeSpec::Fixed(bits) => Ok(*bits),
        SizeSpec::Dynamic { .. } => Err(refuse(
            element,
            "the width comes from another parameter, so no offset after it is known at \
             generation time",
        )),
        SizeSpec::DiscreteLookup(_) => Err(refuse(
            element,
            "the width comes from a DiscreteLookupList, which is not compiled",
        )),
        SizeSpec::Unsupported { .. } => Err(refuse(element, "the width could not be modelled")),
    }
}

/// The width and numeric interpretation a data encoding implies.
fn encoding_repr(
    encoding: &DataEncoding,
    refuse: &impl Fn(&str, &'static str) -> CodegenError,
) -> Result<(u32, Repr), CodegenError> {
    Ok(match encoding {
        DataEncoding::Integer(encoding) => {
            if encoding.byte_order != xtce_model::ByteOrder::MostSignificantFirst {
                return Err(refuse(
                    "IntegerDataEncoding",
                    "leastSignificantByteFirst is not compiled yet",
                ));
            }
            let repr = match encoding.coding {
                IntegerCoding::Unsigned => Repr::Unsigned,
                other => Repr::Signed(other),
            };
            (encoding.size_in_bits, repr)
        }
        DataEncoding::Float(encoding) => {
            if encoding.byte_order != xtce_model::ByteOrder::MostSignificantFirst {
                return Err(refuse(
                    "FloatDataEncoding",
                    "leastSignificantByteFirst is not compiled yet",
                ));
            }
            if encoding.coding != FloatCoding::Ieee754 {
                return Err(refuse(
                    "FloatDataEncoding",
                    "only IEEE-754 is compiled; MIL-STD-1750A is not",
                ));
            }
            let repr = match encoding.size_in_bits {
                16 => Repr::Float16,
                32 => Repr::Float32,
                64 => Repr::Float64,
                _ => {
                    return Err(refuse(
                        "FloatDataEncoding",
                        "IEEE-754 must be 16, 32 or 64 bits",
                    ));
                }
            };
            (encoding.size_in_bits, repr)
        }
        DataEncoding::String(encoding) => {
            let charset = match encoding.charset {
                Charset::Utf8 => TextCharset::Utf8,
                Charset::UsAscii => TextCharset::UsAscii,
                _ => {
                    return Err(refuse(
                        "StringDataEncoding",
                        "only UTF-8 and US-ASCII are compiled; the others need transcoding, \
                         which would allocate per field",
                    ));
                }
            };
            let delimiter = match &encoding.delimiter {
                StringDelimiter::WholeBuffer => TextDelimiter::WholeBuffer,
                StringDelimiter::TerminationChar(bytes) => {
                    TextDelimiter::TerminationChar(bytes.clone())
                }
                StringDelimiter::LeadingSize { size_in_bits } => TextDelimiter::LeadingSize {
                    size_in_bits: *size_in_bits,
                },
            };
            let width = fixed_width(&encoding.raw_size, "StringDataEncoding", refuse)?;
            (width, Repr::Text { charset, delimiter })
        }
        DataEncoding::Binary(encoding) => {
            let width = fixed_width(&encoding.size, "BinaryDataEncoding", refuse)?;
            (width, Repr::Binary)
        }
        DataEncoding::None => {
            return Err(refuse("DataEncoding", "the parameter type has no encoding"));
        }
    })
}

impl Builder<'_> {
    /// Turns an inheritor's restriction criteria into static guards.
    fn guards(&self, id: ContainerId, fields: &[Field]) -> Result<Vec<Guard>, CodegenError> {
        let container = self.db.container(id).ok_or(CodegenError::DanglingIndex)?;
        let name = self.db.name(container.name).to_owned();
        let mut guards = Vec::new();

        for criteria in &container.restriction {
            match criteria {
                MatchCriteria::Comparison(comparison) => {
                    let field = fields
                        .iter()
                        .find(|field| field.parameter == comparison.parameter)
                        .ok_or_else(|| CodegenError::Unsupported {
                            element: "Comparison".to_owned(),
                            container: name.clone(),
                            reason: "the criterion tests a parameter this container's \
                                     ancestors do not decode",
                        })?;
                    if !field.repr.is_integral() {
                        return Err(CodegenError::Unsupported {
                            element: "Comparison".to_owned(),
                            container: name.clone(),
                            reason: "only integer-valued criteria are compiled",
                        });
                    }
                    if comparison.use_calibrated && matches!(field.repr, Repr::Enumerated(_)) {
                        return Err(CodegenError::Unsupported {
                            element: "Comparison".to_owned(),
                            container: name.clone(),
                            reason: "a criterion on a calibrated enumeration compares labels, \
                                     which is not compiled",
                        });
                    }
                    let value =
                        comparison
                            .value
                            .as_int
                            .ok_or_else(|| CodegenError::Unsupported {
                                element: "Comparison".to_owned(),
                                container: name.clone(),
                                reason: "the criterion's value is not an integer",
                            })?;
                    guards.push(Guard {
                        xtce_name: field.xtce_name.clone(),
                        bit_offset: field.bit_offset,
                        bit_width: field.bit_width,
                        repr: field.repr.clone(),
                        operator: comparison.operator,
                        value,
                    });
                }
                MatchCriteria::Boolean(_) => {
                    return Err(CodegenError::Unsupported {
                        element: "BooleanExpression".to_owned(),
                        container: name,
                        reason: "only Comparison and ComparisonList criteria are compiled",
                    });
                }
                MatchCriteria::Unsupported { element } => {
                    return Err(CodegenError::Unsupported {
                        element: self.db.name(*element).to_owned(),
                        container: name,
                        reason: "the criterion kind is outside the modelled subset",
                    });
                }
            }
        }
        Ok(guards)
    }

    fn unique_type_ident(&mut self, xtce_name: &str) -> String {
        let base = type_ident(xtce_name);
        let count = self.idents.entry(base.clone()).or_insert(0);
        *count += 1;
        if *count == 1 {
            base
        } else {
            // Two XTCE names can sanitise to the same Rust identifier; the suffix keeps the
            // generated module compiling rather than silently dropping one.
            format!("{base}{count}")
        }
    }
}

/// Makes every generated field name unique within a container.
///
/// Two XTCE names can sanitise to the same Rust identifier — `A-B` and `A_B` both become
/// `a_b` — and a text field additionally needs a companion name for its raw buffer, which
/// could itself collide with a real parameter called `X_RAW`. Resolving both here means the
/// emitter never has to think about it, and a collision produces a suffix rather than a
/// module that does not compile.
fn assign_unique_idents(fields: &mut [Field]) {
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();

    let claim = |wanted: &str, used: &mut std::collections::HashSet<String>| -> String {
        if used.insert(wanted.to_owned()) {
            return wanted.to_owned();
        }
        for suffix in 2u32.. {
            let candidate = format!("{wanted}_{suffix}");
            if used.insert(candidate.clone()) {
                return candidate;
            }
        }
        wanted.to_owned()
    };

    for field in fields.iter_mut() {
        field.ident = claim(&field.ident, &mut used);
        if field.repr.borrows() && matches!(field.repr, Repr::Text { .. }) {
            let wanted = format!("{}_raw", field.ident);
            field.raw_ident = Some(claim(&wanted, &mut used));
        }
    }
}

/// Converts an XTCE name into a `snake_case` Rust field identifier.
#[must_use]
pub fn field_ident(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 1);
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_').to_owned();
    if trimmed.is_empty() || trimmed.starts_with(|ch: char| ch.is_ascii_digit()) {
        format!("f_{trimmed}")
    } else if is_keyword(&trimmed) {
        format!("{trimmed}_")
    } else {
        trimmed
    }
}

/// Converts an XTCE name into an `UpperCamelCase` Rust type identifier.
#[must_use]
pub fn type_ident(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut capitalise = true;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            if capitalise {
                out.push(ch.to_ascii_uppercase());
                capitalise = false;
            } else {
                out.push(ch.to_ascii_lowercase());
            }
        } else {
            capitalise = true;
        }
    }
    if out.is_empty() || out.starts_with(|ch: char| ch.is_ascii_digit()) {
        format!("C{out}")
    } else {
        out
    }
}

fn is_keyword(word: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "as", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false",
        "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub",
        "ref", "return", "self", "static", "struct", "super", "trait", "true", "type", "unsafe",
        "use", "where", "while", "async", "await", "abstract", "become", "box", "do", "final",
        "macro", "override", "priv", "try", "typeof", "unsized", "virtual", "yield",
    ];
    KEYWORDS.contains(&word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_sanitised() {
        assert_eq!(field_ident("PKT_APID"), "pkt_apid");
        assert_eq!(field_ident("IDX__SCI0RAW"), "idx_sci0raw");
        assert_eq!(field_ident("A-B.C"), "a_b_c");
        assert_eq!(field_ident("_leading_"), "leading");
        assert_eq!(field_ident("2FAST"), "f_2fast");
        assert_eq!(field_ident("type"), "type_");
        assert_eq!(field_ident("!!!"), "f_");

        assert_eq!(type_ident("JPSS_ATT_EPHEM"), "JpssAttEphem");
        assert_eq!(type_ident("CCSDSPacket"), "Ccsdspacket");
        assert_eq!(type_ident("2Fast"), "C2fast");
    }
}
