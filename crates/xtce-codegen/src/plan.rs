//! Deciding what can be compiled, and where every bit of it lives.
//!
//! Compilation is only possible when a container's layout is fixed at load time: every field
//! at a known offset, of a known width, with no value depending on packet content. This pass
//! establishes that, computes the offsets, and refuses anything else **by name** — it never
//! falls back to interpretation, because a silent fallback would make the whole comparison
//! meaningless.

use std::collections::HashMap;

use xtce_model::{
    BooleanExpr, Calibrator, Charset, CompareOp, ComparisonValue, ContainerId, DataEncoding,
    EntryKind, FloatCoding, IntegerCoding, LinearAdjustment, MatchCriteria, Operand, ParamId,
    PolynomialTerm, SizeSpec, Spline, StringDelimiter, TypeKind, XtceDb,
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
    /// MIL-STD-1750A, which is 32 bits and nothing else.
    ///
    /// Not a float format in the IEEE sense at all: a 24-bit two's-complement mantissa in
    /// the top of the word and an 8-bit two's-complement exponent in the bottom, neither
    /// biased, with no implicit leading one and no infinities.
    Mil1750a,
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

/// How wide a field is.
#[derive(Clone, Copy, Debug)]
pub enum Width {
    /// Known at generation time.
    Fixed(u32),
    /// Read from another parameter while decoding.
    ///
    /// Everything after such a field has a run-time offset, which is why this exists at all:
    /// a container holding one cannot be laid out entirely in literals.
    Dynamic {
        /// Index, within the same container, of the field holding the size.
        source: usize,
        /// `slope * x + intercept`, applied to the source value.
        adjustment: Option<LinearAdjustment>,
    },
}

impl Width {
    /// The width, when it is fixed.
    #[must_use]
    pub const fn fixed(self) -> Option<u32> {
        match self {
            Self::Fixed(bits) => Some(bits),
            Self::Dynamic { .. } => None,
        }
    }
}

/// A calibrator this generator compiles.
///
/// The model's [`Calibrator`] also has an `Unsupported` variant and admits splines this
/// generator will not emit — order above one, or no points at all. Those are refused while
/// planning, so what reaches the emitter is only ever something it can write down.
#[derive(Clone, Debug)]
pub enum Calibration {
    /// Terms in document order, which is the order they must be summed in.
    Polynomial(Vec<PolynomialTerm>),
    /// Order 0 or 1, with at least one point.
    Spline(Spline),
}

/// One `<ContextCalibrator>`: a calibrator and the criteria that select it.
#[derive(Clone, Debug)]
pub struct ContextCalibration {
    /// All of these must hold. Their operands are resolved against the fields decoded
    /// *before* this one; a criterion naming anything else compares the value being decoded,
    /// which is what the reference does when a parameter "does not appear in the parsed data
    /// so far".
    pub criteria: Criterion,
    /// The calibrator to apply when they do.
    pub calibration: Calibration,
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
    /// For a calibrated field, the name of the companion field holding the engineering value.
    ///
    /// Same reason as `raw_ident`: a calibrated parameter also has two values, and the
    /// reference reports both.
    pub eng_ident: Option<String>,
    /// Calibrators tried in order before the default, each with the criteria that select it.
    ///
    /// Empty unless the definition has a `<ContextCalibratorList>`. When it does,
    /// [`Field::calibration`] is the fallback and is always present: a context list with no
    /// default would make the engineering value's *type* depend on the packet — a float when
    /// something matched and the raw integer when nothing did — and that is refused.
    pub contexts: Vec<ContextCalibration>,
    /// The calibrator applied to this field's raw value, when one is.
    ///
    /// Only ever set for a numeric field. An enumeration, a boolean and a string are all
    /// derived from the *raw* value — the interpreter returns before it reaches calibration —
    /// so a calibrator on one of those changes nothing, and carrying it here would.
    pub calibration: Option<Calibration>,
    /// Bit offset from the start of the packet, when it is known at generation time.
    ///
    /// `None` once an earlier field in the same container has a data-dependent width.
    pub bit_offset: Option<usize>,
    /// How wide the field is.
    pub width: Width,
    /// How the bits become a value.
    pub repr: Repr,
    /// Whether the field's bytes are reversed before anything else is done with them.
    ///
    /// `byteOrder="leastSignificantByteFirst"`. The reference reads the field big-endian and
    /// then reverses `ceil(width / 8)` bytes of the result, so this is a property of how the
    /// bits are *gathered* rather than of what they mean — which is why it sits beside
    /// [`Repr`] and not inside it.
    pub swap_bytes: bool,
}

impl Field {
    /// The offset and width, when both are known at generation time.
    #[must_use]
    pub fn static_span(&self) -> Option<(usize, u32)> {
        Some((self.bit_offset?, self.width.fixed()?))
    }
}

/// One concrete container, with its whole inheritance chain flattened.
#[derive(Clone, Debug)]
pub struct ContainerPlan {
    /// Name as written in the definition.
    pub xtce_name: String,
    /// Name of the generated struct.
    pub type_ident: String,
    /// Total width of the flattened layout, when every field has a fixed width.
    pub bit_length: Option<usize>,
    /// Width of the leading run of fields whose offsets are known at generation time.
    ///
    /// The generated decoder narrows the packet to this many bits once and reads that whole
    /// run with literal offsets; only what follows needs a cursor.
    pub static_prefix_bits: usize,
    /// Fields in decode order.
    pub fields: Vec<Field>,
}

impl ContainerPlan {
    /// Whether any field's width depends on packet content.
    #[must_use]
    pub fn is_dynamic(&self) -> bool {
        self.bit_length.is_none()
    }
}

/// One `<Comparison>` from a restriction criterion, resolved to a static bit range.
#[derive(Clone, Debug)]
pub struct Guard {
    /// The parameter being tested, for diagnostics.
    pub xtce_name: String,
    /// Where its value sits in the flattened layout. Always known: a criterion may only
    /// test a field the dispatcher can reach before any dynamic width intervenes.
    pub bit_offset: usize,
    /// How wide it is.
    pub bit_width: u32,
    /// How to interpret those bits.
    pub repr: Repr,
    /// Whether the field's bytes are reversed first, as [`Field::swap_bytes`].
    pub swap_bytes: bool,
    /// The operator.
    pub operator: CompareOp,
    /// The literal, already read as an integer.
    pub value: i128,
}

/// One inheritor's restriction criteria, as a tree the dispatcher can evaluate.
///
/// A `<Comparison>` or `<ComparisonList>` is a conjunction and could have stayed a flat list.
/// A `<BooleanExpression>` cannot: `<ORedConditions>` nests, and flattening it would change
/// which container a packet selects.
#[derive(Clone, Debug)]
pub enum Criterion {
    /// One field against one literal.
    Test(Guard),
    /// Every child holds. An empty one is true, which is what `all([])` means and what the
    /// interpreter computes.
    All(Vec<Criterion>),
    /// Some child holds. An empty one is false, for the same reason in reverse.
    Any(Vec<Criterion>),
}

impl Criterion {
    /// Collapses the wrappers the XML shape forces on, without changing what holds.
    ///
    /// A single `<Comparison>` arrives as a conjunction of one, and a `<BooleanExpression>`
    /// as a conjunction of one containing whatever it was. Both are true exactly when their
    /// contents are, so keeping them would only put parentheses in the generated dispatcher
    /// that a reader then has to look through.
    fn simplified(self) -> Self {
        match self {
            Self::Test(_) => self,
            Self::All(children) => Self::flatten(children, true),
            Self::Any(children) => Self::flatten(children, false),
        }
    }

    fn flatten(children: Vec<Self>, conjunction: bool) -> Self {
        let mut out = Vec::with_capacity(children.len());
        for child in children {
            match child.simplified() {
                // `a && (b && c)` is `a && b && c`, and likewise for `||`. Mixing the two
                // does not flatten: that is what the parentheses are for.
                Self::All(inner) if conjunction => out.extend(inner),
                Self::Any(inner) if !conjunction => out.extend(inner),
                other => out.push(other),
            }
        }
        if out.len() == 1 {
            if let Some(only) = out.pop() {
                return only;
            }
        }
        if conjunction {
            Self::All(out)
        } else {
            Self::Any(out)
        }
    }
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
    pub children: Vec<(Criterion, Node)>,
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
    let node = builder.node(root, &[], Some(0), 0)?;
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

/// How far into the packet the layout has reached, while it is still knowable.
///
/// Becomes `None` the moment a field's width comes from the data: from there on the offsets
/// are whatever the packet says, and the generated decoder has to carry a cursor.
type Cursor = Option<usize>;

trait CursorExt {
    fn advance(self, width: Width) -> Cursor;
}

impl CursorExt for Cursor {
    fn advance(self, width: Width) -> Cursor {
        match (self, width) {
            (Some(offset), Width::Fixed(bits)) => Some(offset + bits as usize),
            _ => None,
        }
    }
}

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
        bit_offset: Cursor,
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
            let static_prefix_bits = fields
                .iter()
                .take_while(|field| field.bit_offset.is_some())
                .filter_map(Field::static_span)
                .map(|(offset, width)| offset + width as usize)
                .last()
                .unwrap_or(0);
            let dynamic = fields.iter().any(|field| field.bit_offset.is_none());
            self.containers.push(ContainerPlan {
                xtce_name: name.clone(),
                type_ident,
                bit_length: if dynamic { None } else { offset },
                static_prefix_bits,
                fields: fields.clone(),
            });
            Some(self.containers.len() - 1)
        };

        let mut children = Vec::new();
        for &inheritor in &container.inheritors {
            let criteria = self.criteria(inheritor, &fields)?;
            children.push((criteria, self.node(inheritor, &fields, offset, depth + 1)?));
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
        offset: &mut Cursor,
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
                    let field = self.field(parameter, *offset, fields, &container_name)?;
                    *offset = offset.advance(field.width);
                    fields.push(field);
                }
            }
        }
        Ok(())
    }

    fn field(
        &mut self,
        parameter: ParamId,
        bit_offset: Cursor,
        preceding: &[Field],
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

        let (width, numeric, swap_bytes) = encoding_repr(&ty.encoding, preceding, &refuse)?;
        let repr = self.kind_repr(ty, numeric, &refuse)?;
        let calibration = Self::calibration_for(ty, &repr, &refuse)?;

        if repr.borrows() {
            // Text and binary are handed out as slices of the packet, which is only possible
            // on a byte boundary and a whole number of bytes; otherwise every byte would have
            // to be shifted into a new buffer, which means allocating — the thing this
            // generator exists to avoid. The interpreter handles those.
            //
            // A dynamic width is checked in the decoder instead, because only the packet
            // says what it is.
            if let Width::Fixed(bits) = width {
                if bit_offset.is_some_and(|offset| offset % 8 != 0) || bits % 8 != 0 {
                    return Err(refuse(
                        "sizeInBits",
                        "the field is not byte-aligned, so it cannot be borrowed from the packet",
                    ));
                }
                if bits == 0 {
                    return Err(refuse("sizeInBits", "the field is empty"));
                }
            }
        } else {
            match width {
                // A number's width picks its Rust type, so it cannot be a property of the
                // packet, and the widest integer emitted is 64 bits.
                Width::Dynamic { .. } => {
                    return Err(refuse(
                        "sizeInBits",
                        "only text and binary fields may have a data-dependent width",
                    ));
                }
                Width::Fixed(bits) if !(1..=64).contains(&bits) => {
                    return Err(refuse(
                        "sizeInBits",
                        "only numeric fields of 1 to 64 bits are compiled",
                    ));
                }
                Width::Fixed(_) => {}
            }
        }

        // A `leastSignificantByteFirst` swap of a field that is not a whole number of bytes
        // leaves bits above the width, and the reference sign-extends without masking them
        // away. Between 57 and 63 bits that can produce a number wider than an `i64`, which
        // the reference's arbitrary-precision integers hold and nothing here can.
        // Spelled with `is_some_and` rather than a `let` chain: those are stable only from
        // 1.88, and this project builds on 1.85.
        if swap_bytes
            && matches!(repr, Repr::Signed(_))
            && width.fixed().is_some_and(|bits| bits % 8 != 0 && bits > 56)
        {
            return Err(refuse(
                "IntegerDataEncoding",
                "a little-endian signed field of 57 to 63 bits can decode to a value wider \
                 than an i64 once its bytes are reversed",
            ));
        }

        // The criteria of a context calibrator are resolved against the fields decoded
        // before this one — and, when they name anything else, against this one. So the
        // current field has to be describable as a guard before it exists as a field.
        let contexts = match (bit_offset, width.fixed()) {
            (Some(offset), Some(bits)) => {
                let current = Guard {
                    xtce_name: xtce_name.clone(),
                    bit_offset: offset,
                    bit_width: bits,
                    repr: repr.clone(),
                    swap_bytes,
                    operator: CompareOp::Equal,
                    value: 0,
                };
                Self::contexts_for(ty, preceding, &current, calibration.as_ref(), &refuse)?
            }
            _ if ty.encoding.context_calibrators().is_empty() => Vec::new(),
            // Past a data-dependent width there are no literal offsets to compare against.
            _ => {
                return Err(refuse(
                    "ContextCalibrator",
                    "a context calibrator on a field whose offset is not known when the code \
                     is generated cannot have its criteria compiled",
                ));
            }
        };

        Ok(Field {
            parameter,
            ident: field_ident(&xtce_name),
            raw_ident: None,
            eng_ident: None,
            calibration,
            contexts,
            xtce_name,
            bit_offset,
            width,
            repr,
            swap_bytes,
        })
    }

    /// The calibrator that will actually run, or what stops this field being compiled.
    ///
    /// The interpreter reaches calibration only for a numeric parameter: a string returns its
    /// decoded text, and an enumeration and a boolean are both looked up from the *raw* value
    /// and return before the calibrator is consulted. So a calibrator on one of those is not
    /// refused here — it is ignored, because ignoring it is what the reference does.
    fn calibration_for(
        ty: &xtce_model::ParameterType,
        repr: &Repr,
        refuse: &impl Fn(&str, &'static str) -> CodegenError,
    ) -> Result<Option<Calibration>, CodegenError> {
        // MIL-STD-1750A belongs here too: the interpreter reaches calibration for any
        // numeric type, and a raw MIL value arrives as a float like any other. Leaving it
        // out would drop the calibrator silently, which is the shape of divergence this
        // project exists to avoid.
        let numeric = matches!(
            repr,
            Repr::Unsigned
                | Repr::Signed(_)
                | Repr::Float16
                | Repr::Float32
                | Repr::Float64
                | Repr::Mil1750a
        );
        if !numeric {
            return Ok(None);
        }

        let Some(calibrator) = ty.encoding.default_calibrator() else {
            return Ok(None);
        };

        match calibrator {
            Calibrator::Polynomial(terms) => Ok(Some(Calibration::Polynomial(terms.clone()))),
            Calibrator::Spline(spline) => {
                // Both of these are properties of the definition, so they are settled now
                // rather than left to fail once per packet. Only a query outside the point range
                // is a run-time condition.
                if spline.order > 1 {
                    return Err(refuse(
                        "SplineCalibrator",
                        "only spline orders 0 and 1 are compiled, as in the interpreter",
                    ));
                }
                if spline.points.is_empty() {
                    return Err(refuse(
                        "SplineCalibrator",
                        "a spline with no points has no value to interpolate",
                    ));
                }
                Ok(Some(Calibration::Spline(spline.clone())))
            }
            Calibrator::Unsupported { .. } => Err(refuse(
                "Calibrator",
                "calibrator kind is outside the subset",
            )),
        }
    }

    /// The `<ContextCalibratorList>`, with its criteria resolved to fields.
    ///
    /// A context criterion names a parameter, and the reference resolves it against what has
    /// been decoded so far: "If the parameter to compare is not present in the parsed data
    /// dict, we assume that we are comparing against the current raw value." So the
    /// resolution rule is entirely positional — a preceding field of this container, or else
    /// the field being calibrated — and needs no dependency graph, which is what stopped this
    /// being compiled before.
    fn contexts_for(
        ty: &xtce_model::ParameterType,
        preceding: &[Field],
        current: &Guard,
        default: Option<&Calibration>,
        refuse: &impl Fn(&str, &'static str) -> CodegenError,
    ) -> Result<Vec<ContextCalibration>, CodegenError> {
        let list = ty.encoding.context_calibrators();
        if list.is_empty() {
            return Ok(Vec::new());
        }

        // Without a default, nothing applies when no context matches, and the reference then
        // reports the *raw* value — an integer where a match would have given a float. One
        // struct field cannot be both, which is the same reason a number's width cannot come
        // from the packet.
        if default.is_none() {
            return Err(refuse(
                "ContextCalibratorList",
                "a context list with no DefaultCalibrator makes the engineering value a \
                 float when something matches and an integer when nothing does, and a \
                 generated field has one type",
            ));
        }

        let mut out = Vec::with_capacity(list.len());
        for context in list {
            let mut criteria = Vec::with_capacity(context.criteria.len());
            for criterion in &context.criteria {
                criteria.push(Self::context_criterion(
                    criterion, preceding, current, refuse,
                )?);
            }
            let calibration = match &context.calibrator {
                Calibrator::Polynomial(terms) => Calibration::Polynomial(terms.clone()),
                Calibrator::Spline(spline) => {
                    if spline.order > 1 || spline.points.is_empty() {
                        return Err(refuse(
                            "SplineCalibrator",
                            "only spline orders 0 and 1 with at least one point are compiled",
                        ));
                    }
                    Calibration::Spline(spline.clone())
                }
                Calibrator::Unsupported { .. } => {
                    return Err(refuse(
                        "Calibrator",
                        "calibrator kind is outside the subset",
                    ));
                }
            };
            out.push(ContextCalibration {
                criteria: Criterion::All(criteria).simplified(),
                calibration,
            });
        }
        Ok(out)
    }

    /// One `<ContextMatch>` child, as a criterion over fields this container has decoded.
    fn context_criterion(
        criterion: &MatchCriteria,
        preceding: &[Field],
        current: &Guard,
        refuse: &impl Fn(&str, &'static str) -> CodegenError,
    ) -> Result<Criterion, CodegenError> {
        match criterion {
            MatchCriteria::Comparison(comparison) => Ok(Criterion::Test(Self::context_guard(
                preceding,
                current,
                comparison.parameter,
                comparison.use_calibrated,
                comparison.operator,
                &comparison.value,
                refuse,
            )?)),
            MatchCriteria::Boolean(_) => Err(refuse(
                "BooleanExpression",
                "a context calibrator selected by a boolean expression is not compiled; only \
                 a Comparison or a ComparisonList is",
            )),
            MatchCriteria::Unsupported { .. } => Err(refuse(
                "ContextMatch",
                "the criterion kind is outside the modelled subset",
            )),
        }
    }

    /// The one comparison a context criterion makes.
    fn context_guard(
        preceding: &[Field],
        current: &Guard,
        parameter: ParamId,
        use_calibrated: bool,
        operator: CompareOp,
        value: &ComparisonValue,
        refuse: &impl Fn(&str, &'static str) -> CodegenError,
    ) -> Result<Guard, CodegenError> {
        let literal = value
            .as_int
            .ok_or_else(|| refuse("Comparison", "the criterion's value is not an integer"))?;

        // A preceding field of this container, by parameter — or, when there is none, the
        // field being calibrated, because that is what "not present in the parsed data so
        // far" resolves to.
        let named = preceding
            .iter()
            .rev()
            .find(|field| field.parameter == parameter);

        let Some(field) = named else {
            if use_calibrated {
                // The current value has not been calibrated yet — that is what is being
                // decided — so the reference compares its raw value whatever the attribute
                // says. Rather than reproduce that silently, it is refused: a definition
                // asking for a calibrated value that cannot exist is a definition to fix.
                return Err(refuse(
                    "Comparison",
                    "a criterion on the value being calibrated can only see its raw value, \
                     so useCalibratedValue cannot be honoured",
                ));
            }
            if !current.repr.is_integral() {
                return Err(refuse(
                    "Comparison",
                    "only integer-valued criteria are compiled",
                ));
            }
            return Ok(Guard {
                value: literal,
                operator,
                ..current.clone()
            });
        };

        let (bit_offset, bit_width) = field.static_span().ok_or_else(|| {
            refuse(
                "Comparison",
                "the criterion tests a parameter that sits after a data-dependent width, so \
                 its offset is not known",
            )
        })?;
        if !field.repr.is_integral() {
            return Err(refuse(
                "Comparison",
                "only integer-valued criteria are compiled",
            ));
        }
        if use_calibrated {
            if matches!(field.repr, Repr::Enumerated(_)) {
                return Err(refuse(
                    "Comparison",
                    "a criterion on a calibrated enumeration compares labels, which is not \
                     compiled",
                ));
            }
            if field.calibration.is_some() || !field.contexts.is_empty() {
                return Err(refuse(
                    "Comparison",
                    "the criterion asks for the calibrated value of a calibrated parameter, \
                     which is a float; comparing floats is not compiled",
                ));
            }
            if matches!(field.repr, Repr::Bool) {
                return Err(refuse(
                    "Comparison",
                    "a boolean's engineering value is 0 or 1, not its raw bits, and comparing \
                     it is not compiled",
                ));
            }
        }

        Ok(Guard {
            xtce_name: field.xtce_name.clone(),
            bit_offset,
            bit_width,
            repr: field.repr.clone(),
            swap_bytes: field.swap_bytes,
            operator,
            value: literal,
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
            // An entry naming an array is expanded into one entry per element when the file
            // is loaded, so a field of this type is a parameter referenced some other way —
            // as a criterion's operand, say — and there is no single value to give it.
            TypeKind::Array { .. } | TypeKind::Aggregate { .. } => {
                return Err(refuse(
                    ty.kind.label(),
                    "an array or an aggregate is expanded into its leaves; the whole of it \
                     has no single value",
                ));
            }
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

/// How wide a string or binary field is: a literal, or a reference to an earlier field.
fn size_width(
    size: &SizeSpec,
    element: &str,
    preceding: &[Field],
    refuse: &impl Fn(&str, &'static str) -> CodegenError,
) -> Result<Width, CodegenError> {
    match size {
        SizeSpec::Fixed(bits) => Ok(Width::Fixed(*bits)),
        SizeSpec::Dynamic {
            parameter,
            adjustment,
            use_calibrated,
        } => {
            let source = preceding
                .iter()
                .position(|field| field.parameter == *parameter)
                .ok_or_else(|| {
                    refuse(
                        element,
                        "the size names a parameter this container does not decode before it",
                    )
                })?;
            let repr = preceding.get(source).map(|field| &field.repr);
            // The source must be a plain integer. No calibrator is compiled, so for those the
            // engineering and raw values are the same number and `useCalibratedValue` cannot
            // change the answer — which is why it can be ignored here. For an enumeration or
            // a boolean it would change the answer, so those are refused rather than guessed.
            if !matches!(repr, Some(Repr::Unsigned | Repr::Signed(_))) {
                return Err(refuse(
                    element,
                    "the size names a parameter that is not a plain integer",
                ));
            }
            let _ = use_calibrated;
            Ok(Width::Dynamic {
                source,
                adjustment: *adjustment,
            })
        }
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
    preceding: &[Field],
    refuse: &impl Fn(&str, &'static str) -> CodegenError,
) -> Result<(Width, Repr, bool), CodegenError> {
    let swaps = |order| order == xtce_model::ByteOrder::LeastSignificantFirst;
    Ok(match encoding {
        DataEncoding::Integer(encoding) => {
            let repr = match encoding.coding {
                IntegerCoding::Unsigned => Repr::Unsigned,
                other => Repr::Signed(other),
            };
            (
                Width::Fixed(encoding.size_in_bits),
                repr,
                swaps(encoding.byte_order),
            )
        }
        DataEncoding::Float(encoding) => {
            let repr = match (encoding.coding, encoding.size_in_bits) {
                (FloatCoding::Ieee754, 16) => Repr::Float16,
                (FloatCoding::Ieee754, 32) => Repr::Float32,
                (FloatCoding::Ieee754, 64) => Repr::Float64,
                (FloatCoding::Ieee754, _) => {
                    return Err(refuse(
                        "FloatDataEncoding",
                        "IEEE-754 must be 16, 32 or 64 bits",
                    ));
                }
                (FloatCoding::MilStd1750A, 32) => Repr::Mil1750a,
                // The reference refuses to load a definition that says otherwise, and the
                // interpreter refuses to decode one. There is no wider form of the format.
                (FloatCoding::MilStd1750A, _) => {
                    return Err(refuse(
                        "FloatDataEncoding",
                        "MIL-STD-1750A is a 32-bit format and has no other width",
                    ));
                }
            };
            (
                Width::Fixed(encoding.size_in_bits),
                repr,
                swaps(encoding.byte_order),
            )
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
            let width = size_width(&encoding.raw_size, "StringDataEncoding", preceding, refuse)?;
            // No swap: a string's byte order reaches only the UTF-16 and UTF-32 decoders,
            // and this generator compiles neither. For UTF-8 and US-ASCII the interpreter
            // ignores it, so there is nothing to reproduce.
            (width, Repr::Text { charset, delimiter }, false)
        }
        DataEncoding::Binary(encoding) => {
            let width = size_width(&encoding.size, "BinaryDataEncoding", preceding, refuse)?;
            // A binary field has no byte order in XTCE: it is the bytes as they lie.
            (width, Repr::Binary, false)
        }
        DataEncoding::None => {
            return Err(refuse("DataEncoding", "the parameter type has no encoding"));
        }
    })
}

/// The four things a `<Comparison>` and a `<Condition>` both say, and the name of whichever
/// one said them.
struct Test<'a> {
    element: &'static str,
    parameter: ParamId,
    use_calibrated: bool,
    operator: CompareOp,
    value: &'a ComparisonValue,
}

impl Builder<'_> {
    /// Turns an inheritor's restriction criteria into a tree the dispatcher can evaluate.
    fn criteria(&self, id: ContainerId, fields: &[Field]) -> Result<Criterion, CodegenError> {
        let container = self.db.container(id).ok_or(CodegenError::DanglingIndex)?;
        let name = self.db.name(container.name).to_owned();
        let mut criteria = Vec::new();

        // Several `<RestrictionCriteria>` children are a conjunction, as are the entries of a
        // `<ComparisonList>`; the model has already flattened the latter into this list.
        for criterion in &container.restriction {
            criteria.push(match criterion {
                MatchCriteria::Comparison(comparison) => Criterion::Test(Self::guard(
                    fields,
                    &name,
                    &Test {
                        element: "Comparison",
                        parameter: comparison.parameter,
                        use_calibrated: comparison.use_calibrated,
                        operator: comparison.operator,
                        value: &comparison.value,
                    },
                )?),
                MatchCriteria::Boolean(expr) => Self::boolean(expr, fields, &name)?,
                MatchCriteria::Unsupported { element } => {
                    return Err(CodegenError::Unsupported {
                        element: self.db.name(*element).to_owned(),
                        container: name,
                        reason: "the criterion kind is outside the modelled subset",
                    });
                }
            });
        }
        Ok(Criterion::All(criteria).simplified())
    }

    /// A `<BooleanExpression>` as a criterion tree.
    fn boolean(
        expr: &BooleanExpr,
        fields: &[Field],
        container: &str,
    ) -> Result<Criterion, CodegenError> {
        let refuse = |reason: &'static str| CodegenError::Unsupported {
            element: "Condition".to_owned(),
            container: container.to_owned(),
            reason,
        };

        Ok(match expr {
            BooleanExpr::And(children) => Criterion::All(
                children
                    .iter()
                    .map(|child| Self::boolean(child, fields, container))
                    .collect::<Result<_, _>>()?,
            ),
            BooleanExpr::Or(children) => Criterion::Any(
                children
                    .iter()
                    .map(|child| Self::boolean(child, fields, container))
                    .collect::<Result<_, _>>()?,
            ),
            BooleanExpr::Condition(condition) => {
                let Operand::Parameter {
                    parameter,
                    use_calibrated,
                } = condition.left
                else {
                    // The model takes the first two operands in document order, so a
                    // `<Value>` written before the `<ParameterInstanceRef>` lands here. The
                    // interpreter compares it as *text* against whatever the right-hand side
                    // is, which is a defined behaviour rather than an error — and one this
                    // generator does not reproduce.
                    return Err(refuse(
                        "a literal on the left of a condition is compared as text, which is \
                         not compiled",
                    ));
                };
                let Operand::Literal(value) = condition.right else {
                    // Comparing two decoded parameters has five type-pair cases and a
                    // Python-compatibility answer for text against a number. Nothing in
                    // reach uses one, so there would be nothing to check a guess against.
                    return Err(refuse(
                        "a condition between two parameters is not compiled; only a \
                         parameter against a literal is",
                    ));
                };
                Criterion::Test(Self::guard(
                    fields,
                    container,
                    &Test {
                        element: "Condition",
                        parameter,
                        use_calibrated,
                        operator: condition.operator,
                        value: &value,
                    },
                )?)
            }
        })
    }

    /// One field-against-literal test, from either a `<Comparison>` or a `<Condition>`.
    ///
    /// The two elements say the same thing in different XML, and the interpreter evaluates
    /// them through the same `test_literal`, so they compile the same way.
    fn guard(fields: &[Field], container: &str, test: &Test<'_>) -> Result<Guard, CodegenError> {
        let &Test {
            element,
            parameter,
            use_calibrated,
            operator,
            value,
        } = test;
        let refuse = |reason: &'static str| CodegenError::Unsupported {
            element: element.to_owned(),
            container: container.to_owned(),
            reason,
        };

        let field = fields
            .iter()
            .find(|field| field.parameter == parameter)
            .ok_or_else(|| {
                refuse("the criterion tests a parameter this container's ancestors do not decode")
            })?;

        // The dispatcher tests criteria before decoding anything, so it can only reach
        // fields whose offset is a literal.
        let (bit_offset, bit_width) = field.static_span().ok_or_else(|| {
            refuse(
                "the criterion tests a parameter that sits after a data-dependent width, so \
                 its offset is not known",
            )
        })?;

        if !field.repr.is_integral() {
            return Err(refuse("only integer-valued criteria are compiled"));
        }

        // `useCalibratedValue` defaults to *true*, so most criteria take this path. For a
        // plain integer the engineering value is the raw one and there is nothing to do; for
        // anything the interpreter reports differently, the two would silently select
        // different containers.
        if use_calibrated {
            if matches!(field.repr, Repr::Enumerated(_)) {
                return Err(refuse(
                    "a criterion on a calibrated enumeration compares labels, which is not \
                     compiled",
                ));
            }
            if field.calibration.is_some() {
                return Err(refuse(
                    "the criterion asks for the calibrated value of a calibrated parameter, \
                     which is a float; comparing floats in the dispatcher is not compiled",
                ));
            }
            if matches!(field.repr, Repr::Bool) {
                return Err(refuse(
                    "a boolean's engineering value is 0 or 1, not its raw bits, and comparing \
                     it is not compiled",
                ));
            }
        }

        let literal = value
            .as_int
            .ok_or_else(|| refuse("the criterion's value is not an integer"))?;

        Ok(Guard {
            xtce_name: field.xtce_name.clone(),
            bit_offset,
            bit_width,
            repr: field.repr.clone(),
            swap_bytes: field.swap_bytes,
            operator,
            value: literal,
        })
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
            let wanted = format!("{}_raw", field.ident.trim_end_matches('_'));
            field.raw_ident = Some(claim(&wanted, &mut used));
        }
        if field.calibration.is_some() {
            // `field_ident` escapes a keyword by appending an underscore, so a parameter
            // called SELF is `self_` and the companion would be `self__eng`.
            let wanted = format!("{}_eng", field.ident.trim_end_matches('_'));
            field.eng_ident = Some(claim(&wanted, &mut used));
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
