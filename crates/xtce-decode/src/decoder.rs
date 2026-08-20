//! The interpreted decoder: walk the IR, read bits, produce values.

use std::borrow::Cow;

use xtce_model::{
    BooleanExpr, Calibrator, Comparison, Condition, ContainerId, DataEncoding, DiscreteLookup,
    EntryKind, FloatCoding, IntegerCoding, LocationReference, MatchCriteria, Operand, ParamId,
    ParameterType, SizeSpec, StringDelimiter, TypeKind, XtceDb,
};

use crate::bits::{BitCursor, ones_complement, sign_magnitude, swap_byte_order, twos_complement};
use crate::calibrate::{self, CalibrationInput};
use crate::charset;
use crate::error::DecodeError;
use crate::value::{DecodedPacket, EngValue, ParameterValue, RawValue};

/// Guards against `<ContainerRefEntry>` cycles.
///
/// Base-container inheritance is proved acyclic when the database loads, but an entry list
/// can also reference a container, and nothing in XTCE forbids that reference from coming
/// back around. Bounding the depth turns what would be a stack overflow into an error.
const MAX_CONTAINER_DEPTH: usize = 64;

/// Decodes packets against one XTCE database, starting from one root container.
///
/// Immutable and cheap to clone, so a single decoder can be shared across threads.
#[derive(Clone, Copy)]
pub struct Decoder<'db> {
    db: &'db XtceDb,
    root: ContainerId,
}

impl<'db> Decoder<'db> {
    /// Builds a decoder rooted at the database's default root container.
    ///
    /// # Errors
    ///
    /// [`DecodeError::AmbiguousRoot`] when no conventional root name is present and more
    /// than one container has no base.
    pub fn new(db: &'db XtceDb) -> Result<Self, DecodeError> {
        let root = db
            .default_root_container()
            .ok_or_else(|| DecodeError::AmbiguousRoot {
                candidates: db.root_containers().len(),
            })?;
        Ok(Self { db, root })
    }

    /// Builds a decoder rooted at a named container.
    ///
    /// # Errors
    ///
    /// [`DecodeError::NoSuchContainer`] if the name does not resolve.
    pub fn with_root(db: &'db XtceDb, name: &str) -> Result<Self, DecodeError> {
        let root = db
            .find_container(name)
            .ok_or_else(|| DecodeError::NoSuchContainer {
                name: name.to_owned(),
            })?;
        Ok(Self { db, root })
    }

    /// The database being decoded against.
    #[must_use]
    pub fn db(&self) -> &'db XtceDb {
        self.db
    }

    /// The container decoding starts from.
    #[must_use]
    pub fn root(&self) -> ContainerId {
        self.root
    }

    /// Decodes one packet.
    ///
    /// Starts at the root container, decodes its entry list, then descends to whichever
    /// inheritor's restriction criteria the decoded values satisfy, repeating until a
    /// concrete container is reached.
    ///
    /// # Errors
    ///
    /// See [`DecodeError`]. Notably, a packet whose type the definition does not describe
    /// yields [`DecodeError::UnrecognizedPacket`] rather than a partial result.
    pub fn decode<'p>(&self, data: &'p [u8]) -> Result<DecodedPacket<'db, 'p>, DecodeError> {
        let mut packet = DecodedPacket::new(self.db, data, self.root);
        let mut cursor = BitCursor::new(data);
        let mut current = self.root;

        loop {
            self.decode_container(current, &mut cursor, &mut packet, 0)?;

            let container = self
                .db
                .container(current)
                .ok_or_else(|| DecodeError::dangling_container(current))?;

            let mut matched: Option<ContainerId> = None;
            let mut extra: Vec<ContainerId> = Vec::new();
            for &inheritor in &container.inheritors {
                if self.inheritor_matches(inheritor, &packet)? {
                    match matched {
                        None => matched = Some(inheritor),
                        Some(_) => extra.push(inheritor),
                    }
                }
            }

            if !extra.is_empty() {
                let mut candidates: Vec<ContainerId> = matched.into_iter().collect();
                candidates.extend(extra);
                return Err(DecodeError::AmbiguousPacket {
                    container: self.container_name(current),
                    candidates: candidates
                        .into_iter()
                        .map(|id| self.container_name(id))
                        .collect(),
                });
            }

            if let Some(next) = matched {
                current = next;
            } else {
                if container.is_abstract {
                    return Err(DecodeError::UnrecognizedPacket {
                        container: self.container_name(current),
                        candidates: container
                            .inheritors
                            .iter()
                            .map(|&id| self.container_name(id))
                            .collect(),
                    });
                }
                break;
            }
        }

        packet.set_container(current);
        packet.set_bits_consumed(cursor.position());
        Ok(packet)
    }

    /// Decodes one container's own entry list, expanding `<ContainerRefEntry>` inline.
    ///
    /// Base-container entries are *not* decoded here: they were already decoded on the way
    /// down from the root, which is the direction XTCE inheritance is actually traversed.
    fn decode_container<'p>(
        &self,
        id: ContainerId,
        cursor: &mut BitCursor<'p>,
        packet: &mut DecodedPacket<'db, 'p>,
        depth: usize,
    ) -> Result<(), DecodeError> {
        if depth > MAX_CONTAINER_DEPTH {
            return Err(DecodeError::Unsupported {
                element: "ContainerRefEntry".to_owned(),
                context: format!(
                    "{} (nesting exceeded {MAX_CONTAINER_DEPTH} levels; the entry list is probably cyclic)",
                    self.container_name(id)
                ),
            });
        }

        let container_start = cursor.position();
        for entry in self.db.container_entries(id) {
            if let Some(location) = entry.location {
                let base = match location.reference {
                    LocationReference::PreviousEntry => cursor.position(),
                    LocationReference::ContainerStart => container_start,
                    LocationReference::ContainerEnd | LocationReference::NextEntry => {
                        return Err(DecodeError::Unsupported {
                            element: "LocationInContainerInBits".to_owned(),
                            context: format!(
                                "{} (referenceLocation containerEnd/nextEntry needs a size this \
                                 decoder does not know until the container is finished)",
                                self.container_name(id)
                            ),
                        });
                    }
                };
                let target = i64::try_from(base).unwrap_or(i64::MAX) + location.offset_in_bits;
                cursor.seek(usize::try_from(target).unwrap_or(0));
            }

            for _ in 0..entry.repeat.unwrap_or(1) {
                match entry.kind {
                    EntryKind::Parameter(parameter) => {
                        self.decode_parameter(parameter, cursor, packet)?;
                    }
                    EntryKind::Container(child) => {
                        self.decode_container(child, cursor, packet, depth + 1)?;
                    }
                    EntryKind::Unsupported { element } => {
                        return Err(DecodeError::Unsupported {
                            element: self.db.name(element).to_owned(),
                            context: format!("entry list of {}", self.container_name(id)),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn decode_parameter<'p>(
        &self,
        id: ParamId,
        cursor: &mut BitCursor<'p>,
        packet: &mut DecodedPacket<'db, 'p>,
    ) -> Result<(), DecodeError> {
        let parameter = self
            .db
            .parameter(id)
            .ok_or_else(|| DecodeError::dangling_parameter(id))?;
        let name = self.db.name(parameter.name);
        let ty = self
            .db
            .parameter_type(parameter.type_id)
            .ok_or(DecodeError::DanglingIndex {
                what: "parameter type",
            })?;

        let bit_offset = cursor.position();
        let (raw, eng) = self.decode_value(ty, name, cursor, packet)?;
        packet.insert(ParameterValue {
            parameter: id,
            raw,
            eng,
            bit_offset,
            bit_width: cursor.position().saturating_sub(bit_offset),
        });
        Ok(())
    }

    fn decode_value<'p>(
        &self,
        ty: &'db ParameterType,
        name: &'db str,
        cursor: &mut BitCursor<'p>,
        packet: &DecodedPacket<'db, 'p>,
    ) -> Result<(RawValue<'p>, EngValue<'db, 'p>), DecodeError> {
        if let TypeKind::Unsupported { element } = ty.kind {
            return Err(DecodeError::Unsupported {
                element: self.db.name(element).to_owned(),
                context: format!("parameter {name}"),
            });
        }

        // A string is the one type whose engineering value is derived from its own raw
        // buffer rather than from a numeric conversion, so it takes a separate path. Other
        // types that happen to carry a string encoding — a boolean, say — fall through and
        // are treated as the byte buffer they are, which is what the reference does.
        if matches!(ty.kind, TypeKind::String) {
            let raw = self.read_string_raw(ty, name, cursor, packet)?;
            let RawValue::Bytes(buffer) = raw else {
                return Err(DecodeError::DanglingIndex {
                    what: "string buffer",
                });
            };
            let text = match &buffer {
                Cow::Borrowed(slice) => Self::decode_string(ty, name, slice)?,
                // The buffer was assembled from an unaligned read, so it is owned here and
                // the decoded text cannot borrow from it.
                Cow::Owned(owned) => Cow::Owned(Self::decode_string(ty, name, owned)?.into_owned()),
            };
            return Ok((RawValue::Bytes(buffer), EngValue::Text(text)));
        }

        let raw = self.read_raw(ty, name, cursor, packet)?;

        // Enumerations and booleans look up the *raw* value, never the calibrated one:
        // XTCE 4.3.2.4.3.6 defines the lookup that way, and a calibrator on the underlying
        // encoding does not change which label applies.
        match &ty.kind {
            TypeKind::Enumerated(list) => {
                let value = raw
                    .as_i128()
                    .ok_or_else(|| DecodeError::UnknownEnumeration {
                        parameter: name.to_owned(),
                        value: 0,
                    })?;
                let label =
                    list.label_for(value)
                        .ok_or_else(|| DecodeError::UnknownEnumeration {
                            parameter: name.to_owned(),
                            value,
                        })?;
                return Ok((raw, EngValue::Label(self.db.name(label))));
            }
            TypeKind::Boolean { .. } => {
                let truthy = match &raw {
                    RawValue::Unsigned(value) => *value != 0,
                    RawValue::Signed(value) => *value != 0,
                    RawValue::Float(value) => *value != 0.0,
                    RawValue::Bytes(bytes) => !bytes.is_empty(),
                };
                return Ok((raw, EngValue::Bool(truthy)));
            }
            _ => {}
        }

        let eng = self.calibrate(ty, name, &raw, packet)?;
        Ok((raw, eng))
    }

    /// Applies context and default calibrators, in the reference's order and semantics.
    fn calibrate<'p>(
        &self,
        ty: &'db ParameterType,
        name: &'db str,
        raw: &RawValue<'p>,
        packet: &DecodedPacket<'db, 'p>,
    ) -> Result<EngValue<'db, 'p>, DecodeError> {
        let input = match raw {
            RawValue::Unsigned(value) => CalibrationInput::Integer(i128::from(*value)),
            RawValue::Signed(value) => CalibrationInput::Integer(i128::from(*value)),
            RawValue::Float(value) => CalibrationInput::Float(*value),
            // Binary fields have no calibrators; the engineering value is the buffer.
            // Cloning a `Cow::Borrowed` is free, which is the byte-aligned common case.
            RawValue::Bytes(bytes) => return Ok(EngValue::Bytes(bytes.clone())),
        };

        for context in ty.encoding.context_calibrators() {
            let mut all = true;
            for criteria in &context.criteria {
                if !self.evaluate(criteria, packet, Some(raw), name)? {
                    all = false;
                    break;
                }
            }
            if all {
                return Ok(EngValue::Float(self.run_calibrator(
                    &context.calibrator,
                    input,
                    name,
                )?));
            }
        }

        if let Some(calibrator) = ty.encoding.default_calibrator() {
            return Ok(EngValue::Float(
                self.run_calibrator(calibrator, input, name)?,
            ));
        }

        Ok(match raw {
            RawValue::Unsigned(value) => EngValue::Unsigned(*value),
            RawValue::Signed(value) => EngValue::Signed(*value),
            RawValue::Float(value) => EngValue::Float(*value),
            RawValue::Bytes(bytes) => EngValue::Bytes(bytes.clone()),
        })
    }

    fn run_calibrator(
        &self,
        calibrator: &Calibrator,
        input: CalibrationInput,
        name: &str,
    ) -> Result<f64, DecodeError> {
        if let Calibrator::Unsupported { element } = calibrator {
            return Err(DecodeError::Unsupported {
                element: self.db.name(*element).to_owned(),
                context: format!("calibrator for {name}"),
            });
        }
        calibrate::apply(calibrator, input).map_err(|error| DecodeError::Calibration {
            parameter: name.to_owned(),
            reason: error.to_string(),
        })
    }

    fn read_raw<'p>(
        &self,
        ty: &'db ParameterType,
        name: &'db str,
        cursor: &mut BitCursor<'p>,
        packet: &DecodedPacket<'db, 'p>,
    ) -> Result<RawValue<'p>, DecodeError> {
        match &ty.encoding {
            DataEncoding::Integer(encoding) => {
                let width = encoding.size_in_bits;
                let mut bits = cursor
                    .read_uint(width)
                    .map_err(|source| DecodeError::Bits {
                        parameter: name.to_owned(),
                        source,
                    })?;
                if encoding.byte_order == xtce_model::ByteOrder::LeastSignificantFirst {
                    bits = swap_byte_order(bits, width);
                }
                Ok(match encoding.coding {
                    IntegerCoding::Unsigned => RawValue::Unsigned(bits),
                    IntegerCoding::TwosComplement => RawValue::Signed(twos_complement(bits, width)),
                    IntegerCoding::SignMagnitude => RawValue::Signed(sign_magnitude(bits, width)),
                    IntegerCoding::OnesComplement => RawValue::Signed(ones_complement(bits, width)),
                })
            }

            DataEncoding::Float(encoding) => {
                let width = encoding.size_in_bits;
                let mut bits = cursor
                    .read_uint(width)
                    .map_err(|source| DecodeError::Bits {
                        parameter: name.to_owned(),
                        source,
                    })?;
                if encoding.byte_order == xtce_model::ByteOrder::LeastSignificantFirst {
                    bits = swap_byte_order(bits, width);
                }
                let value = match encoding.coding {
                    FloatCoding::Ieee754 => {
                        ieee754(bits, width).ok_or_else(|| DecodeError::Unsupported {
                            element: "FloatDataEncoding".to_owned(),
                            context: format!("{name}: IEEE-754 at {width} bits"),
                        })?
                    }
                    FloatCoding::MilStd1750A => mil_std_1750a(bits),
                };
                Ok(RawValue::Float(value))
            }

            DataEncoding::Binary(encoding) => {
                let width = self.resolve_size(&encoding.size, packet, name)?;
                let bytes = cursor
                    .read_bytes(width)
                    .map_err(|source| DecodeError::Bits {
                        parameter: name.to_owned(),
                        source,
                    })?;
                Ok(RawValue::Bytes(bytes))
            }

            DataEncoding::String(_) => self.read_string_raw(ty, name, cursor, packet),

            DataEncoding::None => Err(DecodeError::Unsupported {
                element: "DataEncoding".to_owned(),
                context: format!("{name} has no data encoding"),
            }),
        }
    }

    fn read_string_raw<'p>(
        &self,
        ty: &'db ParameterType,
        name: &'db str,
        cursor: &mut BitCursor<'p>,
        packet: &DecodedPacket<'db, 'p>,
    ) -> Result<RawValue<'p>, DecodeError> {
        let DataEncoding::String(encoding) = &ty.encoding else {
            return Err(DecodeError::DanglingIndex {
                what: "string encoding",
            });
        };
        let width = self.resolve_size(&encoding.raw_size, packet, name)?;
        // Strings are padded on the right: the characters start at bit 0 of the buffer, so
        // slack has to go after them, not before as it does for a binary field.
        let bytes = cursor
            .read_bytes_left_aligned(width)
            .map_err(|source| DecodeError::Bits {
                parameter: name.to_owned(),
                source,
            })?;
        Ok(RawValue::Bytes(bytes))
    }

    /// The engineering value of a string: the raw buffer, delimited and decoded.
    fn decode_string<'p>(
        ty: &ParameterType,
        name: &str,
        buffer: &'p [u8],
    ) -> Result<Cow<'p, str>, DecodeError> {
        let DataEncoding::String(encoding) = &ty.encoding else {
            return Ok(Cow::Borrowed(""));
        };

        let text_bytes: Cow<'p, [u8]> = match &encoding.delimiter {
            StringDelimiter::WholeBuffer => Cow::Borrowed(buffer),
            StringDelimiter::TerminationChar(terminator) => {
                // A plain byte search, as the reference does. For UTF-16 and UTF-32 the
                // terminator is a whole code unit, so this cannot split one.
                let end = find_subslice(buffer, terminator).ok_or_else(|| {
                    DecodeError::UnterminatedString {
                        parameter: name.to_owned(),
                        bytes: buffer.len(),
                    }
                })?;
                Cow::Borrowed(buffer.get(..end).unwrap_or_default())
            }
            StringDelimiter::LeadingSize { size_in_bits } => {
                let mut prefix = BitCursor::new(buffer);
                let length_bits =
                    prefix
                        .read_uint(*size_in_bits)
                        .map_err(|source| DecodeError::Bits {
                            parameter: name.to_owned(),
                            source,
                        })?;
                if length_bits % 8 != 0 {
                    return Err(DecodeError::BadFieldSize {
                        parameter: name.to_owned(),
                        bits: i64::try_from(length_bits).unwrap_or(i64::MAX),
                    });
                }
                // The length prefix need not be a whole number of bytes, so the text may
                // start at an unaligned bit position; the cursor handles that.
                prefix
                    .read_bytes(usize::try_from(length_bits).unwrap_or(0))
                    .map_err(|source| DecodeError::Bits {
                        parameter: name.to_owned(),
                        source,
                    })?
            }
        };

        let invalid = |len: usize| DecodeError::InvalidText {
            parameter: name.to_owned(),
            charset: charset::name(encoding.charset),
            bytes: len,
        };

        match text_bytes {
            Cow::Borrowed(slice) => charset::decode(slice, encoding.charset, encoding.byte_order)
                .map_err(|_| invalid(slice.len())),
            Cow::Owned(owned) => charset::decode(&owned, encoding.charset, encoding.byte_order)
                .map(|text| Cow::Owned(text.into_owned()))
                .map_err(|_| invalid(owned.len())),
        }
    }

    fn resolve_size<'p>(
        &self,
        spec: &SizeSpec,
        packet: &DecodedPacket<'db, 'p>,
        name: &str,
    ) -> Result<usize, DecodeError> {
        let bits: i64 = match spec {
            SizeSpec::Fixed(bits) => i64::from(*bits),

            SizeSpec::Dynamic {
                parameter,
                use_calibrated,
                adjustment,
            } => {
                let value =
                    packet
                        .get(*parameter)
                        .ok_or_else(|| DecodeError::ParameterNotYetDecoded {
                            context: "dynamic field size",
                            parameter: self.parameter_name(*parameter),
                        })?;
                let integral = if *use_calibrated {
                    value.eng.as_i128()
                } else {
                    value.raw.as_i128()
                };
                // Integral size with no adjustment: stay in integers so that a size beyond
                // 2^53 is not silently rounded.
                if let (Some(exact), None) = (integral, adjustment) {
                    i64::try_from(exact).unwrap_or(i64::MAX)
                } else {
                    {
                        let numeric = if *use_calibrated {
                            value.eng.as_f64()
                        } else {
                            value.raw.as_f64()
                        }
                        .ok_or_else(|| DecodeError::BadFieldSize {
                            parameter: name.to_owned(),
                            bits: 0,
                        })?;
                        let adjusted = adjustment.map_or(numeric, |a| a.apply(numeric));
                        // Truncation toward zero, matching the reference's `int(...)`.
                        adjusted as i64
                    }
                }
            }

            SizeSpec::DiscreteLookup(lookups) => self.discrete_lookup(lookups, packet, name)?,

            SizeSpec::Unsupported { element } => {
                return Err(DecodeError::Unsupported {
                    element: self.db.name(*element).to_owned(),
                    context: format!("size of {name}"),
                });
            }
        };

        usize::try_from(bits).map_err(|_| DecodeError::BadFieldSize {
            parameter: name.to_owned(),
            bits,
        })
    }

    fn discrete_lookup<'p>(
        &self,
        lookups: &[DiscreteLookup],
        packet: &DecodedPacket<'db, 'p>,
        name: &str,
    ) -> Result<i64, DecodeError> {
        for lookup in lookups {
            let mut all = true;
            for criteria in &lookup.criteria {
                if !self.evaluate(criteria, packet, None, name)? {
                    all = false;
                    break;
                }
            }
            if all {
                return Ok(lookup.value);
            }
        }
        Err(DecodeError::NoDiscreteLookupMatch {
            parameter: name.to_owned(),
        })
    }

    // ------------------------------------------------------------- criteria evaluation

    fn inheritor_matches(
        &self,
        id: ContainerId,
        packet: &DecodedPacket<'db, '_>,
    ) -> Result<bool, DecodeError> {
        let container = self
            .db
            .container(id)
            .ok_or_else(|| DecodeError::dangling_container(id))?;
        // An empty restriction list matches, which is what `all([])` does in the reference.
        // It is usually a modelling mistake in the database, and it surfaces as an
        // ambiguous-packet error rather than being quietly ignored.
        for criteria in &container.restriction {
            if !self.evaluate(criteria, packet, None, self.db.name(container.name))? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Evaluates one match criterion.
    ///
    /// `current` is the raw value of the parameter being decoded right now, which is not yet
    /// in the packet. A context calibrator may compare against its own uncalibrated value,
    /// and this is the only way to reach it.
    fn evaluate(
        &self,
        criteria: &MatchCriteria,
        packet: &DecodedPacket<'db, '_>,
        current: Option<&RawValue<'_>>,
        context: &str,
    ) -> Result<bool, DecodeError> {
        match criteria {
            MatchCriteria::Comparison(comparison) => {
                self.evaluate_comparison(comparison, packet, current)
            }
            MatchCriteria::Boolean(expr) => self.evaluate_boolean(expr, packet),
            MatchCriteria::Unsupported { element } => Err(DecodeError::Unsupported {
                element: self.db.name(*element).to_owned(),
                context: format!("match criteria of {context}"),
            }),
        }
    }

    fn evaluate_comparison(
        &self,
        comparison: &Comparison,
        packet: &DecodedPacket<'db, '_>,
        current: Option<&RawValue<'_>>,
    ) -> Result<bool, DecodeError> {
        let literal = self.db.name(comparison.value);
        let name = self.parameter_name(comparison.parameter);

        let ordering = match packet.get(comparison.parameter) {
            Some(value) => {
                if comparison.use_calibrated {
                    compare_eng(&value.eng, literal, &name)?
                } else {
                    compare_raw(&value.raw, literal, &name)?
                }
            }
            // The referenced parameter is not in the packet, so this must be a comparison
            // against the value currently being decoded.
            None => match current {
                Some(raw) => compare_raw(raw, literal, &name)?,
                None => {
                    return Err(DecodeError::ParameterNotYetDecoded {
                        context: "comparison",
                        parameter: name,
                    });
                }
            },
        };
        Ok(comparison.operator.matches(ordering))
    }

    fn evaluate_boolean(
        &self,
        expr: &BooleanExpr,
        packet: &DecodedPacket<'db, '_>,
    ) -> Result<bool, DecodeError> {
        match expr {
            BooleanExpr::Condition(condition) => self.evaluate_condition(condition, packet),
            BooleanExpr::And(children) => {
                for child in children {
                    if !self.evaluate_boolean(child, packet)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            BooleanExpr::Or(children) => {
                for child in children {
                    if self.evaluate_boolean(child, packet)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    fn evaluate_condition(
        &self,
        condition: &Condition,
        packet: &DecodedPacket<'db, '_>,
    ) -> Result<bool, DecodeError> {
        let (left_value, left_name) = self.operand_value(condition.left, packet)?;

        let ordering = match &condition.right {
            Operand::Literal(literal) => {
                compare_operand_literal(&left_value, self.db.name(*literal), &left_name)?
            }
            Operand::Parameter { .. } => {
                let (right_value, right_name) = self.operand_value(condition.right, packet)?;
                compare_operands(&left_value, &right_value, &left_name, &right_name)?
            }
        };
        Ok(condition.operator.matches(ordering))
    }

    /// Resolves one side of a condition to a comparable scalar.
    fn operand_value(
        &self,
        operand: Operand,
        packet: &DecodedPacket<'db, '_>,
    ) -> Result<(Scalar, String), DecodeError> {
        match operand {
            Operand::Parameter {
                parameter,
                use_calibrated,
            } => {
                let name = self.parameter_name(parameter);
                let value =
                    packet
                        .get(parameter)
                        .ok_or_else(|| DecodeError::ParameterNotYetDecoded {
                            context: "condition",
                            parameter: name.clone(),
                        })?;
                let scalar = if use_calibrated {
                    Scalar::from_eng(&value.eng)
                } else {
                    Scalar::from_raw(&value.raw)
                };
                Ok((scalar, name))
            }
            Operand::Literal(literal) => Ok((
                Scalar::Text(self.db.name(literal).to_owned()),
                "<literal>".to_owned(),
            )),
        }
    }

    fn container_name(&self, id: ContainerId) -> String {
        self.db
            .container(id)
            .map_or_else(|| "?".to_owned(), |c| self.db.name(c.name).to_owned())
    }

    fn parameter_name(&self, id: ParamId) -> String {
        self.db
            .parameter(id)
            .map_or_else(|| "?".to_owned(), |p| self.db.name(p.name).to_owned())
    }
}

/// A comparable view of a value, after the type-directed coercion XTCE comparisons imply.
#[derive(Clone, Debug)]
enum Scalar {
    Integer(i128),
    Float(f64),
    Text(String),
    Opaque(&'static str),
}

impl Scalar {
    fn from_raw(raw: &RawValue<'_>) -> Self {
        match raw {
            RawValue::Unsigned(value) => Self::Integer(i128::from(*value)),
            RawValue::Signed(value) => Self::Integer(i128::from(*value)),
            RawValue::Float(value) => Self::Float(*value),
            RawValue::Bytes(_) => Self::Opaque("binary"),
        }
    }

    fn from_eng(eng: &EngValue<'_, '_>) -> Self {
        match eng {
            EngValue::Unsigned(value) => Self::Integer(i128::from(*value)),
            EngValue::Signed(value) => Self::Integer(i128::from(*value)),
            EngValue::Bool(value) => Self::Integer(i128::from(*value)),
            EngValue::Float(value) => Self::Float(*value),
            EngValue::Label(text) => Self::Text((*text).to_owned()),
            EngValue::Text(text) => Self::Text(text.as_ref().to_owned()),
            EngValue::Bytes(_) => Self::Opaque("binary"),
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            Self::Integer(_) => "integer",
            Self::Float(_) => "float",
            Self::Text(_) => "text",
            Self::Opaque(kind) => kind,
        }
    }
}

/// Compares a raw value against a literal from the definition.
///
/// XTCE does not type comparison literals, so the literal is coerced to whatever the value
/// turned out to be — an integer parameter compares numerically, an enumerated one compares
/// as text. This mirrors the reference implementation, where the coercion is literally
/// `type(parsed_value)(required_value)`.
fn compare_raw(
    raw: &RawValue<'_>,
    literal: &str,
    name: &str,
) -> Result<std::cmp::Ordering, DecodeError> {
    compare_operand_literal(&Scalar::from_raw(raw), literal, name)
}

fn compare_eng(
    eng: &EngValue<'_, '_>,
    literal: &str,
    name: &str,
) -> Result<std::cmp::Ordering, DecodeError> {
    compare_operand_literal(&Scalar::from_eng(eng), literal, name)
}

fn compare_operand_literal(
    value: &Scalar,
    literal: &str,
    name: &str,
) -> Result<std::cmp::Ordering, DecodeError> {
    let incomparable = || DecodeError::IncomparableValue {
        parameter: name.to_owned(),
        value_kind: value.kind(),
        literal: literal.to_owned(),
    };

    match value {
        Scalar::Integer(left) => {
            let right: i128 = literal.trim().parse().map_err(|_| incomparable())?;
            Ok(left.cmp(&right))
        }
        Scalar::Float(left) => {
            let right: f64 = literal.trim().parse().map_err(|_| incomparable())?;
            Ok(left.total_cmp(&right))
        }
        Scalar::Text(left) => Ok(left.as_str().cmp(literal)),
        Scalar::Opaque(_) => Err(incomparable()),
    }
}

fn compare_operands(
    left: &Scalar,
    right: &Scalar,
    left_name: &str,
    right_name: &str,
) -> Result<std::cmp::Ordering, DecodeError> {
    match (left, right) {
        (Scalar::Integer(a), Scalar::Integer(b)) => Ok(a.cmp(b)),
        (Scalar::Float(a), Scalar::Float(b)) => Ok(a.total_cmp(b)),
        (Scalar::Integer(a), Scalar::Float(b)) => Ok((*a as f64).total_cmp(b)),
        (Scalar::Float(a), Scalar::Integer(b)) => Ok(a.total_cmp(&(*b as f64))),
        (Scalar::Text(a), Scalar::Text(b)) => Ok(a.cmp(b)),
        // Mixed text and number: coerce the text side, as the reference does.
        (Scalar::Integer(_) | Scalar::Float(_), Scalar::Text(text)) => {
            compare_operand_literal(left, text, left_name)
        }
        (Scalar::Text(text), Scalar::Integer(_) | Scalar::Float(_)) => {
            compare_operand_literal(right, text, right_name).map(std::cmp::Ordering::reverse)
        }
        _ => Err(DecodeError::IncomparableValue {
            parameter: left_name.to_owned(),
            value_kind: left.kind(),
            literal: right_name.to_owned(),
        }),
    }
}

/// Interprets `bits` as an IEEE-754 value of the given width.
fn ieee754(bits: u64, width: u32) -> Option<f64> {
    match width {
        16 => Some(f64::from(half_to_f32(bits as u16))),
        32 => Some(f64::from(f32::from_bits(bits as u32))),
        64 => Some(f64::from_bits(bits)),
        _ => None,
    }
}

/// Widens IEEE-754 binary16 to `f32`, which is exact.
fn half_to_f32(bits: u16) -> f32 {
    let sign = u32::from(bits >> 15) << 31;
    let exponent = u32::from((bits >> 10) & 0x1F);
    let mantissa = u32::from(bits & 0x03FF);

    match exponent {
        0 if mantissa == 0 => f32::from_bits(sign),
        // Subnormal: renormalise into the much wider f32 exponent range.
        0 => {
            let leading = mantissa.leading_zeros() - 21;
            let exponent = 127 - 15 - leading;
            let mantissa = (mantissa << (leading + 1)) & 0x03FF;
            f32::from_bits(sign | (exponent << 23) | (mantissa << 13))
        }
        0x1F => f32::from_bits(sign | 0x7F80_0000 | (mantissa << 13)),
        _ => f32::from_bits(sign | ((exponent + 127 - 15) << 23) | (mantissa << 13)),
    }
}

/// Decodes a MIL-STD-1750A 32-bit float.
///
/// Layout: sign and 23-bit mantissa in the top 24 bits, 8-bit exponent in the bottom, both
/// two's complement and unbiased.
fn mil_std_1750a(bits: u64) -> f64 {
    let word = bits as u32;
    let exponent = twos_complement(u64::from(word & 0xFF), 8);
    let mantissa = twos_complement(u64::from((word >> 8) & 0x00FF_FFFF), 24);
    (mantissa as f64) * 2f64.powi(i32::try_from(exponent).unwrap_or(0) - 23)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
