//! The interpreted decoder: walk the IR, read bits, produce values.

use std::borrow::Cow;

use xtce_model::{
    BooleanExpr, Calibrator, CompareOp, Comparison, ComparisonValue, Condition, ContainerId,
    DataEncoding, DiscreteLookup, EntryKind, FloatCoding, IntegerCoding, LocationReference,
    MatchCriteria, Operand, ParamId, ParameterType, SizeSpec, StringDelimiter, TypeKind, XtceDb,
};

use crate::bits::{
    BitCursor, ones_complement, sign_magnitude, swap_byte_order, twos_complement,
    twos_complement_unmasked,
};
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
    /// Upper bound on how many parameters one packet can produce from this root.
    ///
    /// Computed once so that a decoded packet reserves its storage in one go instead of
    /// regrowing a `Vec` and a hash table as it fills. CTIM's containers hold about 250
    /// entries each, which is eight doublings per packet without this.
    capacity_hint: usize,
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
        Ok(Self::rooted(db, root))
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
        Ok(Self::rooted(db, root))
    }

    fn rooted(db: &'db XtceDb, root: ContainerId) -> Self {
        Self {
            db,
            root,
            capacity_hint: longest_path_entries(db, root),
        }
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
        let mut packet = DecodedPacket::with_capacity(self.db, data, self.root, self.capacity_hint);
        self.decode_into(&mut packet, data)?;
        Ok(packet)
    }

    /// Decodes one packet into an existing buffer, reusing its allocations.
    ///
    /// Decoding a stream this way allocates nothing after the first packet. All the packets
    /// must share a lifetime, which they do when they are slices of one buffer — the usual
    /// case for a file or a receive window.
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let db = xtce_model::XtceDb::from_path("d.xml")?;
    /// # let stream = std::fs::read("t.bin")?;
    /// let decoder = xtce_decode::Decoder::new(&db)?;
    /// let mut packet = decoder.new_packet(&stream);
    /// for framed in xtce_decode::PacketIter::new(&stream, 0) {
    ///     decoder.decode_into(&mut packet, framed?.bytes())?;
    ///     println!("{} parameters", packet.len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`Self::decode`]. On failure the buffer holds whatever was decoded before the
    /// error, which is useful for diagnosis and must not be mistaken for a complete packet.
    pub fn decode_into<'p>(
        &self,
        packet: &mut DecodedPacket<'db, 'p>,
        data: &'p [u8],
    ) -> Result<(), DecodeError> {
        packet.reset(data, self.root);
        let mut cursor = BitCursor::new(data);
        let mut current = self.root;

        loop {
            self.decode_container(current, &mut cursor, packet, 0)?;

            let container = self
                .db
                .container(current)
                .ok_or_else(|| DecodeError::dangling_container(current))?;

            let mut matched: Option<ContainerId> = None;
            let mut extra: Vec<ContainerId> = Vec::new();
            for &inheritor in &container.inheritors {
                if self.inheritor_matches(inheritor, packet)? {
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
        Ok(())
    }

    /// An empty packet buffer sized for this decoder, for use with [`Self::decode_into`].
    #[must_use]
    pub fn new_packet<'p>(&self, data: &'p [u8]) -> DecodedPacket<'db, 'p> {
        DecodedPacket::with_capacity(self.db, data, self.root, self.capacity_hint)
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
                let swapped = encoding.byte_order == xtce_model::ByteOrder::LeastSignificantFirst;
                if swapped {
                    bits = swap_byte_order(bits, width);
                }
                Ok(match encoding.coding {
                    IntegerCoding::Unsigned => RawValue::Unsigned(bits),
                    // A swap of a field that is not a whole number of bytes leaves bits above
                    // `width`, and the reference keeps them. Masking them away, which is what
                    // `twos_complement` does, gives a different number — see
                    // `twos_complement_unmasked`. Everywhere else the two agree.
                    IntegerCoding::TwosComplement if swapped => {
                        RawValue::Signed(twos_complement_unmasked(bits, width).ok_or_else(
                            || DecodeError::Unsupported {
                                element: "IntegerDataEncoding".to_owned(),
                                context: format!(
                                    "{name}: a {width}-bit little-endian two's-complement \
                                     field can hold a value wider than an i64"
                                ),
                            },
                        )?)
                    }
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
        let literal_text = self.db.name(comparison.value.text);
        let operator = comparison.operator;

        let outcome = match packet.get(comparison.parameter) {
            Some(value) => {
                let scalar = if comparison.use_calibrated {
                    Scalar::from_eng(&value.eng)
                } else {
                    Scalar::from_raw(&value.raw)
                };
                test_literal(scalar, operator, &comparison.value, literal_text)
            }
            // The referenced parameter is not in the packet, so this must be a comparison
            // against the value currently being decoded — how a context calibrator refers to
            // its own uncalibrated value.
            None => match current {
                Some(raw) => test_literal(
                    Scalar::from_raw(raw),
                    operator,
                    &comparison.value,
                    literal_text,
                ),
                None => {
                    return Err(DecodeError::ParameterNotYetDecoded {
                        context: "comparison",
                        parameter: self.parameter_name(comparison.parameter),
                    });
                }
            },
        };

        outcome.map_err(|failure| DecodeError::IncomparableValue {
            parameter: self.parameter_name(comparison.parameter),
            value_kind: failure.value_kind,
            literal: literal_text.to_owned(),
        })
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
        let left = self.operand_value(condition.left, packet)?;

        let outcome = match condition.right {
            // The literal was pre-coerced at load time, so this is a comparison, not a parse.
            Operand::Literal(literal) => test_literal(
                left,
                condition.operator,
                &literal,
                self.db.name(literal.text),
            ),
            Operand::Parameter { .. } => test_scalars(
                left,
                condition.operator,
                self.operand_value(condition.right, packet)?,
            ),
        };

        outcome.map_err(|failure| DecodeError::IncomparableValue {
            parameter: self.operand_name(condition.left),
            value_kind: failure.value_kind,
            literal: self.operand_name(condition.right),
        })
    }

    /// Resolves one side of a condition to a comparable scalar.
    fn operand_value<'v>(
        &self,
        operand: Operand,
        packet: &'v DecodedPacket<'db, '_>,
    ) -> Result<Scalar<'v>, DecodeError>
    where
        'db: 'v,
    {
        match operand {
            Operand::Parameter {
                parameter,
                use_calibrated,
            } => {
                let value =
                    packet
                        .get(parameter)
                        .ok_or_else(|| DecodeError::ParameterNotYetDecoded {
                            context: "condition",
                            parameter: self.parameter_name(parameter),
                        })?;
                Ok(if use_calibrated {
                    Scalar::from_eng(&value.eng)
                } else {
                    Scalar::from_raw(&value.raw)
                })
            }
            Operand::Literal(literal) => Ok(Scalar::Text(self.db.name(literal.text))),
        }
    }

    /// A human-readable name for an operand, built only when reporting a failure.
    fn operand_name(&self, operand: Operand) -> String {
        match operand {
            Operand::Parameter { parameter, .. } => self.parameter_name(parameter),
            Operand::Literal(literal) => format!("{:?}", self.db.name(literal.text)),
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

/// The largest number of entries any single decode path from `root` can visit.
///
/// A decode walks from the root down one chain of inheritors, decoding each container's own
/// entry list and expanding any `<ContainerRefEntry>` inline. This is the deepest such walk,
/// used to size a packet's storage once instead of regrowing it.
///
/// Container expansion is memoised, which is what actually bounds the work: the depth limit
/// alone would not: a chain of forty containers each referencing the next twice is 2^40
/// calls before the cap ever fires. Decoding has the same shape but is braked by running out
/// of packet; this runs at construction time with no such brake.
fn longest_path_entries(db: &XtceDb, root: ContainerId) -> usize {
    let mut expanded: Vec<Option<usize>> = vec![None; db.containers().len()];
    let mut deepest: Vec<Option<usize>> = vec![None; db.containers().len()];
    walk(db, root, 0, &mut expanded, &mut deepest)
}

/// Entries contributed by one container's own list, with `<ContainerRefEntry>` expanded.
fn own_entries(db: &XtceDb, id: ContainerId, depth: usize, memo: &mut Vec<Option<usize>>) -> usize {
    if depth > MAX_CONTAINER_DEPTH {
        return 0;
    }
    if let Some(Some(cached)) = memo.get(id.index()) {
        return *cached;
    }
    // Marked before recursing, so a cycle resolves to zero rather than recursing forever.
    if let Some(slot) = memo.get_mut(id.index()) {
        *slot = Some(0);
    }
    let total = db
        .container_entries(id)
        .iter()
        .map(|entry| {
            let repeat = entry.repeat.unwrap_or(1) as usize;
            match entry.kind {
                EntryKind::Container(child) => own_entries(db, child, depth + 1, memo) * repeat,
                _ => repeat,
            }
        })
        .sum();
    if let Some(slot) = memo.get_mut(id.index()) {
        *slot = Some(total);
    }
    total
}

/// The longest root-to-leaf walk of the inheritance tree below `id`.
fn walk(
    db: &XtceDb,
    id: ContainerId,
    depth: usize,
    expanded: &mut Vec<Option<usize>>,
    deepest: &mut Vec<Option<usize>>,
) -> usize {
    if depth > MAX_CONTAINER_DEPTH {
        return 0;
    }
    if let Some(Some(cached)) = deepest.get(id.index()) {
        return *cached;
    }
    if let Some(slot) = deepest.get_mut(id.index()) {
        *slot = Some(0);
    }
    let here = own_entries(db, id, 0, expanded);
    let below = db.container(id).map_or(0, |container| {
        container
            .inheritors
            .iter()
            .map(|&child| walk(db, child, depth + 1, expanded, deepest))
            .max()
            .unwrap_or(0)
    });
    let total = here + below;
    if let Some(slot) = deepest.get_mut(id.index()) {
        *slot = Some(total);
    }
    total
}

/// A comparable view of a value.
///
/// Borrows its text rather than owning it: this is built and thrown away for every criterion
/// of every candidate container of every packet, and a database whose root has dozens of
/// inheritors would otherwise allocate dozens of strings before reading a single field.
#[derive(Clone, Copy, Debug)]
enum Scalar<'a> {
    Integer(i128),
    Float(f64),
    Text(&'a str),
    /// A value no XTCE comparison is defined over, carrying its kind for the error.
    Opaque(&'static str),
}

impl<'a> Scalar<'a> {
    fn from_raw(raw: &'a RawValue<'_>) -> Self {
        match raw {
            RawValue::Unsigned(value) => Self::Integer(i128::from(*value)),
            RawValue::Signed(value) => Self::Integer(i128::from(*value)),
            RawValue::Float(value) => Self::Float(*value),
            RawValue::Bytes(_) => Self::Opaque("binary"),
        }
    }

    fn from_eng(eng: &'a EngValue<'_, '_>) -> Self {
        match eng {
            EngValue::Unsigned(value) => Self::Integer(i128::from(*value)),
            EngValue::Signed(value) => Self::Integer(i128::from(*value)),
            EngValue::Bool(value) => Self::Integer(i128::from(*value)),
            EngValue::Float(value) => Self::Float(*value),
            EngValue::Label(text) => Self::Text(text),
            EngValue::Text(text) => Self::Text(text.as_ref()),
            EngValue::Bytes(_) => Self::Opaque("binary"),
        }
    }

    const fn kind(self) -> &'static str {
        match self {
            Self::Integer(_) => "integer",
            Self::Float(_) => "float",
            Self::Text(_) => "text",
            Self::Opaque(kind) => kind,
        }
    }
}

/// A comparison whose operands cannot be ordered against each other.
///
/// Deliberately carries no owned data: it becomes a [`DecodeError`] with names and text
/// attached only at the call site, and only when a comparison actually fails.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Incomparable {
    value_kind: &'static str,
}

/// The result of an operator applied to two values that have no ordering.
///
/// IEEE-754 calls this *unordered*, and Python agrees with it: every operator on a NaN is
/// false except `!=`, which is true. `Ord` on `f64` would instead report two NaNs as equal
/// and silently select the wrong container.
const fn unordered(operator: CompareOp) -> bool {
    matches!(operator, CompareOp::NotEqual)
}

/// Applies `operator` to a value and a pre-coerced literal from the definition.
///
/// XTCE does not type comparison literals, so the reading used is chosen by what the value
/// turned out to be: an integer parameter compares numerically, an enumerated one as text.
/// That mirrors the reference implementation, where the coercion is literally
/// `type(parsed_value)(required_value)` — except that the parsing happened at load time.
fn test_literal(
    value: Scalar<'_>,
    operator: CompareOp,
    literal: &ComparisonValue,
    text: &str,
) -> Result<bool, Incomparable> {
    let incomparable = Incomparable {
        value_kind: value.kind(),
    };
    match value {
        Scalar::Integer(left) => match literal.as_int {
            Some(right) => Ok(operator.matches(left.cmp(&right))),
            None => Err(incomparable),
        },
        Scalar::Float(left) => match literal.as_float {
            Some(right) => Ok(ordering(operator, left.partial_cmp(&right))),
            None => Err(incomparable),
        },
        Scalar::Text(left) => Ok(operator.matches(left.cmp(text))),
        Scalar::Opaque(_) => Err(incomparable),
    }
}

/// Applies `operator` to two decoded values.
fn test_scalars(
    left: Scalar<'_>,
    operator: CompareOp,
    right: Scalar<'_>,
) -> Result<bool, Incomparable> {
    match (left, right) {
        (Scalar::Integer(a), Scalar::Integer(b)) => Ok(operator.matches(a.cmp(&b))),
        (Scalar::Float(a), Scalar::Float(b)) => Ok(ordering(operator, a.partial_cmp(&b))),
        (Scalar::Integer(a), Scalar::Float(b)) => {
            Ok(ordering(operator, (a as f64).partial_cmp(&b)))
        }
        (Scalar::Float(a), Scalar::Integer(b)) => {
            Ok(ordering(operator, a.partial_cmp(&(b as f64))))
        }
        (Scalar::Text(a), Scalar::Text(b)) => Ok(operator.matches(a.cmp(b))),
        // Text against a number, with no literal to coerce. Python answers `False` for `==`
        // and `True` for `!=`, and raises `TypeError` for the ordering operators; this
        // reports the same three outcomes.
        _ => match operator {
            CompareOp::Equal => Ok(false),
            CompareOp::NotEqual => Ok(true),
            _ => Err(Incomparable {
                value_kind: left.kind(),
            }),
        },
    }
}

/// Applies an operator to a partial ordering, treating `None` as unordered.
fn ordering(operator: CompareOp, ordering: Option<std::cmp::Ordering>) -> bool {
    match ordering {
        Some(ordering) => operator.matches(ordering),
        None => unordered(operator),
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

/// Widens IEEE-754 binary16 to `f32`, which is exact for every input.
///
/// Subnormals need renormalising: `f16` has no implicit leading 1 below its smallest normal,
/// but every one of those values is comfortably normal in `f32`. For a subnormal fraction
/// `m`, the value is `m × 2^-24`; writing `p` for the index of its highest set bit, the
/// `f32` exponent field is `p + 103` and the fraction is `m` shifted so that bit `p` lands on
/// the implicit-1 position and is then masked away.
fn half_to_f32(bits: u16) -> f32 {
    let sign = u32::from(bits >> 15) << 31;
    let exponent = u32::from((bits >> 10) & 0x1F);
    let fraction = u32::from(bits & 0x03FF);

    match exponent {
        0 if fraction == 0 => f32::from_bits(sign),
        0 => {
            // `p = 31 - leading_zeros()` is the index of the highest set bit, so the shift
            // that moves it up to bit 10 — the implicit-1 position of the 10-bit window —
            // is `10 - p`, i.e. `leading_zeros() - 21`. It ranges 1..=10.
            let shift = fraction.leading_zeros() - 21;
            let exponent = 113 - shift;
            let fraction = (fraction << shift) & 0x03FF;
            f32::from_bits(sign | (exponent << 23) | (fraction << 13))
        }
        0x1F => f32::from_bits(sign | 0x7F80_0000 | (fraction << 13)),
        _ => f32::from_bits(sign | ((exponent + 127 - 15) << 23) | (fraction << 13)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use xtce_model::NameId;

    /// The reference for half-precision: the exact rational value of the encoding.
    ///
    /// Deliberately written from the IEEE-754 definition rather than from the implementation,
    /// so it cannot inherit the implementation's mistakes.
    fn half_reference(bits: u16) -> f64 {
        let sign = if bits >> 15 == 1 { -1.0 } else { 1.0 };
        let exponent = i32::from((bits >> 10) & 0x1F);
        let fraction = f64::from(bits & 0x03FF);
        match exponent {
            0 => sign * fraction * 2f64.powi(-24),
            0x1F => {
                if fraction == 0.0 {
                    sign * f64::INFINITY
                } else {
                    f64::NAN
                }
            }
            _ => sign * (1.0 + fraction / 1024.0) * 2f64.powi(exponent - 15),
        }
    }

    #[test]
    fn half_precision_matches_the_ieee_definition_for_every_encoding() {
        // All 65 536 encodings, which is cheap and leaves nothing to sampling.
        for bits in 0u16..=u16::MAX {
            let got = f64::from(half_to_f32(bits));
            let want = half_reference(bits);
            if want.is_nan() {
                assert!(got.is_nan(), "bits {bits:#06x}: expected NaN, got {got}");
            } else {
                assert_eq!(got.to_bits(), want.to_bits(), "bits {bits:#06x}");
            }
        }
    }

    #[test]
    fn half_precision_subnormals() {
        // These are the values a naive renormalisation gets wrong by a factor of two, and
        // no bundled test file declares a 16-bit float, so only a unit test reaches them.
        assert_eq!(f64::from(half_to_f32(0x0001)), 2f64.powi(-24));
        assert_eq!(f64::from(half_to_f32(0x0002)), 2f64.powi(-23));
        assert_eq!(f64::from(half_to_f32(0x03FF)), 1023.0 * 2f64.powi(-24));
        // Largest subnormal and smallest normal must be adjacent.
        assert_eq!(f64::from(half_to_f32(0x0400)), 2f64.powi(-14));
        assert_eq!(f64::from(half_to_f32(0x8001)), -(2f64.powi(-24)));
    }

    #[test]
    fn half_precision_specials() {
        assert_eq!(f64::from(half_to_f32(0x0000)), 0.0);
        assert!(f64::from(half_to_f32(0x8000)).is_sign_negative());
        assert_eq!(f64::from(half_to_f32(0x3C00)), 1.0);
        assert_eq!(f64::from(half_to_f32(0xC000)), -2.0);
        assert!(f64::from(half_to_f32(0x7C00)).is_infinite());
        assert!(f64::from(half_to_f32(0xFC00)).is_infinite());
        assert!(f64::from(half_to_f32(0x7E00)).is_nan());
    }

    #[test]
    fn mil_std_1750a_reference_values() {
        // Every row of the MIL-STD-1750A specification's own extended-precision table.
        assert_eq!(mil_std_1750a(0x4000_0000), 0.5);
        assert_eq!(mil_std_1750a(0x4000_0001), 1.0);
        assert_eq!(mil_std_1750a(0x4000_0004), 8.0);
        assert_eq!(mil_std_1750a(0x8000_0000), -1.0);
        assert_eq!(mil_std_1750a(0x0000_0000), 0.0);
        // The table gives this as -0.5000001 x 2^-1.
        assert_eq!(mil_std_1750a(0xBFFF_FFFF), -0.250_000_059_604_644_8);
        // Smallest magnitude: -1.0 x 2^-128.
        assert_eq!(mil_std_1750a(0x8000_0080), -2f64.powi(-128));
        assert_eq!(mil_std_1750a(0x4000_007F), 0.5 * 2f64.powi(127));
    }

    fn literal(text: &str) -> ComparisonValue {
        ComparisonValue::new(NameId::ZERO, text)
    }

    #[test]
    fn nan_is_unordered_exactly_as_python_treats_it() {
        use CompareOp::{Equal, Greater, GreaterOrEqual, Less, LessOrEqual, NotEqual};
        let nan = Scalar::Float(f64::NAN);

        // Python: nan == nan is False, nan != nan is True, every ordering is False. `Ord` on
        // f64 would report two NaNs equal, and silently select the wrong container.
        for (operator, expected) in [
            (Equal, false),
            (NotEqual, true),
            (Less, false),
            (LessOrEqual, false),
            (Greater, false),
            (GreaterOrEqual, false),
        ] {
            assert_eq!(
                test_literal(nan, operator, &literal("0"), "0"),
                Ok(expected),
                "{operator:?} against a literal"
            );
            assert_eq!(
                test_scalars(nan, operator, Scalar::Float(f64::NAN)),
                Ok(expected),
                "{operator:?} against another NaN"
            );
            assert_eq!(
                test_scalars(nan, operator, Scalar::Integer(0)),
                Ok(expected),
                "{operator:?} against an integer"
            );
        }
    }

    #[test]
    fn negative_zero_equals_zero() {
        // IEEE-754 says -0.0 == 0.0; a total ordering says it is less.
        assert_eq!(
            test_literal(
                Scalar::Float(-0.0),
                CompareOp::Equal,
                &literal("0.0"),
                "0.0"
            ),
            Ok(true)
        );
        assert_eq!(
            test_scalars(Scalar::Float(-0.0), CompareOp::Equal, Scalar::Float(0.0)),
            Ok(true)
        );
    }

    #[test]
    fn literals_are_coerced_to_the_value_they_meet() {
        assert_eq!(
            test_literal(Scalar::Integer(11), CompareOp::Equal, &literal("11"), "11"),
            Ok(true)
        );
        // A float literal cannot be read as an integer, which is what Python's `int("3.5")`
        // does too.
        assert!(
            test_literal(Scalar::Integer(3), CompareOp::Equal, &literal("3.5"), "3.5").is_err()
        );
        // But an integer literal reads fine as a float.
        assert_eq!(
            test_literal(Scalar::Float(3.0), CompareOp::Equal, &literal("3"), "3"),
            Ok(true)
        );
        // Enumerated parameters compare as text, so their labels never parse as numbers.
        assert_eq!(
            test_literal(Scalar::Text("ON"), CompareOp::Equal, &literal("ON"), "ON"),
            Ok(true)
        );
        assert_eq!(
            test_literal(Scalar::Text("OFF"), CompareOp::Less, &literal("ON"), "ON"),
            Ok(true)
        );
        // Binary is not comparable at all.
        assert!(
            test_literal(
                Scalar::Opaque("binary"),
                CompareOp::Equal,
                &literal("0"),
                "0"
            )
            .is_err()
        );
    }

    #[test]
    fn text_against_a_number_follows_python() {
        // Python: "ON" == 5 is False, "ON" != 5 is True, "ON" < 5 raises TypeError.
        let text = Scalar::Text("ON");
        let number = Scalar::Integer(5);
        assert_eq!(test_scalars(text, CompareOp::Equal, number), Ok(false));
        assert_eq!(test_scalars(text, CompareOp::NotEqual, number), Ok(true));
        assert!(test_scalars(text, CompareOp::Less, number).is_err());
        assert!(test_scalars(number, CompareOp::Greater, text).is_err());
    }

    #[test]
    fn operators_over_an_ordering() {
        use std::cmp::Ordering::{Equal, Greater, Less};
        assert!(CompareOp::Equal.matches(Equal));
        assert!(!CompareOp::Equal.matches(Less));
        assert!(CompareOp::NotEqual.matches(Less));
        assert!(CompareOp::NotEqual.matches(Greater));
        assert!(!CompareOp::NotEqual.matches(Equal));
        assert!(CompareOp::LessOrEqual.matches(Equal));
        assert!(CompareOp::GreaterOrEqual.matches(Equal));
        assert!(!CompareOp::Greater.matches(Equal));
    }
}
