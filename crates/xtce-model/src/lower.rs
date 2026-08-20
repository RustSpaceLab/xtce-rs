//! Lowering: XML tree to [`XtceDb`].
//!
//! Two passes over the tree:
//!
//! 1. **Register.** Walk the `SpaceSystem` hierarchy and allocate an id for every parameter
//!    type, parameter and container, recording its qualified name and the tree node it came
//!    from. Nothing is resolved yet, because XTCE references run in both directions: a
//!    `<BaseContainer>` may name a container defined later in the file.
//! 2. **Lower.** Revisit each node, now able to turn every `parameterRef`,
//!    `parameterTypeRef` and `containerRef` into an id.
//!
//! A third, cheap step links each container to its inheritors and checks that inheritance is
//! acyclic, so a malformed database fails at load time rather than overflowing the stack on
//! the first packet.

use crate::containers::{
    BooleanExpr, CompareOp, Comparison, ComparisonValue, Condition, Container, Entry, EntryKind,
    Location, LocationReference, MatchCriteria, Operand, SpaceSystem,
};
use crate::db::{Unsupported, XtceDb};
use crate::error::{RefKind, XtceError};
use crate::ids::{ContainerId, ParamId, SpaceSystemId, Span, TypeId};
use crate::intern::{FxHashMap, Interner, NameId};
use crate::types::{
    BinaryEncoding, ByteOrder, Calibrator, Charset, ContextCalibrator, DataEncoding,
    DiscreteLookup, Enumeration, EnumerationList, FloatCoding, FloatEncoding, IntegerCoding,
    IntegerEncoding, LinearAdjustment, Parameter, ParameterType, PolynomialTerm, SizeSpec, Spline,
    SplinePoint, StringDelimiter, StringEncoding, TypeKind,
};
use crate::xml::{AttrKey, Dom, Element, Tag};

/// Encoding elements in the order the reference implementation searches for them.
const ENCODING_TAGS: [Tag; 4] = [
    Tag::StringDataEncoding,
    Tag::IntegerDataEncoding,
    Tag::FloatDataEncoding,
    Tag::BinaryDataEncoding,
];

/// A definition registered in pass 1, awaiting lowering in pass 2.
struct Pending<'d> {
    element: Element<'d>,
    space_system: SpaceSystemId,
    qualified_name: NameId,
}

pub(crate) struct Lowering<'d> {
    dom: &'d Dom,
    interner: Interner,

    space_systems: Vec<SpaceSystem>,
    pending_types: Vec<Pending<'d>>,
    pending_params: Vec<Pending<'d>>,
    pending_containers: Vec<Pending<'d>>,

    type_by_qualified: FxHashMap<NameId, TypeId>,
    type_by_leaf: FxHashMap<NameId, TypeId>,
    param_by_qualified: FxHashMap<NameId, ParamId>,
    param_by_leaf: FxHashMap<NameId, ParamId>,
    container_by_qualified: FxHashMap<NameId, ContainerId>,
    container_by_leaf: FxHashMap<NameId, ContainerId>,

    unsupported: Vec<Unsupported>,
    /// Reusable buffer for building candidate qualified names during resolution.
    scratch: String,
}

impl<'d> Lowering<'d> {
    pub(crate) fn new(dom: &'d Dom) -> Self {
        let interner = Interner::with_capacity(dom.len() / 2, dom.len() * 8);
        Self {
            dom,
            interner,
            space_systems: Vec::new(),
            pending_types: Vec::new(),
            pending_params: Vec::new(),
            pending_containers: Vec::new(),
            type_by_qualified: FxHashMap::default(),
            type_by_leaf: FxHashMap::default(),
            param_by_qualified: FxHashMap::default(),
            param_by_leaf: FxHashMap::default(),
            container_by_qualified: FxHashMap::default(),
            container_by_leaf: FxHashMap::default(),
            unsupported: Vec::new(),
            scratch: String::with_capacity(128),
        }
    }

    pub(crate) fn run(mut self) -> Result<XtceDb, XtceError> {
        let root = self.dom.root();
        if root.tag() != Tag::SpaceSystem {
            return Err(XtceError::NotXtce {
                found: root.name().to_owned(),
            });
        }

        self.register_space_system(root, None)?;

        let types = self.lower_types()?;
        let parameters = self.lower_parameters()?;
        let (mut containers, entries) = self.lower_containers()?;

        link_inheritors(&mut containers);
        check_acyclic(&containers, &self.interner)?;

        let root_containers = containers
            .iter()
            .enumerate()
            .filter(|(_, container)| container.base.is_none())
            .map(|(index, _)| ContainerId::new(u32::try_from(index).unwrap_or(u32::MAX)))
            .collect();

        Ok(XtceDb::assemble(crate::db::Parts {
            interner: self.interner,
            space_systems: self.space_systems,
            types,
            parameters,
            containers,
            entries,
            root_containers,
            type_by_qualified: self.type_by_qualified,
            type_by_leaf: self.type_by_leaf,
            param_by_qualified: self.param_by_qualified,
            param_by_leaf: self.param_by_leaf,
            container_by_qualified: self.container_by_qualified,
            container_by_leaf: self.container_by_leaf,
            unsupported: self.unsupported,
            xmlns: self.dom.xmlns().map(str::to_owned),
            skipped_sections: self.dom.skipped_sections().to_vec(),
        }))
    }

    // ---------------------------------------------------------------- pass 1: register

    fn register_space_system(
        &mut self,
        element: Element<'d>,
        parent: Option<SpaceSystemId>,
    ) -> Result<SpaceSystemId, XtceError> {
        let name = element
            .attr(AttrKey::Name)
            .ok_or_else(|| XtceError::Missing {
                what: "SpaceSystem name attribute",
                path: element.path(),
            })?;

        let qualified = match parent {
            Some(parent) => {
                let parent_path = self.qualified_of(parent).to_owned();
                format!("{parent_path}/{name}")
            }
            None => format!("/{name}"),
        };

        let id = SpaceSystemId::new(u32::try_from(self.space_systems.len()).unwrap_or(u32::MAX));
        let name_id = self.interner.intern(name);
        let qualified_id = self.interner.intern(&qualified);
        self.space_systems.push(SpaceSystem {
            name: name_id,
            qualified_name: qualified_id,
            parent,
            children: Vec::new(),
        });
        if let Some(parent) = parent {
            if let Some(node) = self.space_systems.get_mut(parent.index()) {
                node.children.push(id);
            }
        }

        if let Some(telemetry) = element.child(Tag::TelemetryMetaData) {
            if let Some(set) = telemetry.child(Tag::ParameterTypeSet) {
                for child in set.children() {
                    self.register(child, id, Definition::Type)?;
                }
            }
            if let Some(set) = telemetry.child(Tag::ParameterSet) {
                for child in set.children_with(Tag::Parameter) {
                    self.register(child, id, Definition::Parameter)?;
                }
            }
            if let Some(set) = telemetry.child(Tag::ContainerSet) {
                for child in set.children_with(Tag::SequenceContainer) {
                    self.register(child, id, Definition::Container)?;
                }
            }
        }

        for child in element.children_with(Tag::SpaceSystem) {
            self.register_space_system(child, Some(id))?;
        }
        Ok(id)
    }

    fn register(
        &mut self,
        element: Element<'d>,
        space_system: SpaceSystemId,
        kind: Definition,
    ) -> Result<(), XtceError> {
        let Some(name) = element.attr(AttrKey::Name) else {
            return Err(XtceError::Missing {
                what: "name attribute",
                path: element.path(),
            });
        };
        let parent_path = self.qualified_of(space_system).to_owned();
        let qualified = format!("{parent_path}/{name}");
        let qualified_id = self.interner.intern(&qualified);
        let leaf_id = self.interner.intern(name);

        let pending = Pending {
            element,
            space_system,
            qualified_name: qualified_id,
        };

        match kind {
            Definition::Type => {
                let id = TypeId::new(u32::try_from(self.pending_types.len()).unwrap_or(u32::MAX));
                self.pending_types.push(pending);
                insert_unique(
                    &mut self.type_by_qualified,
                    qualified_id,
                    id,
                    RefKind::ParameterType,
                    &qualified,
                    &element,
                )?;
                self.type_by_leaf.entry(leaf_id).or_insert(id);
            }
            Definition::Parameter => {
                let id = ParamId::new(u32::try_from(self.pending_params.len()).unwrap_or(u32::MAX));
                self.pending_params.push(pending);
                insert_unique(
                    &mut self.param_by_qualified,
                    qualified_id,
                    id,
                    RefKind::Parameter,
                    &qualified,
                    &element,
                )?;
                self.param_by_leaf.entry(leaf_id).or_insert(id);
            }
            Definition::Container => {
                let id = ContainerId::new(
                    u32::try_from(self.pending_containers.len()).unwrap_or(u32::MAX),
                );
                self.pending_containers.push(pending);
                insert_unique(
                    &mut self.container_by_qualified,
                    qualified_id,
                    id,
                    RefKind::Container,
                    &qualified,
                    &element,
                )?;
                self.container_by_leaf.entry(leaf_id).or_insert(id);
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------- pass 2: lower

    fn lower_types(&mut self) -> Result<Vec<ParameterType>, XtceError> {
        let pending = std::mem::take(&mut self.pending_types);
        let mut out = Vec::with_capacity(pending.len());
        for item in &pending {
            out.push(self.lower_type(item)?);
        }
        self.pending_types = pending;
        Ok(out)
    }

    fn lower_type(&mut self, pending: &Pending<'d>) -> Result<ParameterType, XtceError> {
        let element = pending.element;
        let name = element.attr(AttrKey::Name).unwrap_or_default();
        let name_id = self.interner.intern(name);

        let mut encoding = self.lower_encoding(element, pending.space_system)?;
        apply_time_unit_scaler(element, &mut encoding);
        let units = self.lower_units(element);

        let kind = match element.tag() {
            Tag::IntegerParameterType => TypeKind::Integer,
            Tag::FloatParameterType => TypeKind::Float,
            Tag::StringParameterType => TypeKind::String,
            Tag::BinaryParameterType => TypeKind::Binary,
            Tag::BooleanParameterType => TypeKind::Boolean {
                zero_label: element
                    .attr(AttrKey::ZeroStringValue)
                    .map(|text| self.interner.intern(text)),
                one_label: element
                    .attr(AttrKey::OneStringValue)
                    .map(|text| self.interner.intern(text)),
            },
            Tag::EnumeratedParameterType => self.lower_enumeration(element),
            Tag::AbsoluteTimeParameterType => TypeKind::AbsoluteTime {
                epoch: element
                    .child(Tag::ReferenceTime)
                    .and_then(|reference| reference.child(Tag::Epoch))
                    .and_then(Element::text)
                    .map(|text| self.interner.intern(text)),
                offset_from: element
                    .child(Tag::ReferenceTime)
                    .and_then(|reference| reference.child(Tag::OffsetFrom))
                    .and_then(|offset| offset.attr(AttrKey::ParameterRef))
                    .and_then(|reference| {
                        self.resolve_parameter_opt(reference, pending.space_system)
                    }),
            },
            Tag::RelativeTimeParameterType => TypeKind::RelativeTime,
            other => {
                let element_name = element.name().to_owned();
                self.note_unsupported(
                    &element_name,
                    &element.path(),
                    "parameter type outside the supported subset",
                );
                let _ = other;
                TypeKind::Unsupported {
                    element: self.interner.intern(&element_name),
                }
            }
        };

        Ok(ParameterType {
            name: name_id,
            qualified_name: pending.qualified_name,
            space_system: pending.space_system,
            units,
            kind,
            encoding,
        })
    }

    fn lower_units(&mut self, element: Element<'d>) -> Vec<NameId> {
        // Time parameter types put their unit on `<Encoding units=..>`; everything else
        // uses `<UnitSet><Unit>`.
        if let Some(units) = element
            .child(Tag::Encoding)
            .and_then(|encoding| encoding.attr(AttrKey::Units))
        {
            return vec![self.interner.intern(units)];
        }
        let Some(set) = element.child(Tag::UnitSet) else {
            return Vec::new();
        };
        set.children_with(Tag::Unit)
            .filter_map(Element::text)
            .map(|text| self.interner.intern(text))
            .collect()
    }

    fn lower_enumeration(&mut self, element: Element<'d>) -> TypeKind {
        let Some(list) = element.child(Tag::EnumerationList) else {
            let name = element.name().to_owned();
            self.note_unsupported(
                &name,
                &element.path(),
                "EnumeratedParameterType without an EnumerationList",
            );
            return TypeKind::Unsupported {
                element: self.interner.intern("EnumerationList"),
            };
        };

        let mut entries = Vec::new();
        for enumeration in list.children_with(Tag::Enumeration) {
            let Some(value) = enumeration.attr(AttrKey::Value).and_then(parse_i128) else {
                self.note_unsupported(
                    "Enumeration",
                    &enumeration.path(),
                    "enumeration value is not an integer",
                );
                return TypeKind::Unsupported {
                    element: self.interner.intern("Enumeration"),
                };
            };
            let max_value = enumeration
                .attr(AttrKey::MaxValue)
                .and_then(parse_i128)
                .unwrap_or(value);
            let label = enumeration.attr(AttrKey::Label).unwrap_or_default();
            entries.push(Enumeration {
                value,
                max_value,
                label: self.interner.intern(label),
            });
        }
        TypeKind::Enumerated(EnumerationList::new(entries))
    }

    fn lower_encoding(
        &mut self,
        type_element: Element<'d>,
        space_system: SpaceSystemId,
    ) -> Result<DataEncoding, XtceError> {
        let Some((tag, element)) = ENCODING_TAGS
            .iter()
            .find_map(|&tag| type_element.descendant(tag).map(|found| (tag, found)))
        else {
            return Ok(DataEncoding::None);
        };

        Ok(match tag {
            Tag::IntegerDataEncoding => DataEncoding::Integer(IntegerEncoding {
                size_in_bits: Self::size_attr(element, 8)?,
                coding: integer_coding(element.attr(AttrKey::Encoding).unwrap_or("unsigned")),
                byte_order: byte_order(element.attr(AttrKey::ByteOrder)),
                default_calibrator: self.lower_default_calibrator(element),
                context_calibrators: self.lower_context_calibrators(element, space_system),
            }),
            Tag::FloatDataEncoding => DataEncoding::Float(FloatEncoding {
                size_in_bits: Self::size_attr(element, 32)?,
                coding: float_coding(element.attr(AttrKey::Encoding).unwrap_or("IEEE754")),
                byte_order: byte_order(element.attr(AttrKey::ByteOrder)),
                default_calibrator: self.lower_default_calibrator(element),
                context_calibrators: self.lower_context_calibrators(element, space_system),
            }),
            Tag::StringDataEncoding => {
                DataEncoding::String(self.lower_string_encoding(element, space_system))
            }
            Tag::BinaryDataEncoding => DataEncoding::Binary(BinaryEncoding {
                size: self.lower_size_spec(element.child(Tag::SizeInBits), space_system),
            }),
            _ => DataEncoding::None,
        })
    }

    fn size_attr(element: Element<'d>, default: u32) -> Result<u32, XtceError> {
        match element.attr(AttrKey::SizeInBits) {
            None => Ok(default),
            Some(text) => text
                .trim()
                .parse::<u32>()
                .map_err(|error| XtceError::Invalid {
                    what: "sizeInBits",
                    value: text.to_owned(),
                    path: element.path(),
                    reason: error.to_string(),
                }),
        }
    }

    fn lower_string_encoding(
        &mut self,
        element: Element<'d>,
        space_system: SpaceSystemId,
    ) -> StringEncoding {
        let charset_text = element.attr(AttrKey::Encoding).unwrap_or("UTF-8");
        let charset = charset(charset_text);
        let byte_order = match element.attr(AttrKey::ByteOrder) {
            Some(text) => byte_order(Some(text)),
            // XTCE lets the charset name carry the endianness; honour that before falling
            // back to the big-endian default.
            None if charset_text.ends_with("LE") => ByteOrder::LeastSignificantFirst,
            None => ByteOrder::MostSignificantFirst,
        };

        // The raw size lives under `<SizeInBits>` (fixed) or `<Variable>` (dynamic), and the
        // delimiter is a child of whichever one is present.
        let size_holder = element
            .child(Tag::SizeInBits)
            .or_else(|| element.child(Tag::Variable));

        let raw_size = match size_holder {
            Some(holder) if holder.tag() == Tag::SizeInBits => {
                match holder
                    .child(Tag::Fixed)
                    .and_then(|fixed| fixed.child(Tag::FixedValue))
                    .or_else(|| holder.child(Tag::FixedValue))
                    .and_then(Element::text)
                    .and_then(|text| text.trim().parse::<u32>().ok())
                {
                    Some(bits) => SizeSpec::Fixed(bits),
                    None => self.lower_size_spec(Some(holder), space_system),
                }
            }
            Some(holder) => self.lower_size_spec(Some(holder), space_system),
            None => SizeSpec::Unsupported {
                element: self.interner.intern("SizeInBits"),
            },
        };

        let delimiter = size_holder
            .and_then(|holder| {
                if let Some(termination) = holder.child(Tag::TerminationChar) {
                    let hex = termination.text().unwrap_or_default();
                    return Some(StringDelimiter::TerminationChar(parse_hex(hex)));
                }
                let leading = holder.child(Tag::LeadingSize)?;
                let bits = leading
                    .attr(AttrKey::SizeInBitsOfSizeTag)
                    .and_then(|text| text.trim().parse::<u32>().ok())
                    .unwrap_or(8);
                Some(StringDelimiter::LeadingSize { size_in_bits: bits })
            })
            .unwrap_or_default();

        StringEncoding {
            charset,
            byte_order,
            raw_size,
            delimiter,
        }
    }

    fn lower_size_spec(
        &mut self,
        holder: Option<Element<'d>>,
        space_system: SpaceSystemId,
    ) -> SizeSpec {
        let Some(holder) = holder else {
            return SizeSpec::Unsupported {
                element: self.interner.intern("SizeInBits"),
            };
        };

        if let Some(fixed) = holder.child(Tag::FixedValue).or_else(|| {
            holder
                .child(Tag::Fixed)
                .and_then(|f| f.child(Tag::FixedValue))
        }) {
            if let Some(bits) = fixed
                .text()
                .and_then(|text| text.trim().parse::<u32>().ok())
            {
                return SizeSpec::Fixed(bits);
            }
        }

        if let Some(dynamic) = holder.child(Tag::DynamicValue) {
            if let Some(instance) = dynamic.child(Tag::ParameterInstanceRef) {
                let reference = instance.attr(AttrKey::ParameterRef).unwrap_or_default();
                if let Some(parameter) = self.resolve_parameter_opt(reference, space_system) {
                    return SizeSpec::Dynamic {
                        parameter,
                        use_calibrated: use_calibrated(instance),
                        adjustment: dynamic.child(Tag::LinearAdjustment).map(linear_adjustment),
                    };
                }
                self.note_unsupported(
                    "DynamicValue",
                    &dynamic.path(),
                    "size reference does not resolve to a known parameter",
                );
            }
            return SizeSpec::Unsupported {
                element: self.interner.intern("DynamicValue"),
            };
        }

        if let Some(list) = holder.child(Tag::DiscreteLookupList) {
            let lookups = list
                .children_with(Tag::DiscreteLookup)
                .map(|lookup| DiscreteLookup {
                    criteria: self.lower_criteria_children(lookup, space_system),
                    value: lookup
                        .attr(AttrKey::Value)
                        .and_then(|text| text.trim().parse::<i64>().ok())
                        .unwrap_or(0),
                })
                .collect();
            return SizeSpec::DiscreteLookup(lookups);
        }

        SizeSpec::Unsupported {
            element: self.interner.intern(holder.name()),
        }
    }

    fn lower_default_calibrator(&mut self, encoding: Element<'d>) -> Option<Calibrator> {
        let holder = encoding.child(Tag::DefaultCalibrator)?;
        self.lower_calibrator(holder)
    }

    fn lower_context_calibrators(
        &mut self,
        encoding: Element<'d>,
        space_system: SpaceSystemId,
    ) -> Vec<ContextCalibrator> {
        let Some(list) = encoding.child(Tag::ContextCalibratorList) else {
            return Vec::new();
        };
        list.children_with(Tag::ContextCalibrator)
            .filter_map(|context| {
                let criteria = context
                    .child(Tag::ContextMatch)
                    .map(|match_element| self.lower_criteria_children(match_element, space_system))
                    .unwrap_or_default();
                let calibrator = context
                    .child(Tag::Calibrator)
                    .and_then(|holder| self.lower_calibrator(holder))?;
                Some(ContextCalibrator {
                    criteria,
                    calibrator,
                })
            })
            .collect()
    }

    fn lower_calibrator(&mut self, holder: Element<'d>) -> Option<Calibrator> {
        for child in holder.children() {
            match child.tag() {
                Tag::PolynomialCalibrator => {
                    let terms = child
                        .children_with(Tag::Term)
                        .map(|term| PolynomialTerm {
                            coefficient: term
                                .attr(AttrKey::Coefficient)
                                .and_then(parse_f64)
                                .unwrap_or(0.0),
                            exponent: term
                                .attr(AttrKey::Exponent)
                                .and_then(|text| text.trim().parse::<i32>().ok())
                                .unwrap_or(0),
                        })
                        .collect();
                    return Some(Calibrator::Polynomial(terms));
                }
                Tag::SplineCalibrator => {
                    let mut points: Vec<SplinePoint> = child
                        .children_with(Tag::SplinePoint)
                        .map(|point| SplinePoint {
                            raw: point.attr(AttrKey::Raw).and_then(parse_f64).unwrap_or(0.0),
                            calibrated: point
                                .attr(AttrKey::Calibrated)
                                .and_then(parse_f64)
                                .unwrap_or(0.0),
                        })
                        .collect();
                    points.sort_by(|a, b| a.raw.total_cmp(&b.raw));
                    return Some(Calibrator::Spline(Spline {
                        order: child
                            .attr(AttrKey::Order)
                            .and_then(|text| text.trim().parse::<u8>().ok())
                            .unwrap_or(0),
                        points,
                        extrapolate: child
                            .attr(AttrKey::Extrapolate)
                            .is_some_and(|text| text.eq_ignore_ascii_case("true")),
                    }));
                }
                Tag::MathOperationCalibrator | Tag::CustomAlgorithm => {
                    let name = child.name().to_owned();
                    self.note_unsupported(&name, &child.path(), "calibrator kind out of scope");
                    return Some(Calibrator::Unsupported {
                        element: self.interner.intern(&name),
                    });
                }
                _ => {}
            }
        }
        None
    }

    fn lower_parameters(&mut self) -> Result<Vec<Parameter>, XtceError> {
        let pending = std::mem::take(&mut self.pending_params);
        let mut out = Vec::with_capacity(pending.len());
        for item in &pending {
            let element = item.element;
            let name = element.attr(AttrKey::Name).unwrap_or_default();
            let type_ref =
                element
                    .attr(AttrKey::ParameterTypeRef)
                    .ok_or_else(|| XtceError::Missing {
                        what: "parameterTypeRef attribute",
                        path: element.path(),
                    })?;
            let type_id = self
                .resolve(type_ref, item.space_system, RefKind::ParameterType)
                .ok_or_else(|| XtceError::UnresolvedReference {
                    kind: RefKind::ParameterType,
                    reference: type_ref.to_owned(),
                    path: element.path(),
                })?;

            out.push(Parameter {
                name: self.interner.intern(name),
                qualified_name: item.qualified_name,
                space_system: item.space_system,
                type_id: TypeId::new(type_id),
                short_description: element
                    .attr(AttrKey::ShortDescription)
                    .map(|text| self.interner.intern(text)),
                long_description: element
                    .child(Tag::LongDescription)
                    .and_then(Element::text)
                    .map(|text| self.interner.intern(text)),
                initial_value: element
                    .attr(AttrKey::InitialValue)
                    .map(|text| self.interner.intern(text)),
            });
        }
        self.pending_params = pending;
        Ok(out)
    }

    fn lower_containers(&mut self) -> Result<(Vec<Container>, Vec<Entry>), XtceError> {
        let pending = std::mem::take(&mut self.pending_containers);
        let mut containers = Vec::with_capacity(pending.len());
        let mut entries: Vec<Entry> = Vec::new();

        for item in &pending {
            let element = item.element;
            let name = element.attr(AttrKey::Name).unwrap_or_default();

            let base_element = element.child(Tag::BaseContainer);
            let base = match base_element.and_then(|base| base.attr(AttrKey::ContainerRef)) {
                Some(reference) => Some(ContainerId::new(
                    self.resolve(reference, item.space_system, RefKind::Container)
                        .ok_or_else(|| XtceError::UnresolvedReference {
                            kind: RefKind::Container,
                            reference: reference.to_owned(),
                            path: element.path(),
                        })?,
                )),
                None => None,
            };

            let restriction = base_element
                .and_then(|base| base.child(Tag::RestrictionCriteria))
                .map(|criteria| self.lower_criteria_children(criteria, item.space_system))
                .unwrap_or_default();

            let start = entries.len();
            if let Some(list) = element.child(Tag::EntryList) {
                for entry in list.children() {
                    entries.push(self.lower_entry(entry, item.space_system)?);
                }
            }

            containers.push(Container {
                name: self.interner.intern(name),
                qualified_name: item.qualified_name,
                space_system: item.space_system,
                is_abstract: element
                    .attr(AttrKey::Abstract)
                    .is_some_and(|text| text.eq_ignore_ascii_case("true")),
                base,
                restriction,
                entries: Span::between(start, entries.len()),
                inheritors: Vec::new(),
                short_description: element
                    .attr(AttrKey::ShortDescription)
                    .map(|text| self.interner.intern(text)),
                long_description: element
                    .child(Tag::LongDescription)
                    .and_then(Element::text)
                    .map(|text| self.interner.intern(text)),
            });
        }
        self.pending_containers = pending;
        Ok((containers, entries))
    }

    fn lower_entry(
        &mut self,
        element: Element<'d>,
        space_system: SpaceSystemId,
    ) -> Result<Entry, XtceError> {
        let kind = match element.tag() {
            Tag::ParameterRefEntry => {
                let reference =
                    element
                        .attr(AttrKey::ParameterRef)
                        .ok_or_else(|| XtceError::Missing {
                            what: "parameterRef attribute",
                            path: element.path(),
                        })?;
                let id = self
                    .resolve(reference, space_system, RefKind::Parameter)
                    .ok_or_else(|| XtceError::UnresolvedReference {
                        kind: RefKind::Parameter,
                        reference: reference.to_owned(),
                        path: element.path(),
                    })?;
                EntryKind::Parameter(ParamId::new(id))
            }
            Tag::ContainerRefEntry => {
                let reference =
                    element
                        .attr(AttrKey::ContainerRef)
                        .ok_or_else(|| XtceError::Missing {
                            what: "containerRef attribute",
                            path: element.path(),
                        })?;
                let id = self
                    .resolve(reference, space_system, RefKind::Container)
                    .ok_or_else(|| XtceError::UnresolvedReference {
                        kind: RefKind::Container,
                        reference: reference.to_owned(),
                        path: element.path(),
                    })?;
                EntryKind::Container(ContainerId::new(id))
            }
            _ => {
                let name = element.name().to_owned();
                self.note_unsupported(&name, &element.path(), "entry kind out of scope");
                EntryKind::Unsupported {
                    element: self.interner.intern(&name),
                }
            }
        };

        let location = element
            .child(Tag::LocationInContainerInBits)
            .and_then(|node| {
                let offset = node
                    .child(Tag::FixedValue)
                    .and_then(Element::text)
                    .or_else(|| node.text())
                    .and_then(|text| text.trim().parse::<i64>().ok())?;
                Some(Location {
                    reference: location_reference(node.attr(AttrKey::ReferenceLocation)),
                    offset_in_bits: offset,
                })
            });

        let repeat = element
            .child(Tag::RepeatEntry)
            .and_then(|repeat| repeat.child(Tag::Count))
            .and_then(|count| count.child(Tag::FixedValue))
            .and_then(Element::text)
            .and_then(|text| text.trim().parse::<u32>().ok());

        Ok(Entry {
            kind,
            location,
            repeat,
        })
    }

    // --------------------------------------------------------------- match criteria

    /// Lowers the children of a `<RestrictionCriteria>` or `<ContextMatch>` element.
    fn lower_criteria_children(
        &mut self,
        holder: Element<'d>,
        space_system: SpaceSystemId,
    ) -> Vec<MatchCriteria> {
        let mut out = Vec::new();
        for child in holder.children() {
            match child.tag() {
                Tag::Comparison => {
                    out.push(self.lower_comparison(child, space_system));
                }
                Tag::ComparisonList => {
                    for comparison in child.children_with(Tag::Comparison) {
                        out.push(self.lower_comparison(comparison, space_system));
                    }
                }
                Tag::BooleanExpression => {
                    out.push(match self.lower_boolean_expression(child, space_system) {
                        Some(expr) => MatchCriteria::Boolean(expr),
                        None => self.unsupported_criteria(child, "unrecognised BooleanExpression"),
                    });
                }
                Tag::CustomAlgorithm => {
                    out.push(self.unsupported_criteria(child, "CustomAlgorithm criteria"));
                }
                _ => {}
            }
        }
        out
    }

    fn lower_comparison(
        &mut self,
        element: Element<'d>,
        space_system: SpaceSystemId,
    ) -> MatchCriteria {
        let reference = element.attr(AttrKey::ParameterRef).unwrap_or_default();
        let Some(parameter) = self.resolve_parameter_opt(reference, space_system) else {
            return self
                .unsupported_criteria(element, "comparison references an unknown parameter");
        };
        let operator = element
            .attr(AttrKey::ComparisonOperator)
            .and_then(CompareOp::parse)
            .unwrap_or(CompareOp::Equal);
        let literal = element.attr(AttrKey::Value).unwrap_or_default();
        let value = ComparisonValue::new(self.interner.intern(literal), literal);
        MatchCriteria::Comparison(Comparison {
            parameter,
            operator,
            value,
            use_calibrated: use_calibrated(element),
        })
    }

    fn lower_boolean_expression(
        &mut self,
        element: Element<'d>,
        space_system: SpaceSystemId,
    ) -> Option<BooleanExpr> {
        for child in element.children() {
            match child.tag() {
                Tag::Condition => {
                    return self
                        .lower_condition(child, space_system)
                        .map(BooleanExpr::Condition);
                }
                Tag::ANDedConditions => {
                    return Some(BooleanExpr::And(self.lower_expr_list(child, space_system)));
                }
                Tag::ORedConditions => {
                    return Some(BooleanExpr::Or(self.lower_expr_list(child, space_system)));
                }
                _ => {}
            }
        }
        None
    }

    fn lower_expr_list(
        &mut self,
        element: Element<'d>,
        space_system: SpaceSystemId,
    ) -> Vec<BooleanExpr> {
        let mut out = Vec::new();
        for child in element.children() {
            match child.tag() {
                Tag::Condition => {
                    if let Some(condition) = self.lower_condition(child, space_system) {
                        out.push(BooleanExpr::Condition(condition));
                    }
                }
                Tag::ANDedConditions => {
                    out.push(BooleanExpr::And(self.lower_expr_list(child, space_system)));
                }
                Tag::ORedConditions => {
                    out.push(BooleanExpr::Or(self.lower_expr_list(child, space_system)));
                }
                _ => {}
            }
        }
        out
    }

    fn lower_condition(
        &mut self,
        element: Element<'d>,
        space_system: SpaceSystemId,
    ) -> Option<Condition> {
        let mut operands = Vec::new();
        let mut operator = None;

        for child in element.children() {
            match child.tag() {
                Tag::ParameterInstanceRef => {
                    let reference = child.attr(AttrKey::ParameterRef).unwrap_or_default();
                    let parameter = self.resolve_parameter_opt(reference, space_system)?;
                    operands.push(Operand::Parameter {
                        parameter,
                        use_calibrated: use_calibrated(child),
                    });
                }
                Tag::Value => {
                    let text = child.text().unwrap_or_default();
                    operands.push(Operand::Literal(ComparisonValue::new(
                        self.interner.intern(text),
                        text,
                    )));
                }
                Tag::ComparisonOperator => {
                    operator = child.text().and_then(CompareOp::parse);
                }
                _ => {}
            }
        }

        let mut operands = operands.into_iter();
        Some(Condition {
            left: operands.next()?,
            operator: operator?,
            right: operands.next()?,
        })
    }

    fn unsupported_criteria(
        &mut self,
        element: Element<'d>,
        reason: &'static str,
    ) -> MatchCriteria {
        let name = element.name().to_owned();
        self.note_unsupported(&name, &element.path(), reason);
        MatchCriteria::Unsupported {
            element: self.interner.intern(&name),
        }
    }

    // ------------------------------------------------------------------- resolution

    fn qualified_of(&self, id: SpaceSystemId) -> &str {
        self.space_systems
            .get(id.index())
            .map(|system| self.interner.resolve(system.qualified_name))
            .unwrap_or_default()
    }

    fn resolve_parameter_opt(&mut self, reference: &str, from: SpaceSystemId) -> Option<ParamId> {
        self.resolve(reference, from, RefKind::Parameter)
            .map(ParamId::new)
    }

    /// Resolves an XTCE name reference to a raw index.
    ///
    /// XTCE reference syntax (CCSDS 660.1-G-2 §4.3.1) is path-like:
    ///
    /// * `/A/B/name` — absolute from the document root;
    /// * `sub/name`, `./name`, `../name` — relative to the current space system;
    /// * `name` — searched in the current space system, then each ancestor in turn.
    ///
    /// A final fallback searches the whole document by unqualified name. That is not in the
    /// standard, but the reference implementation keys its lookup tables that way, and
    /// several shipped databases rely on it.
    fn resolve(&mut self, reference: &str, from: SpaceSystemId, kind: RefKind) -> Option<u32> {
        let reference = reference.trim();
        if reference.is_empty() {
            return None;
        }

        if reference.starts_with('/') {
            normalize_into(&mut self.scratch, "", reference);
            if let Some(id) = self.lookup_qualified(kind) {
                return Some(id);
            }
        } else {
            let mut cursor = Some(from);
            while let Some(system) = cursor {
                let base = self.qualified_of(system);
                // `normalize_into` borrows `self.scratch` mutably while `base` borrows
                // `self` immutably, so the base has to be copied out first. It is short.
                let base = base.to_owned();
                normalize_into(&mut self.scratch, &base, reference);
                if let Some(id) = self.lookup_qualified(kind) {
                    return Some(id);
                }
                cursor = self
                    .space_systems
                    .get(system.index())
                    .and_then(|system| system.parent);
                if reference.contains('/') {
                    // Path-shaped references are only tried relative to the current system
                    // and absolutely; they do not walk up the tree.
                    break;
                }
            }
        }

        let leaf = reference.rsplit('/').next().unwrap_or(reference);
        let leaf_id = self.interner.get(leaf)?;
        match kind {
            RefKind::Parameter => self.param_by_leaf.get(&leaf_id).map(|id| id.raw()),
            RefKind::ParameterType => self.type_by_leaf.get(&leaf_id).map(|id| id.raw()),
            RefKind::Container => self.container_by_leaf.get(&leaf_id).map(|id| id.raw()),
        }
    }

    fn lookup_qualified(&self, kind: RefKind) -> Option<u32> {
        let id = self.interner.get(&self.scratch)?;
        match kind {
            RefKind::Parameter => self.param_by_qualified.get(&id).map(|id| id.raw()),
            RefKind::ParameterType => self.type_by_qualified.get(&id).map(|id| id.raw()),
            RefKind::Container => self.container_by_qualified.get(&id).map(|id| id.raw()),
        }
    }

    fn note_unsupported(&mut self, element: &str, path: &str, reason: &'static str) {
        self.unsupported.push(Unsupported {
            element: element.to_owned(),
            path: path.to_owned(),
            reason,
        });
    }
}

#[derive(Clone, Copy)]
enum Definition {
    Type,
    Parameter,
    Container,
}

fn insert_unique<T: Copy>(
    table: &mut FxHashMap<NameId, T>,
    key: NameId,
    value: T,
    kind: RefKind,
    qualified: &str,
    element: &Element<'_>,
) -> Result<(), XtceError> {
    if table.insert(key, value).is_some() {
        return Err(XtceError::DuplicateDefinition {
            kind,
            name: qualified.to_owned(),
            path: element.path(),
        });
    }
    Ok(())
}

/// Writes `base/reference` into `out`, resolving `.` and `..` segments.
fn normalize_into(out: &mut String, base: &str, reference: &str) {
    let mut segments: Vec<&str> = Vec::new();
    if !reference.starts_with('/') {
        segments.extend(base.split('/').filter(|part| !part.is_empty()));
    }
    for part in reference.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    out.clear();
    for segment in segments {
        out.push('/');
        out.push_str(segment);
    }
}

/// Folds a time parameter type's `<Encoding offset=.. scale=..>` into a polynomial
/// calibrator on its data encoding.
///
/// XTCE 4.3.2.4.8.3 expresses a time parameter's unit conversion as attributes rather than a
/// calibrator, but the two mean the same thing, so representing it as one keeps the decoder
/// from needing a special case. The offset term is emitted before the scale term: the terms
/// are summed in document order and floating-point addition is not associative, so the order
/// is part of the result.
fn apply_time_unit_scaler(type_element: Element<'_>, encoding: &mut DataEncoding) {
    let Some(element) = type_element.child(Tag::Encoding) else {
        return;
    };
    let offset = element.attr(AttrKey::Offset).and_then(parse_f64);
    let scale = element.attr(AttrKey::Scale).and_then(parse_f64);

    let mut terms = Vec::new();
    if let Some(offset) = offset {
        terms.push(PolynomialTerm {
            coefficient: offset,
            exponent: 0,
        });
    }
    match (scale, offset) {
        (Some(scale), _) => terms.push(PolynomialTerm {
            coefficient: scale,
            exponent: 1,
        }),
        // An offset with no scale still needs the identity term, or the raw value would be
        // dropped entirely.
        (None, Some(_)) => terms.push(PolynomialTerm {
            coefficient: 1.0,
            exponent: 1,
        }),
        (None, None) => return,
    }

    let calibrator = Some(Calibrator::Polynomial(terms));
    match encoding {
        DataEncoding::Integer(integer) => integer.default_calibrator = calibrator,
        DataEncoding::Float(float) => float.default_calibrator = calibrator,
        DataEncoding::String(_) | DataEncoding::Binary(_) | DataEncoding::None => {}
    }
}

fn integer_coding(text: &str) -> IntegerCoding {
    match text {
        // `twosCompliment` is a long-standing typo in the XTCE ecosystem and appears in
        // shipped databases; `signed` is informal but equally common.
        "twosComplement" | "twosCompliment" | "signed" => IntegerCoding::TwosComplement,
        "signMagnitude" => IntegerCoding::SignMagnitude,
        "onesComplement" | "onesCompliment" => IntegerCoding::OnesComplement,
        _ => IntegerCoding::Unsigned,
    }
}

fn float_coding(text: &str) -> FloatCoding {
    match text {
        "MILSTD_1750A" | "MIL-1750A" => FloatCoding::MilStd1750A,
        _ => FloatCoding::Ieee754,
    }
}

fn byte_order(text: Option<&str>) -> ByteOrder {
    match text {
        Some("leastSignificantByteFirst") => ByteOrder::LeastSignificantFirst,
        _ => ByteOrder::MostSignificantFirst,
    }
}

fn charset(text: &str) -> Charset {
    match text {
        "US-ASCII" => Charset::UsAscii,
        "ISO-8859-1" => Charset::Iso8859_1,
        "Windows-1252" => Charset::Windows1252,
        "UTF-16" | "UTF-16BE" | "UTF-16LE" => Charset::Utf16,
        "UTF-32" | "UTF-32BE" | "UTF-32LE" => Charset::Utf32,
        _ => Charset::Utf8,
    }
}

fn location_reference(text: Option<&str>) -> LocationReference {
    match text {
        Some("containerStart") => LocationReference::ContainerStart,
        Some("containerEnd") => LocationReference::ContainerEnd,
        Some("nextEntry") => LocationReference::NextEntry,
        _ => LocationReference::PreviousEntry,
    }
}

fn use_calibrated(element: Element<'_>) -> bool {
    element
        .attr(AttrKey::UseCalibratedValue)
        .is_none_or(|text| text.eq_ignore_ascii_case("true"))
}

fn linear_adjustment(element: Element<'_>) -> LinearAdjustment {
    LinearAdjustment {
        slope: element
            .attr(AttrKey::Slope)
            .and_then(parse_f64)
            .unwrap_or(0.0),
        intercept: element
            .attr(AttrKey::Intercept)
            .and_then(parse_f64)
            .unwrap_or(0.0),
    }
}

fn parse_f64(text: &str) -> Option<f64> {
    text.trim().parse::<f64>().ok()
}

fn parse_i128(text: &str) -> Option<i128> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return i128::from_str_radix(hex, 16).ok();
    }
    text.parse::<i128>().ok()
}

/// Parses a hex string such as `"58"` or `"5800"` into bytes, ignoring stray whitespace.
fn parse_hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .filter(|pair| pair.len() == 2)
        .filter_map(|pair| {
            let hi = (pair.first().copied()? as char).to_digit(16)?;
            let lo = (pair.get(1).copied()? as char).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

/// Fills each container's `inheritors` list from the `base` links.
fn link_inheritors(containers: &mut [Container]) {
    let links: Vec<(ContainerId, ContainerId)> = containers
        .iter()
        .enumerate()
        .filter_map(|(index, container)| {
            let base = container.base?;
            let id = ContainerId::new(u32::try_from(index).unwrap_or(u32::MAX));
            Some((base, id))
        })
        .collect();
    for (base, child) in links {
        if let Some(container) = containers.get_mut(base.index()) {
            container.inheritors.push(child);
        }
    }
}

/// Rejects cyclic container inheritance.
///
/// Without this, a database where `A` extends `B` and `B` extends `A` would recurse until
/// the stack overflows on the first packet. Iterative three-colour marking keeps the check
/// itself stack-safe for arbitrarily deep hierarchies.
fn check_acyclic(containers: &[Container], interner: &Interner) -> Result<(), XtceError> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        Unvisited,
        InProgress,
        Done,
    }

    let mut marks = vec![Mark::Unvisited; containers.len()];
    for start in 0..containers.len() {
        if marks.get(start).copied() != Some(Mark::Unvisited) {
            continue;
        }
        let mut chain: Vec<usize> = Vec::new();
        let mut cursor = Some(start);
        while let Some(index) = cursor {
            match marks.get(index).copied() {
                Some(Mark::InProgress) => {
                    let cycle_start = chain.iter().position(|&item| item == index).unwrap_or(0);
                    let names = chain
                        .get(cycle_start..)
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|&item| containers.get(item))
                        .map(|container| interner.resolve(container.qualified_name).to_owned())
                        .collect::<Vec<_>>();
                    return Err(XtceError::InheritanceCycle { chain: names });
                }
                Some(Mark::Done) | None => break,
                Some(Mark::Unvisited) => {}
            }
            if let Some(mark) = marks.get_mut(index) {
                *mark = Mark::InProgress;
            }
            chain.push(index);
            cursor = containers
                .get(index)
                .and_then(|c| c.base)
                .map(super::ids::ContainerId::index);
        }
        for index in chain {
            if let Some(mark) = marks.get_mut(index) {
                *mark = Mark::Done;
            }
        }
    }
    Ok(())
}
