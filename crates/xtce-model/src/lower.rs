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

use crate::commands::MetaCommand;
use crate::containers::{
    BooleanExpr, CompareOp, Comparison, ComparisonValue, Condition, Container, Entry, EntryKind,
    Location, LocationReference, MatchCriteria, Operand, SpaceSystem,
};
use crate::db::{Unsupported, XtceDb};
use crate::error::{RefKind, XtceError};
use crate::ids::{ContainerId, MetaCommandId, ParamId, SpaceSystemId, Span, TypeId};
use crate::intern::{FxHashMap, Interner, NameId};
use crate::types::{
    AggregateMember, ArrayDimension, BinaryEncoding, ByteOrder, Calibrator, Charset,
    ContextCalibrator, DataEncoding, DiscreteLookup, Enumeration, EnumerationList, FloatCoding,
    FloatEncoding, IntegerCoding, IntegerEncoding, LinearAdjustment, Parameter, ParameterType,
    PolynomialTerm, SizeSpec, Spline, SplinePoint, StringDelimiter, StringEncoding, TypeKind,
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
    /// For a container, the telecommand whose `<CommandContainer>` it is.
    ///
    /// `None` for every telemetry container, and for the shared ones in a
    /// `<CommandContainerSet>`. It is what tells the entry lowering that `argumentRef` in
    /// this container resolves against that command's arguments and nothing else.
    command: Option<MetaCommandId>,
}

/// A `<MetaCommand>` registered in pass 1.
struct PendingCommand<'d> {
    element: Element<'d>,
    space_system: SpaceSystemId,
    qualified_name: NameId,
    /// The arguments it declares itself, by unqualified name, in document order.
    arguments: Vec<(NameId, ParamId)>,
    /// Its `<CommandContainer>`, if it has one.
    container: Option<ContainerId>,
    /// Resolved from `<BaseMetaCommand metaCommandRef=..>` once every command is registered.
    base: Option<MetaCommandId>,
}

pub(crate) struct Lowering<'d> {
    dom: &'d Dom,
    interner: Interner,

    space_systems: Vec<SpaceSystem>,
    /// Qualified path of each space system, owned separately from the interner.
    ///
    /// Building `"{parent}/{name}"` needs to read a path while writing to the interner. Held
    /// as its own `Vec`, the two are disjoint fields and the borrow checker allows it; read
    /// back out of the interner, every call would have to clone the parent path first —
    /// which is one allocation per definition, and a large database has ten thousand.
    ss_paths: Vec<String>,
    pending_types: Vec<Pending<'d>>,
    pending_params: Vec<Pending<'d>>,
    pending_containers: Vec<Pending<'d>>,
    pending_commands: Vec<PendingCommand<'d>>,
    /// Every argument each command can name, its own and its bases', by unqualified name.
    ///
    /// Indexed by [`MetaCommandId`] and filled by `resolve_command_bases` before anything is
    /// lowered, because an entry list resolves `argumentRef` through it.
    command_arguments: Vec<FxHashMap<NameId, ParamId>>,
    /// Bytes behind every `<FixedValueEntry>`, in one arena.
    fixed_values: Vec<u8>,

    type_by_qualified: FxHashMap<NameId, TypeId>,
    type_by_leaf: FxHashMap<NameId, TypeId>,
    param_by_qualified: FxHashMap<NameId, ParamId>,
    param_by_leaf: FxHashMap<NameId, ParamId>,
    container_by_qualified: FxHashMap<NameId, ContainerId>,
    container_by_leaf: FxHashMap<NameId, ContainerId>,
    command_by_qualified: FxHashMap<NameId, MetaCommandId>,
    command_by_leaf: FxHashMap<NameId, MetaCommandId>,

    unsupported: Vec<Unsupported>,
    /// Reusable buffer for building candidate qualified names during resolution.
    scratch: String,
}

impl<'d> Lowering<'d> {
    pub(crate) fn new(dom: &'d Dom) -> Self {
        // Two names per element is a generous upper bound (a definition contributes its own
        // name and its qualified path), and over-reserving here costs one allocation while
        // under-reserving costs a full rehash part-way through lowering.
        let interner = Interner::with_capacity(dom.len() * 2, dom.len() * 8);
        Self {
            dom,
            interner,
            space_systems: Vec::new(),
            ss_paths: Vec::new(),
            pending_types: Vec::new(),
            pending_params: Vec::new(),
            pending_containers: Vec::new(),
            pending_commands: Vec::new(),
            command_arguments: Vec::new(),
            fixed_values: Vec::new(),
            type_by_qualified: FxHashMap::default(),
            type_by_leaf: FxHashMap::default(),
            param_by_qualified: FxHashMap::default(),
            param_by_leaf: FxHashMap::default(),
            container_by_qualified: FxHashMap::default(),
            container_by_leaf: FxHashMap::default(),
            command_by_qualified: FxHashMap::default(),
            command_by_leaf: FxHashMap::default(),
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
        // Before anything is lowered: an entry list in a command container resolves
        // `argumentRef` against the command's arguments *and its bases'*, so the inheritance
        // has to be settled first.
        self.resolve_command_bases()?;

        let types = self.lower_types()?;
        let mut parameters = self.lower_parameters()?;
        // `lower_containers` may append to `parameters`: an entry naming an array is expanded
        // into one synthetic parameter per index, so that nothing downstream has to know what
        // an array is.
        let (mut containers, entries) = self.lower_containers(&types, &mut parameters)?;
        let meta_commands = self.lower_commands();

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
            meta_commands,
            fixed_values: self.fixed_values,
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

        let mut qualified = String::new();
        if let Some(parent) = parent {
            qualified.push_str(self.ss_paths.get(parent.index()).map_or("", String::as_str));
        }
        qualified.push('/');
        qualified.push_str(name);

        let id = SpaceSystemId::new(u32::try_from(self.space_systems.len()).unwrap_or(u32::MAX));
        let name_id = self.interner.intern(name);
        let qualified_id = self.interner.intern(&qualified);
        self.ss_paths.push(qualified);
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

        if let Some(commands) = element.child(Tag::CommandMetaData) {
            self.register_command_meta_data(commands, id)?;
        }

        for child in element.children_with(Tag::SpaceSystem) {
            self.register_space_system(child, Some(id))?;
        }
        Ok(id)
    }

    /// Registers what a `<CommandMetaData>` section defines.
    ///
    /// It may hold its own `<ParameterTypeSet>` and `<ParameterSet>` as well as an
    /// `<ArgumentTypeSet>` — the schema puts them there "so that `MetaCommand` data can be
    /// built independently of `TelemetryMetaData`" — and all three register exactly as their
    /// telemetry counterparts do. An argument type is a parameter type: the encodings are the
    /// same elements, and `IntegerArgumentType` extends the same base `IntegerParameterType`
    /// does.
    fn register_command_meta_data(
        &mut self,
        element: Element<'d>,
        space_system: SpaceSystemId,
    ) -> Result<(), XtceError> {
        for set in [Tag::ParameterTypeSet, Tag::ArgumentTypeSet] {
            if let Some(set) = element.child(set) {
                for child in set.children() {
                    self.register(child, space_system, Definition::Type)?;
                }
            }
        }
        if let Some(set) = element.child(Tag::ParameterSet) {
            for child in set.children_with(Tag::Parameter) {
                self.register(child, space_system, Definition::Parameter)?;
            }
        }
        // Containers here are the shared kind: "containers that can be referenced/shared by
        // MetaCommand definitions". They are named at the system level like any other, which
        // a MetaCommand's own private container is not.
        if let Some(set) = element.child(Tag::CommandContainerSet) {
            for child in set.children() {
                self.register(child, space_system, Definition::Container)?;
            }
        }
        if let Some(set) = element.child(Tag::MetaCommandSet) {
            for child in set.children_with(Tag::MetaCommand) {
                self.register_meta_command(child, space_system)?;
            }
        }
        Ok(())
    }

    /// Registers one `<MetaCommand>`, its arguments and its container.
    ///
    /// Arguments are qualified under the command — `/SS/SET_MODE/MODE` — because the schema
    /// says an argument reference "is always resolved locally to the metacommand", and two
    /// commands may each declare a `MODE`. They are deliberately *not* added to the
    /// unqualified index: that index is what `<Comparison parameterRef=..>` and every
    /// telemetry reference searches, and an argument appearing there could shadow a real
    /// parameter of the same name.
    ///
    /// The container is qualified under the command for the same reason and one more: the
    /// schema's uniqueness key for container names covers `ContainerSet` and
    /// `CommandContainerSet` but *not* a `MetaCommand`'s own `<CommandContainer>`, which is
    /// "private except as referred to in `BaseMetaCommand`". Two commands may therefore give
    /// their containers the same name, and registering both at the system level would reject
    /// a file the schema allows. It is still indexed by its bare name, first one winning, so
    /// that the usual `<BaseContainer containerRef="SOME_CMD_CONTAINER">` resolves.
    fn register_meta_command(
        &mut self,
        element: Element<'d>,
        space_system: SpaceSystemId,
    ) -> Result<(), XtceError> {
        let Some(name) = element.attr(AttrKey::Name) else {
            return Err(XtceError::Missing {
                what: "MetaCommand name attribute",
                path: element.path(),
            });
        };
        let id = MetaCommandId::new(u32::try_from(self.pending_commands.len()).unwrap_or(u32::MAX));

        let ss_path = self
            .ss_paths
            .get(space_system.index())
            .map_or(String::new(), Clone::clone);
        let qualified = format!("{ss_path}/{name}");
        let qualified_id = self.interner.intern(&qualified);
        insert_unique(
            &mut self.command_by_qualified,
            qualified_id,
            id,
            RefKind::MetaCommand,
            &qualified,
            &element,
        )?;
        let leaf_id = self.interner.intern(name);
        self.command_by_leaf.entry(leaf_id).or_insert(id);

        let mut arguments = Vec::new();
        if let Some(list) = element.child(Tag::ArgumentList) {
            for argument in list.children_with(Tag::Argument) {
                let Some(argument_name) = argument.attr(AttrKey::Name) else {
                    return Err(XtceError::Missing {
                        what: "Argument name attribute",
                        path: argument.path(),
                    });
                };
                let argument_qualified = format!("{qualified}/{argument_name}");
                let argument_qualified_id = self.interner.intern(&argument_qualified);
                let param_id =
                    ParamId::new(u32::try_from(self.pending_params.len()).unwrap_or(u32::MAX));
                self.pending_params.push(Pending {
                    element: argument,
                    space_system,
                    qualified_name: argument_qualified_id,
                    command: None,
                });
                insert_unique(
                    &mut self.param_by_qualified,
                    argument_qualified_id,
                    param_id,
                    RefKind::Parameter,
                    &argument_qualified,
                    &argument,
                )?;
                arguments.push((self.interner.intern(argument_name), param_id));
            }
        }

        let mut container = None;
        if let Some(element) = element.child(Tag::CommandContainer) {
            let Some(container_name) = element.attr(AttrKey::Name) else {
                return Err(XtceError::Missing {
                    what: "CommandContainer name attribute",
                    path: element.path(),
                });
            };
            let container_qualified = format!("{qualified}/{container_name}");
            let container_qualified_id = self.interner.intern(&container_qualified);
            let container_id =
                ContainerId::new(u32::try_from(self.pending_containers.len()).unwrap_or(u32::MAX));
            self.pending_containers.push(Pending {
                element,
                space_system,
                qualified_name: container_qualified_id,
                command: Some(id),
            });
            insert_unique(
                &mut self.container_by_qualified,
                container_qualified_id,
                container_id,
                RefKind::Container,
                &container_qualified,
                &element,
            )?;
            let container_leaf = self.interner.intern(container_name);
            self.container_by_leaf
                .entry(container_leaf)
                .or_insert(container_id);
            container = Some(container_id);
        }

        self.pending_commands.push(PendingCommand {
            element,
            space_system,
            qualified_name: qualified_id,
            arguments,
            container,
            base: None,
        });
        Ok(())
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
        // `scratch` is moved out and back so that reading a space-system path and writing to
        // the interner do not overlap; no allocation happens after the first definition.
        let mut scratch = std::mem::take(&mut self.scratch);
        scratch.clear();
        scratch.push_str(
            self.ss_paths
                .get(space_system.index())
                .map_or("", String::as_str),
        );
        scratch.push('/');
        scratch.push_str(name);
        let qualified_id = self.interner.intern(&scratch);
        let leaf_id = self.interner.intern(name);
        let qualified = &scratch;

        let pending = Pending {
            element,
            space_system,
            qualified_name: qualified_id,
            command: None,
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
                    qualified,
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
                    qualified,
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
                    qualified,
                    &element,
                )?;
                self.container_by_leaf.entry(leaf_id).or_insert(id);
            }
        }
        self.scratch = scratch;
        Ok(())
    }

    /// Resolves `<BaseMetaCommand>` links and works out what arguments each command can name.
    ///
    /// A command's arguments are its own plus every base's, with a derived declaration
    /// shadowing an inherited one of the same name — the same rule a struct's fields follow,
    /// and the reason the chain is walked root-first.
    fn resolve_command_bases(&mut self) -> Result<(), XtceError> {
        for index in 0..self.pending_commands.len() {
            let (reference, space_system, path) = {
                let command = &self.pending_commands[index];
                let Some(base) = command.element.child(Tag::BaseMetaCommand) else {
                    continue;
                };
                let Some(reference) = base.attr(AttrKey::MetaCommandRef) else {
                    return Err(XtceError::Missing {
                        what: "metaCommandRef attribute",
                        path: base.path(),
                    });
                };
                (reference.to_owned(), command.space_system, base.path())
            };
            let resolved = self
                .resolve(&reference, space_system, RefKind::MetaCommand)
                .ok_or_else(|| XtceError::UnresolvedReference {
                    kind: RefKind::MetaCommand,
                    reference: reference.clone(),
                    path,
                })?;
            self.pending_commands[index].base = Some(MetaCommandId::new(resolved));
        }

        self.command_arguments = Vec::with_capacity(self.pending_commands.len());
        for index in 0..self.pending_commands.len() {
            // Root-first, so an argument a command declares itself wins over the inherited
            // one it shadows.
            let mut chain = vec![index];
            let mut cursor = self.pending_commands[index].base;
            while let Some(base) = cursor {
                if chain.contains(&base.index()) {
                    return Err(XtceError::InheritanceCycle {
                        chain: chain
                            .iter()
                            .chain(std::iter::once(&base.index()))
                            .map(|&at| self.command_name(at))
                            .collect(),
                    });
                }
                chain.push(base.index());
                cursor = self
                    .pending_commands
                    .get(base.index())
                    .and_then(|command| command.base);
            }

            let mut arguments = FxHashMap::default();
            for &at in chain.iter().rev() {
                if let Some(command) = self.pending_commands.get(at) {
                    for &(name, parameter) in &command.arguments {
                        arguments.insert(name, parameter);
                    }
                }
            }
            self.command_arguments.push(arguments);
        }
        Ok(())
    }

    fn command_name(&self, at: usize) -> String {
        self.pending_commands
            .get(at)
            .map(|command| self.interner.resolve(command.qualified_name).to_owned())
            .unwrap_or_default()
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

        // An argument type is a parameter type. XTCE spells them differently because an
        // argument may carry a `<ValidRangeSet>` a parameter may not, but the encodings are
        // the same elements and every `*ArgumentType` extends the same base its
        // `*ParameterType` twin does.
        let kind = match element.tag() {
            Tag::IntegerParameterType | Tag::IntegerArgumentType => TypeKind::Integer,
            Tag::FloatParameterType | Tag::FloatArgumentType => TypeKind::Float,
            Tag::StringParameterType | Tag::StringArgumentType => TypeKind::String,
            Tag::BinaryParameterType | Tag::BinaryArgumentType => TypeKind::Binary,
            Tag::BooleanParameterType | Tag::BooleanArgumentType => TypeKind::Boolean {
                zero_label: element
                    .attr(AttrKey::ZeroStringValue)
                    .map(|text| self.interner.intern(text)),
                one_label: element
                    .attr(AttrKey::OneStringValue)
                    .map(|text| self.interner.intern(text)),
            },
            Tag::EnumeratedParameterType | Tag::EnumeratedArgumentType => {
                self.lower_enumeration(element)
            }
            Tag::AbsoluteTimeParameterType | Tag::AbsoluteTimeArgumentType => {
                TypeKind::AbsoluteTime {
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
                }
            }
            Tag::RelativeTimeParameterType | Tag::RelativeTimeArgumentType => {
                TypeKind::RelativeTime
            }
            Tag::ArrayParameterType | Tag::ArrayArgumentType => {
                self.lower_array_type(element, pending.space_system)
            }
            Tag::AggregateParameterType | Tag::AggregateArgumentType => {
                self.lower_aggregate_type(element, pending.space_system)
            }
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

    /// `<ArrayParameterType>`: an element type and one dimension per axis.
    ///
    /// Anything the expansion could not carry out is reported as unsupported rather than
    /// guessed at, and the type still loads — `xtce info` names it, and only a container that
    /// actually uses it is blocked.
    fn lower_array_type(&mut self, element: Element<'d>, space_system: SpaceSystemId) -> TypeKind {
        let unsupported = |lower: &mut Self, reason: &'static str| {
            let name = element.name().to_owned();
            lower.note_unsupported(&name, &element.path(), reason);
            TypeKind::Unsupported {
                element: lower.interner.intern(&name),
            }
        };

        let Some(reference) = element.attr(AttrKey::ArrayTypeRef) else {
            return unsupported(self, "an array type with no arrayTypeRef has no elements");
        };
        let Some(element_type) = self.resolve(reference, space_system, RefKind::ParameterType)
        else {
            return unsupported(self, "the arrayTypeRef does not resolve");
        };

        let Some(list) = element.child(Tag::DimensionList) else {
            return unsupported(self, "an array type with no DimensionList has no size");
        };

        let mut dimensions = Vec::new();
        for dimension in list.children_with(Tag::Dimension) {
            // `StartingIndex` and `EndingIndex` are `IntegerValueType`, so each may also be a
            // `DynamicValue` or a `DiscreteLookupList`. Those make the element count a
            // property of the packet, and the expansion happens before any packet exists.
            let (Some(start), Some(end)) = (
                fixed_index(dimension.child(Tag::StartingIndex)),
                fixed_index(dimension.child(Tag::EndingIndex)),
            ) else {
                return unsupported(
                    self,
                    "only a Dimension with fixed StartingIndex and EndingIndex is expanded; a \
                     dimension read from the packet is not",
                );
            };
            if start < 0 || end < start {
                return unsupported(
                    self,
                    "a Dimension must run from a non-negative index upwards",
                );
            }
            dimensions.push(ArrayDimension { start, end });
        }

        if dimensions.is_empty() {
            return unsupported(self, "an array type with no Dimension has no size");
        }

        TypeKind::Array {
            element: TypeId::new(element_type),
            dimensions,
        }
    }

    /// `<AggregateParameterType>`: an ordered, packed list of named members.
    fn lower_aggregate_type(
        &mut self,
        element: Element<'d>,
        space_system: SpaceSystemId,
    ) -> TypeKind {
        let unsupported = |lower: &mut Self, reason: &'static str| {
            let name = element.name().to_owned();
            lower.note_unsupported(&name, &element.path(), reason);
            TypeKind::Unsupported {
                element: lower.interner.intern(&name),
            }
        };

        let Some(list) = element.child(Tag::MemberList) else {
            return unsupported(self, "an aggregate with no MemberList has no members");
        };

        let mut members = Vec::new();
        for member in list.children_with(Tag::Member) {
            let Some(name) = member.attr(AttrKey::Name) else {
                return unsupported(self, "a Member with no name cannot be addressed");
            };
            let Some(reference) = member.attr(AttrKey::TypeRef) else {
                return unsupported(self, "a Member with no typeRef has no width");
            };
            let name = self.interner.intern(name);
            let Some(type_id) = self.resolve(reference, space_system, RefKind::ParameterType)
            else {
                return unsupported(self, "a Member's typeRef does not resolve");
            };
            members.push(AggregateMember {
                name,
                type_id: TypeId::new(type_id),
            });
        }

        if members.is_empty() {
            return unsupported(self, "an aggregate with no Member has no members");
        }

        TypeKind::Aggregate { members }
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
            // `<Parameter parameterTypeRef=..>` and `<Argument argumentTypeRef=..>` are the
            // same thing named twice; an argument arrives here because arguments are lowered
            // as parameters.
            let type_ref = element
                .attr(AttrKey::ParameterTypeRef)
                .or_else(|| element.attr(AttrKey::ArgumentTypeRef))
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

    fn lower_containers(
        &mut self,
        types: &[ParameterType],
        parameters: &mut Vec<Parameter>,
    ) -> Result<(Vec<Container>, Vec<Entry>), XtceError> {
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

            let mut restriction = base_element
                .and_then(|base| base.child(Tag::RestrictionCriteria))
                .map(|criteria| self.lower_criteria_children(criteria, item.space_system))
                .unwrap_or_default();
            // An `<ArgumentAssignment>` is a restriction criterion written the other way
            // round. It says this command is the base command with an argument pinned to a
            // value; that pinning is what specialises the definition, and comparing the same
            // bits is what recognises an arriving packet as this command rather than as a
            // sibling. So it joins the criteria the container already has.
            if let Some(command) = item.command {
                restriction.extend(self.argument_assignments(command)?);
            }

            let start = entries.len();
            if let Some(list) = element.child(Tag::EntryList) {
                for entry in list.children() {
                    self.lower_entry(
                        entry,
                        item.space_system,
                        item.command,
                        types,
                        parameters,
                        &mut entries,
                    )?;
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

    /// `<FixedValueEntry>`: bits the definition writes and nobody supplies.
    ///
    /// The bytes go into a shared arena because an entry is `Copy` and cannot own them. The
    /// width is the entry's own and is not derived from the bytes: XTCE requires both
    /// attributes and does not require them to agree.
    fn fixed_value_entry(&mut self, element: Element<'d>) -> Result<EntryKind, XtceError> {
        let Some(hex) = element.attr(AttrKey::BinaryValue) else {
            return Err(XtceError::Missing {
                what: "binaryValue attribute",
                path: element.path(),
            });
        };
        let Some(size_in_bits) = element
            .attr(AttrKey::SizeInBits)
            .and_then(|text| text.trim().parse::<u32>().ok())
        else {
            return Err(XtceError::Missing {
                what: "sizeInBits attribute",
                path: element.path(),
            });
        };
        let bytes = parse_hex(hex);
        let start = self.fixed_values.len();
        self.fixed_values.extend_from_slice(&bytes);
        Ok(EntryKind::FixedValue {
            value: Span::between(start, self.fixed_values.len()),
            size_in_bits,
        })
    }

    /// Lowers one `<EntryList>` child, appending one entry — or, for an array, several.
    fn lower_entry(
        &mut self,
        element: Element<'d>,
        space_system: SpaceSystemId,
        command: Option<MetaCommandId>,
        types: &[ParameterType],
        parameters: &mut Vec<Parameter>,
        out: &mut Vec<Entry>,
    ) -> Result<(), XtceError> {
        let kind = match element.tag() {
            Tag::ParameterRefEntry
            | Tag::ArrayParameterRefEntry
            | Tag::ArgumentRefEntry
            | Tag::ArrayArgumentRefEntry => {
                let argument = matches!(
                    element.tag(),
                    Tag::ArgumentRefEntry | Tag::ArrayArgumentRefEntry
                );
                let attribute = if argument {
                    AttrKey::ArgumentRef
                } else {
                    AttrKey::ParameterRef
                };
                let reference = element.attr(attribute).ok_or_else(|| XtceError::Missing {
                    what: if argument {
                        "argumentRef attribute"
                    } else {
                        "parameterRef attribute"
                    },
                    path: element.path(),
                })?;
                // An argument reference is resolved against the command that owns this
                // container and nowhere else — "there is no path, this is a local
                // reference" — so it can neither reach another command's argument nor fall
                // back to a telemetry parameter that happens to share the name.
                let found = if argument {
                    self.lower_argument_lookup(command, reference)
                } else {
                    self.resolve(reference, space_system, RefKind::Parameter)
                        .map(ParamId::new)
                };
                let id = found.ok_or_else(|| XtceError::UnresolvedReference {
                    kind: RefKind::Parameter,
                    reference: reference.to_owned(),
                    path: element.path(),
                })?;

                // An array is a repetition, so it becomes a repetition of entries. Doing it
                // here means the interpreter, the code generator and the flight encoder all
                // see ordinary fields and none of them has to know arrays exist.
                if let Some(expanded) = self.expand_composite(element, id, types, parameters)? {
                    out.extend(expanded);
                    return Ok(());
                }
                EntryKind::Parameter(id)
            }
            Tag::FixedValueEntry => self.fixed_value_entry(element)?,
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

        out.push(Entry {
            kind,
            location,
            repeat,
        });
        Ok(())
    }

    /// Turns an entry that names an array or an aggregate into one entry per leaf field, or
    /// `None` if it names neither.
    ///
    /// Both are containers of other things, and both are laid out packed and in order, so
    /// both flatten the same way: an array repeats one type under `[i]`, an aggregate lists
    /// named members under `.name`, and either may hold the other. What comes out is one
    /// synthetic parameter per leaf, carrying the leaf's own type and a name that spells the
    /// path to it — `GRID[1][2]`, `STATE.voltage`, `SENSORS[0].reading`.
    ///
    /// The synthetic parameters go into the arena but **not** into the name-resolution index.
    /// That index is what `<Comparison parameterRef=…>`, `DynamicValue` and context
    /// calibrators all search, and a synthetic entry there could shadow a real parameter.
    fn expand_composite(
        &mut self,
        element: Element<'d>,
        parameter: ParamId,
        types: &[ParameterType],
        parameters: &mut Vec<Parameter>,
    ) -> Result<Option<Vec<Entry>>, XtceError> {
        let Some(declared) = parameters.get(parameter.index()) else {
            return Ok(None);
        };
        let type_id = declared.type_id;
        let Some(ty) = types.get(type_id.index()) else {
            return Ok(None);
        };
        if !matches!(ty.kind, TypeKind::Array { .. } | TypeKind::Aggregate { .. }) {
            return Ok(None);
        }

        let base_name = self.interner.resolve(declared.name).to_owned();
        let qualified = declared.qualified_name;
        let space_system = declared.space_system;
        let path = element.path();

        // A `<DimensionList>` on the *entry* subsets the outermost array; the type carries
        // the full size. XTCE: "Only used for subsetting an array. The array's maximum
        // dimension sizes are set in the type." It says nothing about subsetting anything
        // nested, so nothing nested is subset.
        let subset = match element.child(Tag::DimensionList) {
            None => None,
            Some(list) => {
                let mut chosen = Vec::new();
                for dimension in list.children_with(Tag::Dimension) {
                    let (Some(start), Some(end)) = (
                        fixed_index(dimension.child(Tag::StartingIndex)),
                        fixed_index(dimension.child(Tag::EndingIndex)),
                    ) else {
                        return Err(XtceError::ArrayNotExpanded {
                            reason: "a subset with an index read from the packet cannot be \
                                     expanded when the file is loaded"
                                .to_owned(),
                            path,
                        });
                    };
                    chosen.push(ArrayDimension { start, end });
                }
                Some(chosen)
            }
        };

        let mut leaves = Vec::new();
        let mut visiting = Vec::new();
        self.collect_leaves(
            type_id,
            &base_name,
            subset.as_deref(),
            &mut Walk {
                types,
                out: &mut leaves,
                visiting: &mut visiting,
                path: &path,
            },
        )?;

        let mut out = Vec::with_capacity(leaves.len());
        for (name, leaf) in leaves {
            let Ok(id) = u32::try_from(parameters.len()) else {
                return Err(XtceError::ArrayNotExpanded {
                    reason: "the parameter arena is full".to_owned(),
                    path,
                });
            };
            parameters.push(Parameter {
                name: self.interner.intern(&name),
                qualified_name: qualified,
                space_system,
                type_id: leaf,
                short_description: None,
                long_description: None,
                initial_value: None,
            });
            out.push(Entry {
                kind: EntryKind::Parameter(ParamId::new(id)),
                location: None,
                repeat: None,
            });
        }
        Ok(Some(out))
    }

    /// Walks a type, appending `(name, type)` for every leaf it eventually contains.
    ///
    /// `visiting` holds the composite types on the current path. XTCE says circular member
    /// references are not allowed, but a file can still contain one, and following it would
    /// not terminate.
    fn collect_leaves(
        &mut self,
        type_id: TypeId,
        prefix: &str,
        subset: Option<&[ArrayDimension]>,
        walk: &mut Walk<'_>,
    ) -> Result<(), XtceError> {
        let Some(ty) = walk.types.get(type_id.index()) else {
            return Err(XtceError::ArrayNotExpanded {
                reason: "a member or element type does not resolve".to_owned(),
                path: walk.path.to_owned(),
            });
        };

        match &ty.kind {
            TypeKind::Array {
                element,
                dimensions,
            } => {
                let element = *element;
                let declared = dimensions.clone();
                let spans = match subset {
                    None => declared,
                    Some(chosen) => {
                        if chosen.len() != declared.len() {
                            return Err(XtceError::ArrayNotExpanded {
                                reason: format!(
                                    "the type has {} dimension(s) and the subset gives {}",
                                    declared.len(),
                                    chosen.len()
                                ),
                                path: walk.path.to_owned(),
                            });
                        }
                        for (one, whole) in chosen.iter().zip(&declared) {
                            if one.start < whole.start || one.end > whole.end || one.is_empty() {
                                return Err(XtceError::ArrayNotExpanded {
                                    reason: format!(
                                        "the subset {}..={} lies outside the declared {}..={}",
                                        one.start, one.end, whole.start, whole.end
                                    ),
                                    path: walk.path.to_owned(),
                                });
                            }
                        }
                        chosen.to_vec()
                    }
                };

                Self::enter(type_id, walk.visiting, walk.path)?;
                // Row-major, because XTCE says so: "the last dimension is assumed to be the
                // least significant — that is this dimension will cycle through its
                // combination before the next to last dimension changes."
                let count = spans
                    .iter()
                    .try_fold(1usize, |total, span| total.checked_mul(span.len()?));
                let Some(count) = count else {
                    return Err(XtceError::ArrayNotExpanded {
                        reason: "the element count overflows a usize".to_owned(),
                        path: walk.path.to_owned(),
                    });
                };
                let mut indices: Vec<i64> = spans.iter().map(|span| span.start).collect();
                for _ in 0..count {
                    let mut name = prefix.to_owned();
                    for index in &indices {
                        let _ = std::fmt::Write::write_fmt(&mut name, format_args!("[{index}]"));
                    }
                    self.collect_leaves(element, &name, None, walk)?;
                    for (axis, index) in indices.iter_mut().enumerate().rev() {
                        *index += 1;
                        if *index <= spans[axis].end {
                            break;
                        }
                        *index = spans[axis].start;
                    }
                }
                walk.visiting.pop();
            }

            TypeKind::Aggregate { members } => {
                let members = members.clone();
                Self::enter(type_id, walk.visiting, walk.path)?;
                for member in &members {
                    // "Each member may be addressed by the dot syntax similar to C such as
                    // P.voltage."
                    let name = format!("{prefix}.{}", self.interner.resolve(member.name));
                    self.collect_leaves(member.type_id, &name, None, walk)?;
                }
                walk.visiting.pop();
            }

            _ => {
                if walk.out.len() >= MAX_EXPANDED_FIELDS {
                    return Err(XtceError::ArrayNotExpanded {
                        reason: format!(
                            "more than {MAX_EXPANDED_FIELDS} fields, and each one becomes a \
                             parameter and a struct field"
                        ),
                        path: walk.path.to_owned(),
                    });
                }
                walk.out.push((prefix.to_owned(), type_id));
            }
        }
        Ok(())
    }

    /// Records that the expansion has descended into a composite type, refusing a cycle.
    fn enter(type_id: TypeId, visiting: &mut Vec<TypeId>, path: &str) -> Result<(), XtceError> {
        if visiting.contains(&type_id) {
            return Err(XtceError::ArrayNotExpanded {
                reason: "the type contains itself, so expanding it would not terminate".to_owned(),
                path: path.to_owned(),
            });
        }
        visiting.push(type_id);
        Ok(())
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

    /// One argument of `command`, by the bare name an `argumentRef` writes.
    fn lower_argument_lookup(&self, command: Option<MetaCommandId>, name: &str) -> Option<ParamId> {
        let name = self.interner.get(name.trim())?;
        self.command_arguments
            .get(command?.index())
            .and_then(|arguments| arguments.get(&name))
            .copied()
    }

    /// The criteria a command's `<ArgumentAssignmentList>` amounts to.
    ///
    /// Each assignment pins an argument of the *base* command to a value, so each becomes a
    /// comparison against that argument. `argumentValue` is documented as a
    /// "calibrated/engineering value", which is what `useCalibratedValue` defaulting to true
    /// means for a `<Comparison>` — so the criterion is built that way, and an assignment on
    /// an enumerated argument then compares labels, which the code generator refuses by name
    /// rather than compiling into something that disagrees with the interpreter.
    fn argument_assignments(
        &mut self,
        command: MetaCommandId,
    ) -> Result<Vec<MatchCriteria>, XtceError> {
        let Some(pending) = self.pending_commands.get(command.index()) else {
            return Ok(Vec::new());
        };
        let Some(base) = pending.element.child(Tag::BaseMetaCommand) else {
            return Ok(Vec::new());
        };
        let Some(list) = base.child(Tag::ArgumentAssignmentList) else {
            return Ok(Vec::new());
        };

        let assignments: Vec<Element<'d>> = list.children_with(Tag::ArgumentAssignment).collect();
        let mut out = Vec::with_capacity(assignments.len());
        for assignment in assignments {
            let Some(name) = assignment.attr(AttrKey::ArgumentName) else {
                return Err(XtceError::Missing {
                    what: "argumentName attribute",
                    path: assignment.path(),
                });
            };
            let parameter = self
                .lower_argument_lookup(Some(command), name)
                .ok_or_else(|| XtceError::UnresolvedReference {
                    kind: RefKind::Parameter,
                    reference: name.to_owned(),
                    path: assignment.path(),
                })?;
            let literal = assignment.attr(AttrKey::ArgumentValue).unwrap_or_default();
            let value = ComparisonValue::new(self.interner.intern(literal), literal);
            out.push(MatchCriteria::Comparison(Comparison {
                parameter,
                operator: CompareOp::Equal,
                value,
                use_calibrated: true,
            }));
        }
        Ok(out)
    }

    /// Every telecommand, once the containers behind them are lowered.
    fn lower_commands(&mut self) -> Vec<MetaCommand> {
        let pending = std::mem::take(&mut self.pending_commands);
        let out = pending
            .iter()
            .map(|command| MetaCommand {
                name: self
                    .interner
                    .intern(command.element.attr(AttrKey::Name).unwrap_or_default()),
                qualified_name: command.qualified_name,
                space_system: command.space_system,
                is_abstract: command
                    .element
                    .attr(AttrKey::Abstract)
                    .is_some_and(|text| text.eq_ignore_ascii_case("true")),
                base: command.base,
                container: command.container,
                arguments: command
                    .arguments
                    .iter()
                    .map(|&(_, parameter)| parameter)
                    .collect(),
                short_description: command
                    .element
                    .attr(AttrKey::ShortDescription)
                    .map(|text| self.interner.intern(text)),
                long_description: command
                    .element
                    .child(Tag::LongDescription)
                    .and_then(Element::text)
                    .map(|text| self.interner.intern(text)),
            })
            .collect();
        self.pending_commands = pending;
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
        let is_path = reference.contains('/');

        // With a single space system — which is every file in `testdata`, and most databases
        // that are not assembled from several missions — the current system's table and the
        // document-wide leaf table hold exactly the same entries, so building and hashing a
        // qualified name would be pure overhead. This is not a different resolution rule,
        // just the same one arrived at directly.
        if !is_path && self.space_systems.len() == 1 {
            return self.lookup_leaf(reference, kind);
        }

        let mut scratch = std::mem::take(&mut self.scratch);
        let found = self.resolve_by_path(&mut scratch, reference, from, kind, is_path);
        self.scratch = scratch;
        found.or_else(|| self.lookup_leaf(last_segment(reference), kind))
    }

    fn resolve_by_path(
        &self,
        scratch: &mut String,
        reference: &str,
        from: SpaceSystemId,
        kind: RefKind,
        is_path: bool,
    ) -> Option<u32> {
        if reference.starts_with('/') {
            normalize_into(scratch, "", reference);
            return self.lookup_qualified(scratch, kind);
        }

        let mut cursor = Some(from);
        while let Some(system) = cursor {
            let base = self.ss_paths.get(system.index()).map_or("", String::as_str);
            normalize_into(scratch, base, reference);
            if let Some(id) = self.lookup_qualified(scratch, kind) {
                return Some(id);
            }
            if is_path {
                // Path-shaped references are tried relative to the current system and
                // absolutely; they do not walk up the tree.
                break;
            }
            cursor = self
                .space_systems
                .get(system.index())
                .and_then(|system| system.parent);
        }
        None
    }

    fn lookup_leaf(&self, leaf: &str, kind: RefKind) -> Option<u32> {
        let leaf_id = self.interner.get(leaf)?;
        match kind {
            RefKind::Parameter => self.param_by_leaf.get(&leaf_id).map(|id| id.raw()),
            RefKind::ParameterType => self.type_by_leaf.get(&leaf_id).map(|id| id.raw()),
            RefKind::Container => self.container_by_leaf.get(&leaf_id).map(|id| id.raw()),
            RefKind::MetaCommand => self.command_by_leaf.get(&leaf_id).map(|id| id.raw()),
        }
    }

    fn lookup_qualified(&self, qualified: &str, kind: RefKind) -> Option<u32> {
        let id = self.interner.get(qualified)?;
        match kind {
            RefKind::Parameter => self.param_by_qualified.get(&id).map(|id| id.raw()),
            RefKind::ParameterType => self.type_by_qualified.get(&id).map(|id| id.raw()),
            RefKind::Container => self.container_by_qualified.get(&id).map(|id| id.raw()),
            RefKind::MetaCommand => self.command_by_qualified.get(&id).map(|id| id.raw()),
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
/// Writes `base/reference` into `out`, resolving `.` and `..` segments.
///
/// Almost every reference in a real database is a plain name or a plain path, so the common
/// case is a concatenation with no segment analysis and no allocation. The general case
/// falls back to walking segments, which needs a stack because `..` pops.
fn normalize_into(out: &mut String, base: &str, reference: &str) {
    out.clear();
    if !needs_normalising(reference) {
        if !reference.starts_with('/') {
            out.push_str(base);
        }
        if !reference.starts_with('/') {
            out.push('/');
        }
        out.push_str(reference);
        return;
    }

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
    for segment in segments {
        out.push('/');
        out.push_str(segment);
    }
}

/// Whether a reference contains `.`, `..` or empty segments that need resolving.
fn needs_normalising(reference: &str) -> bool {
    if !reference.contains('.') && !reference.contains("//") {
        return false;
    }
    reference
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
}

/// The part of a reference after the last `/`.
fn last_segment(reference: &str) -> &str {
    match reference.rsplit_once('/') {
        Some((_, leaf)) => leaf,
        None => reference,
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

/// The state a leaf walk carries, which does not change as it descends.
///
/// Grouped because it is four things that travel together through a recursion, and passing
/// them one by one made the signature longer than the function.
struct Walk<'a> {
    types: &'a [ParameterType],
    out: &'a mut Vec<(String, TypeId)>,
    visiting: &'a mut Vec<TypeId>,
    path: &'a str,
}

/// How many leaf fields one entry may expand into.
///
/// Every leaf becomes a parameter in the arena and a field in any generated decoder, so a
/// definition asking for a million of them would produce something no compiler will finish.
/// An aggregate of arrays of aggregates reaches large numbers quickly, which is why the limit
/// counts leaves rather than one array's elements. It is arbitrary but named: nothing in a
/// real database comes close, and the refusal says what it was asked for.
const MAX_EXPANDED_FIELDS: usize = 4096;

/// A `<StartingIndex>` or `<EndingIndex>` that is a plain `<FixedValue>`.
///
/// `None` for the `DynamicValue` and `DiscreteLookupList` forms, which the caller refuses:
/// both make the count a property of the packet.
fn fixed_index(element: Option<Element<'_>>) -> Option<i64> {
    element?
        .child(Tag::FixedValue)
        .and_then(Element::text)
        .and_then(|text| text.trim().parse::<i64>().ok())
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
