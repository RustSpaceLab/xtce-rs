//! Telecommands: `<CommandMetaData>` and what it defines.
//!
//! # Why a command is a container here
//!
//! XTCE describes a telecommand with its own vocabulary — a `<MetaCommand>` with an
//! `<ArgumentList>`, an inheritance link that carries `<ArgumentAssignment>`s, and a
//! `<CommandContainer>` whose entry list may name arguments, parameters and fixed values.
//! None of that is a new *shape*. It is a container of fields, selected by fixed values, and
//! that is exactly what a telemetry container is.
//!
//! So it is lowered into the machinery that already exists:
//!
//! * an `<Argument>` becomes a [`crate::Parameter`], qualified under the command that owns it
//!   — the schema says an argument reference "is always resolved locally to the metacommand",
//!   and two commands may each have a `MODE`;
//! * a `<CommandContainer>` becomes a [`crate::Container`];
//! * an `<ArgumentAssignment>` becomes a [`crate::MatchCriteria`] on the container, because
//!   assigning a value to an inherited argument is how a command is specialised, and
//!   comparing that same value is how an arriving packet is recognised as this command;
//! * a `<FixedValueEntry>` becomes an [`crate::EntryKind::FixedValue`].
//!
//! What is left over — which commands exist, what each one is called, which container packs
//! it and which arguments it takes — is [`MetaCommand`]. The interpreter and both code
//! generators need none of it: by the time they run, a command *is* a container. It is here
//! so that a caller can ask what commands a database defines, and so `xtce info` can say.
//!
//! # What the reference does with all this
//!
//! Nothing. `space_packet_parser` has no command support at all — the string
//! `CommandMetaData` does not appear in its source, and a definition carrying one loads with
//! the command half silently ignored. So unlike almost everything else in this crate, none of
//! this is checked against it. The oracle is the schema, quoted where it decides something.

use crate::ids::{ContainerId, MetaCommandId, ParamId, SpaceSystemId};
use crate::intern::NameId;

/// A `<xtce:MetaCommand>`.
#[derive(Clone, Debug)]
pub struct MetaCommand {
    /// Command name as written.
    pub name: NameId,
    /// Fully qualified name.
    pub qualified_name: NameId,
    /// The space system that owns this definition.
    pub space_system: SpaceSystemId,
    /// `abstract="true"`: the command is only a base for others and is never sent itself.
    pub is_abstract: bool,
    /// The command this one specialises, from `<BaseMetaCommand metaCommandRef=..>`.
    pub base: Option<MetaCommandId>,
    /// The container that packs it, from `<CommandContainer>`.
    ///
    /// Optional in the schema: a `MetaCommand` may be an abstract carrier of arguments with
    /// no packaging of its own.
    pub container: Option<ContainerId>,
    /// The arguments this command declares itself, in document order.
    ///
    /// Not the ones it inherits. Each is a parameter in the arena, named
    /// `{space system}/{command}/{argument}`, and deliberately absent from the unqualified
    /// name index so that an argument cannot shadow a telemetry parameter of the same name.
    pub arguments: Vec<ParamId>,
    /// `shortDescription`, if present.
    pub short_description: Option<NameId>,
    /// `<LongDescription>`, if present.
    pub long_description: Option<NameId>,
}
