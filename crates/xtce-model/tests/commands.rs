//! What `<CommandMetaData>` lowers into, exactly.
//!
//! A telecommand is a container of fields selected by fixed values, which is what a telemetry
//! container is, so it is lowered into the machinery that already exists: an argument becomes
//! a parameter qualified under its command, a `<CommandContainer>` becomes a container, and an
//! `<ArgumentAssignment>` becomes a restriction criterion. These tests pin that mapping by
//! name, because it is the only place the semantics live.
//!
//! There is no reference to check against — and unlike arrays and aggregates, not even a
//! `NotImplementedError`. `space_packet_parser` has no command support at all: the string
//! `CommandMetaData` does not appear in its source, and a definition carrying one loads with
//! the command half silently ignored. The oracle is XTCE 1.2 itself:
//!
//! * `ArgumentInstanceRefType`: "An argument instance is the name of an argument as the
//!   reference is always resolved locally to the metacommand. … There is no path, this is a
//!   local reference."
//! * `MetaCommandType`: "A MetaCommand's CommandContainer is private except as referred to in
//!   BaseMetaCommand (they are not visible to other containers and cannot be used in an entry
//!   list)."
//! * `ArgumentAssignmentListType`: the list "specialise[s] this command definition when
//!   inheriting from a more general MetaCommand by restricting the specific values of
//!   otherwise general arguments."
//! * `ArgumentAssignmentType`: "Describe an assignment of an argument with a
//!   calibrated/engineering value."
//! * `ArgumentFixedValueEntryType`: `binaryValue` is `hexBinary` and `sizeInBits` is required.

use xtce_model::{EntryKind, MatchCriteria, XtceDb};

/// Wraps a `<CommandMetaData>` body in a loadable document, with a telemetry half beside it.
///
/// The telemetry half is there in every case on purpose: a `MODE` parameter and a `MODE`
/// argument coexisting is the collision the scoping rules have to survive.
fn definition(command_body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<SpaceSystem xmlns="http://www.omg.org/spec/XTCE/20180204" name="T">
  <TelemetryMetaData>
    <ParameterTypeSet>
      <IntegerParameterType name="U8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>
    </ParameterTypeSet>
    <ParameterSet><Parameter name="MODE" parameterTypeRef="U8"/></ParameterSet>
    <ContainerSet>
      <SequenceContainer name="Report"><EntryList><ParameterRefEntry parameterRef="MODE"/></EntryList></SequenceContainer>
    </ContainerSet>
  </TelemetryMetaData>
  <CommandMetaData>
{command_body}
  </CommandMetaData>
</SpaceSystem>"#
    )
}

fn load(command_body: &str) -> XtceDb {
    XtceDb::from_xml(&definition(command_body)).expect("definition loads")
}

/// The message from a load that must fail. `XtceDb` is not `Debug`, so this is a match.
fn refusal(command_body: &str) -> String {
    match XtceDb::from_xml(&definition(command_body)) {
        Ok(_) => panic!("expected the load to fail, and it did not"),
        Err(error) => error.to_string(),
    }
}

/// A command half with two commands, one extending the other.
const INHERITED: &str = r#"    <ArgumentTypeSet>
      <IntegerArgumentType name="U8_A"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerArgumentType>
      <IntegerArgumentType name="U16_A"><IntegerDataEncoding sizeInBits="16" encoding="unsigned"/></IntegerArgumentType>
    </ArgumentTypeSet>
    <MetaCommandSet>
      <MetaCommand name="Base" abstract="true">
        <ArgumentList>
          <Argument name="OPCODE" argumentTypeRef="U8_A"/>
        </ArgumentList>
        <CommandContainer name="BaseContainer">
          <EntryList>
            <FixedValueEntry name="SYNC" binaryValue="1ACFFC1D" sizeInBits="32"/>
            <ArgumentRefEntry argumentRef="OPCODE"/>
          </EntryList>
        </CommandContainer>
      </MetaCommand>
      <MetaCommand name="SetMode">
        <BaseMetaCommand metaCommandRef="Base">
          <ArgumentAssignmentList>
            <ArgumentAssignment argumentName="OPCODE" argumentValue="7"/>
          </ArgumentAssignmentList>
        </BaseMetaCommand>
        <ArgumentList>
          <Argument name="MODE" argumentTypeRef="U16_A"/>
        </ArgumentList>
        <CommandContainer name="SetModeContainer">
          <EntryList>
            <ArgumentRefEntry argumentRef="MODE"/>
          </EntryList>
          <BaseContainer containerRef="BaseContainer"/>
        </CommandContainer>
      </MetaCommand>
    </MetaCommandSet>"#;

#[test]
fn a_command_becomes_a_container_and_its_arguments_become_parameters() {
    let db = load(INHERITED);

    let commands = db.meta_commands();
    assert_eq!(commands.len(), 2);
    assert_eq!(db.name(commands[0].name), "Base");
    assert!(commands[0].is_abstract, "abstract=\"true\" is carried over");
    assert_eq!(db.name(commands[1].name), "SetMode");
    assert!(!commands[1].is_abstract);
    assert_eq!(
        commands[1]
            .base
            .map(|id| db.name(db.meta_command(id).expect("the base resolves").name)),
        Some("Base")
    );

    // Each command's own arguments, not its inherited ones.
    assert_eq!(commands[0].arguments.len(), 1);
    assert_eq!(commands[1].arguments.len(), 1);
    let argument = db
        .parameter(commands[1].arguments[0])
        .expect("the argument is a parameter");
    assert_eq!(db.name(argument.name), "MODE");
    // Qualified under the command, because an argument is local to it.
    assert_eq!(db.name(argument.qualified_name), "/T/SetMode/MODE");

    let container = db
        .container(commands[1].container.expect("SetMode packs itself"))
        .expect("the container resolves");
    assert_eq!(db.name(container.name), "SetModeContainer");
    assert_eq!(
        db.name(container.qualified_name),
        "/T/SetMode/SetModeContainer"
    );
}

/// An argument does not shadow a telemetry parameter, and cannot be reached from telemetry.
///
/// Both halves of this definition declare a `MODE`. They are different things — one is
/// reported by the spacecraft, the other is supplied by whoever sends the command — and the
/// index that `<Comparison parameterRef="MODE">` searches has to keep pointing at the
/// telemetry one.
#[test]
fn an_argument_does_not_shadow_a_parameter_of_the_same_name() {
    let db = load(INHERITED);

    let by_name = db.find_parameter("MODE").expect("MODE resolves");
    let found = db.parameter(by_name).expect("it exists");
    assert_eq!(
        db.name(found.qualified_name),
        "/T/MODE",
        "the bare name still resolves to the telemetry parameter"
    );

    // The argument is reachable, but only by its qualified name.
    let argument = db
        .find_parameter("/T/SetMode/MODE")
        .expect("the argument resolves when fully qualified");
    assert_ne!(argument, by_name);
}

/// An argument assignment becomes a restriction criterion on the command's container.
///
/// It is the same statement read two ways: assigning `OPCODE = 7` is what makes this command
/// a specialisation of `Base`, and comparing `OPCODE == 7` is what recognises an arriving
/// packet as this command rather than as a sibling.
#[test]
fn an_argument_assignment_becomes_a_restriction_criterion() {
    let db = load(INHERITED);

    let set_mode = db.meta_commands()[1]
        .container
        .expect("SetMode packs itself");
    let container = db.container(set_mode).expect("it resolves");

    assert_eq!(
        container
            .base
            .map(|id| db.name(db.container(id).expect("the base resolves").name)),
        Some("BaseContainer"),
        "the container inherits the base command's packaging"
    );

    assert_eq!(container.restriction.len(), 1);
    let MatchCriteria::Comparison(comparison) = &container.restriction[0] else {
        panic!("expected a comparison, got {:?}", container.restriction[0]);
    };
    let tested = db.parameter(comparison.parameter).expect("it resolves");
    assert_eq!(
        db.name(tested.qualified_name),
        "/T/Base/OPCODE",
        "the assignment pins the *base* command's argument"
    );
    assert_eq!(comparison.value.as_int, Some(7));
    assert!(
        comparison.use_calibrated,
        "the schema calls argumentValue a calibrated/engineering value"
    );
}

/// A `<FixedValueEntry>` keeps its bytes and its width, and carries no parameter.
#[test]
fn a_fixed_value_entry_keeps_its_bytes() {
    let db = load(INHERITED);

    let base = db.meta_commands()[0].container.expect("Base packs itself");
    let entries = db.container_entries(base);
    assert_eq!(entries.len(), 2, "the fixed value and the opcode");

    let EntryKind::FixedValue {
        name,
        value,
        size_in_bits,
    } = entries[0].kind
    else {
        panic!("expected a fixed value, got {:?}", entries[0].kind);
    };
    assert_eq!(name.map(|name| db.name(name)), Some("SYNC"));
    assert_eq!(size_in_bits, 32);
    assert_eq!(db.fixed_value(value), &[0x1A, 0xCF, 0xFC, 0x1D]);
}

/// Two commands may give their containers the same name, and both must load.
///
/// The schema's uniqueness key for container names covers `ContainerSet` and
/// `CommandContainerSet` but not a MetaCommand's own `<CommandContainer>`, which it calls
/// private. Rejecting this file would reject one the schema allows.
#[test]
fn two_commands_may_name_their_containers_the_same() {
    let db = load(
        r#"    <ArgumentTypeSet>
      <IntegerArgumentType name="U8_A"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerArgumentType>
    </ArgumentTypeSet>
    <MetaCommandSet>
      <MetaCommand name="First">
        <ArgumentList><Argument name="A" argumentTypeRef="U8_A"/></ArgumentList>
        <CommandContainer name="Packing">
          <EntryList><ArgumentRefEntry argumentRef="A"/></EntryList>
        </CommandContainer>
      </MetaCommand>
      <MetaCommand name="Second">
        <ArgumentList><Argument name="A" argumentTypeRef="U8_A"/></ArgumentList>
        <CommandContainer name="Packing">
          <EntryList><ArgumentRefEntry argumentRef="A"/></EntryList>
        </CommandContainer>
      </MetaCommand>
    </MetaCommandSet>"#,
    );

    assert_eq!(db.meta_commands().len(), 2);
    let first = db.meta_commands()[0].container.expect("First packs itself");
    let second = db.meta_commands()[1]
        .container
        .expect("Second packs itself");
    assert_ne!(first, second);
    assert_eq!(
        db.name(db.container(first).expect("resolves").qualified_name),
        "/T/First/Packing"
    );
    assert_eq!(
        db.name(db.container(second).expect("resolves").qualified_name),
        "/T/Second/Packing"
    );

    // Each entry list names its own command's argument, not the other's.
    for (command, container) in [(0usize, first), (1, second)] {
        let entries = db.container_entries(container);
        let EntryKind::Parameter(parameter) = entries[0].kind else {
            panic!("expected an argument reference");
        };
        assert_eq!(parameter, db.meta_commands()[command].arguments[0]);
    }
}

/// An `argumentRef` naming nothing the command can see is a load failure, not a guess.
#[test]
fn an_unknown_argument_reference_is_refused() {
    let error = refusal(
        r#"    <ArgumentTypeSet>
      <IntegerArgumentType name="U8_A"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerArgumentType>
    </ArgumentTypeSet>
    <MetaCommandSet>
      <MetaCommand name="Only">
        <ArgumentList><Argument name="A" argumentTypeRef="U8_A"/></ArgumentList>
        <CommandContainer name="Packing">
          <EntryList><ArgumentRefEntry argumentRef="NOPE"/></EntryList>
        </CommandContainer>
      </MetaCommand>
    </MetaCommandSet>"#,
    );
    assert!(
        error.to_string().contains("NOPE"),
        "unexpected error: {error}"
    );
}

/// An `argumentRef` cannot reach a *telemetry* parameter of the same name.
///
/// "There is no path, this is a local reference." A command whose entry list names `MODE`
/// without declaring a `MODE` argument is missing an argument, not silently packing the
/// spacecraft's telemetry parameter.
#[test]
fn an_argument_reference_does_not_fall_back_to_a_parameter() {
    let error = refusal(
        r#"    <ArgumentTypeSet>
      <IntegerArgumentType name="U8_A"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerArgumentType>
    </ArgumentTypeSet>
    <MetaCommandSet>
      <MetaCommand name="Only">
        <ArgumentList><Argument name="A" argumentTypeRef="U8_A"/></ArgumentList>
        <CommandContainer name="Packing">
          <EntryList><ArgumentRefEntry argumentRef="MODE"/></EntryList>
        </CommandContainer>
      </MetaCommand>
    </MetaCommandSet>"#,
    );
    assert!(
        error.to_string().contains("MODE"),
        "unexpected error: {error}"
    );
}

/// A command container *may* name a telemetry parameter, and that resolves normally.
///
/// "Arguments are user provided to the specific command definition. Parameters are
/// provided/calculated/determined by the software creating the command instance." A sequence
/// count the ground fills in is a parameter, and `<ParameterRefEntry>` is how a command names
/// one.
#[test]
fn a_command_container_may_reference_a_parameter() {
    let db = load(
        r#"    <ArgumentTypeSet>
      <IntegerArgumentType name="U8_A"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerArgumentType>
    </ArgumentTypeSet>
    <MetaCommandSet>
      <MetaCommand name="Only">
        <ArgumentList><Argument name="A" argumentTypeRef="U8_A"/></ArgumentList>
        <CommandContainer name="Packing">
          <EntryList>
            <ParameterRefEntry parameterRef="MODE"/>
            <ArgumentRefEntry argumentRef="A"/>
          </EntryList>
        </CommandContainer>
      </MetaCommand>
    </MetaCommandSet>"#,
    );

    let container = db.meta_commands()[0].container.expect("it packs itself");
    let entries = db.container_entries(container);
    let EntryKind::Parameter(parameter) = entries[0].kind else {
        panic!("expected a parameter reference");
    };
    assert_eq!(
        db.name(db.parameter(parameter).expect("resolves").qualified_name),
        "/T/MODE"
    );
}

/// Command inheritance that loops is refused at load, not followed.
#[test]
fn a_cycle_in_command_inheritance_is_refused() {
    let error = refusal(
        r#"    <MetaCommandSet>
      <MetaCommand name="A">
        <BaseMetaCommand metaCommandRef="B"/>
      </MetaCommand>
      <MetaCommand name="B">
        <BaseMetaCommand metaCommandRef="A"/>
      </MetaCommand>
    </MetaCommandSet>"#,
    );
    assert!(
        error.to_string().contains("cycle"),
        "unexpected error: {error}"
    );
}

/// `CommandMetaData` is no longer reported as a section this crate skipped.
#[test]
fn the_command_section_is_no_longer_skipped() {
    let db = load(INHERITED);
    assert!(
        !db.skipped_sections()
            .iter()
            .any(|section| section == "CommandMetaData"),
        "skipped: {:?}",
        db.skipped_sections()
    );
    assert_eq!(db.stats().meta_commands, 2);
}

/// A definition with no command half has no commands, and nothing else changes.
#[test]
fn a_definition_with_no_commands_is_unaffected() {
    let db = XtceDb::from_xml(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<SpaceSystem xmlns="http://www.omg.org/spec/XTCE/20180204" name="T">
  <TelemetryMetaData>
    <ParameterTypeSet>
      <IntegerParameterType name="U8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>
    </ParameterTypeSet>
    <ParameterSet><Parameter name="MODE" parameterTypeRef="U8"/></ParameterSet>
    <ContainerSet>
      <SequenceContainer name="Report"><EntryList><ParameterRefEntry parameterRef="MODE"/></EntryList></SequenceContainer>
    </ContainerSet>
  </TelemetryMetaData>
</SpaceSystem>"#,
    )
    .expect("definition loads");

    assert!(db.meta_commands().is_empty());
    assert_eq!(db.stats().meta_commands, 0);
    assert_eq!(db.containers().len(), 1);
}

/// A container that packs an abstract command is abstract, even without the attribute.
///
/// `abstract` on a `MetaCommand` means it is "not instantiated, rather only used as bases to
/// inherit from to create specialized command definitions". No packet is one, so its
/// container can never be a packet's final match either. That is what `abstract` means on a
/// container, said one level up — and without carrying it down, a packet that matched no
/// specialisation would decode as the base rather than being refused.
#[test]
fn a_container_packing_an_abstract_command_is_abstract() {
    let db = load(INHERITED);
    let base = db.meta_commands()[0].container.expect("Base packs itself");
    let derived = db.meta_commands()[1]
        .container
        .expect("SetMode packs itself");

    assert!(
        db.container(base).expect("resolves").is_abstract,
        "the container of an abstract command is abstract"
    );
    assert!(
        !db.container(derived).expect("resolves").is_abstract,
        "and a concrete command's is not"
    );
}

/// The container a command packs knows which command that is; a telemetry container does not.
#[test]
fn a_command_container_points_back_at_its_command() {
    let db = load(INHERITED);
    let packing = db.meta_commands()[1]
        .container
        .expect("SetMode packs itself");
    assert_eq!(
        db.container(packing).expect("resolves").command,
        Some(xtce_model::MetaCommandId::new(1))
    );

    let report = db
        .find_container("Report")
        .expect("the telemetry container");
    assert_eq!(db.container(report).expect("resolves").command, None);
}

/// An argument type may share a name with a telemetry parameter type, and they stay apart.
///
/// The schema keys these in two overlapping ways. One key covers `TelemetryMetaData`'s and
/// `CommandMetaData`'s `<ParameterTypeSet>`s; another covers `CommandMetaData`'s
/// `<ArgumentTypeSet>` and its `<ParameterTypeSet>`. An argument type and a *telemetry*
/// parameter type are in no key together — so `U8` may be both, meaning two different things,
/// and a loader that shared one index would reject a file the schema allows.
#[test]
fn an_argument_type_may_share_a_name_with_a_parameter_type() {
    let db = load(
        r#"    <ArgumentTypeSet>
      <IntegerArgumentType name="U8"><IntegerDataEncoding sizeInBits="16" encoding="unsigned"/></IntegerArgumentType>
    </ArgumentTypeSet>
    <MetaCommandSet>
      <MetaCommand name="Cmd">
        <ArgumentList><Argument name="A" argumentTypeRef="U8"/></ArgumentList>
        <CommandContainer name="Packing">
          <EntryList><ArgumentRefEntry argumentRef="A"/></EntryList>
        </CommandContainer>
      </MetaCommand>
    </MetaCommandSet>"#,
    );

    // The wrapper's telemetry half declares `U8` as eight bits; the command half as sixteen.
    let argument = db.meta_commands()[0].arguments[0];
    assert_eq!(
        db.type_of(argument)
            .and_then(xtce_model::ParameterType::fixed_size_in_bits),
        Some(16),
        "the argument took the argument type, not the telemetry one of the same name"
    );

    let telemetry = db.find_parameter("MODE").expect("the telemetry parameter");
    assert_eq!(
        db.type_of(telemetry)
            .and_then(xtce_model::ParameterType::fixed_size_in_bits),
        Some(8),
        "and the telemetry parameter kept its own"
    );
}

/// Two argument types of the same name are still a duplicate, as the schema requires.
#[test]
fn two_argument_types_of_the_same_name_are_refused() {
    let error = refusal(
        r#"    <ArgumentTypeSet>
      <IntegerArgumentType name="A_T"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerArgumentType>
      <IntegerArgumentType name="A_T"><IntegerDataEncoding sizeInBits="16" encoding="unsigned"/></IntegerArgumentType>
    </ArgumentTypeSet>
    <MetaCommandSet>
      <MetaCommand name="Cmd">
        <ArgumentList><Argument name="A" argumentTypeRef="A_T"/></ArgumentList>
        <CommandContainer name="Packing">
          <EntryList><ArgumentRefEntry argumentRef="A"/></EntryList>
        </CommandContainer>
      </MetaCommand>
    </MetaCommandSet>"#,
    );
    assert!(
        error.contains("duplicate") && error.contains("A_T"),
        "unexpected error: {error}"
    );
}

/// A command's own `<ParameterTypeSet>` is in both namespaces, so either reference finds it.
#[test]
fn a_command_parameter_type_is_reachable_from_both_kinds_of_reference() {
    let db = load(
        r#"    <ParameterTypeSet>
      <IntegerParameterType name="SHARED"><IntegerDataEncoding sizeInBits="24" encoding="unsigned"/></IntegerParameterType>
    </ParameterTypeSet>
    <ParameterSet><Parameter name="SEQ" parameterTypeRef="SHARED"/></ParameterSet>
    <MetaCommandSet>
      <MetaCommand name="Cmd">
        <ArgumentList><Argument name="A" argumentTypeRef="SHARED"/></ArgumentList>
        <CommandContainer name="Packing">
          <EntryList>
            <ParameterRefEntry parameterRef="SEQ"/>
            <ArgumentRefEntry argumentRef="A"/>
          </EntryList>
        </CommandContainer>
      </MetaCommand>
    </MetaCommandSet>"#,
    );

    let argument = db.meta_commands()[0].arguments[0];
    assert_eq!(
        db.type_of(argument)
            .and_then(xtce_model::ParameterType::fixed_size_in_bits),
        Some(24)
    );
    let parameter = db.find_parameter("SEQ").expect("the command's parameter");
    assert_eq!(
        db.type_of(parameter)
            .and_then(xtce_model::ParameterType::fixed_size_in_bits),
        Some(24)
    );
}

/// An assignment reaches an argument declared two commands up the chain.
///
/// The effective argument scope is built root-first over the whole chain, so a command sees
/// every argument its ancestors declare. Two levels is where a one-level shortcut would still
/// pass, so this goes three deep: `Leaf` pins an argument that `Root` declares and `Middle`
/// never mentions.
#[test]
fn an_assignment_reaches_an_argument_two_levels_up() {
    let db = load(
        r#"    <ArgumentTypeSet>
      <IntegerArgumentType name="U8_A"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerArgumentType>
    </ArgumentTypeSet>
    <MetaCommandSet>
      <MetaCommand name="Root" abstract="true">
        <ArgumentList><Argument name="OPCODE" argumentTypeRef="U8_A"/></ArgumentList>
        <CommandContainer name="RootContainer">
          <EntryList><ArgumentRefEntry argumentRef="OPCODE"/></EntryList>
        </CommandContainer>
      </MetaCommand>
      <MetaCommand name="Middle" abstract="true">
        <BaseMetaCommand metaCommandRef="Root"/>
        <ArgumentList><Argument name="SUBSYSTEM" argumentTypeRef="U8_A"/></ArgumentList>
        <CommandContainer name="MiddleContainer">
          <EntryList><ArgumentRefEntry argumentRef="SUBSYSTEM"/></EntryList>
          <BaseContainer containerRef="RootContainer"/>
        </CommandContainer>
      </MetaCommand>
      <MetaCommand name="Leaf">
        <BaseMetaCommand metaCommandRef="Middle">
          <ArgumentAssignmentList>
            <ArgumentAssignment argumentName="OPCODE" argumentValue="9"/>
            <ArgumentAssignment argumentName="SUBSYSTEM" argumentValue="4"/>
          </ArgumentAssignmentList>
        </BaseMetaCommand>
        <ArgumentList><Argument name="LEVEL" argumentTypeRef="U8_A"/></ArgumentList>
        <CommandContainer name="LeafContainer">
          <EntryList><ArgumentRefEntry argumentRef="LEVEL"/></EntryList>
          <BaseContainer containerRef="MiddleContainer"/>
        </CommandContainer>
      </MetaCommand>
    </MetaCommandSet>"#,
    );

    let leaf = db.meta_commands()[2].container.expect("Leaf packs itself");
    let criteria = &db.container(leaf).expect("resolves").restriction;
    assert_eq!(criteria.len(), 2);

    let named: Vec<&str> = criteria
        .iter()
        .map(|criterion| match criterion {
            MatchCriteria::Comparison(comparison) => db.name(
                db.parameter(comparison.parameter)
                    .expect("resolves")
                    .qualified_name,
            ),
            other => panic!("expected a comparison, got {other:?}"),
        })
        .collect();
    assert_eq!(
        named,
        vec!["/T/Root/OPCODE", "/T/Middle/SUBSYSTEM"],
        "each assignment pins the argument at the level that declares it"
    );
}

/// A container in a `<CommandContainerSet>` is shared, and belongs to no single command.
///
/// The schema puts them there so that MetaCommand definitions can "reference/share" them, and
/// keys their names at the system level like a telemetry container's. So they register like
/// one — and, unlike a command's own private container, they carry no back-link to a command.
#[test]
fn a_shared_command_container_belongs_to_no_command() {
    let db = load(
        r#"    <ArgumentTypeSet>
      <IntegerArgumentType name="U8_A"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerArgumentType>
    </ArgumentTypeSet>
    <ParameterTypeSet>
      <IntegerParameterType name="HDR_T"><IntegerDataEncoding sizeInBits="16" encoding="unsigned"/></IntegerParameterType>
    </ParameterTypeSet>
    <ParameterSet><Parameter name="HDR" parameterTypeRef="HDR_T"/></ParameterSet>
    <CommandContainerSet>
      <SequenceContainer name="SharedHeader" abstract="true">
        <EntryList><ParameterRefEntry parameterRef="HDR"/></EntryList>
      </SequenceContainer>
    </CommandContainerSet>
    <MetaCommandSet>
      <MetaCommand name="Cmd">
        <ArgumentList><Argument name="A" argumentTypeRef="U8_A"/></ArgumentList>
        <CommandContainer name="Packing">
          <EntryList><ArgumentRefEntry argumentRef="A"/></EntryList>
          <BaseContainer containerRef="SharedHeader"/>
        </CommandContainer>
      </MetaCommand>
    </MetaCommandSet>"#,
    );

    let shared = db.find_container("SharedHeader").expect("it registers");
    let shared = db.container(shared).expect("resolves");
    assert_eq!(
        db.name(shared.qualified_name),
        "/T/SharedHeader",
        "named at the system level, not under a command"
    );
    assert_eq!(
        shared.command, None,
        "shared: it packs no single command, so it points back at none"
    );
    assert!(
        shared.is_command,
        "but it is still a telecommand's packaging, which is what root selection asks"
    );

    // The command's own container does point back, and inherits the shared one.
    let packing = db.meta_commands()[0].container.expect("Cmd packs itself");
    let packing = db.container(packing).expect("resolves");
    assert!(packing.command.is_some());
    assert_eq!(
        packing
            .base
            .map(|id| db.name(db.container(id).expect("resolves").name)),
        Some("SharedHeader")
    );
}

/// A shared command container does not become the default root.
///
/// The awkward one. A `<CommandContainerSet>` container that is neither abstract nor derived
/// looks exactly like a telemetry root: no `<BaseContainer>`, a name keyed at the system
/// level, entries like any other. Counting it would leave a definition that had one root with
/// two, and `Decoder::new` would stop working on a file whose telemetry had not changed —
/// the same failure a command's own container would have caused, one level further out.
#[test]
fn a_shared_command_container_does_not_steal_the_default_root() {
    let db = load(
        r#"    <ParameterTypeSet>
      <IntegerParameterType name="HDR_T"><IntegerDataEncoding sizeInBits="16" encoding="unsigned"/></IntegerParameterType>
    </ParameterTypeSet>
    <ParameterSet><Parameter name="HDR" parameterTypeRef="HDR_T"/></ParameterSet>
    <CommandContainerSet>
      <SequenceContainer name="SharedHeader">
        <EntryList><ParameterRefEntry parameterRef="HDR"/></EntryList>
      </SequenceContainer>
    </CommandContainerSet>"#,
    );

    let default = db
        .default_root_container()
        .expect("the telemetry root is still unambiguous");
    assert_eq!(
        db.name(db.container(default).expect("resolves").name),
        "Report"
    );
    // It is still a root of its own tree, and still reachable by name.
    assert!(
        db.root_containers().len() > 1,
        "both are roots; only the default ignores one"
    );
    assert!(db.find_container("SharedHeader").is_some());
}
