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
        value,
        size_in_bits,
    } = entries[0].kind
    else {
        panic!("expected a fixed value, got {:?}", entries[0].kind);
    };
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
