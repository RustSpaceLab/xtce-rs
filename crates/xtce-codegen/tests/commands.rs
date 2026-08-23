//! What a telecommand's fixed values look like by the time the plan is done with them.
//!
//! A `<FixedValueEntry>` is the one thing in a command container that no *decoder* reads: the
//! bits are in the packet, nobody's value is in them, and their whole effect on decoding is
//! the offset of what follows. An **encoder** is the reader that needs them, and this crate
//! does not have one — `xtce-flight` does, through `ContainerPlan::fixed`. So these tests are
//! here rather than there: the plan is what both sides agree on, and a fixed value that came
//! out at the wrong offset or with the wrong bytes would show up in a packet the ground
//! cannot recognise, from an encoder whose own decoder is perfectly happy.

use std::path::{Path, PathBuf};

use xtce_codegen::{Options, plan};
use xtce_model::XtceDb;

fn testdata(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/spp")
        .join(relative)
}

fn commands_plan() -> plan::Plan {
    let db = XtceDb::from_path(testdata("commands.xml")).expect("definition loads");
    xtce_codegen::plan(
        &db,
        &Options {
            root: Some("CmdBaseContainer".to_owned()),
            source_label: None,
        },
    )
    .expect("the definition compiles")
}

fn container<'p>(plan: &'p plan::Plan, name: &str) -> &'p plan::ContainerPlan {
    plan.containers
        .iter()
        .find(|container| container.xtce_name == name)
        .unwrap_or_else(|| panic!("no container named {name}"))
}

/// Every fixed value reaches the plan, at the bit it occupies, inherited ones included.
#[test]
fn fixed_values_keep_their_place() {
    let plan = commands_plan();

    let set_mode = container(&plan, "SetModeContainer");
    let places: Vec<(Option<&str>, usize, u32)> = set_mode
        .fixed
        .iter()
        .map(|fixed| {
            (
                fixed.xtce_name.as_deref(),
                fixed.bit_offset,
                fixed.bit_width,
            )
        })
        .collect();
    assert_eq!(
        places,
        vec![
            // From the base container, which this one extends.
            (Some("SYNC"), 0, 32),
            // Four bits of its own, which is what leaves MODE off a byte boundary.
            (Some("SPARE"), 64, 4),
        ]
    );

    // And the field after the four-bit one is where those four bits leave it.
    let mode = set_mode
        .fields
        .iter()
        .find(|field| field.xtce_name == "MODE")
        .expect("SetMode carries a MODE argument");
    assert_eq!(mode.static_span(), Some((68, 4)));
}

/// The bytes are kept to the width the entry declares, truncating from the left.
///
/// XTCE requires both `binaryValue` and `sizeInBits` and does not require them to agree.
/// `TRAILER` gives four bytes for a sixteen-bit field: read as one big-endian number,
/// `DEADBEEF` in sixteen bits is `BEEF`, and an encoder that wrote `DEAD` — or all four bytes
/// — would produce a packet nothing recognises.
#[test]
fn a_fixed_value_wider_than_its_field_is_truncated_from_the_left() {
    let plan = commands_plan();
    let set_gain = container(&plan, "SetGainContainer");

    let trailer = set_gain
        .fixed
        .iter()
        .find(|fixed| fixed.xtce_name.as_deref() == Some("TRAILER"))
        .expect("SetGain ends with a trailer");
    assert_eq!(trailer.bit_width, 16);
    assert_eq!(trailer.value, vec![0xBE, 0xEF]);

    let sync = set_gain
        .fixed
        .iter()
        .find(|fixed| fixed.xtce_name.as_deref() == Some("SYNC"))
        .expect("and starts with the sync marker");
    assert_eq!(sync.value, vec![0x1A, 0xCF, 0xFC, 0x1D]);
}

/// A value narrower than its field is zero-extended, and spare leading bits are cleared.
///
/// The other direction of the same rule. `SPARE` is four bits and its `binaryValue` is a
/// whole byte, `0A`: the byte that reaches the plan has the high nibble cleared, so a caller
/// writing it into a four-bit field cannot spill into whatever sits above it.
#[test]
fn a_fixed_value_narrower_than_its_bytes_has_its_leading_bits_cleared() {
    let plan = commands_plan();
    let spare = container(&plan, "SetModeContainer")
        .fixed
        .iter()
        .find(|fixed| fixed.xtce_name.as_deref() == Some("SPARE"))
        .expect("SetMode has a four-bit spare");

    assert_eq!(spare.bit_width, 4);
    assert_eq!(spare.value, vec![0x0A]);
}

/// A container with no fixed values has none, rather than an empty one invented for it.
#[test]
fn a_telemetry_container_has_no_fixed_values() {
    let db = XtceDb::from_path(testdata("commands.xml")).expect("definition loads");
    let plan = xtce_codegen::plan(
        &db,
        &Options {
            root: Some("Report".to_owned()),
            source_label: None,
        },
    )
    .expect("the telemetry half compiles too");

    assert!(container(&plan, "Report").fixed.is_empty());
}

/// A criterion on an enumeration resolves to the raw values its labels cover.
///
/// Not a string comparison at run time, and not a comparison against the literal read as a
/// number either: the labels are a finite list, so which of them satisfy the operator is known
/// when the code is generated, and what is left is a set of raw values.
#[test]
fn a_criterion_on_a_label_becomes_a_set_of_raw_values() {
    let plan = commands_plan();

    // `PowerOn` and `PowerOff` share an opcode and differ only in the label they pin.
    let mut tests = Vec::new();
    collect(&plan.root, &mut tests);

    let labels: Vec<(String, Vec<(i128, i128)>)> = tests
        .into_iter()
        .filter_map(|guard| match &guard.test {
            plan::GuardTest::Labels {
                literal, ranges, ..
            } => Some((literal.clone(), ranges.clone())),
            plan::GuardTest::Value { .. } => None,
        })
        .collect();

    assert_eq!(
        labels,
        vec![
            ("ON".to_owned(), vec![(1, 1)]),
            ("OFF".to_owned(), vec![(0, 0)]),
        ],
        "each label resolves to the one raw value the enumeration gives it"
    );
}

/// Every guard in a criterion tree, in order.
fn collect(node: &plan::Node, out: &mut Vec<plan::Guard>) {
    fn walk(criterion: &plan::Criterion, out: &mut Vec<plan::Guard>) {
        match criterion {
            plan::Criterion::Test(guard) => out.push(guard.clone()),
            plan::Criterion::All(children) | plan::Criterion::Any(children) => {
                for child in children {
                    walk(child, out);
                }
            }
        }
    }
    for (criteria, child) in &node.children {
        walk(criteria, out);
        collect(child, out);
    }
}

/// A criterion comparing a *raw* enumeration value is an ordinary number comparison.
///
/// `useCalibratedValue="false"` says to compare the bits, and the bits are a number. Only the
/// engineering value is a label.
#[test]
fn a_raw_criterion_on_an_enumeration_stays_a_number() {
    let db = XtceDb::from_xml(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<SpaceSystem xmlns="http://www.omg.org/spec/XTCE/20180204" name="T">
  <TelemetryMetaData>
    <ParameterTypeSet>
      <EnumeratedParameterType name="E_T">
        <IntegerDataEncoding sizeInBits="8" encoding="unsigned"/>
        <EnumerationList>
          <Enumeration value="0" label="OFF"/>
          <Enumeration value="1" label="ON"/>
        </EnumerationList>
      </EnumeratedParameterType>
      <IntegerParameterType name="U8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>
    </ParameterTypeSet>
    <ParameterSet>
      <Parameter name="STATE" parameterTypeRef="E_T"/>
      <Parameter name="BODY" parameterTypeRef="U8"/>
    </ParameterSet>
    <ContainerSet>
      <SequenceContainer name="Root" abstract="true">
        <EntryList><ParameterRefEntry parameterRef="STATE"/></EntryList>
      </SequenceContainer>
      <SequenceContainer name="Leaf">
        <EntryList><ParameterRefEntry parameterRef="BODY"/></EntryList>
        <BaseContainer containerRef="Root">
          <RestrictionCriteria>
            <Comparison parameterRef="STATE" value="1" useCalibratedValue="false"/>
          </RestrictionCriteria>
        </BaseContainer>
      </SequenceContainer>
    </ContainerSet>
  </TelemetryMetaData>
</SpaceSystem>"#,
    )
    .expect("definition loads");

    let plan = xtce_codegen::plan(&db, &Options::default()).expect("it compiles");
    let mut tests = Vec::new();
    collect(&plan.root, &mut tests);
    assert!(
        matches!(
            tests.as_slice(),
            [guard] if matches!(&guard.test, plan::GuardTest::Value { value: 1, .. })
        ),
        "expected one numeric test, got {tests:?}"
    );
}
