//! The generated decoder must agree with the interpreted one, field for field.
//!
//! The interpreted decoder is already proven equal to the Python reference over every packet
//! of six real streams, so equality with it is equality with the reference — without this
//! test needing to parse a golden file or reimplement the comparison.
//!
//! `generated/jpss_geolocation.rs` is committed rather than produced by a build script, for
//! three reasons: the generated code is meant to be *read*, a diff shows exactly what a
//! change to the emitter did, and the first test below fails if it ever drifts from what the
//! generator currently produces.

use std::path::{Path, PathBuf};

use xtce_decode::{Decoder, EngValue, PacketIter, RawValue};
use xtce_model::XtceDb;

// `include!` rather than `#[path] mod`, so `cargo fmt` leaves the generated file alone
// and the committed bytes stay comparable. This is also how a `build.rs` consumer uses
// it, so the test exercises the real shape.
#[allow(dead_code, clippy::all, clippy::pedantic)]
mod generated {
    include!("generated/jpss_geolocation.rs");
}

const DEFINITION: &str = "jpss/jpss1_geolocation_xtce_v1.xml";
const STREAM: &str = "jpss/J01_G011_LZ_2021-04-09T00-00-00Z_V01.DAT1";

fn testdata(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/spp")
        .join(relative)
}

fn load() -> XtceDb {
    XtceDb::from_path(testdata(DEFINITION)).expect("definition loads")
}

#[test]
fn the_committed_decoder_is_what_the_generator_produces() {
    let db = load();
    let generated = xtce_codegen::generate(
        &db,
        &xtce_codegen::Options {
            root: None,
            // The header records the source path, which differs between the committed file
            // and this run's absolute path, so it is pinned to the same relative form.
            source_label: Some(format!("testdata/spp/{DEFINITION}")),
        },
    )
    .expect("the JPSS definition compiles");

    let committed = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/generated/jpss_geolocation.rs"),
    )
    .expect("the committed decoder is present");

    assert_eq!(
        generated, committed,
        "the committed decoder has drifted from the generator; regenerate it with\n  \
         cargo run --release -p xtce-cli -- codegen testdata/spp/{DEFINITION} \\\n    \
         -o crates/xtce-codegen/tests/generated/jpss_geolocation.rs"
    );
}

/// Both decoders, over every packet of the real stream, compared field by field.
#[test]
fn generated_matches_interpreted_on_every_packet() {
    let db = load();
    let decoder = Decoder::new(&db).expect("root container");
    let stream = std::fs::read(testdata(STREAM)).expect("packet stream is present");

    let mut interpreted_packet = decoder.new_packet(&stream);
    let mut compared = 0usize;

    for (index, framed) in PacketIter::new(&stream, 0).enumerate() {
        let framed = framed.expect("the stream is well framed");
        let bytes = framed.bytes();

        decoder
            .decode_into(&mut interpreted_packet, bytes)
            .unwrap_or_else(|error| panic!("packet {index}: interpreted decode failed: {error}"));
        let compiled = generated::decode(bytes)
            .unwrap_or_else(|error| panic!("packet {index}: generated decode failed: {error}"));

        assert_eq!(
            compiled.container_name(),
            db.name(
                db.container(interpreted_packet.container())
                    .expect("container resolves")
                    .name
            ),
            "packet {index}: the two decoders chose different containers"
        );

        // Declared per packet: the collected values borrow from `compiled`, which does not
        // outlive this iteration.
        let mut fields = Vec::new();
        compiled.for_each_value(|name, raw, eng| fields.push((name, raw, eng)));

        assert_eq!(
            fields.len(),
            interpreted_packet.len(),
            "packet {index}: field counts differ"
        );

        for ((name, raw, eng), value) in fields.iter().zip(interpreted_packet.values()) {
            let interpreted_name = db
                .parameter(value.parameter)
                .map(|parameter| db.name(parameter.name))
                .expect("parameter resolves");
            assert_eq!(
                *name, interpreted_name,
                "packet {index}: field order differs"
            );
            assert!(
                same_raw(raw, &value.raw),
                "packet {index}: {name}: raw differs — generated {raw:?}, interpreted {:?}",
                value.raw
            );
            assert!(
                same_eng(eng, &value.eng),
                "packet {index}: {name}: engineering value differs — generated {eng:?}, \
                 interpreted {:?}",
                value.eng
            );
        }
        compared += 1;
    }

    assert_eq!(compared, 7200, "the whole stream should have been compared");
}

/// Compares by bit pattern, so a NaN matches a NaN and `-0.0` does not match `0.0`.
fn same_raw(generated: &generated::Value, interpreted: &RawValue<'_>) -> bool {
    match (generated, interpreted) {
        (generated::Value::Unsigned(a), RawValue::Unsigned(b)) => a == b,
        (generated::Value::Signed(a), RawValue::Signed(b)) => a == b,
        (generated::Value::Float(a), RawValue::Float(b)) => a.to_bits() == b.to_bits(),
        _ => false,
    }
}

fn same_eng(generated: &generated::Value, interpreted: &EngValue<'_, '_>) -> bool {
    match (generated, interpreted) {
        (generated::Value::Unsigned(a), EngValue::Unsigned(b)) => a == b,
        (generated::Value::Signed(a), EngValue::Signed(b)) => a == b,
        (generated::Value::Float(a), EngValue::Float(b)) => a.to_bits() == b.to_bits(),
        (generated::Value::Bool(a), EngValue::Bool(b)) => a == b,
        (generated::Value::Label(a), EngValue::Label(b)) => a == b,
        _ => false,
    }
}

#[test]
fn a_short_packet_is_refused_by_both() {
    let db = load();
    let decoder = Decoder::new(&db).expect("root container");
    let stream = std::fs::read(testdata(STREAM)).expect("packet stream is present");
    let first = PacketIter::new(&stream, 0)
        .next()
        .expect("at least one packet")
        .expect("well framed");

    for length in [0usize, 1, 2, 6, 40, 70] {
        let truncated = first.bytes().get(..length).unwrap_or_default();
        assert!(
            generated::decode(truncated).is_err(),
            "generated decoder accepted a {length}-byte packet"
        );
        assert!(
            decoder.decode(truncated).is_err(),
            "interpreted decoder accepted a {length}-byte packet"
        );
    }
}

#[test]
fn a_packet_of_another_type_is_refused() {
    // A CTIM packet through the JPSS definition: the APID does not match, so the abstract
    // root runs out of inheritors. This is the same case as the sixth golden file.
    let ctim = std::fs::read(testdata("ctim/ccsds_2021_155_14_39_51")).expect("ctim stream");
    let first = PacketIter::new(&ctim, 0)
        .next()
        .expect("at least one packet")
        .expect("well framed");

    match generated::decode(first.bytes()) {
        Err(generated::DecodeError::Unrecognized { container }) => {
            assert_eq!(container, "CCSDSTelemetryPacket");
        }
        other => panic!("expected the packet to be unrecognised, got {other:?}"),
    }
}

/// Every bundled definition compiles.
///
/// It was not always so, and the list this test used to hold was the point of it: whatever
/// could not be compiled had to be refused *by name*, never quietly turned into a partial
/// decoder. The list is empty now — `contrived_inheritance_structure.xml` was the last one,
/// and its `<BooleanExpression>` compiles.
///
/// So the assertion is inverted. If one of these ever stops compiling, that is either a
/// regression or a definition that grew a construct outside the subset, and either way it
/// should be noticed here rather than in whatever downstream build goes quiet.
#[test]
fn every_bundled_definition_compiles() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/spp");
    let mut definitions = Vec::new();
    let mut stack = vec![directory];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).expect("testdata is readable") {
            let entry = entry.expect("directory entry").path();
            if entry.is_dir() {
                stack.push(entry);
            } else if entry
                .extension()
                .is_some_and(|extension| extension == "xml")
            {
                definitions.push(entry);
            }
        }
    }
    definitions.sort();
    assert_eq!(definitions.len(), 16, "the bundled definitions changed");

    for path in definitions {
        let name = path.display().to_string();
        let db = XtceDb::from_path(&path).unwrap_or_else(|error| panic!("{name}: {error}"));
        let result = xtce_codegen::generate(&db, &xtce_codegen::Options::default());
        assert!(result.is_ok(), "{name}: no longer compiles: {result:?}");
    }
}

/// The layout the generator computed must match what the interpreter actually reads.
#[test]
fn planned_offsets_match_the_interpreters_offsets() {
    let db = load();
    let plan = xtce_codegen::plan(&db, &xtce_codegen::Options::default()).expect("plans");
    let planned = plan.containers.first().expect("one concrete container");

    let decoder = Decoder::new(&db).expect("root container");
    let stream = std::fs::read(testdata(STREAM)).expect("packet stream is present");
    let first = PacketIter::new(&stream, 0)
        .next()
        .expect("a packet")
        .expect("well framed");
    let decoded = decoder.decode(first.bytes()).expect("decodes");

    assert_eq!(planned.fields.len(), decoded.len());
    for (field, value) in planned.fields.iter().zip(decoded.values()) {
        // JPSS is entirely fixed-width, so every field's span is known at generation time.
        let (offset, width) = field
            .static_span()
            .unwrap_or_else(|| panic!("{}: expected a fixed span", field.xtce_name));
        assert_eq!(
            offset, value.bit_offset,
            "{}: planned offset differs from the interpreter's",
            field.xtce_name
        );
        assert_eq!(
            width as usize, value.bit_width,
            "{}: planned width differs from the interpreter's",
            field.xtce_name
        );
    }
    assert_eq!(planned.bit_length, Some(decoded.bits_consumed()));
}

/// Constructs that must stay refused, each with the reason it cannot be compiled.
///
/// Written inline because no bundled definition contains them, and a refusal path with no
/// test is a refusal that can silently turn into a wrong answer.
#[test]
fn constructs_outside_the_compilable_subset_are_refused() {
    fn definition(types: &str, parameters: &str, entries: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<SpaceSystem xmlns="http://www.omg.org/spec/XTCE/20180204" name="T">
  <TelemetryMetaData>
    <ParameterTypeSet>{types}</ParameterTypeSet>
    <ParameterSet>{parameters}</ParameterSet>
    <ContainerSet>
      <SequenceContainer name="Packet"><EntryList>{entries}</EntryList></SequenceContainer>
    </ContainerSet>
  </TelemetryMetaData>
</SpaceSystem>"#
        )
    }

    let flag = r#"<IntegerParameterType name="F"><IntegerDataEncoding sizeInBits="4" encoding="unsigned"/></IntegerParameterType>"#;

    let cases: [(&str, String, &str); 6] = [
        (
            // Three bits of padding put the string off a byte boundary, so it cannot be a
            // slice of the packet and copying it would mean allocating.
            "unaligned string",
            definition(
                &format!(
                    r#"{flag}<StringParameterType name="S"><StringDataEncoding encoding="UTF-8"><SizeInBits><Fixed><FixedValue>16</FixedValue></Fixed></SizeInBits></StringDataEncoding></StringParameterType>"#
                ),
                r#"<Parameter name="PAD" parameterTypeRef="F"/><Parameter name="TEXT" parameterTypeRef="S"/>"#,
                r#"<ParameterRefEntry parameterRef="PAD"/><ParameterRefEntry parameterRef="TEXT"/>"#,
            ),
            "sizeInBits",
        ),
        (
            // UTF-16 cannot borrow: decoding it means building new bytes.
            "charset needing transcoding",
            definition(
                r#"<StringParameterType name="S"><StringDataEncoding encoding="UTF-16BE"><SizeInBits><Fixed><FixedValue>16</FixedValue></Fixed></SizeInBits></StringDataEncoding></StringParameterType>"#,
                r#"<Parameter name="TEXT" parameterTypeRef="S"/>"#,
                r#"<ParameterRefEntry parameterRef="TEXT"/>"#,
            ),
            "StringDataEncoding",
        ),
        (
            // A context calibrator is chosen by criteria over other parameters, which may
            // themselves be calibrated. That is a dependency graph, not an expression.
            "context calibrator",
            definition(
                r#"<IntegerParameterType name="C"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"><ContextCalibratorList><ContextCalibrator><ContextMatch><Comparison parameterRef="A" value="1"/></ContextMatch><Calibrator><PolynomialCalibrator><Term coefficient="2.0" exponent="1"/></PolynomialCalibrator></Calibrator></ContextCalibrator></ContextCalibratorList></IntegerDataEncoding></IntegerParameterType>"#,
                r#"<Parameter name="A" parameterTypeRef="C"/>"#,
                r#"<ParameterRefEntry parameterRef="A"/>"#,
            ),
            "ContextCalibrator",
        ),
        (
            // The interpreter supports orders 0 and 1 only, so anything above that would be
            // a second implementation of a thing there is no reference for.
            "spline above first order",
            definition(
                r#"<IntegerParameterType name="C"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"><DefaultCalibrator><SplineCalibrator order="2"><SplinePoint raw="0" calibrated="0"/><SplinePoint raw="1" calibrated="1"/></SplineCalibrator></DefaultCalibrator></IntegerDataEncoding></IntegerParameterType>"#,
                r#"<Parameter name="A" parameterTypeRef="C"/>"#,
                r#"<ParameterRefEntry parameterRef="A"/>"#,
            ),
            "SplineCalibrator",
        ),
        (
            // A second control, and the one that would have failed before calibration
            // landed: a default polynomial calibrator now compiles.
            "polynomial calibrator",
            definition(
                r#"<IntegerParameterType name="C"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"><DefaultCalibrator><PolynomialCalibrator><Term coefficient="2.0" exponent="1"/></PolynomialCalibrator></DefaultCalibrator></IntegerDataEncoding></IntegerParameterType>"#,
                r#"<Parameter name="A" parameterTypeRef="C"/>"#,
                r#"<ParameterRefEntry parameterRef="A"/>"#,
            ),
            "",
        ),
        (
            // The control: two plain integers, one after the other. Without it the three
            // refusals above would also pass if `generate` refused every inline definition.
            "fixed-width integers",
            definition(
                &format!(
                    r#"{flag}<IntegerParameterType name="V"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>"#
                ),
                r#"<Parameter name="LEN" parameterTypeRef="F"/><Parameter name="N" parameterTypeRef="V"/>"#,
                r#"<ParameterRefEntry parameterRef="LEN"/><ParameterRefEntry parameterRef="N"/>"#,
            ),
            // Empty means "must compile".
            "",
        ),
    ];

    for (what, xml, expected_element) in cases {
        let db = XtceDb::from_xml(&xml).unwrap_or_else(|error| panic!("{what}: {error}"));
        let result = xtce_codegen::generate(&db, &xtce_codegen::Options::default());

        if expected_element.is_empty() {
            assert!(result.is_ok(), "{what}: should compile, got {result:?}");
            continue;
        }
        match result {
            Err(xtce_codegen::CodegenError::Unsupported { element, .. }) => {
                assert_eq!(
                    element, expected_element,
                    "{what}: refused the wrong element"
                );
            }
            other => panic!("{what}: expected a refusal naming {expected_element}, got {other:?}"),
        }
    }
}

/// A criterion the generator would evaluate differently from the interpreter is refused.
///
/// `useCalibratedValue` defaults to **true**, so most criteria in a real definition ask for
/// the engineering value. For a plain integer that is the raw value and there is nothing to
/// do. For anything the interpreter reports differently — a calibrated parameter, whose
/// engineering value is a float, or a boolean, whose engineering value is 0 or 1 rather than
/// its raw bits — comparing the raw bits would select a different container. Silently.
///
/// The first of those became reachable the day calibrators started compiling: before then a
/// calibrated field was refused outright, so a criterion could not name one.
#[test]
fn criteria_the_generator_would_evaluate_differently_are_refused() {
    fn definition(types: &str, parameters: &str, criteria: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<SpaceSystem xmlns="http://www.omg.org/spec/XTCE/20180204" name="T">
  <TelemetryMetaData>
    <ParameterTypeSet>
      {types}
      <IntegerParameterType name="U8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>
    </ParameterTypeSet>
    <ParameterSet>
      {parameters}
      <Parameter name="BODY" parameterTypeRef="U8"/>
    </ParameterSet>
    <ContainerSet>
      <SequenceContainer name="Base" abstract="true">
        <EntryList><ParameterRefEntry parameterRef="SEL"/></EntryList>
      </SequenceContainer>
      <SequenceContainer name="Child">
        <EntryList><ParameterRefEntry parameterRef="BODY"/></EntryList>
        <BaseContainer containerRef="Base">
          <RestrictionCriteria>{criteria}</RestrictionCriteria>
        </BaseContainer>
      </SequenceContainer>
    </ContainerSet>
  </TelemetryMetaData>
</SpaceSystem>"#
        )
    }

    let calibrated = r#"<IntegerParameterType name="SEL_T"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"><DefaultCalibrator><PolynomialCalibrator><Term coefficient="2.0" exponent="1"/></PolynomialCalibrator></DefaultCalibrator></IntegerDataEncoding></IntegerParameterType>"#;
    let boolean = r#"<BooleanParameterType name="SEL_T"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></BooleanParameterType>"#;
    let plain = r#"<IntegerParameterType name="SEL_T"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>"#;
    let parameter = r#"<Parameter name="SEL" parameterTypeRef="SEL_T"/>"#;

    // A `<Condition>` says the same thing as a `<Comparison>` in different XML, and the
    // interpreter evaluates both through the same `test_literal` — but it also admits two
    // shapes a `<Comparison>` cannot express.
    let condition = |body: &str| {
        definition(
            plain,
            parameter,
            &format!("<BooleanExpression><Condition>{body}</Condition></BooleanExpression>"),
        )
    };

    let cases: [(&str, String, bool); 8] = [
        (
            // The ordinary shape, and the one boolean_criteria.xml is built from.
            "condition against a literal",
            condition(
                r#"<ParameterInstanceRef parameterRef="SEL" useCalibratedValue="false"/><ComparisonOperator>&gt;=</ComparisonOperator><Value>4</Value>"#,
            ),
            true,
        ),
        (
            // Two decoded parameters. `test_scalars` has five type-pair arms and a
            // Python-compatibility answer for text against a number; nothing in reach uses
            // one, so there is nothing to check a guess against.
            "condition between two parameters",
            condition(
                r#"<ParameterInstanceRef parameterRef="SEL" useCalibratedValue="false"/><ComparisonOperator>==</ComparisonOperator><ParameterInstanceRef parameterRef="BODY" useCalibratedValue="false"/>"#,
            ),
            false,
        ),
        (
            // The model takes the operands in document order, so a `<Value>` written first
            // lands on the left — where the interpreter compares it as *text*.
            "literal on the left of a condition",
            condition(
                r#"<Value>4</Value><ComparisonOperator>==</ComparisonOperator><ParameterInstanceRef parameterRef="SEL" useCalibratedValue="false"/>"#,
            ),
            false,
        ),
        (
            // The interpreter compares 2 * raw against 4.0; raw bits against 4 would pick
            // this container for a packet the interpreter reads as a different one.
            "calibrated parameter, calibrated comparison",
            definition(
                calibrated,
                parameter,
                r#"<Comparison parameterRef="SEL" value="4" useCalibratedValue="true"/>"#,
            ),
            false,
        ),
        (
            // The same parameter, asked for its raw value: nothing to disagree about.
            "calibrated parameter, raw comparison",
            definition(
                calibrated,
                parameter,
                r#"<Comparison parameterRef="SEL" value="4" useCalibratedValue="false"/>"#,
            ),
            true,
        ),
        (
            // Eight bits wide, so a raw value of 4 has an engineering value of 1.
            "boolean parameter, calibrated comparison",
            definition(
                boolean,
                parameter,
                r#"<Comparison parameterRef="SEL" value="1" useCalibratedValue="true"/>"#,
            ),
            false,
        ),
        (
            "boolean parameter, raw comparison",
            definition(
                boolean,
                parameter,
                r#"<Comparison parameterRef="SEL" value="1" useCalibratedValue="false"/>"#,
            ),
            true,
        ),
        (
            // The control, and the shape almost every real definition uses: no attribute at
            // all, which XTCE reads as `true`, over a parameter with no calibrator.
            "plain integer, no attribute",
            definition(
                plain,
                parameter,
                r#"<Comparison parameterRef="SEL" value="4"/>"#,
            ),
            true,
        ),
    ];

    for (what, xml, should_compile) in cases {
        let db = XtceDb::from_xml(&xml).unwrap_or_else(|error| panic!("{what}: {error}"));
        let result = xtce_codegen::generate(&db, &xtce_codegen::Options::default());
        assert_eq!(
            result.is_ok(),
            should_compile,
            "{what}: expected compile={should_compile}, got {result:?}"
        );
        if !should_compile {
            assert!(
                matches!(
                    result,
                    Err(xtce_codegen::CodegenError::Unsupported { ref element, .. })
                        if element == "Comparison" || element == "Condition"
                ),
                "{what}: refused the wrong element: {result:?}"
            );
        }
    }
}
