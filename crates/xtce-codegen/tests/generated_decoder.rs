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
    let mut fields = Vec::new();

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

        fields.clear();
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

/// Out-of-scope constructs must be refused by name, never silently interpreted.
#[test]
fn unsupported_constructs_are_named_not_ignored() {
    let cases = [
        ("ctim/ctim_xtce_v1.xml", Some("CCSDSTelemetryPacket")),
        ("idex/idex_combined_science_definition.xml", None),
        ("suda/suda_combined_science_definition.xml", None),
        ("jpss/contrived_inheritance_structure.xml", None),
    ];

    for (file, root) in cases {
        let db = XtceDb::from_path(testdata(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let options = xtce_codegen::Options {
            root: root.map(str::to_owned),
            source_label: None,
        };
        match xtce_codegen::generate(&db, &options) {
            Err(xtce_codegen::CodegenError::Unsupported {
                element, reason, ..
            }) => {
                assert!(
                    !element.is_empty(),
                    "{file}: the refusal must name an element"
                );
                assert!(!reason.is_empty(), "{file}: the refusal must give a reason");
            }
            Err(other) => panic!("{file}: expected an Unsupported refusal, got {other}"),
            Ok(_) => panic!(
                "{file}: this definition uses constructs the generator cannot compile, so \
                 generating must fail rather than silently produce a partial decoder"
            ),
        }
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
        assert_eq!(
            field.bit_offset, value.bit_offset,
            "{}: planned offset differs from the interpreter's",
            field.xtce_name
        );
        assert_eq!(
            field.bit_width as usize, value.bit_width,
            "{}: planned width differs from the interpreter's",
            field.xtce_name
        );
    }
    assert_eq!(planned.bit_length, decoded.bits_consumed());
}
