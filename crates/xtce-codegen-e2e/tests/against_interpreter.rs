//! Every generated decoder, against the interpreter, on the real packet stream.
//!
//! The interpreter is already proven equal to `space_packet_parser` over every packet of six
//! streams, so agreeing with it is agreeing with the reference — without this test needing to
//! parse a golden file or reimplement the comparison.
//!
//! The modules below are written by `build.rs`, so nothing here is committed. That is the
//! shape a mission uses, and it is why a 94 000-line decoder can be tested without putting
//! 94 000 lines in the repository.

use std::path::{Path, PathBuf};

use xtce_decode::{Decoder, EngValue, PacketIter, RawValue};
use xtce_model::XtceDb;

// The generated modules live in this crate's library rather than being included here,
// because the library is `#![no_std]` and these tests are not. Compiling them there is what
// makes "generated code names nothing outside `core`" a build failure when it stops being
// true, rather than a sentence in a README.
// `udp` is absent on purpose: it has no packet stream, so compiling it in the library above
// is the whole of its check.
use xtce_codegen_e2e::{boolean_criteria, calibrators, ctim, idex, numeric_edges, suda};

fn testdata(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/spp")
        .join(relative)
}

/// Decodes every packet of a stream both ways and compares field by field.
///
/// A macro rather than a function because each generated module defines its own `Value` and
/// `DecodeError`. The types have the same shape, so only the paths differ.
///
/// Floats are compared by bit pattern: both sides read the same bits, so anything short of
/// exact equality is a real difference, and a NaN must match a NaN.
macro_rules! comparators {
    ($module:ident) => {{
        use $module::Value;

        let same_raw =
            |generated: &Value<'_>, interpreted: &RawValue<'_>| match (generated, interpreted) {
                (Value::Unsigned(a), RawValue::Unsigned(b)) => a == b,
                (Value::Signed(a), RawValue::Signed(b)) => a == b,
                (Value::Float(a), RawValue::Float(b)) => a.to_bits() == b.to_bits(),
                (Value::Bytes(a), RawValue::Bytes(b)) => *a == b.as_ref(),
                _ => false,
            };
        let same_eng = |generated: &Value<'_>, interpreted: &EngValue<'_, '_>| match (
            generated,
            interpreted,
        ) {
            (Value::Unsigned(a), EngValue::Unsigned(b)) => a == b,
            (Value::Signed(a), EngValue::Signed(b)) => a == b,
            (Value::Float(a), EngValue::Float(b)) => a.to_bits() == b.to_bits(),
            (Value::Bool(a), EngValue::Bool(b)) => a == b,
            (Value::Label(a), EngValue::Label(b)) => a == b,
            (Value::Text(a), EngValue::Text(b)) => *a == b.as_ref(),
            (Value::Bytes(a), EngValue::Bytes(b)) => *a == b.as_ref(),
            _ => false,
        };
        (same_raw, same_eng)
    }};
}

/// Decodes one packet both ways and compares it field by field.
macro_rules! assert_same_packet {
    ($module:ident, $db:expr, $decoder:expr, $interpreted:expr, $bytes:expr, $label:expr) => {{
        let (same_raw, same_eng) = comparators!($module);
        let label = $label;
        let bytes = $bytes;

        $decoder
            .decode_into(&mut $interpreted, bytes)
            .unwrap_or_else(|e| panic!("{label}: interpreted decode failed: {e}"));
        let compiled = $module::decode(bytes)
            .unwrap_or_else(|e| panic!("{label}: generated decode failed: {e}"));

        let container = $db
            .container($interpreted.container())
            .map(|container| $db.name(container.name))
            .expect("container resolves");
        assert_eq!(
            compiled.container_name(),
            container,
            "{label}: the two decoders chose different containers"
        );

        let mut fields = Vec::new();
        compiled.for_each_value(|name, raw, eng| fields.push((name, raw, eng)));
        assert_eq!(
            fields.len(),
            $interpreted.len(),
            "{label} ({container}): field counts differ"
        );

        for ((name, raw, eng), value) in fields.iter().zip($interpreted.values()) {
            let expected = $db
                .parameter(value.parameter)
                .map(|parameter| $db.name(parameter.name))
                .expect("parameter resolves");
            assert_eq!(*name, expected, "{label}: field order differs");
            assert!(
                same_raw(raw, &value.raw),
                "{label}: {name}: raw differs — generated {raw:?}, interpreted {:?}",
                value.raw
            );
            assert!(
                same_eng(eng, &value.eng),
                "{label}: {name}: engineering differs — generated {eng:?}, interpreted {:?}",
                value.eng
            );
        }
    }};
}

macro_rules! compare_with_interpreter {
    ($module:ident, $definition:expr, $stream:expr, $root:expr, $skip:expr, $packets:expr) => {{
        let db = XtceDb::from_path(testdata($definition)).expect("definition loads");
        let decoder = match $root {
            Some(name) => Decoder::with_root(&db, name),
            None => Decoder::new(&db),
        }
        .expect("root container");

        let stream = std::fs::read(testdata($stream)).expect("packet stream is present");
        let mut interpreted = decoder.new_packet(&stream);
        let mut compared = 0usize;

        for (index, framed) in PacketIter::new(&stream, $skip).enumerate() {
            let bytes = framed.expect("the stream is well framed").bytes();
            assert_same_packet!(
                $module,
                db,
                decoder,
                interpreted,
                bytes,
                format!("packet {index}")
            );
            compared += 1;
        }

        assert_eq!(
            compared, $packets,
            "the whole stream should have been compared"
        );
    }};
}

#[test]
fn ctim_generated_matches_interpreted_on_every_packet() {
    // CTIM is the scale test: 9 493 parameters, 38 concrete containers, fixed-size UTF-8
    // strings interleaved with integers, and 1499 real packets.
    compare_with_interpreter!(
        ctim,
        "ctim/ctim_xtce_v1.xml",
        "ctim/ccsds_2021_155_14_39_51",
        Some("CCSDSTelemetryPacket"),
        0,
        1499
    );
}

/// IDEX: a binary field whose width comes from `PKT_LEN`, with two fields after it.
///
/// This is the case that forced the cursor. Everything up to the blob is read at literal
/// offsets; the blob and the two fields behind it are walked, because where they sit is a
/// property of the packet.
#[test]
fn idex_generated_matches_interpreted_on_every_packet() {
    compare_with_interpreter!(
        idex,
        "idex/idex_combined_science_definition.xml",
        "idex/sciData_2023_052_14_45_05",
        None::<&str>,
        0,
        78
    );
}

#[test]
fn suda_generated_matches_interpreted_on_every_packet() {
    compare_with_interpreter!(
        suda,
        "suda/suda_combined_science_definition.xml",
        "suda/sciData_2022_130_17_41_53.spl",
        None::<&str>,
        4,
        13
    );
}

/// A CCSDS packet for `apid`, `payload` bytes long, filled with printable ASCII.
///
/// ASCII so that every string field decodes rather than erroring; a deterministic pattern so
/// a failure is reproducible.
fn synthetic_packet(apid: u16, payload: usize) -> Vec<u8> {
    let mut packet = vec![0u8; 6 + payload];
    // Version 0, type 0 (telemetry), secondary header present, then the APID.
    let first = 0x0800u16 | (apid & 0x07FF);
    packet[0] = (first >> 8) as u8;
    packet[1] = (first & 0xFF) as u8;
    // Sequence flags 3 (unsegmented), count 0.
    packet[2] = 0xC0;
    let count = (payload - 1) as u16;
    packet[4] = (count >> 8) as u8;
    packet[5] = (count & 0xFF) as u8;
    for (index, byte) in packet.iter_mut().enumerate().skip(6) {
        *byte = b' ' + (index % 95) as u8;
    }
    packet
}

/// The containers with string fields, on packets built for the purpose.
///
/// No packet in the CTIM stream reaches one: the three containers that declare strings —
/// `APID_6`, `APID_10` and `APID_28` — never occur in it. Without this, compiled string
/// decoding would have no comparison against the interpreter at all, which is precisely the
/// kind of gap the differential suite exists to close. Synthetic packets are enough, because
/// both decoders read the same bytes and any difference between them is real.
#[test]
fn ctim_string_containers_match_on_synthetic_packets() {
    let db = XtceDb::from_path(testdata("ctim/ctim_xtce_v1.xml")).expect("definition loads");
    let decoder = Decoder::with_root(&db, "CCSDSTelemetryPacket").expect("root container");
    for apid in [6u16, 10, 28] {
        let packet = synthetic_packet(apid, 2048);
        // The buffer borrows the packet, so both live for one iteration.
        let mut interpreted = decoder.new_packet(&packet);
        assert_same_packet!(
            ctim,
            db,
            decoder,
            interpreted,
            packet.as_slice(),
            format!("synthetic APID {apid}")
        );
        // The packet must have reached the container the APID names, or the comparison above
        // would be comparing two decoders that both went somewhere uninteresting.
        assert_eq!(
            ctim::decode(&packet).expect("decodes").container_name(),
            format!("APID_{apid}_Packet")
        );
    }
}

#[test]
fn ctim_strings_are_borrowed_from_the_packet() {
    // The point of compiling strings is that they cost nothing: the decoded value points
    // into the caller's buffer. Comparing values alone would still pass if that regressed to
    // an owned copy, so the borrow is asserted directly.
    let packet = synthetic_packet(6, 2048);

    let Ok(ctim::Packet::Apid6Packet(dump)) = ctim::decode(&packet) else {
        panic!("expected the memory-dump container");
    };

    let within = |slice: &[u8]| {
        let base = packet.as_ptr() as usize;
        let start = slice.as_ptr() as usize;
        start >= base && start + slice.len() <= base + packet.len()
    };
    assert!(
        within(dump.mem_dump_name_0_dmp.as_bytes()),
        "the string should point into the packet, not into a copy"
    );
    assert!(
        within(dump.mem_dump_name_0_dmp_raw),
        "and so should its raw buffer"
    );
    assert_eq!(
        dump.mem_dump_name_0_dmp.len(),
        1,
        "an 8-bit string is one character"
    );
}

/// Every numeric shape the emitter produces, aligned and unaligned, on generated packets.
///
/// The mission streams cannot reach these: between them they contain one 32-bit float and no
/// 16-bit float, every one byte-aligned. So the half-float conversion, sign extension at 63
/// bits, and the nine-byte span a 64-bit field occupies when it starts four bits into a byte
/// were all emitted without ever being compared against the interpreter.
///
/// The packets are generated rather than fixed: bit patterns matter here — NaN payloads,
/// subnormals, the sign bit of a 63-bit two's-complement field — and a handful of
/// hand-written packets would test whichever ones happened to be written. A fixed seed keeps
/// a failure reproducible.
#[test]
fn every_numeric_shape_matches_the_interpreter() {
    const BYTES: usize = 80;

    let db = XtceDb::from_path(testdata("numeric_edges.xml")).expect("definition loads");
    let decoder = Decoder::with_root(&db, "NumericEdges").expect("root container");

    // A packet of every byte equal, then xorshift64* patterns. All-zero and all-ones are
    // worth naming: they are zero, negative zero, infinity and the largest NaN payload,
    // depending on which field reads them.
    let mut packets: Vec<Vec<u8>> = (0..=255u8).map(|byte| vec![byte; BYTES]).collect();
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    for _ in 0..2048 {
        let mut packet = vec![0u8; BYTES];
        for chunk in packet.chunks_mut(8) {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let bytes = state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_be_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        packets.push(packet);
    }

    for (index, packet) in packets.iter().enumerate() {
        let mut interpreted = decoder.new_packet(packet);
        assert_same_packet!(
            numeric_edges,
            db,
            decoder,
            interpreted,
            packet.as_slice(),
            format!("packet {index}")
        );
    }
}

/// Calibration, against the interpreter, over generated packets.
///
/// Separate from the macro above because a calibrator is the one thing in the compiled subset
/// that can *refuse* a well-formed packet: a spline whose definition forbids extrapolation
/// has no answer outside its points. Agreement therefore has to include agreeing to fail, and
/// on the same packets — which the macro, written when nothing could fail, does not express.
///
/// `calibrators.xml` is deliberately built so both outcomes are common: two of its splines
/// sit on a four-bit field whose range is wider than their points.
#[test]
fn calibration_matches_the_interpreter_bit_for_bit() {
    const BYTES: usize = 23;

    let db = XtceDb::from_path(testdata("calibrators.xml")).expect("definition loads");
    let decoder = Decoder::with_root(&db, "Calibrated").expect("root container");
    let (same_raw, same_eng) = comparators!(calibrators);

    let mut packets: Vec<Vec<u8>> = (0..=255u8).map(|byte| vec![byte; BYTES]).collect();
    let mut state = 0x51ED_2701_A3C9_0FB7u64;
    for _ in 0..4096 {
        let mut packet = vec![0u8; BYTES];
        for chunk in packet.chunks_mut(8) {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let bytes = state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_be_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        packets.push(packet);
    }

    let mut compared = 0usize;
    let mut refused = 0usize;

    for (index, packet) in packets.iter().enumerate() {
        let mut interpreted = decoder.new_packet(packet);
        let by_interpreter = decoder.decode_into(&mut interpreted, packet);
        let by_generator = calibrators::decode(packet);

        match (by_interpreter, by_generator) {
            (Err(_), Err(_)) => {
                refused += 1;
                continue;
            }
            (Ok(()), Ok(compiled)) => {
                let mut fields = Vec::new();
                compiled.for_each_value(|name, raw, eng| fields.push((name, raw, eng)));
                assert_eq!(
                    fields.len(),
                    interpreted.len(),
                    "packet {index}: field counts differ"
                );

                for ((name, raw, eng), value) in fields.iter().zip(interpreted.values()) {
                    let expected = db
                        .parameter(value.parameter)
                        .map(|parameter| db.name(parameter.name))
                        .expect("parameter resolves");
                    assert_eq!(*name, expected, "packet {index}: field order differs");
                    assert!(
                        same_raw(raw, &value.raw),
                        "packet {index}: {name}: raw differs — generated {raw:?}, \
                         interpreted {:?}",
                        value.raw
                    );
                    // By bit pattern. A calibrated value that is right to fourteen digits and
                    // wrong in the last bit is exactly the failure this file exists to catch.
                    assert!(
                        same_eng(eng, &value.eng),
                        "packet {index}: {name}: engineering differs — generated {eng:?}, \
                         interpreted {:?}",
                        value.eng
                    );
                }
                compared += 1;
            }
            (interpreted_result, generated_result) => panic!(
                "packet {index}: the two implementations disagree about whether it decodes \
                 at all — interpreter {:?}, generated {:?}",
                interpreted_result.err(),
                generated_result.err()
            ),
        }
    }

    assert!(compared > 2_000, "only {compared} packet(s) were compared");
    assert!(
        refused > 100,
        "only {refused} packet(s) exercised a spline refusing to extrapolate"
    );
}

/// The integral and floating-point power paths are not interchangeable.
///
/// `calibrators.xml` gives `POLY_U32` and `POLY_F64` byte-for-byte identical terms over
/// different encodings. Fed the same number, they must still disagree in the last bit: the
/// reference cubes an integral raw exactly and rounds once, and cubes a float raw by repeated
/// squaring, which rounds twice.
///
/// Without this, an emitter that sent both through one path would pass everything above —
/// the two fields are compared against the interpreter separately, and a test that never
/// feeds them the same number never notices they agree when they should not.
#[test]
fn the_integer_power_path_is_not_the_float_one() {
    // 2^27 + 1. Its cube needs 82 bits, so rounding it once is not the same as rounding the
    // square and then the product.
    const VALUE: u32 = (1 << 27) + 1;

    let mut packet = vec![0u8; 23];
    packet[0..4].copy_from_slice(&VALUE.to_be_bytes());
    packet[4..12].copy_from_slice(&f64::from(VALUE).to_bits().to_be_bytes());
    // Both four-bit splines refuse to extrapolate, so they need a query inside their points.
    packet[20] = 0x55;

    let calibrators::Packet::Calibrated(decoded) =
        calibrators::decode(&packet).expect("the packet decodes");

    assert_eq!(decoded.poly_u32, u64::from(VALUE));
    assert_eq!(decoded.poly_f64, f64::from(VALUE));
    assert_ne!(
        decoded.poly_u32_eng.to_bits(),
        decoded.poly_f64_eng.to_bits(),
        "the same value through the integral and floating-point paths came out identical, \
         so the emitter is using one path for both"
    );
    // Not wildly different, though: this is a last-bit disagreement, not a wrong answer.
    let difference = (decoded.poly_u32_eng - decoded.poly_f64_eng).abs();
    assert!(
        difference / decoded.poly_u32_eng.abs() < 1e-15,
        "the two paths differ by more than rounding: {difference}"
    );
}

/// A calibrator on an enumeration or a boolean is ignored, because the reference ignores it.
///
/// XTCE looks both up from the *raw* value, and the interpreter returns before it consults a
/// calibrator. `ENUM_CAL` and `BOOL_CAL` carry one anyway; a generator that helpfully applied
/// it would turn `ARMED` into 1000.
#[test]
fn a_calibrator_on_an_enumeration_or_boolean_is_ignored() {
    let mut packet = vec![0u8; 23];
    packet[20] = 0x55;
    // ENUM_CAL is bits 168..170 and BOOL_CAL is bit 170, so both live in byte 21.
    packet[21] = 0b0110_0000; // ENUM_CAL = 1, BOOL_CAL = 1

    let calibrators::Packet::Calibrated(decoded) =
        calibrators::decode(&packet).expect("the packet decodes");

    assert_eq!(decoded.enum_cal, 1);
    assert_eq!(decoded.enum_cal_label(), Some("ARMED"));
    assert!(decoded.bool_cal_value());

    // The proof that nothing was applied: neither carries an engineering field at all. If the
    // generator had compiled their calibrators, `enum_cal_eng` would exist and this would not
    // compile.
    let mut engineering = Vec::new();
    decoded.for_each_value(|name, _, eng| engineering.push((name, format!("{eng:?}"))));
    let labelled: Vec<&(&str, String)> = engineering
        .iter()
        .filter(|(name, _)| *name == "ENUM_CAL" || *name == "BOOL_CAL")
        .collect();
    assert_eq!(labelled.len(), 2);
    assert!(labelled[0].1.contains("ARMED"), "{:?}", labelled[0]);
    assert!(labelled[1].1.contains("true"), "{:?}", labelled[1]);
}

/// A boolean expression that is a tree, against the interpreter, over every packet shape.
///
/// The one bundled mission file with a `<BooleanExpression>` has a single conjunction of two
/// equalities — the same thing a `<ComparisonList>` already expressed — so compiling it
/// proves almost nothing about the element. What is new is that it nests and that it can be
/// a disjunction, and both change which container a packet selects.
///
/// The loop below has to tolerate failure on both sides, and for two different reasons: a
/// packet may match nothing, or it may match two inheritors at once. `boolean_criteria.xml`
/// gives Alpha and Beta overlapping branches so that the second case is common, because an
/// OR is exactly what makes it easy to write by accident.
#[test]
fn a_boolean_expression_tree_matches_the_interpreter() {
    let db = XtceDb::from_path(testdata("boolean_criteria.xml")).expect("definition loads");
    let decoder = Decoder::with_root(&db, "Root").expect("root container");
    let (same_raw, same_eng) = comparators!(boolean_criteria);

    // Every nibble of SEL against a spread of LEVEL and CODE, so each branch of every
    // expression is reached from both sides.
    let mut packets: Vec<Vec<u8>> = Vec::new();
    for sel in 0..16u8 {
        for level in [0u8, 1, 200, 201, 255] {
            for code in [0u16, 4659, 4660, 4661, 0xFFFF] {
                let mut packet = vec![sel << 4, level, 0, 0, 0x5A];
                packet[2..4].copy_from_slice(&code.to_be_bytes());
                packets.push(packet);
            }
        }
    }

    let mut decoded = 0usize;
    let mut ambiguous = 0usize;
    let mut unrecognised = 0usize;

    for (index, packet) in packets.iter().enumerate() {
        let mut interpreted = decoder.new_packet(packet);
        let by_interpreter = decoder.decode_into(&mut interpreted, packet);
        let by_generator = boolean_criteria::decode(packet);

        let sel = packet[0] >> 4;
        match (by_interpreter, by_generator) {
            (Err(_), Err(_)) => {
                // SEL 2 is in both Alpha's and Beta's disjunction, so it is the ambiguous
                // one and every other refusal is a packet nothing describes.
                if sel == 2 {
                    ambiguous += 1;
                } else {
                    unrecognised += 1;
                }
            }
            (Ok(()), Ok(compiled)) => {
                let container = db
                    .container(interpreted.container())
                    .map(|container| db.name(container.name))
                    .expect("container resolves");
                assert_eq!(
                    compiled.container_name(),
                    container,
                    "packet {index} (SEL {sel}): the two decoders chose different containers"
                );

                let mut fields = Vec::new();
                compiled.for_each_value(|name, raw, eng| fields.push((name, raw, eng)));
                assert_eq!(
                    fields.len(),
                    interpreted.len(),
                    "packet {index}: field counts"
                );
                for ((name, raw, eng), value) in fields.iter().zip(interpreted.values()) {
                    assert!(
                        same_raw(raw, &value.raw),
                        "packet {index}: {name}: raw differs"
                    );
                    assert!(
                        same_eng(eng, &value.eng),
                        "packet {index}: {name}: engineering differs"
                    );
                }
                decoded += 1;
            }
            (interpreted_result, generated_result) => panic!(
                "packet {index} (SEL {sel}): the two disagree about whether it decodes — \
                 interpreter {:?}, generated {:?}",
                interpreted_result.err(),
                generated_result.err()
            ),
        }
    }

    // Exact counts rather than lower bounds, because the point of the file is *which*
    // packets each expression selects. Of 400 packets, over 16 values of SEL and 5 each of
    // LEVEL and CODE:
    //
    //   SEL 1  -> Alpha, all 25
    //   SEL 2  -> Alpha and Beta both, all 25 ambiguous
    //   SEL 3  -> Beta, all 25
    //   SEL 4  -> Gamma when LEVEL > 200 (2 of 5) or CODE == 4660 (1 of 5): 25 - 3*4 = 13
    //   SEL 5  -> Delta when LEVEL != 0: 4 of 5, so 20
    //   the other 11 values of SEL describe nothing: 275
    assert_eq!(
        decoded,
        25 + 25 + 13 + 20,
        "wrong number of packets decoded"
    );
    assert_eq!(
        ambiguous, 25,
        "every SEL = 2 packet should have matched both Alpha and Beta"
    );
    assert_eq!(unrecognised, 12 + 5 + 275, "wrong number matched nothing");
}
