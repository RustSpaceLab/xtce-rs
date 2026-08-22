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

#[allow(dead_code, clippy::all, clippy::pedantic)]
mod ctim {
    include!(concat!(env!("OUT_DIR"), "/ctim.rs"));
}

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
    ($module:ident, $definition:expr, $stream:expr, $root:expr, $packets:expr) => {{
        let db = XtceDb::from_path(testdata($definition)).expect("definition loads");
        let decoder = match $root {
            Some(name) => Decoder::with_root(&db, name),
            None => Decoder::new(&db),
        }
        .expect("root container");

        let stream = std::fs::read(testdata($stream)).expect("packet stream is present");
        let mut interpreted = decoder.new_packet(&stream);
        let mut compared = 0usize;

        for (index, framed) in PacketIter::new(&stream, 0).enumerate() {
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
        1499
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
