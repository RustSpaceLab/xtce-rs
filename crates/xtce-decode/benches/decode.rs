//! Decoding throughput on real mission data.
//!
//! Measures `Decoder::decode` and nothing else — no name lookup, no map building, no
//! digesting. The differential harness reports a decode time too, but that figure includes
//! its own per-packet bookkeeping, so it understates the decoder and must not be quoted as a
//! decoder benchmark.
//!
//! The Python reference's own timings for the same inputs are in
//! `testdata/golden/reference_timings.json`, produced by the same run that generated the
//! goldens.

use std::hint::black_box;
use std::path::{Path, PathBuf};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use xtce_decode::{Decoder, PacketIter};
use xtce_model::XtceDb;

struct Case {
    name: &'static str,
    xtce: &'static str,
    packets: &'static str,
    root: Option<&'static str>,
    skip_header_bytes: usize,
}

const CASES: &[Case] = &[
    Case {
        name: "jpss",
        xtce: "jpss/jpss1_geolocation_xtce_v1.xml",
        packets: "jpss/J01_G011_LZ_2021-04-09T00-00-00Z_V01.DAT1",
        root: None,
        skip_header_bytes: 0,
    },
    Case {
        name: "ctim",
        xtce: "ctim/ctim_xtce_v1.xml",
        packets: "ctim/ccsds_2021_155_14_39_51",
        root: Some("CCSDSTelemetryPacket"),
        skip_header_bytes: 0,
    },
    Case {
        name: "idex",
        xtce: "idex/idex_combined_science_definition.xml",
        packets: "idex/sciData_2023_052_14_45_05",
        root: None,
        skip_header_bytes: 0,
    },
];

fn testdata(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/spp")
        .join(relative)
}

fn decode_streams(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("decode");
    for case in CASES {
        let Ok(db) = XtceDb::from_path(testdata(case.xtce)) else {
            continue;
        };
        let decoder = match case.root {
            Some(name) => Decoder::with_root(&db, name),
            None => Decoder::new(&db),
        };
        let Ok(decoder) = decoder else { continue };
        let Ok(stream) = std::fs::read(testdata(case.packets)) else {
            continue;
        };

        // Frame once, outside the measured loop: this benchmark is about decoding, not
        // about walking CCSDS headers.
        let packets: Vec<&[u8]> = PacketIter::new(&stream, case.skip_header_bytes)
            .filter_map(Result::ok)
            .map(|packet| packet.bytes())
            .collect();
        if packets.is_empty() {
            continue;
        }

        let bytes: usize = packets.iter().map(|packet| packet.len()).sum();
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_function(case.name, |bencher| {
            bencher.iter(|| {
                for packet in &packets {
                    // `decode` returns a `Result`; a benchmark that silently discarded
                    // failures would measure the error path.
                    let decoded = decoder.decode(black_box(packet));
                    black_box(decoded.map(|packet| packet.len()).unwrap_or(0));
                }
            });
        });
    }
    group.finish();
}

/// One packet at a time, so the per-packet cost is visible without stream-length noise.
fn decode_single_packet(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("decode_one");
    for case in CASES {
        let Ok(db) = XtceDb::from_path(testdata(case.xtce)) else {
            continue;
        };
        let decoder = match case.root {
            Some(name) => Decoder::with_root(&db, name),
            None => Decoder::new(&db),
        };
        let Ok(decoder) = decoder else { continue };
        let Ok(stream) = std::fs::read(testdata(case.packets)) else {
            continue;
        };
        let Some(Ok(packet)) = PacketIter::new(&stream, case.skip_header_bytes).next() else {
            continue;
        };
        let bytes = packet.bytes().to_vec();

        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_function(case.name, |bencher| {
            bencher.iter(|| {
                let decoded = decoder.decode(black_box(&bytes));
                black_box(decoded.map(|packet| packet.len()).unwrap_or(0));
            });
        });
    }
    group.finish();
}

/// The same streams through `decode_into`, which reuses one packet buffer.
///
/// The difference against `decode` is exactly the cost of the per-packet allocations.
fn decode_reusing_buffer(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("decode_into");
    for case in CASES {
        let Ok(db) = XtceDb::from_path(testdata(case.xtce)) else {
            continue;
        };
        let decoder = match case.root {
            Some(name) => Decoder::with_root(&db, name),
            None => Decoder::new(&db),
        };
        let Ok(decoder) = decoder else { continue };
        let Ok(stream) = std::fs::read(testdata(case.packets)) else {
            continue;
        };
        let packets: Vec<&[u8]> = PacketIter::new(&stream, case.skip_header_bytes)
            .filter_map(Result::ok)
            .map(|packet| packet.bytes())
            .collect();
        if packets.is_empty() {
            continue;
        }

        let bytes: usize = packets.iter().map(|packet| packet.len()).sum();
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_function(case.name, |bencher| {
            bencher.iter(|| {
                let mut buffer = decoder.new_packet(&stream);
                for packet in &packets {
                    let outcome = decoder.decode_into(&mut buffer, black_box(packet));
                    black_box(outcome.is_ok() as usize + buffer.len());
                }
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    decode_streams,
    decode_reusing_buffer,
    decode_single_packet
);
criterion_main!(benches);
