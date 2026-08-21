//! Generated decoder against interpreted decoder, on the same packets.
//!
//! This benchmark exists to decide whether the code generator is worth its complexity. Both
//! decoders are in one criterion group so the comparison cannot be avoided, and both are
//! measured over the same 7200-packet stream with the same framing done outside the loop.
//!
//! If the generated decoder is not meaningfully faster, that is a finding, not a failure —
//! and `PROGRESS.md` should say so.

use std::hint::black_box;
use std::path::{Path, PathBuf};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use xtce_decode::{Decoder, PacketIter};
use xtce_model::XtceDb;

#[allow(dead_code, clippy::all, clippy::pedantic)]
mod generated {
    include!("../tests/generated/jpss_geolocation.rs");
}

fn testdata(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/spp")
        .join(relative)
}

fn compare(criterion: &mut Criterion) {
    let Ok(db) = XtceDb::from_path(testdata("jpss/jpss1_geolocation_xtce_v1.xml")) else {
        return;
    };
    let Ok(decoder) = Decoder::new(&db) else {
        return;
    };
    let Ok(stream) = std::fs::read(testdata("jpss/J01_G011_LZ_2021-04-09T00-00-00Z_V01.DAT1"))
    else {
        return;
    };
    let packets: Vec<&[u8]> = PacketIter::new(&stream, 0)
        .filter_map(Result::ok)
        .map(|packet| packet.bytes())
        .collect();
    if packets.is_empty() {
        return;
    }

    let bytes: usize = packets.iter().map(|packet| packet.len()).sum();
    let mut group = criterion.benchmark_group("jpss_stream");
    group.throughput(Throughput::Bytes(bytes as u64));

    group.bench_function("interpreted", |bencher| {
        bencher.iter(|| {
            let mut buffer = decoder.new_packet(&stream);
            for packet in &packets {
                let outcome = decoder.decode_into(&mut buffer, black_box(packet));
                black_box(outcome.is_ok() as usize + buffer.len());
            }
        });
    });

    // Dispatch alone: only the discriminator fields are consumed, so the optimiser is free
    // to drop every other field read. Reported separately and labelled, because quoting it
    // as the decoder's speed would be dishonest — it is the cost of *choosing* a container.
    group.bench_function("generated_dispatch_only", |bencher| {
        bencher.iter(|| {
            for packet in &packets {
                let decoded = generated::decode(black_box(packet));
                black_box(decoded.map(|p| p.container_name().len()).unwrap_or(0));
            }
        });
    });

    // The honest comparison: the whole struct is consumed, so every field is really read.
    group.bench_function("generated", |bencher| {
        bencher.iter(|| {
            for packet in &packets {
                let _ = black_box(generated::decode(black_box(packet)));
            }
        });
    });

    // Closer still to what the interpreted decoder does, which also hands back a name and
    // both values for every field.
    group.bench_function("generated_visiting_fields", |bencher| {
        bencher.iter(|| {
            let mut total = 0usize;
            for packet in &packets {
                if let Ok(decoded) = generated::decode(black_box(packet)) {
                    decoded.for_each_value(|name, raw, eng| {
                        black_box((name, raw, eng));
                        total += 1;
                    });
                }
            }
            black_box(total)
        });
    });

    group.finish();
}

criterion_group!(benches, compare);
criterion_main!(benches);
