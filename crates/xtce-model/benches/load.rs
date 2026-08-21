//! XTCE load time.
//!
//! The project's thesis is that loading a mission database should not cost more than parsing
//! the packets it describes. The Python reference's figures for the same files are in
//! `testdata/golden/reference_timings.json`.
//!
//! Both halves are measured separately, because they are optimised differently: `parse_xml`
//! is the XML reader and the interner, `load` adds reference resolution and the cycle check.

use std::hint::black_box;
use std::path::{Path, PathBuf};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use xtce_model::XtceDb;
use xtce_model::xml::Dom;

const FILES: &[(&str, &str)] = &[
    ("jpss", "jpss/jpss1_geolocation_xtce_v1.xml"),
    ("idex", "idex/idex_combined_science_definition.xml"),
    ("ctim", "ctim/ctim_xtce_v1.xml"),
];

fn testdata(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/spp")
        .join(relative)
}

fn load_definitions(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("load");
    for (name, relative) in FILES {
        let Ok(text) = std::fs::read_to_string(testdata(relative)) else {
            continue;
        };
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_function(*name, |bencher| {
            bencher.iter(|| {
                let db = XtceDb::from_xml(black_box(&text));
                black_box(db.map(|db| db.parameters().len()).unwrap_or(0));
            });
        });
    }
    group.finish();
}

/// The XML half alone, so a regression can be attributed to the reader or to lowering.
fn parse_xml_only(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("parse_xml");
    for (name, relative) in FILES {
        let Ok(text) = std::fs::read_to_string(testdata(relative)) else {
            continue;
        };
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_function(*name, |bencher| {
            bencher.iter(|| {
                let dom = Dom::parse(black_box(&text));
                black_box(dom.map(|dom| dom.len()).unwrap_or(0));
            });
        });
    }
    group.finish();
}

/// The XML reader with no tree built at all.
///
/// This is the ceiling: no implementation of `parse_xml` can be faster than iterating the
/// events it has to see. Keeping it in the suite stops "the parser is slow" from being
/// asserted without knowing how much of the time is unavoidable.
fn raw_events(criterion: &mut Criterion) {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut group = criterion.benchmark_group("raw_events");
    for (name, relative) in FILES {
        let Ok(text) = std::fs::read_to_string(testdata(relative)) else {
            continue;
        };
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_function(*name, |bencher| {
            bencher.iter(|| {
                let mut reader = Reader::from_str(black_box(&text));
                reader.config_mut().trim_text(true);
                let mut count = 0usize;
                loop {
                    match reader.read_event() {
                        Ok(Event::Eof) | Err(_) => break,
                        Ok(Event::Start(start) | Event::Empty(start)) => {
                            count += start.attributes().count();
                        }
                        Ok(_) => count += 1,
                    }
                }
                black_box(count)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, load_definitions, parse_xml_only, raw_events);
criterion_main!(benches);
