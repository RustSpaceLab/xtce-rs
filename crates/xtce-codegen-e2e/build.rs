//! Compiles the bundled XTCE definitions into Rust decoders, into `OUT_DIR`.
//!
//! Panicking is the right failure mode here: a definition this project ships and expects to
//! compile must not silently degrade into a skipped test.

use std::path::{Path, PathBuf};

/// `(module name, definition, root container)`.
const CASES: &[(&str, &str, Option<&str>)] = &[
    (
        "ctim",
        "ctim/ctim_xtce_v1.xml",
        Some("CCSDSTelemetryPacket"),
    ),
    // Both of these have a binary field whose width comes from PKT_LEN, and two more fields
    // after it — so their offsets are only known while decoding. They are the reason the
    // generator has a cursor at all.
    ("idex", "idex/idex_combined_science_definition.xml", None),
    ("suda", "suda/suda_combined_science_definition.xml", None),
    // No packet stream ships for this one; generating and compiling it is the check.
    ("udp", "udp_packet.xml", None),
    // Every numeric shape the emitter can produce, aligned and unaligned. The mission
    // definitions between them have one 32-bit float and no 16-bit float, all byte-aligned,
    // so without this the half-float and nine-byte-span paths would go unchecked.
    ("numeric_edges", "numeric_edges.xml", Some("NumericEdges")),
];

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let testdata = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/spp");

    for (module, relative, root) in CASES {
        let path = testdata.join(relative);
        println!("cargo::rerun-if-changed={}", path.display());

        let db = xtce_model::XtceDb::from_path(&path)
            .unwrap_or_else(|error| panic!("{relative}: {error}"));

        let options = xtce_codegen::Options {
            root: root.map(str::to_owned),
            source_label: Some(format!("testdata/spp/{relative}")),
        };
        let source = xtce_codegen::generate(&db, &options)
            .unwrap_or_else(|error| panic!("{relative}: {error}"));

        std::fs::write(out_dir.join(format!("{module}.rs")), source)
            .unwrap_or_else(|error| panic!("{module}.rs: {error}"));
    }
}
