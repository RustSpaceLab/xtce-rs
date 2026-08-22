//! Compiles the bundled XTCE definitions into Rust decoders, into `OUT_DIR`.
//!
//! Panicking is the right failure mode here: a definition this project ships and expects to
//! compile must not silently degrade into a skipped test.

use std::path::{Path, PathBuf};

/// `(module name, definition, root container)`.
const CASES: &[(&str, &str, Option<&str>)] = &[(
    "ctim",
    "ctim/ctim_xtce_v1.xml",
    Some("CCSDSTelemetryPacket"),
)];

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
