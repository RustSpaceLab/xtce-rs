# xtce-codegen

[![crates.io](https://img.shields.io/crates/v/xtce-codegen.svg)](https://crates.io/crates/xtce-codegen)
[![docs.rs](https://docs.rs/xtce-codegen/badge.svg)](https://docs.rs/xtce-codegen)

Compiles an XTCE definition into a `struct` per container whose `decode` is a sequence of
loads, shifts and masks with every offset already a literal. Nothing consults the XTCE model at
run time.

Measured against the interpreted decoder in the same repository on the same 7 200-packet
stream: roughly 100× it, which is about 11 000× the Python reference.

Refusals are fatal by design. A construct the generator cannot compile is refused with the
element named, rather than falling back to interpretation — a silent fallback would make the
measurement above meaningless.

## Example

```rust,no_run
use xtce_model::XtceDb;

let db = XtceDb::from_path("mission.xml")?;
let source = xtce_codegen::generate(&db, &xtce_codegen::Options::default())?;
std::fs::write("decoder.rs", source)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Part of [RustSpaceLab/xtce-rs](https://github.com/RustSpaceLab/xtce-rs).
