# xtce-codegen

Compiles an XTCE definition into a `struct` per container whose `decode` is a sequence of
loads, shifts and masks with every offset already a literal. Nothing consults the XTCE model at
run time.

Measured against the interpreted decoder in the same repository on the same 7 200-packet
stream: roughly 100× it, which is about 11 000× the Python reference.

Refusals are fatal by design. A construct the generator cannot compile is refused with the
element named, rather than falling back to interpretation — a silent fallback would make the
measurement above meaningless.

Part of [RustSpaceLab/xtce-rs](https://github.com/RustSpaceLab/xtce-rs).
