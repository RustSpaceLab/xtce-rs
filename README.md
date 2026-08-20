# RustSpace

High-performance Rust libraries for space data systems.

## Projects

### `xtce-rs` — CCSDS telemetry decoding from XTCE

Decodes CCSDS space packets according to an [XTCE](https://www.omg.org/spec/XTCE/) telemetry
definition.

The reference implementation in this niche, [`lasp/space_packet_parser`][spp], has a known
performance problem: on real mission databases, loading the XTCE file costs more than parsing
the packets ([issue #112][issue112]). This project attacks both halves — a fast XML-to-IR
loader, and a decoder that walks a flat arena instead of a graph of Python objects — and is
validated against that same implementation packet for packet.

| Crate | What it does |
|---|---|
| `xtce-model` | XTCE XML → arena-backed IR, reference resolution, validation |
| `xtce-decode` | IR + `&[u8]` → parameter values |
| `xtce-cli` | `xtce info`, `xtce decode`, `xtce bench` |
| `xtask` | differential test harness against the Python reference |

Scope is a deliberate subset of XTCE, documented in [`SUPPORTED.md`](SUPPORTED.md).
Correctness is defined by agreement with the reference: `testdata/golden/` holds its output
for five real mission definition/packet pairs, and `cargo xtask diff` checks every packet
against it.

```console
$ cargo run -p xtce-cli -- info testdata/spp/ctim/ctim_xtce_v1.xml
$ cargo run -p xtce-cli -- decode testdata/spp/jpss/jpss1_geolocation_xtce_v1.xml \
      testdata/spp/jpss/J01_G011_LZ_2021-04-09T00-00-00Z_V01.DAT1 --limit 3
$ cargo run -p xtask --release -- diff
```

## Layout

```
crates/          library and binary crates
testdata/spp/    real XTCE files and packet streams (BSD-3, see testdata/SOURCES.md)
testdata/golden/ reference output, committed so CI needs no Python
tools/           the golden-file generator
```

## Licence

MIT OR Apache-2.0. Vendored test data keeps its own licence; see
[`testdata/SOURCES.md`](testdata/SOURCES.md).

[spp]: https://github.com/lasp/space_packet_parser
[issue112]: https://github.com/lasp/space_packet_parser/issues/112
