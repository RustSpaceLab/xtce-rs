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
| `xtce-codegen` | IR → a static Rust decoder with every offset baked in |
| `xtce-cli` | `xtce info`, `xtce decode`, `xtce bench` |
| `xtask` | differential test harness against the Python reference |

Scope is a deliberate subset of XTCE, documented in [`SUPPORTED.md`](SUPPORTED.md).

#### Correctness

Correctness is defined as agreement with the reference, not as passing tests written
alongside the code. `testdata/golden/` holds the reference's output for six real
definition/packet pairs, and `cargo xtask diff` re-derives all of it:

* every raw and engineering value of the first 64 packets, compared field by field;
* a SHA-256 over a canonical encoding of **all** ~17 000 packets, so a divergence past the
  detail window cannot hide;
* one case is a definition pointed at a stream it does not describe, so the "both refuse this
  packet" half of the contract is tested too.

All six agree.

#### Speed

Measured with criterion against the same reference on the same inputs
(`testdata/golden/reference_timings.json`):

| | xtce-rs | `space_packet_parser` | |
|---|---|---|---|
| Load a 1.6 MB definition (CTIM, 9 493 parameters) | 10.5 ms | 120 ms | **11×** |
| Decode 1499 CTIM packets | 48 ms | 5109 ms | **106×** |
| Decode 7200 JPSS packets | 9.3 ms | 954 ms | **102×** |
| The same, through a **generated** decoder | 84 µs | 954 ms | **11 400×** |

The generated decoder is what `xtce-codegen` produces: a `struct` per container whose
`decode` is loads, shifts and masks with every bit offset already a literal. It compiles a
narrower subset than the interpreter and refuses anything else by name rather than falling
back — see [`SUPPORTED.md`](SUPPORTED.md).

#### Try it

```console
$ cargo run --release -p xtce-cli -- info testdata/spp/ctim/ctim_xtce_v1.xml
$ cargo run --release -p xtce-cli -- decode \
      testdata/spp/jpss/jpss1_geolocation_xtce_v1.xml \
      testdata/spp/jpss/J01_G011_LZ_2021-04-09T00-00-00Z_V01.DAT1 --limit 3 --raw
$ cargo run --release -p xtce-cli -- codegen \\
      testdata/spp/jpss/jpss1_geolocation_xtce_v1.xml
$ cargo xtask diff
$ cargo bench
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
