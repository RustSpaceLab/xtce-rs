# xtce-rs

[![CI](https://github.com/RustSpaceLab/xtce-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/RustSpaceLab/xtce-rs/actions/workflows/ci.yml)

Decode CCSDS telemetry packets in Rust, according to an [XTCE](https://www.omg.org/spec/XTCE/)
definition. Part of [RustSpaceLab](https://github.com/RustSpaceLab).

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
| `xtce-cli` | `xtce info`, `xtce decode`, `xtce codegen`, `xtce bench` |
| `xtce-py` | Python bindings (PyO3), built by `maturin` |
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

From Python:

```python
import xtce

definition = xtce.Definition("jpss1_geolocation_xtce_v1.xml")
packets = definition.decode_stream(open("telemetry.dat", "rb").read())
print(len(packets), packets[0]["PKT_APID"])
```

`decode_stream` frames and decodes a whole buffer in one call, releasing the GIL for the Rust
part. That matters: a per-packet round trip would give the speed-up back to the interpreter.
7200 JPSS packets take 38 ms including building every Python dictionary, against the
reference's 954 ms.

The bindings are their own Cargo workspace, so `cargo build --workspace` never needs
libpython. Build them with `maturin develop --release --manifest-path crates/xtce-py/Cargo.toml`.

## Testing

Nothing below needs Python unless it says so: the reference implementation's output is
committed under `testdata/golden/`.

### Everything, the short way

```console
$ cargo test --workspace     # 109 tests
$ cargo xtask diff           # the differential suite, 7 definition/stream pairs
```

`cargo xtask diff` is the one that matters. It decodes every packet of six real mission
streams and checks the result against what `space_packet_parser` produced:

```
ctim                             ok
  1499 packets (0 not described)   load 8.7x   decode 4.9x   digest ok
  105 packet(s) had bits no entry claimed (both implementations agree on the values)
...
all 6 case(s) match the reference implementation
```

Two independent checks per case. Every raw and engineering value of the first 64 packets is
compared field by field, so a failure names the packet, the parameter and both values. Then a
SHA-256 over a canonical encoding of **all** ~17 000 packets is compared against the digest
the reference produced — so a divergence past the detail window cannot hide. `digest ok` and a
clean detail section together mean the two implementations agree on every packet.

The `load`/`decode` multipliers in that output include the harness's own bookkeeping. They are
a floor, not a benchmark; use `cargo bench` for real numbers.

### What each layer actually proves

| Command | Proves |
|---|---|
| `cargo test -p xtce-model` | the XML reader and IR on all 10 bundled definitions |
| `cargo test -p xtce-decode` | bit reading (property tests against a one-bit-at-a-time oracle), and 25 end-to-end cases over inline XML snippets |
| `cargo test -p xtce-codegen` | the generated decoder equals the interpreted one on all 7200 JPSS packets, field by field |
| `cargo test -p xtce-codegen-e2e` | every bundled definition compiles under `#![no_std]`, and each agrees with the interpreter |
| `cargo xtask diff` | the interpreted decoder equals the Python reference on seven streams, six of them real |
| `pytest crates/xtce-py/tests` | the Python bindings lose nothing crossing the boundary |

They are deliberately layered: codegen is checked against the interpreter, and the
interpreter against the reference, so codegen inherits the reference's authority without
needing its own golden files.

### One case, or one difference

```console
$ cargo xtask diff --case ctim
$ cargo xtask diff --case suda --max-differences 100
```

### Benchmarks

```console
$ cargo bench                                   # everything
$ cargo bench -p xtce-decode --bench decode     # decoding only
$ cargo bench -p xtce-model  --bench load       # loading only, plus the raw-parser ceiling
$ cargo bench -p xtce-codegen                   # generated vs interpreted, side by side
```

Criterion writes an HTML report to `target/criterion/report/index.html` and compares against
the previous run, so a regression shows up as a red percentage.

The reference implementation's own timings for the same inputs are in
`testdata/golden/reference_timings.json`, recorded by the run that produced the goldens.

### By hand

```console
$ cargo run --release -p xtce-cli -- info testdata/spp/ctim/ctim_xtce_v1.xml
$ cargo run --release -p xtce-cli -- decode \
      testdata/spp/jpss/jpss1_geolocation_xtce_v1.xml \
      testdata/spp/jpss/J01_G011_LZ_2021-04-09T00-00-00Z_V01.DAT1 --limit 2 --raw
```

`info` reports how many containers are fully decodable and what blocks the rest. `decode`
reports packets with bits no entry claimed — on CTIM that is 105 of 1499, which says the
definition does not describe the whole packet.

### Python bindings

These do need a Python toolchain:

```console
$ python3.12 -m venv .venv
$ .venv/bin/pip install maturin pytest space_packet_parser==6.1.2
$ .venv/bin/maturin develop --release --manifest-path crates/xtce-py/Cargo.toml
$ .venv/bin/pytest crates/xtce-py/tests -q
```

### Regenerating the golden files

Only needed after deliberately changing what is compared, or to add a case. It runs the
Python reference, so it needs the venv above:

```console
$ .venv/bin/python tools/gen_goldens.py
```

A change to `testdata/golden/` in a diff means the *reference's* output changed — treat that
as something to explain, not to accept.

## Layout

```
crates/          library and binary crates
testdata/spp/    real XTCE files and packet streams (BSD-3, see testdata/SOURCES.md)
testdata/golden/ reference output, committed so CI needs no Python
tools/           the golden-file generator
```

## Licence

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option.

The vendored test data under `testdata/spp/` keeps its own licence — BSD 3-Clause,
© 2023 University of Colorado — and is redistributed with the copyright notice that licence
requires. Provenance for every file is in [`testdata/SOURCES.md`](testdata/SOURCES.md).

### Contributing

Unless you state otherwise, any contribution you intentionally submit for inclusion in this
work shall be dual-licensed as above, without any additional terms or conditions.

[spp]: https://github.com/lasp/space_packet_parser
[issue112]: https://github.com/lasp/space_packet_parser/issues/112
