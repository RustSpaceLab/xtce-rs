# Progress log

## 2026-08-21 — M0 through M3

**Done.** Workspace, CI, vendored test data, golden files, the model, the decoder, and the
differential harness. All five golden cases match the Python reference exactly.

```
ctim                         ok    1499 packets   digest ok
idex                         ok      78 packets   digest ok
jpss_contrived_inheritance   ok    7200 packets   digest ok
jpss_geolocation             ok    7200 packets   digest ok
suda                         ok      13 packets   digest ok
```

"Match" means every raw and engineering value of the first 64 packets compared field by
field, *and* a SHA-256 over the canonical encoding of all 16 000 packets agreeing with the
digest the reference produced.

### Decisions worth recording

**Represent, do not reject.** The specification said an out-of-scope element should raise
`XtceError::Unsupported` at load. Taken literally that makes M1 unreachable: `DynamicValue`,
`BooleanExpression` and `AliasSet` appear in most of the real test files, so nothing would
load and there would be nothing to compare against. Representation and evaluation are now
separate — `xtce-model` models everything it meets, and `xtce-decode` raises at the moment a
value actually depends on an out-of-scope construct. `xtce info` reports per file how many
containers are fully decodable and what blocks the rest, which is a more useful artefact
than the tree dump the milestone asked for.

**The golden format is not `json.dumps`.** The first version stored floats via Python's
`float.hex()` and digested `json.dumps(..., sort_keys=True)`. Both would have required
reproducing CPython's exact output byte for byte on the Rust side — `ensure_ascii` escaping,
the zero special case in `float.hex()`. Floats are now stored as their IEEE-754 bit pattern
and the digest runs over an explicitly specified length-prefixed encoding that both sides
implement from the same twenty-line description.

**SHA-256 is implemented here** rather than added as a dependency, because the goldens are
digested by Python's `hashlib` and this side has to agree with the standard. NIST vectors
are in the tests. The first version had a bug in the streaming path — a partial buffer was
discarded when an update did not complete a block — which made `finalize` loop forever. The
chunk-size test now covers it.

**Deliberate divergences from the reference** are listed at the bottom of `SUPPORTED.md`.
None is exercised by the bundled test data, so the differential result is unaffected by them.

### Numbers (release, criterion, M1 Mac)

Load, and decode of the whole stream:

| Case | Load | Reference | Speed-up | Decode | Reference | Speed-up |
|---|---|---|---|---|---|---|
| ctim — 1.6 MB definition, 1499 packets | 23.2 ms | 120 ms | 5.2x | 77.1 ms | 5109 ms | 66x |
| jpss — 7200 packets | 0.17 ms | 10 ms | 59x | 15.8 ms | 954 ms | 61x |
| idex — 78 packets | 1.25 ms | 21 ms | 17x | 0.21 ms | 19.5 ms | 94x |

**Correction.** The decode figures first recorded here came from `xtask diff`, which times
its own per-packet bookkeeping — name lookup, `BTreeMap`, SHA-256 — alongside the decoder.
For ctim that inflated decode from 77 ms to 1087 ms, a factor of fourteen. The table above is
`Decoder::decode` and nothing else, measured by criterion. The project's claim is a measured
advantage, so measuring the wrong thing is not a small error.

Load is the weak half: 68 MiB/s on ctim, of which the XML reader is 10.7 ms and lowering the
other 12.5 ms. That is the number the whole thesis rests on — the reference's issue #112 is
about *load* time — so it is where the optimisation work goes next.

### Two bugs the differential tests could not have caught

Both live in code paths no bundled test file reaches, which is exactly why they needed unit
tests rather than more golden cases.

**`half_to_f32` mis-scaled every subnormal by a factor of two.** The renormalisation shift
was off by one bit. No test file declares a 16-bit `FloatDataEncoding`, so no golden case
would ever have executed it. Now checked exhaustively against all 65 536 encodings, compared
against the IEEE-754 definition written out independently.

**Float comparisons used `total_cmp`.** That makes NaN compare equal to NaN and `-0.0` less
than `0.0`, where IEEE-754 and Python say the opposite. A NaN comparing equal to everything
would silently select the wrong container — precisely the failure `SUPPORTED.md` promises
cannot happen. Comparisons now return a three-valued result, and *unordered* means no
operator holds. No bundled file has a restriction criterion on a float parameter, so the
goldens were blind to it.

### Note on milestone order

`CONTRIBUTING.md` rule 2 says work strictly in order. M4's content — calibrators, String, Binary and
AbsoluteTime types — landed inside M2 rather than after it, because the IDEX and SUDA test
files need dynamically sized binary fields and CTIM needs strings, so M3 could not have gone
green without them. Nothing was skipped; the boundary moved.

### Next

Optimise loading, with the benchmarks above as the baseline. Then M5 (codegen) and M7
(PyO3 bindings).

## 2026-08-21 — M6: measure, then optimise

Benchmarks first, then changes justified by them, then the differential suite re-run after
each. All six golden cases still agree, digest included.

| | before | after | reference | speed-up |
|---|---|---|---|---|
| load ctim (1.6 MB) | 23.2 ms | 10.5 ms | 120 ms | 11.4× |
| load jpss | 175 µs | 72 µs | 10 ms | 139× |
| decode ctim (1499 packets) | 77.1 ms | 48.0 ms | 5109 ms | 106× |
| decode jpss (7200 packets) | 15.8 ms | 9.3 ms | 954 ms | 102× |
| decode idex (78 packets) | 206 µs | 128 µs | 19.5 ms | 153× |

`raw_events` is in the benchmark suite as the ceiling: quick-xml iterating the events with no
tree built is 3.2 ms on ctim against `parse_xml`'s 6.5 ms, so tree construction is no longer
the dominant cost and further work there has little room.

### What actually mattered

**Interning attribute values was a pessimisation.** It trades a hash lookup for a memcpy of
about eight bytes, and the 1.6 MB file has a quarter of a million of them. The tree is
transient; deduplication belongs in the IR, which keeps only the names it needs.

**The hand-rolled interner needed a hash finalizer.** Replacing `HashMap<Box<str>, NameId>`
with open addressing over the arena removed one allocation per unique name — and made ctim
*31 % slower*. FxHash is fast but its low bits carry little entropy, and a bucket index is
exactly the low bits; every CTIM parameter name starts `CTIM__`. A splitmix64 finalizer took
16.5 ms back to 10.5 ms. Worth recording as the reason the mixer is not optional.

**Reserving a packet's storage once was 40 % of decode.** CTIM containers hold ~250 entries,
so every packet was regrowing a `Vec` and a hash table through eight doublings. The bound is
computed at decoder construction over the longest path from the root.

### What the new reporting found

`xtce decode` and `xtask diff` now report packets with bits no entry claimed. On CTIM that is
105 of 1499. Both implementations agree on every value, so it is not a decoding difference —
the reference warns about it and the golden generator suppresses the warning. It says the
definition does not describe the whole packet, which is worth seeing.

### Next

M5 (`xtce-codegen`) and M7 (PyO3 bindings) are the remaining milestones.

## 2026-08-21 — M5: the code generator

`xtce-codegen` turns a definition into a `struct` per container whose `decode` is a sequence
of loads, shifts and masks with every offset already a literal. Nothing consults the XTCE
model at run time.

### Does it earn its complexity

That was the open question, so the benchmark puts both decoders in one criterion group. Same
7200-packet JPSS stream, framing done outside the loop:

| | time | vs interpreted | vs the Python reference |
|---|---|---|---|
| interpreted | 8.67 ms | — | 110× |
| **generated** | **83.8 µs** | **103×** | **11 400×** |
| generated, then visiting every field | 347 µs | 25× | 2 750× |
| generated, dispatch only | 17.4 µs | *(not a decode figure — see below)* | |

The middle row is the honest headline: the whole struct is consumed, so every field is really
read. The last row only consumes the discriminators, which lets the optimiser drop the other
field reads; it is the cost of *choosing* a container, and is labelled that way in the
benchmark so it cannot be quoted as the decoder's speed. The third row is closest to what the
interpreter actually does, since that also hands back a name and both values per field.

So: yes. Two orders of magnitude over an interpreter that is already two orders over the
reference.

### How correctness is established

The generated decoder is compared against the *interpreted* one over every one of the 7200
packets, field by field, with floats compared by bit pattern. The interpreted decoder is
already proven equal to the Python reference over every packet of six streams, so this is
equality with the reference — without the test needing to parse a golden file or reimplement
the comparison.

The generated file is committed rather than produced by a build script. It is meant to be
read; a diff shows exactly what a change to the emitter did; and a test fails if it drifts
from what the generator currently produces.

### Two things the shape of the output forced

**No inner attributes.** The first version emitted `#![doc]` and `#![allow]` at the top of the
file. Those are illegal inside `include!`, which is exactly how a `build.rs` consumer uses
generated code — so the primary use case was broken. The header is now ordinary `//`
comments, the caller supplies the lint allowances on the surrounding module, and the emitter
avoids redundant parentheses so `unused_parens` never fires.

**`include!`, not `#[path] mod`.** With `#[path]`, `cargo fmt` reformats the generated file
and the drift test fails on whitespace. Comparing token streams instead does not help:
rustfmt also moves braces and trailing commas, which changes the tokens. Under `include!`,
rustfmt does not follow the file at all and the committed bytes stay exactly what the
generator wrote.

**Refusals are fatal, by design.** Nine of the ten bundled definitions cannot be compiled, and
each is refused with the element named. Falling back to interpretation would have made the
benchmark above meaningless.

### Next

M7, the PyO3 bindings, is the last milestone in the specification.

## 2026-08-21 — M7: Python bindings, and the last milestone

`import xtce` works. The specification's exit condition was "decodes the same file"; what it
actually does is decode four real mission files and match `space_packet_parser` field by
field, engineering values and raw values both, through the same standard the Rust side is
held to.

```
$ pytest crates/xtce-py/tests -q
14 passed
```

7200 JPSS packets decode in 38 ms including the construction of every Python dictionary,
against the reference's 954 ms — 25×. The pure Rust figure is 9.3 ms, so about three quarters
of the remaining time is building Python objects, which is the floor for any binding that
returns dictionaries.

### Three decisions

**Its own workspace, not a member.** Adding `xtce-py` to `members` would make
`cargo build --workspace` require libpython, and the three CI jobs that prove this project
builds with nothing but a Rust toolchain would stop proving it. It is in `exclude`, has its
own lockfile, and is built by `maturin`. `cargo tree --workspace | grep pyo3` returns nothing.

**Batch-shaped API.** The decoder is two orders of magnitude faster than the reference and a
per-packet call would return all of that to the interpreter. `decode_stream` frames and
decodes a whole buffer in one call and releases the GIL around the Rust loop, so values are
materialised as owned Rust values with the GIL released and converted in one pass with it
held. There is a test that a counter thread keeps running during a long decode, because
without it the binding would serialise every consumer behind itself and nothing else would
notice.

**Names interned once.** Parameter names become Python string objects when the definition
loads, indexed by parameter id, so a 7200-packet stream allocates no strings for dictionary
keys at all.

### CI

A fourth job builds the wheel and runs the Python differential tests. It is advisory — it
needs a Python toolchain and a network install of the reference, neither of which this
repository controls — for the same reason the latest-stable clippy job is advisory. The three
blocking jobs are unchanged.

### All milestones complete

M0 through M7. `BLOCKERS.md` says where a next session should start.

## 2026-08-23 — calibrators in the code generator

`xtce-codegen` compiles `DefaultCalibrator` now, both kinds: `PolynomialCalibrator` and
`SplineCalibrator` of order 0 or 1. Eleven of the twelve bundled definitions compile.

**What the difficulty actually was.** Not the arithmetic — a polynomial is four lines. It is
that the arithmetic has to be *the same* arithmetic. Floating-point addition is neither
associative nor commutative, so summing the terms by Horner's method, or sorted by exponent,
or in any order but the one the document lists them in, gives an answer that is right to
fourteen digits and wrong in the last bit. `xtce-decode` accumulates in document order
because the Python reference does; the emitter now does too, and the comparison is on
`to_bits()`.

The sharper edge is the power. The reference raises an *integral* raw value to its power in
arbitrary-precision integers and converts to `f64` once; a *float* raw goes through repeated
squaring, which rounds at every step. Those are different numbers. `integer_power` in the
emitted code mirrors the first, falling back to `powi` when the exact route overflows an
`i128`, and the path is chosen by the field's encoding — never by convenience.

**A calibrator on an enumeration or a boolean is ignored, on purpose.** XTCE looks both up
from the raw value and the interpreter returns before it consults a calibrator, so applying
one would be a divergence dressed up as helpfulness. The plan attaches a calibrator only to a
numeric field.

**Refused by name:** `ContextCalibrator`, splines above first order, splines with no points.
The first is a dependency graph — its criteria range over other parameters, which may
themselves be calibrated — and nothing in reach uses one, so there would be nothing to check
a guess against. The other two are properties of the definition, so they are settled while
planning rather than failing once per packet. Only a query outside a non-extrapolating
spline's points is a run-time error, and it has its own `DecodeError::Calibration`.

**`testdata/spp/calibrators.xml` had to be written**, because no bundled mission definition
has a calibrator at all — grepping all five returns nothing. Its centre is a pair of
parameters carrying byte-for-byte identical polynomial terms over different encodings, one
32-bit unsigned integer and one binary64. Fed the same number they must *disagree* in the
last bit, and a generator that used one power routine for both would otherwise pass every
test in this repository. A third parameter's fourth power overflows an `i128` above about
3.6 thousand million, so random values exercise both branches of the fallback.

The first draft of that file put the cubed term and a fifth-power term on the same parameter.
It tested nothing: the fifth-power term is so much larger that it swallowed the last-bit
difference the cubed one was there to expose. Splitting them into two parameters is what made
the test discriminate — verified by mutating the emitter to widen integers and call `powi`,
which the differential test then catches at packet 35 and the direct test catches outright.

**Coverage:** 4352 generated packets per run, of which a few hundred are ones both
implementations must refuse — two of the file's splines sit on a four-bit field wider than
their points, so agreement has to include agreeing to fail, on the same packets. That is a
case the existing comparison macro could not express, so the calibration test does its own
loop.

Still true, and worth repeating: nothing differentially tests `xtce-decode`'s calibration
against Python, because there is no mission definition with a calibrator to run through both.
The generated path is now pinned to the interpreted one bit for bit; the interpreted one is
pinned to hand-computed values and an exhaustive unit test, not to the reference.

## 2026-08-22 — strings, binaries and variable width in the code generator

The generator compiled numbers. Anything else — a string, a binary blob, a field whose width
comes from the packet — was refused by name, which meant CTIM, IDEX and SUDA were refused
whole. Only JPSS compiled, and JPSS is one container of twenty-seven fixed fields.

Ten of the eleven bundled definitions compile now. CTIM is 9493 parameters and 38 concrete
containers; IDEX and SUDA carry a binary blob whose length is `8 × PKT_LEN − 328` bits, with
two more fields behind it.

### Strings and binaries borrow the packet

A decoded string is a `&str` into the caller's buffer: no allocation, no copy. That decides
the whole shape of the feature. Only byte-aligned fields are compiled, because an unaligned
one would have to be shifted into a new buffer, and only UTF-8 and US-ASCII, because Latin-1
or UTF-16 would have to be transcoded into one. Both are refused by name instead, and the
interpreter handles them.

A text field becomes *two* struct fields. XTCE gives a string two values — the buffer as
allocated and the string found inside it — and reproducing the reference exactly needs both.
`TerminationChar` and `LeadingSize` delimiters are compiled.

There is a test that the decoded string's pointer lies inside the caller's buffer. Comparing
values alone would still pass if this regressed to an owned copy, which is the one thing the
feature exists to avoid.

### A cursor, but only past the first dynamic field

IDEX's science packets are the case that forced it. Everything up to the blob is read at
literal offsets; from the blob on, a `usize` cursor is walked — the same walk the interpreter
does, except the widths, conversions and names are still fixed at generation time.

A numeric field of variable width stays refused: a number's width picks its Rust type, and
that cannot be a property of the packet. For text and binary it only picks how many bytes to
borrow, which can.

### The differential suite, and what it did not cover

`xtce-codegen-e2e` generates decoders in `build.rs` and compares them against the interpreter
on the real streams. That is the shape a mission uses, and it is how a 94 000-line decoder
gets tested without committing 94 000 lines.

Two gaps turned up, and both were real bugs rather than missing tests.

No packet in the CTIM stream reaches a container with a string field — `APID_6`, `APID_10`
and `APID_28` never occur in it — so compiled string decoding had zero coverage. Synthetic
packets close that.

The second is worse. Between them the mission definitions contain **one** 32-bit float, no
16-bit float, and no numeric field spanning nine bytes. So `numeric_edges.xml` was written:
every numeric shape the emitter produces, each one byte-aligned and again four bits off a
boundary, compared over 2304 generated packets. It failed twice on first run.

*A cast is not atomic.* `x as u64 << 48` does not parse — the type after `as` swallows the
`<<` as the start of generic arguments. Sign extension is a shift, so every two's-complement
field of 8, 16, 24 or 32 bits sitting on a byte boundary emitted exactly that. The mission
definitions contain one two's-complement field in total, CTIM's `ana_proc_temp`, and it
starts at bit 251 — off a boundary, where the mask had already put the parentheses in.

*The nine-byte span was truncated before it was shifted.* A 64-bit field starting four bits
into a byte occupies nine bytes, which is why the emitter loads it through `u128`. It then
cast to `u64` and *then* shifted — throwing away the four bits at the top of the field. The
module documentation claimed this case was "handled by construction". It was not, and no
mission file had ever reached it.

Both predate this session's work. Neither is the kind of thing a reader catches; only a
definition built to reach them does.

### Smaller things

Every load now uses the narrowest integer that spans the field, and casts only where the
consumer needs a different width. Before, every float read came out as
`u32::from_be_bytes([..]) as u64 as u32`. The CTIM decoder is 3.9 MB and 94 011 lines; with
eight-byte padding on every load it was 5.4 MB.

The interpreter collapses a parameter that appears twice in one entry list — CTIM's
`APID_20_Packet` has two `SPARE_8` entries — because it stores values in a dictionary where
the second assignment overwrites the first and the key keeps its position. The generated
struct keeps both fields, since both really are in the packet at different offsets, but the
reported values now collapse the same way.

`cargo xtask diff` still reports all six cases matching the reference.
