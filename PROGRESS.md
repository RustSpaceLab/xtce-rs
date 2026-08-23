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

## 2026-08-23 — MIL-STD-1750A, and it matched first time

The generator compiles MIL-STD-1750A. Seventeen of seventeen bundled definitions compile.

**It is not a float format in the IEEE sense and shares none of its arithmetic.** A 24-bit
two's-complement mantissa in the top of the word and an 8-bit two's-complement exponent in the
bottom, neither biased, no implicit leading one, no infinities and no NaN. The value is
`mantissa * 2 ** (exponent - 23)`. The interpreter already had it, tested against the
standard's own table of reference values; the generator emits the same arithmetic and reuses
the `powi` helper written for calibrators.

**The reference implements it**, which arrays and aggregates cannot say — so `mil_1750a.xml`
comes with a packet stream and a golden, and this is the second feature whose interpreted path
is pinned to `space_packet_parser` directly. It matched on the first run, big-endian,
little-endian, four bits off a byte boundary and calibrated. After four features where reading
the reference or running it turned something up, one that simply agreed is worth recording too.

Nothing in that stream needs fixing up, unlike `byte_order_stream.bin`, which has to turn its
binary16 NaNs into infinities. Every one of the 2³² MIL words denotes a finite number, so
there is nothing whose *kind* the two implementations could disagree about.

**One thing nearly went wrong quietly.** `calibration_for` decides whether a field is numeric
enough to carry a calibrator, from a list of `Repr` variants. Adding `Repr::Mil1750a` without
adding it to that list would have dropped a calibrator on a MIL field silently — the
interpreter reaches calibration for any numeric type, and a MIL raw value arrives as a float
like any other. `mil_1750a.xml` has a calibrated MIL field for exactly that reason.

**And one thing that is wrong, found on the way and not fixed.** Reading the reference's
polynomial calibrator to check the MIL case showed it computes `x ** n`, which for a float
base is a libm `pow` call, where `xtce-decode` uses `powi` — square and multiply. Measured
over 200 000 random values: identical for exponents 0 and 1, 84 disagreements at exponent 2,
and 16 561 — about 8% — at exponent 3. `calibrators.xml` has exactly that shape and is
compared only against the interpreter, so nothing is presently wrong; the gap is that the
float polynomial has never been held to the reference and would not survive it. Recorded in
`BLOCKERS.md` rather than fixed, because `pow` is not required to be correctly rounded and the
reference's own answer can differ between platforms — a golden over it would depend on the
machine that made it, and `powi` at least gives the same answer everywhere.

## 2026-08-23 — a MIL-STD-1750A float of the wrong width

`mil_std_1750a` takes `bits as u32`. For a field declared 32 bits wide, which is what the
format is, that is exactly right. For any other width it silently truncates, and the value it
returns is one nothing else would produce.

The reference does not have this problem because it refuses the definition outright:
`FloatDataEncoding` raises when `encoding == "MILSTD_1750A"` and `size_in_bits != 32`, at
load. Here the file loads and the parameter decodes — to the low 32 bits of whatever it was.

Refused at decode now, with the width named. Not at load, deliberately: this project's
invariant is that loading always succeeds and only decoding reports what it cannot do, which
is what `TypeKind::Unsupported` is built on, and matching Python's *timing* here would break
it for nothing. The consequence is worth stating plainly — a definition with a 48-bit
MIL-STD-1750A field does not open in Python at all and does open here, and then refuses that
one parameter.

Pre-existing, not introduced by any of this week's work. Found while reading the reference's
implementation before compiling the format, which is the second time reading it has turned up
something; the first was the sub-byte little-endian sign extension.

## 2026-08-23 — aggregates, and the expansion generalised

`AggregateParameterType` decodes. Sixteen of sixteen bundled definitions compile, and there
is nothing left in `testdata/spp` that `xtce-codegen` refuses.

**It is the same expansion arrays got, and that is the whole design.** An array and an
aggregate are both containers of other things, both laid out packed and in order, so both
flatten the same way: an entry naming one becomes one entry per leaf, each pointing at a
synthetic parameter carrying the leaf's own type and a name that spells the path to it. What
changed in `lower.rs` is that the walk is recursive now — `expand_array` became
`expand_composite` plus a `collect_leaves` that descends through either. An array repeats one
type under `[i]`, an aggregate lists named members under `.name`, and either may hold the
other:

    RAIL.voltage        an aggregate
    RAILS[0].voltage    an array of aggregates
    STATE.samples[2]    an aggregate holding an array

Nothing below `xtce-model` changed at all. Not the interpreter, not the emitter, not the
flight encoder.

**The naming is XTCE's, quoted rather than chosen.** `AggregateDataType`: "analogous to a
C-struct … The data members are ordered and contiguous in the MemberList element (packed).
Each member may be addressed by the dot syntax similar to C such as `P.voltage`."
`MemberListType` adds that when the aggregate is referenced from a container the members "are
assumed to be added sequentially (in the order listed here)", which is exactly this case.

**Cycles are refused rather than followed.** `MemberType` says "Circular references are not
allowed", but a file can still contain one and following it would not terminate. The walk
carries the composite types on its current path and refuses to enter one twice.

**The ceiling counts leaves now, not one array's elements.** An aggregate of arrays of
aggregates reaches large numbers without any single dimension looking unreasonable: three
thousand two-member pairs is six thousand fields from a dimension well under the old limit.
The refusal names the ceiling and the entry but not the total, deliberately — counting first
would mean a second traversal that has to agree with the one that builds the names, and the
two drifting apart is a worse failure than a message that says "more than this".

**The same evidence gap as arrays, and the same answer.** The reference refuses aggregates
too. So the fixture gives its members *different widths from each other*, for the same reason
`arrays.xml`'s two-dimensional array is two by three and not square: over equal-width members
a reordered expansion produces the same fields over the same bits. Confirmed by reversing the
member list — the tests that check names fail, and `aggregates_match_the_interpreter` still
passes, because both implementations read the same expansion. `STATE` also ends on a four-bit
member, so nothing after it is byte-aligned until the pad; an expansion that rounded a member
up to a byte would show up there and nowhere else.

## 2026-08-23 — arrays, expanded before anything sees them

`ArrayParameterType` decodes. Fifteen of fifteen bundled definitions compile.

**An array is a repetition, so it becomes a repetition of entries.** When the file loads, an
entry naming an array is replaced by one entry per element, each pointing at a synthetic
parameter of the element type named `TEMPS[3]` or `GRID[1][2]`. Nothing downstream knows
arrays exist: the interpreter walks ordinary entries, the generator emits ordinary fields, the
flight encoder writes ordinary struct members. The whole feature is one function in `lower.rs`
and a `TypeKind` variant, and it needed no change at all in three of the four crates.

The synthetic parameters go in the arena but **not** in the name-resolution index. That index
is what `<Comparison parameterRef=…>`, `DynamicValue` and context calibrators search, and a
synthetic `ARR[0]` sitting in it could shadow a real parameter of that name with nothing
saying so. A test names that: the elements are present in the arena and a definition that
tries to reference one does not load.

**This is the first feature here with no Python rung.** `space_packet_parser` raises
`NotImplementedError` for an `<ArrayParameterType>` and says supporting it is on its roadmap
— its own test asserts the raise. So there is no reference answer, and `SUPPORTED.md` records
the difference next to `signMagnitude`, which it also rejects and this crate decodes.

What stands in for the missing rung is that the semantics were not invented. XTCE 1.2 states
both of the things that could have been guessed wrong, and `crates/xtce-model/tests/arrays.rs`
quotes them:

* `DimensionType` — "the starting and ending index for each dimension … Indexes are zero
  based", both ends inclusive.
* `DimensionListType` — "the last dimension is assumed to be the least significant … this
  dimension will cycle through its combination before the next to last dimension changes",
  which is row-major.

**The two-dimensional fixture is two by three, not square.** That is the whole point of it.
Over a square array a transposed expansion produces the same number of fields covering the
same bits, so it passes everything. Confirmed by mutating the expansion to advance the first
axis first: the two tests that check *names* fail, and `arrays_match_the_interpreter` still
passes — because both implementations read the same expansion, so a differential test cannot
see a shared misreading. That is worth knowing about the shape of the evidence here, not just
about arrays.

**Refused by name:** a dimension whose index comes from the packet (the expansion happens
before any packet exists), a subset outside the dimensions the type declares, and more than
4096 elements in one entry — each element is a parameter and a struct field, and the refusal
says how many were asked for. A subset keeps the array's own indices: three elements of a ten
element array are `WINDOW[3]`, `WINDOW[4]`, `WINDOW[5]`, because renumbering from zero would
make them impossible to line up with the same array read whole.

## 2026-08-23 — little-endian, and the first feature pinned to Python directly

`leastSignificantByteFirst` compiles. Fourteen of fourteen bundled definitions now do.

**What the element means is narrower than it sounds.** Not "read the field little-endian":
the reference reads it big-endian and *then* reverses `ceil(width / 8)` bytes of the value —

    val = int.from_bytes(val.to_bytes((size_in_bits + 7) // 8, "little"), "big")

Where a field starts on a byte and fills whole ones the two descriptions coincide, and the
generator emits a reversed load. Where they do not, the reversal has to happen after the
read, on the value, and the generated code calls the same helper the interpreter does. For a
twelve-bit field it produces a number *wider than the field it came from*: `0x0AB` comes back
as `0xAB00`.

**The interpreter already implemented all of this**, tested against hand-computed values. It
had never been run against the reference, because no mission definition in reach sets
`byteOrder` at all — so `byte_order.xml` came with something none of the other purpose-built
files have: a packet stream, and a golden. That makes little-endian the only feature here
whose *interpreted* path is checked against `space_packet_parser` directly rather than
through hand-computed values, and the ladder runs the whole way for the first time:
generated ⟷ interpreted ⟷ Python, on the same bytes.

It was worth doing. The first run found two divergences.

**One is a bug, now fixed.** After reversing the bytes of a field that is not a whole number
of bytes, the reference sign-extends *without* masking the bits the reversal pushed above the
width. `twos_complement` here masks — it sign-extends by shifting, which is branchless and
right everywhere the value fits its field. It does not fit here. A twelve-bit little-endian
two's-complement field read −1782 in this crate and 43274 in the reference. There is now a
separate `twos_complement_unmasked` for the one case that needs it, with the masking form
left alone everywhere else; a property test pins that the two agree for every value that fits
its width, and that the unmasked one follows the reference where they do not.

That fix has a limit worth naming: between 57 and 63 bits, not a whole number of bytes, the
reversal can produce a number wider than an `i64`, which the reference's arbitrary-precision
integers hold and nothing here can. The interpreter reports it; the generator refuses it.

**The other is on the record as a divergence.** CPython's `struct` discards a binary16 NaN's
payload — `unpack("<e")` returns a canonical NaN — while keeping a binary32 or binary64 one.
That is an artefact of its hand-rolled half unpacking, not a decision, and this crate keeps
all three payloads. `SUPPORTED.md` says so, and `tools/gen_byte_order_stream.py` turns a
binary16 NaN into an infinity when it generates one rather than leaving a documented
difference to fail a golden. It is the only place a stream is shaped around a divergence
instead of happening to miss it, and it says why in the code.

**`gen_goldens.py --only` used to clobber the timings.** Regenerating one case rewrote
`reference_timings.json` with just that case, dropping the baseline for every other — which
is what `cargo bench` reports against and cannot be recovered without rerunning everything on
the same machine. It merges now. The file had already been reduced to a single case by an
earlier run; it is rebuilt from the per-case goldens, which carry the same numbers.

Before adding the case, the installed reference was checked against an existing golden: SUDA
reproduces byte for byte — digest, counts and all 64 detail packets — so the new case was
generated by the same thing that generated the old ones.

## 2026-08-23 — the generated code is checked for `core`, not just claimed to be

Two smaller things, both about a claim that was not a check.

**`crates/xtce-codegen-e2e` is a `#![no_std]` library now.** The generated decoders used to
be `include!`d separately by each test; they live in the crate's library instead, which the
tests import. Same compilation, same cost — but the library carries `#![no_std]`, so a
generated decoder that names anything outside `core` is a build failure rather than a
surprise in somebody else's cross-compile.

That gap was not hypothetical. A day earlier the calibration emitter reached `main` calling
`f64::powi`, which is a `std` method: every test passed and the output would not have built
for a Cortex-M. It was caught by the bare-metal probe in a *different repository*. Verified
non-vacuous the same way as the panic gate — putting `.powi` back makes
`cargo test -p xtce-codegen-e2e` fail to compile, naming the generated file and line.

This closes half of the claim. The other half is that the code also *cross-compiles*, which
needs a target this repository's CI does not build for, and still rests on `xtce-flight`'s
probe.

**A digest mismatch says what to do about it.** The golden files hold full detail for the
first 64 packets and one SHA-256 over all of them, so a mismatch past the window told you
only that something differed. The report now distinguishes the two cases it can be: if the
window covers the whole stream, every value agreed and the difference is in *which*
parameters are present or their order, because the digest covers that too; otherwise it
prints the `gen_goldens.py --detail` invocation that would widen the window, with the case
and packet count filled in.

That is as far as it goes without regenerating the goldens, which needs the pinned reference
from git rather than PyPI and changes what the project is measured against. `BLOCKERS.md`
records why that is a decision rather than a task.

## 2026-08-23 — BooleanExpression, and every bundled definition compiles

`contrived_inheritance_structure.xml` was the last one `xtce-codegen` refused. It compiles
now, and so does everything else in `testdata/spp` — thirteen for thirteen.

**The plan grew a tree.** Restriction criteria were a `Vec<Guard>`, which is exactly right
for a `<Comparison>` or a `<ComparisonList>`: both are conjunctions, and a list is a
conjunction. A `<BooleanExpression>` is not. `<ORedConditions>` nests inside
`<ANDedConditions>` and the other way round, and flattening that into a list would change
which container a packet selects. So `Node.children` now carries a `Criterion` —
`Test`/`All`/`Any` — and the emitter walks it into a boolean expression, parenthesising a
composite child so that `&&` binding tighter than `||` never decides anything.

Empty nodes keep the interpreter's answers, which are Python's: `all([])` is true and
`any([])` is false. The tree is simplified before it reaches the emitter — a conjunction of
one is its own contents, and an `All` inside an `All` flattens — because the XML shape forces
wrappers that would otherwise show up as parentheses a reader has to look through.

**A `<Condition>` is a `<Comparison>` in different XML**, and the interpreter evaluates both
through the same `test_literal`, so they compile to the same guard through the same function.
Two shapes it admits that a `<Comparison>` cannot are refused by name: a condition between
two *parameters* (`test_scalars` has five type-pair arms and a Python-compatibility answer
for text against a number, and nothing in reach uses one), and a literal on the *left*, which
the model allows because it takes operands in document order and which the interpreter then
compares as text.

**`testdata/spp/boolean_criteria.xml` had to be written.** The mission file that has a
`<BooleanExpression>` contains one conjunction of two equalities — the shape a
`<ComparisonList>` already expressed — so compiling it proves nothing about the element. The
new file has a disjunction, an OR inside an AND, `>` and `!=` (every criterion in every
bundled mission file is an equality), and a criterion on a field past the first byte.

Two of its inheritors overlap deliberately. An OR is what makes an accidental ambiguity easy
to write, and the dispatcher must keep reporting one rather than picking the first match. The
test asserts exact counts over 400 packets — 83 decoded, 25 ambiguous, 292 matching nothing —
rather than lower bounds, because *which* packets each expression selects is the whole point.

The `unsupported_constructs_are_named_not_ignored` test had one entry and now has none, so it
is inverted: `every_bundled_definition_compiles` walks `testdata/spp` and fails if any of the
thirteen stops compiling.

## 2026-08-23 — a criterion that would have picked the wrong container

Compiling calibrators opened a hole one commit earlier, and this closes it.

`useCalibratedValue` defaults to **true** in XTCE, so most restriction criteria in a real
definition ask for the engineering value. Before calibrators compiled, a criterion could not
name a calibrated parameter — the whole field was refused — so "engineering value" and "raw
value" were always the same number and the dispatcher could compare raw bits. The moment
calibrated fields started compiling, that stopped being true, and nothing said so: the
generated dispatcher compared the raw bits while the interpreter compared the calibrated
float. A definition with `2 * x` on its discriminator would have had the two implementations
select *different containers* for the same packet, in silence.

Confirmed before fixing, on a six-line definition: the emitted dispatcher tested
`head[0] == 4` where the interpreter tests `2.0 * raw == 4.0`, so the two disagreed for every
packet with a discriminator of 2 or 4.

Refused by name now, along with one that was already latent: a criterion asking for the
calibrated value of a **boolean**, whose engineering value is 0 or 1 rather than its raw
bits. Eight bits of boolean holding 4 reads as `true`, which is 1, and comparing 4 would have
been wrong the same way. Nothing in the bundled definitions reaches either — all eleven that
compiled before still compile — but a mission file easily could.

Both are refused rather than compiled. Comparing floats in a dispatcher that runs before any
field is decoded means NaN ordering and literal coercion in the one place where being wrong
selects the wrong parser for the whole packet, and no definition in reach asks for it.

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

**`powi` is in `std`.** The emitted file names nothing outside `core`, deliberately, so that
it can be included in a bare-metal build — and the first version of the calibration emitter
quietly broke that by calling `f64::powi`. Every test passed; the code would not have built
for a Cortex-M. It is written out now, as the same square-and-multiply sequence `powi`
performs, checked bit-identical over four million comparisons and pinned by the differential
test, which compares against an interpreter that calls the real thing.

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
