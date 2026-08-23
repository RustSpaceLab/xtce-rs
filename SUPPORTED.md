# Supported XTCE subset

XTCE is a large standard. Four previous Rust attempts stalled aiming for full conformance,
so this project implements a deliberate subset and treats that as a design decision rather
than a shortfall — the same call Yamcs made.

Coverage has three levels, and the distinction matters:

* **Decodable** — modelled and produces values.
* **Represented** — parsed and present in the IR, but decoding a value that depends on it
  returns `XtceError::Unsupported { element, path }`. Loading still succeeds, so
  `xtce info` works on any real mission database and reports exactly what it cannot decode.
* **Rejected** — not modelled at all.

Representing rather than rejecting is what lets a file load whose telemetry section is 95 %
in scope. Rejecting on first sight would make most real databases unloadable, which would
make the differential tests impossible to run at all.

## Section coverage

| Section | Level | Note |
|---|---|---|
| `TelemetryMetaData` | Decodable | the whole point |
| `CommandMetaData` | Decodable | telecommands: see below. Was rejected until 2026-08-23 |
| `ServiceSet`, `MessageSet`, `StreamSet`, `AlgorithmSet` | Rejected | as above |
| `AliasSet`, `AncillaryDataSet` | Rejected | metadata only, never affects decoding |

## Telecommands

A `<MetaCommand>` is a container of fields selected by fixed values, which is what a
`<SequenceContainer>` is, so it is lowered into the same machinery rather than beside it.
Nothing downstream — the interpreter, the code generator, the flight emitter — has a special
case for commands.

| Element | Level | Note |
|---|---|---|
| `MetaCommand` | Decodable | `abstract` carried down to its container: no packet is an abstract command |
| `BaseMetaCommand` | Decodable | inheritance, cycle-checked at load |
| `ArgumentList`, `Argument` | Decodable | each becomes a parameter qualified under its command, `/SS/Cmd/ARG`, absent from the unqualified index so it cannot shadow a telemetry parameter |
| `ArgumentAssignment` | Decodable | becomes a restriction criterion on the command's container, with `useCalibratedValue` true — the schema calls `argumentValue` a calibrated value |
| `CommandContainer` | Decodable | a container; qualified under its command, since the schema calls it private and does not require its name to be unique |
| `ArgumentRefEntry`, `ArrayArgumentRefEntry` | Decodable | resolved against the owning command's arguments only: "there is no path, this is a local reference" |
| `ParameterRefEntry` in a command container | Decodable | a command may name parameters as well as arguments |
| `FixedValueEntry` | Decodable | the bits are stepped over and reported as nobody's value; see the divergence table |
| `*ArgumentType` (integer, float, string, binary, boolean, enumerated, time, array, aggregate) | Decodable | the same types under a different name; `ValidRangeSet` is ignored, as ranges are everywhere here |
| `CommandContainerSet` | Decodable | shared containers, registered like telemetry ones |
| `BlockMetaCommand` | Rejected | a sequence of commands, not a packet layout |
| `VerifierSet`, `TransmissionConstraintList`, `Interlock`, `ParameterToSetList` | Rejected | operational behaviour, not packet layout |
| `ArgumentAssignment` on an enumerated argument | Refused when compiled | `argumentValue` is a calibrated value, so it would compare labels; the interpreter does compare them |

## Parameter types

| Element | Level | Note |
|---|---|---|
| `IntegerParameterType` | Decodable | `unsigned`, `twosComplement` (incl. the `twosCompliment` typo and informal `signed`), `signMagnitude`, `onesComplement`; 1–64 bits |
| `FloatParameterType` | Decodable | IEEE-754 at 16, 32, 64 bits; MIL-STD-1750A at 32 bits and no other width, which is what the format is |
| `EnumeratedParameterType` | Decodable | full `EnumerationList` including `maxValue` ranges |
| `BooleanParameterType` | Decodable | value is `bool` from the raw value; `zeroStringValue` / `oneStringValue` available via `XtceDb::boolean_label` |
| `StringParameterType` | Decodable | fixed and variable raw size; `TerminationChar` and `LeadingSize` delimiters |
| `BinaryParameterType` | Decodable | fixed, `DynamicValue` and `DiscreteLookupList` sizing |
| `AbsoluteTimeParameterType` | Decodable | `Encoding` with `offset` / `scale`; `Epoch` and `OffsetFrom` are modelled but not applied |
| `RelativeTimeParameterType` | Represented | no epoch arithmetic |
| `ArrayParameterType` | Decodable | expanded when the file loads into one parameter per element, named `ARR[0]`, `ARR[1][2]`; row-major, inclusive indices, up to 4096 elements per entry |
| `AggregateParameterType` | Decodable | expanded when the file loads into one parameter per member, named `P.voltage`; members packed in document order, nests with arrays either way |

## Data encodings

| Element | Level | Note |
|---|---|---|
| `IntegerDataEncoding` | Decodable | `byteOrder` both ways |
| `FloatDataEncoding` | Decodable | `byteOrder` both ways |
| `StringDataEncoding` | Decodable | UTF-8, US-ASCII, ISO-8859-1, Windows-1252, UTF-16, UTF-32 |
| `BinaryDataEncoding` | Decodable | |
| `SizeInBits/DynamicValue` + `LinearAdjustment` | Decodable | required by the IDEX and SUDA test files |
| `SizeInBits/DiscreteLookupList` | Decodable | |
| `ErrorDetectCorrect` | Rejected | ignored if present |

## Containers

| Element | Level | Note |
|---|---|---|
| `SequenceContainer`, `EntryList` | Decodable | |
| `ParameterRefEntry` | Decodable | |
| `ContainerRefEntry` | Decodable | expanded inline |
| `BaseContainer` + `RestrictionCriteria` | Decodable | |
| `Comparison`, `ComparisonList` | Decodable | all six operators, in every accepted spelling |
| `BooleanExpression` (`Condition`, `ANDedConditions`, `ORedConditions`) | Decodable | required by `contrived_inheritance_structure.xml` |
| `LocationInContainerInBits` | Decodable | `previousEntry` and `containerStart` |
| `LocationInContainerInBits` with `containerEnd` / `nextEntry` | Represented | needs a container size that is only known once decoding finishes; reported at decode time |
| `RepeatEntry` with a fixed `Count` | Decodable | |
| `RepeatEntry` with `DynamicValue` | Represented | entry decodes once, then reports unsupported |
| `IndirectParameterRefEntry` | Represented | `EntryKind::Unsupported` |
| `ArrayParameterRefEntry` | Represented | `EntryKind::Unsupported` |
| `CustomAlgorithm` in `RestrictionCriteria` | Represented | `MatchCriteria::Unsupported`; never silently matches |

## Calibration

| Element | Level | Note |
|---|---|---|
| `PolynomialCalibrator` | Decodable | terms accumulated in document order, to match the reference bit for bit |
| `SplineCalibrator` | Decodable | orders 0 and 1, with and without extrapolation |
| `ContextCalibrator` | Decodable | criteria evaluated in document order, first match wins |
| `MathOperationCalibrator` | Represented | `Calibrator::Unsupported` |

## Deliberate divergences from the reference implementation

These are places where `space_packet_parser` and this crate differ on purpose. Each is
covered by a test.

| Topic | Reference | Here |
|---|---|---|
| `LocationInContainerInBits` | ignored | honoured |
| `RepeatEntry` | ignored | fixed counts honoured |
| `signMagnitude` / `onesComplement` | rejected | decoded |
| `ArrayParameterType`, `AggregateParameterType` | raise `NotImplementedError` at load — on its roadmap | expanded into one parameter per leaf |
| `CommandMetaData` | no command support of any kind — the string does not appear in its source, and a definition carrying one loads with the command half silently ignored | telecommands are decoded, and compiled |
| `FixedValueEntry` | — | the bits are stepped over, not checked: XTCE selects a container by its restriction criteria and has no rule that makes a fixed value discriminate |
| Enumeration `maxValue` ranges | not implemented | honoured |
| Out-of-scope construct | raises at load | represented; raises at decode |
| Comparing a text value against a number (`Condition` with two parameter operands) | `==` false, `!=` true, ordering raises `TypeError` | the same three outcomes, the ordering case as `DecodeError::IncomparableValue` |
| Spline query equal to the largest raw value | raises (`list.index(True)` finds nothing) | clamps to the final segment, which XTCE's inclusive range implies |
| Container entry lists that reference each other cyclically | recurses until the stack overflows | bounded at 64 levels and reported |
| A binary16 NaN's payload | discarded — CPython's `struct` returns a canonical NaN for `"e"` while preserving the payload for `"f"` and `"d"` | preserved, as for binary32 and binary64 |

None of the bundled test files exercise a divergence, so the differential tests are
unaffected by them. That is not an accident for the last row:
`tools/gen_byte_order_stream.py` turns a binary16 NaN into an infinity when it generates one,
and says why. It is the only place a stream is shaped around a divergence rather than
happening to miss it.

## Code generation

`xtce-codegen` compiles a definition into a static Rust decoder. It handles a *narrower*
subset than the interpreter: a field is compiled when what to do with its bits is decided at
generation time. Most fields also sit at a fixed offset, and those are read with a literal
index, a literal shift and a literal mask. A text or binary field may take its width from an
earlier field instead; from there the decoder walks a cursor, exactly as the interpreter
does, but with the widths, conversions and names still fixed.

A construct outside that subset is **refused by name**, never handed back to the interpreter.
A silent fallback would hide from the caller that half their database is still interpreted,
and would make a generated-versus-interpreted benchmark meaningless.

| Construct | Compiled | Note |
|---|---|---|
| `IntegerDataEncoding`, big-endian, 1–64 bits | Yes | all four signed codings |
| `FloatDataEncoding`, IEEE-754 16/32/64, big-endian | Yes | |
| `EnumeratedParameterType`, `BooleanParameterType` | Yes | label lookup emitted as a `match` |
| `BaseContainer` + `Comparison` / `ComparisonList` | Yes | inheritance chain flattened into one struct |
| `ContainerRefEntry` | Yes | expanded inline |
| `leastSignificantByteFirst` | Yes | a reversed load where the field starts on a byte and fills whole ones; the reference's own reversal of the *value* where it does not |
| A little-endian signed field of 57 to 63 bits | Refused | the reversal can widen it past what an `i64` holds, where the reference's integers do not run out |
| `DefaultCalibrator` / `PolynomialCalibrator` | Yes | terms summed in document order; an integral raw value is raised to its power exactly in `i128` and converted once, a float raw by `powi` — the same two paths the interpreter takes |
| `DefaultCalibrator` / `SplineCalibrator` | Yes | orders 0 and 1; out of range without extrapolation is `DecodeError::Calibration` |
| A criterion asking for the calibrated value of a calibrated parameter | Refused | the interpreter compares a float there, and the dispatcher runs before anything is decoded |
| A criterion asking for the calibrated value of a boolean | Refused | its engineering value is 0 or 1, not its raw bits |
| A calibrator on an enumeration or a boolean | Ignored | XTCE looks both up from the *raw* value; the reference returns before it reaches a calibrator, so applying one would be wrong |
| `ContextCalibrator` | Yes | tried in order, first match wins; a criterion naming a parameter not yet decoded resolves to the value being calibrated, as the reference does |
| A `ContextCalibratorList` with no `DefaultCalibrator` | Refused | nothing applies when no context matches and the reference then reports the *raw* value, so the engineering value's type would depend on the packet |
| `useCalibratedValue` on a criterion naming the field being calibrated | Refused | the value has not been calibrated — that is what is being decided — and the reference quietly compares the raw one instead |
| A `ContextCalibrator` selected by a `BooleanExpression` | Refused | only a `Comparison` or `ComparisonList` is compiled there |
| A spline above first order, or with no points | Refused | settled while planning, not once per packet |
| `powi` | Written out | it lives in `std`, and generated code names nothing outside `core`; the emitted sequence is bit-identical |
| `MathOperationCalibrator`, `CustomAlgorithm` | Refused | |
| `StringDataEncoding`, fixed size, byte-aligned | Yes | UTF-8 and US-ASCII; `TerminationChar` and `LeadingSize` delimiters; the string borrows the packet |
| `BinaryDataEncoding`, fixed size, byte-aligned | Yes | borrows the packet |
| Text or binary not on a byte boundary | Refused | borrowing is impossible, and copying would put an allocation on the hot path |
| Text in a charset needing transcoding | Refused | Latin-1, Windows-1252, UTF-16, UTF-32 cannot borrow |
| Text or binary whose width comes from another field | Yes | `DynamicValue` with a `LinearAdjustment`; the fields after it are walked with a cursor |
| A *numeric* field of variable width | Refused | a number's width picks its Rust type, which cannot vary per packet |
| A dynamic width landing off a byte boundary | Refused at run time | `DecodeError::Unaligned`, since only the packet says where it lands |
| `ArrayParameterType`, `ArrayParameterRefEntry`, `AggregateParameterType` | Yes | the entry is already one field per leaf by the time the generator sees it |
| An array dimension read from the packet | Refused | the expansion happens when the file loads, before any packet exists |
| A type that contains itself | Refused | XTCE forbids it, and following it would not terminate |
| More than 4096 leaves in one entry | Refused | each becomes a parameter and a struct field |
| `MetaCommand`, `CommandContainer`, `ArgumentRefEntry` | Yes | a telecommand is a container by the time the generator sees it |
| `ArgumentAssignment` | Yes | compiled as the restriction criterion it is |
| An `ArgumentAssignment` on an enumerated argument | Refused | `argumentValue` is a calibrated value, so it compares labels, which the dispatcher does not |
| `FixedValueEntry` | Yes | the decoder steps over the bits; `ContainerPlan::fixed` carries them for an encoder, reduced to the declared width — a wider `binaryValue` truncates from the left, a narrower one zero-extends |
| A `FixedValueEntry` after a data-dependent width | Refused | where its bits go is not known at generation time |
| `LocationInContainerInBits`, `RepeatEntry` | Refused | |
| `BooleanExpression`: `Condition`, `ANDedConditions`, `ORedConditions` | Yes | nested, against a literal; two inheritors that both match are still `Ambiguous` |
| A `Condition` between two parameters | Refused | five type-pair cases and a Python-compatibility answer for text against a number; nothing in reach uses one |
| A `Condition` with a literal on the left | Refused | the interpreter compares it as text there |
| MIL-STD-1750A floats, 32 bits | Yes | a 24-bit two's-complement mantissa and an 8-bit two's-complement exponent, neither biased; `mantissa * 2 ** (exponent - 23)` |
| MIL-STD-1750A at any other width | Refused | the format has no other width, and the reference refuses to load one |

Every one of the eighteen bundled definitions compiles, including CTIM — 9493 parameters
and 38 concrete containers — and IDEX and SUDA, whose science packets carry a binary blob
whose length comes from `PKT_LEN`. Each is checked against the interpreter on its real packet
stream by `xtce-codegen-e2e`, and the interpreter is checked against `space_packet_parser`,
so a generated decoder is held to the reference at one remove.

Two definitions are the exception to "real samples only", both for the same reason: a path
the emitter can produce that no mission file reaches.

`numeric_edges.xml` exists because the mission files between them contain one 32-bit float,
no 16-bit float, and no numeric field spanning nine bytes. It declares every numeric shape
the emitter can produce, aligned and four bits off a byte boundary, and is compared over
2304 generated packets.

`calibrators.xml` exists because **no bundled mission definition has a calibrator at all** —
so before it, neither the interpreted nor the generated calibration path had ever been
compared against anything. It is built around the one difference that is easy to get wrong
and hard to see: two parameters carry identical polynomial terms over different encodings,
one integer and one binary64, and for about a quarter of 32-bit values the two must come out
differing in the last bit. A generator that used one power routine for both would pass every
other test in this repository. It is compared over 4352 generated packets, of which a few
hundred are ones both implementations must *refuse* — a spline that may not extrapolate,
asked for a point outside itself.

`arrays.xml` and `aggregates.xml` are the fifth and sixth, and cover the only two features in
this project with no Python rung at all: the reference refuses both outright. What stands in for it is that the semantics were not
invented — XTCE 1.2 states the index convention and the row-major order in as many words, and
`crates/xtce-model/tests/arrays.rs` quotes both and pins the expansion against them. Its
two-dimensional array is two by three rather than square on purpose, and `aggregates.xml`
gives its members different widths for the same reason: over a square array, or a member list
of equal-width members, a transposed or reordered expansion produces the same fields over the
same bits. The differential test cannot see either, because both implementations read the same
expansion — so the names are checked against the XTCE text separately, and both checks were
confirmed by mutating the expansion until they failed.

`context_calibrators.xml` is the eighth, and the third with a packet stream and a golden. It
is also the only stream here whose bytes are *shaped* rather than arbitrary, and the reason is
worth stating: a context is chosen by a comparison, and a comparison against a uniformly
random field almost never holds. `MODE == 1` over a random byte is one packet in 256, so five
hundred packets would take each branch twice and the default four hundred and ninety times.
The fields the criteria test are drawn from small ranges so that every branch is taken tens of
times, and the test asserts they still are. Everything not named in a criterion stays
arbitrary.

`mil_1750a.xml` is the seventh, and the second with a packet stream and a golden of its own —
the reference implements MIL-STD-1750A, so unlike arrays and aggregates this one can be pinned
to Python. It matched on the first run, which after four features that did not is worth
recording as much as a failure would have been. Nothing in its stream needs fixing up either:
every one of the 2³² words denotes a finite number, because the format has no infinities and
no NaN.

`byte_order.xml` is the fourth, and the first with a packet stream of its own. No mission
definition in reach sets `byteOrder` at all, so there is no recorded telemetry with a
little-endian field in it and nothing to put in front of the reference. Its stream is
generated by `tools/gen_byte_order_stream.py` from a fixed seed and *is* a golden case, which
makes little-endian the one feature whose interpreted path is pinned to `space_packet_parser`
directly rather than to hand-computed values.

Doing that found two divergences in the interpreter on the day it was added. The first is
fixed: after reversing the bytes of a field that is not a whole number of bytes, the
reference sign-extends *without* masking the bits the reversal pushed above the width, and
this crate masked — so a twelve-bit little-endian field read −1782 here and 43274 there. The
second is on the record above: binary16 NaN payloads.

`boolean_criteria.xml` is the third written-for-this-project file. The one bundled mission
definition with a `<BooleanExpression>`, `contrived_inheritance_structure.xml`, contains a
single conjunction of two equalities — the same thing a `<ComparisonList>` already expressed.
What is actually new about the element is that it *nests* and that it can be a disjunction,
and both change which container a packet selects. So the file has an `<ORedConditions>`, an
OR inside an AND, the `>` and `!=` operators that no mission file uses, a criterion past the
first byte, and two inheritors whose branches overlap — because an OR makes an accidental
ambiguity much easier to write, and the dispatcher has to keep reporting one rather than
picking the first match.

## Python bindings

`xtce-py` exposes the interpreted decoder, so its coverage is exactly the "Decodable" column
above — not the narrower code-generation subset. A construct that is represented but not
decodable raises `ValueError` naming the element, and `Definition.unsupported()` lists them
before you decode anything.
