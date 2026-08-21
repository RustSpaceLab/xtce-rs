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
| `CommandMetaData` | Rejected | subtree dropped during parsing, counted in `skipped_sections()` |
| `ServiceSet`, `MessageSet`, `StreamSet`, `AlgorithmSet` | Rejected | as above |
| `AliasSet`, `AncillaryDataSet` | Rejected | metadata only, never affects decoding |

## Parameter types

| Element | Level | Note |
|---|---|---|
| `IntegerParameterType` | Decodable | `unsigned`, `twosComplement` (incl. the `twosCompliment` typo and informal `signed`), `signMagnitude`, `onesComplement`; 1–64 bits |
| `FloatParameterType` | Decodable | IEEE-754 at 16, 32, 64 bits; MIL-STD-1750A at 32 bits |
| `EnumeratedParameterType` | Decodable | full `EnumerationList` including `maxValue` ranges |
| `BooleanParameterType` | Decodable | value is `bool` from the raw value; `zeroStringValue` / `oneStringValue` available via `XtceDb::boolean_label` |
| `StringParameterType` | Decodable | fixed and variable raw size; `TerminationChar` and `LeadingSize` delimiters |
| `BinaryParameterType` | Decodable | fixed, `DynamicValue` and `DiscreteLookupList` sizing |
| `AbsoluteTimeParameterType` | Decodable | `Encoding` with `offset` / `scale`; `Epoch` and `OffsetFrom` are modelled but not applied |
| `RelativeTimeParameterType` | Represented | no epoch arithmetic |
| `ArrayParameterType` | Represented | `TypeKind::Unsupported` |
| `AggregateParameterType` | Represented | `TypeKind::Unsupported` |

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
| Enumeration `maxValue` ranges | not implemented | honoured |
| Out-of-scope construct | raises at load | represented; raises at decode |
| Spline query equal to the largest raw value | raises (`list.index(True)` finds nothing) | clamps to the final segment, which XTCE's inclusive range implies |
| Container entry lists that reference each other cyclically | recurses until the stack overflows | bounded at 64 levels and reported |

None of the bundled test files exercise a divergence, so the differential tests are
unaffected by them.

## Code generation

`xtce-codegen` compiles a definition into a static Rust decoder. It handles a *narrower*
subset than the interpreter, because a layout can only be compiled when it is fixed at load
time — every field at a known offset and width, with nothing depending on packet content.

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
| `leastSignificantByteFirst` | Refused | |
| Calibrators | Refused | the interpreter sums polynomial terms in document order with exact integer powers; until the emitted arithmetic is proved identical, compiling it risks a silent last-bit divergence |
| `StringDataEncoding`, `BinaryDataEncoding` | Refused | width can depend on packet content |
| `LocationInContainerInBits`, `RepeatEntry` | Refused | |
| `BooleanExpression` criteria | Refused | |
| MIL-STD-1750A floats | Refused | |

Of the ten bundled definitions, `jpss1_geolocation_xtce_v1.xml` compiles completely. The
other nine are refused with the element named — CTIM on its strings, IDEX and SUDA on their
dynamically sized binary fields, `contrived_inheritance_structure.xml` on its
`BooleanExpression`. All nine decode fine through the interpreter.
