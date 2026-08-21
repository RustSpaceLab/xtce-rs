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
