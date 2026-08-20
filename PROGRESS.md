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

### Numbers (release, M1 Mac)

| Case | Load | Reference load | Decode | Reference decode |
|---|---|---|---|---|
| ctim (1.6 MB, 1499 packets) | 23 ms | 120 ms | 1087 ms | 5109 ms |
| jpss (7200 packets) | 0.2 ms | 10 ms | 112 ms | 954 ms |

Decode timings include the harness's own per-packet work (name lookup, `BTreeMap`, SHA-256),
so they understate the decoder. M6 will measure it properly with criterion.

### Next

M6 benchmarks before M4/M5, so that "make it faster" has numbers behind it rather than
guesses.
