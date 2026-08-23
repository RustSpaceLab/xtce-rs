# Blockers

Nothing outstanding. Every milestone in `xtce-rs-spec.md` (M0 through M7) is done and
verified; see `PROGRESS.md` for what each one produced and what it measured.

## Where a next session should start

1. **`BooleanExpression` restriction criteria in `xtce-codegen`.** Eleven of the twelve
   bundled definitions compile now — strings, binaries, data-dependent widths and calibrators
   have all landed; see `PROGRESS.md`. `contrived_inheritance_structure.xml` is the twelfth,
   and `BooleanExpression` is the only thing stopping it.

   Worth knowing before starting: every emitter path added so far needed a definition written
   to reach it. `numeric_edges.xml` caught two real bugs; `calibrators.xml` exists because no
   mission file has a calibrator at all. Assume the same here.

2. **Give the differential harness a `--full` mode.** The golden files hold full detail for
   the first 64 packets of each stream and a digest over all of them. A digest mismatch
   currently tells you *that* something differs past packet 64, not *which* packet. A mode
   that regenerates full detail on demand would close that.

3. **Talk to `greglucas/space-data-toolkit`.** Section 7 of the specification suggests it,
   and the benchmark it asked for now exists.

## Things deliberately left undone

* **`CommandMetaData`.** Out of scope by design, dropped during parsing, counted in
  `skipped_sections()`.
* **`ContextCalibrator` in `xtce-codegen`.** The interpreter evaluates one; the generator
  refuses it by name. Its criteria range over other parameters, which may themselves be
  calibrated and may sit later in the container, so compiling it means resolving a dependency
  graph. No definition in reach uses one, so there is nothing to validate a guess against.
* **Little-endian bit fields, `ArrayParameterType`, `AggregateParameterType`.** Represented
  in the IR and reported by `xtce info`, refused at decode with the element named.
* **Publishing to crates.io.** `CONTRIBUTING.md` rule 7 forbids it without being asked. The names
  `xtce`, `xtce-model` and `xtce-decode` were free on crates.io as of writing.

Format for real entries: what, why it blocks, what was tried.
