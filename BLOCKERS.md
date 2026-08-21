# Blockers

Nothing outstanding. Every milestone in `xtce-rs-spec.md` (M0 through M7) is done and
verified; see `PROGRESS.md` for what each one produced and what it measured.

## Where a next session should start

1. **Widen `xtce-codegen`.** It compiles one of the ten bundled definitions. Strings and
   fixed-size binary fields are the next tranche and are mechanical — the layout is still
   static. Calibrators are the one to be careful with: the interpreter sums polynomial terms
   in document order with exact integer powers, and the emitted arithmetic has to be proved
   identical before it can ship, or it becomes a silent last-bit divergence.

2. **Give the differential harness a `--full` mode.** The golden files hold full detail for
   the first 64 packets of each stream and a digest over all of them. A digest mismatch
   currently tells you *that* something differs past packet 64, not *which* packet. A mode
   that regenerates full detail on demand would close that.

3. **Talk to `greglucas/space-data-toolkit`.** Section 7 of the specification suggests it,
   and the benchmark it asked for now exists.

## Things deliberately left undone

* **`CommandMetaData`.** Out of scope by design, dropped during parsing, counted in
  `skipped_sections()`.
* **Little-endian bit fields, `ArrayParameterType`, `AggregateParameterType`.** Represented
  in the IR and reported by `xtce info`, refused at decode with the element named.
* **Publishing to crates.io.** `CONTRIBUTING.md` rule 7 forbids it without being asked. The names
  `xtce`, `xtce-model` and `xtce-decode` were free on crates.io as of writing.

Format for real entries: what, why it blocks, what was tried.
