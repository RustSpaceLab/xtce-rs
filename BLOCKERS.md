# Blockers

Nothing outstanding. Every milestone in `xtce-rs-spec.md` (M0 through M7) is done and
verified; see `PROGRESS.md` for what each one produced and what it measured. As of
2026-08-23 every bundled definition compiles through `xtce-codegen`, so the generator's
subset is no longer narrower than the data on hand — the remaining refusals are constructs
nothing in reach uses.

## Where a next session should start

1. **Localising a digest mismatch needs the goldens regenerated.** `cargo xtask diff` now
   tells you what to run when the digest differs but the detail window is clean — the window
   is 64 packets and a SHA-256 does not localise, so widening it and regenerating is the
   answer, and the report prints the exact command. What it cannot do is find the packet on
   its own.

   The real fix is a per-packet or per-window digest in the golden files, which means
   regenerating them with the pinned reference. That is `space_packet_parser` at commit
   `6de220ff` — **not** the 6.0.1 on PyPI — and regenerating ground truth changes what the
   whole project is measured against, so it wants a deliberate decision rather than a
   drive-by.

2. **Talk to `greglucas/space-data-toolkit`.** Section 7 of the specification suggests it,
   and the benchmark it asked for now exists.

## Things deliberately left undone

* **`CommandMetaData`.** Out of scope by design, dropped during parsing, counted in
  `skipped_sections()`.
* **`ContextCalibrator` in `xtce-codegen`.** The interpreter evaluates one; the generator
  refuses it by name. Its criteria range over other parameters, which may themselves be
  calibrated and may sit later in the container, so compiling it means resolving a dependency
  graph. No definition in reach uses one, so there is nothing to validate a guess against.
* **`AggregateParameterType`.** Represented in the IR and reported by `xtce info`, refused
  at decode with the element named. It shared this line with arrays until 2026-08-23 and is
  not the same problem: an array is a repetition, so it expands into indexed copies of one
  element type, while an aggregate is a record whose members have their own names and types.
  The reference refuses both, so neither has an oracle — but XTCE states the array's index
  convention and layout order outright, and there is correspondingly less to state about a
  record.
* **Publishing to crates.io.** `CONTRIBUTING.md` rule 7 forbids it without being asked. The names
  `xtce`, `xtce-model` and `xtce-decode` were free on crates.io as of writing.

Format for real entries: what, why it blocks, what was tried.
