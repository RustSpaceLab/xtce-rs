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

## Known divergences with no test behind them

* **A polynomial calibrator over a *float* encoding.** `xtce-decode` raises the raw value to
  its power with `powi` — square and multiply. The reference writes `x ** n`, which for a
  float base is CPython's `**`, which is a libm `pow` call. Measured on 2026-08-23 over
  200 000 random values: they agree for exponents 0 and 1, differ for 84 values at exponent 2,
  and for **16 561 — about 8% — at exponent 3**. Python also raises `OverflowError` where
  `powi` returns infinity.

  Not fixed, and not turned into a golden, on purpose. `pow` is not required by the C standard
  to be correctly rounded, so the reference's own answer can differ between platforms;
  committing a golden over one would make the suite depend on the machine that produced it.
  `powi` at least gives the same answer everywhere. `calibrators.xml` exercises exactly this
  shape but is compared only against the interpreter, so nothing here is currently wrong —
  the gap is that the interpreter's float polynomial has never been held to the reference and
  would not survive being held to it.

  What it would take: decide whether bit-for-bit agreement with a platform-dependent `pow` is
  worth having, and if so, whether `powf` is close enough on the machines that matter.

## Things deliberately left undone

* **`CommandMetaData`.** Out of scope by design, dropped during parsing, counted in
  `skipped_sections()`.
* **Publishing to crates.io.** `CONTRIBUTING.md` rule 7 forbids it without being asked. The names
  `xtce`, `xtce-model` and `xtce-decode` were free on crates.io as of writing.

Format for real entries: what, why it blocks, what was tried.
