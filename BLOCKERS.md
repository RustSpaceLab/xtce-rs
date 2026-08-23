# Blockers

Nothing outstanding. Every milestone in `xtce-rs-spec.md` (M0 through M7) is done and
verified; see `PROGRESS.md` for what each one produced and what it measured. As of
2026-08-23 every bundled definition compiles through `xtce-codegen`, so the generator's
subset is no longer narrower than the data on hand — the remaining refusals are constructs
nothing in reach uses.

## Where a next session should start

0. **A real `<CommandMetaData>`.** Everything the command support claims is checked against a
   purpose-built file and the schema, because no bundled definition has a command half and the
   reference has no command support to compare against. The first real one this meets will
   find something.

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

  **Decided on 2026-08-24: keep `powi`, and this is no longer an open question.** Three
  measurements settle it, taken over 100 000 random finite bases at each exponent.

  `powf` would buy the agreement. At exponent 3 it matches CPython on **100 %** of values,
  against `powi`'s 74 %, because both end up in the same libm `pow`.

  The generated decoder cannot call it. Generated code names nothing outside `core`, which is
  why the emitter writes the square-and-multiply sequence out by hand in the first place —
  `f64::powf` is `std`, exactly as `f64::powi` is. Changing the interpreter alone would break
  the equality between the interpreted and the generated decoder, and that equality is what
  every claim about generated code rests on: codegen is checked against the interpreter, and
  the interpreter against the reference. Trading the inner rung for the outer one leaves the
  ladder shorter than it was.

  And at exponent 2, agreeing would mean being wrong. Rust's `x * x` and CPython's `x ** 2`
  differ for 0.15 % of values — and where they differ, it is CPython that is a unit in the
  last place off the correctly rounded square, which `x * x` gives by definition:

      base = 0.7275253015377592
      x * x    = 0.5292930643776075   (3fe0eff802300bda)
      x ** 2   = 0.5292930643776074   (3fe0eff802300bd9)
      math.pow = 0.5292930643776074

  So the divergence is not one implementation being sloppy. It is two different arithmetics,
  each correct by its own rule, and one of them is reproducible on every machine while the
  other is a property of the libm that happens to be installed. `SUPPORTED.md` records it as a
  deliberate divergence rather than a defect.

## Things deliberately left undone

* **The rest of `CommandMetaData`.** The section is read as of 2026-08-23 — telecommands are
  decoded and compiled — but only the packet layout: `MetaCommand`, `ArgumentList`,
  `CommandContainer`, `ArgumentAssignment` and `FixedValueEntry`. `BlockMetaCommand`,
  `VerifierSet`, `TransmissionConstraintList`, `Interlock` and `ParameterToSetList` describe
  operational behaviour rather than bits, and are out of scope by design.
* **An `ArgumentAssignment` on an enumerated argument.** `argumentValue` is a calibrated value,
  so it compares labels, which the dispatcher does not — refused by name. It is the pattern
  real command sets use most, and worth revisiting with a real database in hand.
* **Publishing to crates.io.** `CONTRIBUTING.md` rule 7 forbids it without being asked. The names
  `xtce`, `xtce-model` and `xtce-decode` were free on crates.io as of writing.

Format for real entries: what, why it blocks, what was tried.
