# Working rules for this repository

1. **SCOPE.** Implement only what `SUPPORTED.md` lists. A construct outside the decodable
   subset is *represented* in the IR and reported as `XtceError::Unsupported` at decode time
   — never implemented ad hoc, and never silently ignored when it could change which
   container matches. Do not widen `SUPPORTED.md` without being asked.

2. **MILESTONES.** Work M0 → M1 → M2 → … in order. Do not advance until the exit condition
   in `xtce-rs-spec.md` has been verified by running a command. Assume nothing.

3. **COMMITS.** After each milestone and each self-contained unit of work. Conventional
   commits. Never commit code that does not compile.

4. **BLOCKERS.** If two attempts do not resolve something, add an entry to `BLOCKERS.md`
   (what, why, what was tried) and move on. Do not loop.

5. **QUALITY.** No `unwrap()`, `expect()` or `panic!` in library code — the lints are
   enforced at the crate root, tests are exempt. `cargo clippy --all-targets -- -D warnings`
   must pass. Every parser change gets a test with a minimal XML snippet inline in the test,
   not a file.

6. **CORRECTNESS IS DIFFERENTIAL.** The Python reference decides. If this crate and
   `space_packet_parser` disagree on a bundled test file, this crate is wrong until proven
   otherwise, and the proof goes in `SUPPORTED.md` under "Deliberate divergences".

7. **LOG.** Append to `PROGRESS.md` after each milestone: what was done, what works, what is
   next. Terse.

8. **DEPENDENCIES.** `quick-xml`, `thiserror`, `clap`, `criterion`, `proptest`, `quote`,
   `proc-macro2`, `prettyplease`, `pyo3`, `serde`/`serde_json` (tests and CLI only). Anything
   else needs a justification in `PROGRESS.md`. Do not publish to crates.io.
