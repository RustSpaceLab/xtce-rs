//! `cargo xtask diff` — decode every golden case and compare against the reference.
//!
//! Two checks per case, and both matter:
//!
//! * **Detail.** The first N packets are compared parameter by parameter, so a failure names
//!   the packet, the parameter and both values.
//! * **Digest.** A SHA-256 over the canonical encoding of *every* packet in the stream. The
//!   detail section is truncated for size; without the digest, a divergence in packet 5000
//!   of 7200 would go unnoticed.
//!
//! A digest mismatch with a clean detail section is still a failure. It means the first
//! differing packet is past the detail window, and the harness cannot say which one: the
//! golden holds no per-packet reference beyond the window, and a SHA-256 does not localise.
//! Widening the window and regenerating is the way to find it, and the report says so with
//! the command already filled in.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use xtce_decode::{DecodeError, Decoder, PacketIter};
use xtce_model::XtceDb;

use crate::encoding::{Scalar, eng_scalar, raw_scalar, write_blob};
use crate::sha256::{Sha256, to_hex};

/// One packet as a name-keyed map, which is how the reference stores it.
type PacketMap = BTreeMap<String, (Scalar, Scalar)>;

/// A golden file, as loaded.
struct Golden {
    case: String,
    xtce: PathBuf,
    packets: PathBuf,
    root_container: Option<String>,
    skip_header_bytes: usize,
    packet_count: usize,
    unrecognized_count: usize,
    digest: String,
    /// Packets per window digest, and one digest per window.
    ///
    /// The whole-stream digest says *whether* the two implementations diverge and the detail
    /// section only covers the first 64 packets, so a divergence past it had nowhere to be
    /// pointed at. These narrow it to a window without regenerating anything. Zero and empty
    /// for a golden written before they existed.
    window_size: usize,
    window_digests: Vec<String>,
    detail: Vec<Option<PacketMap>>,
    reference_load_seconds: f64,
    reference_parse_seconds: f64,
}

/// What happened for one case.
pub struct CaseReport {
    pub case: String,
    pub packets: usize,
    pub unrecognized: usize,
    pub trailing: usize,
    pub differences: Vec<String>,
    pub digest_matches: bool,
    /// The first window of packets whose digest differs, when the goldens carry windows.
    ///
    /// `(first packet, last packet)`, inclusive. `None` when the digests match, when the
    /// golden predates windows, or when the difference is in the packet count rather than in
    /// any window.
    pub diverging_window: Option<(usize, usize)>,
    /// How many packets the golden holds full detail for.
    pub detail_window: usize,
    pub load_seconds: f64,
    pub decode_seconds: f64,
    pub reference_load_seconds: f64,
    pub reference_parse_seconds: f64,
}

impl CaseReport {
    #[must_use]
    pub fn passed(&self) -> bool {
        self.differences.is_empty() && self.digest_matches
    }
}

/// Runs every golden case found in `golden_dir`.
///
/// # Errors
///
/// Returns a message if the golden directory cannot be read or a case cannot be run at all.
/// A *difference* is not an error here; it is reported in the [`CaseReport`].
pub fn run(
    testdata: &Path,
    golden_dir: &Path,
    only: &[String],
    max_differences: usize,
) -> Result<Vec<CaseReport>, String> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(golden_dir)
        .map_err(|error| format!("cannot read {}: {error}", golden_dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "json")
                && path
                    .file_stem()
                    .is_some_and(|stem| stem != "reference_timings")
        })
        .collect();
    files.sort();

    let mut reports = Vec::new();
    for file in files {
        let golden = load_golden(&file)?;
        if !only.is_empty() && !only.contains(&golden.case) {
            continue;
        }
        reports.push(run_case(testdata, &golden, max_differences)?);
    }
    Ok(reports)
}

fn load_golden(path: &Path) -> Result<Golden, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| format!("{} is not valid JSON: {error}", path.display()))?;

    let string = |key: &str| -> Result<String, String> {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("{}: missing string field {key:?}", path.display()))
    };
    let number = |key: &str| -> Result<u64, String> {
        value
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("{}: missing numeric field {key:?}", path.display()))
    };

    let mut detail = Vec::new();
    if let Some(items) = value.get("detail").and_then(serde_json::Value::as_array) {
        for item in items {
            detail.push(parse_detail_packet(item)?);
        }
    }

    let reference = value.get("reference");
    let seconds = |key: &str| -> f64 {
        reference
            .and_then(|reference| reference.get(key))
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(f64::NAN)
    };

    Ok(Golden {
        case: string("case")?,
        xtce: PathBuf::from(string("xtce")?),
        packets: PathBuf::from(string("packets")?),
        root_container: value
            .get("root_container")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        skip_header_bytes: usize::try_from(number("skip_header_bytes")?).unwrap_or(0),
        packet_count: usize::try_from(number("packet_count")?).unwrap_or(0),
        unrecognized_count: usize::try_from(number("unrecognized_count").unwrap_or(0)).unwrap_or(0),
        digest: string("digest_sha256")?,
        window_size: usize::try_from(number("window_size").unwrap_or(0)).unwrap_or(0),
        window_digests: value
            .get("window_digests")
            .and_then(serde_json::Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        detail,
        reference_load_seconds: seconds("load_seconds"),
        reference_parse_seconds: seconds("parse_seconds"),
    })
}

/// `None` means the reference refused to decode this packet.
fn parse_detail_packet(value: &serde_json::Value) -> Result<Option<PacketMap>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "detail entry is not an object".to_owned())?;
    if object.contains_key("__unrecognized__") {
        return Ok(None);
    }
    let mut map = PacketMap::new();
    for (name, pair) in object {
        let items = pair
            .as_array()
            .ok_or_else(|| format!("{name}: detail value is not a [raw, eng] pair"))?;
        let raw = items
            .first()
            .ok_or_else(|| format!("{name}: detail value has no raw"))?;
        let eng = items
            .get(1)
            .ok_or_else(|| format!("{name}: detail value has no eng"))?;
        map.insert(
            name.clone(),
            (Scalar::from_json(raw)?, Scalar::from_json(eng)?),
        );
    }
    Ok(Some(map))
}

fn run_case(
    testdata: &Path,
    golden: &Golden,
    max_differences: usize,
) -> Result<CaseReport, String> {
    let xtce_path = testdata.join(&golden.xtce);
    let packets_path = testdata.join(&golden.packets);

    let load_start = std::time::Instant::now();
    let db = XtceDb::from_path(&xtce_path)
        .map_err(|error| format!("{}: {error}", xtce_path.display()))?;
    let load_seconds = load_start.elapsed().as_secs_f64();

    let decoder = match &golden.root_container {
        Some(name) => Decoder::with_root(&db, name),
        None => Decoder::new(&db),
    }
    .map_err(|error| format!("{}: {error}", golden.case))?;

    let stream = std::fs::read(&packets_path)
        .map_err(|error| format!("cannot read {}: {error}", packets_path.display()))?;

    let mut differences = Vec::new();
    let mut hasher = Sha256::new();
    let mut windows = WindowDigests::new(golden.window_size);
    let mut canonical = Vec::with_capacity(4096);
    let mut count = 0usize;
    let mut unrecognized = 0usize;
    let mut trailing = 0usize;

    let decode_start = std::time::Instant::now();
    for (index, framed) in PacketIter::new(&stream, golden.skip_header_bytes).enumerate() {
        let framed = framed.map_err(|error| format!("{}: packet {index}: {error}", golden.case))?;

        let decoded = decoder.decode(framed.bytes());
        canonical.clear();

        let observed: Option<PacketMap> = match decoded {
            Ok(packet) => {
                if packet.trailing_bits() != 0 {
                    trailing += 1;
                }
                let mut map = PacketMap::new();
                for (name, value) in packet.iter_named() {
                    map.insert(
                        name.to_owned(),
                        (raw_scalar(&value.raw), eng_scalar(&value.eng)),
                    );
                }
                Some(map)
            }
            Err(DecodeError::UnrecognizedPacket { .. }) => {
                unrecognized += 1;
                None
            }
            Err(error) => {
                if differences.len() < max_differences {
                    differences.push(format!("packet {index}: decode failed: {error}"));
                }
                count += 1;
                // A failed packet still has to advance the digest, or every subsequent
                // packet would be blamed for this one.
                canonical.push(b'?');
                let mut framed_digest = Vec::new();
                write_blob(&mut framed_digest, &canonical);
                hasher.update(&framed_digest);
                windows.update(&framed_digest);
                continue;
            }
        };

        write_canonical_packet(&mut canonical, observed.as_ref());
        let mut framed_digest = Vec::with_capacity(canonical.len() + 8);
        write_blob(&mut framed_digest, &canonical);
        hasher.update(&framed_digest);
        windows.update(&framed_digest);

        if let Some(expected) = golden.detail.get(index) {
            compare_packet(
                index,
                expected.as_ref(),
                observed.as_ref(),
                &mut differences,
                max_differences,
            );
        }
        count += 1;
    }
    let decode_seconds = decode_start.elapsed().as_secs_f64();

    if count != golden.packet_count {
        differences.push(format!(
            "packet count: reference {} vs {count}",
            golden.packet_count
        ));
    }
    if unrecognized != golden.unrecognized_count {
        differences.push(format!(
            "unrecognised packets: reference {} vs {unrecognized}",
            golden.unrecognized_count
        ));
    }

    let digest = to_hex(&hasher.finalize());
    let diverging_window = if digest == golden.digest {
        None
    } else {
        windows.first_difference(&golden.window_digests)
    };
    Ok(CaseReport {
        case: golden.case.clone(),
        packets: count,
        unrecognized,
        trailing,
        differences,
        digest_matches: digest == golden.digest,
        diverging_window,
        detail_window: golden.detail.len(),
        load_seconds,
        decode_seconds,
        reference_load_seconds: golden.reference_load_seconds,
        reference_parse_seconds: golden.reference_parse_seconds,
    })
}

/// One digest per window of packets, mirroring `WINDOW` in `tools/gen_goldens.py`.
struct WindowDigests {
    size: usize,
    hasher: Sha256,
    seen: usize,
    digests: Vec<String>,
}

impl WindowDigests {
    fn new(size: usize) -> Self {
        Self {
            size,
            hasher: Sha256::new(),
            seen: 0,
            digests: Vec::new(),
        }
    }

    fn update(&mut self, framed: &[u8]) {
        if self.size == 0 {
            return;
        }
        self.hasher.update(framed);
        self.seen += 1;
        if self.seen % self.size == 0 {
            let finished = std::mem::take(&mut self.hasher);
            self.digests.push(to_hex(&finished.finalize()));
        }
    }

    /// The packets covered by the first window that differs from `expected`.
    ///
    /// A window that exists on one side and not the other counts as a difference, which is
    /// what a stream of a different length looks like from here.
    fn first_difference(mut self, expected: &[String]) -> Option<(usize, usize)> {
        if self.size == 0 || expected.is_empty() {
            return None;
        }
        if self.seen % self.size != 0 {
            let finished = std::mem::take(&mut self.hasher);
            self.digests.push(to_hex(&finished.finalize()));
        }
        let at = self
            .digests
            .iter()
            .zip(expected)
            .position(|(ours, theirs)| ours != theirs)
            .or_else(|| {
                (self.digests.len() != expected.len())
                    .then(|| self.digests.len().min(expected.len()))
            })?;
        Some((at * self.size, (at + 1) * self.size - 1))
    }
}

/// Mirrors `canonical_packet` in `tools/gen_goldens.py`.
fn write_canonical_packet(out: &mut Vec<u8>, packet: Option<&PacketMap>) {
    let Some(packet) = packet else {
        out.push(b'!');
        return;
    };
    // `BTreeMap` iterates in byte order, which for UTF-8 is code-point order — the same
    // order Python's `sorted()` produces.
    for (name, (raw, eng)) in packet {
        write_blob(out, name.as_bytes());
        raw.write_canonical(out);
        eng.write_canonical(out);
    }
}

fn compare_packet(
    index: usize,
    expected: Option<&PacketMap>,
    observed: Option<&PacketMap>,
    differences: &mut Vec<String>,
    max_differences: usize,
) {
    let mut report = |message: String| {
        if differences.len() < max_differences {
            differences.push(message);
        }
    };

    match (expected, observed) {
        (None, None) => {}
        (None, Some(map)) => report(format!(
            "packet {index}: reference rejected this packet, we decoded {} parameter(s)",
            map.len()
        )),
        (Some(_), None) => report(format!(
            "packet {index}: reference decoded this packet, we rejected it"
        )),
        (Some(expected), Some(observed)) => {
            for (name, want) in expected {
                match observed.get(name) {
                    None => report(format!("packet {index}: {name}: missing from our output")),
                    Some(got) => {
                        if got.0 != want.0 {
                            report(format!(
                                "packet {index}: {name}: raw differs — reference {:?}, ours {:?}",
                                want.0, got.0
                            ));
                        }
                        if got.1 != want.1 {
                            report(format!(
                                "packet {index}: {name}: eng differs — reference {:?}, ours {:?}",
                                want.1, got.1
                            ));
                        }
                    }
                }
            }
            for name in observed.keys() {
                if !expected.contains_key(name) {
                    report(format!(
                        "packet {index}: {name}: present in our output but not the reference"
                    ));
                }
            }
        }
    }
}

/// Renders a report block for one case.
#[must_use]
pub fn format_report(report: &CaseReport) -> String {
    let mut out = String::new();
    let verdict = if report.passed() { "ok" } else { "FAILED" };
    let _ = writeln!(out, "{:<28} {verdict}", report.case);
    let _ = writeln!(
        out,
        "  {} packets ({} not described)   load {:.1}x   decode {:.1}x   digest {}",
        report.packets,
        report.unrecognized,
        report.reference_load_seconds / report.load_seconds.max(f64::MIN_POSITIVE),
        report.reference_parse_seconds / report.decode_seconds.max(f64::MIN_POSITIVE),
        if report.digest_matches {
            "ok"
        } else {
            "MISMATCH"
        },
    );
    // The decode figure below includes this harness's own per-packet work — name lookup,
    // map building, digesting — so it is a floor on the speed-up, not a decoder benchmark.
    // `cargo bench -p xtce-decode` measures the decoder.
    let _ = writeln!(
        out,
        "  load {:.1} ms (reference {:.1} ms)   decode {:.1} ms incl. harness (reference {:.1} ms)",
        report.load_seconds * 1e3,
        report.reference_load_seconds * 1e3,
        report.decode_seconds * 1e3,
        report.reference_parse_seconds * 1e3,
    );
    // A mismatch the detail section cannot see is the awkward case: something differs, and
    // the harness knows only that the value comparison did not find it. Rather than leave
    // the reader to work out what to do, say which of the two situations it is.
    if !report.digest_matches && report.differences.is_empty() {
        if report.detail_window >= report.packets {
            // Every packet was compared value by value and agreed, yet the digests differ.
            // The digest covers more than the values: which parameters are present, and the
            // order they are in. So the difference is in the shape of the packet, not in a
            // number.
            let _ = writeln!(
                out,
                "  every one of the {} packets was compared and agreed, so the difference is \
                 not in a value.",
                report.packets
            );
            let _ = writeln!(
                out,
                "  the digest also covers which parameters are present and their order; \
                 look there."
            );
        } else {
            let _ = writeln!(
                out,
                "  every packet in the detail window agrees, so the first difference is past \
                 packet {}.",
                report.detail_window
            );
            // A SHA-256 does not localise, but the golden carries one per window of packets,
            // and that narrows it to a few hundred without regenerating anything.
            let detail = match report.diverging_window {
                Some((first, last)) => {
                    let _ = writeln!(
                        out,
                        "  the window digests put it between packet {first} and packet {last}."
                    );
                    last + 1
                }
                None => {
                    let _ = writeln!(
                        out,
                        "  this golden carries no window digests, so all that is known is \
                         that it is somewhere past the window."
                    );
                    report.packets
                }
            };
            let _ = writeln!(out, "  widen the detail far enough to reach it and re-run:");
            let _ = writeln!(
                out,
                "    .venv/bin/python tools/gen_goldens.py --only {} --detail {detail}",
                report.case
            );
            let _ = writeln!(
                out,
                "  then re-run; the difference will name its packet and parameter."
            );
        }
    }
    if report.trailing > 0 {
        // The reference only warns about this, and the golden generator suppresses warnings,
        // so without reporting it here a definition that does not cover its own packets is
        // invisible to both sides. It is not a mismatch — both implementations agree on
        // every value — but it says the definition is incomplete.
        let _ = writeln!(
            out,
            "  {} packet(s) had bits no entry claimed (both implementations agree on the values)",
            report.trailing
        );
    }
    for difference in &report.differences {
        let _ = writeln!(out, "    {difference}");
    }
    if !report.differences.is_empty() {
        let _ = writeln!(
            out,
            "    ({} difference(s) shown)",
            report.differences.len()
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Sha256, WindowDigests, to_hex};

    /// The digest of `count` packets, as the generator would write them.
    fn expected(count: usize, size: usize, corrupt: Option<usize>) -> Vec<String> {
        let mut out = Vec::new();
        let mut hasher = Sha256::new();
        for index in 0..count {
            hasher.update(format!("packet {index}").as_bytes());
            if (index + 1) % size == 0 {
                let done = std::mem::take(&mut hasher);
                out.push(to_hex(&done.finalize()));
            }
        }
        if count % size != 0 {
            out.push(to_hex(&hasher.finalize()));
        }
        if let Some(at) = corrupt {
            out[at] = "0".repeat(64);
        }
        out
    }

    fn observed(count: usize, size: usize) -> WindowDigests {
        let mut windows = WindowDigests::new(size);
        for index in 0..count {
            windows.update(format!("packet {index}").as_bytes());
        }
        windows
    }

    #[test]
    fn identical_streams_have_no_diverging_window() {
        let windows = observed(1000, 256);
        assert_eq!(windows.first_difference(&expected(1000, 256, None)), None);
    }

    /// The window is reported as the packets it covers, not as its index.
    #[test]
    fn a_differing_window_is_reported_as_a_packet_range() {
        let windows = observed(1000, 256);
        assert_eq!(
            windows.first_difference(&expected(1000, 256, Some(2))),
            Some((512, 767))
        );
    }

    /// The last window is short unless the stream divides evenly, and still has to be checked.
    ///
    /// Without finishing it, a divergence in the final packets would be the one case the
    /// windows could not localise — and a stream whose length is a multiple of the window is
    /// the exception rather than the rule.
    #[test]
    fn the_short_final_window_is_compared_too() {
        let windows = observed(700, 256);
        let mut theirs = expected(700, 256, None);
        assert_eq!(theirs.len(), 3, "two full windows and 188 packets");
        theirs[2] = "0".repeat(64);
        assert_eq!(windows.first_difference(&theirs), Some((512, 767)));
    }

    /// A stream of a different length differs at the first window one side does not have.
    #[test]
    fn a_shorter_stream_differs_at_the_window_it_runs_out_on() {
        let windows = observed(512, 256);
        assert_eq!(
            windows.first_difference(&expected(1000, 256, None)),
            Some((512, 767))
        );
    }

    /// A golden written before window digests existed localises nothing, and says nothing.
    #[test]
    fn a_golden_without_windows_reports_none() {
        let windows = observed(1000, 0);
        assert_eq!(windows.first_difference(&[]), None);
    }
}
