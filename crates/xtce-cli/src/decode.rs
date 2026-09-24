//! `xtce decode` — run a packet stream through a definition and print the values.

use std::io::Write;
use std::path::Path;
use std::time::Instant;

use xtce_decode::{DecodeError, Decoder, EngValue, PacketIter, RawValue};
use xtce_model::XtceDb;

/// How to render each packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Format {
    /// One aligned line per parameter, grouped by packet.
    Table,
    /// One JSON object per packet, one packet per line.
    Jsonl,
    /// Nothing per packet; only the summary.
    Quiet,
}

/// Everything `xtce decode` was asked to do.
pub struct Options<'a> {
    pub definition: &'a Path,
    pub packets: &'a Path,
    pub root: Option<&'a str>,
    pub skip_header_bytes: usize,
    pub limit: Option<usize>,
    pub only: &'a [String],
    pub format: Format,
    pub show_raw: bool,
}

/// Decodes a stream and writes the result.
///
/// # Errors
///
/// Returns a message if the definition or stream cannot be read, if a `--param` selects
/// nothing the definition describes, if no root container can be chosen, or if the stream is
/// not well-framed. A packet that fails to *decode* is reported and counted, not fatal: one
/// malformed frame in a downlink should not end the run.
pub fn run(options: &Options<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let load_start = Instant::now();
    let db = XtceDb::from_path(options.definition)?;
    let load_elapsed = load_start.elapsed();

    check_only(&db, options.only)?;

    let decoder = match options.root {
        Some(name) => Decoder::with_root(&db, name)?,
        None => Decoder::new(&db)?,
    };

    let stream = std::fs::read(options.packets)?;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    let mut decoded_count = 0usize;
    let mut failed = 0usize;
    let mut unrecognised = 0usize;
    let mut trailing = 0usize;
    let mut total = 0usize;

    // One packet buffer for the whole stream: after the first packet this allocates nothing.
    let mut packet = decoder.new_packet(&stream);

    let decode_start = Instant::now();
    for (index, framed) in PacketIter::new(&stream, options.skip_header_bytes).enumerate() {
        if options.limit.is_some_and(|limit| total >= limit) {
            break;
        }
        total += 1;
        let framed = framed?;

        match decoder.decode_into(&mut packet, framed.bytes()) {
            Ok(()) => {
                decoded_count += 1;
                if packet.trailing_bits() != 0 {
                    trailing += 1;
                }
                match options.format {
                    Format::Table => write_table(&mut out, index, &packet, options)?,
                    Format::Jsonl => write_jsonl(&mut out, index, &packet, options)?,
                    Format::Quiet => {}
                }
            }
            Err(DecodeError::UnrecognizedPacket { container, .. }) => {
                unrecognised += 1;
                if options.format != Format::Quiet {
                    writeln!(
                        out,
                        "packet {index}: not described by this definition (no inheritor of {container} matches)"
                    )?;
                }
            }
            Err(error) => {
                failed += 1;
                writeln!(out, "packet {index}: {error}")?;
            }
        }
    }
    let decode_elapsed = decode_start.elapsed();

    writeln!(out)?;
    writeln!(
        out,
        "{total} packet(s): {decoded_count} decoded, {unrecognised} not described, {failed} failed"
    )?;
    if trailing > 0 {
        // Worth surfacing: the definition and the packets disagree about length, which
        // usually means a container is missing entries rather than that anything is corrupt.
        writeln!(
            out,
            "{trailing} packet(s) had bits no entry claimed — the definition may be incomplete"
        )?;
    }
    writeln!(
        out,
        "load {:.2} ms, decode {:.2} ms ({:.1} packets/s)",
        load_elapsed.as_secs_f64() * 1e3,
        decode_elapsed.as_secs_f64() * 1e3,
        decoded_count as f64 / decode_elapsed.as_secs_f64().max(f64::MIN_POSITIVE),
    )?;
    out.flush()?;

    if failed > 0 {
        return Err(format!("{failed} packet(s) failed to decode").into());
    }
    Ok(())
}

/// Whether `--param` asked for this parameter. No `--param` at all means all of them.
fn wanted(only: &[String], name: &str) -> bool {
    only.is_empty() || only.iter().any(|pattern| glob_matches(pattern, name))
}

/// Matches one `--param` pattern against a parameter name.
///
/// `*` stands for any run of characters, including none. Everything else must match exactly,
/// and case matters, because XTCE names do. A pattern with no `*` is a plain equality test,
/// which is what `--param` has always meant.
fn glob_matches(pattern: &str, name: &str) -> bool {
    let mut segments = pattern.split('*');
    // `split` yields at least one segment for any input, so the prefix is always there.
    let prefix = segments.next().unwrap_or(pattern);
    let Some(mut rest) = name.strip_prefix(prefix) else {
        return false;
    };
    let Some(suffix) = segments.next_back() else {
        // No `*` in the pattern: the prefix had to have been the whole name.
        return rest.is_empty();
    };
    for middle in segments {
        let Some(at) = rest.find(middle) else {
            return false;
        };
        // Consume what this segment matched, so two `*` segments cannot claim the same
        // characters. Leftmost is the right choice: it leaves the most room for the rest.
        rest = &rest[at + middle.len()..];
    }
    // `ends_with` is what keeps the prefix and the suffix from overlapping: whatever the
    // prefix took is no longer in `rest` to be taken again.
    rest.ends_with(suffix)
}

/// Rejects a `--param` that selects nothing, before the stream is read.
///
/// Without this a mistyped name printed every packet header, no values at all, and exited 0
/// — the same output as a definition that genuinely never carries that parameter. On a
/// database with thousands of parameters that is an expensive thing to have to spot by eye.
fn check_only(db: &XtceDb, only: &[String]) -> Result<(), String> {
    if only.is_empty() {
        return Ok(());
    }

    let names: Vec<&str> = db
        .parameters()
        .iter()
        .map(|parameter| db.name(parameter.name))
        .collect();
    let unmatched: Vec<&str> = only
        .iter()
        .filter(|pattern| !names.iter().any(|name| glob_matches(pattern, name)))
        .map(String::as_str)
        .collect();
    if unmatched.is_empty() {
        return Ok(());
    }

    let mut message = format!(
        "{} of {} --param value(s) match no parameter in this definition, which describes {}:",
        unmatched.len(),
        only.len(),
        names.len()
    );
    for pattern in unmatched {
        message.push_str("\n  ");
        message.push_str(pattern);
        if let Some(suggestion) = suggest(pattern, &names) {
            message.push_str("  — did you mean ");
            message.push_str(suggestion);
            message.push('?');
        }
    }
    Err(message)
}

/// The nearest parameter name to a pattern that matched nothing, when one is near enough to
/// be worth printing.
///
/// A pattern containing `*` gets no suggestion: there the useful answer is that the glob was
/// too narrow, not that some one name was almost right.
fn suggest<'a>(pattern: &str, names: &[&'a str]) -> Option<&'a str> {
    if pattern.contains('*') {
        return None;
    }
    // Case is the mistake often enough — and XTCE names are case-sensitive — to be worth
    // ruling out before spending anything on edit distance.
    if let Some(name) = names
        .iter()
        .copied()
        .find(|name| name.eq_ignore_ascii_case(pattern))
    {
        return Some(name);
    }
    // Scale the budget with the pattern: one wrong character in three is a typo, but four
    // wrong characters in twelve is a different name.
    let budget = (pattern.chars().count() / 3).clamp(1, 3);
    names
        .iter()
        .copied()
        .map(|name| (edit_distance(pattern, name), name))
        .filter(|(distance, _)| *distance <= budget)
        .min_by_key(|(distance, name)| (*distance, name.len()))
        .map(|(_, name)| name)
}

/// Optimal string alignment distance, on the error path only, to suggest a name.
///
/// Levenshtein, plus swapping two adjacent characters as a single edit rather than two,
/// because on a keyboard that is one slip and one of the commonest ways to mistype a name.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    // Three rolling rows: a transposition reaches back two rows, so one previous row is not
    // enough.
    let mut two_back = vec![0usize; b.len() + 1];
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        current[0] = i;
        for j in 1..=b.len() {
            let substitute = previous[j - 1] + usize::from(a[i - 1] != b[j - 1]);
            let mut best = substitute.min(previous[j] + 1).min(current[j - 1] + 1);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(two_back[j - 2] + 1);
            }
            current[j] = best;
        }
        std::mem::swap(&mut two_back, &mut previous);
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

fn write_table(
    out: &mut impl Write,
    index: usize,
    packet: &xtce_decode::DecodedPacket<'_, '_>,
    options: &Options<'_>,
) -> std::io::Result<()> {
    let db = packet.db();
    let container = db
        .container(packet.container())
        .map_or("?", |container| db.name(container.name));
    writeln!(
        out,
        "--- packet {index}  {container}  {} bit(s), {} parameter(s)",
        packet.bits_consumed(),
        packet.len()
    )?;
    for (name, value) in packet.iter_named() {
        if !wanted(options.only, name) {
            continue;
        }
        if options.show_raw {
            writeln!(out, "  {name:<32} {:<24} raw {}", value.eng, value.raw)?;
        } else {
            writeln!(out, "  {name:<32} {}", value.eng)?;
        }
    }
    Ok(())
}

fn write_jsonl(
    out: &mut impl Write,
    index: usize,
    packet: &xtce_decode::DecodedPacket<'_, '_>,
    options: &Options<'_>,
) -> std::io::Result<()> {
    write!(out, r#"{{"packet":{index},"values":{{"#)?;
    let mut first = true;
    for (name, value) in packet.iter_named() {
        if !wanted(options.only, name) {
            continue;
        }
        if !first {
            write!(out, ",")?;
        }
        first = false;
        write!(out, "\"")?;
        write_json_string(out, name)?;
        write!(out, "\":")?;
        if options.show_raw {
            write!(out, "{{\"eng\":")?;
            write_eng(out, &value.eng)?;
            write!(out, ",\"raw\":")?;
            write_raw(out, &value.raw)?;
            write!(out, "}}")?;
        } else {
            write_eng(out, &value.eng)?;
        }
    }
    writeln!(out, "}}}}")
}

fn write_eng(out: &mut impl Write, value: &EngValue<'_, '_>) -> std::io::Result<()> {
    match value {
        EngValue::Unsigned(number) => write!(out, "{number}"),
        EngValue::Signed(number) => write!(out, "{number}"),
        EngValue::Float(number) => write_json_float(out, *number),
        EngValue::Bool(flag) => write!(out, "{flag}"),
        EngValue::Label(text) => write_quoted(out, text),
        EngValue::Text(text) => write_quoted(out, text),
        EngValue::Bytes(bytes) => write_hex(out, bytes),
    }
}

fn write_raw(out: &mut impl Write, value: &RawValue<'_>) -> std::io::Result<()> {
    match value {
        RawValue::Unsigned(number) => write!(out, "{number}"),
        RawValue::Signed(number) => write!(out, "{number}"),
        RawValue::Float(number) => write_json_float(out, *number),
        RawValue::Bytes(bytes) => write_hex(out, bytes),
    }
}

/// JSON has no literal for NaN or infinity, so those become `null` rather than invalid JSON.
fn write_json_float(out: &mut impl Write, value: f64) -> std::io::Result<()> {
    if value.is_finite() {
        write!(out, "{value}")
    } else {
        write!(out, "null")
    }
}

fn write_hex(out: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    write!(out, "\"")?;
    for byte in bytes {
        write!(out, "{byte:02x}")?;
    }
    write!(out, "\"")
}

fn write_quoted(out: &mut impl Write, text: &str) -> std::io::Result<()> {
    write!(out, "\"")?;
    write_json_string(out, text)?;
    write!(out, "\"")
}

fn write_json_string(out: &mut impl Write, text: &str) -> std::io::Result<()> {
    for ch in text.chars() {
        match ch {
            '"' => write!(out, "\\\"")?,
            '\\' => write!(out, "\\\\")?,
            '\n' => write!(out, "\\n")?,
            '\r' => write!(out, "\\r")?,
            '\t' => write!(out, "\\t")?,
            control if control < ' ' => write!(out, "\\u{:04x}", control as u32)?,
            other => write!(out, "{other}")?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_only, edit_distance, glob_matches, suggest, wanted};
    use xtce_model::XtceDb;

    /// Three names, two of them sharing a prefix, so a glob has something to select between.
    const DEFINITION: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<xtce:SpaceSystem name="TestSystem" xmlns:xtce="http://www.omg.org/spec/XTCE/20180204">
  <xtce:TelemetryMetaData>
    <xtce:ParameterTypeSet>
      <xtce:IntegerParameterType name="UINT32" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="32" encoding="unsigned"/>
      </xtce:IntegerParameterType>
    </xtce:ParameterTypeSet>
    <xtce:ParameterSet>
      <xtce:Parameter name="ADGPSPOSX" parameterTypeRef="UINT32"/>
      <xtce:Parameter name="ADGPSPOSY" parameterTypeRef="UINT32"/>
      <xtce:Parameter name="USEC" parameterTypeRef="UINT32"/>
    </xtce:ParameterSet>
    <xtce:ContainerSet>
      <xtce:SequenceContainer name="PKT">
        <xtce:EntryList>
          <xtce:ParameterRefEntry parameterRef="ADGPSPOSX"/>
        </xtce:EntryList>
      </xtce:SequenceContainer>
    </xtce:ContainerSet>
  </xtce:TelemetryMetaData>
</xtce:SpaceSystem>
"#;

    fn db() -> XtceDb {
        XtceDb::from_xml(DEFINITION).expect("the test definition parses")
    }

    fn only(patterns: &[&str]) -> Vec<String> {
        patterns
            .iter()
            .map(|pattern| (*pattern).to_owned())
            .collect()
    }

    #[test]
    fn a_pattern_without_a_star_is_an_equality_test() {
        assert!(glob_matches("USEC", "USEC"));
        assert!(!glob_matches("USE", "USEC"));
        assert!(!glob_matches("USECS", "USEC"));
        // XTCE names are case-sensitive, and so is the match.
        assert!(!glob_matches("usec", "USEC"));
    }

    #[test]
    fn a_star_stands_for_any_run_of_characters() {
        assert!(glob_matches("ADGPS*", "ADGPSPOSX"));
        assert!(glob_matches("*POSX", "ADGPSPOSX"));
        assert!(glob_matches("AD*POS*", "ADGPSPOSX"));
        assert!(glob_matches("AD*X", "ADGPSPOSX"));
        assert!(glob_matches("*", "ADGPSPOSX"));
        assert!(!glob_matches("ADGPS*", "USEC"));
        assert!(!glob_matches("*POSZ", "ADGPSPOSX"));
    }

    #[test]
    fn a_star_may_stand_for_nothing() {
        assert!(glob_matches("USEC*", "USEC"));
        assert!(glob_matches("*USEC", "USEC"));
        assert!(glob_matches("US*EC", "USEC"));
    }

    #[test]
    fn two_segments_cannot_claim_the_same_characters() {
        // "B" would be matched twice over if the two ends were allowed to overlap.
        assert!(!glob_matches("AB*BC", "ABC"));
        assert!(glob_matches("AB*BC", "ABBC"));
        assert!(!glob_matches("A*A", "A"));
        assert!(glob_matches("A*A", "AA"));

        // The same, for the segments between the stars: "GPSPOSX" holds two S's, not three.
        assert!(glob_matches("AD*S*S*X", "ADGPSPOSX"));
        assert!(!glob_matches("AD*S*S*S*X", "ADGPSPOSX"));
    }

    #[test]
    fn a_segment_between_stars_has_to_be_there() {
        assert!(glob_matches("AD*POS*X", "ADGPSPOSX"));
        assert!(!glob_matches("AD*ZZZ*X", "ADGPSPOSX"));
        // In order, too: POS comes after GPS, not before it.
        assert!(!glob_matches("AD*POS*GPS*X", "ADGPSPOSX"));
    }

    #[test]
    fn no_param_at_all_selects_everything() {
        assert!(wanted(&[], "USEC"));
        assert!(wanted(&[], "ADGPSPOSX"));
    }

    #[test]
    fn param_selects_only_what_it_names() {
        let selection = only(&["USEC"]);
        assert!(wanted(&selection, "USEC"));
        assert!(!wanted(&selection, "ADGPSPOSX"));

        let selection = only(&["USEC", "ADGPSPOSY"]);
        assert!(wanted(&selection, "USEC"));
        assert!(wanted(&selection, "ADGPSPOSY"));
        assert!(!wanted(&selection, "ADGPSPOSX"));
    }

    #[test]
    fn param_selects_by_glob() {
        let selection = only(&["ADGPS*"]);
        assert!(wanted(&selection, "ADGPSPOSX"));
        assert!(wanted(&selection, "ADGPSPOSY"));
        assert!(!wanted(&selection, "USEC"));
    }

    #[test]
    fn a_name_the_definition_describes_is_accepted() {
        assert!(check_only(&db(), &only(&["USEC"])).is_ok());
        assert!(check_only(&db(), &only(&["USEC", "ADGPSPOSX"])).is_ok());
        assert!(check_only(&db(), &only(&["ADGPS*"])).is_ok());
        assert!(check_only(&db(), &[]).is_ok());
    }

    #[test]
    fn a_name_the_definition_does_not_describe_is_rejected() {
        let error = check_only(&db(), &only(&["ADGPSPOZX"]))
            .expect_err("a mistyped name has to be an error, not an empty report");
        assert!(error.contains("ADGPSPOZX"), "{error}");
        // The whole point of failing is to say what was probably meant.
        assert!(error.contains("ADGPSPOSX"), "{error}");
    }

    #[test]
    fn a_glob_matching_nothing_is_rejected_too() {
        let error = check_only(&db(), &only(&["ADGPZ*"]))
            .expect_err("a glob that selects nothing is as useless as a mistyped name");
        assert!(error.contains("ADGPZ*"), "{error}");
    }

    #[test]
    fn every_unmatched_param_is_reported_at_once() {
        let error = check_only(&db(), &only(&["USEC", "NOPE", "ALSO_NOPE"]))
            .expect_err("two of the three match nothing");
        assert!(error.contains("NOPE"), "{error}");
        assert!(error.contains("ALSO_NOPE"), "{error}");
        assert!(error.contains("2 of 3"), "{error}");
    }

    #[test]
    fn wrong_case_is_suggested_before_anything_else() {
        let names = ["ADGPSPOSX", "ADGPSPOSY", "USEC"];
        assert_eq!(suggest("usec", &names), Some("USEC"));
        assert_eq!(suggest("Usec", &names), Some("USEC"));
    }

    #[test]
    fn a_near_miss_is_suggested_and_a_far_one_is_not() {
        let names = ["ADGPSPOSX", "ADGPSPOSY", "USEC"];
        assert_eq!(suggest("ADGPSPOZX", &names), Some("ADGPSPOSX"));
        assert_eq!(suggest("UESC", &names), Some("USEC"));
        assert_eq!(suggest("TOTALLY_UNRELATED", &names), None);
        // A glob is not a misspelling of any one name, so it gets no suggestion.
        assert_eq!(suggest("ADGPZ*", &names), None);
    }

    #[test]
    fn edit_distance_counts_single_character_changes() {
        assert_eq!(edit_distance("", ""), 0);
        assert_eq!(edit_distance("USEC", "USEC"), 0);
        assert_eq!(edit_distance("USEC", ""), 4);
        assert_eq!(edit_distance("", "USEC"), 4);
        // One substitution, one deletion, one insertion.
        assert_eq!(edit_distance("USEC", "USEK"), 1);
        assert_eq!(edit_distance("USEC", "USC"), 1);
        assert_eq!(edit_distance("USEC", "USECX"), 1);
        assert_eq!(edit_distance("USEC", "SUEC"), 1);
    }

    #[test]
    fn a_transposition_is_one_edit_not_two() {
        // The distinction that lets a swapped pair still be suggested on a short name.
        assert_eq!(edit_distance("USEC", "UESC"), 1);
        assert_eq!(edit_distance("ADGPSPOSX", "ADGPSPSOX"), 1);
        // Two characters apart is still two edits: only *adjacent* swaps are one.
        assert_eq!(edit_distance("ABCD", "CBAD"), 2);
    }
}
