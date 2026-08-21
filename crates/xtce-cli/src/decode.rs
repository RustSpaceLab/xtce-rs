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
/// Returns a message if the definition or stream cannot be read, if no root container can be
/// chosen, or if the stream is not well-framed. A packet that fails to *decode* is reported
/// and counted, not fatal: one malformed frame in a downlink should not end the run.
pub fn run(options: &Options<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let load_start = Instant::now();
    let db = XtceDb::from_path(options.definition)?;
    let load_elapsed = load_start.elapsed();

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

fn wanted(options: &Options<'_>, name: &str) -> bool {
    options.only.is_empty() || options.only.iter().any(|want| want == name)
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
        if !wanted(options, name) {
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
        if !wanted(options, name) {
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
