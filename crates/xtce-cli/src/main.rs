//! `xtce` — inspect and decode CCSDS telemetry defined by XTCE.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::todo, clippy::unimplemented)]
#![warn(clippy::pedantic)]
// Counts, durations and byte totals become f64 only to be printed as a rate or a size in
// KiB. A definition with 2^53 parameters would have louder problems than a rounded average.
#![allow(clippy::cast_precision_loss)]
// The doc comments on `Command` are clap's `--help` text, not rustdoc. Backticks around a
// container name would be shown to the reader literally, so they do not belong there.
#![allow(clippy::doc_markdown)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand};
use xtce_model::XtceDb;

mod compile;
mod decode;
mod diff;
mod encode;
mod info;
mod lsp;
mod pcap;
mod pus;
mod sim;
mod validate;
mod wireshark;

#[derive(Parser)]
#[command(name = "xtce", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Summarise one or more XTCE files: space systems, counts, and anything not decodable.
    Info {
        /// XTCE files to inspect. Use '-' to read from standard input.
        #[arg(required = true)]
        files: Vec<PathBuf>,

        /// Print the full space-system tree with every parameter and container.
        #[arg(long)]
        verbose: bool,
    },

    /// Decode a CCSDS packet stream against an XTCE definition.
    Decode {
        /// XTCE definition. Use '-' to read from standard input.
        definition: PathBuf,

        /// File of concatenated CCSDS packets. Use '-' to read from standard input.
        packets: PathBuf,

        /// Container to start from. Defaults to CCSDSPacket, CCSDSTelemetryPacket, or the
        /// only container without a base.
        #[arg(long)]
        root: Option<String>,

        /// Bytes of per-packet wrapper to skip before each CCSDS header.
        #[arg(long, default_value_t = 0)]
        skip_header_bytes: usize,

        /// Stop after this many packets.
        #[arg(long)]
        limit: Option<usize>,

        /// Show only these parameters. Repeatable. A * matches any run of characters, and a
        /// value matching nothing in the definition is an error.
        #[arg(long = "param")]
        params: Vec<String>,

        /// Output format.
        #[arg(long, value_enum, default_value_t = decode::Format::Table)]
        format: decode::Format,

        /// Also show the raw value alongside the engineering value.
        #[arg(long)]
        raw: bool,

        /// Suppress the final summary (load and decode timing, packet counts).
        #[arg(long)]
        no_summary: bool,
    },

    /// Compile a definition into a static Rust decoder.
    Codegen {
        /// XTCE definition. Use '-' to read from standard input.
        definition: PathBuf,

        /// Container to start from.
        #[arg(long)]
        root: Option<String>,

        /// Write here instead of standard output.
        #[arg(long, short)]
        out: Option<PathBuf>,
    },

    /// Multi-target XTCE mission compiler (rust-ground, wireshark, json-schema, docs, dashboard, c-header, python-ctypes).
    Compile {
        /// XTCE definition. Use '-' to read from standard input.
        definition: PathBuf,

        /// Artifact target to compile.
        #[arg(long, value_enum, default_value_t = compile::Target::RustGround)]
        target: compile::Target,

        /// Explicit root container to start from.
        #[arg(long)]
        root: Option<String>,

        /// Write compiled artifact here instead of standard output.
        #[arg(long, short)]
        out: Option<PathBuf>,
    },

    /// Compile a definition into a Wireshark Lua dissector script (.lua).
    Wireshark {
        /// XTCE definition. Use '-' to read from standard input.
        definition: PathBuf,

        /// Container to start from.
        #[arg(long)]
        root: Option<String>,

        /// Write here instead of standard output.
        #[arg(long, short)]
        out: Option<PathBuf>,

        /// Also register the dissector on this UDP port in addition to DLT_USER0 (147).
        #[arg(long)]
        udp_port: Option<u16>,
    },

    /// Wrap a raw CCSDS packet stream in a libpcap (.pcap) capture file for Wireshark.
    Pcap {
        /// File of concatenated CCSDS packets. Use '-' to read from standard input.
        packets: PathBuf,

        /// Write here instead of standard output.
        #[arg(long, short)]
        out: Option<PathBuf>,

        /// Bytes of per-packet wrapper to skip before each CCSDS header.
        #[arg(long, default_value_t = 0)]
        skip_header_bytes: usize,

        /// Stop after this many packets.
        #[arg(long)]
        limit: Option<usize>,
    },

    /// Assemble a binary CCSDS telemetry or telecommand packet from an XTCE definition.
    Encode {
        /// XTCE definition. Use '-' to read from standard input.
        definition: PathBuf,

        /// Concrete container or MetaCommand name to encode.
        target: String,

        /// Explicit root container to start inheritance walk from.
        #[arg(long)]
        root: Option<String>,

        /// Field or argument assignment in NAME=VALUE form (repeatable).
        #[arg(long = "set", short = 's')]
        assignments: Vec<String>,

        /// Write encoded packet here instead of standard output.
        #[arg(long, short)]
        out: Option<PathBuf>,

        /// Emit lowercase hexadecimal text instead of raw binary bytes.
        #[arg(long)]
        hex: bool,

        /// Stamp the final 16 bits of the packet with an ECSS CRC-16-CCITT syndrome.
        #[arg(long)]
        crc: bool,
    },

    /// Inspect ECSS-E-ST-70-41C (PUS-C) packet streams, run a HIL OBC session, or emit XTCE XML.
    Pus {
        /// File of concatenated CCSDS/PUS packets. Use '-' to read from standard input.
        packets: Option<PathBuf>,

        /// Run a closed-loop Hardware-in-the-Loop (HIL) session against the no_std OBC responder.
        #[arg(long)]
        hil_demo: bool,

        /// Bind a live UDP socket (e.g. 127.0.0.1:5006) serving the no_std HIL OBC responder.
        #[arg(long)]
        hil_udp: Option<String>,

        /// Emit a complete XTCE 1.2 XML mission definition for the ECSS PUS-C spacecraft profile.
        #[arg(long)]
        emit_xtce: bool,

        /// Write output (HIL capture or emitted XTCE XML) to this file.
        #[arg(long, short)]
        out: Option<PathBuf>,

        /// Bytes of per-packet wrapper to skip before each CCSDS header.
        #[arg(long, default_value_t = 0)]
        skip_header_bytes: usize,

        /// Stop after this many packets.
        #[arg(long)]
        limit: Option<usize>,
    },

    /// Time loading an XTCE file.
    Bench {
        /// XTCE file to load. Use '-' to read from standard input.
        file: PathBuf,

        /// Number of load iterations to time.
        #[arg(long, default_value_t = 10)]
        iterations: u32,
    },

    /// Compare two XTCE definitions and classify changes (BREAKING, WARNING, COMPATIBLE).
    Diff {
        /// Previous (baseline) XTCE definition file.
        old: PathBuf,

        /// New (candidate) XTCE definition file.
        new: PathBuf,

        /// Explicit root container to start inheritance and bit-offset analysis from.
        #[arg(long)]
        root: Option<String>,

        /// Exit with a non-zero status code when BREAKING changes are detected.
        #[arg(long)]
        fail_on_breaking: bool,
    },

    /// Validate an XTCE definition for structural, semantic, and codegen readiness, or emit JSON metadata.
    Validate {
        /// XTCE definition. Use '-' to read from standard input.
        definition: PathBuf,

        /// Explicit root container to start from.
        #[arg(long)]
        root: Option<String>,

        /// Emit a canonical JSON metadata dictionary (parameters, containers, telecommands) instead of the text report.
        #[arg(long)]
        json: bool,

        /// Fail with a non-zero exit code on warnings as well as errors.
        #[arg(long)]
        strict: bool,
    },

    /// Generate a deterministic CCSDS / ECSS PUS-C mission telemetry stream (with optional fault injection).
    Sim {
        /// Mission scenario to simulate.
        #[arg(long, value_enum, default_value_t = sim::Scenario::Nominal)]
        scenario: sim::Scenario,

        /// Number of telemetry packets to generate.
        #[arg(long, default_value_t = 20)]
        packets: usize,

        /// Deterministic PRNG seed (SplitMix64) for reproducible sensor noise.
        #[arg(long, default_value_t = 42)]
        seed: u64,

        /// Wrap the generated packet stream in a libpcap (.pcap) DLT_USER0 container for Wireshark.
        #[arg(long)]
        pcap: bool,

        /// Write generated packets here instead of standard output.
        #[arg(long, short)]
        out: Option<PathBuf>,
    },

    /// Start the XTCE 1.2 Language Server Protocol (LSP) JSON-RPC server over stdio.
    Lsp,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            let mut source = std::error::Error::source(&*error);
            while let Some(cause) = source {
                eprintln!("  caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

const MAX_DEFINITION_BYTES: u64 = 256 * 1024 * 1024;

fn load_db(path: &Path) -> Result<XtceDb, Box<dyn std::error::Error>> {
    if path.as_os_str() == "-" {
        let mut xml = String::new();
        std::io::stdin()
            .take(MAX_DEFINITION_BYTES)
            .read_to_string(&mut xml)?;
        Ok(XtceDb::from_xml(&xml)?)
    } else {
        Ok(XtceDb::from_path(path)?)
    }
}

#[allow(clippy::too_many_lines)]
fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Info { files, verbose } => run_info(&files, verbose),
        Command::Decode {
            definition,
            packets,
            root,
            skip_header_bytes,
            limit,
            params,
            format,
            raw,
            no_summary,
        } => decode::run(&decode::Options {
            definition: &definition,
            packets: &packets,
            root: root.as_deref(),
            skip_header_bytes,
            limit,
            only: &params,
            format,
            show_raw: raw,
            no_summary,
        }),
        Command::Codegen {
            definition,
            root,
            out,
        } => run_codegen(&definition, root, out),
        Command::Compile {
            definition,
            target,
            root,
            out,
        } => run_compile(&definition, target, root.as_deref(), out.as_deref()),
        Command::Wireshark {
            definition,
            root,
            out,
            udp_port,
        } => run_wireshark(&definition, root.as_deref(), out.as_deref(), udp_port),
        Command::Pcap {
            packets,
            out,
            skip_header_bytes,
            limit,
        } => pcap::run(&pcap::Options {
            packets: &packets,
            out: out.as_deref(),
            skip_header_bytes,
            limit,
        }),
        Command::Encode {
            definition,
            target,
            root,
            assignments,
            out,
            hex,
            crc,
        } => run_encode(
            &definition,
            &target,
            root.as_deref(),
            &assignments,
            out.as_deref(),
            hex,
            crc,
        ),
        Command::Pus {
            packets,
            hil_demo,
            hil_udp,
            emit_xtce,
            out,
            skip_header_bytes,
            limit,
        } => pus::run(&pus::Options {
            packets: packets.as_deref(),
            hil_demo,
            hil_udp: hil_udp.as_deref(),
            emit_xtce,
            out: out.as_deref(),
            skip_header_bytes,
            limit,
        }),
        Command::Bench { file, iterations } => run_bench(&file, iterations),
        Command::Diff {
            old,
            new,
            root,
            fail_on_breaking,
        } => run_diff(&old, &new, root.as_deref(), fail_on_breaking),
        Command::Validate {
            definition,
            root,
            json,
            strict,
        } => run_validate(&definition, root.as_deref(), json, strict),
        Command::Sim {
            scenario,
            packets,
            seed,
            pcap,
            out,
        } => sim::run(&sim::Options {
            scenario,
            packets,
            seed,
            pcap_format: pcap,
            out: out.as_deref(),
        }),
        Command::Lsp => lsp::run_stdio(),
    }
}

fn run_compile(
    definition: &Path,
    target: compile::Target,
    root: Option<&str>,
    out: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = load_db(definition)?;
    compile::run_with_db(
        &db,
        &compile::Options {
            definition,
            target,
            root,
            out,
        },
    )
}

fn run_diff(
    old: &Path,
    new: &Path,
    root: Option<&str>,
    fail_on_breaking: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let old_db = load_db(old)?;
    let new_db = load_db(new)?;
    diff::run(
        &old_db,
        &new_db,
        &diff::Options {
            root,
            fail_on_breaking,
        },
    )
}

fn run_validate(
    definition: &Path,
    root: Option<&str>,
    json: bool,
    strict: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = load_db(definition)?;
    validate::run(&db, &validate::Options { root, json, strict })
}

fn run_encode(
    definition: &Path,
    target: &str,
    root: Option<&str>,
    assignments: &[String],
    out: Option<&Path>,
    hex: bool,
    crc: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = load_db(definition)?;
    encode::run_with_db(
        &db,
        &encode::Options {
            target,
            root,
            assignments,
            out,
            hex,
            crc,
        },
    )
}

fn run_wireshark(
    definition: &Path,
    root: Option<&str>,
    out: Option<&Path>,
    udp_port: Option<u16>,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = load_db(definition)?;
    wireshark::run_with_db(
        &db,
        &wireshark::Options {
            definition,
            root,
            out,
            udp_port,
        },
    )
}

fn run_info(files: &[PathBuf], verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut failures = 0;
    for file in files {
        let started = Instant::now();
        match load_db(file) {
            Ok(db) => info::report(&db, started.elapsed(), verbose),
            Err(error) => {
                failures += 1;
                eprintln!("{}: {error}", file.display());
            }
        }
    }
    if failures > 0 {
        return Err(format!("{failures} of {} file(s) failed to load", files.len()).into());
    }
    Ok(())
}

fn run_codegen(
    definition: &Path,
    root: Option<String>,
    out: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = load_db(definition)?;
    let source_label = if definition.as_os_str() == "-" {
        Some("<stdin>".to_owned())
    } else {
        Some(definition.display().to_string())
    };
    let source = xtce_codegen::generate(&db, &xtce_codegen::Options { root, source_label })?;
    match out {
        Some(path) => {
            std::fs::write(&path, source)?;
            eprintln!("wrote {}", path.display());
            eprintln!(
                "include it inside a module carrying the lint allowances generated \
                 code needs; the file's header shows how"
            );
        }
        None => print!("{source}"),
    }
    Ok(())
}

fn run_bench(file: &Path, iterations: u32) -> Result<(), Box<dyn std::error::Error>> {
    let (bytes, xml_data) = if file.as_os_str() == "-" {
        let mut xml = String::new();
        std::io::stdin()
            .take(MAX_DEFINITION_BYTES)
            .read_to_string(&mut xml)?;
        (xml.len() as u64, Some(xml))
    } else {
        (std::fs::metadata(file).map_or(0, |meta| meta.len()), None)
    };
    let mut timings = Vec::with_capacity(iterations as usize);
    let mut last = None;
    for _ in 0..iterations.max(1) {
        let started = Instant::now();
        let db = match &xml_data {
            Some(xml) => XtceDb::from_xml(xml)?,
            None => XtceDb::from_path(file)?,
        };
        timings.push(started.elapsed());
        last = Some(db);
    }
    timings.sort_unstable();
    let median = timings.get(timings.len() / 2).copied().unwrap_or_default();
    let best = timings.first().copied().unwrap_or_default();

    if file.as_os_str() == "-" {
        println!("<stdin>");
    } else {
        println!("{}", file.display());
    }
    println!("  size        {:>10.1} KiB", bytes as f64 / 1024.0);
    println!("  load median {:>10.3} ms", median.as_secs_f64() * 1e3);
    println!("  load best   {:>10.3} ms", best.as_secs_f64() * 1e3);
    if let Some(db) = last {
        let stats = db.stats();
        println!(
            "  throughput  {:>10.1} MiB/s",
            (bytes as f64 / (1024.0 * 1024.0)) / median.as_secs_f64().max(f64::MIN_POSITIVE)
        );
        println!(
            "  model       {} parameters, {} containers, {} interned names ({:.1} KiB)",
            stats.parameters,
            stats.containers,
            stats.interned_names,
            stats.interned_bytes as f64 / 1024.0
        );
    }
    Ok(())
}
