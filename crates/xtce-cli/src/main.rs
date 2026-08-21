//! `xtce` — inspect and decode CCSDS telemetry defined by XTCE.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand};
use xtce_model::XtceDb;

mod decode;
mod info;

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
        /// XTCE files to inspect.
        #[arg(required = true)]
        files: Vec<PathBuf>,

        /// Print the full space-system tree with every parameter and container.
        #[arg(long)]
        verbose: bool,
    },

    /// Decode a CCSDS packet stream against an XTCE definition.
    Decode {
        /// XTCE definition.
        definition: PathBuf,

        /// File of concatenated CCSDS packets.
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

        /// Show only these parameters. Repeatable.
        #[arg(long = "param")]
        params: Vec<String>,

        /// Output format.
        #[arg(long, value_enum, default_value_t = decode::Format::Table)]
        format: decode::Format,

        /// Also show the raw value alongside the engineering value.
        #[arg(long)]
        raw: bool,
    },

    /// Time loading an XTCE file.
    Bench {
        /// XTCE file to load.
        file: PathBuf,

        /// Number of load iterations to time.
        #[arg(long, default_value_t = 10)]
        iterations: u32,
    },
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

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Info { files, verbose } => {
            let mut failures = 0;
            for file in &files {
                let started = Instant::now();
                match XtceDb::from_path(file) {
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

        Command::Decode {
            definition,
            packets,
            root,
            skip_header_bytes,
            limit,
            params,
            format,
            raw,
        } => decode::run(&decode::Options {
            definition: &definition,
            packets: &packets,
            root: root.as_deref(),
            skip_header_bytes,
            limit,
            only: &params,
            format,
            show_raw: raw,
        }),

        Command::Bench { file, iterations } => {
            let bytes = std::fs::metadata(&file).map(|meta| meta.len()).unwrap_or(0);
            let mut timings = Vec::with_capacity(iterations as usize);
            let mut last = None;
            for _ in 0..iterations.max(1) {
                let started = Instant::now();
                let db = XtceDb::from_path(&file)?;
                timings.push(started.elapsed());
                last = Some(db);
            }
            timings.sort_unstable();
            let median = timings.get(timings.len() / 2).copied().unwrap_or_default();
            let best = timings.first().copied().unwrap_or_default();

            println!("{}", file.display());
            println!("  size        {:>10.1} KiB", bytes as f64 / 1024.0);
            println!("  load median {:>10.3} ms", median.as_secs_f64() * 1e3);
            println!("  load best   {:>10.3} ms", best.as_secs_f64() * 1e3);
            if let Some(db) = last {
                let stats = db.stats();
                println!(
                    "  throughput  {:>10.1} MiB/s",
                    (bytes as f64 / (1024.0 * 1024.0))
                        / median.as_secs_f64().max(f64::MIN_POSITIVE)
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
    }
}
