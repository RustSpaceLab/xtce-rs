//! Development tasks for this workspace.
//!
//! Run as `cargo xtask <command>` (the alias lives in `.cargo/config.toml`).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod diff;
mod encoding;
mod sha256;

#[derive(Parser)]
#[command(name = "xtask", about = "Development tasks for xtce-rs", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Decode every golden case and compare against the Python reference implementation.
    Diff {
        /// Restrict to named case(s).
        #[arg(long = "case")]
        cases: Vec<String>,

        /// Maximum differences to report per case.
        #[arg(long, default_value_t = 20)]
        max_differences: usize,

        /// Directory holding the vendored test data.
        #[arg(long, default_value = "testdata/spp")]
        testdata: PathBuf,

        /// Directory holding the golden files.
        #[arg(long, default_value = "testdata/golden")]
        golden: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Diff {
            cases,
            max_differences,
            testdata,
            golden,
        } => {
            let root = workspace_root();
            let reports = match diff::run(
                &root.join(&testdata),
                &root.join(&golden),
                &cases,
                max_differences,
            ) {
                Ok(reports) => reports,
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::FAILURE;
                }
            };

            if reports.is_empty() {
                eprintln!("error: no golden cases matched");
                return ExitCode::FAILURE;
            }

            for report in &reports {
                print!("{}", diff::format_report(report));
            }

            let failed = reports.iter().filter(|report| !report.passed()).count();
            println!();
            if failed == 0 {
                println!(
                    "all {} case(s) match the reference implementation",
                    reports.len()
                );
                ExitCode::SUCCESS
            } else {
                println!("{failed} of {} case(s) differ", reports.len());
                ExitCode::FAILURE
            }
        }
    }
}

/// The workspace root, so the task can be run from anywhere.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

use std::path::Path;
