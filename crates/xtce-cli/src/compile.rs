//! `xtce compile` — multi-target XTCE mission compiler.
//!
//! Treats an XTCE 1.2 definition as a single source of truth and compiles it into multiple
//! mission artifacts in one pass:
//! - `rust-ground`: zero-allocation `#![no_std]` static Rust decoder module (`xtce-codegen`).
//! - `wireshark`: standalone Wireshark Lua dissector script (`.lua`).
//! - `json-schema`: JSON Schema (Draft 2020-12) describing decoded telemetry and command packets.
//! - `docs`: Markdown mission dictionary documenting all containers, parameters, types, and
//!   telecommands.
//! - `dashboard`: Telemetry Studio JSON dashboard layout and limit-alarm configuration.

use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use xtce_model::{DataEncoding, TypeKind, XtceDb};

use crate::wireshark;

/// Compilation targets supported by `xtce compile --target <TARGET>`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Target {
    /// Static `#![no_std]` Rust decoder module (`xtce_codegen`).
    RustGround,
    /// Standalone Wireshark Lua dissector script (`.lua`).
    Wireshark,
    /// JSON Schema (Draft 2020-12) for decoded telemetry & telecommand packets.
    JsonSchema,
    /// Markdown mission dictionary of containers, parameters, enumerations, and telecommands.
    Docs,
    /// Telemetry Studio JSON dashboard and alarm configuration.
    Dashboard,
}

/// Options for `xtce compile`.
pub struct Options<'a> {
    pub definition: &'a Path,
    pub target: Target,
    pub root: Option<&'a str>,
    pub out: Option<&'a Path>,
}

/// Executes `xtce compile` against a loaded [`XtceDb`].
///
/// # Errors
///
/// Returns an error if code generation or writing to the output path fails.
pub fn run_with_db(db: &XtceDb, opts: &Options<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let content = match opts.target {
        Target::RustGround => {
            let source_label = if opts.definition.as_os_str() == "-" {
                Some("<stdin>".to_owned())
            } else {
                Some(opts.definition.display().to_string())
            };
            xtce_codegen::generate(
                db,
                &xtce_codegen::Options {
                    root: opts.root.map(str::to_owned),
                    source_label,
                },
            )?
        }
        Target::Wireshark => {
            return wireshark::run_with_db(
                db,
                &wireshark::Options {
                    definition: opts.definition,
                    root: opts.root,
                    out: opts.out,
                    udp_port: Some(5006),
                },
            );
        }
        Target::JsonSchema => emit_json_schema(db),
        Target::Docs => emit_markdown_docs(db),
        Target::Dashboard => emit_dashboard_config(db),
    };

    match opts.out {
        Some(path) if path.as_os_str() != "-" => {
            std::fs::write(path, content)?;
            eprintln!("compiled {:?} target to {}", opts.target, path.display());
        }
        _ => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(content.as_bytes())?;
        }
    }
    Ok(())
}

/// Emits a JSON Schema (Draft 2020-12) describing decoded packets for `db`.
#[must_use]
pub fn emit_json_schema(db: &XtceDb) -> String {
    let mut out = String::with_capacity(4096);
    let root_ss = db
        .space_systems()
        .first()
        .map_or("Mission", |ss| db.name(ss.name));

    let _ = writeln!(out, "{{");
    let _ = writeln!(
        out,
        "  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\","
    );
    let _ = writeln!(
        out,
        "  \"title\": \"{root_ss} Telemetry & Command Schema\","
    );
    let _ = writeln!(out, "  \"type\": \"object\",");
    let _ = writeln!(out, "  \"required\": [\"container\", \"parameters\"],");
    let _ = writeln!(out, "  \"properties\": {{");
    let _ = writeln!(out, "    \"container\": {{");
    let _ = writeln!(out, "      \"type\": \"string\",");
    let _ = write!(out, "      \"enum\": [");

    let concrete: Vec<&str> = db
        .containers()
        .iter()
        .filter(|c| !c.is_abstract)
        .map(|c| db.name(c.name))
        .collect();
    for (idx, name) in concrete.iter().enumerate() {
        let sep = if idx + 1 < concrete.len() { ", " } else { "" };
        let _ = write!(out, "{name:?}{sep}");
    }
    let _ = writeln!(out, "]");
    let _ = writeln!(out, "    }},");
    let _ = writeln!(out, "    \"parameters\": {{");
    let _ = writeln!(out, "      \"type\": \"object\",");
    let _ = writeln!(out, "      \"properties\": {{");

    let params = db.parameters();
    for (idx, param) in params.iter().enumerate() {
        let comma = if idx + 1 < params.len() { "," } else { "" };
        let p_name = db.name(param.name);
        let json_type = db
            .parameter_type(param.type_id)
            .map_or("\"string\"", |ty| match ty.kind {
                TypeKind::Integer => "\"integer\"",
                TypeKind::Float => "\"number\"",
                TypeKind::Boolean { .. } => "\"boolean\"",
                _ => "\"string\"",
            });
        let _ = writeln!(
            out,
            "        {p_name:?}: {{ \"type\": {json_type} }}{comma}"
        );
    }

    let _ = writeln!(out, "      }}");
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "  }}");
    let _ = writeln!(out, "}}");
    out
}

/// Emits a Markdown mission reference dictionary for `db`.
#[must_use]
pub fn emit_markdown_docs(db: &XtceDb) -> String {
    let mut out = String::with_capacity(4096);
    let root_ss = db
        .space_systems()
        .first()
        .map_or("Mission", |ss| db.name(ss.name));
    let stats = db.stats();

    let _ = writeln!(out, "# {root_ss} — XTCE Mission Data Dictionary\n");
    let _ = writeln!(
        out,
        "- **Space Systems:** {}\n- **Parameters:** {}\n- **Containers:** {} ({} abstract)\n- **Telecommands:** {}\n",
        stats.space_systems,
        stats.parameters,
        stats.containers,
        stats.abstract_containers,
        stats.meta_commands
    );

    let _ = writeln!(out, "## 1. Sequence Containers\n");
    let _ = writeln!(out, "| Container | Kind | Base | Entries |");
    let _ = writeln!(out, "|---|---|---|---:|");
    for c in db.containers() {
        let name = db.name(c.name);
        let kind = if c.is_abstract {
            "abstract"
        } else if c.is_command {
            "command"
        } else {
            "telemetry"
        };
        let base = c
            .base
            .and_then(|id| db.container(id))
            .map_or("-", |b| db.name(b.name));
        let _ = writeln!(
            out,
            "| `{name}` | {kind} | `{base}` | {} |",
            c.entries.len()
        );
    }

    let _ = writeln!(out, "\n## 2. Parameters & Arguments\n");
    let _ = writeln!(out, "| Parameter | Type | Family | Width (bits) |");
    let _ = writeln!(out, "|---|---|---|---:|");
    for p in db.parameters() {
        let p_name = db.name(p.name);
        if let Some(ty) = db.parameter_type(p.type_id) {
            let t_name = db.name(ty.name);
            let family = ty.kind.label();
            let bits = ty
                .fixed_size_in_bits()
                .map_or_else(|| "var".to_owned(), |b| b.to_string());
            let _ = writeln!(out, "| `{p_name}` | `{t_name}` | {family} | {bits} |");
        }
    }

    if !db.meta_commands().is_empty() {
        let _ = writeln!(out, "\n## 3. Telecommands (`<MetaCommandSet>`)\n");
        let _ = writeln!(out, "| Telecommand | Abstract | Arguments |");
        let _ = writeln!(out, "|---|---|---:|");
        for cmd in db.meta_commands() {
            let name = db.name(cmd.name);
            let _ = writeln!(
                out,
                "| `{name}` | {} | {} |",
                cmd.is_abstract,
                cmd.arguments.len()
            );
        }
    }

    out
}

/// Emits a Telemetry Studio JSON dashboard and alarm configuration for `db`.
#[must_use]
pub fn emit_dashboard_config(db: &XtceDb) -> String {
    let mut out = String::with_capacity(2048);
    let root_ss = db
        .space_systems()
        .first()
        .map_or("Mission", |ss| db.name(ss.name));

    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "  \"mission\": {root_ss:?},");
    let _ = writeln!(out, "  \"theme\": \"orbittrack-dark\",");
    let _ = writeln!(out, "  \"panels\": [");

    let numeric_params: Vec<(&str, &str)> = db
        .parameters()
        .iter()
        .filter_map(|p| {
            let ty = db.parameter_type(p.type_id)?;
            match &ty.encoding {
                DataEncoding::Integer(_) | DataEncoding::Float(_) => {
                    Some((db.name(p.name), ty.kind.label()))
                }
                _ => None,
            }
        })
        .collect();

    for (idx, (p_name, kind)) in numeric_params.iter().enumerate() {
        let comma = if idx + 1 < numeric_params.len() {
            ","
        } else {
            ""
        };
        let widget = if *kind == "enumerated" {
            "status-badge"
        } else {
            "timeseries-chart"
        };
        let _ = writeln!(
            out,
            "    {{\"parameter\": {p_name:?}, \"widget\": {widget:?}}}{comma}"
        );
    }

    let _ = writeln!(out, "  ]");
    let _ = writeln!(out, "}}");
    out
}

#[cfg(test)]
mod tests {
    use xtce_model::XtceDb;

    use super::{emit_dashboard_config, emit_json_schema, emit_markdown_docs};
    use crate::pus::ECSS_PUS_XTCE_XML;

    #[test]
    fn compiles_json_schema_markdown_docs_and_dashboard_config() {
        let db = XtceDb::from_xml(ECSS_PUS_XTCE_XML).expect("loads PUS XTCE");

        let schema = emit_json_schema(&db);
        assert!(schema.contains("https://json-schema.org/draft/2020-12/schema"));
        assert!(schema.contains("\"TM_3_25_ObcHousekeeping\""));
        assert!(schema.contains("\"OBC_VBUS_V\""));

        let docs = emit_markdown_docs(&db);
        assert!(docs.contains("# ECSS_PUS_EO_Satellite — XTCE Mission Data Dictionary"));
        assert!(docs.contains("| `TM_3_25_ObcHousekeeping` | telemetry |"));

        let dash = emit_dashboard_config(&db);
        assert!(dash.contains("\"mission\": \"ECSS_PUS_EO_Satellite\""));
        assert!(dash.contains("\"parameter\": \"OBC_TEMP_C\""));
    }
}
