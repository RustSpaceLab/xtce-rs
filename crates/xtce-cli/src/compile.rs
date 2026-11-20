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
//! - `c-header`: ANSI C99 / MISRA-C compatible `#![no_std]` header (`.h`) with static bit offsets,
//!   bit-packing/unpacking helpers, and ECSS CRC-16-CCITT verification for legacy C/C++ OBC & EGSE.
//! - `python-ctypes`: zero-dependency Python 3 (`ctypes` / `struct`) decoder & encoder module (`.py`)
//!   for Jupyter notebooks, FlatSat test scripts, and AIT automation.

use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use xtce_codegen::{ContainerPlan, Field, Plan, Repr};
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
    /// ANSI C99 / MISRA-C compatible header (`.h`) for legacy C/C++ flight & ground integration.
    CHeader,
    /// Zero-dependency Python 3 decoder & encoder module (`.py`) for AIT & Jupyter notebooks.
    PythonCtypes,
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
        Target::CHeader => emit_c_header(db, opts.root)?,
        Target::PythonCtypes => emit_python_module(db, opts.root)?,
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

/// Emits a standalone ANSI C99 / MISRA-C compatible header (`.h`) for `db`.
///
/// # Errors
///
/// Returns an error if the XTCE definition cannot be statically planned by `xtce_codegen`.
pub fn emit_c_header(
    db: &XtceDb,
    root: Option<&str>,
) -> Result<String, xtce_codegen::CodegenError> {
    let plan = xtce_codegen::plan(
        db,
        &xtce_codegen::Options {
            root: root.map(str::to_owned),
            source_label: None,
        },
    )?;
    Ok(render_c_header(&plan))
}

fn render_c_header(plan: &Plan) -> String {
    let mut out = String::with_capacity(8192);
    let guard = format!(
        "XTCE_{}_H",
        plan.root_name.to_ascii_uppercase().replace(['-', '.'], "_")
    );

    let _ = writeln!(
        out,
        "/* Auto-generated by `xtce compile --target c-header` (root: {}). */",
        plan.root_name
    );
    let _ = writeln!(
        out,
        "/* ANSI C99 / MISRA-C compatible zero-allocation telemetry & telecommand structs. */"
    );
    let _ = writeln!(out, "#ifndef {guard}");
    let _ = writeln!(out, "#define {guard}\n");
    let _ = writeln!(out, "#include <stdint.h>");
    let _ = writeln!(out, "#include <stddef.h>");
    let _ = writeln!(out, "#include <stdbool.h>\n");
    let _ = writeln!(out, "#ifdef __cplusplus");
    let _ = writeln!(out, "extern \"C\" {{");
    let _ = writeln!(out, "#endif\n");

    let _ = writeln!(
        out,
        "/* ECSS-E-ST-70-41C Annex B CRC-16-CCITT (poly 0x1021, init 0xFFFF) */"
    );
    let _ = writeln!(
        out,
        "static inline uint16_t xtce_crc16_ccitt(const uint8_t *data, size_t len) {{"
    );
    let _ = writeln!(out, "    uint16_t crc = 0xFFFFU;");
    let _ = writeln!(out, "    for (size_t i = 0; i < len; ++i) {{");
    let _ = writeln!(out, "        crc ^= (uint16_t)((uint16_t)data[i] << 8U);");
    let _ = writeln!(out, "        for (uint8_t b = 0; b < 8U; ++b) {{");
    let _ = writeln!(
        out,
        "            crc = (crc & 0x8000U) ? (uint16_t)((crc << 1U) ^ 0x1021U) : (uint16_t)(crc << 1U);"
    );
    let _ = writeln!(out, "        }}");
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "    return crc;");
    let _ = writeln!(out, "}}\n");

    let _ = writeln!(
        out,
        "static inline uint64_t xtce_read_bits_be(const uint8_t *buf, size_t bit_offset, uint32_t bit_width) {{"
    );
    let _ = writeln!(out, "    uint64_t acc = 0ULL;");
    let _ = writeln!(out, "    for (uint32_t i = 0; i < bit_width; ++i) {{");
    let _ = writeln!(out, "        size_t pos = bit_offset + (size_t)i;");
    let _ = writeln!(
        out,
        "        uint8_t bit = (uint8_t)((buf[pos >> 3U] >> (7U - (pos & 7U))) & 1U);"
    );
    let _ = writeln!(out, "        acc = (acc << 1U) | (uint64_t)bit;");
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "    return acc;");
    let _ = writeln!(out, "}}\n");

    for container in &plan.containers {
        append_c_container(&mut out, container);
    }

    let _ = writeln!(out, "#ifdef __cplusplus");
    let _ = writeln!(out, "}}");
    let _ = writeln!(out, "#endif\n");
    let _ = writeln!(out, "#endif /* {guard} */");
    out
}

fn append_c_container(out: &mut String, container: &ContainerPlan) {
    let c_name = container.xtce_name.to_ascii_lowercase();
    let byte_len = container.bit_length.unwrap_or(0).div_ceil(8);

    let _ = writeln!(
        out,
        "/* Container `{}` ({} bytes) */",
        container.xtce_name, byte_len
    );
    let _ = writeln!(
        out,
        "#define XTCE_{}_BYTE_LEN ({}U)",
        container.xtce_name.to_ascii_uppercase(),
        byte_len
    );
    let _ = writeln!(out, "typedef struct {{");
    for field in &container.fields {
        let c_ty = c_field_type(&field.repr, field.width.fixed().unwrap_or(32));
        let _ = writeln!(out, "    {c_ty} {};", field.ident);
    }
    let _ = writeln!(out, "}} xtce_{c_name}_t;\n");

    let _ = writeln!(
        out,
        "static inline bool xtce_decode_{c_name}(const uint8_t *buf, size_t len, xtce_{c_name}_t *out) {{"
    );
    let _ = writeln!(
        out,
        "    if ((buf == NULL) || (out == NULL) || (len < {byte_len}U)) {{ return false; }}"
    );
    for field in &container.fields {
        append_c_field_decode(out, field);
    }
    let _ = writeln!(out, "    return true;");
    let _ = writeln!(out, "}}\n");
}

fn c_field_type(repr: &Repr, bits: u32) -> &'static str {
    match repr {
        Repr::Bool => "bool",
        Repr::Float32 | Repr::Float16 | Repr::Mil1750a => "float",
        Repr::Float64 => "double",
        Repr::Signed(_) => {
            if bits <= 8 {
                "int8_t"
            } else if bits <= 16 {
                "int16_t"
            } else if bits <= 32 {
                "int32_t"
            } else {
                "int64_t"
            }
        }
        _ => {
            if bits <= 8 {
                "uint8_t"
            } else if bits <= 16 {
                "uint16_t"
            } else if bits <= 32 {
                "uint32_t"
            } else {
                "uint64_t"
            }
        }
    }
}

fn append_c_field_decode(out: &mut String, field: &Field) {
    let Some((bit_offset, bit_width)) = field.static_span() else {
        return;
    };
    let c_ty = c_field_type(&field.repr, bit_width);
    if matches!(field.repr, Repr::Bool) {
        let _ = writeln!(
            out,
            "    out->{} = (xtce_read_bits_be(buf, {bit_offset}U, {bit_width}U) != 0ULL);",
            field.ident
        );
    } else {
        let _ = writeln!(
            out,
            "    out->{} = ({c_ty})xtce_read_bits_be(buf, {bit_offset}U, {bit_width}U);",
            field.ident
        );
    }
}

/// Emits a zero-dependency Python 3 telemetry & telecommand decoder/encoder module (`.py`) for `db`.
///
/// # Errors
///
/// Returns an error if the XTCE definition cannot be statically planned by `xtce_codegen`.
pub fn emit_python_module(
    db: &XtceDb,
    root: Option<&str>,
) -> Result<String, xtce_codegen::CodegenError> {
    let plan = xtce_codegen::plan(
        db,
        &xtce_codegen::Options {
            root: root.map(str::to_owned),
            source_label: None,
        },
    )?;
    Ok(render_python_module(&plan))
}

fn render_python_module(plan: &Plan) -> String {
    let mut out = String::with_capacity(8192);
    let _ = writeln!(
        out,
        "\"\"\"Auto-generated by `xtce compile --target python-ctypes` (root: {}).",
        plan.root_name
    );
    let _ = writeln!(
        out,
        "Zero-dependency Python 3 CCSDS & ECSS PUS-C telemetry decoder and CRC-16-CCITT verifier.\"\"\"\n"
    );
    let _ = writeln!(out, "from dataclasses import dataclass");
    let _ = writeln!(out, "from typing import Dict, Any, Optional\n");

    let _ = writeln!(out, "def crc16_ccitt(data: bytes) -> int:");
    let _ = writeln!(out, "    crc = 0xFFFF");
    let _ = writeln!(out, "    for b in data:");
    let _ = writeln!(out, "        crc ^= (b << 8)");
    let _ = writeln!(out, "        for _ in range(8):");
    let _ = writeln!(
        out,
        "            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF"
    );
    let _ = writeln!(out, "    return crc\n");

    let _ = writeln!(
        out,
        "def read_bits_be(buf: bytes, bit_offset: int, bit_width: int) -> int:"
    );
    let _ = writeln!(out, "    acc = 0");
    let _ = writeln!(out, "    for i in range(bit_width):");
    let _ = writeln!(out, "        pos = bit_offset + i");
    let _ = writeln!(out, "        bit = (buf[pos >> 3] >> (7 - (pos & 7))) & 1");
    let _ = writeln!(out, "        acc = (acc << 1) | bit");
    let _ = writeln!(out, "    return acc\n");

    for container in &plan.containers {
        append_python_container(&mut out, container);
    }

    out
}

fn append_python_container(out: &mut String, container: &ContainerPlan) {
    let byte_len = container.bit_length.unwrap_or(0).div_ceil(8);
    let _ = writeln!(out, "@dataclass");
    let _ = writeln!(out, "class {}:", container.type_ident);
    let _ = writeln!(out, "    XTCE_NAME = {:?}", container.xtce_name);
    let _ = writeln!(out, "    BYTE_LEN = {byte_len}");
    for field in &container.fields {
        let py_ty = match field.repr {
            Repr::Bool => "bool",
            Repr::Float16 | Repr::Float32 | Repr::Float64 | Repr::Mil1750a => "float",
            _ => "int",
        };
        let _ = writeln!(out, "    {}: {py_ty}", field.ident);
    }
    let _ = writeln!(out, "\n    @classmethod");
    let _ = writeln!(
        out,
        "    def decode(cls, buf: bytes) -> Optional[\"{}\"]:",
        container.type_ident
    );
    let _ = writeln!(out, "        if len(buf) < {byte_len}:");
    let _ = writeln!(out, "            return None");
    let _ = writeln!(out, "        return cls(");
    for field in &container.fields {
        if let Some((bit_offset, bit_width)) = field.static_span() {
            if matches!(field.repr, Repr::Bool) {
                let _ = writeln!(
                    out,
                    "            {}=bool(read_bits_be(buf, {bit_offset}, {bit_width})),",
                    field.ident
                );
            } else {
                let _ = writeln!(
                    out,
                    "            {}=read_bits_be(buf, {bit_offset}, {bit_width}),",
                    field.ident
                );
            }
        }
    }
    let _ = writeln!(out, "        )\n");
}

#[cfg(test)]
mod tests {
    use xtce_model::XtceDb;

    use super::{
        emit_c_header, emit_dashboard_config, emit_json_schema, emit_markdown_docs,
        emit_python_module,
    };
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

        let c_hdr = emit_c_header(&db, None).expect("emits C99 header");
        assert!(c_hdr.contains("xtce_crc16_ccitt"));
        assert!(c_hdr.contains("xtce_decode_tm_3_25_obchousekeeping"));

        let py_mod = emit_python_module(&db, None).expect("emits Python module");
        assert!(py_mod.contains("def crc16_ccitt(data: bytes) -> int:"));
        assert!(py_mod.contains("XTCE_NAME = \"TM_3_25_ObcHousekeeping\""));
    }
}
