//! `xtce validate` — semantic validation and JSON metadata export for XTCE definitions.
//!
//! Goes beyond XML syntax checking to inspect the lowered [`XtceDb`] intermediate representation
//! for dangling references, unsupported constructs, unreachable abstract containers, and static
//! codegen compilability, and optionally exports the normalized mission metadata as JSON.

use std::io::Write;

use xtce_model::{DataEncoding, TypeKind, XtceDb};

/// Severity of a semantic validation diagnostic.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    /// Prevents correct decoding of at least one container or parameter.
    Error,
    /// Non-fatal issue (e.g. an abstract container with no inheritors or a dynamic construct
    /// that requires interpreted decoding rather than static codegen).
    Warning,
}

/// One semantic diagnostic discovered while validating an [`XtceDb`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Diagnostic {
    pub level: Level,
    pub subject: String,
    pub message: String,
}

/// Summary of validating an [`XtceDb`].
#[derive(Clone, Debug, Default)]
pub struct ValidationReport {
    pub diagnostics: Vec<Diagnostic>,
    pub compilable_containers: Option<usize>,
}

impl ValidationReport {
    /// Count of [`Level::Error`] diagnostics.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.level == Level::Error)
            .count()
    }

    /// Count of [`Level::Warning`] diagnostics.
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.level == Level::Warning)
            .count()
    }
}

/// CLI options for `xtce validate`.
pub struct Options<'a> {
    pub root: Option<&'a str>,
    pub json: bool,
    pub strict: bool,
}

/// Runs `xtce validate` on `db` and emits either a text report or JSON metadata dictionary.
///
/// # Errors
///
/// Returns an error if I/O fails, if semantic errors are present, or if `strict` is set and
/// warnings are present.
pub fn run(db: &XtceDb, opts: &Options<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let report = validate_db(db, opts.root);
    let mut stdout = std::io::stdout().lock();
    if opts.json {
        write_json_metadata(&mut stdout, db, &report)?;
    } else {
        write_text_report(&mut stdout, db, &report)?;
    }
    if report.error_count() > 0 {
        return Err(format!("validation failed with {} error(s)", report.error_count()).into());
    }
    if opts.strict && report.warning_count() > 0 {
        return Err(format!(
            "strict validation failed with {} warning(s)",
            report.warning_count()
        )
        .into());
    }
    Ok(())
}

/// Performs semantic validation on `db` and tests static codegen compilability from `root`.
#[must_use]
pub fn validate_db(db: &XtceDb, root: Option<&str>) -> ValidationReport {
    let mut report = ValidationReport::default();

    for unsup in db.unsupported() {
        push_unsupported_construct(
            &mut report.diagnostics,
            &unsup.path,
            &unsup.element,
            unsup.reason,
        );
    }

    for param in db.parameters() {
        check_parameter(db, param, &mut report.diagnostics);
    }

    for container in db.containers() {
        if container.is_abstract && container.inheritors.is_empty() {
            push_diag(
                &mut report.diagnostics,
                Level::Warning,
                db.name(container.name),
                "abstract container has no inheritors (dead branch)",
            );
        }
    }

    let opts = xtce_codegen::Options {
        root: root.map(str::to_owned),
        source_label: None,
    };
    match xtce_codegen::plan(db, &opts) {
        Ok(plan) => {
            report.compilable_containers = Some(plan.containers.len());
        }
        Err(err) => {
            push_codegen_warning(&mut report.diagnostics, &err);
        }
    }

    report
}

fn check_parameter(db: &XtceDb, param: &xtce_model::Parameter, diagnostics: &mut Vec<Diagnostic>) {
    let name = db.name(param.name);
    let Some(ty) = db.parameter_type(param.type_id) else {
        push_diag(
            diagnostics,
            Level::Error,
            name,
            "parameter type index does not resolve",
        );
        return;
    };

    if let TypeKind::Unsupported { element } = ty.kind {
        push_unsupported_type(diagnostics, name, db.name(element));
    }
    if matches!(ty.encoding, DataEncoding::None)
        && !matches!(ty.kind, TypeKind::Array { .. } | TypeKind::Aggregate { .. })
    {
        push_diag(
            diagnostics,
            Level::Error,
            name,
            "parameter type has no data encoding",
        );
    }
}

fn push_diag(diagnostics: &mut Vec<Diagnostic>, level: Level, subject: &str, message: &str) {
    diagnostics.push(Diagnostic {
        level,
        subject: subject.to_owned(),
        message: message.to_owned(),
    });
}

fn push_unsupported_construct(
    diagnostics: &mut Vec<Diagnostic>,
    path: &str,
    element: &str,
    reason: &str,
) {
    diagnostics.push(Diagnostic {
        level: Level::Error,
        subject: path.to_owned(),
        message: format!("unsupported construct <{element}>: {reason}"),
    });
}

fn push_unsupported_type(diagnostics: &mut Vec<Diagnostic>, name: &str, element: &str) {
    diagnostics.push(Diagnostic {
        level: Level::Error,
        subject: name.to_owned(),
        message: format!("unsupported parameter type <{element}>"),
    });
}

fn push_codegen_warning(diagnostics: &mut Vec<Diagnostic>, err: &xtce_codegen::CodegenError) {
    diagnostics.push(Diagnostic {
        level: Level::Warning,
        subject: "codegen".to_owned(),
        message: format!("interpreted-only definition ({err})"),
    });
}

/// Writes the validation report in human-readable text format.
///
/// # Errors
///
/// Returns an I/O error if writing fails.
pub fn write_text_report(
    out: &mut impl Write,
    db: &XtceDb,
    report: &ValidationReport,
) -> std::io::Result<()> {
    for diag in &report.diagnostics {
        let tag = match diag.level {
            Level::Error => "ERROR",
            Level::Warning => "WARN ",
        };
        writeln!(out, "{tag} {}: {}", diag.subject, diag.message)?;
    }

    let stats = db.stats();
    let codegen_status = report.compilable_containers.map_or_else(
        || "interpreted-only".to_owned(),
        |n| format!("static-codegen ready ({n} concrete container(s))"),
    );

    writeln!(
        out,
        "VALIDATED {} parameter(s), {} container(s), {} command(s) — {} error(s), {} warning(s) [{codegen_status}]",
        stats.parameters,
        stats.containers,
        stats.meta_commands,
        report.error_count(),
        report.warning_count(),
    )
}

/// Writes a normalized JSON metadata export of `db` and `report` to `out`.
///
/// # Errors
///
/// Returns an I/O error if writing fails.
pub fn write_json_metadata(
    out: &mut impl Write,
    db: &XtceDb,
    report: &ValidationReport,
) -> std::io::Result<()> {
    let stats = db.stats();
    writeln!(out, "{{")?;
    writeln!(out, "  \"parameters_count\": {},", stats.parameters)?;
    writeln!(out, "  \"containers_count\": {},", stats.containers)?;
    writeln!(out, "  \"commands_count\": {},", stats.meta_commands)?;
    writeln!(out, "  \"errors_count\": {},", report.error_count())?;
    writeln!(out, "  \"warnings_count\": {},", report.warning_count())?;
    writeln!(
        out,
        "  \"static_codegen_ready\": {},",
        report.compilable_containers.is_some()
    )?;
    writeln!(out, "  \"containers\": [")?;
    let containers = db.containers();
    for (idx, c) in containers.iter().enumerate() {
        let comma = if idx + 1 < containers.len() { "," } else { "" };
        writeln!(
            out,
            "    {{\"name\": {:?}, \"abstract\": {}, \"entries\": {}}}{comma}",
            db.name(c.name),
            c.is_abstract,
            c.entries.len()
        )?;
    }
    writeln!(out, "  ]")?;
    writeln!(out, "}}")
}

#[cfg(test)]
mod tests {
    use xtce_model::XtceDb;

    use super::{validate_db, write_json_metadata, write_text_report};
    use crate::pus::ECSS_PUS_XTCE_XML;

    #[test]
    fn valid_ecss_pus_definition_passes_with_zero_errors_and_static_codegen_ready() {
        let db = XtceDb::from_xml(ECSS_PUS_XTCE_XML).expect("loads");
        let report = validate_db(&db, None);

        assert_eq!(report.error_count(), 0);
        assert_eq!(report.compilable_containers, Some(9));

        let mut text = Vec::new();
        write_text_report(&mut text, &db, &report).expect("writes text");
        let text_str = String::from_utf8(text).expect("utf8");
        assert!(text_str.contains("0 error(s)"));
        assert!(text_str.contains("static-codegen ready (9 concrete container(s))"));

        let mut json = Vec::new();
        write_json_metadata(&mut json, &db, &report).expect("writes json");
        let json_str = String::from_utf8(json).expect("utf8");
        assert!(json_str.contains("\"static_codegen_ready\": true"));
        assert!(json_str.contains("\"TM_3_25_ObcHousekeeping\""));
    }
}
