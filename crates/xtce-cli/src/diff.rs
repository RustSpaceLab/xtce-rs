//! `xtce diff` — semantic comparison of two XTCE definitions at the canonical IR and layout level.
//!
//! Compares two mission definitions (`old` and `new`) and classifies every difference as:
//! - `BREAKING`: wire-format or decoding incompatibility (removed parameter/container, changed
//!   type family, bit width, signedness, byte order, removed/relabeled enumeration entry, or
//!   shifted bit offset inside a container).
//! - `WARNING`: backward-compatible extension that downstream consumers should review (added
//!   enumeration label, appended trailing field extending a container).
//! - `COMPATIBLE`: additive definition change that does not alter existing packet layouts
//!   (new standalone parameter or new container).

use std::collections::BTreeMap;
use std::io::Write;

use xtce_codegen::{ContainerPlan, Plan};
use xtce_model::{ByteOrder, DataEncoding, Parameter, ParameterType, TypeKind, XtceDb};

/// Classification of a semantic difference between two XTCE definitions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    /// Wire-format or decoding incompatibility.
    Breaking,
    /// Non-breaking change that may affect consumers (e.g. new enum variant or trailing field).
    Warning,
    /// Purely additive change.
    Compatible,
}

impl Severity {
    /// Short uppercase tag used in reports (`BREAKING`, `WARNING`, `COMPATIBLE`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Breaking => "BREAKING",
            Self::Warning => "WARNING",
            Self::Compatible => "COMPATIBLE",
        }
    }
}

/// One semantic change detected between two XTCE definitions.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Finding {
    pub severity: Severity,
    pub subject: String,
    pub detail: String,
}

/// Complete semantic diff report between two [`XtceDb`] definitions.
#[derive(Clone, Debug, Default)]
pub struct DiffReport {
    pub findings: Vec<Finding>,
    pub unchanged_parameters: usize,
    pub unchanged_containers: usize,
}

impl DiffReport {
    /// Number of `BREAKING` findings in the report.
    #[must_use]
    pub fn breaking_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Breaking)
            .count()
    }

    /// Number of `WARNING` findings in the report.
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count()
    }
}

/// Compares `old_db` and `new_db` at the canonical IR and flattened container layout levels.
#[must_use]
pub fn compare(old_db: &XtceDb, new_db: &XtceDb, root: Option<&str>) -> DiffReport {
    let mut report = DiffReport::default();

    compare_parameters(old_db, new_db, &mut report);
    compare_containers(old_db, new_db, root, &mut report);

    report
}

fn compare_parameters(old_db: &XtceDb, new_db: &XtceDb, report: &mut DiffReport) {
    let mut old_params: BTreeMap<&str, &Parameter> = BTreeMap::new();
    for p in old_db.parameters() {
        old_params.insert(old_db.name(p.name), p);
    }

    let mut new_params: BTreeMap<&str, &Parameter> = BTreeMap::new();
    for p in new_db.parameters() {
        new_params.insert(new_db.name(p.name), p);
    }

    for (&name, &old_p) in &old_params {
        if let Some(&new_p) = new_params.get(name) {
            let before = report.findings.len();
            diff_parameter_pair(name, old_db, old_p, new_db, new_p, &mut report.findings);
            if report.findings.len() == before {
                report.unchanged_parameters += 1;
            }
        } else {
            push_finding(
                &mut report.findings,
                Severity::Breaking,
                name,
                "parameter removed from definition",
            );
        }
    }

    for &name in new_params.keys() {
        if !old_params.contains_key(name) {
            push_finding(
                &mut report.findings,
                Severity::Compatible,
                name,
                "parameter added to definition",
            );
        }
    }
}

fn diff_parameter_pair(
    name: &str,
    old_db: &XtceDb,
    old_p: &Parameter,
    new_db: &XtceDb,
    new_p: &Parameter,
    findings: &mut Vec<Finding>,
) {
    let (Some(old_ty), Some(new_ty)) = (
        old_db.parameter_type(old_p.type_id),
        new_db.parameter_type(new_p.type_id),
    ) else {
        return;
    };

    let old_sig = type_signature(old_ty);
    let new_sig = type_signature(new_ty);
    if old_sig != new_sig {
        findings.push(Finding {
            severity: Severity::Breaking,
            subject: name.to_owned(),
            detail: format!("type changed: {old_sig} -> {new_sig}"),
        });
        return;
    }

    if let (TypeKind::Enumerated(old_enums), TypeKind::Enumerated(new_enums)) =
        (&old_ty.kind, &new_ty.kind)
    {
        diff_enumerations(name, old_db, old_enums, new_db, new_enums, findings);
    }
}

fn diff_enumerations(
    param_name: &str,
    old_db: &XtceDb,
    old_enums: &xtce_model::EnumerationList,
    new_db: &XtceDb,
    new_enums: &xtce_model::EnumerationList,
    findings: &mut Vec<Finding>,
) {
    let mut old_by_label: BTreeMap<&str, (i128, i128)> = BTreeMap::new();
    for item in old_enums.entries() {
        let label = old_db.name(item.label);
        old_by_label.insert(label, (item.value, item.max_value));
    }

    let mut new_by_label: BTreeMap<&str, (i128, i128)> = BTreeMap::new();
    for item in new_enums.entries() {
        let label = new_db.name(item.label);
        new_by_label.insert(label, (item.value, item.max_value));
    }

    for (&label, &(old_val, old_max)) in &old_by_label {
        match new_by_label.get(label) {
            None => push_enum_removed(findings, param_name, label),
            Some(&(new_val, new_max)) if (old_val, old_max) != (new_val, new_max) => {
                push_enum_revalued(findings, param_name, label, old_val, new_val);
            }
            Some(_) => {}
        }
    }

    for &label in new_by_label.keys() {
        if !old_by_label.contains_key(label) {
            push_enum_added(findings, param_name, label);
        }
    }
}

fn push_finding(findings: &mut Vec<Finding>, severity: Severity, subject: &str, detail: &str) {
    findings.push(Finding {
        severity,
        subject: subject.to_owned(),
        detail: detail.to_owned(),
    });
}

fn push_enum_removed(findings: &mut Vec<Finding>, param_name: &str, label: &str) {
    findings.push(Finding {
        severity: Severity::Breaking,
        subject: param_name.to_owned(),
        detail: format!("enum value removed: {label}"),
    });
}

fn push_enum_revalued(
    findings: &mut Vec<Finding>,
    param_name: &str,
    label: &str,
    old_val: i128,
    new_val: i128,
) {
    findings.push(Finding {
        severity: Severity::Breaking,
        subject: param_name.to_owned(),
        detail: format!("enum {label} value changed: {old_val} -> {new_val}"),
    });
}

fn push_enum_added(findings: &mut Vec<Finding>, param_name: &str, label: &str) {
    findings.push(Finding {
        severity: Severity::Warning,
        subject: param_name.to_owned(),
        detail: format!("enum value added: {label}"),
    });
}

fn type_signature(ty: &ParameterType) -> String {
    let family = ty.kind.label();
    let bits = ty
        .fixed_size_in_bits()
        .map_or_else(|| "var".to_owned(), |b| b.to_string());
    let byte_order = match &ty.encoding {
        DataEncoding::Integer(enc) => enc.byte_order,
        DataEncoding::Float(enc) => enc.byte_order,
        DataEncoding::String(enc) => enc.byte_order,
        DataEncoding::Binary(_) | DataEncoding::None => ByteOrder::MostSignificantFirst,
    };
    let order = match byte_order {
        ByteOrder::MostSignificantFirst => "be",
        ByteOrder::LeastSignificantFirst => "le",
    };
    let coding = match &ty.encoding {
        DataEncoding::Integer(int_enc) => match int_enc.coding {
            xtce_model::IntegerCoding::Unsigned => "uint",
            xtce_model::IntegerCoding::TwosComplement => "int-2c",
            xtce_model::IntegerCoding::OnesComplement => "int-1c",
            xtce_model::IntegerCoding::SignMagnitude => "int-sm",
        },
        DataEncoding::Float(_) => "float",
        DataEncoding::String(_) => "str",
        DataEncoding::Binary(_) => "bin",
        DataEncoding::None => family,
    };
    format!("{coding}{bits}({family},{order})")
}

fn compare_containers(
    old_db: &XtceDb,
    new_db: &XtceDb,
    root: Option<&str>,
    report: &mut DiffReport,
) {
    let opts = xtce_codegen::Options {
        root: root.map(str::to_owned),
        source_label: None,
    };
    let (Ok(old_plan), Ok(new_plan)) = (
        xtce_codegen::plan(old_db, &opts),
        xtce_codegen::plan(new_db, &opts),
    ) else {
        return;
    };

    diff_plans(&old_plan, &new_plan, report);
}

fn diff_plans(old_plan: &Plan, new_plan: &Plan, report: &mut DiffReport) {
    let mut old_containers: BTreeMap<&str, &ContainerPlan> = BTreeMap::new();
    for c in &old_plan.containers {
        old_containers.insert(c.xtce_name.as_str(), c);
    }

    let mut new_containers: BTreeMap<&str, &ContainerPlan> = BTreeMap::new();
    for c in &new_plan.containers {
        new_containers.insert(c.xtce_name.as_str(), c);
    }

    for (&name, &old_c) in &old_containers {
        if let Some(&new_c) = new_containers.get(name) {
            let before = report.findings.len();
            diff_container_pair(name, old_c, new_c, &mut report.findings);
            if report.findings.len() == before {
                report.unchanged_containers += 1;
            }
        } else {
            push_finding(
                &mut report.findings,
                Severity::Breaking,
                name,
                "container removed from definition",
            );
        }
    }

    for &name in new_containers.keys() {
        if !old_containers.contains_key(name) {
            push_finding(
                &mut report.findings,
                Severity::Compatible,
                name,
                "container added to definition",
            );
        }
    }
}

fn diff_container_pair(
    container_name: &str,
    old_c: &ContainerPlan,
    new_c: &ContainerPlan,
    findings: &mut Vec<Finding>,
) {
    let mut old_fields: BTreeMap<&str, (Option<usize>, Option<u32>)> = BTreeMap::new();
    for f in &old_c.fields {
        old_fields.insert(f.xtce_name.as_str(), (f.bit_offset, f.width.fixed()));
    }

    let mut new_fields: BTreeMap<&str, (Option<usize>, Option<u32>)> = BTreeMap::new();
    for f in &new_c.fields {
        new_fields.insert(f.xtce_name.as_str(), (f.bit_offset, f.width.fixed()));
    }

    for (&field_name, &(old_off, old_w)) in &old_fields {
        match new_fields.get(field_name) {
            None => push_field_removed(findings, container_name, field_name),
            Some(&(new_off, new_w)) => {
                if old_off != new_off {
                    push_offset_changed(findings, container_name, field_name, old_off, new_off);
                }
                if old_w != new_w {
                    push_width_changed(findings, container_name, field_name, old_w, new_w);
                }
            }
        }
    }

    for (&field_name, &(new_off, _)) in &new_fields {
        if !old_fields.contains_key(field_name) {
            push_field_added(findings, container_name, field_name, new_off);
        }
    }
}

fn push_field_removed(findings: &mut Vec<Finding>, container: &str, field: &str) {
    findings.push(Finding {
        severity: Severity::Breaking,
        subject: container.to_owned(),
        detail: format!("field {field} removed from container"),
    });
}

fn push_offset_changed(
    findings: &mut Vec<Finding>,
    container: &str,
    field: &str,
    old_off: Option<usize>,
    new_off: Option<usize>,
) {
    findings.push(Finding {
        severity: Severity::Breaking,
        subject: container.to_owned(),
        detail: format!(
            "field {field} bit offset changed: {} -> {}",
            old_off.map_or_else(|| "dynamic".to_owned(), |v| v.to_string()),
            new_off.map_or_else(|| "dynamic".to_owned(), |v| v.to_string())
        ),
    });
}

fn push_width_changed(
    findings: &mut Vec<Finding>,
    container: &str,
    field: &str,
    old_w: Option<u32>,
    new_w: Option<u32>,
) {
    findings.push(Finding {
        severity: Severity::Breaking,
        subject: container.to_owned(),
        detail: format!(
            "field {field} bit width changed: {} -> {}",
            old_w.map_or_else(|| "dynamic".to_owned(), |v| v.to_string()),
            new_w.map_or_else(|| "dynamic".to_owned(), |v| v.to_string())
        ),
    });
}

fn push_field_added(
    findings: &mut Vec<Finding>,
    container: &str,
    field: &str,
    new_off: Option<usize>,
) {
    findings.push(Finding {
        severity: Severity::Warning,
        subject: container.to_owned(),
        detail: format!(
            "field {field} added to container at bit {}",
            new_off.map_or_else(|| "dynamic".to_owned(), |v| v.to_string())
        ),
    });
}

/// CLI options for `xtce diff`.
pub struct Options<'a> {
    pub root: Option<&'a str>,
    pub fail_on_breaking: bool,
}

/// Runs `xtce diff` against `old_db` and `new_db` and prints the report to standard output.
///
/// # Errors
///
/// Returns an error if I/O fails or if `fail_on_breaking` is set and breaking changes exist.
pub fn run(
    old_db: &XtceDb,
    new_db: &XtceDb,
    opts: &Options<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let report = compare(old_db, new_db, opts.root);
    let mut stdout = std::io::stdout().lock();
    write_text_report(&mut stdout, &report)?;
    if opts.fail_on_breaking && report.breaking_count() > 0 {
        return Err(format!(
            "detected {} breaking change(s) between definitions",
            report.breaking_count()
        )
        .into());
    }
    Ok(())
}

/// Writes a human-readable semantic diff report to `out`.
///
/// # Errors
///
/// Returns an I/O error if writing to `out` fails.
pub fn write_text_report(out: &mut impl Write, report: &DiffReport) -> std::io::Result<()> {
    for finding in &report.findings {
        writeln!(out, "{} {}", finding.severity.label(), finding.subject)?;
        writeln!(out, "  {}\n", finding.detail)?;
    }
    writeln!(
        out,
        "OK {} parameter(s) unchanged, {} container(s) unchanged ({} breaking, {} warning)",
        report.unchanged_parameters,
        report.unchanged_containers,
        report.breaking_count(),
        report.warning_count()
    )
}

#[cfg(test)]
mod tests {
    use xtce_model::XtceDb;

    use super::{Severity, compare, write_text_report};

    const V1_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<xtce:SpaceSystem name="Sat" xmlns:xtce="http://www.omg.org/spec/XTCE/20180204">
  <xtce:TelemetryMetaData>
    <xtce:ParameterTypeSet>
      <xtce:IntegerParameterType name="U16_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="16" encoding="unsigned"/>
      </xtce:IntegerParameterType>
      <xtce:EnumeratedParameterType name="MODE_T">
        <xtce:IntegerDataEncoding sizeInBits="8" encoding="unsigned"/>
        <xtce:EnumerationList>
          <xtce:Enumeration value="0" label="IDLE"/>
          <xtce:Enumeration value="1" label="NOMINAL"/>
        </xtce:EnumerationList>
      </xtce:EnumeratedParameterType>
    </xtce:ParameterTypeSet>
    <xtce:ParameterSet>
      <xtce:Parameter name="BATTERY_VOLTAGE" parameterTypeRef="U16_T"/>
      <xtce:Parameter name="SATELLITE_MODE" parameterTypeRef="MODE_T"/>
      <xtce:Parameter name="POWER_STATUS" parameterTypeRef="U16_T"/>
    </xtce:ParameterSet>
    <xtce:ContainerSet>
      <xtce:SequenceContainer name="CCSDSPacket">
        <xtce:EntryList>
          <xtce:ParameterRefEntry parameterRef="BATTERY_VOLTAGE"/>
          <xtce:ParameterRefEntry parameterRef="SATELLITE_MODE"/>
          <xtce:ParameterRefEntry parameterRef="POWER_STATUS"/>
        </xtce:EntryList>
      </xtce:SequenceContainer>
    </xtce:ContainerSet>
  </xtce:TelemetryMetaData>
</xtce:SpaceSystem>"#;

    const V2_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<xtce:SpaceSystem name="Sat" xmlns:xtce="http://www.omg.org/spec/XTCE/20180204">
  <xtce:TelemetryMetaData>
    <xtce:ParameterTypeSet>
      <xtce:FloatParameterType name="F32_T" sizeInBits="32">
        <xtce:FloatDataEncoding sizeInBits="32" encoding="IEEE754_1985"/>
      </xtce:FloatParameterType>
      <xtce:IntegerParameterType name="U16_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="16" encoding="unsigned"/>
      </xtce:IntegerParameterType>
      <xtce:EnumeratedParameterType name="MODE_T">
        <xtce:IntegerDataEncoding sizeInBits="8" encoding="unsigned"/>
        <xtce:EnumerationList>
          <xtce:Enumeration value="0" label="IDLE"/>
          <xtce:Enumeration value="1" label="NOMINAL"/>
          <xtce:Enumeration value="2" label="SAFE_MODE"/>
        </xtce:EnumerationList>
      </xtce:EnumeratedParameterType>
    </xtce:ParameterTypeSet>
    <xtce:ParameterSet>
      <xtce:Parameter name="BATTERY_VOLTAGE" parameterTypeRef="F32_T"/>
      <xtce:Parameter name="SATELLITE_MODE" parameterTypeRef="MODE_T"/>
      <xtce:Parameter name="POWER_STATUS" parameterTypeRef="U16_T"/>
    </xtce:ParameterSet>
    <xtce:ContainerSet>
      <xtce:SequenceContainer name="CCSDSPacket">
        <xtce:EntryList>
          <xtce:ParameterRefEntry parameterRef="BATTERY_VOLTAGE"/>
          <xtce:ParameterRefEntry parameterRef="SATELLITE_MODE"/>
          <xtce:ParameterRefEntry parameterRef="POWER_STATUS"/>
        </xtce:EntryList>
      </xtce:SequenceContainer>
    </xtce:ContainerSet>
  </xtce:TelemetryMetaData>
</xtce:SpaceSystem>"#;

    #[test]
    fn identical_definitions_report_zero_findings() {
        let db1 = XtceDb::from_xml(V1_XML).expect("v1 loads");
        let db2 = XtceDb::from_xml(V1_XML).expect("v1 copy loads");
        let report = compare(&db1, &db2, None);

        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.unchanged_parameters, 3);
        assert_eq!(report.unchanged_containers, 1);
    }

    #[test]
    fn detects_breaking_type_and_offset_shifts_and_warning_enum_addition() {
        let db1 = XtceDb::from_xml(V1_XML).expect("v1 loads");
        let db2 = XtceDb::from_xml(V2_XML).expect("v2 loads");
        let report = compare(&db1, &db2, None);

        assert!(report.breaking_count() >= 2);
        assert!(report.warning_count() >= 1);

        let mut buf = Vec::new();
        write_text_report(&mut buf, &report).expect("writes report");
        let text = String::from_utf8(buf).expect("utf8");

        assert!(text.contains("BREAKING BATTERY_VOLTAGE"));
        assert!(text.contains("type changed: uint16(integer,be) -> float32(float,be)"));
        assert!(text.contains("WARNING SATELLITE_MODE"));
        assert!(text.contains("enum value added: SAFE_MODE"));
        assert!(text.contains("BREAKING CCSDSPacket"));
        assert!(text.contains("field POWER_STATUS bit offset changed: 24 -> 40"));
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.severity == Severity::Breaking && f.subject == "BATTERY_VOLTAGE")
        );
    }
}
