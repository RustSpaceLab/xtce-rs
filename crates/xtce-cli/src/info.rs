//! `xtce info` — what a definition contains, and what this crate cannot decode in it.

use std::time::Duration;

use xtce_model::{ContainerId, EntryKind, MatchCriteria, SizeSpec, TypeKind, XtceDb};

pub fn report(db: &XtceDb, elapsed: Duration, verbose: bool) {
    let stats = db.stats();
    let source = db
        .source()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<memory>".to_owned());

    println!("{source}");
    println!(
        "  loaded in {:.3} ms{}",
        elapsed.as_secs_f64() * 1e3,
        db.xmlns()
            .map(|ns| format!("   namespace {ns}"))
            .unwrap_or_default()
    );

    print_tree(db);

    println!(
        "  {} space system(s), {} parameter(s), {} type(s), {} container(s) ({} abstract), {} entry(s)",
        stats.space_systems,
        stats.parameters,
        stats.parameter_types,
        stats.containers,
        stats.abstract_containers,
        stats.entries,
    );

    if stats.meta_commands > 0 {
        // Counted apart from the containers and parameters above, which already include a
        // command's packaging and its arguments: a telecommand *is* a container here, and
        // saying so twice would make the totals look wrong.
        let abstract_commands = db
            .meta_commands()
            .iter()
            .filter(|command| command.is_abstract)
            .count();
        let arguments: usize = db
            .meta_commands()
            .iter()
            .map(|command| command.arguments.len())
            .sum();
        println!(
            "  {} telecommand(s) ({abstract_commands} abstract), {arguments} argument(s), \
             counted among the containers and parameters above",
            stats.meta_commands,
        );
    }

    let (decodable, blocked) = classify_containers(db);
    println!(
        "  {decodable} container(s) fully decodable, {} blocked",
        blocked.len()
    );
    for (id, reason) in blocked.iter().take(if verbose { usize::MAX } else { 5 }) {
        let name = db
            .container(*id)
            .map(|container| db.name(container.qualified_name))
            .unwrap_or("?");
        println!("    blocked: {name} — {reason}");
    }
    if !verbose && blocked.len() > 5 {
        println!("    ... and {} more (use --verbose)", blocked.len() - 5);
    }

    if !db.skipped_sections().is_empty() {
        let mut sections = db.skipped_sections().to_vec();
        sections.sort_unstable();
        sections.dedup();
        println!(
            "  sections skipped as out of scope: {}",
            sections.join(", ")
        );
    }

    if !db.unsupported().is_empty() {
        println!(
            "  {} construct(s) represented but not decodable:",
            db.unsupported().len()
        );
        let limit = if verbose { usize::MAX } else { 10 };
        for item in db.unsupported().iter().take(limit) {
            println!("    <{}> at {} — {}", item.element, item.path, item.reason);
        }
        if !verbose && db.unsupported().len() > limit {
            println!(
                "    ... and {} more (use --verbose)",
                db.unsupported().len() - limit
            );
        }
    }

    if verbose {
        print_containers(db);
    }
    println!();
}

fn print_tree(db: &XtceDb) {
    for system in db.space_systems() {
        let depth = ancestor_depth(db, system);
        println!(
            "  {:indent$}{}",
            "",
            db.name(system.qualified_name),
            indent = depth * 2
        );
    }
}

fn ancestor_depth(db: &XtceDb, system: &xtce_model::SpaceSystem) -> usize {
    let mut depth = 0;
    let mut cursor = system.parent;
    while let Some(id) = cursor {
        depth += 1;
        cursor = db.space_system(id).and_then(|parent| parent.parent);
    }
    depth
}

/// Splits containers into those every entry of which can be decoded, and those blocked by an
/// out-of-scope construct — naming the construct.
///
/// This is more useful than a bare tree dump: it answers "how much of this file can you
/// actually decode", which is the question a mission database raises.
fn classify_containers(db: &XtceDb) -> (usize, Vec<(ContainerId, String)>) {
    let mut decodable = 0;
    let mut blocked = Vec::new();

    for (index, container) in db.containers().iter().enumerate() {
        let id = ContainerId::new(u32::try_from(index).unwrap_or(u32::MAX));
        let mut reason = None;

        for criteria in &container.restriction {
            if let MatchCriteria::Unsupported { element } = criteria {
                reason = Some(format!("restriction criteria use <{}>", db.name(*element)));
                break;
            }
        }

        if reason.is_none() {
            for entry in db.container_entries(id) {
                match entry.kind {
                    EntryKind::Unsupported { element } => {
                        reason = Some(format!("entry list contains <{}>", db.name(element)));
                        break;
                    }
                    // Bits the definition fixes. Nothing to decode and nothing that can
                    // make a container undecodable.
                    EntryKind::FixedValue { .. } => {}
                    EntryKind::Parameter(parameter) => {
                        let Some(ty) = db.type_of(parameter) else {
                            continue;
                        };
                        if let TypeKind::Unsupported { element } = ty.kind {
                            reason = Some(format!(
                                "{} has unsupported type <{}>",
                                db.parameter(parameter).map_or("?", |p| db.name(p.name)),
                                db.name(element)
                            ));
                            break;
                        }
                        if let Some(element) = unsupported_size(&ty.encoding) {
                            reason = Some(format!(
                                "{} has an unsupported size specifier <{}>",
                                db.parameter(parameter).map_or("?", |p| db.name(p.name)),
                                db.name(element)
                            ));
                            break;
                        }
                    }
                    EntryKind::Container(_) => {}
                }
            }
        }

        match reason {
            Some(reason) => blocked.push((id, reason)),
            None => decodable += 1,
        }
    }
    (decodable, blocked)
}

fn unsupported_size(encoding: &xtce_model::DataEncoding) -> Option<xtce_model::NameId> {
    let size = match encoding {
        xtce_model::DataEncoding::Binary(binary) => &binary.size,
        xtce_model::DataEncoding::String(string) => &string.raw_size,
        _ => return None,
    };
    match size {
        SizeSpec::Unsupported { element } => Some(*element),
        _ => None,
    }
}

fn print_containers(db: &XtceDb) {
    println!("  containers:");
    for (index, container) in db.containers().iter().enumerate() {
        let id = ContainerId::new(u32::try_from(index).unwrap_or(u32::MAX));
        let base = container
            .base
            .and_then(|base| db.container(base))
            .map(|base| format!(" extends {}", db.name(base.name)))
            .unwrap_or_default();
        println!(
            "    {}{}{}",
            db.name(container.name),
            if container.is_abstract {
                " (abstract)"
            } else {
                ""
            },
            base
        );
        for entry in db.container_entries(id) {
            match entry.kind {
                EntryKind::Parameter(parameter) => {
                    let Some(param) = db.parameter(parameter) else {
                        continue;
                    };
                    let ty = db.type_of(parameter);
                    let bits = ty
                        .and_then(xtce_model::ParameterType::fixed_size_in_bits)
                        .map(|bits| format!("{bits}b"))
                        .unwrap_or_else(|| "var".to_owned());
                    println!(
                        "      {:<28} {:<16} {}",
                        db.name(param.name),
                        ty.map_or("?", |ty| ty.kind.label()),
                        bits
                    );
                }
                EntryKind::Container(child) => {
                    let name = db.container(child).map_or("?", |c| db.name(c.name));
                    println!("      <container {name}>");
                }
                EntryKind::FixedValue {
                    value,
                    size_in_bits,
                } => {
                    let bytes = db.fixed_value(value);
                    let hex: String = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
                    println!("      {:<28} {:<16} {size_in_bits}b", "<fixed value>", hex);
                }
                EntryKind::Unsupported { element } => {
                    println!("      <unsupported {}>", db.name(element));
                }
            }
        }
    }
}
