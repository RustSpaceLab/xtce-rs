//! `xtce lsp` — Language Server Protocol (LSP) server for OMG XTCE 1.2 XML mission databases.
//!
//! Speaks standard JSON-RPC 2.0 over `stdin`/`stdout` with `Content-Length` framing and provides
//! real-time IDE intelligence for spacecraft engineers editing large XTCE 1.2 definitions in
//! VS Code, RustRover, Neovim, or Helix:
//! - `textDocument/didOpen`, `textDocument/didChange`, `textDocument/didSave`: parses the XML
//!   buffer into an [`XtceDb`], validates container inheritance, bit-layout compilability, and
//!   dangling references, and publishes `textDocument/publishDiagnostics`.
//! - `textDocument/hover`: resolves the identifier or attribute value under the cursor against
//!   parameters, parameter types, sequence containers, and telecommands, rendering a Markdown
//!   card with type signature, bit width, byte order, calibration, and container bit offsets.
//! - `textDocument/definition`: jumps to the line and column where the referenced
//!   `<Parameter>`, `<*ParameterType>`, `<SequenceContainer>`, or `<MetaCommand>` is defined.
//! - `textDocument/documentSymbol`: populates the IDE outline tree with all containers,
//!   parameters, and telecommands.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};

use xtce_model::{ByteOrder, DataEncoding, TypeKind, XtceDb};

use crate::validate::{self, Level};

/// Maximum LSP message payload size accepted from `stdin` (32 MiB) to prevent unbounded allocation.
const MAX_LSP_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Cached document buffer with precomputed line-start byte offsets for O(1) line lookup.
#[derive(Default)]
struct CachedDocument {
    text: String,
    line_starts: Vec<usize>,
}

impl CachedDocument {
    fn new(text: String) -> Self {
        let mut line_starts = vec![0];
        for (idx, b) in text.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(idx + 1);
            }
        }
        Self { text, line_starts }
    }

    fn line_slice(&self, line: usize) -> Option<&str> {
        let start = *self.line_starts.get(line)?;
        let end = self
            .line_starts
            .get(line + 1)
            .map_or(self.text.len(), |next| next.saturating_sub(1));
        let slice = self.text.get(start..end)?;
        Some(slice.strip_suffix('\r').unwrap_or(slice))
    }
}

/// In-memory state of the XTCE Language Server.
#[derive(Default)]
pub struct LspServer {
    documents: BTreeMap<String, CachedDocument>,
    shutdown_requested: bool,
}

/// Runs the `xtce lsp` JSON-RPC 2.0 loop over standard input and standard output.
///
/// # Errors
///
/// Returns an error if reading from standard input or writing to standard output fails.
pub fn run_stdio() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    let mut server = LspServer::default();
    server.serve(&mut reader, &mut writer)
}

impl LspServer {
    /// Processes framed JSON-RPC messages from `reader` and writes responses/notifications to `out`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if stream reading or writing fails.
    pub fn serve(
        &mut self,
        reader: &mut impl BufRead,
        out: &mut impl Write,
    ) -> Result<(), Box<dyn std::error::Error>> {
        while let Some(body) = read_lsp_frame(reader)? {
            let should_exit = self.handle_message(&body, out)?;
            out.flush()?;
            if should_exit {
                break;
            }
        }
        Ok(())
    }

    fn handle_message(&mut self, body: &str, out: &mut impl Write) -> std::io::Result<bool> {
        let Some(method) = extract_json_str(body, "method") else {
            return Ok(false);
        };
        let id_raw = extract_json_id(body);

        match method.as_str() {
            "initialize" => {
                if let Some(id) = id_raw {
                    let result = r#"{"capabilities":{"textDocumentSync":1,"hoverProvider":true,"definitionProvider":true,"documentSymbolProvider":true},"serverInfo":{"name":"xtce-lsp","version":"0.2.2"}}"#;
                    write_rpc_result(out, &id, result)?;
                }
            }
            "initialized" => {}
            "shutdown" => {
                self.shutdown_requested = true;
                if let Some(id) = id_raw {
                    write_rpc_result(out, &id, "null")?;
                }
            }
            "exit" => return Ok(true),
            "textDocument/didOpen" | "textDocument/didChange" => {
                if let Some(uri) = extract_json_str(body, "uri") {
                    if let Some(text) = extract_json_str(body, "text") {
                        let diag_json = build_diagnostics_notification(&uri, &text);
                        self.documents.insert(uri, CachedDocument::new(text));
                        write_lsp_frame(out, &diag_json)?;
                    }
                }
            }
            "textDocument/hover" => {
                if let Some(id) = id_raw {
                    let resp = self.handle_hover(body);
                    write_rpc_result(out, &id, &resp)?;
                }
            }
            "textDocument/definition" => {
                if let Some(id) = id_raw {
                    let resp = self.handle_definition(body);
                    write_rpc_result(out, &id, &resp)?;
                }
            }
            "textDocument/documentSymbol" => {
                if let Some(id) = id_raw {
                    let resp = self.handle_document_symbols(body);
                    write_rpc_result(out, &id, &resp)?;
                }
            }
            _ => {
                if let Some(id) = id_raw {
                    write_rpc_result(out, &id, "null")?;
                }
            }
        }
        Ok(false)
    }

    fn handle_hover(&self, body: &str) -> String {
        let Some(uri) = extract_json_str(body, "uri") else {
            return "null".to_owned();
        };
        let Some(doc) = self.documents.get(&uri) else {
            return "null".to_owned();
        };
        let line = extract_json_usize(body, "line").unwrap_or(0);
        let character = extract_json_usize(body, "character").unwrap_or(0);

        let Some(line_str) = doc.line_slice(line) else {
            return "null".to_owned();
        };
        let Some(token) = word_in_line_utf16(line_str, character) else {
            return "null".to_owned();
        };
        let Ok(db) = XtceDb::from_xml(&doc.text) else {
            return "null".to_owned();
        };
        let Some(markdown) = build_hover_markdown(&db, token) else {
            return "null".to_owned();
        };

        let mut escaped = String::with_capacity(markdown.len() + 32);
        escape_json_into(&markdown, &mut escaped);
        format!(r#"{{"contents":{{"kind":"markdown","value":"{escaped}"}}}}"#)
    }

    fn handle_definition(&self, body: &str) -> String {
        let Some(uri) = extract_json_str(body, "uri") else {
            return "null".to_owned();
        };
        let Some(doc) = self.documents.get(&uri) else {
            return "null".to_owned();
        };
        let line = extract_json_usize(body, "line").unwrap_or(0);
        let character = extract_json_usize(body, "character").unwrap_or(0);

        let Some(line_str) = doc.line_slice(line) else {
            return "null".to_owned();
        };
        let Some(token) = word_in_line_utf16(line_str, character) else {
            return "null".to_owned();
        };
        let Some((def_line, def_col)) = find_xml_definition_line(&doc.text, token) else {
            return "null".to_owned();
        };

        let mut uri_esc = String::with_capacity(uri.len());
        escape_json_into(&uri, &mut uri_esc);
        let end_col = def_col + token.len();
        format!(
            r#"{{"uri":"{uri_esc}","range":{{"start":{{"line":{def_line},"character":{def_col}}},"end":{{"line":{def_line},"character":{end_col}}}}}}}"#
        )
    }

    fn handle_document_symbols(&self, body: &str) -> String {
        let Some(uri) = extract_json_str(body, "uri") else {
            return "[]".to_owned();
        };
        let Some(doc) = self.documents.get(&uri) else {
            return "[]".to_owned();
        };
        let Ok(db) = XtceDb::from_xml(&doc.text) else {
            return "[]".to_owned();
        };

        let mut out = String::with_capacity(2048);
        out.push('[');
        let mut first = true;

        for c in db.containers() {
            let name = db.name(c.name);
            let (line, col) = find_xml_definition_line(&doc.text, name).unwrap_or((0, 0));
            append_symbol_json(&mut out, &mut first, name, 23, line, col);
        }
        for p in db.parameters() {
            let name = db.name(p.name);
            let (line, col) = find_xml_definition_line(&doc.text, name).unwrap_or((0, 0));
            append_symbol_json(&mut out, &mut first, name, 8, line, col);
        }
        for cmd in db.meta_commands() {
            let name = db.name(cmd.name);
            let (line, col) = find_xml_definition_line(&doc.text, name).unwrap_or((0, 0));
            append_symbol_json(&mut out, &mut first, name, 12, line, col);
        }

        out.push(']');
        out
    }
}

fn append_symbol_json(
    out: &mut String,
    first: &mut bool,
    name: &str,
    kind: u8,
    line: usize,
    col: usize,
) {
    if !*first {
        out.push(',');
    }
    *first = false;
    out.push_str(r#"{"name":""#);
    escape_json_into(name, out);
    let end_col = col + name.len();
    let _ = write!(
        out,
        r#"","kind":{kind},"range":{{"start":{{"line":{line},"character":{col}}},"end":{{"line":{line},"character":{end_col}}}}},"selectionRange":{{"start":{{"line":{line},"character":{col}}},"end":{{"line":{line},"character":{end_col}}}}}}}"#
    );
}

/// Builds markdown documentation for a parameter, parameter type, container, or telecommand.
#[must_use]
pub fn build_hover_markdown(db: &XtceDb, symbol: &str) -> Option<String> {
    let mut md = String::with_capacity(512);

    if let Some(param_id) = db.find_parameter(symbol) {
        let param = db.parameter(param_id)?;
        let p_name = db.name(param.name);
        let q_name = db.name(param.qualified_name);
        let _ = writeln!(md, "### Parameter `{p_name}`\n");
        let _ = writeln!(md, "- **Qualified Path:** `{q_name}`");
        if let Some(desc) = param.short_description {
            let _ = writeln!(md, "- **Description:** {}", db.name(desc));
        }
        if let Some(ty) = db.parameter_type(param.type_id) {
            append_type_details(db, ty, &mut md);
        }
        return Some(md);
    }

    if let Some(container_id) = db.find_container(symbol) {
        let container = db.container(container_id)?;
        let c_name = db.name(container.name);
        let q_name = db.name(container.qualified_name);
        let kind = if container.is_abstract {
            "Abstract SequenceContainer"
        } else if container.is_command {
            "CommandContainer"
        } else {
            "Concrete SequenceContainer"
        };
        let _ = writeln!(md, "### {kind} `{c_name}`\n");
        let _ = writeln!(md, "- **Qualified Path:** `{q_name}`");
        if let Some(base_id) = container.base {
            if let Some(base) = db.container(base_id) {
                let _ = writeln!(md, "- **Extends:** `{}`", db.name(base.name));
            }
        }
        let _ = writeln!(md, "- **Direct Entries:** {}", container.entries.len());
        let _ = writeln!(md, "- **Inheritors:** {}", container.inheritors.len());
        return Some(md);
    }

    if let Some(type_id) = db.find_type(symbol) {
        let ty = db.parameter_type(type_id)?;
        let t_name = db.name(ty.name);
        let _ = writeln!(md, "### ParameterType `{t_name}`\n");
        append_type_details(db, ty, &mut md);
        return Some(md);
    }

    if let Some(cmd_id) = db.find_meta_command(symbol) {
        let cmd = db.meta_command(cmd_id)?;
        let c_name = db.name(cmd.name);
        let _ = writeln!(md, "### MetaCommand `{c_name}`\n");
        let _ = writeln!(md, "- **Abstract:** `{}`", cmd.is_abstract);
        let _ = writeln!(md, "- **Arguments:** {}", cmd.arguments.len());
        return Some(md);
    }

    None
}

fn append_type_details(db: &XtceDb, ty: &xtce_model::ParameterType, md: &mut String) {
    let _ = writeln!(
        md,
        "- **Type:** `{}` (`{}`)",
        db.name(ty.name),
        ty.kind.label()
    );
    if let Some(bits) = ty.fixed_size_in_bits() {
        let _ = writeln!(md, "- **Size:** `{bits}` bits");
    } else {
        let _ = writeln!(md, "- **Size:** dynamic / variable");
    }
    let order = match &ty.encoding {
        DataEncoding::Integer(enc) => Some(enc.byte_order),
        DataEncoding::Float(enc) => Some(enc.byte_order),
        DataEncoding::String(enc) => Some(enc.byte_order),
        DataEncoding::Binary(_) | DataEncoding::None => None,
    };
    if let Some(bo) = order {
        let label = match bo {
            ByteOrder::MostSignificantFirst => "mostSignificantByteFirst (Big-Endian)",
            ByteOrder::LeastSignificantFirst => "leastSignificantByteFirst (Little-Endian)",
        };
        let _ = writeln!(md, "- **Byte Order:** `{label}`");
    }
    if let TypeKind::Enumerated(enums) = &ty.kind {
        let _ = writeln!(md, "- **Enumerations:** {} items", enums.entries().len());
    }
}

fn build_diagnostics_notification(uri: &str, xml_text: &str) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str(
        r#"{"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{"uri":""#,
    );
    escape_json_into(uri, &mut out);
    out.push_str(r#"","diagnostics":["#);

    match XtceDb::from_xml(xml_text) {
        Ok(db) => {
            let report = validate::validate_db(&db, None);
            for (idx, diag) in report.diagnostics.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                let severity = match diag.level {
                    Level::Error => 1,
                    Level::Warning => 2,
                };
                let (line, col) =
                    find_xml_definition_line(xml_text, &diag.subject).unwrap_or((0, 0));
                append_diagnostic_entry(
                    &mut out,
                    line,
                    col,
                    severity,
                    &diag.subject,
                    &diag.message,
                );
            }
        }
        Err(err) => {
            let msg = err.to_string();
            append_diagnostic_entry(&mut out, 0, 0, 1, "xtce-model", &msg);
        }
    }

    out.push_str("]}}");
    out
}

fn append_diagnostic_entry(
    out: &mut String,
    line: usize,
    col: usize,
    severity: u8,
    subject: &str,
    message: &str,
) {
    let _ = write!(
        out,
        r#"{{"range":{{"start":{{"line":{line},"character":{col}}},"end":{{"line":{line},"character":{}}}}},"severity":{severity},"source":"xtce-lsp","message":""#,
        col + subject.len().max(1)
    );
    escape_json_into(subject, out);
    out.push_str(": ");
    escape_json_into(message, out);
    out.push_str(r#""}"#);
}

/// Finds the 0-based `(line, column)` where `name="symbol"` appears in `xml_text`.
#[must_use]
pub fn find_xml_definition_line(xml_text: &str, symbol: &str) -> Option<(usize, usize)> {
    let leaf = symbol.rsplit('/').next().unwrap_or(symbol);
    let needle = format!(r#"name="{leaf}""#);
    for (line_idx, line_str) in xml_text.lines().enumerate() {
        if let Some(pos) = line_str.find(&needle) {
            return Some((line_idx, pos + 6));
        }
    }
    None
}

fn word_in_line_utf16(target_line: &str, character_utf16: usize) -> Option<&str> {
    if target_line.is_empty() {
        return None;
    }
    let mut utf16_col = 0usize;
    let mut target_byte_idx = None;
    for (byte_idx, ch) in target_line.char_indices() {
        let ch_utf16_len = ch.len_utf16();
        if character_utf16 >= utf16_col && character_utf16 < utf16_col + ch_utf16_len {
            target_byte_idx = Some(byte_idx);
            break;
        }
        utf16_col += ch_utf16_len;
    }
    let idx = target_byte_idx?;
    let bytes = target_line.as_bytes();
    if !is_ident_byte(*bytes.get(idx)?) {
        return None;
    }
    let mut start = idx;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = idx;
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    target_line.get(start..end)
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b'/'
}

fn read_lsp_frame(reader: &mut impl BufRead) -> std::io::Result<Option<String>> {
    let mut content_length: Option<usize> = None;
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("Content-Length:") {
            content_length = rest.trim().parse::<usize>().ok();
        } else if let Some(rest) = trimmed.strip_prefix("content-length:") {
            content_length = rest.trim().parse::<usize>().ok();
        }
    }

    let Some(len) = content_length else {
        return Ok(None);
    };
    if len > MAX_LSP_BODY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "LSP frame exceeds MAX_LSP_BODY_BYTES (32 MiB)",
        ));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    String::from_utf8(buf)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn write_lsp_frame(out: &mut impl Write, json_body: &str) -> std::io::Result<()> {
    write!(
        out,
        "Content-Length: {}\r\n\r\n{json_body}",
        json_body.len()
    )
}

fn write_rpc_result(out: &mut impl Write, id_raw: &str, result_json: &str) -> std::io::Result<()> {
    let body = format!(r#"{{"jsonrpc":"2.0","id":{id_raw},"result":{result_json}}}"#);
    write_lsp_frame(out, &body)
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let pattern = format!(r#""{key}""#);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json.get(start..)?.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;

    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(ch) = chars.next() {
        if ch == '"' {
            return Some(out);
        }
        if ch == '\\' {
            match chars.next()? {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                other => out.push(other),
            }
        } else {
            out.push(ch);
        }
    }
    None
}

fn extract_json_usize(json: &str, key: &str) -> Option<usize> {
    let pattern = format!(r#""{key}""#);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json.get(start..)?.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse::<usize>().ok()
}

fn extract_json_id(json: &str) -> Option<String> {
    let start = json.find(r#""id""#)? + 4;
    let rest = json.get(start..)?.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    if rest.starts_with('"') {
        let end = rest.get(1..)?.find('"')? + 2;
        return rest.get(..end).map(str::to_owned);
    }
    let digits: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    if digits.is_empty() {
        None
    } else {
        Some(digits)
    }
}

fn escape_json_into(input: &str, out: &mut String) {
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use xtce_model::XtceDb;

    use super::{LspServer, build_hover_markdown, find_xml_definition_line};
    use crate::pus::ECSS_PUS_XTCE_XML;

    fn frame(json: &str) -> String {
        format!("Content-Length: {}\r\n\r\n{json}", json.len())
    }

    #[test]
    fn hover_and_definition_resolve_ecss_pus_parameters_and_containers() {
        let db = XtceDb::from_xml(ECSS_PUS_XTCE_XML).expect("loads ECSS PUS XTCE");

        let hover_param = build_hover_markdown(&db, "OBC_VBUS_V").expect("hover for OBC_VBUS_V");
        assert!(hover_param.contains("### Parameter `OBC_VBUS_V`"));
        assert!(hover_param.contains("`16` bits"));

        let hover_cont = build_hover_markdown(&db, "TM_3_25_ObcHousekeeping")
            .expect("hover for TM_3_25_ObcHousekeeping");
        assert!(hover_cont.contains("Concrete SequenceContainer `TM_3_25_ObcHousekeeping`"));
        assert!(hover_cont.contains("Extends:** `CCSDSPacket`"));

        let (line, col) =
            find_xml_definition_line(ECSS_PUS_XTCE_XML, "TM_3_25_ObcHousekeeping").expect("found");
        assert!(line > 10);
        assert!(col > 0);
    }

    #[test]
    fn lsp_server_handles_initialize_did_open_hover_and_exit() {
        let xml = r#"<SpaceSystem name="Sat"><TelemetryMetaData><ParameterTypeSet><IntegerParameterType name="U16"><IntegerDataEncoding sizeInBits="16" encoding="unsigned"/></IntegerParameterType></ParameterTypeSet><ParameterSet><Parameter name="VBUS" parameterTypeRef="U16"/></ParameterSet><ContainerSet><SequenceContainer name="CCSDSPacket"><EntryList><ParameterRefEntry parameterRef="VBUS"/></EntryList></SequenceContainer></ContainerSet></TelemetryMetaData></SpaceSystem>"#;
        let vbus_col = xml.find("VBUS").expect("VBUS in xml");
        let mut xml_escaped = String::new();
        super::escape_json_into(xml, &mut xml_escaped);

        let mut input = String::new();
        input.push_str(&frame(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        ));
        input.push_str(&frame(&format!(
            r#"{{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{{"textDocument":{{"uri":"file:///mission.xml","text":"{xml_escaped}"}}}}}}"#
        )));
        input.push_str(&frame(&format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"textDocument/hover","params":{{"textDocument":{{"uri":"file:///mission.xml"}},"position":{{"line":0,"character":{vbus_col}}}}}}}"#
        )));
        input.push_str(&frame(r#"{"jsonrpc":"2.0","id":3,"method":"shutdown"}"#));
        input.push_str(&frame(r#"{"jsonrpc":"2.0","method":"exit"}"#));

        let mut reader = Cursor::new(input.into_bytes());
        let mut output = Vec::new();
        let mut server = LspServer::default();
        server.serve(&mut reader, &mut output).expect("LSP session");

        let out_str = String::from_utf8(output).expect("utf8");
        assert!(out_str.contains(r#""name":"xtce-lsp""#));
        assert!(out_str.contains(r#""method":"textDocument/publishDiagnostics""#));
        assert!(out_str.contains("Parameter `VBUS`"));
    }

    #[test]
    fn word_in_line_utf16_handles_multibyte_and_edge_cases() {
        let line = r#"<!-- 🛰️ komentarz --> <Parameter name="OBC_VBUS_V" parameterTypeRef="U16"/>"#;
        // "<!-- " is 5 UTF-16 units, "🛰️" is 3 UTF-16 units (surrogate pair + VS16), " komentarz --> <Parameter name=\"" is 32 UTF-16 units => 40
        let word = super::word_in_line_utf16(line, 43);
        assert_eq!(word, Some("OBC_VBUS_V"));
        assert!(super::word_in_line_utf16(line, 21).is_none());
        assert!(super::word_in_line_utf16("", 0).is_none());
        assert!(super::word_in_line_utf16(line, 999).is_none());
    }
}
