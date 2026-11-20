//! Client-side WebAssembly (`wasm32-unknown-unknown`) XTCE 1.2 & ECSS-E-ST-70-41C (PUS-C)
//! telemetry, PCAP, and mission database inspector.
//!
//! This crate compiles to a pure, zero-bindgen-CLI `cdylib` targeting `wasm32-unknown-unknown`
//! with raw C-ABI exports and linear-memory helpers so any browser or WebAssembly runtime can
//! inspect XTCE 1.2 XML definitions, decode raw CCSDS / ECSS PUS-C streams or Wireshark `.pcap`
//! captures, and generate deterministic fault-injection telemetry streams entirely in the browser
//! with zero server uploads.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::todo, clippy::unimplemented)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::too_many_lines
)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::alloc::{Layout, alloc, dealloc};
use std::cell::RefCell;
use std::fmt::Write as _;

use xtce_decode::{DecodeError, Decoder, PacketIter, SpacePacketBytes};
use xtce_model::{TypeKind, XtceDb};
use xtce_pus::{
    CucTimestamp, MAX_HIL_FRAME_LEN, ObcHousekeeping, PusHeader, PusPacket, TmParams, encode_tm,
    verify_crc16_ccitt,
};

thread_local! {
    static RESULT_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn store_result(bytes: Vec<u8>) {
    RESULT_BUF.with(|cell| {
        *cell.borrow_mut() = bytes;
    });
}

fn store_json_error(msg: &str) -> i32 {
    let mut out = String::with_capacity(msg.len() + 32);
    out.push_str("{\"ok\":false,\"error\":");
    push_json_str(&mut out, msg);
    out.push('}');
    store_result(out.into_bytes());
    1
}

/// Allocates `len` bytes in WebAssembly linear memory and returns a pointer for the host to write to.
#[unsafe(no_mangle)]
pub extern "C" fn wasm_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return std::ptr::null_mut();
    }
    let Ok(layout) = Layout::from_size_align(len, 1) else {
        return std::ptr::null_mut();
    };
    // SAFETY: `layout` has non-zero size (`len > 0`) and alignment 1.
    unsafe { alloc(layout) }
}

/// Frees a buffer previously allocated by [`wasm_alloc`].
///
/// # Safety
///
/// `ptr` must have been returned by [`wasm_alloc`] with the exact same `len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    if let Ok(layout) = Layout::from_size_align(len, 1) {
        // SAFETY: Caller guarantees `ptr` was allocated via `wasm_alloc(len)`.
        unsafe {
            dealloc(ptr, layout);
        }
    }
}

/// Returns a pointer to the latest result buffer (JSON UTF-8 or binary stream) in linear memory.
#[unsafe(no_mangle)]
pub extern "C" fn wasm_result_ptr() -> *const u8 {
    RESULT_BUF.with(|cell| cell.borrow().as_ptr())
}

/// Returns the byte length of the latest result buffer in linear memory.
#[unsafe(no_mangle)]
pub extern "C" fn wasm_result_len() -> usize {
    RESULT_BUF.with(|cell| cell.borrow().len())
}

/// Inspects an XTCE 1.2 XML document in memory and writes a JSON summary of all space systems,
/// parameters, sequence containers, telecommands, and unsupported constructs into the result buffer.
///
/// Returns `0` on success, or `1` if the XML cannot be parsed as a valid XTCE document.
///
/// # Safety
///
/// `xml_ptr` must point to a valid byte slice of length `xml_len` in linear memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_inspect_xtce(xml_ptr: *const u8, xml_len: usize) -> i32 {
    if xml_ptr.is_null() || xml_len == 0 {
        return store_json_error("empty XTCE XML buffer");
    }
    // SAFETY: Caller guarantees `xml_ptr..xml_ptr + xml_len` is valid initialized memory.
    let xml_bytes = unsafe { std::slice::from_raw_parts(xml_ptr, xml_len) };
    let Ok(xml_str) = std::str::from_utf8(xml_bytes) else {
        return store_json_error("XTCE XML is not valid UTF-8");
    };
    match inspect_xtce_to_json(xml_str) {
        Ok(json) => {
            store_result(json.into_bytes());
            0
        }
        Err(err) => store_json_error(&err),
    }
}

/// Decodes a raw CCSDS packet stream or Wireshark `.pcap` capture against an XTCE 1.2 XML
/// definition and ECSS-E-ST-70-41C (PUS-C) parser, writing the complete JSON result into the
/// result buffer.
///
/// Automatically detects `.pcap` global headers (`0xA1B2C3D4`, `0xD4C3B2A1`, `0xA1B23C4D`,
/// `0x4D3CB2A1`) and strips the 24-byte global header and 16-byte record headers in memory.
///
/// Returns `0` on success, or `1` on fatal error.
///
/// # Safety
///
/// `xml_ptr` and `pkt_ptr` must point to valid byte slices of lengths `xml_len` and `pkt_len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_decode_xtce_and_packets(
    xml_ptr: *const u8,
    xml_len: usize,
    pkt_ptr: *const u8,
    pkt_len: usize,
    max_packets: usize,
) -> i32 {
    if xml_ptr.is_null() || xml_len == 0 {
        return store_json_error("empty XTCE XML buffer");
    }
    if pkt_ptr.is_null() || pkt_len == 0 {
        return store_json_error("empty packet/PCAP buffer");
    }
    // SAFETY: Caller guarantees both slices are valid in linear memory.
    let xml_bytes = unsafe { std::slice::from_raw_parts(xml_ptr, xml_len) };
    // SAFETY: Caller guarantees both slices are valid in linear memory.
    let pkt_bytes = unsafe { std::slice::from_raw_parts(pkt_ptr, pkt_len) };
    let Ok(xml_str) = std::str::from_utf8(xml_bytes) else {
        return store_json_error("XTCE XML is not valid UTF-8");
    };

    let limit = if max_packets == 0 { 500 } else { max_packets };
    match decode_xtce_and_packets_to_json(xml_str, pkt_bytes, limit) {
        Ok(json) => {
            store_result(json.into_bytes());
            0
        }
        Err(err) => store_json_error(&err),
    }
}

/// Generates a deterministic CCSDS / ECSS-E-ST-70-41C (PUS-C) binary stream (or `.pcap` capture
/// when `as_pcap != 0`) directly in WebAssembly memory and stores the bytes in the result buffer.
///
/// `scenario_id`:
/// * `0` = Nominal orbital pass
/// * `1` = Eclipse voltage drop (21.4 V -> SAFE mode)
/// * `2` = OBC thermal runaway (+68.5 °C -> SAFE mode)
/// * `3` = RF downlink sequence gap
/// * `4` = Watchdog cold reboot
/// * `5` = ADCS attitude tumble
/// * `6` = ADC sensor glitch spike
#[unsafe(no_mangle)]
pub extern "C" fn wasm_generate_pus_stream(
    scenario_id: u32,
    packet_count: usize,
    seed: u64,
    as_pcap: u32,
) -> i32 {
    let count = packet_count.clamp(1, 5_000);
    let raw = generate_pus_stream_bytes(scenario_id, count, seed);
    if as_pcap != 0 {
        let pcap = wrap_in_pcap(&raw);
        store_result(pcap);
    } else {
        store_result(raw);
    }
    0
}

fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn type_kind_label(kind: &TypeKind) -> &'static str {
    match kind {
        TypeKind::Integer => "integer",
        TypeKind::Float => "float",
        TypeKind::String => "string",
        TypeKind::Binary => "binary",
        TypeKind::Boolean { .. } => "boolean",
        TypeKind::Enumerated(_) => "enumerated",
        TypeKind::AbsoluteTime { .. } => "absolute-time",
        TypeKind::RelativeTime => "relative-time",
        TypeKind::Aggregate { .. } => "aggregate",
        TypeKind::Array { .. } => "array",
        TypeKind::Unsupported { .. } => "unsupported",
    }
}

/// Parses an XTCE 1.2 XML string and returns a JSON summary of the database.
///
/// # Errors
///
/// Returns an error string if the XML is malformed or fails XTCE lowering.
pub fn inspect_xtce_to_json(xml_str: &str) -> Result<String, String> {
    let db = XtceDb::from_xml(xml_str).map_err(|e| e.to_string())?;
    let stats = db.stats();

    let root_name = db
        .space_systems()
        .first()
        .map_or("Unknown", |ss| db.name(ss.name));
    let default_root_container = db
        .default_root_container()
        .and_then(|id| db.container(id))
        .map(|c| db.name(c.name));

    let mut out = String::with_capacity(4096);
    out.push_str("{\"ok\":true,\"root_space_system\":");
    push_json_str(&mut out, root_name);
    out.push_str(",\"xmlns\":");
    if let Some(ns) = db.xmlns() {
        push_json_str(&mut out, ns);
    } else {
        out.push_str("null");
    }
    out.push_str(",\"default_root_container\":");
    if let Some(rc) = default_root_container {
        push_json_str(&mut out, rc);
    } else {
        out.push_str("null");
    }

    let _ = write!(
        out,
        ",\"stats\":{{\"space_systems\":{},\"parameters\":{},\"parameter_types\":{},\"decodable_parameter_types\":{},\"containers\":{},\"abstract_containers\":{},\"concrete_containers\":{},\"entries\":{},\"meta_commands\":{},\"unsupported\":{}}}",
        stats.space_systems,
        stats.parameters,
        stats.parameter_types,
        stats.decodable_parameter_types,
        stats.containers,
        stats.abstract_containers,
        stats.containers.saturating_sub(stats.abstract_containers),
        stats.entries,
        stats.meta_commands,
        stats.unsupported
    );

    out.push_str(",\"space_systems\":[");
    for (i, ss) in db.space_systems().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        push_json_str(&mut out, db.name(ss.name));
        out.push_str(",\"qualified_name\":");
        push_json_str(&mut out, db.name(ss.qualified_name));
        out.push('}');
    }
    out.push(']');

    out.push_str(",\"containers\":[");
    for (i, c) in db.containers().iter().take(200).enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        push_json_str(&mut out, db.name(c.name));
        out.push_str(",\"qualified_name\":");
        push_json_str(&mut out, db.name(c.qualified_name));
        let base_name = c
            .base
            .and_then(|bid| db.container(bid))
            .map(|b| db.name(b.name));
        out.push_str(",\"base\":");
        if let Some(bn) = base_name {
            push_json_str(&mut out, bn);
        } else {
            out.push_str("null");
        }
        let _ = write!(
            out,
            ",\"abstract\":{},\"is_command\":{},\"entries\":{}}}",
            c.is_abstract,
            c.is_command,
            c.entries.len()
        );
    }
    out.push(']');

    out.push_str(",\"parameters\":[");
    for (i, p) in db.parameters().iter().take(250).enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        push_json_str(&mut out, db.name(p.name));
        let (kind_str, bits_opt, unit_str) =
            db.parameter_type(p.type_id)
                .map_or(("unknown", None, ""), |ty| {
                    let u = ty.units.first().map_or("", |uid| db.name(*uid));
                    (type_kind_label(&ty.kind), ty.fixed_size_in_bits(), u)
                });
        out.push_str(",\"kind\":");
        push_json_str(&mut out, kind_str);
        out.push_str(",\"bits\":");
        if let Some(b) = bits_opt {
            let _ = write!(out, "{b}");
        } else {
            out.push_str("null");
        }
        out.push_str(",\"unit\":");
        push_json_str(&mut out, unit_str);
        out.push('}');
    }
    out.push(']');

    out.push_str(",\"telecommands\":[");
    for (i, cmd) in db.meta_commands().iter().take(100).enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        push_json_str(&mut out, db.name(cmd.name));
        let _ = write!(
            out,
            ",\"abstract\":{},\"arguments\":{}}}",
            cmd.is_abstract,
            cmd.arguments.len()
        );
    }
    out.push(']');

    out.push_str(",\"unsupported\":[");
    for (i, u) in db.unsupported().iter().take(50).enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"element\":");
        push_json_str(&mut out, &u.element);
        out.push_str(",\"path\":");
        push_json_str(&mut out, &u.path);
        out.push_str(",\"reason\":");
        push_json_str(&mut out, u.reason);
        out.push('}');
    }
    out.push_str("]}");

    Ok(out)
}

/// Checks if `bytes` begins with a standard libpcap global header magic number and, if so,
/// extracts the concatenated raw packet payloads from all PCAP records.
#[must_use]
pub fn extract_packets_if_pcap(bytes: &[u8]) -> (bool, Vec<u8>) {
    if bytes.len() < 24 {
        return (false, Vec::new());
    }
    let magic_le = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let (is_pcap, little_endian) = match magic_le {
        0xA1B2_C3D4 | 0xA1B2_3C4D => (true, true),
        0xD4C3_B2A1 | 0x4D3C_B2A1 => (true, false),
        _ => (false, true),
    };
    if !is_pcap {
        return (false, Vec::new());
    }

    let mut out = Vec::with_capacity(bytes.len());
    let mut offset = 24usize;
    while offset + 16 <= bytes.len() {
        let incl_len = if little_endian {
            u32::from_le_bytes([
                bytes[offset + 8],
                bytes[offset + 9],
                bytes[offset + 10],
                bytes[offset + 11],
            ]) as usize
        } else {
            u32::from_be_bytes([
                bytes[offset + 8],
                bytes[offset + 9],
                bytes[offset + 10],
                bytes[offset + 11],
            ]) as usize
        };
        offset += 16;
        if offset + incl_len > bytes.len() {
            break;
        }
        out.extend_from_slice(&bytes[offset..offset + incl_len]);
        offset += incl_len;
    }
    (true, out)
}

/// Decodes a packet stream (raw CCSDS or `.pcap`) against an XTCE 1.2 XML string and returns JSON.
///
/// # Errors
///
/// Returns an error string if the XTCE XML cannot be parsed or has no root container.
#[allow(clippy::too_many_lines)]
pub fn decode_xtce_and_packets_to_json(
    xml_str: &str,
    pkt_bytes: &[u8],
    max_packets: usize,
) -> Result<String, String> {
    let db = XtceDb::from_xml(xml_str).map_err(|e| e.to_string())?;
    let stats = db.stats();
    let decoder = Decoder::new(&db).map_err(|e| e.to_string())?;

    let (is_pcap, extracted) = extract_packets_if_pcap(pkt_bytes);
    let stream: &[u8] = if is_pcap { &extracted } else { pkt_bytes };

    let root_name = db
        .space_systems()
        .first()
        .map_or("Unknown", |ss| db.name(ss.name));

    let mut total_packets = 0usize;
    let mut decoded_packets = 0usize;
    let mut unrecognized_packets = 0usize;
    let mut failed_packets = 0usize;
    let mut crc_valid_packets = 0usize;
    let mut payload_bytes = 0usize;
    let mut container_counts: Vec<(&str, usize)> = Vec::new();

    let mut packets_json = String::with_capacity(16_384);
    packets_json.push('[');
    let mut first_pkt_entry = true;

    for framed_res in PacketIter::new(stream, 0) {
        let Ok(framed) = framed_res else {
            failed_packets += 1;
            break;
        };
        let raw = framed.bytes();
        total_packets += 1;
        payload_bytes += raw.len();

        let sp = SpacePacketBytes::new(raw);
        let apid = sp.apid();
        let seq_count = sp.sequence_count();
        let pkt_type = sp.packet_type();
        let crc_ok = raw.len() >= 8 && verify_crc16_ccitt(raw);
        if crc_ok {
            crc_valid_packets += 1;
        }
        let crc_val = if raw.len() >= 2 {
            u16::from_be_bytes([raw[raw.len() - 2], raw[raw.len() - 1]])
        } else {
            0
        };

        let pus_info = PusPacket::parse(raw).ok().map(|p| match p.header {
            PusHeader::Telemetry {
                service,
                subtype,
                timestamp,
                ..
            } => ("TM", service, subtype, timestamp.coarse_seconds),
            PusHeader::Telecommand {
                service, subtype, ..
            } => ("TC", service, subtype, 0),
        });

        match decoder.decode(raw) {
            Ok(decoded) => {
                decoded_packets += 1;
                let cname = db
                    .container(decoded.container())
                    .map_or("?", |c| db.name(c.name));
                if let Some(entry) = container_counts.iter_mut().find(|(n, _)| *n == cname) {
                    entry.1 += 1;
                } else {
                    container_counts.push((cname, 1));
                }

                if total_packets <= max_packets {
                    if !first_pkt_entry {
                        packets_json.push(',');
                    }
                    first_pkt_entry = false;

                    let _ = write!(
                        packets_json,
                        "{{\"index\":{},\"status\":\"decoded\",\"container\":",
                        total_packets - 1
                    );
                    push_json_str(&mut packets_json, cname);
                    let _ = write!(
                        packets_json,
                        ",\"apid\":\"0x{apid:03X}\",\"apid_num\":{apid},\"seq_count\":{seq_count},\"direction\":\"{}\",\"length\":{},\"bits_consumed\":{},\"trailing_bits\":{},\"crc_ok\":{},\"crc_hex\":\"0x{crc_val:04X}\"",
                        if pkt_type == 1 { "TC" } else { "TM" },
                        raw.len(),
                        decoded.bits_consumed(),
                        decoded.trailing_bits(),
                        crc_ok
                    );

                    if let Some((dir, st, sub, coarse_s)) = pus_info {
                        let _ = write!(
                            packets_json,
                            ",\"pus_label\":\"{dir}[{st},{sub}]\",\"pus_service\":{st},\"pus_subtype\":{sub},\"cuc_coarse_s\":{coarse_s}"
                        );
                    } else {
                        packets_json.push_str(",\"pus_label\":null");
                    }

                    packets_json.push_str(",\"hex_preview\":\"");
                    for (bi, b) in raw.iter().take(28).enumerate() {
                        if bi > 0 {
                            packets_json.push(' ');
                        }
                        let _ = write!(packets_json, "{b:02X}");
                    }
                    if raw.len() > 28 {
                        packets_json.push_str(" ...");
                    }
                    packets_json.push('"');

                    packets_json.push_str(",\"parameters\":[");
                    for (pi, (pname, pval)) in decoded.iter_named().enumerate() {
                        if pi > 0 {
                            packets_json.push(',');
                        }
                        let unit_str = db
                            .type_of(pval.parameter)
                            .and_then(|ty| ty.units.first())
                            .map_or("", |uid| db.name(*uid));
                        append_decoded_param_json(&mut packets_json, pname, pval, unit_str);
                    }
                    packets_json.push_str("]}");
                }
            }
            Err(DecodeError::UnrecognizedPacket { container, .. }) => {
                unrecognized_packets += 1;
                if total_packets <= max_packets {
                    if !first_pkt_entry {
                        packets_json.push(',');
                    }
                    first_pkt_entry = false;
                    let _ = write!(
                        packets_json,
                        "{{\"index\":{},\"status\":\"unrecognized\",\"container\":",
                        total_packets - 1
                    );
                    push_json_str(&mut packets_json, &container);
                    let _ = write!(
                        packets_json,
                        ",\"apid\":\"0x{apid:03X}\",\"apid_num\":{apid},\"seq_count\":{seq_count},\"direction\":\"{}\",\"length\":{},\"crc_ok\":{},\"crc_hex\":\"0x{crc_val:04X}\",\"parameters\":[]}}",
                        if pkt_type == 1 { "TC" } else { "TM" },
                        raw.len(),
                        crc_ok
                    );
                }
            }
            Err(err) => {
                failed_packets += 1;
                if total_packets <= max_packets {
                    if !first_pkt_entry {
                        packets_json.push(',');
                    }
                    first_pkt_entry = false;
                    append_decode_error_json(
                        &mut packets_json,
                        total_packets - 1,
                        &err,
                        apid,
                        seq_count,
                        raw.len(),
                        crc_ok,
                    );
                }
            }
        }
    }
    packets_json.push(']');

    let mut out = String::with_capacity(packets_json.len() + 1024);
    out.push_str("{\"ok\":true,\"root_space_system\":");
    push_json_str(&mut out, root_name);
    let _ = write!(
        out,
        ",\"is_pcap\":{is_pcap},\"input_bytes\":{},\"stream_bytes\":{payload_bytes},\"total_packets\":{total_packets},\"decoded_packets\":{decoded_packets},\"unrecognized_packets\":{unrecognized_packets},\"failed_packets\":{failed_packets},\"crc_valid_packets\":{crc_valid_packets}",
        pkt_bytes.len()
    );
    let _ = write!(
        out,
        ",\"db_stats\":{{\"space_systems\":{},\"parameters\":{},\"parameter_types\":{},\"containers\":{},\"meta_commands\":{},\"unsupported\":{}}}",
        stats.space_systems,
        stats.parameters,
        stats.parameter_types,
        stats.containers,
        stats.meta_commands,
        stats.unsupported
    );

    out.push_str(",\"container_distribution\":[");
    for (i, (cname, ccount)) in container_counts.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"container\":");
        push_json_str(&mut out, cname);
        let _ = write!(out, ",\"count\":{ccount}}}");
    }
    out.push(']');

    out.push_str(",\"packets\":");
    out.push_str(&packets_json);
    out.push('}');

    Ok(out)
}

fn append_decoded_param_json(
    out: &mut String,
    pname: &str,
    pval: &xtce_decode::ParameterValue<'_, '_>,
    unit_str: &str,
) {
    out.push_str("{\"name\":");
    push_json_str(out, pname);
    out.push_str(",\"raw\":");
    push_json_str(out, &pval.raw.to_string());
    out.push_str(",\"eng\":");
    push_json_str(out, &pval.eng.to_string());
    out.push_str(",\"unit\":");
    push_json_str(out, unit_str);
    let _ = write!(
        out,
        ",\"bit_offset\":{},\"bit_width\":{}}}",
        pval.bit_offset, pval.bit_width
    );
}

fn append_decode_error_json(
    out: &mut String,
    index: usize,
    err: &DecodeError,
    apid: u16,
    seq_count: u16,
    len: usize,
    crc_ok: bool,
) {
    let _ = write!(out, "{{\"index\":{index},\"status\":\"error\",\"error\":");
    push_json_str(out, &err.to_string());
    let _ = write!(
        out,
        ",\"apid\":\"0x{apid:03X}\",\"seq_count\":{seq_count},\"length\":{len},\"crc_ok\":{crc_ok},\"parameters\":[]}}"
    );
}

/// Deterministic `SplitMix64` PRNG for client-side WASM telemetry simulation.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    const fn jitter_i16(&mut self, span: u16) -> i16 {
        if span == 0 {
            return 0;
        }
        let r = (self.next_u64() % ((span as u64) * 2 + 1)) as i16;
        r - (span as i16)
    }
}

/// Generates a deterministic sequence of CCSDS / ECSS PUS-C frames in memory.
#[must_use]
pub fn generate_pus_stream_bytes(scenario_id: u32, packet_count: usize, seed: u64) -> Vec<u8> {
    let mut rng = SplitMix64::new(seed);
    let mut stream = Vec::with_capacity(packet_count * 36);

    let apid: u16 = 0x010;
    let destination_id: u16 = 0x0001;
    let mut seq_count: u16 = 0;
    let mut msg_counter: u16 = 0;
    let mut uptime_s: u32 = 100;
    let mut mode: u8 = 2; // NOMINAL
    let mut frame_buf = [0u8; MAX_HIL_FRAME_LEN];
    let fault_step = (packet_count / 2).max(1);

    for step in 0..packet_count {
        uptime_s = uptime_s.wrapping_add(1);
        let v_jitter = rng.jitter_i16(25);
        let t_jitter = rng.jitter_i16(10);

        let mut bus_voltage_mv: u16 = (28_200i32 + i32::from(v_jitter)) as u16;
        let mut obc_temp_cdeg: i16 = 2_250 + t_jitter;

        match scenario_id {
            1 if step >= fault_step => {
                let drop = ((step - fault_step + 1) * 900).min(6_800) as u16;
                bus_voltage_mv = bus_voltage_mv.saturating_sub(drop);
                if bus_voltage_mv < 24_000 {
                    mode = 0;
                }
            }
            2 if step >= fault_step => {
                let rise = ((step - fault_step + 1) * 650).min(4_600) as i16;
                obc_temp_cdeg = obc_temp_cdeg.saturating_add(rise);
                if obc_temp_cdeg > 5_500 {
                    mode = 0;
                }
            }
            3 if step == fault_step => {
                seq_count = (seq_count + 17) & 0x3FFF;
            }
            4 if step == fault_step => {
                uptime_s = 1;
                seq_count = 0;
                mode = 0;
            }
            5 if step >= fault_step => {
                mode = 0;
            }
            6 if step == fault_step + 1 => {
                bus_voltage_mv = 35_900;
                obc_temp_cdeg = 8_500;
            }
            _ => {}
        }

        let (service, subtype, payload_len, payload) = if step == fault_step && scenario_id != 0 {
            let (ev_id, aux_val): (u16, u16) = match scenario_id {
                1 => (0x1201, bus_voltage_mv),
                2 => (0x1202, obc_temp_cdeg as u16),
                3 => (0x0502, 17),
                4 => (0x0503, 1),
                5 => (0x0504, 0),
                6 => (0x0505, 0xFFFF),
                _ => (0x0000, 0),
            };
            let id_b = ev_id.to_be_bytes();
            let aux_b = aux_val.to_be_bytes();
            let mut app = [0u8; 11];
            app[0] = id_b[0];
            app[1] = id_b[1];
            app[2] = aux_b[0];
            app[3] = aux_b[1];
            (5u8, 2u8, 4usize, app)
        } else if step % 5 == 4 {
            (17u8, 2u8, 0usize, [0u8; 11])
        } else {
            let hk = ObcHousekeeping {
                uptime_s,
                bus_voltage_mv,
                obc_temp_cdeg,
                mode,
            };
            (3u8, 25u8, 11usize, hk.to_app_data())
        };

        let params = TmParams {
            apid,
            sequence_count: seq_count,
            service,
            subtype,
            msg_counter,
            destination_id,
            timestamp: CucTimestamp {
                coarse_seconds: uptime_s,
                fine_subseconds: 0,
            },
        };

        if let Ok(written) = encode_tm(&params, &payload[..payload_len], &mut frame_buf) {
            stream.extend_from_slice(&frame_buf[..written]);
        }

        seq_count = (seq_count + 1) & 0x3FFF;
        msg_counter = msg_counter.wrapping_add(1);
    }

    stream
}

/// Wraps a raw CCSDS packet stream in a libpcap (`.pcap`, `DLT_USER0 = 147`) capture buffer.
#[must_use]
pub fn wrap_in_pcap(raw_stream: &[u8]) -> Vec<u8> {
    const GLOBAL_HEADER: [u8; 24] = [
        0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xFF, 0xFF, 0x00, 0x00, 0x93, 0x00, 0x00, 0x00,
    ];
    let mut out = Vec::with_capacity(24 + raw_stream.len() + 256);
    out.extend_from_slice(&GLOBAL_HEADER);

    for (idx, framed_res) in PacketIter::new(raw_stream, 0).enumerate() {
        let Ok(framed) = framed_res else {
            break;
        };
        let bytes = framed.bytes();
        let pkt_len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let idx_u32 = u32::try_from(idx).unwrap_or(u32::MAX);
        let seconds = idx_u32 / 1_000;
        let micros = (idx_u32 % 1_000) * 1_000;

        out.extend_from_slice(&seconds.to_le_bytes());
        out.extend_from_slice(&micros.to_le_bytes());
        out.extend_from_slice(&pkt_len.to_le_bytes());
        out.extend_from_slice(&pkt_len.to_le_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_stream_and_pcap_roundtrip_decode() {
        let raw = generate_pus_stream_bytes(1, 10, 42);
        let pcap = wrap_in_pcap(&raw);
        let (is_pcap, stripped) = extract_packets_if_pcap(&pcap);
        assert!(is_pcap);
        assert_eq!(stripped, raw);
    }

    #[test]
    fn extract_packets_if_pcap_edge_cases_and_invalid_magic() {
        let empty: &[u8] = &[];
        let (is_pcap_empty, extracted_empty) = extract_packets_if_pcap(empty);
        assert!(!is_pcap_empty);
        assert_eq!(extracted_empty, [] as [u8; 0]);

        let short_bytes: &[u8] = &[0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00];
        let (is_pcap_short, extracted_short) = extract_packets_if_pcap(short_bytes);
        assert!(!is_pcap_short);
        assert_eq!(extracted_short, [] as [u8; 0]);

        let mut invalid_header_pcap = vec![0x11, 0x22, 0x33, 0x44];
        invalid_header_pcap.resize(24, 0);
        let (is_pcap_invalid, extracted_invalid) = extract_packets_if_pcap(&invalid_header_pcap);
        assert!(!is_pcap_invalid);
        assert_eq!(extracted_invalid, [] as [u8; 0]);
    }
}
