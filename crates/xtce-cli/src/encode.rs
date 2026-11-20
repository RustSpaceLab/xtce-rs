//! `xtce encode` — assemble a binary CCSDS telemetry or telecommand packet from an XTCE
//! definition and `NAME=VALUE` field assignments.
//!
//! Turns `xtce` into a bidirectional EGSE tool: given a concrete container or `<MetaCommand>`
//! name, the encoder walks the inheritance tree from the root container, populates all
//! `<FixedValueEntry>` bit patterns, restriction criteria (`<Comparison>`), and command
//! `<ArgumentAssignment>` guards automatically, applies user-supplied `--set NAME=VALUE`
//! overrides, and outputs the bit-packed packet as raw bytes or hex.

#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use std::io::Write;
use std::path::Path;

use xtce_codegen::{ContainerPlan, Criterion, Field, Guard, GuardTest, Node, Plan, Repr};
use xtce_model::{IntegerCoding, XtceDb};
use xtce_pus::crc16_ccitt;

/// Configuration for `xtce encode`.
pub struct Options<'a> {
    pub target: &'a str,
    pub root: Option<&'a str>,
    pub assignments: &'a [String],
    pub out: Option<&'a Path>,
    pub hex: bool,
    pub crc: bool,
}

/// Encodes a single packet for `target` (a container name or `<MetaCommand>` name) in `db`.
///
/// # Errors
///
/// Returns a descriptive error if the target container or command does not exist, if the
/// target container is abstract, if a `--set` entry is not `NAME=VALUE` or names an unknown
/// field, or if a value cannot be parsed for its XTCE type.
pub fn encode_packet(
    db: &XtceDb,
    target: &str,
    explicit_root: Option<&str>,
    assignments: &[String],
    stamp_crc: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let container_id = resolve_target_container(db, target)?;
    let container_name = db
        .container(container_id)
        .map(|c| db.name(c.name))
        .ok_or("internal: resolved container id does not exist")?;

    let root_name = match explicit_root {
        Some(name) => name,
        None => find_hierarchy_root_name(db, container_id)?,
    };

    let plan = xtce_codegen::plan(
        db,
        &xtce_codegen::Options {
            root: Some(root_name.to_owned()),
            source_label: None,
        },
    )?;

    let container_plan = plan
        .containers
        .iter()
        .find(|c| c.xtce_name == container_name)
        .ok_or_else(|| {
            format!("container {container_name:?} is abstract and cannot be encoded directly")
        })?;

    let total_bits = container_plan.bit_length.ok_or_else(|| {
        format!(
            "container {container_name:?} has a variable-width field and requires fixed bit layout"
        )
    })?;

    let mut buf = vec![0u8; total_bits.div_ceil(8)];

    // 1. Populate `<FixedValueEntry>` bit patterns from telecommand containers.
    for fixed in &container_plan.fixed {
        write_fixed_bits(&mut buf, fixed.bit_offset, fixed.bit_width, &fixed.value);
    }

    // 2. Populate inheritance guards (`RestrictionCriteria` and `<ArgumentAssignment>`).
    apply_inheritance_guards(&plan, &container_plan.xtce_name, &mut buf);

    // 3. Apply explicit user `--set NAME=VALUE` assignments.
    for spec in assignments {
        apply_single_assignment(&mut buf, container_plan, spec)?;
    }

    // 4. Stamp trailing 16-bit ECSS CRC-16-CCITT if requested and packet is at least 2 bytes.
    if stamp_crc && buf.len() >= 2 {
        let body_end = buf.len() - 2;
        let crc = crc16_ccitt(&buf[..body_end]);
        buf[body_end..].copy_from_slice(&crc.to_be_bytes());
    }

    Ok(buf)
}

fn apply_single_assignment(
    buf: &mut [u8],
    container_plan: &ContainerPlan,
    spec: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (name, val_str) = spec
        .split_once('=')
        .ok_or("invalid assignment: expected NAME=VALUE")?;
    let field = container_plan
        .fields
        .iter()
        .find(|f| f.xtce_name == name)
        .ok_or("container has no field with the specified name")?;
    encode_field_value(buf, field, val_str)
}

fn resolve_target_container(
    db: &XtceDb,
    target: &str,
) -> Result<xtce_model::ContainerId, Box<dyn std::error::Error>> {
    if let Some(id) = db.find_container(target) {
        return Ok(id);
    }
    for cmd in db.meta_commands() {
        if db.name(cmd.name) == target {
            if let Some(cid) = cmd.container {
                return Ok(cid);
            }
        }
    }
    Err(format!("no container or telecommand named {target:?} in definition").into())
}

fn find_hierarchy_root_name(
    db: &XtceDb,
    mut current: xtce_model::ContainerId,
) -> Result<&str, Box<dyn std::error::Error>> {
    let mut steps = 0usize;
    while let Some(c) = db.container(current) {
        if let Some(base) = c.base {
            current = base;
            steps += 1;
            if steps > 64 {
                break;
            }
        } else {
            return Ok(db.name(c.name));
        }
    }
    Err("could not resolve hierarchy root container".into())
}

fn apply_inheritance_guards(plan: &Plan, target_name: &str, buf: &mut [u8]) {
    let mut guards: Vec<&Guard> = Vec::new();
    collect_path_guards(&plan.root, target_name, &mut guards);
    for guard in guards {
        if let Some(val) = guard.test.sole_value() {
            let bits = (val as u128) as u64;
            write_bits_uint(
                buf,
                guard.bit_offset,
                guard.bit_width,
                bits,
                guard.swap_bytes,
            );
        }
    }
}

fn collect_path_guards<'a>(node: &'a Node, target_name: &str, out: &mut Vec<&'a Guard>) -> bool {
    if node.xtce_name == target_name {
        return true;
    }
    for (criterion, child) in &node.children {
        let saved_len = out.len();
        collect_criterion_guards(criterion, out);
        if collect_path_guards(child, target_name, out) {
            return true;
        }
        out.truncate(saved_len);
    }
    false
}

fn collect_criterion_guards<'a>(criterion: &'a Criterion, out: &mut Vec<&'a Guard>) {
    match criterion {
        Criterion::Test(guard) => {
            if matches!(
                guard.test,
                GuardTest::Value { .. } | GuardTest::Labels { .. }
            ) {
                out.push(guard);
            }
        }
        Criterion::All(children) => {
            for child in children {
                collect_criterion_guards(child, out);
            }
        }
        Criterion::Any(children) => {
            if let Some(first) = children.first() {
                collect_criterion_guards(first, out);
            }
        }
    }
}

fn encode_field_value(
    buf: &mut [u8],
    field: &Field,
    val_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (bit_offset, bit_width) = field.static_span().ok_or_else(|| {
        format!(
            "field {:?} does not have a static bit offset",
            field.xtce_name
        )
    })?;

    match &field.repr {
        Repr::Unsigned => {
            let v = parse_uint(val_str).map_err(|e| format!("{}: {e}", field.xtce_name))?;
            write_bits_uint(buf, bit_offset, bit_width, v, field.swap_bytes);
        }
        Repr::Signed(coding) => {
            let v = parse_int(val_str).map_err(|e| format!("{}: {e}", field.xtce_name))?;
            let encoded = encode_signed_bits(v, bit_width, *coding);
            write_bits_uint(buf, bit_offset, bit_width, encoded, field.swap_bytes);
        }
        Repr::Bool => {
            let b = match val_str {
                "true" | "1" | "TRUE" => 1u64,
                "false" | "0" | "FALSE" => 0u64,
                _ => {
                    return Err(
                        format!("{}: expected boolean (true/false/1/0)", field.xtce_name).into(),
                    );
                }
            };
            write_bits_uint(buf, bit_offset, bit_width, b, field.swap_bytes);
        }
        Repr::Enumerated(entries) => {
            let raw = resolve_enum_value(entries, val_str, &field.xtce_name)?;
            write_bits_uint(
                buf,
                bit_offset,
                bit_width,
                (raw as u128) as u64,
                field.swap_bytes,
            );
        }
        Repr::Float32 => {
            let f: f32 = val_str
                .parse()
                .map_err(|e| format!("{}: invalid f32 ({e})", field.xtce_name))?;
            write_bits_uint(
                buf,
                bit_offset,
                bit_width,
                u64::from(f.to_bits()),
                field.swap_bytes,
            );
        }
        Repr::Float64 => {
            let f: f64 = val_str
                .parse()
                .map_err(|e| format!("{}: invalid f64 ({e})", field.xtce_name))?;
            write_bits_uint(buf, bit_offset, bit_width, f.to_bits(), field.swap_bytes);
        }
        Repr::Text { .. } => {
            write_raw_bytes_at_bit(buf, bit_offset, bit_width, val_str.as_bytes());
        }
        Repr::Binary => {
            let bytes =
                parse_hex_bytes(val_str).map_err(|e| format!("{}: {e}", field.xtce_name))?;
            write_raw_bytes_at_bit(buf, bit_offset, bit_width, &bytes);
        }
        Repr::Float16 | Repr::Mil1750a => {
            let v = parse_uint(val_str).map_err(|e| format!("{}: {e}", field.xtce_name))?;
            write_bits_uint(buf, bit_offset, bit_width, v, field.swap_bytes);
        }
    }

    Ok(())
}

fn resolve_enum_value(
    entries: &[(i128, i128, String)],
    val_str: &str,
    field_name: &str,
) -> Result<i128, Box<dyn std::error::Error>> {
    for (low, _, label) in entries {
        if label == val_str {
            return Ok(*low);
        }
    }
    if let Ok(raw) = val_str.parse::<i128>() {
        for (low, high, _) in entries {
            if raw >= *low && raw <= *high {
                return Ok(raw);
            }
        }
    }
    Err(format!("{field_name}: {val_str:?} is not a valid enumeration label or raw value").into())
}

fn parse_uint(text: &str) -> Result<u64, std::num::ParseIntError> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse::<u64>()
    }
}

fn parse_int(text: &str) -> Result<i64, std::num::ParseIntError> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16)
    } else {
        text.parse::<i64>()
    }
}

fn parse_hex_bytes(text: &str) -> Result<Vec<u8>, &'static str> {
    let clean = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    if clean.len() % 2 != 0 {
        return Err("hex string must have an even number of digits");
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    let bytes = clean.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).map_err(|_| "invalid UTF-8 in hex")?;
        let b = u8::from_str_radix(pair, 16).map_err(|_| "invalid hexadecimal digit")?;
        out.push(b);
        i += 2;
    }
    Ok(out)
}

fn encode_signed_bits(value: i64, width: u32, coding: IntegerCoding) -> u64 {
    if width == 0 || width > 64 {
        return 0;
    }
    let mask = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    match coding {
        IntegerCoding::Unsigned | IntegerCoding::TwosComplement => (value as u64) & mask,
        IntegerCoding::OnesComplement => {
            if value >= 0 {
                (value as u64) & mask
            } else {
                (!(-value as u64)) & mask
            }
        }
        IntegerCoding::SignMagnitude => {
            if value >= 0 {
                (value as u64) & mask
            } else {
                let sign_bit = 1u64 << (width - 1);
                let mag_mask = sign_bit - 1;
                sign_bit | ((-value as u64) & mag_mask)
            }
        }
    }
}

fn write_bits_uint(buf: &mut [u8], bit_offset: usize, bit_width: u32, raw: u64, swap_bytes: bool) {
    if bit_width == 0 || bit_width > 64 {
        return;
    }
    let val = if swap_bytes && bit_width >= 16 && (bit_width % 8 == 0) {
        let nbytes = (bit_width / 8) as usize;
        let be = raw.to_be_bytes();
        let start = 8 - nbytes;
        let mut swapped = [0u8; 8];
        let mut i = 0;
        while i < nbytes {
            swapped[start + i] = be[7 - i];
            i += 1;
        }
        u64::from_be_bytes(swapped)
    } else {
        raw
    };

    for i in 0..(bit_width as usize) {
        let shift = (bit_width as usize) - 1 - i;
        let bit = ((val >> shift) & 1) as u8;
        let pos = bit_offset + i;
        let byte_idx = pos / 8;
        let bit_in_byte = 7 - (pos % 8);
        if let Some(slot) = buf.get_mut(byte_idx) {
            *slot = (*slot & !(1 << bit_in_byte)) | (bit << bit_in_byte);
        }
    }
}

fn write_fixed_bits(buf: &mut [u8], bit_offset: usize, bit_width: u32, right_aligned_bytes: &[u8]) {
    let total_avail = right_aligned_bytes.len() * 8;
    let width = bit_width as usize;
    if width > total_avail {
        return;
    }
    let start_bit_in_src = total_avail - width;
    for i in 0..width {
        let src_pos = start_bit_in_src + i;
        let src_byte = right_aligned_bytes[src_pos / 8];
        let bit = (src_byte >> (7 - (src_pos % 8))) & 1;
        let dst_pos = bit_offset + i;
        let dst_idx = dst_pos / 8;
        let dst_bit = 7 - (dst_pos % 8);
        if let Some(slot) = buf.get_mut(dst_idx) {
            *slot = (*slot & !(1 << dst_bit)) | (bit << dst_bit);
        }
    }
}

fn write_raw_bytes_at_bit(buf: &mut [u8], bit_offset: usize, bit_width: u32, src: &[u8]) {
    let max_bits = (bit_width as usize).min(src.len() * 8);
    for i in 0..max_bits {
        let src_byte = src[i / 8];
        let bit = (src_byte >> (7 - (i % 8))) & 1;
        let dst_pos = bit_offset + i;
        let dst_idx = dst_pos / 8;
        let dst_bit = 7 - (dst_pos % 8);
        if let Some(slot) = buf.get_mut(dst_idx) {
            *slot = (*slot & !(1 << dst_bit)) | (bit << dst_bit);
        }
    }
}

/// Executes `xtce encode` using a pre-loaded [`XtceDb`].
///
/// # Errors
///
/// Returns an error if packet assembly or output writing fails.
pub fn run_with_db(db: &XtceDb, options: &Options<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = encode_packet(
        db,
        options.target,
        options.root,
        options.assignments,
        options.crc,
    )?;

    match options.out {
        Some(path) if path.as_os_str() != "-" => {
            if options.hex {
                let mut file = std::fs::File::create(path)?;
                write_hex_line(&mut file, &bytes)?;
            } else {
                std::fs::write(path, &bytes)?;
            }
            eprintln!(
                "encoded {} ({} bytes) to {}",
                options.target,
                bytes.len(),
                path.display()
            );
        }
        _ => {
            let stdout = std::io::stdout();
            let mut out = std::io::BufWriter::new(stdout.lock());
            if options.hex {
                write_hex_line(&mut out, &bytes)?;
            } else {
                out.write_all(&bytes)?;
            }
            out.flush()?;
        }
    }

    Ok(())
}

fn write_hex_line(out: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut line = Vec::with_capacity(bytes.len() * 2 + 1);
    for &b in bytes {
        line.push(HEX[(b >> 4) as usize]);
        line.push(HEX[(b & 0x0F) as usize]);
    }
    line.push(b'\n');
    out.write_all(&line)
}

#[cfg(test)]
mod tests {
    use xtce_decode::{Decoder, EngValue, RawValue};
    use xtce_model::XtceDb;
    use xtce_pus::verify_crc16_ccitt;

    use super::encode_packet;
    use crate::pus::ECSS_PUS_XTCE_XML;

    #[test]
    fn encodes_container_with_guards_enums_and_crc_and_roundtrips_through_decoder() {
        let db = XtceDb::from_xml(ECSS_PUS_XTCE_XML).expect("PUS XTCE loads");
        let decoder = Decoder::new(&db).expect("decoder");

        let assignments = vec![
            "CCSDS_SEC_HDR=1".to_owned(),
            "CCSDS_APID=0x010".to_owned(),
            "CCSDS_SEQ_FLAGS=3".to_owned(),
            "CCSDS_SEQ_COUNT=42".to_owned(),
            "PUS_VERSION=2".to_owned(),
            "HK_SID=1".to_owned(),
            "OBC_UPTIME_S=120".to_owned(),
            "OBC_VBUS_V=28200".to_owned(),
            "OBC_TEMP_C=-1500".to_owned(),
            "OBC_MODE=EO_IMAGING".to_owned(),
        ];

        let encoded = encode_packet(&db, "TM_3_25_ObcHousekeeping", None, &assignments, true)
            .expect("encodes TM_3_25_ObcHousekeeping");

        // Verify trailing CRC-16-CCITT is valid
        assert!(verify_crc16_ccitt(&encoded));

        // Decode back through xtce_decode::Decoder and verify round-trip values!
        let packet = decoder.decode(&encoded).expect("decodes back");
        assert_eq!(
            db.name(db.container(packet.container()).unwrap().name),
            "TM_3_25_ObcHousekeeping"
        );
        assert_eq!(
            packet.get_by_name("PUS_SERVICE").unwrap().raw,
            RawValue::Unsigned(3)
        );
        assert_eq!(
            packet.get_by_name("PUS_SUBTYPE").unwrap().raw,
            RawValue::Unsigned(25)
        );
        assert_eq!(
            packet.get_by_name("OBC_UPTIME_S").unwrap().raw,
            RawValue::Unsigned(120)
        );
        assert_eq!(
            packet.get_by_name("OBC_TEMP_C").unwrap().raw,
            RawValue::Signed(-1500)
        );
        assert_eq!(
            packet.get_by_name("OBC_MODE").unwrap().eng,
            EngValue::Label("EO_IMAGING")
        );
    }

    #[test]
    fn encodes_metacommand_with_fixed_values_and_argument_assignments() {
        const CMD_XTCE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<xtce:SpaceSystem name="Sat" xmlns:xtce="http://www.omg.org/spec/XTCE/20180204">
  <xtce:CommandMetaData>
    <xtce:ArgumentTypeSet>
      <xtce:IntegerArgumentType name="U8_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="8" encoding="unsigned"/>
      </xtce:IntegerArgumentType>
      <xtce:IntegerArgumentType name="U16_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="16" encoding="unsigned"/>
      </xtce:IntegerArgumentType>
    </xtce:ArgumentTypeSet>
    <xtce:MetaCommandSet>
      <xtce:MetaCommand name="BaseCmd" abstract="true">
        <xtce:ArgumentList>
          <xtce:Argument name="OPCODE" argumentTypeRef="U8_T"/>
        </xtce:ArgumentList>
        <xtce:CommandContainer name="BaseCmdContainer">
          <xtce:EntryList>
            <xtce:FixedValueEntry name="SYNC" binaryValue="CAFE" sizeInBits="16"/>
            <xtce:ArgumentRefEntry argumentRef="OPCODE"/>
          </xtce:EntryList>
        </xtce:CommandContainer>
      </xtce:MetaCommand>
      <xtce:MetaCommand name="SetExposure">
        <xtce:BaseMetaCommand metaCommandRef="BaseCmd">
          <xtce:ArgumentAssignmentList>
            <xtce:ArgumentAssignment argumentName="OPCODE" argumentValue="7"/>
          </xtce:ArgumentAssignmentList>
        </xtce:BaseMetaCommand>
        <xtce:ArgumentList>
          <xtce:Argument name="EXPOSURE_MS" argumentTypeRef="U16_T"/>
        </xtce:ArgumentList>
        <xtce:CommandContainer name="SetExposureContainer">
          <xtce:BaseContainer containerRef="BaseCmdContainer"/>
          <xtce:EntryList>
            <xtce:ArgumentRefEntry argumentRef="EXPOSURE_MS"/>
          </xtce:EntryList>
        </xtce:CommandContainer>
      </xtce:MetaCommand>
    </xtce:MetaCommandSet>
  </xtce:CommandMetaData>
</xtce:SpaceSystem>"#;

        let db = XtceDb::from_xml(CMD_XTCE).expect("loads command xml");
        let bytes = encode_packet(
            &db,
            "SetExposure",
            None,
            &["EXPOSURE_MS=500".to_owned()],
            false,
        )
        .expect("encodes SetExposure");

        assert_eq!(bytes, vec![0xCA, 0xFE, 0x07, 0x01, 0xF4]);

        let decoder = Decoder::with_root(&db, "BaseCmdContainer").expect("cmd decoder");
        let packet = decoder.decode(&bytes).expect("decodes command");
        let values: Vec<(&str, RawValue<'_>)> = packet
            .iter_named()
            .map(|(name, val)| (name, val.raw.clone()))
            .collect();
        assert_eq!(
            values,
            vec![
                ("OPCODE", RawValue::Unsigned(7)),
                ("EXPOSURE_MS", RawValue::Unsigned(500)),
            ]
        );
    }
}
