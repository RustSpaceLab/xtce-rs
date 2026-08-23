//! End-to-end decoding against minimal XTCE snippets written inline.
//!
//! The golden files prove agreement with the reference on real mission data, but they only
//! reach the constructs those five files happen to use. These tests reach the rest — and
//! being inline, each one shows the exact XML that produces the behaviour it asserts.

use xtce_decode::{DecodeError, Decoder, EngValue, RawValue};
use xtce_model::XtceDb;

/// Wraps parameter types, parameters and containers in the surrounding boilerplate.
fn definition(types: &str, parameters: &str, containers: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<SpaceSystem xmlns="http://www.omg.org/spec/XTCE/20180204" name="Test">
  <TelemetryMetaData>
    <ParameterTypeSet>{types}</ParameterTypeSet>
    <ParameterSet>{parameters}</ParameterSet>
    <ContainerSet>{containers}</ContainerSet>
  </TelemetryMetaData>
</SpaceSystem>"#
    )
}

/// A single-container definition over the given parameter types.
fn simple(types: &str, parameters: &str, entries: &str) -> String {
    definition(
        types,
        parameters,
        &format!(
            r#"<SequenceContainer name="Packet"><EntryList>{entries}</EntryList></SequenceContainer>"#
        ),
    )
}

fn load(xml: &str) -> XtceDb {
    XtceDb::from_xml(xml).unwrap_or_else(|error| panic!("definition failed to load: {error}"))
}

fn decode_one<'a>(
    db: &'a XtceDb,
    packet: &'a [u8],
) -> Vec<(String, RawValue<'a>, EngValue<'a, 'a>)> {
    let decoder = Decoder::with_root(db, "Packet").expect("root container");
    let decoded = decoder.decode(packet).expect("packet decodes");
    decoded
        .iter_named()
        .map(|(name, value)| (name.to_owned(), value.raw.clone(), value.eng.clone()))
        .collect()
}

#[test]
fn integer_fields_straddle_byte_boundaries() {
    // Three fields of 3, 11 and 2 bits: 16 bits total, none byte-aligned after the first.
    let xml = simple(
        r#"
        <IntegerParameterType name="T3"><IntegerDataEncoding sizeInBits="3" encoding="unsigned"/></IntegerParameterType>
        <IntegerParameterType name="T11"><IntegerDataEncoding sizeInBits="11" encoding="unsigned"/></IntegerParameterType>
        <IntegerParameterType name="T2"><IntegerDataEncoding sizeInBits="2" encoding="twosComplement"/></IntegerParameterType>"#,
        r#"
        <Parameter name="A" parameterTypeRef="T3"/>
        <Parameter name="B" parameterTypeRef="T11"/>
        <Parameter name="C" parameterTypeRef="T2"/>"#,
        r#"
        <ParameterRefEntry parameterRef="A"/>
        <ParameterRefEntry parameterRef="B"/>
        <ParameterRefEntry parameterRef="C"/>"#,
    );
    let db = load(&xml);

    // 101 10101010101 11  =>  0b1011_0101 0b0101_0111 = 0xB5 0x57
    let values = decode_one(&db, &[0xB5, 0x57]);
    assert_eq!(values[0].1, RawValue::Unsigned(0b101));
    assert_eq!(values[1].1, RawValue::Unsigned(0b101_0101_0101));
    // 0b11 as a 2-bit two's complement value is -1.
    assert_eq!(values[2].1, RawValue::Signed(-1));
    // With no calibrator the engineering value is the raw value.
    assert_eq!(values[0].2, EngValue::Unsigned(0b101));
}

#[test]
fn sixty_four_bit_field_at_a_bit_offset() {
    let xml = simple(
        r#"
        <IntegerParameterType name="T1"><IntegerDataEncoding sizeInBits="1" encoding="unsigned"/></IntegerParameterType>
        <IntegerParameterType name="T64"><IntegerDataEncoding sizeInBits="64" encoding="unsigned"/></IntegerParameterType>"#,
        r#"
        <Parameter name="FLAG" parameterTypeRef="T1"/>
        <Parameter name="WIDE" parameterTypeRef="T64"/>"#,
        r#"
        <ParameterRefEntry parameterRef="FLAG"/>
        <ParameterRefEntry parameterRef="WIDE"/>"#,
    );
    let db = load(&xml);

    // One flag bit set, then 64 one-bits — a nine-byte span.
    let packet = [0xFF; 9];
    let values = decode_one(&db, &packet);
    assert_eq!(values[0].1, RawValue::Unsigned(1));
    assert_eq!(values[1].1, RawValue::Unsigned(u64::MAX >> 1 | (1 << 63)));

    // And with a distinctive pattern, so a truncating read would be visible.
    let packet = [0x80, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let values = decode_one(&db, &packet);
    // 0x80 contributes one flag bit and seven zeros, so the field starts 0x0024...
    assert_eq!(values[1].1, RawValue::Unsigned(0x0024_68AC_F135_79BD));
}

#[test]
fn little_endian_integers() {
    let xml = simple(
        r#"<IntegerParameterType name="T"><IntegerDataEncoding sizeInBits="32" encoding="unsigned" byteOrder="leastSignificantByteFirst"/></IntegerParameterType>"#,
        r#"<Parameter name="LE" parameterTypeRef="T"/>"#,
        r#"<ParameterRefEntry parameterRef="LE"/>"#,
    );
    let db = load(&xml);
    let values = decode_one(&db, &[0x78, 0x56, 0x34, 0x12]);
    assert_eq!(values[0].1, RawValue::Unsigned(0x1234_5678));
}

#[test]
fn ieee754_floats() {
    let xml = simple(
        r#"
        <FloatParameterType name="F32"><FloatDataEncoding sizeInBits="32" encoding="IEEE754"/></FloatParameterType>
        <FloatParameterType name="F64"><FloatDataEncoding sizeInBits="64" encoding="IEEE754_1985"/></FloatParameterType>"#,
        r#"
        <Parameter name="SINGLE" parameterTypeRef="F32"/>
        <Parameter name="DOUBLE" parameterTypeRef="F64"/>"#,
        r#"
        <ParameterRefEntry parameterRef="SINGLE"/>
        <ParameterRefEntry parameterRef="DOUBLE"/>"#,
    );
    let db = load(&xml);

    let mut packet = Vec::new();
    packet.extend(1.5f32.to_be_bytes());
    packet.extend((-2.25f64).to_be_bytes());
    let values = decode_one(&db, &packet);
    assert_eq!(values[0].1, RawValue::Float(1.5));
    assert_eq!(values[1].1, RawValue::Float(-2.25));
    // A float parameter's engineering value is its raw value when uncalibrated.
    assert_eq!(values[1].2, EngValue::Float(-2.25));
}

#[test]
fn polynomial_calibration_produces_a_float_from_an_integer_raw() {
    let xml = simple(
        r#"
        <IntegerParameterType name="T">
          <IntegerDataEncoding sizeInBits="8" encoding="unsigned">
            <DefaultCalibrator>
              <PolynomialCalibrator>
                <Term coefficient="1.5" exponent="0"/>
                <Term coefficient="0.25" exponent="1"/>
              </PolynomialCalibrator>
            </DefaultCalibrator>
          </IntegerDataEncoding>
        </IntegerParameterType>"#,
        r#"<Parameter name="TEMP" parameterTypeRef="T"/>"#,
        r#"<ParameterRefEntry parameterRef="TEMP"/>"#,
    );
    let db = load(&xml);
    let values = decode_one(&db, &[100]);
    // The raw value stays an integer; only the engineering value is calibrated.
    assert_eq!(values[0].1, RawValue::Unsigned(100));
    assert_eq!(values[0].2, EngValue::Float(1.5 + 0.25 * 100.0));
}

#[test]
fn enumerations_look_up_the_raw_value_and_honour_ranges() {
    let xml = simple(
        r#"
        <EnumeratedParameterType name="T">
          <IntegerDataEncoding sizeInBits="8" encoding="unsigned"/>
          <EnumerationList>
            <Enumeration value="0" label="OFF"/>
            <Enumeration value="1" label="ON"/>
            <Enumeration value="10" maxValue="19" label="WARMING"/>
          </EnumerationList>
        </EnumeratedParameterType>"#,
        r#"<Parameter name="MODE" parameterTypeRef="T"/>"#,
        r#"<ParameterRefEntry parameterRef="MODE"/>"#,
    );
    let db = load(&xml);

    for (byte, label) in [(0u8, "OFF"), (1, "ON"), (10, "WARMING"), (19, "WARMING")] {
        let packet = [byte];
        let values = decode_one(&db, &packet);
        assert_eq!(values[0].1, RawValue::Unsigned(u64::from(byte)));
        assert_eq!(values[0].2, EngValue::Label(label), "byte {byte}");
    }

    // A value between the point entries and the range is not in the enumeration.
    let decoder = Decoder::with_root(&db, "Packet").expect("root");
    assert!(matches!(
        decoder.decode(&[5]),
        Err(DecodeError::UnknownEnumeration { value: 5, .. })
    ));
    assert!(matches!(
        decoder.decode(&[20]),
        Err(DecodeError::UnknownEnumeration { value: 20, .. })
    ));
}

#[test]
fn booleans_take_truthiness_from_the_raw_value() {
    let xml = simple(
        r#"
        <BooleanParameterType name="T" zeroStringValue="SAFE" oneStringValue="ARMED">
          <IntegerDataEncoding sizeInBits="4" encoding="unsigned"/>
        </BooleanParameterType>"#,
        r#"<Parameter name="ARM" parameterTypeRef="T"/>"#,
        r#"<ParameterRefEntry parameterRef="ARM"/>"#,
    );
    let db = load(&xml);

    let values = decode_one(&db, &[0x00]);
    assert_eq!(values[0].2, EngValue::Bool(false));
    let values = decode_one(&db, &[0x70]);
    assert_eq!(values[0].1, RawValue::Unsigned(7));
    assert_eq!(values[0].2, EngValue::Bool(true));

    // The labels are modelled even though the decoded value is a plain bool, matching the
    // reference implementation while keeping the definition's own words available.
    let type_id = db.find_type("T").expect("type exists");
    assert_eq!(db.boolean_label(type_id, true), Some("ARMED"));
    assert_eq!(db.boolean_label(type_id, false), Some("SAFE"));
}

#[test]
fn fixed_size_strings_keep_their_whole_buffer_as_the_raw_value() {
    let xml = simple(
        r#"
        <StringParameterType name="T">
          <StringDataEncoding encoding="UTF-8">
            <SizeInBits><Fixed><FixedValue>48</FixedValue></Fixed></SizeInBits>
          </StringDataEncoding>
        </StringParameterType>"#,
        r#"<Parameter name="TAG" parameterTypeRef="T"/>"#,
        r#"<ParameterRefEntry parameterRef="TAG"/>"#,
    );
    let db = load(&xml);
    let values = decode_one(&db, b"ABCDEF");
    assert_eq!(values[0].1, RawValue::Bytes(b"ABCDEF".as_slice().into()));
    assert_eq!(values[0].2, EngValue::Text("ABCDEF".into()));
}

#[test]
fn termination_characters_cut_the_string_short() {
    let xml = simple(
        r#"
        <StringParameterType name="T">
          <StringDataEncoding encoding="UTF-8">
            <SizeInBits><Fixed><FixedValue>48</FixedValue></Fixed><TerminationChar>00</TerminationChar></SizeInBits>
          </StringDataEncoding>
        </StringParameterType>"#,
        r#"<Parameter name="TAG" parameterTypeRef="T"/>"#,
        r#"<ParameterRefEntry parameterRef="TAG"/>"#,
    );
    let db = load(&xml);
    let values = decode_one(&db, b"AB\0DEF");
    // The raw value is the whole allocated buffer; only the derived string is cut.
    assert_eq!(values[0].1, RawValue::Bytes(b"AB\0DEF".as_slice().into()));
    assert_eq!(values[0].2, EngValue::Text("AB".into()));

    let decoder = Decoder::with_root(&db, "Packet").expect("root");
    assert!(matches!(
        decoder.decode(b"ABCDEF"),
        Err(DecodeError::UnterminatedString { .. })
    ));
}

#[test]
fn leading_size_strings() {
    let xml = simple(
        r#"
        <StringParameterType name="T">
          <StringDataEncoding encoding="UTF-8">
            <SizeInBits><Fixed><FixedValue>48</FixedValue></Fixed><LeadingSize sizeInBitsOfSizeTag="8"/></SizeInBits>
          </StringDataEncoding>
        </StringParameterType>"#,
        r#"<Parameter name="TAG" parameterTypeRef="T"/>"#,
        r#"<ParameterRefEntry parameterRef="TAG"/>"#,
    );
    let db = load(&xml);
    // Leading byte says 24 bits, so three characters follow; the rest is slack.
    let values = decode_one(&db, &[24, b'X', b'Y', b'Z', 0, 0]);
    assert_eq!(values[0].2, EngValue::Text("XYZ".into()));
}

#[test]
fn binary_fields_sized_by_another_parameter() {
    let xml = simple(
        r#"
        <IntegerParameterType name="LEN"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>
        <BinaryParameterType name="BLOB">
          <BinaryDataEncoding>
            <SizeInBits>
              <DynamicValue>
                <ParameterInstanceRef parameterRef="COUNT"/>
                <LinearAdjustment slope="8" intercept="0"/>
              </DynamicValue>
            </SizeInBits>
          </BinaryDataEncoding>
        </BinaryParameterType>"#,
        r#"
        <Parameter name="COUNT" parameterTypeRef="LEN"/>
        <Parameter name="DATA" parameterTypeRef="BLOB"/>"#,
        r#"
        <ParameterRefEntry parameterRef="COUNT"/>
        <ParameterRefEntry parameterRef="DATA"/>"#,
    );
    let db = load(&xml);
    // COUNT is in bytes; the LinearAdjustment converts it to bits.
    let values = decode_one(&db, &[3, 0xAA, 0xBB, 0xCC]);
    assert_eq!(values[1].1, RawValue::Bytes(vec![0xAA, 0xBB, 0xCC].into()));

    let decoder = Decoder::with_root(&db, "Packet").expect("root");
    // A length longer than the packet is an error, not a panic or a short read.
    assert!(matches!(
        decoder.decode(&[9, 0xAA]),
        Err(DecodeError::Bits { .. })
    ));
}

#[test]
fn container_inheritance_selects_by_restriction_criteria() {
    let xml = definition(
        r#"
        <IntegerParameterType name="T8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>
        <IntegerParameterType name="T16"><IntegerDataEncoding sizeInBits="16" encoding="unsigned"/></IntegerParameterType>"#,
        r#"
        <Parameter name="APID" parameterTypeRef="T8"/>
        <Parameter name="HOUSEKEEPING" parameterTypeRef="T16"/>
        <Parameter name="SCIENCE" parameterTypeRef="T16"/>"#,
        r#"
        <SequenceContainer name="Packet" abstract="true">
          <EntryList><ParameterRefEntry parameterRef="APID"/></EntryList>
        </SequenceContainer>
        <SequenceContainer name="Housekeeping">
          <BaseContainer containerRef="Packet">
            <RestrictionCriteria><Comparison parameterRef="APID" value="1"/></RestrictionCriteria>
          </BaseContainer>
          <EntryList><ParameterRefEntry parameterRef="HOUSEKEEPING"/></EntryList>
        </SequenceContainer>
        <SequenceContainer name="Science">
          <BaseContainer containerRef="Packet">
            <RestrictionCriteria><Comparison parameterRef="APID" value="2"/></RestrictionCriteria>
          </BaseContainer>
          <EntryList><ParameterRefEntry parameterRef="SCIENCE"/></EntryList>
        </SequenceContainer>"#,
    );
    let db = load(&xml);
    let decoder = Decoder::with_root(&db, "Packet").expect("root");

    let decoded = decoder.decode(&[1, 0x12, 0x34]).expect("housekeeping");
    assert_eq!(
        db.name(db.container(decoded.container()).expect("resolves").name),
        "Housekeeping"
    );
    assert_eq!(
        decoded.get_by_name("HOUSEKEEPING").map(|v| v.eng.clone()),
        Some(EngValue::Unsigned(0x1234))
    );
    assert!(decoded.get_by_name("SCIENCE").is_none());

    let decoded = decoder.decode(&[2, 0x56, 0x78]).expect("science");
    assert_eq!(
        db.name(db.container(decoded.container()).expect("resolves").name),
        "Science"
    );

    // An APID no inheritor claims leaves the abstract root with nothing to descend into.
    assert!(matches!(
        decoder.decode(&[3, 0x00, 0x00]),
        Err(DecodeError::UnrecognizedPacket { .. })
    ));
}

#[test]
fn container_ref_entries_are_expanded_inline() {
    let xml = definition(
        r#"<IntegerParameterType name="T8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>"#,
        r#"
        <Parameter name="A" parameterTypeRef="T8"/>
        <Parameter name="B" parameterTypeRef="T8"/>
        <Parameter name="C" parameterTypeRef="T8"/>"#,
        r#"
        <SequenceContainer name="Header">
          <EntryList><ParameterRefEntry parameterRef="A"/><ParameterRefEntry parameterRef="B"/></EntryList>
        </SequenceContainer>
        <SequenceContainer name="Packet">
          <EntryList>
            <ContainerRefEntry containerRef="Header"/>
            <ParameterRefEntry parameterRef="C"/>
          </EntryList>
        </SequenceContainer>"#,
    );
    let db = load(&xml);
    let values = decode_one(&db, &[1, 2, 3]);
    assert_eq!(
        values
            .iter()
            .map(|(name, ..)| name.as_str())
            .collect::<Vec<_>>(),
        vec!["A", "B", "C"]
    );
    assert_eq!(values[2].1, RawValue::Unsigned(3));
}

#[test]
fn location_in_container_seeks_within_the_packet() {
    let xml = definition(
        r#"<IntegerParameterType name="T8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>"#,
        r#"
        <Parameter name="FIRST" parameterTypeRef="T8"/>
        <Parameter name="SKIPPED_TO" parameterTypeRef="T8"/>
        <Parameter name="FROM_START" parameterTypeRef="T8"/>"#,
        r#"
        <SequenceContainer name="Packet">
          <EntryList>
            <ParameterRefEntry parameterRef="FIRST"/>
            <ParameterRefEntry parameterRef="SKIPPED_TO">
              <LocationInContainerInBits referenceLocation="previousEntry"><FixedValue>16</FixedValue></LocationInContainerInBits>
            </ParameterRefEntry>
            <ParameterRefEntry parameterRef="FROM_START">
              <LocationInContainerInBits referenceLocation="containerStart"><FixedValue>8</FixedValue></LocationInContainerInBits>
            </ParameterRefEntry>
          </EntryList>
        </SequenceContainer>"#,
    );
    let db = load(&xml);
    // Byte 0 is FIRST; two bytes of padding are skipped; byte 3 is SKIPPED_TO; then the
    // cursor jumps back to bit 8, so FROM_START reads byte 1.
    let values = decode_one(&db, &[0x11, 0x22, 0x33, 0x44]);
    assert_eq!(values[0].1, RawValue::Unsigned(0x11));
    assert_eq!(values[1].1, RawValue::Unsigned(0x44));
    assert_eq!(values[2].1, RawValue::Unsigned(0x22));
}

#[test]
fn repeat_entries_with_a_fixed_count() {
    let xml = definition(
        r#"<IntegerParameterType name="T8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>"#,
        r#"<Parameter name="SAMPLE" parameterTypeRef="T8"/>"#,
        r#"
        <SequenceContainer name="Packet">
          <EntryList>
            <ParameterRefEntry parameterRef="SAMPLE">
              <RepeatEntry><Count><FixedValue>3</FixedValue></Count></RepeatEntry>
            </ParameterRefEntry>
          </EntryList>
        </SequenceContainer>"#,
    );
    let db = load(&xml);
    let decoder = Decoder::with_root(&db, "Packet").expect("root");
    let decoded = decoder.decode(&[1, 2, 3]).expect("decodes");
    // Repeating one parameter overwrites it, exactly as a dict assignment would; what the
    // repeat buys is the cursor advance, so all three bytes are consumed.
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded.bits_consumed(), 24);
    assert_eq!(decoded.trailing_bits(), 0);
    assert_eq!(
        decoded.get_by_name("SAMPLE").map(|v| v.raw.clone()),
        Some(RawValue::Unsigned(3))
    );
}

#[test]
fn a_truncated_packet_is_an_error_not_a_panic() {
    let xml = simple(
        r#"<IntegerParameterType name="T"><IntegerDataEncoding sizeInBits="32" encoding="unsigned"/></IntegerParameterType>"#,
        r#"<Parameter name="WORD" parameterTypeRef="T"/>"#,
        r#"<ParameterRefEntry parameterRef="WORD"/>"#,
    );
    let db = load(&xml);
    let decoder = Decoder::with_root(&db, "Packet").expect("root");
    for length in 0..4 {
        let packet = vec![0xFFu8; length];
        assert!(
            matches!(decoder.decode(&packet), Err(DecodeError::Bits { .. })),
            "length {length} should fail cleanly"
        );
    }
    assert!(decoder.decode(&[0xFF; 4]).is_ok());
}

#[test]
fn trailing_bits_are_reported_not_hidden() {
    let xml = simple(
        r#"<IntegerParameterType name="T"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>"#,
        r#"<Parameter name="BYTE" parameterTypeRef="T"/>"#,
        r#"<ParameterRefEntry parameterRef="BYTE"/>"#,
    );
    let db = load(&xml);
    let decoder = Decoder::with_root(&db, "Packet").expect("root");
    let decoded = decoder.decode(&[1, 2, 3]).expect("decodes");
    assert_eq!(decoded.bits_consumed(), 8);
    assert_eq!(decoded.trailing_bits(), 16);
}

#[test]
fn out_of_scope_constructs_load_and_fail_at_decode() {
    // An ArrayParameterType is modelled but not decodable. Loading must succeed — a real
    // mission database is full of things this crate does not decode — and the failure must
    // name the element.
    let xml = simple(
        r#"
        <IntegerParameterType name="T8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>
        <ArrayParameterType name="ARR" arrayTypeRef="T8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></ArrayParameterType>"#,
        r#"<Parameter name="SAMPLES" parameterTypeRef="ARR"/>"#,
        r#"<ParameterRefEntry parameterRef="SAMPLES"/>"#,
    );
    let db = load(&xml);
    assert!(
        !db.unsupported().is_empty(),
        "the array type should be recorded as unsupported"
    );

    let decoder = Decoder::with_root(&db, "Packet").expect("root");
    match decoder.decode(&[0x00]) {
        Err(DecodeError::Unsupported { element, .. }) => {
            assert_eq!(element, "ArrayParameterType");
        }
        other => panic!("expected an Unsupported error, got {other:?}"),
    }
}

#[test]
fn boolean_expression_criteria() {
    let xml = definition(
        r#"<IntegerParameterType name="T8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>"#,
        r#"
        <Parameter name="A" parameterTypeRef="T8"/>
        <Parameter name="B" parameterTypeRef="T8"/>
        <Parameter name="PAYLOAD" parameterTypeRef="T8"/>"#,
        r#"
        <SequenceContainer name="Packet" abstract="true">
          <EntryList><ParameterRefEntry parameterRef="A"/><ParameterRefEntry parameterRef="B"/></EntryList>
        </SequenceContainer>
        <SequenceContainer name="Both">
          <BaseContainer containerRef="Packet">
            <RestrictionCriteria>
              <BooleanExpression>
                <ANDedConditions>
                  <Condition><ParameterInstanceRef parameterRef="A"/><ComparisonOperator>==</ComparisonOperator><Value>1</Value></Condition>
                  <Condition><ParameterInstanceRef parameterRef="B"/><ComparisonOperator>&gt;</ComparisonOperator><Value>5</Value></Condition>
                </ANDedConditions>
              </BooleanExpression>
            </RestrictionCriteria>
          </BaseContainer>
          <EntryList><ParameterRefEntry parameterRef="PAYLOAD"/></EntryList>
        </SequenceContainer>"#,
    );
    let db = load(&xml);
    let decoder = Decoder::with_root(&db, "Packet").expect("root");

    assert!(
        decoder.decode(&[1, 6, 0xFF]).is_ok(),
        "both conditions hold"
    );
    assert!(
        matches!(
            decoder.decode(&[1, 5, 0xFF]),
            Err(DecodeError::UnrecognizedPacket { .. })
        ),
        "second condition fails"
    );
    assert!(
        matches!(
            decoder.decode(&[0, 6, 0xFF]),
            Err(DecodeError::UnrecognizedPacket { .. })
        ),
        "first condition fails"
    );
}

#[test]
fn comparison_against_an_enumeration_label() {
    // The reference coerces a comparison literal to the runtime type of the value, so a
    // criterion on an enumerated parameter compares against its *label*, not its raw value.
    let xml = definition(
        r#"
        <EnumeratedParameterType name="MODE_T">
          <IntegerDataEncoding sizeInBits="8" encoding="unsigned"/>
          <EnumerationList><Enumeration value="0" label="IDLE"/><Enumeration value="1" label="ACTIVE"/></EnumerationList>
        </EnumeratedParameterType>
        <IntegerParameterType name="T8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>"#,
        r#"
        <Parameter name="MODE" parameterTypeRef="MODE_T"/>
        <Parameter name="PAYLOAD" parameterTypeRef="T8"/>"#,
        r#"
        <SequenceContainer name="Packet" abstract="true">
          <EntryList><ParameterRefEntry parameterRef="MODE"/></EntryList>
        </SequenceContainer>
        <SequenceContainer name="Active">
          <BaseContainer containerRef="Packet">
            <RestrictionCriteria><Comparison parameterRef="MODE" value="ACTIVE"/></RestrictionCriteria>
          </BaseContainer>
          <EntryList><ParameterRefEntry parameterRef="PAYLOAD"/></EntryList>
        </SequenceContainer>"#,
    );
    let db = load(&xml);
    let decoder = Decoder::with_root(&db, "Packet").expect("root");
    assert!(decoder.decode(&[1, 0x42]).is_ok());
    assert!(matches!(
        decoder.decode(&[0, 0x42]),
        Err(DecodeError::UnrecognizedPacket { .. })
    ));
}

#[test]
fn ambiguous_inheritors_are_reported() {
    let xml = definition(
        r#"<IntegerParameterType name="T8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>"#,
        r#"<Parameter name="A" parameterTypeRef="T8"/>"#,
        r#"
        <SequenceContainer name="Packet" abstract="true">
          <EntryList><ParameterRefEntry parameterRef="A"/></EntryList>
        </SequenceContainer>
        <SequenceContainer name="One">
          <BaseContainer containerRef="Packet">
            <RestrictionCriteria><Comparison parameterRef="A" value="1"/></RestrictionCriteria>
          </BaseContainer>
          <EntryList/>
        </SequenceContainer>
        <SequenceContainer name="Also">
          <BaseContainer containerRef="Packet">
            <RestrictionCriteria><Comparison parameterRef="A" comparisonOperator="&lt;" value="9"/></RestrictionCriteria>
          </BaseContainer>
          <EntryList/>
        </SequenceContainer>"#,
    );
    let db = load(&xml);
    let decoder = Decoder::with_root(&db, "Packet").expect("root");
    match decoder.decode(&[1]) {
        Err(DecodeError::AmbiguousPacket { candidates, .. }) => {
            assert_eq!(candidates.len(), 2);
        }
        other => panic!("expected an ambiguity error, got {other:?}"),
    }
}

#[test]
fn cyclic_container_inheritance_is_rejected_at_load() {
    let xml = definition(
        r#"<IntegerParameterType name="T8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>"#,
        r#"<Parameter name="A" parameterTypeRef="T8"/>"#,
        r#"
        <SequenceContainer name="First">
          <BaseContainer containerRef="Second"/>
          <EntryList><ParameterRefEntry parameterRef="A"/></EntryList>
        </SequenceContainer>
        <SequenceContainer name="Second">
          <BaseContainer containerRef="First"/>
          <EntryList><ParameterRefEntry parameterRef="A"/></EntryList>
        </SequenceContainer>"#,
    );
    match XtceDb::from_xml(&xml) {
        Err(xtce_model::XtceError::InheritanceCycle { chain }) => {
            assert!(chain.len() >= 2, "cycle should name the containers");
        }
        Err(other) => panic!("expected an inheritance cycle error, got {other}"),
        Ok(_) => panic!("a cyclic definition must not load"),
    }
}

#[test]
fn namespace_spelling_does_not_change_the_result() {
    let body = r#"
  <TelemetryMetaData>
    <ParameterTypeSet>
      <IntegerParameterType name="T"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>
    </ParameterTypeSet>
    <ParameterSet><Parameter name="A" parameterTypeRef="T"/></ParameterSet>
    <ContainerSet>
      <SequenceContainer name="Packet"><EntryList><ParameterRefEntry parameterRef="A"/></EntryList></SequenceContainer>
    </ContainerSet>
  </TelemetryMetaData>"#;

    let bare = format!(r#"<SpaceSystem name="T">{body}</SpaceSystem>"#);
    let defaulted = format!(
        r#"<SpaceSystem xmlns="http://www.omg.org/spec/XTCE/20180204" name="T">{body}</SpaceSystem>"#
    );
    let prefixed_body = body.replace('<', "<xtce:").replace("<xtce:/", "</xtce:");
    let prefixed = format!(
        r#"<xtce:SpaceSystem xmlns:xtce="http://www.omg.org/spec/XTCE/20180204" name="T">{prefixed_body}</xtce:SpaceSystem>"#
    );

    for xml in [&bare, &defaulted, &prefixed] {
        let db = load(xml);
        let values = decode_one(&db, &[0x5A]);
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].1, RawValue::Unsigned(0x5A));
    }
}

/// Every reference shape XTCE allows, across nested space systems.
///
/// All ten bundled test files have exactly one `SpaceSystem`, so nothing in `testdata`
/// reaches path resolution, ancestor search, or `.`/`..` segments. This is the only coverage
/// those paths have.
#[test]
fn references_resolve_across_nested_space_systems() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<SpaceSystem xmlns="http://www.omg.org/spec/XTCE/20180204" name="Root">
  <TelemetryMetaData>
    <ParameterTypeSet>
      <IntegerParameterType name="Shared8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>
    </ParameterTypeSet>
    <ParameterSet>
      <!-- Only visible to descendants through the ancestor walk. -->
      <Parameter name="FROM_ROOT" parameterTypeRef="Shared8"/>
    </ParameterSet>
  </TelemetryMetaData>

  <SpaceSystem name="Bus">
    <TelemetryMetaData>
      <ParameterTypeSet>
        <IntegerParameterType name="Local16"><IntegerDataEncoding sizeInBits="16" encoding="unsigned"/></IntegerParameterType>
        <!-- Same leaf name as Payload/Width, and registered first. A resolver that fell
             back to the document-wide leaf table would pick this one from anywhere. -->
        <IntegerParameterType name="Width"><IntegerDataEncoding sizeInBits="32" encoding="unsigned"/></IntegerParameterType>
      </ParameterTypeSet>
      <ParameterSet>
        <Parameter name="BUS_VOLTAGE" parameterTypeRef="Local16"/>
      </ParameterSet>
    </TelemetryMetaData>
  </SpaceSystem>

  <SpaceSystem name="Payload">
    <TelemetryMetaData>
      <ParameterTypeSet>
        <IntegerParameterType name="Local8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>
        <IntegerParameterType name="Width"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>
      </ParameterTypeSet>
      <ParameterSet>
        <!-- Bare name: resolved by walking up to Root. -->
        <Parameter name="P_ANCESTOR" parameterTypeRef="Shared8"/>
        <Parameter name="P_LOCAL" parameterTypeRef="Local8"/>
        <!-- Absolute path into a sibling space system. -->
        <Parameter name="P_ABSOLUTE" parameterTypeRef="/Root/Bus/Local16"/>
        <!-- Relative path with `..`, reaching the same sibling. -->
        <Parameter name="P_RELATIVE" parameterTypeRef="../Bus/Local16"/>
        <!-- Explicit `.` prefix for a local type. -->
        <Parameter name="P_DOT" parameterTypeRef="./Local8"/>
        <!-- The discriminating pair: both name a type called `Width`, and the leaf table
             holds only Bus's. Only real path resolution gets these right. -->
        <Parameter name="P_LOCAL_WIDTH" parameterTypeRef="./Width"/>
        <Parameter name="P_SIBLING_WIDTH" parameterTypeRef="/Root/Bus/Width"/>
      </ParameterSet>
      <ContainerSet>
        <SequenceContainer name="Packet">
          <EntryList>
            <ParameterRefEntry parameterRef="P_ANCESTOR"/>
            <ParameterRefEntry parameterRef="P_LOCAL"/>
            <ParameterRefEntry parameterRef="P_ABSOLUTE"/>
            <ParameterRefEntry parameterRef="P_RELATIVE"/>
            <ParameterRefEntry parameterRef="P_DOT"/>
            <ParameterRefEntry parameterRef="P_LOCAL_WIDTH"/>
            <ParameterRefEntry parameterRef="/Root/FROM_ROOT"/>
            <ParameterRefEntry parameterRef="../Bus/BUS_VOLTAGE"/>
          </EntryList>
        </SequenceContainer>
      </ContainerSet>
    </TelemetryMetaData>
  </SpaceSystem>
</SpaceSystem>"#;

    let db = load(xml);
    assert_eq!(db.stats().space_systems, 3);

    // Qualified names must reflect the nesting.
    let payload_local = db
        .find_type("/Root/Payload/Local8")
        .expect("qualified type");
    assert_eq!(
        db.name(db.parameter_type(payload_local).expect("resolves").name),
        "Local8"
    );

    // Each reference shape must have found the right width: 8 bits except the two that
    // reach `Bus/Local16`.
    let widths: Vec<u32> = [
        "P_ANCESTOR",
        "P_LOCAL",
        "P_ABSOLUTE",
        "P_RELATIVE",
        "P_DOT",
        // 8 from Payload/Width, not 32 from Bus/Width, which is what the leaf table holds.
        "P_LOCAL_WIDTH",
        "P_SIBLING_WIDTH",
    ]
    .iter()
    .map(|name| {
        let id = db
            .find_parameter(name)
            .unwrap_or_else(|| panic!("{name} exists"));
        db.type_of(id)
            .and_then(xtce_model::ParameterType::fixed_size_in_bits)
            .unwrap_or_else(|| panic!("{name} has a fixed size"))
    })
    .collect();
    assert_eq!(widths, vec![8, 8, 16, 16, 8, 8, 32]);

    // And the container's entry list resolved both a path and an ancestor reference.
    let decoder = Decoder::with_root(&db, "Packet").expect("root");
    let decoded = decoder
        .decode(&[1, 2, 0x00, 0x03, 0x00, 0x04, 5, 9, 6, 0x00, 0x07])
        .expect("decodes");
    assert_eq!(decoded.len(), 8);
    assert_eq!(
        decoded.get_by_name("P_ABSOLUTE").map(|v| v.raw.clone()),
        Some(RawValue::Unsigned(3))
    );
    assert_eq!(
        decoded.get_by_name("BUS_VOLTAGE").map(|v| v.raw.clone()),
        Some(RawValue::Unsigned(7))
    );
    assert_eq!(decoded.trailing_bits(), 0);
}

#[test]
fn an_unresolvable_reference_names_itself() {
    let xml = simple(
        r#"<IntegerParameterType name="T"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>"#,
        r#"<Parameter name="A" parameterTypeRef="NoSuchType"/>"#,
        r#"<ParameterRefEntry parameterRef="A"/>"#,
    );
    match XtceDb::from_xml(&xml) {
        Err(xtce_model::XtceError::UnresolvedReference { reference, .. }) => {
            assert_eq!(reference, "NoSuchType");
        }
        Err(other) => panic!("expected an unresolved reference, got {other}"),
        Ok(_) => panic!("a dangling reference must not load"),
    }
}

/// MIL-STD-1750A is a 32-bit format, and any other width is refused rather than truncated.
///
/// The reference raises when a definition says otherwise, and raises at *load*, so a file
/// like this one does not open in Python at all. Here it opens — loading always succeeds, and
/// only decoding reports what it cannot do — but the parameter reports rather than decoding
/// the low 32 bits of a 48-bit field, which is a number nothing else would ever produce.
#[test]
fn a_mil_std_1750a_float_that_is_not_32_bits_is_refused() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<SpaceSystem xmlns="http://www.omg.org/spec/XTCE/20180204" name="T">
  <TelemetryMetaData>
    <ParameterTypeSet>
      <FloatParameterType name="WIDE_T">
        <FloatDataEncoding sizeInBits="48" encoding="MILSTD_1750A"/>
      </FloatParameterType>
      <FloatParameterType name="OK_T">
        <FloatDataEncoding sizeInBits="32" encoding="MILSTD_1750A"/>
      </FloatParameterType>
    </ParameterTypeSet>
    <ParameterSet>
      <Parameter name="OK" parameterTypeRef="OK_T"/>
      <Parameter name="WIDE" parameterTypeRef="WIDE_T"/>
    </ParameterSet>
    <ContainerSet>
      <SequenceContainer name="Only">
        <EntryList>
          <ParameterRefEntry parameterRef="OK"/>
          <ParameterRefEntry parameterRef="WIDE"/>
        </EntryList>
      </SequenceContainer>
    </ContainerSet>
  </TelemetryMetaData>
</SpaceSystem>"#;

    let db = XtceDb::from_xml(xml).expect("the definition loads");
    let decoder = Decoder::new(&db).expect("root container");
    // 0x40000001 is 1.0 in MIL-STD-1750A, then six bytes for the 48-bit field.
    let packet = [0x40, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    let mut decoded = decoder.new_packet(&packet);
    let error = decoder
        .decode_into(&mut decoded, &packet)
        .expect_err("the 48-bit field cannot be decoded");
    let message = error.to_string();
    assert!(
        message.contains("48 bits"),
        "the refusal should say how wide: {message}"
    );
    assert!(
        message.contains("MIL-STD-1750A"),
        "and what it is: {message}"
    );
}

// -------------------------------------------------------------------------------------
// Telecommands
// -------------------------------------------------------------------------------------

/// A telecommand definition: two commands, one specialising the other.
///
/// `SetMode` extends `Base` by pinning `OPCODE` to 7, so a packet is `SetMode` when its
/// opcode byte is 7 and `Base` — which is abstract, and therefore never the answer — when it
/// is not. Between the sync pattern and the opcode there is nothing to decode: a
/// `<FixedValueEntry>` is bits the definition wrote and nobody's value.
const COMMANDS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<SpaceSystem xmlns="http://www.omg.org/spec/XTCE/20180204" name="Test">
  <TelemetryMetaData>
    <ParameterTypeSet>
      <IntegerParameterType name="U8"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerParameterType>
    </ParameterTypeSet>
    <ParameterSet><Parameter name="TM" parameterTypeRef="U8"/></ParameterSet>
    <ContainerSet>
      <SequenceContainer name="Report"><EntryList><ParameterRefEntry parameterRef="TM"/></EntryList></SequenceContainer>
    </ContainerSet>
  </TelemetryMetaData>
  <CommandMetaData>
    <ArgumentTypeSet>
      <IntegerArgumentType name="U8_A"><IntegerDataEncoding sizeInBits="8" encoding="unsigned"/></IntegerArgumentType>
      <IntegerArgumentType name="U16_A"><IntegerDataEncoding sizeInBits="16" encoding="unsigned"/></IntegerArgumentType>
    </ArgumentTypeSet>
    <MetaCommandSet>
      <MetaCommand name="Base" abstract="true">
        <ArgumentList><Argument name="OPCODE" argumentTypeRef="U8_A"/></ArgumentList>
        <CommandContainer name="BaseContainer">
          <EntryList>
            <FixedValueEntry name="SYNC" binaryValue="1ACFFC1D" sizeInBits="32"/>
            <ArgumentRefEntry argumentRef="OPCODE"/>
          </EntryList>
        </CommandContainer>
      </MetaCommand>
      <MetaCommand name="SetMode">
        <BaseMetaCommand metaCommandRef="Base">
          <ArgumentAssignmentList>
            <ArgumentAssignment argumentName="OPCODE" argumentValue="7"/>
          </ArgumentAssignmentList>
        </BaseMetaCommand>
        <ArgumentList><Argument name="MODE" argumentTypeRef="U16_A"/></ArgumentList>
        <CommandContainer name="SetModeContainer">
          <EntryList><ArgumentRefEntry argumentRef="MODE"/></EntryList>
          <BaseContainer containerRef="BaseContainer"/>
        </CommandContainer>
      </MetaCommand>
    </MetaCommandSet>
  </CommandMetaData>
</SpaceSystem>"#;

/// A telecommand decodes with the machinery telemetry uses, because it is a container.
///
/// Nothing in the decoder knows what a command is. The root is named rather than defaulted —
/// see below — and from there the argument assignment selects the specialisation exactly as
/// a `<RestrictionCriteria>` would.
#[test]
fn a_telecommand_decodes_like_any_other_container() {
    let db = load(COMMANDS);
    let decoder = Decoder::with_root(&db, "BaseContainer").expect("root container");

    // Sync, opcode 7, mode 0x0102.
    let packet = [0x1A, 0xCF, 0xFC, 0x1D, 7, 0x01, 0x02];
    let decoded = decoder.decode(&packet).expect("packet decodes");

    let values: Vec<(String, RawValue<'_>)> = decoded
        .iter_named()
        .map(|(name, value)| (name.to_owned(), value.raw.clone()))
        .collect();
    assert_eq!(
        values,
        vec![
            ("OPCODE".to_owned(), RawValue::Unsigned(7)),
            ("MODE".to_owned(), RawValue::Unsigned(0x0102)),
        ],
        "the fixed value contributes no value, and the arguments do"
    );
    assert_eq!(
        db.name(
            db.container(decoded.container())
                .expect("the container resolves")
                .name
        ),
        "SetModeContainer",
        "the argument assignment selected the specialisation"
    );
}

/// An opcode the assignment does not match stops at the abstract base, and is refused.
#[test]
fn a_telecommand_whose_assignment_does_not_hold_is_not_that_command() {
    let db = load(COMMANDS);
    let decoder = Decoder::with_root(&db, "BaseContainer").expect("root container");

    let packet = [0x1A, 0xCF, 0xFC, 0x1D, 8, 0x01, 0x02];
    let error = decoder
        .decode(&packet)
        .expect_err("opcode 8 is no command here");
    assert!(
        matches!(error, DecodeError::UnrecognizedPacket { .. }),
        "unexpected error: {error}"
    );
}

/// Adding a command half does not take the default root away from the telemetry.
///
/// A command container with no `<BaseContainer>` is a root of the command tree, so counting
/// it among the candidates would leave a definition that used to have exactly one root with
/// two, and `Decoder::new` would stop working on a file whose telemetry had not changed.
#[test]
fn the_default_root_ignores_command_containers() {
    let db = load(COMMANDS);
    let decoder = Decoder::new(&db).expect("the telemetry root is still unambiguous");
    let decoded = decoder.decode(&[42]).expect("packet decodes");
    assert_eq!(
        db.name(
            db.container(decoded.container())
                .expect("the container resolves")
                .name
        ),
        "Report"
    );
}
