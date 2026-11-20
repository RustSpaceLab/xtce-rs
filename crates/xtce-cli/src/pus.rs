//! `xtce pus` — inspect ECSS-E-ST-70-41C (PUS-C) packet streams, run closed-loop HIL demos,
//! and emit a matching XTCE 1.2 mission database (`--emit-xtce`).

use std::io::{Read, Write};
use std::path::Path;

use xtce_decode::PacketReader;
use xtce_pus::{
    AckFlags, FUNC_EO_OPTICAL_CAPTURE, HousekeepingMessage, MAX_HIL_FRAME_LEN, MemoryMessage,
    MonitoringMessage, ObcHousekeeping, ParameterManagementMessage, PusError, PusHeader, PusPacket,
    PusResponder, PusService, ScheduleMessage, TcParams, TestMessage, VerificationReport,
    encode_tc,
};

/// Configuration for `xtce pus`.
pub struct Options<'a> {
    pub packets: Option<&'a Path>,
    pub hil_demo: bool,
    pub hil_udp: Option<&'a str>,
    pub emit_xtce: bool,
    pub out: Option<&'a Path>,
    pub skip_header_bytes: usize,
    pub limit: Option<usize>,
}

fn open_packet_source(packets: &Path) -> std::io::Result<Box<dyn Read>> {
    if packets.as_os_str() == "-" {
        Ok(Box::new(std::io::BufReader::new(std::io::stdin())))
    } else {
        let file = std::fs::File::open(packets)?;
        Ok(Box::new(std::io::BufReader::new(file)))
    }
}

/// Executes `xtce pus`.
///
/// # Errors
///
/// Returns an error if no action (`<PACKETS>`, `--hil-demo`, `--hil-udp`, or `--emit-xtce`) is
/// specified or if I/O fails.
pub fn run(options: &Options<'_>) -> Result<(), Box<dyn std::error::Error>> {
    if options.emit_xtce {
        return write_pus_xtce(options.out);
    }

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    if let Some(bind_addr) = options.hil_udp {
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        serve_hil_udp(&socket, &mut out, options.limit)?;
        out.flush()?;
        return Ok(());
    }

    if options.hil_demo {
        run_hil_demo(&mut out, options.out)?;
        out.flush()?;
        return Ok(());
    }

    let Some(packets_path) = options.packets else {
        return Err(
            "provide a packet stream file (or '-'), --hil-demo, --hil-udp, or --emit-xtce".into(),
        );
    };

    let source = open_packet_source(packets_path)?;
    let mut reader = PacketReader::new(source, options.skip_header_bytes);
    inspect_stream(&mut reader, &mut out, options.limit)?;
    out.flush()?;
    Ok(())
}

fn write_pus_xtce(out_path: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    match out_path {
        Some(path) if path.as_os_str() != "-" => {
            std::fs::write(path, ECSS_PUS_XTCE_XML)?;
            eprintln!("wrote ECSS PUS-C XTCE definition to {}", path.display());
        }
        _ => print!("{ECSS_PUS_XTCE_XML}"),
    }
    Ok(())
}

fn inspect_stream<R: Read, W: Write>(
    reader: &mut PacketReader<R>,
    out: &mut W,
    limit: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut total = 0usize;
    let mut valid = 0usize;
    let mut crc_failed = 0usize;
    let mut malformed = 0usize;

    while let Some(framed) = reader.next_packet()? {
        if limit.is_some_and(|max| total >= max) {
            break;
        }
        let index = total;
        total += 1;

        match PusPacket::parse(framed.bytes()) {
            Ok(pkt) => {
                valid += 1;
                write_pus_packet(out, index, &pkt)?;
            }
            Err(PusError::CrcMismatch { expected, computed }) => {
                crc_failed += 1;
                writeln!(
                    out,
                    "packet {index:>4}  [CRC FAIL] packet=0x{expected:04X} computed=0x{computed:04X}"
                )?;
            }
            Err(err) => {
                malformed += 1;
                writeln!(out, "packet {index:>4}  [NON-PUS]  {err}")?;
            }
        }
    }

    writeln!(out)?;
    writeln!(
        out,
        "{total} packet(s): {valid} valid ECSS PUS (CRC-16-CCITT ok), {crc_failed} CRC failed, {malformed} non-PUS"
    )?;
    Ok(())
}

fn write_pus_packet(
    out: &mut impl Write,
    index: usize,
    pkt: &PusPacket<'_>,
) -> std::io::Result<()> {
    match pkt.header {
        PusHeader::Telecommand {
            version,
            service,
            subtype,
            source_id,
            ..
        } => {
            write!(
                out,
                "packet {index:>4}  TC[{service},{subtype}]  PUS-v{version} apid=0x{:03X} seq={} src=0x{source_id:04X} crc=0x{:04X}  ",
                pkt.apid, pkt.sequence_count, pkt.crc
            )?;
        }
        PusHeader::Telemetry {
            version,
            service,
            subtype,
            msg_counter,
            timestamp,
            ..
        } => {
            write!(
                out,
                "packet {index:>4}  TM[{service},{subtype}]  PUS-v{version} apid=0x{:03X} seq={} cnt={msg_counter} t={}s crc=0x{:04X}  ",
                pkt.apid, pkt.sequence_count, timestamp.coarse_seconds, pkt.crc
            )?;
        }
    }

    match pkt.decode_service() {
        Ok(PusService::Verification(ver)) => write_verification_summary(out, ver),
        Ok(PusService::Housekeeping(hk)) => write_hk_summary(out, &hk),
        Ok(PusService::Event(ev)) => writeln!(
            out,
            "Event({:?}, id=0x{:04X}, aux={}B)",
            ev.severity,
            ev.event_id,
            ev.aux_data.len()
        ),
        Ok(PusService::Memory(mem)) => write_memory_summary(out, &mem),
        Ok(PusService::Function(call)) => writeln!(
            out,
            "PerformFunction(fn_id=0x{:04X}, args={}B)",
            call.function_id,
            call.args.len()
        ),
        Ok(PusService::Schedule(sched)) => write_schedule_summary(out, &sched),
        Ok(PusService::Monitoring(mon)) => write_monitoring_summary(out, mon),
        Ok(PusService::ParameterManagement(pm)) => write_param_mgmt_summary(out, pm),
        Ok(PusService::Test(TestMessage::AreYouAliveCommand)) => {
            writeln!(out, "AreYouAliveCommand")
        }
        Ok(PusService::Test(TestMessage::AreYouAliveReport)) => {
            writeln!(out, "AreYouAliveReport")
        }
        Ok(PusService::Custom { app_data, .. }) => {
            writeln!(out, "ApplicationData({}B)", app_data.len())
        }
        Err(err) => writeln!(out, "MalformedService({err})"),
    }
}

fn write_verification_summary(
    out: &mut impl Write,
    ver: VerificationReport,
) -> std::io::Result<()> {
    match ver {
        VerificationReport::AcceptanceSuccess { request_id } => {
            writeln!(out, "AcceptanceSuccess(req=0x{request_id:08X})")
        }
        VerificationReport::AcceptanceFailure {
            request_id,
            failure_code,
        } => writeln!(
            out,
            "AcceptanceFailure(req=0x{request_id:08X}, code=0x{failure_code:04X})"
        ),
        VerificationReport::ExecutionStartSuccess { request_id } => {
            writeln!(out, "ExecutionStartSuccess(req=0x{request_id:08X})")
        }
        VerificationReport::ExecutionCompleteSuccess { request_id } => {
            writeln!(out, "ExecutionCompleteSuccess(req=0x{request_id:08X})")
        }
        VerificationReport::ExecutionCompleteFailure {
            request_id,
            failure_code,
        } => writeln!(
            out,
            "ExecutionCompleteFailure(req=0x{request_id:08X}, code=0x{failure_code:04X})"
        ),
    }
}

fn write_hk_summary(out: &mut impl Write, hk: &HousekeepingMessage<'_>) -> std::io::Result<()> {
    match hk {
        HousekeepingMessage::EnablePeriodic { sid } => {
            writeln!(out, "EnablePeriodicHk(sid={sid})")
        }
        HousekeepingMessage::DisablePeriodic { sid } => {
            writeln!(out, "DisablePeriodicHk(sid={sid})")
        }
        HousekeepingMessage::OneShotRequest { sid } => {
            writeln!(out, "OneShotHkRequest(sid={sid})")
        }
        HousekeepingMessage::ParameterReport { sid, parameters } => {
            if *sid == ObcHousekeeping::SID {
                if let Some(obc) = ObcHousekeeping::from_parameter_bytes(parameters) {
                    return writeln!(
                        out,
                        "ObcHkReport(sid={sid}, uptime={}s, vbus={}.{:02}V, temp={}.{:02}C, mode={})",
                        obc.uptime_s,
                        obc.bus_voltage_mv / 1_000,
                        (obc.bus_voltage_mv % 1_000) / 10,
                        obc.obc_temp_cdeg / 100,
                        (obc.obc_temp_cdeg.unsigned_abs()) % 100,
                        obc.mode
                    );
                }
            }
            writeln!(out, "HkParameterReport(sid={sid}, {}B)", parameters.len())
        }
    }
}

fn write_memory_summary(out: &mut impl Write, mem: &MemoryMessage<'_>) -> std::io::Result<()> {
    match mem {
        MemoryMessage::LoadRaw {
            memory_id,
            address,
            data,
        } => writeln!(
            out,
            "MemoryLoadRaw(mem={memory_id}, addr=0x{address:08X}, len={}B)",
            data.len()
        ),
        MemoryMessage::DumpRawRequest {
            memory_id,
            address,
            length,
        } => writeln!(
            out,
            "MemoryDumpRequest(mem={memory_id}, addr=0x{address:08X}, len={length}B)"
        ),
        MemoryMessage::DumpRawReport {
            memory_id,
            address,
            data,
        } => writeln!(
            out,
            "MemoryDumpReport(mem={memory_id}, addr=0x{address:08X}, len={}B)",
            data.len()
        ),
        MemoryMessage::CheckRawRequest {
            memory_id,
            address,
            length,
        } => writeln!(
            out,
            "MemoryCheckRequest(mem={memory_id}, addr=0x{address:08X}, len={length}B)"
        ),
        MemoryMessage::CheckRawReport {
            memory_id,
            address,
            length,
            checksum,
        } => writeln!(
            out,
            "MemoryCheckReport(mem={memory_id}, addr=0x{address:08X}, len={length}B, crc=0x{checksum:04X})"
        ),
    }
}

fn write_schedule_summary(
    out: &mut impl Write,
    sched: &ScheduleMessage<'_>,
) -> std::io::Result<()> {
    match sched {
        ScheduleMessage::Enable => writeln!(out, "ScheduleEnable"),
        ScheduleMessage::Disable => writeln!(out, "ScheduleDisable"),
        ScheduleMessage::Reset => writeln!(out, "ScheduleReset"),
        ScheduleMessage::InsertActivity {
            release_time_s,
            activity_data,
        } => writeln!(
            out,
            "ScheduleInsertActivity(release_t={release_time_s}s, payload={}B)",
            activity_data.len()
        ),
        ScheduleMessage::SummaryReport {
            enabled,
            pending_count,
        } => writeln!(
            out,
            "ScheduleSummaryReport(enabled={enabled}, pending={pending_count})"
        ),
    }
}

fn write_monitoring_summary(out: &mut impl Write, mon: MonitoringMessage) -> std::io::Result<()> {
    match mon {
        MonitoringMessage::Enable => writeln!(out, "MonitoringEnable"),
        MonitoringMessage::Disable => writeln!(out, "MonitoringDisable"),
        MonitoringMessage::CheckTransitionReport {
            param_id,
            observed_value,
            limit_value,
        } => writeln!(
            out,
            "MonitoringTransition(param=0x{param_id:04X}, val={observed_value}, limit={limit_value})"
        ),
    }
}

fn write_param_mgmt_summary(
    out: &mut impl Write,
    pm: ParameterManagementMessage,
) -> std::io::Result<()> {
    match pm {
        ParameterManagementMessage::ReportRequest { param_id } => {
            writeln!(out, "ParameterReportRequest(param=0x{param_id:04X})")
        }
        ParameterManagementMessage::ValueReport { param_id, value } => {
            writeln!(
                out,
                "ParameterValueReport(param=0x{param_id:04X}, val={value})"
            )
        }
        ParameterManagementMessage::SetValue { param_id, value } => {
            writeln!(
                out,
                "ParameterSetValue(param=0x{param_id:04X}, val={value})"
            )
        }
    }
}

fn run_hil_demo(
    out: &mut impl Write,
    capture_out: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(
        out,
        "=== ECSS-E-ST-70-41C (PUS-C) Earth Observation HIL Closed-Loop Session ==="
    )?;
    let mut responder = PusResponder::new(0x010, 0x0001);
    let mut recorded_stream: Vec<u8> = Vec::with_capacity(1024);
    let mut frame_index = 0usize;

    let sid_bytes = ObcHousekeeping::SID.to_be_bytes();
    let mem_load: [u8; 11] = [1, 0, 0, 0, 8, b'C', b'A', b'M', b'I', b'L', b'A'];
    let mem_check: [u8; 7] = [1, 0, 0, 0, 8, 0, 6];
    let fn_eo_capture: [u8; 3] = [
        (FUNC_EO_OPTICAL_CAPTURE >> 8) as u8,
        (FUNC_EO_OPTICAL_CAPTURE & 0xFF) as u8,
        0x01,
    ];
    let sched_insert: [u8; 6] = [0x00, 0x00, 0x02, 0x58, 0x00, 0x20];

    let steps: [(u8, u8, &[u8], bool); 9] = [
        (17, 1, &[], false),
        (3, 5, &sid_bytes, false),
        (6, 2, &mem_load, false),
        (6, 9, &mem_check, false),
        (8, 1, &fn_eo_capture, false),
        (11, 1, &[], false),
        (11, 4, &sched_insert, false),
        (3, 27, &sid_bytes, false),
        (17, 1, &[], true),
    ];

    let mut tc_buf = [0u8; MAX_HIL_FRAME_LEN];
    let mut tm_frames = [[0u8; MAX_HIL_FRAME_LEN]; 4];
    let mut tm_lens = [0usize; 4];

    for (seq, &(service, subtype, app_data, inject_bit_flip)) in steps.iter().enumerate() {
        responder.tick_second();
        let tc_len = encode_tc(
            &TcParams {
                apid: 0x010,
                sequence_count: u16::try_from(seq).unwrap_or(0),
                ack: AckFlags::ACCEPT_AND_COMPLETE,
                service,
                subtype,
                source_id: 0x0042,
            },
            app_data,
            &mut tc_buf,
        )?;

        if inject_bit_flip {
            tc_buf[7] ^= 0x80;
        }

        if let Ok(parsed_tc) = PusPacket::parse(&tc_buf[..tc_len]) {
            write_pus_packet(out, frame_index, &parsed_tc)?;
        } else {
            writeln!(
                out,
                "packet {frame_index:>4}  [UPLINK SEU BIT-FLIP INJECTED -> CRC-16-CCITT INVALID]"
            )?;
        }
        frame_index += 1;

        let tm_count =
            responder.process_telecommand(&tc_buf[..tc_len], &mut tm_frames, &mut tm_lens)?;
        for slot in 0..tm_count {
            let slice = &tm_frames[slot][..tm_lens[slot]];
            if let Ok(parsed_tm) = PusPacket::parse(slice) {
                write_pus_packet(out, frame_index, &parsed_tm)?;
            }
            recorded_stream.extend_from_slice(slice);
            frame_index += 1;
        }
    }

    if let Some(path) = capture_out {
        std::fs::write(path, &recorded_stream)?;
        eprintln!(
            "wrote {} bytes of ECSS PUS HIL telemetry frames to {}",
            recorded_stream.len(),
            path.display()
        );
    }

    Ok(())
}

/// Runs a live UDP FlatSat OBC responder loop on `socket`, processing up to `limit` telecommands.
///
/// # Errors
///
/// Returns an error if socket I/O or stream writing fails.
pub fn serve_hil_udp(
    socket: &std::net::UdpSocket,
    out: &mut impl Write,
    limit: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut responder = PusResponder::new(0x010, 0x0001);
    let mut rx_buf = [0u8; 256];
    let mut tm_frames = [[0u8; MAX_HIL_FRAME_LEN]; 4];
    let mut tm_lens = [0usize; 4];
    let mut processed = 0usize;
    let mut frame_index = 0usize;

    while limit.is_none_or(|max| processed < max) {
        let (n, peer) = socket.recv_from(&mut rx_buf)?;
        responder.tick_second();
        let tc_slice = &rx_buf[..n];

        if let Ok(parsed_tc) = PusPacket::parse(tc_slice) {
            write_pus_packet(out, frame_index, &parsed_tc)?;
        }
        frame_index += 1;

        if let Ok(tm_count) = responder.process_telecommand(tc_slice, &mut tm_frames, &mut tm_lens)
        {
            for slot in 0..tm_count {
                let slice = &tm_frames[slot][..tm_lens[slot]];
                socket.send_to(slice, peer)?;
                if let Ok(parsed_tm) = PusPacket::parse(slice) {
                    write_pus_packet(out, frame_index, &parsed_tm)?;
                }
                frame_index += 1;
            }
        }
        processed += 1;
    }

    Ok(())
}

/// Complete XTCE 1.2 XML mission definition describing the ECSS-E-ST-70-41C (PUS-C)
/// telemetry containers emitted by [`PusResponder`].
pub const ECSS_PUS_XTCE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<xtce:SpaceSystem name="ECSS_PUS_EO_Satellite" xmlns:xtce="http://www.omg.org/spec/XTCE/20180204">
  <xtce:TelemetryMetaData>
    <xtce:ParameterTypeSet>
      <xtce:IntegerParameterType name="U3_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="3" encoding="unsigned"/>
      </xtce:IntegerParameterType>
      <xtce:IntegerParameterType name="U1_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="1" encoding="unsigned"/>
      </xtce:IntegerParameterType>
      <xtce:IntegerParameterType name="U2_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="2" encoding="unsigned"/>
      </xtce:IntegerParameterType>
      <xtce:IntegerParameterType name="U4_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="4" encoding="unsigned"/>
      </xtce:IntegerParameterType>
      <xtce:IntegerParameterType name="U8_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="8" encoding="unsigned"/>
      </xtce:IntegerParameterType>
      <xtce:IntegerParameterType name="U11_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="11" encoding="unsigned"/>
      </xtce:IntegerParameterType>
      <xtce:IntegerParameterType name="U14_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="14" encoding="unsigned"/>
      </xtce:IntegerParameterType>
      <xtce:IntegerParameterType name="U16_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="16" encoding="unsigned"/>
      </xtce:IntegerParameterType>
      <xtce:IntegerParameterType name="U32_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="32" encoding="unsigned"/>
      </xtce:IntegerParameterType>
      <xtce:IntegerParameterType name="VBUS_V_T" signed="false">
        <xtce:IntegerDataEncoding sizeInBits="16" encoding="unsigned">
          <xtce:DefaultCalibrator>
            <xtce:PolynomialCalibrator>
              <xtce:Term exponent="0" coefficient="0.0"/>
              <xtce:Term exponent="1" coefficient="0.001"/>
            </xtce:PolynomialCalibrator>
          </xtce:DefaultCalibrator>
        </xtce:IntegerDataEncoding>
      </xtce:IntegerParameterType>
      <xtce:IntegerParameterType name="TEMP_C_T" signed="true">
        <xtce:IntegerDataEncoding sizeInBits="16" encoding="twosComplement">
          <xtce:DefaultCalibrator>
            <xtce:PolynomialCalibrator>
              <xtce:Term exponent="0" coefficient="0.0"/>
              <xtce:Term exponent="1" coefficient="0.01"/>
            </xtce:PolynomialCalibrator>
          </xtce:DefaultCalibrator>
        </xtce:IntegerDataEncoding>
      </xtce:IntegerParameterType>
      <xtce:EnumeratedParameterType name="OBC_MODE_T">
        <xtce:IntegerDataEncoding sizeInBits="8" encoding="unsigned"/>
        <xtce:EnumerationList>
          <xtce:Enumeration value="0" label="SAFE"/>
          <xtce:Enumeration value="1" label="IDLE"/>
          <xtce:Enumeration value="2" label="NOMINAL"/>
          <xtce:Enumeration value="3" label="EO_IMAGING"/>
        </xtce:EnumerationList>
      </xtce:EnumeratedParameterType>
    </xtce:ParameterTypeSet>
    <xtce:ParameterSet>
      <xtce:Parameter name="CCSDS_VERSION" parameterTypeRef="U3_T"/>
      <xtce:Parameter name="CCSDS_TYPE" parameterTypeRef="U1_T"/>
      <xtce:Parameter name="CCSDS_SEC_HDR" parameterTypeRef="U1_T"/>
      <xtce:Parameter name="CCSDS_APID" parameterTypeRef="U11_T"/>
      <xtce:Parameter name="CCSDS_SEQ_FLAGS" parameterTypeRef="U2_T"/>
      <xtce:Parameter name="CCSDS_SEQ_COUNT" parameterTypeRef="U14_T"/>
      <xtce:Parameter name="CCSDS_DATA_LEN" parameterTypeRef="U16_T"/>
      <xtce:Parameter name="PUS_VERSION" parameterTypeRef="U4_T"/>
      <xtce:Parameter name="PUS_TIME_REF" parameterTypeRef="U4_T"/>
      <xtce:Parameter name="PUS_SERVICE" parameterTypeRef="U8_T"/>
      <xtce:Parameter name="PUS_SUBTYPE" parameterTypeRef="U8_T"/>
      <xtce:Parameter name="PUS_MSG_COUNTER" parameterTypeRef="U16_T"/>
      <xtce:Parameter name="PUS_DEST_ID" parameterTypeRef="U16_T"/>
      <xtce:Parameter name="CUC_COARSE_S" parameterTypeRef="U32_T"/>
      <xtce:Parameter name="CUC_FINE_SUB" parameterTypeRef="U16_T"/>
      <xtce:Parameter name="VERIF_REQ_ID" parameterTypeRef="U32_T"/>
      <xtce:Parameter name="VERIF_FAIL_CODE" parameterTypeRef="U16_T"/>
      <xtce:Parameter name="HK_SID" parameterTypeRef="U16_T"/>
      <xtce:Parameter name="OBC_UPTIME_S" parameterTypeRef="U32_T"/>
      <xtce:Parameter name="OBC_VBUS_V" parameterTypeRef="VBUS_V_T"/>
      <xtce:Parameter name="OBC_TEMP_C" parameterTypeRef="TEMP_C_T"/>
      <xtce:Parameter name="OBC_MODE" parameterTypeRef="OBC_MODE_T"/>
      <xtce:Parameter name="EVENT_ID" parameterTypeRef="U16_T"/>
      <xtce:Parameter name="EVENT_AUX_U16" parameterTypeRef="U16_T"/>
      <xtce:Parameter name="EVENT_AUX_U8" parameterTypeRef="U8_T"/>
      <xtce:Parameter name="MEM_ID" parameterTypeRef="U8_T"/>
      <xtce:Parameter name="MEM_ADDR" parameterTypeRef="U32_T"/>
      <xtce:Parameter name="MEM_LEN" parameterTypeRef="U16_T"/>
      <xtce:Parameter name="MEM_CRC16" parameterTypeRef="U16_T"/>
      <xtce:Parameter name="SCHED_ENABLED" parameterTypeRef="U8_T"/>
      <xtce:Parameter name="SCHED_PENDING" parameterTypeRef="U16_T"/>
      <xtce:Parameter name="PEC_CRC16" parameterTypeRef="U16_T"/>
    </xtce:ParameterSet>
    <xtce:ContainerSet>
      <xtce:SequenceContainer name="CCSDSPacket" abstract="true">
        <xtce:EntryList>
          <xtce:ParameterRefEntry parameterRef="CCSDS_VERSION"/>
          <xtce:ParameterRefEntry parameterRef="CCSDS_TYPE"/>
          <xtce:ParameterRefEntry parameterRef="CCSDS_SEC_HDR"/>
          <xtce:ParameterRefEntry parameterRef="CCSDS_APID"/>
          <xtce:ParameterRefEntry parameterRef="CCSDS_SEQ_FLAGS"/>
          <xtce:ParameterRefEntry parameterRef="CCSDS_SEQ_COUNT"/>
          <xtce:ParameterRefEntry parameterRef="CCSDS_DATA_LEN"/>
          <xtce:ParameterRefEntry parameterRef="PUS_VERSION"/>
          <xtce:ParameterRefEntry parameterRef="PUS_TIME_REF"/>
          <xtce:ParameterRefEntry parameterRef="PUS_SERVICE"/>
          <xtce:ParameterRefEntry parameterRef="PUS_SUBTYPE"/>
          <xtce:ParameterRefEntry parameterRef="PUS_MSG_COUNTER"/>
          <xtce:ParameterRefEntry parameterRef="PUS_DEST_ID"/>
          <xtce:ParameterRefEntry parameterRef="CUC_COARSE_S"/>
          <xtce:ParameterRefEntry parameterRef="CUC_FINE_SUB"/>
        </xtce:EntryList>
      </xtce:SequenceContainer>
      <xtce:SequenceContainer name="TM_1_1_AcceptSuccess">
        <xtce:BaseContainer containerRef="CCSDSPacket">
          <xtce:RestrictionCriteria>
            <xtce:ComparisonList>
              <xtce:Comparison parameterRef="PUS_SERVICE" value="1"/>
              <xtce:Comparison parameterRef="PUS_SUBTYPE" value="1"/>
            </xtce:ComparisonList>
          </xtce:RestrictionCriteria>
        </xtce:BaseContainer>
        <xtce:EntryList>
          <xtce:ParameterRefEntry parameterRef="VERIF_REQ_ID"/>
          <xtce:ParameterRefEntry parameterRef="PEC_CRC16"/>
        </xtce:EntryList>
      </xtce:SequenceContainer>
      <xtce:SequenceContainer name="TM_1_2_AcceptFailure">
        <xtce:BaseContainer containerRef="CCSDSPacket">
          <xtce:RestrictionCriteria>
            <xtce:ComparisonList>
              <xtce:Comparison parameterRef="PUS_SERVICE" value="1"/>
              <xtce:Comparison parameterRef="PUS_SUBTYPE" value="2"/>
            </xtce:ComparisonList>
          </xtce:RestrictionCriteria>
        </xtce:BaseContainer>
        <xtce:EntryList>
          <xtce:ParameterRefEntry parameterRef="VERIF_REQ_ID"/>
          <xtce:ParameterRefEntry parameterRef="VERIF_FAIL_CODE"/>
          <xtce:ParameterRefEntry parameterRef="PEC_CRC16"/>
        </xtce:EntryList>
      </xtce:SequenceContainer>
      <xtce:SequenceContainer name="TM_1_7_CompleteSuccess">
        <xtce:BaseContainer containerRef="CCSDSPacket">
          <xtce:RestrictionCriteria>
            <xtce:ComparisonList>
              <xtce:Comparison parameterRef="PUS_SERVICE" value="1"/>
              <xtce:Comparison parameterRef="PUS_SUBTYPE" value="7"/>
            </xtce:ComparisonList>
          </xtce:RestrictionCriteria>
        </xtce:BaseContainer>
        <xtce:EntryList>
          <xtce:ParameterRefEntry parameterRef="VERIF_REQ_ID"/>
          <xtce:ParameterRefEntry parameterRef="PEC_CRC16"/>
        </xtce:EntryList>
      </xtce:SequenceContainer>
      <xtce:SequenceContainer name="TM_3_25_ObcHousekeeping">
        <xtce:BaseContainer containerRef="CCSDSPacket">
          <xtce:RestrictionCriteria>
            <xtce:ComparisonList>
              <xtce:Comparison parameterRef="PUS_SERVICE" value="3"/>
              <xtce:Comparison parameterRef="PUS_SUBTYPE" value="25"/>
            </xtce:ComparisonList>
          </xtce:RestrictionCriteria>
        </xtce:BaseContainer>
        <xtce:EntryList>
          <xtce:ParameterRefEntry parameterRef="HK_SID"/>
          <xtce:ParameterRefEntry parameterRef="OBC_UPTIME_S"/>
          <xtce:ParameterRefEntry parameterRef="OBC_VBUS_V"/>
          <xtce:ParameterRefEntry parameterRef="OBC_TEMP_C"/>
          <xtce:ParameterRefEntry parameterRef="OBC_MODE"/>
          <xtce:ParameterRefEntry parameterRef="PEC_CRC16"/>
        </xtce:EntryList>
      </xtce:SequenceContainer>
      <xtce:SequenceContainer name="TM_5_1_EventInfo">
        <xtce:BaseContainer containerRef="CCSDSPacket">
          <xtce:RestrictionCriteria>
            <xtce:ComparisonList>
              <xtce:Comparison parameterRef="PUS_SERVICE" value="5"/>
              <xtce:Comparison parameterRef="PUS_SUBTYPE" value="1"/>
            </xtce:ComparisonList>
          </xtce:RestrictionCriteria>
        </xtce:BaseContainer>
        <xtce:EntryList>
          <xtce:ParameterRefEntry parameterRef="EVENT_ID"/>
        </xtce:EntryList>
      </xtce:SequenceContainer>
      <xtce:SequenceContainer name="TM_5_2_EventLowAnomaly">
        <xtce:BaseContainer containerRef="CCSDSPacket">
          <xtce:RestrictionCriteria>
            <xtce:ComparisonList>
              <xtce:Comparison parameterRef="PUS_SERVICE" value="5"/>
              <xtce:Comparison parameterRef="PUS_SUBTYPE" value="2"/>
            </xtce:ComparisonList>
          </xtce:RestrictionCriteria>
        </xtce:BaseContainer>
        <xtce:EntryList>
          <xtce:ParameterRefEntry parameterRef="EVENT_ID"/>
          <xtce:ParameterRefEntry parameterRef="EVENT_AUX_U16"/>
          <xtce:ParameterRefEntry parameterRef="PEC_CRC16"/>
        </xtce:EntryList>
      </xtce:SequenceContainer>
      <xtce:SequenceContainer name="TM_6_10_MemoryCheckReport">
        <xtce:BaseContainer containerRef="CCSDSPacket">
          <xtce:RestrictionCriteria>
            <xtce:ComparisonList>
              <xtce:Comparison parameterRef="PUS_SERVICE" value="6"/>
              <xtce:Comparison parameterRef="PUS_SUBTYPE" value="10"/>
            </xtce:ComparisonList>
          </xtce:RestrictionCriteria>
        </xtce:BaseContainer>
        <xtce:EntryList>
          <xtce:ParameterRefEntry parameterRef="MEM_ID"/>
          <xtce:ParameterRefEntry parameterRef="MEM_ADDR"/>
          <xtce:ParameterRefEntry parameterRef="MEM_LEN"/>
          <xtce:ParameterRefEntry parameterRef="MEM_CRC16"/>
          <xtce:ParameterRefEntry parameterRef="PEC_CRC16"/>
        </xtce:EntryList>
      </xtce:SequenceContainer>
      <xtce:SequenceContainer name="TM_11_13_ScheduleSummary">
        <xtce:BaseContainer containerRef="CCSDSPacket">
          <xtce:RestrictionCriteria>
            <xtce:ComparisonList>
              <xtce:Comparison parameterRef="PUS_SERVICE" value="11"/>
              <xtce:Comparison parameterRef="PUS_SUBTYPE" value="13"/>
            </xtce:ComparisonList>
          </xtce:RestrictionCriteria>
        </xtce:BaseContainer>
        <xtce:EntryList>
          <xtce:ParameterRefEntry parameterRef="SCHED_ENABLED"/>
          <xtce:ParameterRefEntry parameterRef="SCHED_PENDING"/>
          <xtce:ParameterRefEntry parameterRef="PEC_CRC16"/>
        </xtce:EntryList>
      </xtce:SequenceContainer>
      <xtce:SequenceContainer name="TM_17_2_AreYouAliveReport">
        <xtce:BaseContainer containerRef="CCSDSPacket">
          <xtce:RestrictionCriteria>
            <xtce:ComparisonList>
              <xtce:Comparison parameterRef="PUS_SERVICE" value="17"/>
              <xtce:Comparison parameterRef="PUS_SUBTYPE" value="2"/>
            </xtce:ComparisonList>
          </xtce:RestrictionCriteria>
        </xtce:BaseContainer>
        <xtce:EntryList>
          <xtce:ParameterRefEntry parameterRef="PEC_CRC16"/>
        </xtce:EntryList>
      </xtce:SequenceContainer>
    </xtce:ContainerSet>
  </xtce:TelemetryMetaData>
</xtce:SpaceSystem>
"#;

#[cfg(test)]
mod tests {
    use xtce_decode::Decoder;
    use xtce_model::XtceDb;

    use super::{ECSS_PUS_XTCE_XML, run_hil_demo};

    #[test]
    fn hil_demo_executes_all_earth_observation_ecss_pus_scenarios() {
        let mut out = Vec::new();
        run_hil_demo(&mut out, None).expect("hil demo succeeds");
        let text = String::from_utf8(out).expect("utf8");

        assert!(text.contains("TC[17,1]"));
        assert!(text.contains("TM[17,2]"));
        assert!(text.contains("AcceptanceSuccess"));
        assert!(text.contains("EnablePeriodicHk(sid=1)"));
        assert!(text.contains("MemoryLoadRaw(mem=1, addr=0x00000008, len=6B)"));
        assert!(text.contains("MemoryCheckReport(mem=1, addr=0x00000008, len=6B"));
        assert!(text.contains("PerformFunction(fn_id=0x0010, args=1B)"));
        assert!(text.contains("ScheduleSummaryReport(enabled=true, pending=1)"));
        assert!(text.contains("ObcHkReport(sid=1"));
        assert!(text.contains("mode=3"));
        assert!(text.contains("AcceptanceFailure"));
        assert!(text.contains("Event(LowAnomaly, id=0x0101"));
    }

    #[test]
    fn emitted_pus_xtce_database_decodes_hil_packets_and_compiles_wireshark_lua() {
        let db = XtceDb::from_xml(ECSS_PUS_XTCE_XML).expect("PUS XTCE XML loads");
        let decoder = Decoder::new(&db).expect("decoder initializes");

        // Verify the emitted XTCE definition also compiles cleanly into a Wireshark Lua dissector
        let lua =
            crate::wireshark::generate_lua(&db, None, "ecss_pus.xml", Some(5006)).expect("lua");
        assert!(lua.contains("TM_3_25_ObcHousekeeping"));
        assert!(lua.contains("TM_6_10_MemoryCheckReport"));

        // Verify a live TM[3,25] frame from PusResponder decodes through xtce_decode::Decoder
        let mut responder = xtce_pus::PusResponder::new(0x010, 0x0001);
        let sid_bytes = xtce_pus::ObcHousekeeping::SID.to_be_bytes();
        let mut tc_buf = [0u8; 32];
        let tc_len = xtce_pus::encode_tc(
            &xtce_pus::TcParams {
                apid: 0x010,
                sequence_count: 1,
                ack: xtce_pus::AckFlags::ACCEPT_AND_COMPLETE,
                service: 3,
                subtype: 27,
                source_id: 0x0042,
            },
            &sid_bytes,
            &mut tc_buf,
        )
        .expect("TC[3,27]");

        let mut tm_frames = [[0u8; xtce_pus::MAX_HIL_FRAME_LEN]; 4];
        let mut tm_lens = [0usize; 4];
        let count = responder
            .process_telecommand(&tc_buf[..tc_len], &mut tm_frames, &mut tm_lens)
            .expect("HIL responds");
        assert_eq!(count, 3);

        for slot in 0..count {
            let packet = decoder
                .decode(&tm_frames[slot][..tm_lens[slot]])
                .expect("XTCE decodes ECSS PUS frame");
            assert!(packet.len() >= 15);
        }
    }

    #[test]
    fn hil_udp_roundtrip_over_localhost_socket() {
        let server_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds server");
        let server_addr = server_sock.local_addr().expect("server addr");

        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds client");
        client_sock
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("timeout");

        // Send one TC[17,1] Are-You-Alive telecommand datagram to the server socket
        let mut tc_buf = [0u8; 32];
        let tc_len = xtce_pus::encode_tc(
            &xtce_pus::TcParams {
                apid: 0x010,
                sequence_count: 1,
                ack: xtce_pus::AckFlags::ACCEPT_AND_COMPLETE,
                service: 17,
                subtype: 1,
                source_id: 0x0042,
            },
            &[],
            &mut tc_buf,
        )
        .expect("TC[17,1]");
        client_sock
            .send_to(&tc_buf[..tc_len], server_addr)
            .expect("sends TC over UDP");

        let mut log = Vec::new();
        super::serve_hil_udp(&server_sock, &mut log, Some(1)).expect("serves 1 UDP command");

        // Receive all 3 response datagrams (TM[1,1], TM[17,2], TM[1,7])
        let mut rx = [0u8; 64];
        let (n0, _) = client_sock.recv_from(&mut rx).expect("TM[1,1]");
        assert_eq!(
            xtce_pus::PusPacket::parse(&rx[..n0])
                .unwrap()
                .header
                .subtype(),
            1
        );
        let (n1, _) = client_sock.recv_from(&mut rx).expect("TM[17,2]");
        assert_eq!(
            xtce_pus::PusPacket::parse(&rx[..n1])
                .unwrap()
                .header
                .service(),
            17
        );
        let (n2, _) = client_sock.recv_from(&mut rx).expect("TM[1,7]");
        assert_eq!(
            xtce_pus::PusPacket::parse(&rx[..n2])
                .unwrap()
                .header
                .subtype(),
            7
        );
    }
}
