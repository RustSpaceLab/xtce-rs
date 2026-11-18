//! `xtce pus` — inspect ECSS-E-ST-70-41C (PUS-C) packet streams and run closed-loop HIL demos.

use std::io::{Read, Write};
use std::path::Path;

use xtce_decode::PacketReader;
use xtce_pus::{
    AckFlags, HousekeepingMessage, MAX_HIL_FRAME_LEN, ObcHousekeeping, PusError, PusHeader,
    PusPacket, PusResponder, PusService, TcParams, TestMessage, VerificationReport, encode_tc,
};

/// Configuration for `xtce pus`.
pub struct Options<'a> {
    pub packets: Option<&'a Path>,
    pub hil_demo: bool,
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
/// Returns an error if neither `--hil-demo` nor a packet source path is given, or if I/O fails.
pub fn run(options: &Options<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    if options.hil_demo {
        run_hil_demo(&mut out, options.out)?;
        out.flush()?;
        return Ok(());
    }

    let Some(packets_path) = options.packets else {
        return Err("provide a packet stream file (or '-') or pass --hil-demo".into());
    };

    let source = open_packet_source(packets_path)?;
    let mut reader = PacketReader::new(source, options.skip_header_bytes);
    inspect_stream(&mut reader, &mut out, options.limit)?;
    out.flush()?;
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

fn run_hil_demo(
    out: &mut impl Write,
    capture_out: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(
        out,
        "=== ECSS-E-ST-70-41C (PUS-C) Hardware-in-the-Loop (HIL) Closed-Loop Session ==="
    )?;
    let mut responder = PusResponder::new(0x010, 0x0001);
    let mut recorded_stream: Vec<u8> = Vec::with_capacity(512);
    let mut frame_index = 0usize;

    let sid_bytes = ObcHousekeeping::SID.to_be_bytes();
    let steps: [(u8, u8, &[u8], bool); 4] = [
        (17, 1, &[], false),
        (3, 5, &sid_bytes, false),
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
            recorded_stream.extend_from_slice(&tc_buf[..tc_len]);
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
            "wrote {} bytes of ECSS PUS HIL frames to {}",
            recorded_stream.len(),
            path.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run_hil_demo;

    #[test]
    fn hil_demo_executes_all_four_ecss_pus_scenarios() {
        let mut out = Vec::new();
        run_hil_demo(&mut out, None).expect("hil demo succeeds");
        let text = String::from_utf8(out).expect("utf8");

        assert!(text.contains("TC[17,1]"));
        assert!(text.contains("TM[17,2]"));
        assert!(text.contains("AcceptanceSuccess"));
        assert!(text.contains("EnablePeriodicHk(sid=1)"));
        assert!(text.contains("ObcHkReport(sid=1"));
        assert!(text.contains("AcceptanceFailure"));
        assert!(text.contains("Event(LowAnomaly, id=0x0101"));
    }
}
