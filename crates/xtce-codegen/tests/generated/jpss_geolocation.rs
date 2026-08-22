// Decoder generated from `testdata/spp/jpss/jpss1_geolocation_xtce_v1.xml` by `xtce-codegen`, rooted at `CCSDSPacket`.
//
// 1 container(s) are decoded here. Every bit offset and mask below was computed
// when this file was generated; nothing consults the XTCE definition at run time.
//
// Do not edit: regenerate instead. Intended to be included inside a module that
// carries the lint allowances generated code needs, for example:
//
//     #[allow(dead_code, clippy::all, clippy::pedantic)]
//     mod telemetry {
//         include!(concat!(env!("OUT_DIR"), "/telemetry.rs"));
//     }

/// Why a packet could not be decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// The packet is shorter than the container it matched.
    TooShort {
        /// Bytes the container needs.
        needed: usize,
        /// Bytes the packet has.
        got: usize,
    },
    /// No inheritor of an abstract container matched, so the packet is of a type
    /// this definition does not describe.
    Unrecognized {
        /// The container that ran out of options.
        container: &'static str,
    },
    /// More than one inheritor matched, so the packet type is ambiguous.
    Ambiguous {
        /// The container being specialised.
        container: &'static str,
    },
    /// A string field's bytes are not valid text in its declared character set.
    InvalidText {
        /// The parameter being decoded.
        parameter: &'static str,
    },
    /// A string declares a termination character its buffer does not contain.
    UnterminatedString {
        /// The parameter being decoded.
        parameter: &'static str,
    },
    /// A leading-size prefix declares a length its buffer cannot hold.
    BadStringLength {
        /// The parameter being decoded.
        parameter: &'static str,
    },
}
impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { needed, got } => {
                write!(f, "packet has {got} byte(s), container needs {needed}")
            }
            Self::Unrecognized { container } => {
                write!(f, "no inheritor of {container} matches this packet")
            }
            Self::Ambiguous { container } => {
                write!(f, "more than one inheritor of {container} matches")
            }
            Self::InvalidText { parameter } => {
                write!(f, "{parameter}: bytes are not valid text")
            }
            Self::UnterminatedString { parameter } => {
                write!(f, "{parameter}: termination character not found")
            }
            Self::BadStringLength { parameter } => {
                write!(f, "{parameter}: leading size is larger than the buffer")
            }
        }
    }
}
impl core::error::Error for DecodeError {}
/// A decoded value, in the same shape the interpreted decoder produces.
///
/// Text and binary values borrow from the packet, so nothing is copied out of it.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Value<'a> {
    /// An unsigned integer field.
    Unsigned(u64),
    /// A signed integer field.
    Signed(i64),
    /// A float field.
    Float(f64),
    /// A boolean parameter's value.
    Bool(bool),
    /// An enumeration label.
    Label(&'static str),
    /// Text decoded from the packet.
    Text(&'a str),
    /// Bytes as they appear in the packet.
    Bytes(&'a [u8]),
}
/// `JPSS_ATT_EPHEM`: 27 field(s) in 568 bit(s).
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub struct JpssAttEphem {
    /// `VERSION` — 3 bit(s) at bit 0.
    pub version: u64,
    /// `TYPE` — 1 bit(s) at bit 3.
    pub type_: u64,
    /// `SEC_HDR_FLG` — 1 bit(s) at bit 4.
    pub sec_hdr_flg: u64,
    /// `PKT_APID` — 11 bit(s) at bit 5.
    pub pkt_apid: u64,
    /// `SEQ_FLGS` — 2 bit(s) at bit 16.
    pub seq_flgs: u64,
    /// `SRC_SEQ_CTR` — 14 bit(s) at bit 18.
    pub src_seq_ctr: u64,
    /// `PKT_LEN` — 16 bit(s) at bit 32.
    pub pkt_len: u64,
    /// `DOY` — 16 bit(s) at bit 48.
    pub doy: u64,
    /// `MSEC` — 32 bit(s) at bit 64.
    pub msec: u64,
    /// `USEC` — 16 bit(s) at bit 96.
    pub usec: u64,
    /// `ADAESCID` — 8 bit(s) at bit 112.
    pub adaescid: u64,
    /// `ADAET1DAY` — 16 bit(s) at bit 120.
    pub adaet1day: u64,
    /// `ADAET1MS` — 32 bit(s) at bit 136.
    pub adaet1ms: u64,
    /// `ADAET1US` — 16 bit(s) at bit 168.
    pub adaet1us: u64,
    /// `ADGPSPOSX` — 32 bit(s) at bit 184.
    pub adgpsposx: f64,
    /// `ADGPSPOSY` — 32 bit(s) at bit 216.
    pub adgpsposy: f64,
    /// `ADGPSPOSZ` — 32 bit(s) at bit 248.
    pub adgpsposz: f64,
    /// `ADGPSVELX` — 32 bit(s) at bit 280.
    pub adgpsvelx: f64,
    /// `ADGPSVELY` — 32 bit(s) at bit 312.
    pub adgpsvely: f64,
    /// `ADGPSVELZ` — 32 bit(s) at bit 344.
    pub adgpsvelz: f64,
    /// `ADAET2DAY` — 16 bit(s) at bit 376.
    pub adaet2day: u64,
    /// `ADAET2MS` — 32 bit(s) at bit 392.
    pub adaet2ms: u64,
    /// `ADAET2US` — 16 bit(s) at bit 424.
    pub adaet2us: u64,
    /// `ADCFAQ1` — 32 bit(s) at bit 440.
    pub adcfaq1: f64,
    /// `ADCFAQ2` — 32 bit(s) at bit 472.
    pub adcfaq2: f64,
    /// `ADCFAQ3` — 32 bit(s) at bit 504.
    pub adcfaq3: f64,
    /// `ADCFAQ4` — 32 bit(s) at bit 536.
    pub adcfaq4: f64,
}
impl JpssAttEphem {
    /// Name of this container in the XTCE definition.
    pub const NAME: &'static str = "JPSS_ATT_EPHEM";
    /// Total width of this container's fields, in bits.
    pub const BIT_LENGTH: usize = 568;
    /// Bytes a packet must have for this container to decode.
    pub const BYTE_LENGTH: usize = 71;
    /// Parameter names, in decode order.
    pub const FIELDS: [&'static str; 27] = [
        "VERSION",
        "TYPE",
        "SEC_HDR_FLG",
        "PKT_APID",
        "SEQ_FLGS",
        "SRC_SEQ_CTR",
        "PKT_LEN",
        "DOY",
        "MSEC",
        "USEC",
        "ADAESCID",
        "ADAET1DAY",
        "ADAET1MS",
        "ADAET1US",
        "ADGPSPOSX",
        "ADGPSPOSY",
        "ADGPSPOSZ",
        "ADGPSVELX",
        "ADGPSVELY",
        "ADGPSVELZ",
        "ADAET2DAY",
        "ADAET2MS",
        "ADAET2US",
        "ADCFAQ1",
        "ADCFAQ2",
        "ADCFAQ3",
        "ADCFAQ4",
    ];
    /// Decodes this container from the start of `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::TooShort`] if the packet is smaller than [`Self::BYTE_LENGTH`],
    /// or a text error if a string field does not hold valid text.
    #[inline]
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let packet: &[u8; 71] = match data.get(..71) {
            Some(prefix) => {
                match prefix.try_into() {
                    Ok(array) => array,
                    Err(_) => {
                        return Err(DecodeError::TooShort {
                            needed: 71,
                            got: data.len(),
                        });
                    }
                }
            }
            None => {
                return Err(DecodeError::TooShort {
                    needed: 71,
                    got: data.len(),
                });
            }
        };
        Ok(Self {
            version: (packet[0] as u64 >> 5) & 7,
            type_: (packet[0] as u64 >> 4) & 1,
            sec_hdr_flg: (packet[0] as u64 >> 3) & 1,
            pkt_apid: (u16::from_be_bytes([packet[0], packet[1]]) as u64) & 2047,
            seq_flgs: (packet[2] as u64 >> 6) & 3,
            src_seq_ctr: (u16::from_be_bytes([packet[2], packet[3]]) as u64) & 16383,
            pkt_len: u16::from_be_bytes([packet[4], packet[5]]) as u64,
            doy: u16::from_be_bytes([packet[6], packet[7]]) as u64,
            msec: u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]])
                as u64,
            usec: u16::from_be_bytes([packet[12], packet[13]]) as u64,
            adaescid: packet[14] as u64,
            adaet1day: u16::from_be_bytes([packet[15], packet[16]]) as u64,
            adaet1ms: u32::from_be_bytes([
                packet[17],
                packet[18],
                packet[19],
                packet[20],
            ]) as u64,
            adaet1us: u16::from_be_bytes([packet[21], packet[22]]) as u64,
            adgpsposx: f64::from(
                f32::from_bits(
                    u32::from_be_bytes([packet[23], packet[24], packet[25], packet[26]])
                        as u64 as u32,
                ),
            ),
            adgpsposy: f64::from(
                f32::from_bits(
                    u32::from_be_bytes([packet[27], packet[28], packet[29], packet[30]])
                        as u64 as u32,
                ),
            ),
            adgpsposz: f64::from(
                f32::from_bits(
                    u32::from_be_bytes([packet[31], packet[32], packet[33], packet[34]])
                        as u64 as u32,
                ),
            ),
            adgpsvelx: f64::from(
                f32::from_bits(
                    u32::from_be_bytes([packet[35], packet[36], packet[37], packet[38]])
                        as u64 as u32,
                ),
            ),
            adgpsvely: f64::from(
                f32::from_bits(
                    u32::from_be_bytes([packet[39], packet[40], packet[41], packet[42]])
                        as u64 as u32,
                ),
            ),
            adgpsvelz: f64::from(
                f32::from_bits(
                    u32::from_be_bytes([packet[43], packet[44], packet[45], packet[46]])
                        as u64 as u32,
                ),
            ),
            adaet2day: u16::from_be_bytes([packet[47], packet[48]]) as u64,
            adaet2ms: u32::from_be_bytes([
                packet[49],
                packet[50],
                packet[51],
                packet[52],
            ]) as u64,
            adaet2us: u16::from_be_bytes([packet[53], packet[54]]) as u64,
            adcfaq1: f64::from(
                f32::from_bits(
                    u32::from_be_bytes([packet[55], packet[56], packet[57], packet[58]])
                        as u64 as u32,
                ),
            ),
            adcfaq2: f64::from(
                f32::from_bits(
                    u32::from_be_bytes([packet[59], packet[60], packet[61], packet[62]])
                        as u64 as u32,
                ),
            ),
            adcfaq3: f64::from(
                f32::from_bits(
                    u32::from_be_bytes([packet[63], packet[64], packet[65], packet[66]])
                        as u64 as u32,
                ),
            ),
            adcfaq4: f64::from(
                f32::from_bits(
                    u32::from_be_bytes([packet[67], packet[68], packet[69], packet[70]])
                        as u64 as u32,
                ),
            ),
        })
    }
    /// Calls `visit(name, raw, engineering)` for every field, in decode order.
    ///
    /// The values borrow for as long as `self` does, so a caller may collect them
    /// rather than only look at them in passing.
    #[inline]
    pub fn for_each_value<'v>(
        &'v self,
        mut visit: impl FnMut(&'static str, Value<'v>, Value<'v>),
    ) {
        visit("VERSION", Value::Unsigned(self.version), Value::Unsigned(self.version));
        visit("TYPE", Value::Unsigned(self.type_), Value::Unsigned(self.type_));
        visit(
            "SEC_HDR_FLG",
            Value::Unsigned(self.sec_hdr_flg),
            Value::Unsigned(self.sec_hdr_flg),
        );
        visit(
            "PKT_APID",
            Value::Unsigned(self.pkt_apid),
            Value::Unsigned(self.pkt_apid),
        );
        visit(
            "SEQ_FLGS",
            Value::Unsigned(self.seq_flgs),
            Value::Unsigned(self.seq_flgs),
        );
        visit(
            "SRC_SEQ_CTR",
            Value::Unsigned(self.src_seq_ctr),
            Value::Unsigned(self.src_seq_ctr),
        );
        visit("PKT_LEN", Value::Unsigned(self.pkt_len), Value::Unsigned(self.pkt_len));
        visit("DOY", Value::Unsigned(self.doy), Value::Unsigned(self.doy));
        visit("MSEC", Value::Unsigned(self.msec), Value::Unsigned(self.msec));
        visit("USEC", Value::Unsigned(self.usec), Value::Unsigned(self.usec));
        visit(
            "ADAESCID",
            Value::Unsigned(self.adaescid),
            Value::Unsigned(self.adaescid),
        );
        visit(
            "ADAET1DAY",
            Value::Unsigned(self.adaet1day),
            Value::Unsigned(self.adaet1day),
        );
        visit(
            "ADAET1MS",
            Value::Unsigned(self.adaet1ms),
            Value::Unsigned(self.adaet1ms),
        );
        visit(
            "ADAET1US",
            Value::Unsigned(self.adaet1us),
            Value::Unsigned(self.adaet1us),
        );
        visit("ADGPSPOSX", Value::Float(self.adgpsposx), Value::Float(self.adgpsposx));
        visit("ADGPSPOSY", Value::Float(self.adgpsposy), Value::Float(self.adgpsposy));
        visit("ADGPSPOSZ", Value::Float(self.adgpsposz), Value::Float(self.adgpsposz));
        visit("ADGPSVELX", Value::Float(self.adgpsvelx), Value::Float(self.adgpsvelx));
        visit("ADGPSVELY", Value::Float(self.adgpsvely), Value::Float(self.adgpsvely));
        visit("ADGPSVELZ", Value::Float(self.adgpsvelz), Value::Float(self.adgpsvelz));
        visit(
            "ADAET2DAY",
            Value::Unsigned(self.adaet2day),
            Value::Unsigned(self.adaet2day),
        );
        visit(
            "ADAET2MS",
            Value::Unsigned(self.adaet2ms),
            Value::Unsigned(self.adaet2ms),
        );
        visit(
            "ADAET2US",
            Value::Unsigned(self.adaet2us),
            Value::Unsigned(self.adaet2us),
        );
        visit("ADCFAQ1", Value::Float(self.adcfaq1), Value::Float(self.adcfaq1));
        visit("ADCFAQ2", Value::Float(self.adcfaq2), Value::Float(self.adcfaq2));
        visit("ADCFAQ3", Value::Float(self.adcfaq3), Value::Float(self.adcfaq3));
        visit("ADCFAQ4", Value::Float(self.adcfaq4), Value::Float(self.adcfaq4));
    }
}
/// A packet, decoded as whichever container matched.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Packet {
    /// A packet decoded as `JPSS_ATT_EPHEM`.
    JpssAttEphem(JpssAttEphem),
}
impl Packet {
    /// Name of the container this packet matched.
    #[inline]
    pub fn container_name(&self) -> &'static str {
        match self {
            Self::JpssAttEphem(_) => JpssAttEphem::NAME,
        }
    }
    /// Calls `visit(name, raw, engineering)` for every field, in decode order.
    ///
    /// The values borrow for as long as `self` does, so a caller may collect them
    /// rather than only look at them in passing.
    #[inline]
    pub fn for_each_value<'v>(
        &'v self,
        visit: impl FnMut(&'static str, Value<'v>, Value<'v>),
    ) {
        match self {
            Self::JpssAttEphem(packet) => packet.for_each_value(visit),
        }
    }
}
/// Decodes one packet, starting from `CCSDSPacket`.
///
/// Reads the discriminator fields, descends to whichever inheritor's restriction
/// criteria hold, and decodes that container. The walk mirrors the interpreted
/// decoder exactly, including its treatment of an ambiguous match as an error.
///
/// # Errors
///
/// See [`DecodeError`].
#[inline]
pub fn decode(data: &[u8]) -> Result<Packet, DecodeError> {
    let head: &[u8; 2] = match data.get(..2) {
        Some(prefix) => {
            match prefix.try_into() {
                Ok(array) => array,
                Err(_) => {
                    return Err(DecodeError::TooShort {
                        needed: 2,
                        got: data.len(),
                    });
                }
            }
        }
        None => {
            return Err(DecodeError::TooShort {
                needed: 2,
                got: data.len(),
            });
        }
    };
    {
        let mut matched = 0u32;
        let mut which = usize::MAX;
        if (head[0] as u64 >> 5) & 7 == 0 && (head[0] as u64 >> 4) & 1 == 0 {
            matched += 1;
            which = 0;
        }
        if matched > 1 {
            return Err(DecodeError::Ambiguous {
                container: "CCSDSPacket",
            });
        }
        match which {
            0 => {
                let mut matched = 0u32;
                let mut which = usize::MAX;
                if (u16::from_be_bytes([head[0], head[1]]) as u64) & 2047 == 11 {
                    matched += 1;
                    which = 0;
                }
                if matched > 1 {
                    return Err(DecodeError::Ambiguous {
                        container: "CCSDSTelemetryPacket",
                    });
                }
                match which {
                    0 => Ok(Packet::JpssAttEphem(JpssAttEphem::decode(data)?)),
                    _ => {
                        Err(DecodeError::Unrecognized {
                            container: "CCSDSTelemetryPacket",
                        })
                    }
                }
            }
            _ => {
                Err(DecodeError::Unrecognized {
                    container: "CCSDSPacket",
                })
            }
        }
    }
}
