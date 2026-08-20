//! The shared value encoding that makes differential testing possible.
//!
//! Both sides — Python's `space_packet_parser` via `tools/gen_goldens.py`, and this
//! workspace — reduce a decoded parameter to the same small set of scalars. Everything is
//! compared in that form, so a difference in the report is a difference in the *decoding*,
//! never in the formatting.
//!
//! Floats carry their IEEE-754 bit pattern rather than a decimal rendering, so equality is
//! exact and NaN compares equal to NaN — which is what "the two implementations produced the
//! same bits" should mean.

use std::fmt;

use xtce_decode::{EngValue, RawValue};

/// One decoded scalar, in the form both implementations agree on.
#[derive(Clone, PartialEq, Eq)]
pub enum Scalar {
    /// A missing value.
    Null,
    /// A JSON boolean. Only the `__unrecognized__` marker uses this.
    Bool(bool),
    /// An integer of any width the reference can produce.
    Int(i128),
    /// A float, as its IEEE-754 bit pattern.
    Float(u64),
    /// Text.
    Text(String),
    /// Binary data.
    Bytes(Vec<u8>),
}

impl Scalar {
    /// The canonical byte encoding fed to the digest.
    ///
    /// Mirrors `encode_canonical` in `tools/gen_goldens.py` exactly; the two definitions
    /// have to be read together.
    pub fn write_canonical(&self, out: &mut Vec<u8>) {
        match self {
            Self::Null => out.push(b'n'),
            Self::Bool(value) => out.extend_from_slice(if *value { b"B1" } else { b"B0" }),
            Self::Int(value) => {
                out.push(b'i');
                write_blob(out, value.to_string().as_bytes());
            }
            Self::Float(bits) => {
                out.push(b'f');
                out.extend_from_slice(format!("{bits:016x}").as_bytes());
            }
            Self::Text(text) => {
                out.push(b's');
                write_blob(out, text.as_bytes());
            }
            Self::Bytes(bytes) => {
                out.push(b'b');
                write_blob(out, bytes);
            }
        }
    }

    /// Parses the JSON form written by the golden generator.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        match value {
            serde_json::Value::Null => Ok(Self::Null),
            serde_json::Value::Bool(flag) => Ok(Self::Bool(*flag)),
            serde_json::Value::Number(number) => number
                .as_i128()
                .map(Self::Int)
                .ok_or_else(|| format!("golden holds a non-integer number {number}")),
            serde_json::Value::String(text) => Ok(Self::Text(text.clone())),
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::String(hex)) = map.get("f") {
                    return u64::from_str_radix(hex, 16)
                        .map(Self::Float)
                        .map_err(|_| format!("golden holds a malformed float {hex:?}"));
                }
                if let Some(serde_json::Value::String(hex)) = map.get("b") {
                    return parse_hex(hex)
                        .map(Self::Bytes)
                        .ok_or_else(|| format!("golden holds malformed bytes {hex:?}"));
                }
                Err(format!("golden holds an unrecognised object {map:?}"))
            }
            serde_json::Value::Array(_) => Err("golden holds an unexpected array".to_owned()),
        }
    }
}

/// The raw side of a decoded value.
#[must_use]
pub fn raw_scalar(raw: &RawValue<'_>) -> Scalar {
    match raw {
        RawValue::Unsigned(value) => Scalar::Int(i128::from(*value)),
        RawValue::Signed(value) => Scalar::Int(i128::from(*value)),
        RawValue::Float(value) => Scalar::Float(value.to_bits()),
        RawValue::Bytes(bytes) => Scalar::Bytes(bytes.to_vec()),
    }
}

/// The engineering side of a decoded value.
///
/// Booleans become 0 and 1 rather than JSON booleans, because the reference's
/// `BoolParameter` subclasses `int`, so that is what it serialises as. Matching the
/// reference's *representation* here is the point — an encoding difference would show up as
/// a spurious decoding difference.
#[must_use]
pub fn eng_scalar(eng: &EngValue<'_, '_>) -> Scalar {
    match eng {
        EngValue::Unsigned(value) => Scalar::Int(i128::from(*value)),
        EngValue::Signed(value) => Scalar::Int(i128::from(*value)),
        EngValue::Bool(value) => Scalar::Int(i128::from(*value)),
        EngValue::Float(value) => Scalar::Float(value.to_bits()),
        EngValue::Label(text) => Scalar::Text((*text).to_owned()),
        EngValue::Text(text) => Scalar::Text(text.as_ref().to_owned()),
        EngValue::Bytes(bytes) => Scalar::Bytes(bytes.to_vec()),
    }
}

/// `len(payload) ":" payload`, the length prefix used throughout the canonical encoding.
pub fn write_blob(out: &mut Vec<u8>, payload: &[u8]) {
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(payload);
}

fn parse_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = char::from(*pair.first()?).to_digit(16)?;
            let lo = char::from(*pair.get(1)?).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Bool(value) => write!(f, "{value}"),
            Self::Int(value) => write!(f, "{value}"),
            Self::Float(bits) => {
                let value = f64::from_bits(*bits);
                write!(f, "{value:?} (0x{bits:016x})")
            }
            Self::Text(text) => write!(f, "{text:?}"),
            Self::Bytes(bytes) => {
                write!(f, "b\"")?;
                for byte in bytes.iter().take(24) {
                    write!(f, "{byte:02x}")?;
                }
                if bytes.len() > 24 {
                    write!(f, "…")?;
                }
                write!(f, "\" ({} bytes)", bytes.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(scalar: &Scalar) -> Vec<u8> {
        let mut out = Vec::new();
        scalar.write_canonical(&mut out);
        out
    }

    #[test]
    fn canonical_forms_match_the_generator() {
        assert_eq!(canonical(&Scalar::Null), b"n");
        assert_eq!(canonical(&Scalar::Bool(true)), b"B1");
        assert_eq!(canonical(&Scalar::Bool(false)), b"B0");
        assert_eq!(canonical(&Scalar::Int(-42)), b"i3:-42");
        assert_eq!(canonical(&Scalar::Int(0)), b"i1:0");
        assert_eq!(canonical(&Scalar::Text("AB".into())), b"s2:AB");
        assert_eq!(canonical(&Scalar::Bytes(vec![0, 255])), b"b2:\x00\xff");
        // 1.0 is 0x3ff0000000000000
        assert_eq!(
            canonical(&Scalar::Float(1.0f64.to_bits())),
            b"f3ff0000000000000000000000000000"
                .get(..17)
                .unwrap_or_default()
        );
    }

    #[test]
    fn length_prefixes_count_bytes_not_characters() {
        let mut out = Vec::new();
        write_blob(&mut out, "łąka".as_bytes());
        // Two two-byte code points plus two ASCII bytes.
        assert_eq!(out, b"6:\xc5\x82\xc4\x85ka");
    }

    #[test]
    fn json_round_trips() {
        let cases = [
            ("null", Scalar::Null),
            ("true", Scalar::Bool(true)),
            ("-7", Scalar::Int(-7)),
            (r#""hi""#, Scalar::Text("hi".into())),
            (
                r#"{"f":"3ff0000000000000"}"#,
                Scalar::Float(0x3ff0_0000_0000_0000),
            ),
            (r#"{"b":"00ff"}"#, Scalar::Bytes(vec![0, 255])),
        ];
        for (json, want) in cases {
            let value: serde_json::Value = serde_json::from_str(json).expect("valid json");
            assert_eq!(Scalar::from_json(&value), Ok(want), "{json}");
        }
    }

    #[test]
    fn nan_bit_patterns_compare_equal_to_themselves() {
        let nan = Scalar::Float(f64::NAN.to_bits());
        assert_eq!(nan, Scalar::Float(f64::NAN.to_bits()));
        assert_ne!(nan, Scalar::Float(0.0f64.to_bits()));
        // Positive and negative zero are distinct bit patterns and must not compare equal.
        assert_ne!(
            Scalar::Float(0.0f64.to_bits()),
            Scalar::Float((-0.0f64).to_bits())
        );
    }
}
