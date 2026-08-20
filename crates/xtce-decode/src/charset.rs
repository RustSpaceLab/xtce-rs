//! Text decoding for the character sets XTCE permits.
//!
//! Implemented directly rather than via an encoding crate: XTCE allows exactly six families,
//! four of which are trivial, and a decoder for spacecraft telemetry should not pull in a
//! table of every legacy code page to read a UTF-8 status string.

use std::borrow::Cow;

use xtce_model::{ByteOrder, Charset};

/// The bytes are not valid text in the requested character set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InvalidText;

/// Decodes `bytes` as `charset`.
///
/// Single-byte ASCII-compatible input is returned borrowed; anything needing transcoding
/// allocates.
///
/// # Errors
///
/// Returns [`InvalidText`] if the bytes are not a valid encoding of text in `charset`.
/// Latin-1 and Windows-1252 have no invalid sequences except the five undefined
/// Windows-1252 code points, which are rejected — matching Python's `bytes.decode`, and for
/// the same reason: silently substituting a replacement character would turn a corrupt field
/// into a plausible-looking string.
pub fn decode(
    bytes: &[u8],
    charset: Charset,
    byte_order: ByteOrder,
) -> Result<Cow<'_, str>, InvalidText> {
    match charset {
        Charset::Utf8 => std::str::from_utf8(bytes)
            .map(Cow::Borrowed)
            .map_err(|_| InvalidText),
        Charset::UsAscii => {
            if bytes.is_ascii() {
                std::str::from_utf8(bytes)
                    .map(Cow::Borrowed)
                    .map_err(|_| InvalidText)
            } else {
                Err(InvalidText)
            }
        }
        Charset::Iso8859_1 => Ok(if bytes.is_ascii() {
            std::str::from_utf8(bytes)
                .map(Cow::Borrowed)
                .map_err(|_| InvalidText)?
        } else {
            Cow::Owned(bytes.iter().map(|&byte| char::from(byte)).collect())
        }),
        Charset::Windows1252 => decode_windows_1252(bytes),
        Charset::Utf16 => decode_utf16(bytes, byte_order),
        Charset::Utf32 => decode_utf32(bytes, byte_order),
    }
}

/// A human-readable name, for error messages.
#[must_use]
pub const fn name(charset: Charset) -> &'static str {
    match charset {
        Charset::Utf8 => "UTF-8",
        Charset::UsAscii => "US-ASCII",
        Charset::Iso8859_1 => "ISO-8859-1",
        Charset::Windows1252 => "Windows-1252",
        Charset::Utf16 => "UTF-16",
        Charset::Utf32 => "UTF-32",
    }
}

/// Windows-1252 differs from Latin-1 only in `0x80..=0x9F`. `None` marks the five code
/// points the standard leaves undefined.
const CP1252_HIGH: [Option<char>; 32] = [
    Some('\u{20AC}'), // 80 EURO SIGN
    None,             // 81
    Some('\u{201A}'), // 82
    Some('\u{0192}'), // 83
    Some('\u{201E}'), // 84
    Some('\u{2026}'), // 85
    Some('\u{2020}'), // 86
    Some('\u{2021}'), // 87
    Some('\u{02C6}'), // 88
    Some('\u{2030}'), // 89
    Some('\u{0160}'), // 8A
    Some('\u{2039}'), // 8B
    Some('\u{0152}'), // 8C
    None,             // 8D
    Some('\u{017D}'), // 8E
    None,             // 8F
    None,             // 90
    Some('\u{2018}'), // 91
    Some('\u{2019}'), // 92
    Some('\u{201C}'), // 93
    Some('\u{201D}'), // 94
    Some('\u{2022}'), // 95
    Some('\u{2013}'), // 96
    Some('\u{2014}'), // 97
    Some('\u{02DC}'), // 98
    Some('\u{2122}'), // 99
    Some('\u{0161}'), // 9A
    Some('\u{203A}'), // 9B
    Some('\u{0153}'), // 9C
    None,             // 9D
    Some('\u{017E}'), // 9E
    Some('\u{0178}'), // 9F
];

fn decode_windows_1252(bytes: &[u8]) -> Result<Cow<'_, str>, InvalidText> {
    if bytes.is_ascii() {
        return std::str::from_utf8(bytes)
            .map(Cow::Borrowed)
            .map_err(|_| InvalidText);
    }
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        let ch = match byte {
            0x80..=0x9F => *CP1252_HIGH
                .get(usize::from(byte - 0x80))
                .ok_or(InvalidText)?
                .as_ref()
                .ok_or(InvalidText)?,
            other => char::from(other),
        };
        out.push(ch);
    }
    Ok(Cow::Owned(out))
}

fn decode_utf16(bytes: &[u8], byte_order: ByteOrder) -> Result<Cow<'_, str>, InvalidText> {
    if bytes.len() % 2 != 0 {
        return Err(InvalidText);
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| {
            let hi = pair.first().copied().unwrap_or(0);
            let lo = pair.get(1).copied().unwrap_or(0);
            match byte_order {
                ByteOrder::MostSignificantFirst => u16::from_be_bytes([hi, lo]),
                ByteOrder::LeastSignificantFirst => u16::from_le_bytes([hi, lo]),
            }
        })
        .collect();
    String::from_utf16(&units)
        .map(Cow::Owned)
        .map_err(|_| InvalidText)
}

fn decode_utf32(bytes: &[u8], byte_order: ByteOrder) -> Result<Cow<'_, str>, InvalidText> {
    if bytes.len() % 4 != 0 {
        return Err(InvalidText);
    }
    let mut out = String::with_capacity(bytes.len() / 4);
    for chunk in bytes.chunks_exact(4) {
        let mut word = [0u8; 4];
        word.copy_from_slice(chunk);
        let scalar = match byte_order {
            ByteOrder::MostSignificantFirst => u32::from_be_bytes(word),
            ByteOrder::LeastSignificantFirst => u32::from_le_bytes(word),
        };
        out.push(char::from_u32(scalar).ok_or(InvalidText)?);
    }
    Ok(Cow::Owned(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_is_borrowed_in_every_single_byte_charset() {
        for charset in [
            Charset::Utf8,
            Charset::UsAscii,
            Charset::Iso8859_1,
            Charset::Windows1252,
        ] {
            let decoded = decode(b"STATUS OK", charset, ByteOrder::MostSignificantFirst)
                .expect("ascii decodes");
            assert!(matches!(decoded, Cow::Borrowed(_)), "{charset:?} allocated");
            assert_eq!(decoded, "STATUS OK");
        }
    }

    #[test]
    fn latin1_maps_every_byte() {
        let decoded = decode(
            &[0xE9, 0xF1],
            Charset::Iso8859_1,
            ByteOrder::MostSignificantFirst,
        )
        .expect("latin-1 has no invalid bytes");
        assert_eq!(decoded, "éñ");
    }

    #[test]
    fn windows_1252_rejects_undefined_code_points() {
        assert_eq!(
            decode(
                &[0x80],
                Charset::Windows1252,
                ByteOrder::MostSignificantFirst
            )
            .as_deref(),
            Ok("€")
        );
        assert_eq!(
            decode(
                &[0x81],
                Charset::Windows1252,
                ByteOrder::MostSignificantFirst
            ),
            Err(InvalidText)
        );
    }

    #[test]
    fn invalid_utf8_is_an_error_not_a_replacement_character() {
        assert_eq!(
            decode(
                &[0xFF, 0xFE],
                Charset::Utf8,
                ByteOrder::MostSignificantFirst
            ),
            Err(InvalidText)
        );
        assert_eq!(
            decode(&[0x80], Charset::UsAscii, ByteOrder::MostSignificantFirst),
            Err(InvalidText)
        );
    }

    #[test]
    fn utf16_honours_byte_order() {
        assert_eq!(
            decode(
                &[0x00, 0x21],
                Charset::Utf16,
                ByteOrder::MostSignificantFirst
            )
            .as_deref(),
            Ok("!")
        );
        assert_eq!(
            decode(
                &[0x21, 0x00],
                Charset::Utf16,
                ByteOrder::LeastSignificantFirst
            )
            .as_deref(),
            Ok("!")
        );
        assert_eq!(
            decode(&[0x00], Charset::Utf16, ByteOrder::MostSignificantFirst),
            Err(InvalidText)
        );
        // Lone surrogate.
        assert_eq!(
            decode(
                &[0xD8, 0x00],
                Charset::Utf16,
                ByteOrder::MostSignificantFirst
            ),
            Err(InvalidText)
        );
    }

    #[test]
    fn utf32_honours_byte_order() {
        assert_eq!(
            decode(
                &[0x00, 0x00, 0x00, 0x41],
                Charset::Utf32,
                ByteOrder::MostSignificantFirst
            )
            .as_deref(),
            Ok("A")
        );
        assert_eq!(
            decode(
                &[0x41, 0x00, 0x00, 0x00],
                Charset::Utf32,
                ByteOrder::LeastSignificantFirst
            )
            .as_deref(),
            Ok("A")
        );
        assert_eq!(
            decode(
                &[0xFF, 0xFF, 0xFF, 0xFF],
                Charset::Utf32,
                ByteOrder::MostSignificantFirst
            ),
            Err(InvalidText)
        );
    }
}
