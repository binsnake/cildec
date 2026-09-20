//! Compressed integer encoding used by metadata blobs (ECMA-335 II.23.2).
//!
//! Unsigned values occupy 1, 2 or 4 bytes selected by the top bits of the first
//! byte. Signed values use the same three widths with the sign bit rotated into
//! the least significant position.

use crate::error::{Error, ErrorKind, Result};

/// The largest value that a compressed unsigned integer can encode.
pub const MAX_COMPRESSED_U32: u32 = 0x1FFF_FFFF;

/// Decodes a compressed unsigned integer from the front of `bytes`.
///
/// Returns the value and the number of bytes consumed.
pub fn read_u32(bytes: &[u8]) -> Result<(u32, usize)> {
    let b0 = *bytes.first().ok_or(Error::new(ErrorKind::Truncated, 0, "compressed integer"))?;
    if b0 & 0x80 == 0 {
        Ok((u32::from(b0), 1))
    } else if b0 & 0xC0 == 0x80 {
        let b1 = *bytes.get(1).ok_or(Error::new(ErrorKind::Truncated, 1, "compressed integer"))?;
        Ok(((u32::from(b0 & 0x3F) << 8) | u32::from(b1), 2))
    } else if b0 & 0xE0 == 0xC0 {
        let b = bytes.get(1..4).ok_or(Error::new(ErrorKind::Truncated, 1, "compressed integer"))?;
        let value = (u32::from(b0 & 0x1F) << 24)
            | (u32::from(b[0]) << 16)
            | (u32::from(b[1]) << 8)
            | u32::from(b[2]);
        Ok((value, 4))
    } else {
        Err(Error::new(ErrorKind::Malformed, 0, "compressed integer"))
    }
}

/// Decodes a compressed signed integer from the front of `bytes`.
///
/// Returns the value and the number of bytes consumed.
pub fn read_i32(bytes: &[u8]) -> Result<(i32, usize)> {
    let b0 = *bytes.first().ok_or(Error::new(ErrorKind::Truncated, 0, "compressed integer"))?;
    if b0 & 0x80 == 0 {
        let raw = i32::from(b0);
        Ok((rotate(raw, 0x40), 1))
    } else if b0 & 0xC0 == 0x80 {
        let b1 = *bytes.get(1).ok_or(Error::new(ErrorKind::Truncated, 1, "compressed integer"))?;
        let raw = (i32::from(b0 & 0x3F) << 8) | i32::from(b1);
        Ok((rotate(raw, 0x2000), 2))
    } else if b0 & 0xE0 == 0xC0 {
        let b = bytes.get(1..4).ok_or(Error::new(ErrorKind::Truncated, 1, "compressed integer"))?;
        let raw = (i32::from(b0 & 0x1F) << 24)
            | (i32::from(b[0]) << 16)
            | (i32::from(b[1]) << 8)
            | i32::from(b[2]);
        Ok((rotate(raw, 0x1000_0000), 4))
    } else {
        Err(Error::new(ErrorKind::Malformed, 0, "compressed integer"))
    }
}

/// Undoes the one-bit rotation: the encoded value carries its sign in bit 0.
fn rotate(raw: i32, sign_bit: i32) -> i32 {
    let value = raw >> 1;
    if raw & 1 != 0 { value - sign_bit } else { value }
}

/// Encodes `value` as a compressed unsigned integer.
///
/// Returns the byte count written into `out`, or `None` when `value` exceeds
/// [`MAX_COMPRESSED_U32`]. Present for tests and for a future writer; the
/// decoders above are what the rest of the crate uses.
pub fn write_u32(value: u32, out: &mut [u8; 4]) -> Option<usize> {
    if value < 0x80 {
        out[0] = value as u8;
        Some(1)
    } else if value < 0x4000 {
        out[0] = 0x80 | (value >> 8) as u8;
        out[1] = value as u8;
        Some(2)
    } else if value <= MAX_COMPRESSED_U32 {
        out[0] = 0xC0 | (value >> 24) as u8;
        out[1] = (value >> 16) as u8;
        out[2] = (value >> 8) as u8;
        out[3] = value as u8;
        Some(4)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_boundaries() {
        let cases: &[(&[u8], u32, usize)] = &[
            (&[0x00], 0, 1),
            (&[0x03], 0x03, 1),
            (&[0x7F], 0x7F, 1),
            (&[0x80, 0x80], 0x80, 2),
            (&[0xAE, 0x57], 0x2E57, 2),
            (&[0xBF, 0xFF], 0x3FFF, 2),
            (&[0xC0, 0x00, 0x40, 0x00], 0x4000, 4),
            (&[0xDF, 0xFF, 0xFF, 0xFF], 0x1FFF_FFFF, 4),
        ];
        for &(bytes, value, len) in cases {
            assert_eq!(read_u32(bytes).unwrap(), (value, len), "{bytes:02x?}");
            let mut out = [0u8; 4];
            let n = write_u32(value, &mut out).unwrap();
            assert_eq!(&out[..n], bytes, "re-encoding {value:#x}");
        }
    }

    #[test]
    fn unsigned_rejects_the_reserved_prefix() {
        assert_eq!(read_u32(&[0xE0, 0, 0, 0]).unwrap_err().kind, ErrorKind::Malformed);
        assert_eq!(read_u32(&[0xFF]).unwrap_err().kind, ErrorKind::Malformed);
        assert_eq!(read_u32(&[]).unwrap_err().kind, ErrorKind::Truncated);
        assert_eq!(read_u32(&[0x80]).unwrap_err().kind, ErrorKind::Truncated);
        assert_eq!(read_u32(&[0xC0, 0, 0]).unwrap_err().kind, ErrorKind::Truncated);
    }

    #[test]
    fn signed_boundaries() {
        // The worked examples from II.23.2.
        let cases: &[(&[u8], i32, usize)] = &[
            (&[0x06], 3, 1),
            (&[0x7B], -3, 1),
            (&[0x80, 0x80], 64, 2),
            (&[0x01], -64, 1),
            (&[0xC0, 0x00, 0x40, 0x00], 8192, 4),
            (&[0x80, 0x01], -8192, 2),
            (&[0xDF, 0xFF, 0xFF, 0xFE], 268_435_455, 4),
            (&[0xC0, 0x00, 0x00, 0x01], -268_435_456, 4),
            (&[0x00], 0, 1),
        ];
        for &(bytes, value, len) in cases {
            assert_eq!(read_i32(bytes).unwrap(), (value, len), "{bytes:02x?}");
        }
    }

    #[test]
    fn every_one_byte_encoding_round_trips_unsigned() {
        for b in 0u8..0x80 {
            assert_eq!(read_u32(&[b]).unwrap(), (u32::from(b), 1));
        }
    }

    #[test]
    fn write_rejects_oversized() {
        let mut out = [0u8; 4];
        assert_eq!(write_u32(0x2000_0000, &mut out), None);
    }
}
