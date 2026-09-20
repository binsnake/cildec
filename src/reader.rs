//! Internal bounds-checked little-endian cursor.
//!
//! Every read either succeeds and advances the cursor by exactly the width of
//! the value, or fails with [`ErrorKind::Truncated`] naming the absolute offset
//! at which the read started. There is no panicking accessor in this module.

use crate::error::{Error, ErrorKind, Result};

/// A cursor over a byte slice, tracking an absolute base offset so that errors
/// can name a position in the original input rather than in a sub-slice.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    base: usize,
    context: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(data: &'a [u8], base: usize, context: &'static str) -> Self {
        Reader { data, pos: 0, base, context }
    }

    pub(crate) const fn position(&self) -> usize {
        self.pos
    }

    /// Absolute offset of the cursor in the original input.
    pub(crate) const fn absolute(&self) -> usize {
        self.base.saturating_add(self.pos)
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub(crate) fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.data.len() {
            return Err(self.err(ErrorKind::OutOfRange));
        }
        self.pos = pos;
        Ok(())
    }

    pub(crate) fn skip(&mut self, n: usize) -> Result<()> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.err(ErrorKind::OutOfRange))?;
        self.seek(end)
    }

    /// Aligns the cursor up to a multiple of `align` relative to `origin`.
    pub(crate) fn align_to(&mut self, origin: usize, align: usize) -> Result<()> {
        debug_assert!(align.is_power_of_two());
        let rel = self.pos.saturating_sub(origin);
        let pad = rel.wrapping_neg() & (align - 1);
        self.skip(pad)
    }

    fn err(&self, kind: ErrorKind) -> Error {
        Error::new(kind, self.absolute(), self.context)
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.err(ErrorKind::Truncated))?;
        let slice = self.data.get(self.pos..end).ok_or_else(|| self.err(ErrorKind::Truncated))?;
        self.pos = end;
        Ok(slice)
    }

    /// Returns the remaining bytes without consuming them.
    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        let b = *self.data.get(self.pos).ok_or_else(|| self.err(ErrorKind::Truncated))?;
        self.pos += 1;
        Ok(b)
    }

    pub(crate) fn peek_u8(&self) -> Result<u8> {
        self.data.get(self.pos).copied().ok_or_else(|| self.err(ErrorKind::Truncated))
    }

    pub(crate) fn i8(&mut self) -> Result<i8> {
        Ok(self.u8()? as i8)
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    pub(crate) fn i64(&mut self) -> Result<i64> {
        Ok(self.u64()? as i64)
    }

    pub(crate) fn f32(&mut self) -> Result<f32> {
        Ok(f32::from_bits(self.u32()?))
    }

    pub(crate) fn f64(&mut self) -> Result<f64> {
        Ok(f64::from_bits(self.u64()?))
    }
}

/// Reads a 2- or 4-byte little-endian value out of `bytes` at `offset` without
/// a cursor. Returns `None` when the range is not fully inside `bytes`.
pub(crate) fn read_uint_at(bytes: &[u8], offset: usize, width: u8) -> Option<u32> {
    match width {
        2 => {
            let b = bytes.get(offset..offset.checked_add(2)?)?;
            Some(u32::from(u16::from_le_bytes([b[0], b[1]])))
        }
        4 => {
            let b = bytes.get(offset..offset.checked_add(4)?)?;
            Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounds_checked() {
        let mut r = Reader::new(&[1, 2, 3], 0x100, "test");
        assert_eq!(r.u16().unwrap(), 0x0201);
        assert_eq!(r.remaining(), 1);
        let e = r.u32().unwrap_err();
        assert_eq!(e.kind, ErrorKind::Truncated);
        assert_eq!(e.offset, Some(0x102));
    }

    #[test]
    fn align_is_relative_to_origin() {
        let data = [0u8; 16];
        let mut r = Reader::new(&data, 0, "test");
        r.skip(5).unwrap();
        r.align_to(0, 4).unwrap();
        assert_eq!(r.position(), 8);
        let mut r = Reader::new(&data, 0, "test");
        r.skip(5).unwrap();
        r.align_to(1, 4).unwrap();
        assert_eq!(r.position(), 5);
    }

    #[test]
    fn skip_past_end_is_out_of_range() {
        let mut r = Reader::new(&[0u8; 4], 0, "test");
        assert_eq!(r.skip(usize::MAX).unwrap_err().kind, ErrorKind::OutOfRange);
        assert_eq!(r.skip(5).unwrap_err().kind, ErrorKind::OutOfRange);
    }
}
