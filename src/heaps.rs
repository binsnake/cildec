//! The four metadata heaps: `#Strings`, `#US`, `#Blob` and `#GUID` (II.24.2.2–II.24.2.4).
//!
//! Heaps are read lazily. Constructing one only records its byte range; every
//! accessor bounds-checks both the start of the entry and the length it decodes
//! from the entry itself, so a hostile index can at worst produce an error.
//!
//! Index 0 denotes the empty value in `#Strings`, `#US` and `#Blob`. `#GUID` is
//! indexed from 1 and index 0 means "no GUID"; [`GuidHeap::get`] rejects it, so
//! check [`GuidIndex::is_empty`] first.

use alloc::borrow::Cow;
use alloc::string::String;
use core::fmt;

use crate::compressed;
use crate::error::{Error, ErrorKind, Result};
use crate::token::{BlobIndex, GuidIndex, StringIndex, UserStringToken};

/// A 16-byte GUID as stored in the `#GUID` heap (little-endian first three fields).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// The all-zero GUID.
    pub const ZERO: Guid = Guid([0; 16]);

    /// The raw bytes in heap order.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-",
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9]
        )?;
        for byte in &b[10..] {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({self})")
    }
}

/// The shared byte range of a heap, plus the absolute offset used in errors.
#[derive(Clone, Copy, Debug, Default)]
struct Span<'a> {
    data: &'a [u8],
    base: usize,
}

impl<'a> Span<'a> {
    const fn new(data: &'a [u8], base: usize) -> Self {
        Span { data, base }
    }

    fn at(&self, offset: u32, context: &'static str) -> Result<&'a [u8]> {
        let offset = offset as usize;
        self.data.get(offset..).ok_or(Error::new(
            ErrorKind::OutOfRange,
            self.base.saturating_add(offset),
            context,
        ))
    }
}

macro_rules! heap_common {
    ($name:ident, $ctx:literal) => {
        impl<'a> $name<'a> {
            /// Wraps a heap byte range. `base` is the absolute offset of the
            /// heap in the input, used only for error reporting.
            pub const fn new(data: &'a [u8], base: usize) -> Self {
                $name(Span::new(data, base))
            }

            /// An empty heap, used when the stream is absent.
            pub const fn empty() -> Self {
                $name(Span { data: &[], base: 0 })
            }

            /// The raw heap bytes.
            pub const fn data(&self) -> &'a [u8] {
                self.0.data
            }

            /// The heap size in bytes.
            pub const fn len(&self) -> usize {
                self.0.data.len()
            }

            /// True when the heap is absent or zero-length.
            pub const fn is_empty(&self) -> bool {
                self.0.data.is_empty()
            }

            /// The absolute offset of this heap in the parsed input.
            pub const fn base(&self) -> usize {
                self.0.base
            }

            /// The context string used in errors from this heap.
            pub const fn context() -> &'static str {
                $ctx
            }
        }
    };
}

/// The `#Strings` heap: NUL-terminated, nominally UTF-8 byte strings (II.24.2.3).
#[derive(Clone, Copy, Debug, Default)]
pub struct StringsHeap<'a>(Span<'a>);
heap_common!(StringsHeap, "#Strings");

impl<'a> StringsHeap<'a> {
    /// The bytes of the entry at `index`, up to but not including its NUL.
    ///
    /// An unterminated final entry yields the rest of the heap rather than an
    /// error; obfuscated images routinely omit the last NUL.
    pub fn bytes(&self, index: StringIndex) -> Result<&'a [u8]> {
        let rest = self.0.at(index.0, "#Strings")?;
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        Ok(&rest[..end])
    }

    /// The entry at `index` as UTF-8.
    pub fn str(&self, index: StringIndex) -> Result<&'a str> {
        let bytes = self.bytes(index)?;
        core::str::from_utf8(bytes).map_err(|e| {
            Error::new(
                ErrorKind::InvalidUtf8,
                self.0.base.saturating_add(index.0 as usize).saturating_add(e.valid_up_to()),
                "#Strings",
            )
        })
    }

    /// The entry at `index` as UTF-8, or `None` if it is out of range or not
    /// valid UTF-8.
    pub fn str_opt(&self, index: StringIndex) -> Option<&'a str> {
        self.str(index).ok()
    }

    /// The entry at `index` with invalid sequences replaced by `U+FFFD`.
    pub fn lossy(&self, index: StringIndex) -> Result<Cow<'a, str>> {
        Ok(String::from_utf8_lossy(self.bytes(index)?))
    }

    /// Iterates every NUL-terminated entry, yielding its index and bytes.
    ///
    /// Entry 0 (the empty string) is included. Interior indices that point into
    /// the middle of an entry are legal in metadata but are not visited here.
    pub fn iter(&self) -> StringsIter<'a> {
        StringsIter { data: self.0.data, pos: 0 }
    }
}

/// Iterator over `#Strings` entries; see [`StringsHeap::iter`].
#[derive(Clone, Debug)]
pub struct StringsIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for StringsIter<'a> {
    type Item = (StringIndex, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }
        let start = self.pos;
        let rest = &self.data[start..];
        let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        // Always advances by at least one byte, so this terminates.
        self.pos = start + len + 1;
        Some((StringIndex(start as u32), &rest[..len]))
    }
}

/// The `#Blob` heap: length-prefixed byte strings (II.24.2.4).
#[derive(Clone, Copy, Debug, Default)]
pub struct BlobHeap<'a>(Span<'a>);
heap_common!(BlobHeap, "#Blob");

impl<'a> BlobHeap<'a> {
    /// The bytes of the blob at `index`, excluding its length prefix.
    pub fn get(&self, index: BlobIndex) -> Result<&'a [u8]> {
        let rest = self.0.at(index.0, "#Blob")?;
        let base = self.0.base.saturating_add(index.0 as usize);
        let (len, used) = compressed::read_u32(rest).map_err(|e| e.rebase(base))?;
        let start = used;
        let end = start.checked_add(len as usize).ok_or(Error::new(
            ErrorKind::OutOfRange,
            base,
            "#Blob",
        ))?;
        rest.get(start..end).ok_or(Error::new(ErrorKind::OutOfRange, base, "#Blob"))
    }

    /// The blob at `index` together with its total encoded size.
    pub fn get_with_size(&self, index: BlobIndex) -> Result<(&'a [u8], usize)> {
        let rest = self.0.at(index.0, "#Blob")?;
        let base = self.0.base.saturating_add(index.0 as usize);
        let (len, used) = compressed::read_u32(rest).map_err(|e| e.rebase(base))?;
        let end = used.checked_add(len as usize).ok_or(Error::new(
            ErrorKind::OutOfRange,
            base,
            "#Blob",
        ))?;
        let bytes = rest.get(used..end).ok_or(Error::new(ErrorKind::OutOfRange, base, "#Blob"))?;
        Ok((bytes, end))
    }

    /// The absolute offset in the parsed input of the blob body at `index`.
    pub fn body_offset(&self, index: BlobIndex) -> Result<usize> {
        let rest = self.0.at(index.0, "#Blob")?;
        let base = self.0.base.saturating_add(index.0 as usize);
        let (_, used) = compressed::read_u32(rest).map_err(|e| e.rebase(base))?;
        Ok(base.saturating_add(used))
    }

    /// Iterates every blob from the start of the heap.
    ///
    /// Stops at the first entry that cannot be decoded, which is how a heap
    /// with trailing garbage terminates.
    pub fn iter(&self) -> BlobIter<'a> {
        BlobIter { heap: *self, pos: 0 }
    }
}

/// Iterator over `#Blob` entries; see [`BlobHeap::iter`].
#[derive(Clone, Debug)]
pub struct BlobIter<'a> {
    heap: BlobHeap<'a>,
    pos: u32,
}

impl<'a> Iterator for BlobIter<'a> {
    type Item = (BlobIndex, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos as usize >= self.heap.len() {
            return None;
        }
        let index = BlobIndex(self.pos);
        let (bytes, size) = self.heap.get_with_size(index).ok()?;
        // A zero-length prefix still consumes its length byte, so `size >= 1`.
        self.pos = self.pos.checked_add(u32::try_from(size).ok()?)?;
        Some((index, bytes))
    }
}

/// The `#GUID` heap: a 1-based array of 16-byte GUIDs (II.24.2.5).
#[derive(Clone, Copy, Debug, Default)]
pub struct GuidHeap<'a>(Span<'a>);
heap_common!(GuidHeap, "#GUID");

impl<'a> GuidHeap<'a> {
    /// The number of complete GUIDs in the heap.
    pub const fn count(&self) -> usize {
        self.0.data.len() / 16
    }

    /// The GUID at a 1-based index.
    ///
    /// Index 0 means "no GUID" and is rejected with [`ErrorKind::OutOfRange`].
    pub fn get(&self, index: GuidIndex) -> Result<Guid> {
        if index.0 == 0 {
            return Err(Error::new(ErrorKind::OutOfRange, self.0.base, "#GUID"));
        }
        let start = (index.0 as usize - 1).checked_mul(16).ok_or(Error::new(
            ErrorKind::OutOfRange,
            self.0.base,
            "#GUID",
        ))?;
        let bytes = self.0.data.get(start..start + 16).ok_or(Error::new(
            ErrorKind::OutOfRange,
            self.0.base.saturating_add(start),
            "#GUID",
        ))?;
        let mut out = [0u8; 16];
        out.copy_from_slice(bytes);
        Ok(Guid(out))
    }

    /// The GUID at `index`, or `None` for index 0 or an out-of-range index.
    pub fn get_opt(&self, index: GuidIndex) -> Option<Guid> {
        self.get(index).ok()
    }

    /// Iterates every complete GUID with its 1-based index.
    pub fn iter(&self) -> impl Iterator<Item = (GuidIndex, Guid)> + 'a {
        let heap = *self;
        (1..=heap.count() as u32)
            .filter_map(move |i| heap.get(GuidIndex(i)).ok().map(|g| (GuidIndex(i), g)))
    }
}

/// One `#US` entry: UTF-16LE code units plus the trailing "has special
/// characters" byte (II.24.2.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UserString<'a> {
    /// The raw UTF-16LE bytes, excluding the trailing flag byte.
    pub bytes: &'a [u8],
    /// The trailing flag byte, or `None` when the entry was empty.
    pub flag: Option<u8>,
    /// True when the entry byte length was even, which the spec forbids; the
    /// trailing odd byte was dropped.
    pub odd_length: bool,
}

impl<'a> UserString<'a> {
    /// The number of UTF-16 code units.
    pub const fn len_utf16(&self) -> usize {
        self.bytes.len() / 2
    }

    /// True when the string has no code units.
    pub const fn is_empty(&self) -> bool {
        self.bytes.len() < 2
    }

    /// True when the trailing flag byte is non-zero, meaning the string
    /// contains characters outside the ASCII-compatible fast path.
    pub const fn has_special_chars(&self) -> bool {
        matches!(self.flag, Some(f) if f != 0)
    }

    /// The UTF-16 code units, in order.
    pub fn code_units(&self) -> impl Iterator<Item = u16> + 'a {
        let bytes = self.bytes;
        (0..bytes.len() / 2).map(move |i| u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]))
    }

    /// The string with unpaired surrogates replaced by `U+FFFD`.
    pub fn to_string_lossy(&self) -> String {
        char::decode_utf16(self.code_units())
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    }
}

/// The `#US` heap: length-prefixed UTF-16LE user strings (II.24.2.4).
#[derive(Clone, Copy, Debug, Default)]
pub struct UserStringsHeap<'a>(Span<'a>);
heap_common!(UserStringsHeap, "#US");

impl<'a> UserStringsHeap<'a> {
    /// The entry at the offset carried by a `ldstr` token.
    pub fn get(&self, token: UserStringToken) -> Result<UserString<'a>> {
        self.get_at(token.offset())
    }

    /// The entry at a raw heap offset.
    pub fn get_at(&self, offset: u32) -> Result<UserString<'a>> {
        let rest = self.0.at(offset, "#US")?;
        let base = self.0.base.saturating_add(offset as usize);
        let (len, used) = compressed::read_u32(rest).map_err(|e| e.rebase(base))?;
        let end =
            used.checked_add(len as usize).ok_or(Error::new(ErrorKind::OutOfRange, base, "#US"))?;
        let body = rest.get(used..end).ok_or(Error::new(ErrorKind::OutOfRange, base, "#US"))?;
        Ok(split_user_string(body))
    }

    /// The entry at `offset` together with its total encoded size.
    fn get_with_size(&self, offset: u32) -> Result<(UserString<'a>, usize)> {
        let rest = self.0.at(offset, "#US")?;
        let base = self.0.base.saturating_add(offset as usize);
        let (len, used) = compressed::read_u32(rest).map_err(|e| e.rebase(base))?;
        let end =
            used.checked_add(len as usize).ok_or(Error::new(ErrorKind::OutOfRange, base, "#US"))?;
        let body = rest.get(used..end).ok_or(Error::new(ErrorKind::OutOfRange, base, "#US"))?;
        Ok((split_user_string(body), end))
    }

    /// Iterates every entry from the start of the heap.
    pub fn iter(&self) -> UserStringsIter<'a> {
        UserStringsIter { heap: *self, pos: 0 }
    }
}

fn split_user_string(body: &[u8]) -> UserString<'_> {
    match body.split_last() {
        None => UserString { bytes: &[], flag: None, odd_length: false },
        Some((&flag, rest)) => {
            let odd_length = rest.len() % 2 != 0;
            let units = if odd_length { &rest[..rest.len() - 1] } else { rest };
            UserString { bytes: units, flag: Some(flag), odd_length }
        }
    }
}

/// Iterator over `#US` entries; see [`UserStringsHeap::iter`].
#[derive(Clone, Debug)]
pub struct UserStringsIter<'a> {
    heap: UserStringsHeap<'a>,
    pos: u32,
}

impl<'a> Iterator for UserStringsIter<'a> {
    type Item = (UserStringToken, UserString<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos as usize >= self.heap.len() {
            return None;
        }
        let offset = self.pos;
        let (value, size) = self.heap.get_with_size(offset).ok()?;
        self.pos = self.pos.checked_add(u32::try_from(size).ok()?)?;
        Some((UserStringToken(0x7000_0000 | offset), value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn strings_heap_reads_and_iterates() {
        let data = b"\0System\0Console\0";
        let heap = StringsHeap::new(data, 0x1000);
        assert_eq!(heap.bytes(StringIndex(0)).unwrap(), b"");
        assert_eq!(heap.str(StringIndex(1)).unwrap(), "System");
        assert_eq!(heap.str(StringIndex(8)).unwrap(), "Console");
        // Interior index: the tail of an entry is itself a valid string.
        assert_eq!(heap.str(StringIndex(4)).unwrap(), "tem");
        assert_eq!(heap.bytes(StringIndex(99)).unwrap_err().kind, ErrorKind::OutOfRange);
        let all: Vec<_> = heap.iter().map(|(_, b)| b).collect();
        assert_eq!(all, alloc::vec![&b""[..], &b"System"[..], &b"Console"[..]]);
    }

    #[test]
    fn strings_heap_tolerates_invalid_utf8_and_missing_nul() {
        let data = b"\0ok\0\xFF\xFEbad";
        let heap = StringsHeap::new(data, 0);
        assert_eq!(heap.bytes(StringIndex(4)).unwrap(), b"\xFF\xFEbad");
        assert_eq!(heap.str(StringIndex(4)).unwrap_err().kind, ErrorKind::InvalidUtf8);
        assert_eq!(heap.str_opt(StringIndex(4)), None);
        assert_eq!(heap.lossy(StringIndex(4)).unwrap(), "\u{FFFD}\u{FFFD}bad");
    }

    #[test]
    fn blob_heap_reads_lengths() {
        // index 0 = empty, index 1 = 3 bytes, index 5 = 0x80 bytes (2-byte prefix)
        let mut data = alloc::vec![0u8];
        data.extend_from_slice(&[3, 0xAA, 0xBB, 0xCC]);
        data.push(0x80);
        data.push(0x80);
        data.extend(core::iter::repeat_n(0x11u8, 0x80));
        let heap = BlobHeap::new(&data, 0);
        assert_eq!(heap.get(BlobIndex(0)).unwrap(), b"");
        assert_eq!(heap.get(BlobIndex(1)).unwrap(), &[0xAA, 0xBB, 0xCC]);
        assert_eq!(heap.get(BlobIndex(5)).unwrap().len(), 0x80);
        assert_eq!(heap.iter().count(), 3);
    }

    #[test]
    fn blob_heap_rejects_a_length_past_the_end() {
        let data = [0x10u8, 1, 2, 3];
        let heap = BlobHeap::new(&data, 0x40);
        let e = heap.get(BlobIndex(0)).unwrap_err();
        assert_eq!(e.kind, ErrorKind::OutOfRange);
        assert_eq!(e.offset, Some(0x40));
    }

    #[test]
    fn guid_heap_is_one_based() {
        let mut data = [0u8; 32];
        data[0] = 1;
        data[16] = 2;
        let heap = GuidHeap::new(&data, 0);
        assert_eq!(heap.count(), 2);
        assert_eq!(heap.get(GuidIndex(1)).unwrap().0[0], 1);
        assert_eq!(heap.get(GuidIndex(2)).unwrap().0[0], 2);
        assert_eq!(heap.get(GuidIndex(0)).unwrap_err().kind, ErrorKind::OutOfRange);
        assert_eq!(heap.get(GuidIndex(3)).unwrap_err().kind, ErrorKind::OutOfRange);
        assert_eq!(heap.iter().count(), 2);
    }

    #[test]
    fn guid_display_uses_mixed_endianness() {
        let g = Guid([
            0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A, 0xF0, 0xDE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ]);
        assert_eq!(alloc::format!("{g}"), "12345678-9abc-def0-0102-030405060708");
    }

    #[test]
    fn user_strings_split_the_flag_byte() {
        // "Hi" = 48 00 69 00, plus flag 00 -> blob length 5.
        let data = [0u8, 5, 0x48, 0x00, 0x69, 0x00, 0x00];
        let heap = UserStringsHeap::new(&data, 0);
        let s = heap.get(UserStringToken(0x7000_0001)).unwrap();
        assert_eq!(s.len_utf16(), 2);
        assert_eq!(s.to_string_lossy(), "Hi");
        assert!(!s.has_special_chars());
        assert!(!s.odd_length);
        let empty = heap.get_at(0).unwrap();
        assert!(empty.is_empty());
        assert_eq!(heap.iter().count(), 2);
    }

    #[test]
    fn user_strings_tolerate_an_even_body() {
        // Body length 4 -> 3 bytes of UTF-16 data, which is malformed.
        let data = [4u8, 0x48, 0x00, 0x69, 0x00];
        let heap = UserStringsHeap::new(&data, 0);
        let s = heap.get_at(0).unwrap();
        assert!(s.odd_length);
        assert_eq!(s.to_string_lossy(), "H");
    }

    #[test]
    fn empty_heaps_never_panic() {
        assert!(StringsHeap::empty().bytes(StringIndex(0)).is_ok());
        assert!(BlobHeap::empty().get(BlobIndex(0)).is_err());
        assert!(GuidHeap::empty().get(GuidIndex(1)).is_err());
        assert!(UserStringsHeap::empty().get_at(0).is_err());
        assert_eq!(StringsHeap::empty().iter().count(), 0);
    }
}
