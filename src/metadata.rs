//! The metadata root and its streams (ECMA-335 II.24.2.1, II.24.2.2).
//!
//! A metadata region starts with the signature `0x424A5342` ("BSJB"), a version
//! string, and a directory of named streams. This module locates the four heaps
//! and the table stream and hands their byte ranges to the corresponding
//! decoder; every other stream, known or not, is exposed as a named range.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Diagnostic, DiagnosticCode, Error, ErrorKind, Result, Strictness};
use crate::heaps::{BlobHeap, GuidHeap, StringsHeap, UserStringsHeap};
use crate::reader::Reader;
use crate::tables::Tables;

const CTX: &str = "metadata root";

/// The metadata root signature, `BSJB` in little-endian order.
pub const METADATA_SIGNATURE: u32 = 0x424A_5342;

/// One entry of the metadata stream directory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StreamHeader<'a> {
    /// The stream name bytes, without the terminating NUL.
    pub name_bytes: &'a [u8],
    /// The declared offset of the stream from the metadata root.
    pub offset: u32,
    /// The declared size of the stream in bytes.
    pub size: u32,
    /// The stream bytes, clamped to the metadata region.
    pub data: &'a [u8],
}

impl<'a> StreamHeader<'a> {
    /// The stream name as UTF-8, or `None` when it is not valid UTF-8.
    pub fn name(&self) -> Option<&'a str> {
        core::str::from_utf8(self.name_bytes).ok()
    }

    /// The stream name with invalid sequences replaced.
    pub fn name_lossy(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.name_bytes)
    }

    /// True when the declared size did not fit inside the metadata region.
    pub fn is_clamped(&self) -> bool {
        self.data.len() != self.size as usize
    }
}

/// A parsed metadata region: the root header, the stream directory, the four
/// heaps and the table stream.
#[derive(Clone, Debug)]
pub struct Metadata<'a> {
    bytes: &'a [u8],
    base: usize,
    strictness: Strictness,
    diagnostics: Vec<Diagnostic>,
    major_version: u16,
    minor_version: u16,
    flags: u16,
    version_bytes: &'a [u8],
    streams: Vec<StreamHeader<'a>>,
    strings: StringsHeap<'a>,
    user_strings: UserStringsHeap<'a>,
    blobs: BlobHeap<'a>,
    guids: GuidHeap<'a>,
    tables: Tables<'a>,
    has_pdb_stream: bool,
}

impl<'a> Metadata<'a> {
    /// Parses a metadata region in [`Strictness::Permissive`] mode.
    ///
    /// `bytes` must start at the `BSJB` signature; use
    /// [`PeImage::metadata`](crate::pe::PeImage::metadata) to locate it inside
    /// a PE file.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        Self::parse_at(bytes, 0, Strictness::Permissive)
    }

    /// Parses a metadata region with an explicit strictness.
    pub fn parse_with(bytes: &'a [u8], strictness: Strictness) -> Result<Self> {
        Self::parse_at(bytes, 0, strictness)
    }

    /// Parses a metadata region that begins at absolute offset `base` in the
    /// original input, so that errors and diagnostics name file offsets.
    pub fn parse_at(bytes: &'a [u8], base: usize, strictness: Strictness) -> Result<Self> {
        let mut diagnostics = Vec::new();
        let mut r = Reader::new(bytes, base, CTX);

        if r.u32()? != METADATA_SIGNATURE {
            return Err(Error::new(ErrorKind::Malformed, base, CTX));
        }
        let major_version = r.u16()?;
        let minor_version = r.u16()?;
        let _reserved = r.u32()?;
        let version_length = r.u32()? as usize;
        let version_at = r.absolute();
        let version_field = r.take(version_length)?;
        let version_bytes = match version_field.iter().position(|&b| b == 0) {
            Some(end) => &version_field[..end],
            None => {
                if strictness.is_strict() {
                    return Err(Error::new(ErrorKind::Malformed, version_at, CTX));
                }
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::VersionStringPadding,
                    version_at,
                    version_length as u64,
                ));
                version_field
            }
        };
        let flags = r.u16()?;
        let stream_count = r.u16()? as usize;

        let mut streams = Vec::new();
        for _ in 0..stream_count {
            // A truncated directory ends the list rather than the parse; the
            // streams already found remain usable.
            let at = r.absolute();
            let Ok(offset) = r.u32() else {
                if strictness.is_strict() {
                    return Err(Error::new(ErrorKind::Truncated, at, CTX));
                }
                break;
            };
            let Ok(size) = r.u32() else {
                if strictness.is_strict() {
                    return Err(Error::new(ErrorKind::Truncated, at, CTX));
                }
                break;
            };
            let name_start = r.position();
            let rest = r.rest();
            let name_len = rest.iter().position(|&b| b == 0);
            let (name_bytes, advance) = match name_len {
                // Names are NUL-terminated and padded to a 4-byte boundary.
                Some(len) => (&rest[..len], (len + 1).next_multiple_of(4)),
                None => {
                    if strictness.is_strict() {
                        return Err(Error::new(ErrorKind::Malformed, r.absolute(), CTX));
                    }
                    diagnostics.push(Diagnostic::new(
                        DiagnosticCode::StreamNamePadding,
                        r.absolute(),
                        rest.len() as u64,
                    ));
                    (rest, rest.len())
                }
            };
            if name_bytes.len() > 32 && strictness.is_strict() {
                return Err(Error::new(ErrorKind::Malformed, r.absolute(), CTX));
            }
            r.seek(name_start + advance)?;

            let start = offset as usize;
            let declared_end = start.saturating_add(size as usize);
            let end = declared_end.min(bytes.len());
            let data = bytes.get(start.min(bytes.len())..end).unwrap_or(&[]);
            if data.len() != size as usize {
                if strictness.is_strict() {
                    return Err(Error::new(ErrorKind::Truncated, base + start, CTX));
                }
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::StreamRangeClamped,
                    base + start,
                    declared_end as u64,
                ));
            }
            streams.push(StreamHeader { name_bytes, offset, size, data });
        }

        let mut strings = StringsHeap::empty();
        let mut user_strings = UserStringsHeap::empty();
        let mut blobs = BlobHeap::empty();
        let mut guids = GuidHeap::empty();
        let mut table_stream: Option<(&[u8], usize, bool)> = None;
        let mut seen: Vec<&[u8]> = Vec::new();
        let mut has_pdb_stream = false;

        for stream in &streams {
            let stream_base = base.saturating_add(stream.offset as usize);
            if seen.contains(&stream.name_bytes) {
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::DuplicateStreamName,
                    stream_base,
                    0,
                ));
                if strictness.is_strict() {
                    return Err(Error::new(ErrorKind::Malformed, stream_base, CTX));
                }
                continue;
            }
            seen.push(stream.name_bytes);
            match stream.name_bytes {
                b"#Strings" => strings = StringsHeap::new(stream.data, stream_base),
                b"#US" => user_strings = UserStringsHeap::new(stream.data, stream_base),
                b"#Blob" => blobs = BlobHeap::new(stream.data, stream_base),
                b"#GUID" => guids = GuidHeap::new(stream.data, stream_base),
                b"#~" => {
                    if table_stream.is_none() {
                        table_stream = Some((stream.data, stream_base, false));
                    }
                }
                b"#-" => {
                    if table_stream.is_none() {
                        table_stream = Some((stream.data, stream_base, true));
                    }
                }
                b"#Pdb" => has_pdb_stream = true,
                _ => {}
            }
        }

        let tables = match table_stream {
            Some((data, stream_base, uncompressed)) => {
                Tables::parse(data, stream_base, uncompressed, strictness, &mut diagnostics)?
            }
            None => {
                if strictness.is_strict() {
                    return Err(Error::new(ErrorKind::Malformed, base, CTX));
                }
                Tables::empty()
            }
        };

        Ok(Metadata {
            bytes,
            base,
            strictness,
            diagnostics,
            major_version,
            minor_version,
            flags,
            version_bytes,
            streams,
            strings,
            user_strings,
            blobs,
            guids,
            tables,
            has_pdb_stream,
        })
    }

    /// The bytes of the metadata region.
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The absolute offset of the metadata region in the original input.
    pub const fn base(&self) -> usize {
        self.base
    }

    /// The strictness this region was parsed with.
    pub const fn strictness(&self) -> Strictness {
        self.strictness
    }

    /// Deviations tolerated while parsing.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// The metadata root major version, normally 1.
    pub const fn major_version(&self) -> u16 {
        self.major_version
    }

    /// The metadata root minor version, normally 1.
    pub const fn minor_version(&self) -> u16 {
        self.minor_version
    }

    /// The metadata root flags field, reserved and normally 0.
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    /// The raw version string bytes, without padding.
    pub const fn version_bytes(&self) -> &'a [u8] {
        self.version_bytes
    }

    /// The version string, e.g. `v4.0.30319`, with invalid UTF-8 replaced.
    pub fn version_string(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.version_bytes)
    }

    /// The stream directory, in declaration order, including unknown streams.
    pub fn streams(&self) -> &[StreamHeader<'a>] {
        &self.streams
    }

    /// One stream by name, or `None`.
    pub fn stream(&self, name: &str) -> Option<&StreamHeader<'a>> {
        self.streams.iter().find(|s| s.name_bytes == name.as_bytes())
    }

    /// The `#Strings` heap.
    pub const fn strings(&self) -> &StringsHeap<'a> {
        &self.strings
    }

    /// The `#US` heap.
    pub const fn user_strings(&self) -> &UserStringsHeap<'a> {
        &self.user_strings
    }

    /// The `#Blob` heap.
    pub const fn blobs(&self) -> &BlobHeap<'a> {
        &self.blobs
    }

    /// The `#GUID` heap.
    pub const fn guids(&self) -> &GuidHeap<'a> {
        &self.guids
    }

    /// The `#~` or `#-` table stream.
    pub const fn tables(&self) -> &Tables<'a> {
        &self.tables
    }

    /// True when a `#Pdb` stream is present, i.e. this is a Portable PDB.
    pub const fn has_pdb_stream(&self) -> bool {
        self.has_pdb_stream
    }

    /// True when the table stream was `#-`, meaning an edit-and-continue or
    /// uncompressed image that may carry `*Ptr` indirection tables.
    pub const fn is_uncompressed(&self) -> bool {
        self.tables.is_uncompressed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::TableId;

    /// Builds a minimal but well-formed metadata region with the given streams.
    fn build(streams: &[(&str, &[u8])]) -> Vec<u8> {
        let version = b"v4.0.30319\0\0";
        let mut header = Vec::new();
        header.extend_from_slice(&METADATA_SIGNATURE.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&(version.len() as u32).to_le_bytes());
        header.extend_from_slice(version);
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&(streams.len() as u16).to_le_bytes());

        let mut directory_size = 0usize;
        for (name, _) in streams {
            directory_size += 8 + (name.len() + 1).next_multiple_of(4);
        }
        let mut offset = header.len() + directory_size;
        let mut directory = Vec::new();
        let mut payload = Vec::new();
        for (name, data) in streams {
            directory.extend_from_slice(&(offset as u32).to_le_bytes());
            directory.extend_from_slice(&(data.len() as u32).to_le_bytes());
            let mut name_bytes = name.as_bytes().to_vec();
            name_bytes.push(0);
            while name_bytes.len() % 4 != 0 {
                name_bytes.push(0);
            }
            directory.extend_from_slice(&name_bytes);
            payload.extend_from_slice(data);
            offset += data.len();
        }
        header.extend_from_slice(&directory);
        header.extend_from_slice(&payload);
        header
    }

    /// A `#~` stream with no tables present.
    fn empty_table_stream() -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        s.push(2); // MajorVersion
        s.push(0); // MinorVersion
        s.push(0); // HeapSizes
        s.push(1); // Reserved
        s.extend_from_slice(&0u64.to_le_bytes()); // Valid
        s.extend_from_slice(&0u64.to_le_bytes()); // Sorted
        s
    }

    #[test]
    fn parses_a_minimal_region() {
        let bytes = build(&[("#~", &empty_table_stream()), ("#Strings", b"\0ok\0")]);
        let md = Metadata::parse(&bytes).unwrap();
        assert_eq!(md.version_string(), "v4.0.30319");
        assert_eq!(md.streams().len(), 2);
        assert_eq!(md.streams()[0].name(), Some("#~"));
        assert_eq!(md.strings().len(), 4);
        assert_eq!(md.tables().row_count(TableId::TypeDef), 0);
        assert!(!md.has_pdb_stream());
        assert!(md.diagnostics().is_empty());
    }

    #[test]
    fn unknown_streams_are_exposed_not_rejected() {
        let bytes = build(&[("#~", &empty_table_stream()), ("#JTD", b""), ("#Schema", b"\x01")]);
        let md = Metadata::parse(&bytes).unwrap();
        assert_eq!(md.streams().len(), 3);
        assert!(md.stream("#JTD").is_some());
        assert_eq!(md.stream("#Schema").unwrap().data, b"\x01");
    }

    #[test]
    fn duplicate_stream_names_keep_the_first() {
        let bytes = build(&[
            ("#~", &empty_table_stream()),
            ("#Strings", b"\0a\0"),
            ("#Strings", b"\0bb\0"),
        ]);
        let md = Metadata::parse(&bytes).unwrap();
        assert_eq!(md.strings().len(), 3);
        assert!(
            md.diagnostics().iter().any(|d| d.code == DiagnosticCode::DuplicateStreamName),
            "expected a duplicate-name diagnostic"
        );
        assert!(Metadata::parse_with(&bytes, Strictness::Strict).is_err());
    }

    #[test]
    fn a_stream_running_past_the_end_is_clamped() {
        let mut bytes = build(&[("#~", &empty_table_stream()), ("#Blob", b"\0")]);
        let len = bytes.len();
        // Enlarge the last stream size field beyond the region.
        let size_pos = len - 1 - 1;
        let _ = size_pos;
        // Rebuild by hand: patch the #Blob declared size to a huge value.
        let pattern = b"#Blob\0\0\0";
        let dir_pos = bytes.windows(8).position(|w| w == pattern).unwrap();
        bytes[dir_pos - 4..dir_pos].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
        let md = Metadata::parse(&bytes).unwrap();
        assert!(md.blobs().len() <= bytes.len());
        assert!(md.diagnostics().iter().any(|d| d.code == DiagnosticCode::StreamRangeClamped));
        assert!(Metadata::parse_with(&bytes, Strictness::Strict).is_err());
    }

    #[test]
    fn a_pdb_stream_is_reported() {
        let bytes = build(&[("#~", &empty_table_stream()), ("#Pdb", &[0u8; 8])]);
        assert!(Metadata::parse(&bytes).unwrap().has_pdb_stream());
    }

    #[test]
    fn the_uncompressed_stream_is_recognised() {
        let bytes = build(&[("#-", &empty_table_stream())]);
        let md = Metadata::parse(&bytes).unwrap();
        assert!(md.is_uncompressed());
    }

    #[test]
    fn truncated_inputs_never_panic() {
        let full = build(&[("#~", &empty_table_stream()), ("#Strings", b"\0ok\0")]);
        for len in 0..full.len() {
            let _ = Metadata::parse(&full[..len]);
            let _ = Metadata::parse_with(&full[..len], Strictness::Strict);
        }
    }

    #[test]
    fn a_wrong_signature_is_rejected() {
        assert_eq!(Metadata::parse(b"NOPE").unwrap_err().kind, ErrorKind::Malformed);
    }
}
