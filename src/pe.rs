//! The PE/COFF container that carries a managed image (ECMA-335 II.25).
//!
//! This module implements only as much of PE/COFF as ECMA-335 II.25 requires:
//! the MS-DOS stub, the PE signature, the COFF header, the PE32 and PE32+
//! optional headers, the data directories, the section table, RVA translation,
//! and the CLI header (II.25.3.3). Relocations, imports, exports, debug
//! directories and native code are not interpreted; where a directory names a
//! range that this crate does not decode, the range itself is exposed.

use alloc::vec::Vec;

use crate::error::{Diagnostic, DiagnosticCode, Error, ErrorKind, Result, Strictness};
use crate::metadata::Metadata;
use crate::reader::Reader;
use crate::token::{TableId, Token};

const CTX: &str = "PE image";

/// The index of the CLI header in the PE data directory (II.25.3.3).
pub const CLI_HEADER_DIRECTORY: usize = 14;

/// A `(RVA, size)` pair from a PE data directory or a CLI header field.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DataDirectory {
    /// Relative virtual address of the first byte, or 0 when absent.
    pub rva: u32,
    /// Size in bytes, or 0 when absent.
    pub size: u32,
}

impl DataDirectory {
    /// True when both fields are zero, meaning the directory is not present.
    pub const fn is_empty(self) -> bool {
        self.rva == 0 && self.size == 0
    }
}

/// One entry of the PE section table.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Section {
    /// The raw 8-byte section name, NUL-padded.
    pub name_bytes: [u8; 8],
    /// `VirtualSize`: the size of the section once mapped.
    pub virtual_size: u32,
    /// `VirtualAddress`: the RVA of the mapped section.
    pub virtual_address: u32,
    /// `SizeOfRawData`: the size of the section in the file.
    pub size_of_raw_data: u32,
    /// `PointerToRawData`: the file offset of the section.
    pub pointer_to_raw_data: u32,
    /// `Characteristics`.
    pub characteristics: u32,
}

impl Section {
    /// The section name as UTF-8 with trailing NULs removed, or `None` when it
    /// is not valid UTF-8.
    pub fn name(&self) -> Option<&str> {
        let end = self.name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&self.name_bytes[..end]).ok()
    }

    /// The number of mapped bytes, which is `VirtualSize` when it is non-zero
    /// and `SizeOfRawData` otherwise (some linkers leave `VirtualSize` at 0).
    pub const fn mapped_size(&self) -> u32 {
        if self.virtual_size == 0 { self.size_of_raw_data } else { self.virtual_size }
    }

    /// True when `rva` falls inside the mapped range of this section.
    pub const fn contains_rva(&self, rva: u32) -> bool {
        let end = self.virtual_address.saturating_add(self.mapped_size());
        rva >= self.virtual_address && rva < end
    }
}

/// Flags from the CLI header `Flags` field (II.25.3.3.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct CliFlags(pub u32);

macro_rules! cli_flag {
    ($(#[$attr:meta])* $name:ident, $bit:literal) => {
        $(#[$attr])*
        pub const fn $name(self) -> bool {
            self.0 & $bit != 0
        }
    };
}

impl CliFlags {
    cli_flag!(
        /// `COMIMAGE_FLAGS_ILONLY`: the image contains no native code.
        il_only,
        0x0000_0001
    );
    cli_flag!(
        /// `COMIMAGE_FLAGS_32BITREQUIRED`: the image must run as 32-bit.
        requires_32bit,
        0x0000_0002
    );
    cli_flag!(
        /// `COMIMAGE_FLAGS_IL_LIBRARY`.
        il_library,
        0x0000_0004
    );
    cli_flag!(
        /// `COMIMAGE_FLAGS_STRONGNAMESIGNED`.
        strong_name_signed,
        0x0000_0008
    );
    cli_flag!(
        /// `COMIMAGE_FLAGS_NATIVE_ENTRYPOINT`: `EntryPointToken` holds an RVA.
        native_entry_point,
        0x0000_0010
    );
    cli_flag!(
        /// `COMIMAGE_FLAGS_TRACKDEBUGDATA`.
        track_debug_data,
        0x0001_0000
    );
    cli_flag!(
        /// `COMIMAGE_FLAGS_32BITPREFERRED`.
        prefers_32bit,
        0x0002_0000
    );

    /// The raw flags value.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// The managed entry point declared by the CLI header.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EntryPoint {
    /// No entry point.
    #[default]
    None,
    /// A `MethodDef` or `File` token.
    Token(Token),
    /// An RVA, when `COMIMAGE_FLAGS_NATIVE_ENTRYPOINT` is set.
    Rva(u32),
}

/// The CLI header, `IMAGE_COR20_HEADER` (II.25.3.3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CliHeader {
    /// `cb`: the declared size of this header, normally 72.
    pub size: u32,
    /// `MajorRuntimeVersion`.
    pub major_runtime_version: u16,
    /// `MinorRuntimeVersion`.
    pub minor_runtime_version: u16,
    /// The metadata root directory.
    pub metadata: DataDirectory,
    /// `Flags`.
    pub flags: CliFlags,
    /// The managed entry point.
    pub entry_point: EntryPoint,
    /// The managed resources directory; not decoded by this crate.
    pub resources: DataDirectory,
    /// The strong-name signature blob; not verified by this crate.
    pub strong_name_signature: DataDirectory,
    /// `CodeManagerTable`, reserved and always zero in practice.
    pub code_manager_table: DataDirectory,
    /// The vtable fixup table; not decoded by this crate.
    pub vtable_fixups: DataDirectory,
    /// `ExportAddressTableJumps`.
    pub export_address_table_jumps: DataDirectory,
    /// `ManagedNativeHeader`, where a ReadyToRun header lives; range only.
    pub managed_native_header: DataDirectory,
}

/// A parsed managed PE image, borrowing the bytes it was parsed from.
#[derive(Clone, Debug)]
pub struct PeImage<'a> {
    bytes: &'a [u8],
    strictness: Strictness,
    diagnostics: Vec<Diagnostic>,
    machine: u16,
    characteristics: u16,
    is_pe32_plus: bool,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    size_of_image: u32,
    size_of_headers: u32,
    subsystem: u16,
    dll_characteristics: u16,
    entry_point_rva: u32,
    data_directories: Vec<DataDirectory>,
    sections: Vec<Section>,
}

impl<'a> PeImage<'a> {
    /// Parses a PE image in [`Strictness::Permissive`] mode.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        Self::parse_with(bytes, Strictness::Permissive)
    }

    /// Parses a PE image with an explicit strictness.
    pub fn parse_with(bytes: &'a [u8], strictness: Strictness) -> Result<Self> {
        let mut diagnostics = Vec::new();
        let mut r = Reader::new(bytes, 0, CTX);

        if r.take(2)? != b"MZ" {
            return Err(Error::new(ErrorKind::Malformed, 0, CTX));
        }
        r.seek(0x3C)?;
        let pe_offset = r.u32()? as usize;
        r.seek(pe_offset)?;
        if r.take(4)? != b"PE\0\0" {
            return Err(Error::new(ErrorKind::Malformed, pe_offset, CTX));
        }

        // COFF header (20 bytes).
        let machine = r.u16()?;
        let number_of_sections = r.u16()?;
        let _time_date_stamp = r.u32()?;
        let _pointer_to_symbol_table = r.u32()?;
        let _number_of_symbols = r.u32()?;
        let size_of_optional_header = r.u16()? as usize;
        let characteristics = r.u16()?;

        let optional_start = r.position();
        let magic = r.u16()?;
        let is_pe32_plus = match magic {
            0x010B => false,
            0x020B => true,
            _ => return Err(Error::new(ErrorKind::Unsupported, optional_start, CTX)),
        };

        r.seek(optional_start + 16)?;
        let entry_point_rva = r.u32()?;

        let (image_base, dir_count_offset) = if is_pe32_plus {
            r.seek(optional_start + 24)?;
            (r.u64()?, optional_start + 108)
        } else {
            r.seek(optional_start + 28)?;
            (u64::from(r.u32()?), optional_start + 92)
        };
        let section_alignment = r.u32()?;
        let file_alignment = r.u32()?;
        r.seek(optional_start + 56)?;
        let size_of_image = r.u32()?;
        let size_of_headers = r.u32()?;
        r.seek(optional_start + 68)?;
        let subsystem = r.u16()?;
        let dll_characteristics = r.u16()?;

        r.seek(dir_count_offset)?;
        let declared_dirs = r.u32()? as usize;
        // 16 is the architectural maximum; a larger count is a lie about a
        // fixed-size array, so clamp it before allocating.
        let dir_count = declared_dirs.min(16).min(r.remaining() / 8);
        let mut data_directories = Vec::with_capacity(dir_count);
        for _ in 0..dir_count {
            let rva = r.u32()?;
            let size = r.u32()?;
            data_directories.push(DataDirectory { rva, size });
        }

        // Section headers follow the optional header, whose declared size is
        // authoritative even when it disagrees with the magic.
        let sections_offset = optional_start
            .checked_add(size_of_optional_header)
            .ok_or_else(|| Error::new(ErrorKind::Malformed, optional_start, CTX))?;
        r.seek(sections_offset)?;
        let section_count = (number_of_sections as usize).min(r.remaining() / 40);
        if strictness.is_strict() && section_count != number_of_sections as usize {
            return Err(Error::new(ErrorKind::Truncated, sections_offset, CTX));
        }
        let mut sections = Vec::with_capacity(section_count);
        for _ in 0..section_count {
            let at = r.absolute();
            let mut name_bytes = [0u8; 8];
            name_bytes.copy_from_slice(r.take(8)?);
            let virtual_size = r.u32()?;
            let virtual_address = r.u32()?;
            let size_of_raw_data = r.u32()?;
            let pointer_to_raw_data = r.u32()?;
            let _pointer_to_relocations = r.u32()?;
            let _pointer_to_linenumbers = r.u32()?;
            let _number_of_relocations = r.u16()?;
            let _number_of_linenumbers = r.u16()?;
            let characteristics = r.u32()?;

            let raw_end = (pointer_to_raw_data as u64) + (size_of_raw_data as u64);
            let mut size_of_raw_data = size_of_raw_data;
            if raw_end > bytes.len() as u64 {
                if strictness.is_strict() {
                    return Err(Error::new(ErrorKind::Truncated, at, CTX));
                }
                diagnostics.push(Diagnostic::new(DiagnosticCode::SectionRangeClamped, at, raw_end));
                size_of_raw_data = (bytes.len() as u64)
                    .saturating_sub(pointer_to_raw_data as u64)
                    .min(u32::MAX as u64) as u32;
            }

            sections.push(Section {
                name_bytes,
                virtual_size,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                characteristics,
            });
        }

        Ok(PeImage {
            bytes,
            strictness,
            diagnostics,
            machine,
            characteristics,
            is_pe32_plus,
            image_base,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            subsystem,
            dll_characteristics,
            entry_point_rva,
            data_directories,
            sections,
        })
    }

    /// The bytes this image was parsed from.
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The strictness this image was parsed with.
    pub const fn strictness(&self) -> Strictness {
        self.strictness
    }

    /// Deviations tolerated while parsing the container.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// True when the optional header magic was `PE32+` (`0x20B`).
    pub const fn is_pe32_plus(&self) -> bool {
        self.is_pe32_plus
    }

    /// The COFF `Machine` field.
    pub const fn machine(&self) -> u16 {
        self.machine
    }

    /// The COFF `Characteristics` field.
    pub const fn characteristics(&self) -> u16 {
        self.characteristics
    }

    /// `ImageBase`, widened to 64 bits for PE32.
    pub const fn image_base(&self) -> u64 {
        self.image_base
    }

    /// `SectionAlignment`.
    pub const fn section_alignment(&self) -> u32 {
        self.section_alignment
    }

    /// `FileAlignment`.
    pub const fn file_alignment(&self) -> u32 {
        self.file_alignment
    }

    /// `SizeOfImage`.
    pub const fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    /// `SizeOfHeaders`.
    pub const fn size_of_headers(&self) -> u32 {
        self.size_of_headers
    }

    /// `Subsystem`.
    pub const fn subsystem(&self) -> u16 {
        self.subsystem
    }

    /// `DllCharacteristics`.
    pub const fn dll_characteristics(&self) -> u16 {
        self.dll_characteristics
    }

    /// `AddressOfEntryPoint`, the native entry stub RVA.
    pub const fn entry_point_rva(&self) -> u32 {
        self.entry_point_rva
    }

    /// The section table, in file order.
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// The PE data directories, in index order.
    pub fn data_directories(&self) -> &[DataDirectory] {
        &self.data_directories
    }

    /// One data directory by index, or an empty directory when absent.
    pub fn data_directory(&self, index: usize) -> DataDirectory {
        self.data_directories.get(index).copied().unwrap_or_default()
    }

    /// Translates an RVA to a file offset.
    ///
    /// RVAs inside the mapped headers translate to themselves, matching how the
    /// loader maps the first `SizeOfHeaders` bytes at RVA 0.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            if section.contains_rva(rva) {
                let delta = rva - section.virtual_address;
                if delta >= section.size_of_raw_data {
                    // Mapped but not backed by file bytes (e.g. `.bss`).
                    return None;
                }
                let offset = (section.pointer_to_raw_data as usize).checked_add(delta as usize)?;
                return (offset <= self.bytes.len()).then_some(offset);
            }
        }
        if rva < self.size_of_headers && (rva as usize) < self.bytes.len() {
            return Some(rva as usize);
        }
        None
    }

    /// Returns `len` bytes starting at `rva`, failing if any of them fall
    /// outside the file-backed part of the containing section.
    pub fn rva_slice(&self, rva: u32, len: usize) -> Result<&'a [u8]> {
        let offset = self.rva_to_offset(rva).ok_or(Error {
            kind: ErrorKind::OutOfRange,
            offset: None,
            context: "RVA",
        })?;
        let available = self.rva_available(rva).unwrap_or(0);
        if len > available {
            return Err(Error::new(ErrorKind::OutOfRange, offset, "RVA"));
        }
        let end =
            offset.checked_add(len).ok_or(Error::new(ErrorKind::OutOfRange, offset, "RVA"))?;
        self.bytes.get(offset..end).ok_or(Error::new(ErrorKind::Truncated, offset, "RVA"))
    }

    /// The number of file-backed bytes available from `rva` to the end of its
    /// section, or `None` when the RVA is not mapped.
    pub fn rva_available(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            if section.contains_rva(rva) {
                let delta = rva - section.virtual_address;
                if delta >= section.size_of_raw_data {
                    return None;
                }
                let in_section = (section.size_of_raw_data - delta) as usize;
                let file_start =
                    (section.pointer_to_raw_data as usize).checked_add(delta as usize)?;
                let in_file = self.bytes.len().checked_sub(file_start)?;
                return Some(in_section.min(in_file));
            }
        }
        if rva < self.size_of_headers {
            let start = rva as usize;
            let limit = (self.size_of_headers as usize).min(self.bytes.len());
            return limit.checked_sub(start);
        }
        None
    }

    /// Returns every byte from `rva` to the end of its section.
    pub fn rva_rest(&self, rva: u32) -> Result<&'a [u8]> {
        let len = self.rva_available(rva).ok_or(Error {
            kind: ErrorKind::OutOfRange,
            offset: None,
            context: "RVA",
        })?;
        self.rva_slice(rva, len)
    }

    /// Parses the CLI header named by data directory 14 (II.25.3.3).
    pub fn cli_header(&self) -> Result<CliHeader> {
        let dir = self.data_directory(CLI_HEADER_DIRECTORY);
        if dir.is_empty() {
            return Err(Error::detached(ErrorKind::Malformed, "CLI header"));
        }
        let bytes = self.rva_slice(dir.rva, 72.min(self.rva_available(dir.rva).unwrap_or(0)))?;
        let base = self.rva_to_offset(dir.rva).unwrap_or(0);
        let mut r = Reader::new(bytes, base, "CLI header");

        let size = r.u32()?;
        let major_runtime_version = r.u16()?;
        let minor_runtime_version = r.u16()?;
        let metadata = read_dir(&mut r)?;
        let flags = CliFlags(r.u32()?);
        let entry_point_raw = r.u32()?;
        let resources = read_dir(&mut r)?;
        let strong_name_signature = read_dir(&mut r)?;
        let code_manager_table = read_dir(&mut r)?;
        let vtable_fixups = read_dir(&mut r)?;
        let export_address_table_jumps = read_dir(&mut r)?;
        let managed_native_header = read_dir(&mut r)?;

        if size != 72 && self.strictness.is_strict() {
            return Err(Error::new(ErrorKind::Malformed, base, "CLI header"));
        }

        let entry_point = if entry_point_raw == 0 {
            EntryPoint::None
        } else if flags.native_entry_point() {
            EntryPoint::Rva(entry_point_raw)
        } else {
            EntryPoint::Token(Token(entry_point_raw))
        };

        Ok(CliHeader {
            size,
            major_runtime_version,
            minor_runtime_version,
            metadata,
            flags,
            entry_point,
            resources,
            strong_name_signature,
            code_manager_table,
            vtable_fixups,
            export_address_table_jumps,
            managed_native_header,
        })
    }

    /// Diagnostics for the CLI header that `cli_header` cannot record because
    /// it takes `&self`; call this to collect them explicitly.
    pub fn cli_header_diagnostics(&self) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        if let Ok(header) = self.cli_header() {
            let base =
                self.rva_to_offset(self.data_directory(CLI_HEADER_DIRECTORY).rva).unwrap_or(0);
            if header.size != 72 {
                out.push(Diagnostic::new(
                    DiagnosticCode::CliHeaderSize,
                    base,
                    u64::from(header.size),
                ));
            }
            if header.flags.prefers_32bit() && !header.flags.requires_32bit() {
                out.push(Diagnostic::new(
                    DiagnosticCode::BitnessFlagsInconsistent,
                    base,
                    u64::from(header.flags.bits()),
                ));
            }
        }
        out
    }

    /// Parses the metadata root named by the CLI header.
    pub fn metadata(&self) -> Result<Metadata<'a>> {
        let header = self.cli_header()?;
        if header.metadata.is_empty() {
            return Err(Error::detached(ErrorKind::Malformed, "metadata directory"));
        }
        let available = self.rva_available(header.metadata.rva).ok_or(Error {
            kind: ErrorKind::OutOfRange,
            offset: None,
            context: "metadata directory",
        })?;
        let len = (header.metadata.size as usize).min(available);
        let bytes = self.rva_slice(header.metadata.rva, len)?;
        let base = self.rva_to_offset(header.metadata.rva).unwrap_or(0);
        Metadata::parse_at(bytes, base, self.strictness)
    }

    /// The `MethodDef` token of the managed entry point, if there is one.
    pub fn entry_point_token(&self) -> Option<Token> {
        match self.cli_header().ok()?.entry_point {
            EntryPoint::Token(t) if t.table() == Some(TableId::MethodDef) => Some(t),
            _ => None,
        }
    }
}

fn read_dir(r: &mut Reader<'_>) -> Result<DataDirectory> {
    let rva = r.u32()?;
    let size = r.u32()?;
    Ok(DataDirectory { rva, size })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(va: u32, vsize: u32, ptr: u32, rsize: u32) -> Section {
        Section {
            name_bytes: *b".text\0\0\0",
            virtual_size: vsize,
            virtual_address: va,
            size_of_raw_data: rsize,
            pointer_to_raw_data: ptr,
            characteristics: 0,
        }
    }

    fn image(bytes: &[u8], sections: Vec<Section>) -> PeImage<'_> {
        PeImage {
            bytes,
            strictness: Strictness::Permissive,
            diagnostics: Vec::new(),
            machine: 0x14C,
            characteristics: 0,
            is_pe32_plus: false,
            image_base: 0x400000,
            section_alignment: 0x2000,
            file_alignment: 0x200,
            size_of_image: 0x4000,
            size_of_headers: 0x200,
            subsystem: 3,
            dll_characteristics: 0,
            entry_point_rva: 0,
            data_directories: Vec::new(),
            sections,
        }
    }

    #[test]
    fn rva_translation_respects_raw_size() {
        let bytes = [0u8; 0x600];
        let img = image(&bytes, alloc::vec![section(0x2000, 0x400, 0x200, 0x200)]);
        assert_eq!(img.rva_to_offset(0x2000), Some(0x200));
        assert_eq!(img.rva_to_offset(0x21FF), Some(0x3FF));
        // Mapped by VirtualSize but not backed by raw bytes.
        assert_eq!(img.rva_to_offset(0x2200), None);
        // Outside every section.
        assert_eq!(img.rva_to_offset(0x9000), None);
        // Inside the headers.
        assert_eq!(img.rva_to_offset(0x80), Some(0x80));
    }

    #[test]
    fn rva_slice_is_bounded_by_the_section() {
        let bytes = [0u8; 0x600];
        let img = image(&bytes, alloc::vec![section(0x2000, 0x400, 0x200, 0x200)]);
        assert_eq!(img.rva_available(0x2100), Some(0x100));
        assert!(img.rva_slice(0x2100, 0x100).is_ok());
        assert_eq!(img.rva_slice(0x2100, 0x101).unwrap_err().kind, ErrorKind::OutOfRange);
    }

    #[test]
    fn zero_virtual_size_falls_back_to_raw_size() {
        let bytes = [0u8; 0x600];
        let img = image(&bytes, alloc::vec![section(0x2000, 0, 0x200, 0x200)]);
        assert_eq!(img.rva_to_offset(0x2000), Some(0x200));
        assert_eq!(img.rva_to_offset(0x2200), None);
    }

    #[test]
    fn garbage_is_rejected_without_panicking() {
        for len in 0..80usize {
            let bytes = alloc::vec![0x4Du8; len];
            let _ = PeImage::parse(&bytes);
        }
        assert!(PeImage::parse(b"not a pe").is_err());
        assert!(PeImage::parse(&[]).is_err());
    }

    #[test]
    fn cli_flags_decode() {
        let f = CliFlags(0x0002_0001);
        assert!(f.il_only());
        assert!(f.prefers_32bit());
        assert!(!f.requires_32bit());
        assert!(!f.native_entry_point());
    }
}
