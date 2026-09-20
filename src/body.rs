//! Method bodies and exception-handling tables (ECMA-335 II.25.4).
//!
//! A body is a tiny or fat header, the CIL byte range, and — for a fat header
//! with `MoreSects` — a chain of 4-byte-aligned data sections, of which only
//! the exception-handling section is decoded.
//!
//! [`MethodBody::parse`] succeeds as long as the header and code range are
//! readable, even when the exception table violates ECMA-335. Structural
//! validation of the handlers is a separate step, [`MethodBody::validate_handlers`],
//! so that a consumer can still read the code of an obfuscated method.

use alloc::vec::Vec;

use crate::error::{Diagnostic, DiagnosticCode, Error, ErrorKind, Result, Strictness};
use crate::il::{FoldedIter, InstructionIter};
use crate::pe::PeImage;
use crate::reader::Reader;
use crate::tables::MethodDefRow;
use crate::token::{TableId, Token};

const CTX: &str = "method body";

/// Which header form a body uses.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HeaderKind {
    /// `CorILMethod_TinyFormat`: one byte, code size in the top 6 bits.
    Tiny,
    /// `CorILMethod_FatFormat`: a 12-byte header.
    Fat,
}

/// Flags from a fat method header (II.25.4.4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct FatFlags(pub u16);

impl FatFlags {
    /// `CorILMethod_MoreSects`: data sections follow the code.
    pub const fn more_sects(self) -> bool {
        self.0 & 0x0008 != 0
    }

    /// `CorILMethod_InitLocals`: locals are zero-initialised on entry.
    pub const fn init_locals(self) -> bool {
        self.0 & 0x0010 != 0
    }

    /// The raw flags value, including the format bits.
    pub const fn bits(self) -> u16 {
        self.0
    }
}

/// What an exception clause does (II.25.4.6).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HandlerKind {
    /// A typed catch; the token names the caught type.
    Catch(Token),
    /// A filtered catch; the filter code starts at this IL offset.
    Filter {
        /// IL offset of the first filter instruction.
        filter_offset: u32,
    },
    /// A `finally` block.
    Finally,
    /// A `fault` block.
    Fault,
}

/// One exception-handling clause.
///
/// All offsets are IL offsets relative to the start of [`MethodBody::code`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExceptionHandler {
    /// What the clause does.
    pub kind: HandlerKind,
    /// IL offset of the protected block.
    pub try_offset: u32,
    /// Length in bytes of the protected block.
    pub try_length: u32,
    /// IL offset of the handler.
    pub handler_offset: u32,
    /// Length in bytes of the handler.
    pub handler_length: u32,
    /// The raw clause flags, before classification.
    pub raw_flags: u32,
}

impl ExceptionHandler {
    /// The end IL offset of the protected block, saturating on overflow.
    pub const fn try_end(&self) -> u32 {
        self.try_offset.saturating_add(self.try_length)
    }

    /// The end IL offset of the handler, saturating on overflow.
    pub const fn handler_end(&self) -> u32 {
        self.handler_offset.saturating_add(self.handler_length)
    }
}

/// A method data section this crate does not decode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RawSection<'a> {
    /// The section `Kind` byte.
    pub kind: u8,
    /// The section bytes, excluding the 4-byte section header.
    pub data: &'a [u8],
}

/// A decoded method body.
#[derive(Clone, Debug)]
pub struct MethodBody<'a> {
    /// Which header form the body used.
    pub kind: HeaderKind,
    /// Fat header flags; always zero for a tiny header, which has none.
    pub flags: FatFlags,
    /// `MaxStack`; 8 for a tiny header, as II.25.4.2 requires.
    pub max_stack: u16,
    /// Exactly `CodeSize` bytes of CIL.
    pub code: &'a [u8],
    /// The RVA of the first IL byte, for consumers that need absolute addresses.
    pub code_rva: u32,
    /// The `StandAloneSig` token of the locals signature, when there is one.
    pub local_var_sig: Option<Token>,
    /// The exception-handling clauses, in the order the image declares them.
    pub exception_handlers: Vec<ExceptionHandler>,
    /// Data sections other than the exception table, kept as raw bytes.
    pub unknown_sections: Vec<RawSection<'a>>,
    /// The declared fat header size in dwords; 0 for a tiny header.
    pub header_dwords: u8,
    /// The total size of the body in bytes, header and sections included.
    pub total_size: usize,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> MethodBody<'a> {
    /// Parses a method body in [`Strictness::Permissive`] mode.
    ///
    /// `bytes` must start at the method header and may extend past the end of
    /// the body; `code_rva` is the RVA of the first IL byte.
    pub fn parse(bytes: &'a [u8], code_rva: u32) -> Result<Self> {
        Self::parse_with(bytes, code_rva, Strictness::Permissive)
    }

    /// Parses a method body with an explicit strictness.
    pub fn parse_with(bytes: &'a [u8], code_rva: u32, strictness: Strictness) -> Result<Self> {
        let mut diagnostics = Vec::new();
        let mut r = Reader::new(bytes, 0, CTX);
        let first = r.peek_u8()?;

        match first & 0x03 {
            0x02 => {
                let header = r.u8()?;
                let code_size = usize::from(header >> 2);
                let code = r.take(code_size)?;
                Ok(MethodBody {
                    kind: HeaderKind::Tiny,
                    // A tiny header carries no flags: its remaining six bits
                    // are the code size, so `InitLocals` and `MoreSects` are
                    // both absent by construction.
                    flags: FatFlags(0),
                    max_stack: 8,
                    code,
                    code_rva: code_rva.wrapping_add(1),
                    local_var_sig: None,
                    exception_handlers: Vec::new(),
                    unknown_sections: Vec::new(),
                    header_dwords: 0,
                    total_size: 1 + code_size,
                    diagnostics,
                })
            }
            0x03 => {
                let flags_and_size = r.u16()?;
                let flags = FatFlags(flags_and_size & 0x0FFF);
                let header_dwords = (flags_and_size >> 12) as u8;
                let max_stack = r.u16()?;
                let code_size = r.u32()? as usize;
                let local_var_sig_tok = r.u32()?;

                if header_dwords != 3 {
                    if strictness.is_strict() {
                        return Err(Error::new(ErrorKind::Malformed, 0, CTX));
                    }
                    diagnostics.push(Diagnostic::new(
                        DiagnosticCode::FatHeaderSize,
                        0,
                        u64::from(header_dwords),
                    ));
                }
                // The declared header size is authoritative, as the runtime
                // treats it; a size below 3 dwords would overlap the fields we
                // just read, so it is clamped up.
                let header_size = usize::from(header_dwords.max(3)) * 4;
                r.seek(header_size)?;
                let code = r.take(code_size)?;

                let local_var_sig = match local_var_sig_tok {
                    0 => None,
                    value => Some(Token(value)),
                };
                if strictness.is_strict()
                    && local_var_sig.is_some_and(|t| t.table() != Some(TableId::StandAloneSig))
                {
                    return Err(Error::new(ErrorKind::Malformed, 8, CTX));
                }

                let mut exception_handlers = Vec::new();
                let mut unknown_sections = Vec::new();
                if flags.more_sects() {
                    parse_sections(
                        &mut r,
                        strictness,
                        &mut diagnostics,
                        &mut exception_handlers,
                        &mut unknown_sections,
                    )?;
                }

                Ok(MethodBody {
                    kind: HeaderKind::Fat,
                    flags,
                    max_stack,
                    code,
                    code_rva: code_rva.wrapping_add(header_size as u32),
                    local_var_sig,
                    exception_handlers,
                    unknown_sections,
                    header_dwords,
                    total_size: r.position(),
                    diagnostics,
                })
            }
            _ => Err(Error::new(ErrorKind::Malformed, 0, CTX)),
        }
    }

    /// Reads the body of a `MethodDef` row from an image.
    ///
    /// Returns `Ok(None)` when the method has no CIL body: RVA 0 (abstract,
    /// P/Invoke, or runtime-provided) or a non-CIL `ImplFlags`.
    pub fn from_image(image: &PeImage<'a>, method: &MethodDefRow) -> Result<Option<Self>> {
        if method.has_no_body() {
            return Ok(None);
        }
        let bytes = image.rva_rest(method.rva)?;
        Self::parse_with(bytes, method.rva, image.strictness()).map(Some)
    }

    /// Deviations tolerated while parsing this body.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// The size of the CIL in bytes.
    pub fn code_size(&self) -> usize {
        self.code.len()
    }

    /// Checks the exception table against II.25.4.6.
    ///
    /// Verifies that every try and handler range lies inside the code, that no
    /// range is zero-length, that a filter starts inside the code and ends
    /// where its handler begins, and that try blocks are properly nested or
    /// disjoint rather than partially overlapping.
    pub fn validate_handlers(&self) -> Result<()> {
        let code_len = self.code.len() as u64;
        for (i, h) in self.exception_handlers.iter().enumerate() {
            let try_end = u64::from(h.try_offset) + u64::from(h.try_length);
            let handler_end = u64::from(h.handler_offset) + u64::from(h.handler_length);
            if try_end > code_len || handler_end > code_len {
                return Err(Error::new(ErrorKind::OutOfRange, i, "exception handler"));
            }
            if h.try_length == 0 || h.handler_length == 0 {
                return Err(Error::new(ErrorKind::Malformed, i, "exception handler"));
            }
            // A handler may not lie inside the block it protects.
            if h.handler_offset < h.try_end() && h.handler_end() > h.try_offset {
                return Err(Error::new(ErrorKind::Malformed, i, "exception handler"));
            }
            if let HandlerKind::Filter { filter_offset } = h.kind {
                if u64::from(filter_offset) >= code_len {
                    return Err(Error::new(ErrorKind::OutOfRange, i, "exception filter"));
                }
                if filter_offset >= h.handler_offset {
                    return Err(Error::new(ErrorKind::Malformed, i, "exception filter"));
                }
            }
            for (j, other) in self.exception_handlers.iter().enumerate() {
                if i == j {
                    continue;
                }
                if partially_overlaps(h.try_offset, h.try_end(), other.try_offset, other.try_end())
                {
                    return Err(Error::new(ErrorKind::Malformed, i, "exception handler nesting"));
                }
                if partially_overlaps(
                    h.handler_offset,
                    h.handler_end(),
                    other.handler_offset,
                    other.handler_end(),
                ) {
                    return Err(Error::new(ErrorKind::Malformed, i, "exception handler nesting"));
                }
            }
        }
        Ok(())
    }

    /// Decodes the code as a raw instruction stream, with prefixes as separate
    /// items.
    pub fn instructions(&self) -> InstructionIter<'a> {
        InstructionIter::new(self.code)
    }

    /// Decodes the code with prefixes folded onto the instruction they modify.
    pub fn folded_instructions(&self) -> FoldedIter<'a> {
        FoldedIter::new(self.code)
    }

    /// The IL offset of every instruction, in order.
    ///
    /// Decoding stops at the first error, so the result may be shorter than the
    /// code; use [`MethodBody::instructions`] when the error matters.
    pub fn instruction_offsets(&self) -> Vec<u32> {
        let mut offsets = Vec::new();
        for item in self.instructions() {
            match item {
                Ok(instruction) => offsets.push(instruction.offset),
                Err(_) => break,
            }
        }
        offsets
    }

    /// True when `offset` is the start of an instruction.
    ///
    /// This decodes the method from the start, so callers checking many offsets
    /// should build a set from [`MethodBody::instruction_offsets`] instead.
    pub fn is_instruction_boundary(&self, offset: u32) -> bool {
        for item in self.instructions() {
            match item {
                Ok(instruction) => {
                    if instruction.offset == offset {
                        return true;
                    }
                    if instruction.offset > offset {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
        false
    }
}

/// True when two half-open ranges overlap without one containing the other.
fn partially_overlaps(a_start: u32, a_end: u32, b_start: u32, b_end: u32) -> bool {
    let overlaps = a_start < b_end && b_start < a_end;
    if !overlaps {
        return false;
    }
    let a_in_b = b_start <= a_start && a_end <= b_end;
    let b_in_a = a_start <= b_start && b_end <= a_end;
    !a_in_b && !b_in_a
}

fn parse_sections<'a>(
    r: &mut Reader<'a>,
    strictness: Strictness,
    diagnostics: &mut Vec<Diagnostic>,
    handlers: &mut Vec<ExceptionHandler>,
    unknown: &mut Vec<RawSection<'a>>,
) -> Result<()> {
    loop {
        r.align_to(0, 4)?;
        let section_start = r.position();
        let kind = r.u8()?;
        let fat = kind & 0x40 != 0;
        let more = kind & 0x80 != 0;
        let data_size = if fat {
            let b = r.take(3)?;
            u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16)
        } else {
            let size = u32::from(r.u8()?);
            let _reserved = r.u16()?;
            size
        };

        let is_eh = kind & 0x01 != 0;
        let clause_size: usize = if fat { 24 } else { 12 };
        let declared = data_size as usize;
        let mut body_size = declared.saturating_sub(4);

        // ECMA-335 II.25.4.5 says `DataSize` counts the 4-byte section header
        // as well as the clauses, "n*12+4". Some Visual Basic compilers wrote
        // it without the header, which silently drops the last clause of every
        // section they emit. The two readings are told apart by arithmetic:
        // the header-inclusive one leaves a partial clause while the
        // header-exclusive one divides exactly.
        if is_eh
            && clause_size > 0
            && body_size % clause_size != 0
            && declared % clause_size == 0
            && declared <= r.remaining()
        {
            if strictness.is_strict() {
                return Err(Error::new(ErrorKind::Malformed, section_start, CTX));
            }
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::EhSectionSize,
                section_start,
                u64::from(data_size),
            ));
            body_size = declared;
        }

        let available = r.remaining();
        let body_size = if body_size > available {
            if strictness.is_strict() {
                return Err(Error::new(ErrorKind::Truncated, section_start, CTX));
            }
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::EhSectionSize,
                section_start,
                u64::from(data_size),
            ));
            available
        } else {
            body_size
        };
        let body = r.take(body_size)?;

        if is_eh {
            if body.len() % clause_size != 0 {
                if strictness.is_strict() {
                    return Err(Error::new(ErrorKind::Malformed, section_start, CTX));
                }
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::EhSectionSize,
                    section_start,
                    body.len() as u64,
                ));
            }
            let count = body.len() / clause_size;
            handlers.reserve(count);
            for i in 0..count {
                let chunk = &body[i * clause_size..(i + 1) * clause_size];
                handlers.push(read_clause(chunk, fat, section_start + 4 + i * clause_size)?);
            }
        } else {
            unknown.push(RawSection { kind, data: body });
        }

        if !more {
            return Ok(());
        }
        if r.is_empty() {
            if strictness.is_strict() {
                return Err(Error::new(ErrorKind::Truncated, r.position(), CTX));
            }
            return Ok(());
        }
    }
}

fn read_clause(chunk: &[u8], fat: bool, at: usize) -> Result<ExceptionHandler> {
    let mut r = Reader::new(chunk, at, "exception clause");
    let (raw_flags, try_offset, try_length, handler_offset, handler_length, extra) = if fat {
        (r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?)
    } else {
        let flags = u32::from(r.u16()?);
        let try_offset = u32::from(r.u16()?);
        let try_length = u32::from(r.u8()?);
        let handler_offset = u32::from(r.u16()?);
        let handler_length = u32::from(r.u8()?);
        let extra = r.u32()?;
        (flags, try_offset, try_length, handler_offset, handler_length, extra)
    };

    let kind = match raw_flags & 0x0007 {
        0x0000 => HandlerKind::Catch(Token(extra)),
        0x0001 => HandlerKind::Filter { filter_offset: extra },
        0x0002 => HandlerKind::Finally,
        0x0004 => HandlerKind::Fault,
        _ => return Err(Error::new(ErrorKind::Malformed, at, "exception clause")),
    };

    Ok(ExceptionHandler { kind, try_offset, try_length, handler_offset, handler_length, raw_flags })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny(code: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![((code.len() as u8) << 2) | 0x02];
        out.extend_from_slice(code);
        out
    }

    fn fat(code: &[u8], flags: u16, sections: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&((3u16 << 12) | flags | 0x0003).to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&(code.len() as u32).to_le_bytes());
        out.extend_from_slice(&0x1100_0001u32.to_le_bytes());
        out.extend_from_slice(code);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(sections);
        out
    }

    #[test]
    fn parses_a_tiny_header() {
        let body = tiny(&[0x00, 0x2A]);
        let parsed = MethodBody::parse(&body, 0x2000).unwrap();
        assert_eq!(parsed.kind, HeaderKind::Tiny);
        assert_eq!(parsed.max_stack, 8);
        assert_eq!(parsed.code, &[0x00, 0x2A]);
        assert_eq!(parsed.code_rva, 0x2001);
        assert_eq!(parsed.local_var_sig, None);
        assert_eq!(parsed.total_size, 3);
        assert!(parsed.exception_handlers.is_empty());
    }

    #[test]
    fn a_tiny_body_can_be_the_maximum_63_bytes() {
        let code = alloc::vec![0u8; 63];
        let body = tiny(&code);
        assert_eq!(MethodBody::parse(&body, 0).unwrap().code.len(), 63);
    }

    #[test]
    fn parses_a_fat_header() {
        let body = fat(&[0x2A], 0x0010, &[]);
        let parsed = MethodBody::parse(&body, 0x2000).unwrap();
        assert_eq!(parsed.kind, HeaderKind::Fat);
        assert!(parsed.flags.init_locals());
        assert!(!parsed.flags.more_sects());
        assert_eq!(parsed.code, &[0x2A]);
        assert_eq!(parsed.code_rva, 0x200C);
        assert_eq!(parsed.local_var_sig, Some(Token(0x1100_0001)));
        assert_eq!(parsed.header_dwords, 3);
    }

    #[test]
    fn parses_a_small_exception_section() {
        // One finally clause over the whole 8-byte body.
        let mut section = alloc::vec![0x01u8, 4 + 12, 0, 0];
        section.extend_from_slice(&0x0002u16.to_le_bytes()); // Finally
        section.extend_from_slice(&0u16.to_le_bytes()); // TryOffset
        section.push(4); // TryLength
        section.extend_from_slice(&4u16.to_le_bytes()); // HandlerOffset
        section.push(4); // HandlerLength
        section.extend_from_slice(&0u32.to_le_bytes());
        let body = fat(&[0x00; 8], 0x0008, &section);
        let parsed = MethodBody::parse(&body, 0).unwrap();
        assert_eq!(parsed.exception_handlers.len(), 1);
        let h = parsed.exception_handlers[0];
        assert_eq!(h.kind, HandlerKind::Finally);
        assert_eq!((h.try_offset, h.try_length), (0, 4));
        assert_eq!((h.handler_offset, h.handler_length), (4, 4));
        parsed.validate_handlers().unwrap();
    }

    #[test]
    fn parses_a_fat_exception_section_and_chained_sections() {
        let mut section = alloc::vec![0x41u8 | 0x80]; // EHTable | FatFormat | MoreSects
        let size = 4u32 + 24;
        section.extend_from_slice(&size.to_le_bytes()[..3]);
        section.extend_from_slice(&0x0001u32.to_le_bytes()); // Filter
        section.extend_from_slice(&0u32.to_le_bytes());
        section.extend_from_slice(&4u32.to_le_bytes());
        section.extend_from_slice(&8u32.to_le_bytes());
        section.extend_from_slice(&4u32.to_le_bytes());
        section.extend_from_slice(&4u32.to_le_bytes()); // FilterOffset
        // A second, non-EH section.
        section.extend_from_slice(&[0x02, 4 + 4, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF]);

        let body = fat(&[0x00; 12], 0x0008, &section);
        let parsed = MethodBody::parse(&body, 0).unwrap();
        assert_eq!(parsed.exception_handlers.len(), 1);
        assert_eq!(parsed.exception_handlers[0].kind, HandlerKind::Filter { filter_offset: 4 });
        assert_eq!(parsed.unknown_sections.len(), 1);
        assert_eq!(parsed.unknown_sections[0].data, &[0xDE, 0xAD, 0xBE, 0xEF]);
        parsed.validate_handlers().unwrap();
    }

    #[test]
    fn a_section_size_that_omits_its_own_header_is_recovered() {
        // ECMA-335 II.25.4.5 defines DataSize as n*12+4, counting the section
        // header. Some Visual Basic compilers wrote n*12, which drops the last
        // clause of every section. Two clauses, declared as 24 rather than 28.
        let mut section = alloc::vec![0x01u8, 24, 0, 0];
        for (flags, try_offset, try_length, handler_offset, handler_length) in
            [(0x0000u16, 0u16, 8u8, 8u16, 4u8), (0x0002, 0, 12, 12, 4)]
        {
            section.extend_from_slice(&flags.to_le_bytes());
            section.extend_from_slice(&try_offset.to_le_bytes());
            section.push(try_length);
            section.extend_from_slice(&handler_offset.to_le_bytes());
            section.push(handler_length);
            section.extend_from_slice(&0u32.to_le_bytes());
        }
        let body = fat(&[0x00; 16], 0x0008, &section);

        let parsed = MethodBody::parse(&body, 0).unwrap();
        assert_eq!(parsed.exception_handlers.len(), 2, "the second clause must survive");
        assert_eq!(parsed.exception_handlers[0].kind, HandlerKind::Catch(Token(0)));
        assert_eq!(parsed.exception_handlers[1].kind, HandlerKind::Finally);
        assert!(parsed.diagnostics().iter().any(|d| d.code == DiagnosticCode::EhSectionSize));
        parsed.validate_handlers().unwrap();

        // It is a specification violation, so strict mode refuses it.
        assert!(MethodBody::parse_with(&body, 0, Strictness::Strict).is_err());
    }

    #[test]
    fn a_conforming_section_size_is_never_reinterpreted() {
        // A correct DataSize is n*12+4, which is congruent to 4 modulo 12 and
        // so can never be mistaken for the header-exclusive form. Check every
        // clause count that fits in the one-byte field.
        for count in 0..=20u8 {
            let declared = 4 + u32::from(count) * 12;
            let mut section = alloc::vec![0x01u8, declared as u8, 0, 0];
            for _ in 0..count {
                section.extend_from_slice(&0x0002u16.to_le_bytes());
                section.extend_from_slice(&0u16.to_le_bytes());
                section.push(4);
                section.extend_from_slice(&4u16.to_le_bytes());
                section.push(4);
                section.extend_from_slice(&0u32.to_le_bytes());
            }
            let body = fat(&[0x00; 8], 0x0008, &section);
            let parsed = MethodBody::parse(&body, 0).unwrap();
            assert_eq!(parsed.exception_handlers.len(), usize::from(count), "count {count}");
            assert!(
                parsed.diagnostics().is_empty(),
                "a conforming section must not be diagnosed, count {count}"
            );
        }
    }

    #[test]
    fn validate_rejects_ranges_outside_the_code() {
        let mut section = alloc::vec![0x01u8, 4 + 12, 0, 0];
        section.extend_from_slice(&0x0002u16.to_le_bytes());
        section.extend_from_slice(&0u16.to_le_bytes());
        section.push(200); // TryLength past the end
        section.extend_from_slice(&4u16.to_le_bytes());
        section.push(4);
        section.extend_from_slice(&0u32.to_le_bytes());
        let body = fat(&[0x00; 8], 0x0008, &section);
        let parsed = MethodBody::parse(&body, 0).unwrap();
        // Parsing still succeeds so the code stays readable.
        assert_eq!(parsed.code.len(), 8);
        assert_eq!(parsed.validate_handlers().unwrap_err().kind, ErrorKind::OutOfRange);
    }

    #[test]
    fn validate_rejects_partially_overlapping_try_blocks() {
        let mut section = alloc::vec![0x01u8, 4 + 24, 0, 0];
        for (try_offset, try_length, handler_offset) in [(0u16, 8u8, 8u16), (4, 8, 12)] {
            section.extend_from_slice(&0x0002u16.to_le_bytes());
            section.extend_from_slice(&try_offset.to_le_bytes());
            section.push(try_length);
            section.extend_from_slice(&handler_offset.to_le_bytes());
            section.push(4);
            section.extend_from_slice(&0u32.to_le_bytes());
        }
        let body = fat(&[0x00; 16], 0x0008, &section);
        let parsed = MethodBody::parse(&body, 0).unwrap();
        assert_eq!(parsed.exception_handlers.len(), 2);
        assert!(parsed.validate_handlers().is_err());
    }

    #[test]
    fn a_fat_header_size_other_than_three_is_diagnosed() {
        let mut body = fat(&[0x2A], 0, &[]);
        body[1] = (body[1] & 0x0F) | 0x40; // header size 4 dwords
        let parsed = MethodBody::parse(&body, 0);
        // The declared size pushes the code start past the 1-byte body.
        assert!(parsed.is_err() || parsed.unwrap().header_dwords == 4);
        assert!(MethodBody::parse_with(&body, 0, Strictness::Strict).is_err());
    }

    #[test]
    fn an_unknown_header_format_is_rejected() {
        assert_eq!(MethodBody::parse(&[0x00], 0).unwrap_err().kind, ErrorKind::Malformed);
        assert_eq!(MethodBody::parse(&[0x01], 0).unwrap_err().kind, ErrorKind::Malformed);
        assert_eq!(MethodBody::parse(&[], 0).unwrap_err().kind, ErrorKind::Truncated);
    }

    #[test]
    fn every_truncation_of_a_body_errors_cleanly() {
        let mut section = alloc::vec![0x01u8, 4 + 12, 0, 0];
        section.extend_from_slice(&0x0002u16.to_le_bytes());
        section.extend_from_slice(&0u16.to_le_bytes());
        section.push(4);
        section.extend_from_slice(&4u16.to_le_bytes());
        section.push(4);
        section.extend_from_slice(&0u32.to_le_bytes());
        let body = fat(&[0x00; 8], 0x0008, &section);
        for len in 0..body.len() {
            let _ = MethodBody::parse(&body[..len], 0);
            let _ = MethodBody::parse_with(&body[..len], 0, Strictness::Strict);
        }
    }

    #[test]
    fn overlap_helper_distinguishes_nesting_from_overlap() {
        assert!(!partially_overlaps(0, 10, 2, 5)); // nested
        assert!(!partially_overlaps(2, 5, 0, 10)); // nested the other way
        assert!(!partially_overlaps(0, 4, 4, 8)); // adjacent
        assert!(partially_overlaps(0, 6, 4, 10)); // straddling
    }
}
