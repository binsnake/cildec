//! Error and diagnostic types.
//!
//! Every fallible entry point in this crate returns [`Error`], a `Copy` struct
//! carrying a machine-readable [`ErrorKind`], the byte offset into the input
//! that was handed to the failing `parse` call, and a short static context
//! string naming the structure that failed to decode.
//!
//! Errors never allocate and never borrow from the input, so they can be
//! propagated freely across the `'a` lifetime of a parsed image.

use core::fmt;

/// The classification of a decoding failure.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input ended before the structure being decoded was complete.
    Truncated,
    /// The bytes were present but do not form a legal structure.
    Malformed,
    /// The structure is legal but this version of the crate does not decode it.
    Unsupported,
    /// An index, RVA, or offset pointed outside the region it must lie in.
    OutOfRange,
    /// A nested structure exceeded the configured recursion limit.
    RecursionLimit,
    /// Text that must be UTF-8 was not.
    InvalidUtf8,
    /// A CIL prefix was not followed by an instruction it is legal on.
    InvalidPrefixTarget,
    /// The byte (or `0xFE`-escaped byte pair) is not a defined CIL opcode.
    UnknownOpcode,
}

impl ErrorKind {
    /// A short lowercase description, used by the [`Display`](fmt::Display) impl.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Truncated => "truncated input",
            ErrorKind::Malformed => "malformed structure",
            ErrorKind::Unsupported => "unsupported structure",
            ErrorKind::OutOfRange => "value out of range",
            ErrorKind::RecursionLimit => "recursion limit exceeded",
            ErrorKind::InvalidUtf8 => "invalid UTF-8",
            ErrorKind::InvalidPrefixTarget => "invalid prefix target",
            ErrorKind::UnknownOpcode => "unknown opcode",
        }
    }
}

/// A decoding failure.
///
/// `offset`, when present, is a byte offset into the buffer passed to the
/// `parse` call that produced this error, not into an inner slice.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Error {
    /// What went wrong.
    pub kind: ErrorKind,
    /// Byte offset into the failing `parse` call input, when known.
    pub offset: Option<usize>,
    /// The structure that failed to decode, e.g. `"CLI header"`.
    pub context: &'static str,
}

impl Error {
    /// Constructs an error with an offset.
    pub const fn new(kind: ErrorKind, offset: usize, context: &'static str) -> Self {
        Error { kind, offset: Some(offset), context }
    }

    /// Constructs an error with no meaningful offset.
    pub const fn detached(kind: ErrorKind, context: &'static str) -> Self {
        Error { kind, offset: None, context }
    }

    /// Returns a copy of this error with `base` added to any existing offset.
    ///
    /// Used when an inner parser reports an offset relative to a sub-slice and
    /// the caller knows where that sub-slice began.
    #[must_use]
    pub const fn rebase(self, base: usize) -> Self {
        match self.offset {
            Some(o) => Error {
                kind: self.kind,
                offset: Some(o.saturating_add(base)),
                context: self.context,
            },
            None => Error { kind: self.kind, offset: Some(base), context: self.context },
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.kind.as_str())?;
        if let Some(offset) = self.offset {
            write!(f, " at offset {offset:#x}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Shorthand for results produced by this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// How tolerant a parser should be of images that deviate from ECMA-335.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Strictness {
    /// Reject everything ECMA-335 rejects.
    Strict,
    /// Accept the real-world deviations documented in the crate root, recording
    /// each one as a [`Diagnostic`]. This is the default.
    #[default]
    Permissive,
}

impl Strictness {
    /// True when this is [`Strictness::Strict`].
    pub const fn is_strict(self) -> bool {
        matches!(self, Strictness::Strict)
    }
}

/// A deviation from ECMA-335 that was accepted in [`Strictness::Permissive`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Diagnostic {
    /// What was tolerated.
    pub code: DiagnosticCode,
    /// Byte offset into the parsed input, when known.
    pub offset: Option<usize>,
    /// Code-specific detail: a table id, a stream index, a declared size, etc.
    pub detail: u64,
}

impl Diagnostic {
    pub(crate) const fn new(code: DiagnosticCode, offset: usize, detail: u64) -> Self {
        Diagnostic { code, offset: Some(offset), detail }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (detail {:#x})", self.code.as_str(), self.detail)?;
        if let Some(offset) = self.offset {
            write!(f, " at offset {offset:#x}")?;
        }
        Ok(())
    }
}

/// The set of tolerated deviations this crate can report.
///
/// Every variant is produced by some parser; a deviation that a `&self`
/// accessor notices instead, such as a `#US` entry with an even body length, is
/// reported on the value itself (see [`UserString::odd_length`](crate::heaps::UserString::odd_length)).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum DiagnosticCode {
    /// A fat method header declared a size other than 3 dwords.
    FatHeaderSize,
    /// A metadata stream name was not NUL-padded to a 4-byte boundary.
    StreamNamePadding,
    /// Two metadata streams shared a name; the first was kept.
    DuplicateStreamName,
    /// A stream declared range was clamped to the end of the metadata region.
    StreamRangeClamped,
    /// The `Valid` bitvector set a bit for a reserved table id with zero rows.
    ReservedTablePresent,
    /// A table the spec marks sorted was not sorted; lookups fall back to a scan.
    TableNotSorted,
    /// The metadata version string was not NUL-terminated inside its field.
    VersionStringPadding,
    /// The CLI header declared a size other than 72 bytes.
    CliHeaderSize,
    /// A section header raw range ran past the end of the file.
    SectionRangeClamped,
    /// An exception-handling section declared a size inconsistent with its clauses.
    EhSectionSize,
    /// `32BITPREFERRED` was set without `32BITREQUIRED`.
    BitnessFlagsInconsistent,
    /// The table stream declared heap-size bits this crate ignores.
    UnknownHeapSizeBits,
}

impl DiagnosticCode {
    /// A short static description.
    pub const fn as_str(self) -> &'static str {
        match self {
            DiagnosticCode::FatHeaderSize => "fat method header size is not 3 dwords",
            DiagnosticCode::StreamNamePadding => "stream name is not NUL-padded",
            DiagnosticCode::DuplicateStreamName => "duplicate stream name",
            DiagnosticCode::StreamRangeClamped => "stream range clamped to metadata region",
            DiagnosticCode::ReservedTablePresent => "reserved table id flagged present",
            DiagnosticCode::TableNotSorted => "table declared sorted is not sorted",
            DiagnosticCode::VersionStringPadding => "version string is not NUL-terminated",
            DiagnosticCode::CliHeaderSize => "CLI header size is not 72",
            DiagnosticCode::SectionRangeClamped => "section raw range clamped to file",
            DiagnosticCode::EhSectionSize => "exception section size is inconsistent",
            DiagnosticCode::BitnessFlagsInconsistent => "32BITPREFERRED without 32BITREQUIRED",
            DiagnosticCode::UnknownHeapSizeBits => "unknown HeapSizes bits",
        }
    }
}
