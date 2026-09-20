//! A zero-dependency decoder for ECMA-335 metadata and CIL method bodies.
//!
//! `cildec` reads a managed PE image, or a bare metadata blob, and exposes its
//! tables, heaps, signatures, method bodies and exception-handling tables as
//! typed, bounds-checked Rust values. It then decodes CIL method bodies into a
//! typed instruction stream with exact byte offsets and sizes, absolute branch
//! targets, folded prefixes and the per-opcode static facts from ECMA-335
//! Partition VI, Annex C.
//!
//! The normative reference throughout is **ECMA-335, 6th edition (June 2012)**.
//! Module documentation cites the partition and section each part implements.
//!
//! # Design
//!
//! * **Safe on hostile input.** The crate is a parser of untrusted bytes. It
//!   forbids `unsafe`, has no reachable panic on any input, never allocates on
//!   the basis of a declared count without checking it against the bytes that
//!   remain, and never loops without making progress. This is enforced by
//!   fuzzing, not just by review.
//! * **Lazy.** Opening an image parses headers and the table directory only.
//!   Heaps, signatures and method bodies are decoded when asked for.
//! * **Borrowing.** Everything borrows the input `&[u8]`; row and instruction
//!   decoding copies only the few bytes of the value itself.
//! * **Deterministic.** No hash-map iteration affects any output, so two runs
//!   over the same bytes produce identical results in identical order.
//!
//! # Strictness
//!
//! Real images deviate from ECMA-335. [`Strictness::Permissive`], the default,
//! accepts the deviations listed under [`DiagnosticCode`] and records each one
//! so a consumer can decide what to do. [`Strictness::Strict`] rejects
//! everything the specification rejects.
//!
//! # Example
//!
//! ```no_run
//! use cildec::{PeImage, MethodBody, Names};
//!
//! # fn main() -> Result<(), cildec::Error> {
//! let bytes = std::fs::read("Example.dll").unwrap();
//! let image = PeImage::parse(&bytes)?;
//! let metadata = image.metadata()?;
//! let names = Names::new(&metadata);
//!
//! for (rid, row) in metadata.tables().iter::<cildec::tables::MethodDefRow>() {
//!     let row = row?;
//!     if metadata.strings().str_opt(row.name) != Some("Main") {
//!         continue;
//!     }
//!     let Some(body) = MethodBody::from_image(&image, &row)? else { continue };
//!     println!("{}", names.method_def_full(cildec::Rid::new(rid))?);
//!     for folded in body.folded_instructions() {
//!         let folded = folded?;
//!         let instruction = &folded.instruction;
//!         print!("  IL_{:04x}: {}", instruction.offset, instruction.opcode.name());
//!         if let Some(token) = instruction.operand.token() {
//!             print!(" {}", names.token(token));
//!         }
//!         println!();
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # What this crate does not do
//!
//! It does not simulate the stack, build control-flow graphs, verify IL, check
//! operand types, resolve across assemblies, decode custom-attribute or
//! marshalling blobs, verify signatures, decode managed resources, interpret
//! Portable PDB semantics, or write metadata. Ranges and raw blobs for those
//! are exposed so that a consumer can do its own work.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

extern crate alloc;

pub mod body;
pub mod compressed;
pub mod display;
pub mod error;
pub mod heaps;
pub mod il;
pub mod metadata;
pub mod pe;
mod reader;
pub mod signature;
pub mod tables;
pub mod token;

pub use compressed::{read_i32 as read_compressed_i32, read_u32 as read_compressed_u32};

pub use body::{ExceptionHandler, FatFlags, HandlerKind, HeaderKind, MethodBody, RawSection};
pub use display::Names;
pub use error::{Diagnostic, DiagnosticCode, Error, ErrorKind, Result, Strictness};
pub use heaps::{BlobHeap, Guid, GuidHeap, StringsHeap, UserString, UserStringsHeap};
pub use il::{
    FlowControl, FoldedInstruction, FoldedIter, Instruction, InstructionIter, NoChecks, OpCode,
    OpCodeInfo, OpCodeKind, Operand, OperandKind, Prefixes, StackBehaviourPop, StackBehaviourPush,
};
pub use metadata::{Metadata, StreamHeader};
pub use pe::{CliFlags, CliHeader, DataDirectory, EntryPoint, PeImage, Section};
pub use signature::{
    ArrayShape, CallConv, CustomMod, FieldSig, LocalVar, LocalVarSig, MethodSig, MethodSpecSig,
    Param, PropertySig, SignatureOptions, Type, TypeSpecSig,
};
pub use tables::{CodedIndex, ColumnKind, TableLayout, TableRow, Tables};
pub use token::{BlobIndex, GuidIndex, Rid, StringIndex, TableId, Token, UserStringToken, marker};

/// Reads a file and parses it as a managed PE image.
///
/// The returned image borrows `bytes`, so the caller keeps ownership of the
/// buffer; this helper only exists to save a `std::fs::read` call.
#[cfg(feature = "std")]
pub fn read_file(path: impl AsRef<std::path::Path>) -> std::io::Result<alloc::vec::Vec<u8>> {
    std::fs::read(path)
}

#[cfg(test)]
pub(crate) mod test_support {
    use alloc::vec::Vec;

    /// A metadata region with an empty `#~` stream and no heaps.
    pub fn minimal_metadata() -> Vec<u8> {
        let mut table_stream = Vec::new();
        table_stream.extend_from_slice(&0u32.to_le_bytes());
        table_stream.extend_from_slice(&[2, 0, 0, 1]);
        table_stream.extend_from_slice(&0u64.to_le_bytes());
        table_stream.extend_from_slice(&0u64.to_le_bytes());

        let version = b"v4.0.30319\0\0";
        let mut out = Vec::new();
        out.extend_from_slice(&crate::metadata::METADATA_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(version.len() as u32).to_le_bytes());
        out.extend_from_slice(version);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        let directory = 8 + 4;
        out.extend_from_slice(&((out.len() + directory) as u32).to_le_bytes());
        out.extend_from_slice(&(table_stream.len() as u32).to_le_bytes());
        out.extend_from_slice(b"#~\0\0");
        out.extend_from_slice(&table_stream);
        out
    }
}
