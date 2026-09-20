//! The CIL instruction decoder (ECMA-335 Partition III, Partition VI Annex C).
//!
//! Decoding is total over the code range: every step either yields an
//! instruction with an exact byte size, or an error naming the offset and the
//! cause. Bytes are never skipped silently, so the sizes of the instructions
//! a method yields sum to exactly the length of its code.
//!
//! Two iterators are available. [`InstructionIter`] is the raw stream, where a
//! prefix such as `volatile.` is its own instruction and prefix placement is
//! never validated. [`FoldedIter`] attaches prefixes to the instruction they
//! modify and rejects a prefix that precedes an instruction it is not legal
//! on (III.2.1–III.2.6).
//!
//! Branch operands are absolute IL offsets, computed from the offset of the
//! following instruction plus the encoded delta. Whether the target lands on
//! an instruction boundary is not checked here; use
//! [`MethodBody::instruction_offsets`](crate::body::MethodBody::instruction_offsets)
//! for that.

mod table;

pub use table::{ALL_OPCODES, OPCODE_COUNT, OpCode};

use alloc::vec::Vec;

use crate::error::{Error, ErrorKind, Result};
use crate::reader::Reader;
use crate::token::{Token, UserStringToken};

const CTX: &str = "CIL";

/// The shape of an instruction operand (ECMA-335 VI.C).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum OperandKind {
    /// No operand.
    InlineNone,
    /// A 4-byte signed integer.
    InlineI,
    /// A 1-byte signed integer.
    ShortInlineI,
    /// An 8-byte signed integer.
    InlineI8,
    /// A 4-byte IEEE float.
    ShortInlineR,
    /// An 8-byte IEEE float.
    InlineR,
    /// A 4-byte signed branch delta.
    InlineBrTarget,
    /// A 1-byte signed branch delta.
    ShortInlineBrTarget,
    /// A 4-byte count followed by that many 4-byte branch deltas.
    InlineSwitch,
    /// A `MethodDef`, `MemberRef` or `MethodSpec` token.
    InlineMethod,
    /// A `Field` or `MemberRef` token.
    InlineField,
    /// A `TypeDef`, `TypeRef` or `TypeSpec` token.
    InlineType,
    /// Any metadata token.
    InlineTok,
    /// A `#US` token.
    InlineString,
    /// A `StandAloneSig` token.
    InlineSig,
    /// A 2-byte local or argument index.
    InlineVar,
    /// A 1-byte local or argument index.
    ShortInlineVar,
}

impl OperandKind {
    /// The fixed operand size in bytes, or `None` for [`OperandKind::InlineSwitch`],
    /// whose size depends on the encoded count.
    pub const fn fixed_size(self) -> Option<usize> {
        Some(match self {
            OperandKind::InlineNone => 0,
            OperandKind::ShortInlineI
            | OperandKind::ShortInlineBrTarget
            | OperandKind::ShortInlineVar => 1,
            OperandKind::InlineVar => 2,
            OperandKind::InlineI
            | OperandKind::ShortInlineR
            | OperandKind::InlineBrTarget
            | OperandKind::InlineMethod
            | OperandKind::InlineField
            | OperandKind::InlineType
            | OperandKind::InlineTok
            | OperandKind::InlineString
            | OperandKind::InlineSig => 4,
            OperandKind::InlineI8 | OperandKind::InlineR => 8,
            OperandKind::InlineSwitch => return None,
        })
    }

    /// True when the operand is a metadata token.
    pub const fn is_token(self) -> bool {
        matches!(
            self,
            OperandKind::InlineMethod
                | OperandKind::InlineField
                | OperandKind::InlineType
                | OperandKind::InlineTok
                | OperandKind::InlineString
                | OperandKind::InlineSig
        )
    }
}

/// How many operands an instruction pops (ECMA-335 VI.C).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum StackBehaviourPop {
    Pop0,
    Pop1,
    Pop1Pop1,
    PopI,
    PopIPop1,
    PopIPopI,
    PopIPopI8,
    PopIPopIPopI,
    PopIPopR4,
    PopIPopR8,
    PopRef,
    PopRefPop1,
    PopRefPopI,
    PopRefPopIPop1,
    PopRefPopIPopI,
    PopRefPopIPopI8,
    PopRefPopIPopR4,
    PopRefPopIPopR8,
    PopRefPopIPopRef,
    /// The count depends on the call signature.
    VarPop,
}

impl StackBehaviourPop {
    /// The number of stack slots popped, or `None` for [`StackBehaviourPop::VarPop`].
    pub const fn count(self) -> Option<u8> {
        Some(match self {
            StackBehaviourPop::Pop0 => 0,
            StackBehaviourPop::Pop1 | StackBehaviourPop::PopI | StackBehaviourPop::PopRef => 1,
            StackBehaviourPop::Pop1Pop1
            | StackBehaviourPop::PopIPop1
            | StackBehaviourPop::PopIPopI
            | StackBehaviourPop::PopIPopI8
            | StackBehaviourPop::PopIPopR4
            | StackBehaviourPop::PopIPopR8
            | StackBehaviourPop::PopRefPop1
            | StackBehaviourPop::PopRefPopI => 2,
            StackBehaviourPop::PopIPopIPopI
            | StackBehaviourPop::PopRefPopIPop1
            | StackBehaviourPop::PopRefPopIPopI
            | StackBehaviourPop::PopRefPopIPopI8
            | StackBehaviourPop::PopRefPopIPopR4
            | StackBehaviourPop::PopRefPopIPopR8
            | StackBehaviourPop::PopRefPopIPopRef => 3,
            StackBehaviourPop::VarPop => return None,
        })
    }
}

/// How many results an instruction pushes (ECMA-335 VI.C).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum StackBehaviourPush {
    Push0,
    Push1,
    Push1Push1,
    PushI,
    PushI8,
    PushR4,
    PushR8,
    PushRef,
    /// The count depends on the call signature.
    VarPush,
}

impl StackBehaviourPush {
    /// The number of stack slots pushed, or `None` for [`StackBehaviourPush::VarPush`].
    pub const fn count(self) -> Option<u8> {
        Some(match self {
            StackBehaviourPush::Push0 => 0,
            StackBehaviourPush::Push1
            | StackBehaviourPush::PushI
            | StackBehaviourPush::PushI8
            | StackBehaviourPush::PushR4
            | StackBehaviourPush::PushR8
            | StackBehaviourPush::PushRef => 1,
            StackBehaviourPush::Push1Push1 => 2,
            StackBehaviourPush::VarPush => return None,
        })
    }
}

/// How an instruction affects control flow (ECMA-335 VI.C).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum FlowControl {
    /// Execution continues with the next instruction.
    Next,
    /// An unconditional transfer.
    Branch,
    /// A conditional transfer.
    CondBranch,
    /// A call, which normally returns to the next instruction.
    Call,
    /// A return from the method.
    Return,
    /// An exception is raised.
    Throw,
    /// A debugger breakpoint.
    Break,
    /// A prefix or other instruction that does not itself transfer control.
    Meta,
}

impl FlowControl {
    /// True when the next instruction in address order cannot be reached.
    pub const fn is_unconditional_transfer(self) -> bool {
        matches!(self, FlowControl::Branch | FlowControl::Return | FlowControl::Throw)
    }
}

/// The category an opcode belongs to (ECMA-335 VI.C).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum OpCodeKind {
    /// A base instruction.
    Primitive,
    /// A short or implied-operand encoding of a primitive instruction.
    Macro,
    /// An object-model instruction.
    ObjModel,
    /// An instruction prefix.
    Prefix,
    /// Reserved for the runtime.
    Internal,
}

/// The static facts ECMA-335 records about one opcode.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct OpCodeInfo {
    /// The canonical mnemonic, e.g. `"ldarg.0"` or `"conv.ovf.i1.un"`.
    pub name: &'static str,
    /// The encoding bytes; for a one-byte opcode the second byte is 0.
    pub encoding: [u8; 2],
    /// The number of encoding bytes, 1 or 2.
    pub size: u8,
    /// The operand shape.
    pub operand: OperandKind,
    /// What the instruction pops.
    pub pop: StackBehaviourPop,
    /// What the instruction pushes.
    pub push: StackBehaviourPush,
    /// How the instruction affects control flow.
    pub flow: FlowControl,
    /// The opcode category.
    pub kind: OpCodeKind,
}

impl OpCode {
    /// The static facts about this opcode.
    pub const fn info(self) -> &'static OpCodeInfo {
        &table::OPCODE_INFO[self as usize]
    }

    /// The canonical mnemonic.
    pub const fn name(self) -> &'static str {
        self.info().name
    }

    /// True when this opcode is an instruction prefix.
    pub const fn is_prefix(self) -> bool {
        matches!(self.info().kind, OpCodeKind::Prefix)
    }

    /// The general-purpose opcode a short or macro encoding stands for.
    ///
    /// `ldarg.0`, `ldarg.s` and `ldarg` all map to `ldarg`; `ldc.i4.m1` and
    /// `ldc.i4.s` map to `ldc.i4`; `br.s` maps to `br`. Every other opcode maps
    /// to itself, so this reduces the 219 encodings to the roughly 100 distinct
    /// semantic operations a consumer needs to dispatch on.
    pub const fn canonical(self) -> OpCode {
        table::canonical_of(self)
    }

    /// Decodes an opcode from the front of `bytes`.
    ///
    /// Returns the opcode and the number of bytes it occupies, 1 or 2.
    pub fn from_bytes(bytes: &[u8]) -> Result<(OpCode, usize)> {
        let first = *bytes.first().ok_or(Error::new(ErrorKind::Truncated, 0, CTX))?;
        if first == 0xFE {
            let second = *bytes.get(1).ok_or(Error::new(ErrorKind::Truncated, 1, CTX))?;
            match table::decode_two(second) {
                Some(op) => Ok((op, 2)),
                None => Err(Error::new(ErrorKind::UnknownOpcode, 0, CTX)),
            }
        } else {
            match table::decode_one(first) {
                Some(op) => Ok((op, 1)),
                None => Err(Error::new(ErrorKind::UnknownOpcode, 0, CTX)),
            }
        }
    }
}

/// A decoded instruction operand.
///
/// `PartialEq` follows IEEE semantics for the float variants, so two decodes of
/// the same `ldc.r4 NaN` are not equal; compare `to_bits()` when that matters.
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Operand {
    /// No operand, or a macro encoding with no implied value.
    None,
    /// A one-byte signed value that is not a widened constant, i.e. the `no.`
    /// prefix check mask.
    I8(i8),
    /// A 4-byte signed integer, including the widened `ldc.i4.s` and the
    /// constants implied by `ldc.i4.0` through `ldc.i4.8` and `ldc.i4.m1`.
    I32(i32),
    /// An 8-byte signed integer.
    I64(i64),
    /// A 4-byte float.
    R32(f32),
    /// An 8-byte float.
    R64(f64),
    /// An absolute IL offset, already resolved from the encoded delta.
    BranchTarget(u32),
    /// Absolute IL offsets for a `switch`, in table order.
    Switch(Vec<u32>),
    /// A method token from `call`, `callvirt`, `newobj`, `ldftn`, `jmp`.
    Method(Token),
    /// A field token from `ldfld`, `stsfld`, `ldflda`.
    Field(Token),
    /// A type token from `castclass`, `newarr`, `box`, `constrained.`.
    Type(Token),
    /// An unrestricted token from `ldtoken`.
    Tok(Token),
    /// A `StandAloneSig` token from `calli`.
    Sig(Token),
    /// A `#US` token from `ldstr`.
    String(UserStringToken),
    /// A local or argument index, widened from the short and macro encodings.
    Var(u16),
}

impl Operand {
    /// The token, for the operand kinds that carry one.
    pub const fn token(&self) -> Option<Token> {
        match self {
            Operand::Method(t)
            | Operand::Field(t)
            | Operand::Type(t)
            | Operand::Tok(t)
            | Operand::Sig(t) => Some(*t),
            _ => None,
        }
    }

    /// The absolute branch targets of this operand, if it has any.
    pub fn branch_targets(&self) -> &[u32] {
        match self {
            Operand::BranchTarget(target) => core::slice::from_ref(target),
            Operand::Switch(targets) => targets,
            _ => &[],
        }
    }
}

/// One decoded instruction.
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Instruction {
    /// The IL offset of the first opcode byte.
    pub offset: u32,
    /// The total encoded size: opcode bytes plus operand bytes.
    ///
    /// This is wider than the one byte ECMA-335 would suggest because a
    /// `switch` with more than 62 targets is longer than 255 bytes.
    pub size: u32,
    /// The exact opcode as encoded, short and macro forms included.
    pub opcode: OpCode,
    /// The decoded operand.
    pub operand: Operand,
}

impl Instruction {
    /// The IL offset of the following instruction.
    pub const fn next_offset(&self) -> u32 {
        self.offset.wrapping_add(self.size)
    }

    /// The static facts about this instruction opcode.
    pub const fn info(&self) -> &'static OpCodeInfo {
        self.opcode.info()
    }
}

/// Which runtime checks a `no.` prefix suppresses (III.2.2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NoChecks {
    /// Skip the type check.
    pub typecheck: bool,
    /// Skip the array range check.
    pub rangecheck: bool,
    /// Skip the null check.
    pub nullcheck: bool,
}

impl NoChecks {
    /// Decodes the `no.` operand byte.
    pub const fn from_bits(bits: u8) -> Self {
        NoChecks {
            typecheck: bits & 0x01 != 0,
            rangecheck: bits & 0x02 != 0,
            nullcheck: bits & 0x04 != 0,
        }
    }

    /// True when no check is suppressed.
    pub const fn is_empty(self) -> bool {
        !self.typecheck && !self.rangecheck && !self.nullcheck
    }
}

/// The prefixes attached to one instruction.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Prefixes {
    /// `constrained.` and the type token it carries.
    pub constrained: Option<Token>,
    /// `volatile.`.
    pub volatile: bool,
    /// `unaligned.` and the declared alignment, 1, 2 or 4.
    pub unaligned: Option<u8>,
    /// `tail.`.
    pub tail: bool,
    /// `readonly.`.
    pub readonly: bool,
    /// `no.` and the checks it suppresses.
    pub no: NoChecks,
}

impl Prefixes {
    /// True when no prefix is present.
    pub const fn is_empty(&self) -> bool {
        self.constrained.is_none()
            && !self.volatile
            && self.unaligned.is_none()
            && !self.tail
            && !self.readonly
            && self.no.is_empty()
    }
}

/// An instruction with its prefixes folded in.
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FoldedInstruction {
    /// The prefixed instruction itself.
    pub instruction: Instruction,
    /// The prefixes that preceded it.
    pub prefixes: Prefixes,
    /// The IL offset of the first prefix byte, or of the instruction when there
    /// are no prefixes. Use this and [`FoldedInstruction::end_offset`] to
    /// account for every byte of the method.
    pub first_offset: u32,
}

impl FoldedInstruction {
    /// The IL offset just past the instruction.
    pub const fn end_offset(&self) -> u32 {
        self.instruction.next_offset()
    }

    /// The total byte span of the prefixes and the instruction.
    pub const fn total_size(&self) -> u32 {
        self.end_offset().wrapping_sub(self.first_offset)
    }
}

/// Decodes one instruction at `offset` in `code`.
pub fn decode_at(code: &[u8], offset: u32) -> Result<Instruction> {
    let start = offset as usize;
    let rest = code.get(start..).ok_or(Error::new(ErrorKind::OutOfRange, start, CTX))?;
    let (opcode, opcode_size) = OpCode::from_bytes(rest).map_err(|e| e.rebase(start))?;
    let info = opcode.info();

    let mut r = Reader::new(rest, start, CTX);
    r.skip(opcode_size)?;

    let operand = match info.operand {
        OperandKind::InlineNone => match (table::implied_var(opcode), table::implied_i32(opcode)) {
            (Some(index), _) => Operand::Var(index),
            (_, Some(value)) => Operand::I32(value),
            _ => Operand::None,
        },
        OperandKind::ShortInlineI => {
            let value = r.i8()?;
            if matches!(opcode, OpCode::LdcI4S) {
                Operand::I32(i32::from(value))
            } else {
                Operand::I8(value)
            }
        }
        OperandKind::InlineI => Operand::I32(r.i32()?),
        OperandKind::InlineI8 => Operand::I64(r.i64()?),
        OperandKind::ShortInlineR => Operand::R32(r.f32()?),
        OperandKind::InlineR => Operand::R64(r.f64()?),
        OperandKind::ShortInlineVar => Operand::Var(u16::from(r.u8()?)),
        OperandKind::InlineVar => Operand::Var(r.u16()?),
        OperandKind::ShortInlineBrTarget => {
            let delta = i32::from(r.i8()?);
            let next = offset.wrapping_add(r.position() as u32);
            Operand::BranchTarget(next.wrapping_add(delta as u32))
        }
        OperandKind::InlineBrTarget => {
            let delta = r.i32()?;
            let next = offset.wrapping_add(r.position() as u32);
            Operand::BranchTarget(next.wrapping_add(delta as u32))
        }
        OperandKind::InlineSwitch => {
            let count = r.u32()? as usize;
            // Each target costs 4 bytes, so a count larger than the remaining
            // code is a lie; reject it before reserving anything.
            if count > r.remaining() / 4 {
                return Err(Error::new(ErrorKind::Truncated, start, CTX));
            }
            let mut deltas = Vec::with_capacity(count);
            for _ in 0..count {
                deltas.push(r.i32()?);
            }
            let next = offset.wrapping_add(r.position() as u32);
            Operand::Switch(deltas.into_iter().map(|d| next.wrapping_add(d as u32)).collect())
        }
        OperandKind::InlineMethod => Operand::Method(Token(r.u32()?)),
        OperandKind::InlineField => Operand::Field(Token(r.u32()?)),
        OperandKind::InlineType => Operand::Type(Token(r.u32()?)),
        OperandKind::InlineTok => Operand::Tok(Token(r.u32()?)),
        OperandKind::InlineSig => Operand::Sig(Token(r.u32()?)),
        OperandKind::InlineString => Operand::String(UserStringToken(r.u32()?)),
    };

    Ok(Instruction { offset, size: r.position() as u32, opcode, operand })
}

/// The raw instruction stream of a method body; see
/// [`MethodBody::instructions`](crate::body::MethodBody::instructions).
#[derive(Clone, Debug)]
pub struct InstructionIter<'a> {
    code: &'a [u8],
    offset: u32,
    done: bool,
}

impl<'a> InstructionIter<'a> {
    /// Decodes `code` from offset 0.
    pub const fn new(code: &'a [u8]) -> Self {
        InstructionIter { code, offset: 0, done: false }
    }

    /// The offset the next instruction will be decoded at.
    pub const fn offset(&self) -> u32 {
        self.offset
    }
}

impl Iterator for InstructionIter<'_> {
    type Item = Result<Instruction>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset as usize >= self.code.len() {
            return None;
        }
        match decode_at(self.code, self.offset) {
            Ok(instruction) => {
                // Every opcode is at least one byte, so the offset advances on
                // every step. The only way it could not is a code range long
                // enough to wrap a `u32`, which would loop forever; stop
                // instead, after yielding the instruction just decoded.
                let next = instruction.next_offset();
                if next <= self.offset {
                    self.done = true;
                } else {
                    self.offset = next;
                }
                Some(Ok(instruction))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// The instruction stream with prefixes folded onto their targets; see
/// [`MethodBody::folded_instructions`](crate::body::MethodBody::folded_instructions).
#[derive(Clone, Debug)]
pub struct FoldedIter<'a> {
    inner: InstructionIter<'a>,
}

impl<'a> FoldedIter<'a> {
    /// Decodes `code` from offset 0.
    pub const fn new(code: &'a [u8]) -> Self {
        FoldedIter { inner: InstructionIter::new(code) }
    }
}

impl Iterator for FoldedIter<'_> {
    type Item = Result<FoldedInstruction>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut prefixes = Prefixes::default();
        let mut first_offset = None;
        loop {
            let item = match self.inner.next() {
                Some(item) => item,
                None => {
                    // The code ended on a prefix, which modifies nothing.
                    return match first_offset {
                        Some(at) => {
                            self.inner.done = true;
                            Some(Err(Error::new(
                                ErrorKind::InvalidPrefixTarget,
                                at as usize,
                                "CIL prefix",
                            )))
                        }
                        None => None,
                    };
                }
            };
            let instruction = match item {
                Ok(instruction) => instruction,
                Err(e) => return Some(Err(e)),
            };
            let first = *first_offset.get_or_insert(instruction.offset);

            if instruction.opcode.is_prefix() {
                if let Err(e) = apply_prefix(&mut prefixes, &instruction) {
                    self.inner.done = true;
                    return Some(Err(e));
                }
                continue;
            }

            if !prefixes.is_empty() {
                if let Err(e) = check_prefix_targets(&prefixes, instruction.opcode, first) {
                    self.inner.done = true;
                    return Some(Err(e));
                }
            }

            return Some(Ok(FoldedInstruction { instruction, prefixes, first_offset: first }));
        }
    }
}

fn apply_prefix(prefixes: &mut Prefixes, instruction: &Instruction) -> Result<()> {
    let duplicate = || Error::new(ErrorKind::Malformed, instruction.offset as usize, "CIL prefix");
    match instruction.opcode {
        OpCode::Constrained => {
            if prefixes.constrained.is_some() {
                return Err(duplicate());
            }
            prefixes.constrained = instruction.operand.token();
        }
        OpCode::Volatile => {
            if prefixes.volatile {
                return Err(duplicate());
            }
            prefixes.volatile = true;
        }
        OpCode::Unaligned => {
            if prefixes.unaligned.is_some() {
                return Err(duplicate());
            }
            let alignment = match instruction.operand {
                Operand::I8(value) => value as u8,
                _ => 0,
            };
            prefixes.unaligned = Some(alignment);
        }
        OpCode::Tail => {
            if prefixes.tail {
                return Err(duplicate());
            }
            prefixes.tail = true;
        }
        OpCode::Readonly => {
            if prefixes.readonly {
                return Err(duplicate());
            }
            prefixes.readonly = true;
        }
        OpCode::No => {
            if !prefixes.no.is_empty() {
                return Err(duplicate());
            }
            let bits = match instruction.operand {
                Operand::I8(value) => value as u8,
                _ => 0,
            };
            prefixes.no = NoChecks::from_bits(bits);
            if prefixes.no.is_empty() {
                // A `no.` that suppresses nothing would be indistinguishable
                // from no prefix at all, so record it as a structural error.
                return Err(Error::new(
                    ErrorKind::Malformed,
                    instruction.offset as usize,
                    "CIL prefix",
                ));
            }
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                instruction.offset as usize,
                "CIL prefix",
            ));
        }
    }
    Ok(())
}

fn check_prefix_targets(prefixes: &Prefixes, target: OpCode, at: u32) -> Result<()> {
    let bad = || Error::new(ErrorKind::InvalidPrefixTarget, at as usize, "CIL prefix");
    // ECMA-335 6th edition allows `constrained.` only before `callvirt`, but
    // static abstract interface members made `constrained. call` and
    // `constrained. ldftn` ordinary output from Roslyn, and the runtime accepts
    // them. Real images win over the 2012 text here.
    if prefixes.constrained.is_some()
        && !matches!(target, OpCode::Callvirt | OpCode::Call | OpCode::Ldftn)
    {
        return Err(bad());
    }
    if prefixes.tail && !matches!(target, OpCode::Call | OpCode::Calli | OpCode::Callvirt) {
        return Err(bad());
    }
    if prefixes.readonly && !matches!(target, OpCode::Ldelema | OpCode::Call | OpCode::Callvirt) {
        return Err(bad());
    }
    if prefixes.volatile && !allows_volatile(target) {
        return Err(bad());
    }
    if prefixes.unaligned.is_some() && !allows_unaligned(target) {
        return Err(bad());
    }
    if !prefixes.no.is_empty() && !allows_no(target) {
        return Err(bad());
    }
    Ok(())
}

/// III.2.6: `volatile.` may precede these instructions.
const fn allows_volatile(op: OpCode) -> bool {
    use OpCode::*;
    matches!(
        op,
        LdindI1
            | LdindU1
            | LdindI2
            | LdindU2
            | LdindI4
            | LdindU4
            | LdindI8
            | LdindI
            | LdindR4
            | LdindR8
            | LdindRef
            | StindRef
            | StindI1
            | StindI2
            | StindI4
            | StindI8
            | StindR4
            | StindR8
            | StindI
            | Ldfld
            | Stfld
            | Ldsfld
            | Stsfld
            | Ldobj
            | Stobj
            | Initblk
            | Cpblk
    )
}

/// III.2.5: `unaligned.` may precede these instructions.
const fn allows_unaligned(op: OpCode) -> bool {
    use OpCode::*;
    matches!(
        op,
        LdindI1
            | LdindU1
            | LdindI2
            | LdindU2
            | LdindI4
            | LdindU4
            | LdindI8
            | LdindI
            | LdindR4
            | LdindR8
            | LdindRef
            | StindRef
            | StindI1
            | StindI2
            | StindI4
            | StindI8
            | StindR4
            | StindR8
            | StindI
            | Ldfld
            | Stfld
            | Ldobj
            | Stobj
            | Initblk
            | Cpblk
    )
}

/// III.2.2: `no.` may precede the instructions whose checks it can suppress.
const fn allows_no(op: OpCode) -> bool {
    use OpCode::*;
    matches!(
        op,
        Castclass
            | Isinst
            | Unbox
            | UnboxAny
            | Ldelema
            | Ldelem
            | LdelemI1
            | LdelemU1
            | LdelemI2
            | LdelemU2
            | LdelemI4
            | LdelemU4
            | LdelemI8
            | LdelemI
            | LdelemR4
            | LdelemR8
            | LdelemRef
            | Stelem
            | StelemI
            | StelemI1
            | StelemI2
            | StelemI4
            | StelemI8
            | StelemR4
            | StelemR8
            | StelemRef
            | Ldfld
            | Stfld
            | Callvirt
            | Ldvirtftn
            | Ldlen
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_covers_every_defined_encoding() {
        let mut seen_one = 0usize;
        let mut seen_two = 0usize;
        for op in ALL_OPCODES {
            let info = op.info();
            // The enum discriminant must index its own row.
            assert_eq!(info.encoding[0], if info.size == 1 { info.encoding[0] } else { 0xFE });
            let bytes: &[u8] = if info.size == 1 {
                seen_one += 1;
                &info.encoding[..1]
            } else {
                seen_two += 1;
                &info.encoding[..2]
            };
            let (decoded, size) = OpCode::from_bytes(bytes).unwrap();
            assert_eq!(decoded, op, "round trip failed for {}", info.name);
            assert_eq!(size, usize::from(info.size));
        }
        assert_eq!(seen_one + seen_two, OPCODE_COUNT);
        assert_eq!(OPCODE_COUNT, 219);
    }

    #[test]
    fn every_byte_either_decodes_or_is_reported_unknown() {
        for byte in 0u8..=0xFF {
            match OpCode::from_bytes(&[byte]) {
                Ok((op, size)) => {
                    assert_eq!(size, 1);
                    assert_eq!(op.info().encoding[0], byte);
                    assert_eq!(op.info().size, 1);
                    assert!(byte <= 0xE0, "{byte:#04x} is outside the one-byte range");
                }
                Err(e) if byte == 0xFE => assert_eq!(e.kind, ErrorKind::Truncated),
                Err(e) => assert_eq!(e.kind, ErrorKind::UnknownOpcode, "byte {byte:#04x}"),
            }
        }
        for byte in 0u8..=0xFF {
            match OpCode::from_bytes(&[0xFE, byte]) {
                Ok((op, size)) => {
                    assert_eq!(size, 2);
                    assert_eq!(op.info().encoding, [0xFE, byte]);
                    assert!(byte <= 0x1E, "{byte:#04x} is outside the two-byte range");
                }
                Err(e) => {
                    assert_eq!(e.kind, ErrorKind::UnknownOpcode);
                    assert!(matches!(byte, 0x08 | 0x10 | 0x1B) || byte > 0x1E, "byte {byte:#04x}");
                }
            }
        }
    }

    #[test]
    fn names_are_unique_and_lowercase() {
        let mut names: Vec<&str> = ALL_OPCODES.iter().map(|o| o.name()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate opcode name");
        for op in ALL_OPCODES {
            let name = op.name();
            assert!(!name.is_empty());
            assert_eq!(name, name.to_ascii_lowercase());
        }
    }

    #[test]
    fn canonical_maps_short_and_macro_forms() {
        assert_eq!(OpCode::Ldarg0.canonical(), OpCode::Ldarg);
        assert_eq!(OpCode::LdargS.canonical(), OpCode::Ldarg);
        assert_eq!(OpCode::Ldarg.canonical(), OpCode::Ldarg);
        assert_eq!(OpCode::LdcI4M1.canonical(), OpCode::LdcI4);
        assert_eq!(OpCode::LdcI48.canonical(), OpCode::LdcI4);
        assert_eq!(OpCode::LdcI4S.canonical(), OpCode::LdcI4);
        assert_eq!(OpCode::BrS.canonical(), OpCode::Br);
        assert_eq!(OpCode::BneUnS.canonical(), OpCode::BneUn);
        assert_eq!(OpCode::LeaveS.canonical(), OpCode::Leave);
        assert_eq!(OpCode::Stloc2.canonical(), OpCode::Stloc);
        assert_eq!(OpCode::Add.canonical(), OpCode::Add);
        // A canonical form is always its own canonical form.
        for op in ALL_OPCODES {
            assert_eq!(op.canonical().canonical(), op.canonical(), "{}", op.name());
        }
    }

    #[test]
    fn macro_forms_carry_their_implied_operand() {
        // ldarg.2; ldloc.3; stloc.0; ldc.i4.m1; ldc.i4.8; ret
        let code = [0x04, 0x09, 0x0A, 0x15, 0x1E, 0x2A];
        let decoded: Vec<_> = InstructionIter::new(&code).map(|i| i.unwrap()).collect();
        assert_eq!(decoded[0].operand, Operand::Var(2));
        assert_eq!(decoded[1].operand, Operand::Var(3));
        assert_eq!(decoded[2].operand, Operand::Var(0));
        assert_eq!(decoded[3].operand, Operand::I32(-1));
        assert_eq!(decoded[4].operand, Operand::I32(8));
        assert_eq!(decoded[5].operand, Operand::None);
        assert!(decoded.iter().all(|i| i.size == 1));
    }

    #[test]
    fn short_forms_are_widened() {
        // ldarg.s 3; ldc.i4.s -5; br.s +2; nop; nop
        let code = [0x0E, 0x03, 0x1F, 0xFB, 0x2B, 0x02, 0x00, 0x00];
        let decoded: Vec<_> = InstructionIter::new(&code).map(|i| i.unwrap()).collect();
        assert_eq!(decoded[0].operand, Operand::Var(3));
        assert_eq!(decoded[1].operand, Operand::I32(-5));
        assert_eq!(decoded[2].operand, Operand::BranchTarget(8));
        assert_eq!(decoded[2].opcode, OpCode::BrS);
    }

    #[test]
    fn branch_targets_are_absolute() {
        // br +0 at offset 0 (5 bytes) -> target 5
        let code = [0x38, 0x00, 0x00, 0x00, 0x00, 0x2A];
        let i = decode_at(&code, 0).unwrap();
        assert_eq!(i.operand, Operand::BranchTarget(5));
        // A negative delta wraps backwards.
        let code = [0x00, 0x2B, 0xFD];
        let i = decode_at(&code, 1).unwrap();
        assert_eq!(i.operand, Operand::BranchTarget(0));
    }

    #[test]
    fn switch_targets_are_absolute_and_bounded() {
        // switch (2) { +1, -1 }; nop; nop
        let mut code = alloc::vec![0x45u8];
        code.extend_from_slice(&2u32.to_le_bytes());
        code.extend_from_slice(&1i32.to_le_bytes());
        code.extend_from_slice(&(-1i32).to_le_bytes());
        code.push(0x00);
        let i = decode_at(&code, 0).unwrap();
        assert_eq!(i.size, 13);
        assert_eq!(i.operand, Operand::Switch(alloc::vec![14, 12]));

        // A count larger than the remaining code must not allocate.
        let mut bad = alloc::vec![0x45u8];
        bad.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert_eq!(decode_at(&bad, 0).unwrap_err().kind, ErrorKind::Truncated);
    }

    #[test]
    fn sizes_sum_to_the_code_length() {
        // A mixture of operand shapes.
        let mut code = alloc::vec![0x00u8, 0x2A];
        code.extend_from_slice(&[0x20, 0x01, 0x00, 0x00, 0x00]); // ldc.i4 1
        code.extend_from_slice(&[0x21, 1, 0, 0, 0, 0, 0, 0, 0]); // ldc.i8 1
        code.extend_from_slice(&[0x22, 0, 0, 0x80, 0x3F]); // ldc.r4 1.0
        code.extend_from_slice(&[0x23, 0, 0, 0, 0, 0, 0, 0xF0, 0x3F]); // ldc.r8 1.0
        code.extend_from_slice(&[0xFE, 0x09, 0x01, 0x00]); // ldarg 1
        let total: u32 = InstructionIter::new(&code).map(|i| i.unwrap().size).sum();
        assert_eq!(total as usize, code.len());
    }

    #[test]
    fn an_unknown_opcode_stops_the_iterator() {
        let code = [0x00, 0xFF, 0x00];
        let items: Vec<_> = InstructionIter::new(&code).collect();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        let e = items[1].as_ref().unwrap_err();
        assert_eq!(e.kind, ErrorKind::UnknownOpcode);
        assert_eq!(e.offset, Some(1));
    }

    #[test]
    fn a_truncated_operand_is_reported_at_its_offset() {
        let code = [0x20, 0x01];
        let e = decode_at(&code, 0).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Truncated);
        assert_eq!(e.offset, Some(1));
    }

    #[test]
    fn folding_attaches_prefixes() {
        // volatile. ldfld <field>; ret
        let mut code = alloc::vec![0xFE, 0x13, 0x7B];
        code.extend_from_slice(&0x0400_0001u32.to_le_bytes());
        code.push(0x2A);
        let folded: Vec<_> = FoldedIter::new(&code).map(|i| i.unwrap()).collect();
        assert_eq!(folded.len(), 2);
        assert!(folded[0].prefixes.volatile);
        assert_eq!(folded[0].first_offset, 0);
        assert_eq!(folded[0].instruction.opcode, OpCode::Ldfld);
        assert_eq!(folded[0].total_size(), 7);
        assert!(folded[1].prefixes.is_empty());
    }

    #[test]
    fn folding_rejects_an_illegal_prefix_target() {
        // volatile. ret
        let code = [0xFE, 0x13, 0x2A];
        let items: Vec<_> = FoldedIter::new(&code).collect();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].as_ref().unwrap_err().kind, ErrorKind::InvalidPrefixTarget);
        // The raw iterator does not care.
        assert_eq!(InstructionIter::new(&code).filter(|i| i.is_ok()).count(), 2);
    }

    #[test]
    fn folding_rejects_a_prefix_at_the_end_of_the_code() {
        // volatile. with nothing after it modifies nothing.
        let code = [0x00, 0xFE, 0x13];
        let items: Vec<_> = FoldedIter::new(&code).collect();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        let e = items[1].as_ref().unwrap_err();
        assert_eq!(e.kind, ErrorKind::InvalidPrefixTarget);
        assert_eq!(e.offset, Some(1));
        // The raw iterator still yields both instructions.
        assert_eq!(InstructionIter::new(&code).filter(|i| i.is_ok()).count(), 2);
    }

    #[test]
    fn folding_an_empty_range_yields_nothing() {
        assert_eq!(FoldedIter::new(&[]).count(), 0);
    }

    #[test]
    fn folding_rejects_duplicate_prefixes() {
        // volatile. volatile. ldfld
        let mut code = alloc::vec![0xFE, 0x13, 0xFE, 0x13, 0x7B];
        code.extend_from_slice(&0u32.to_le_bytes());
        let items: Vec<_> = FoldedIter::new(&code).collect();
        assert_eq!(items[0].as_ref().unwrap_err().kind, ErrorKind::Malformed);
    }

    #[test]
    fn constrained_must_precede_a_call() {
        let mut ok = alloc::vec![0xFE, 0x16];
        ok.extend_from_slice(&0x0100_0001u32.to_le_bytes());
        ok.push(0x6F); // callvirt
        ok.extend_from_slice(&0x0A00_0001u32.to_le_bytes());
        let folded = FoldedIter::new(&ok).next().unwrap().unwrap();
        assert_eq!(folded.prefixes.constrained, Some(Token(0x0100_0001)));

        // `constrained. call` is what Roslyn emits for a static abstract
        // interface member, so it is accepted even though ECMA-335 6th edition
        // names only `callvirt`.
        let mut static_virtual = alloc::vec![0xFE, 0x16];
        static_virtual.extend_from_slice(&0x0100_0001u32.to_le_bytes());
        static_virtual.push(0x28); // call
        static_virtual.extend_from_slice(&0x0A00_0001u32.to_le_bytes());
        assert!(FoldedIter::new(&static_virtual).next().unwrap().is_ok());

        let mut bad = alloc::vec![0xFE, 0x16];
        bad.extend_from_slice(&0x0100_0001u32.to_le_bytes());
        bad.push(0x2A); // ret
        assert_eq!(
            FoldedIter::new(&bad).next().unwrap().unwrap_err().kind,
            ErrorKind::InvalidPrefixTarget
        );
    }

    #[test]
    fn the_no_prefix_decodes_its_mask() {
        // no. 0x05 castclass <type>
        let mut code = alloc::vec![0xFE, 0x19, 0x05, 0x74];
        code.extend_from_slice(&0x0200_0001u32.to_le_bytes());
        let folded = FoldedIter::new(&code).next().unwrap().unwrap();
        assert!(folded.prefixes.no.typecheck);
        assert!(!folded.prefixes.no.rangecheck);
        assert!(folded.prefixes.no.nullcheck);
    }

    #[test]
    fn decoding_any_byte_string_terminates_without_panicking() {
        // Exercise the decoder over a deterministic pseudo-random corpus.
        let mut state = 0x1234_5678u32;
        for _ in 0..2_000 {
            let mut code = alloc::vec![0u8; 64];
            for byte in code.iter_mut() {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 24) as u8;
            }
            let mut total = 0u64;
            for item in InstructionIter::new(&code) {
                match item {
                    Ok(i) => {
                        assert!(i.size > 0);
                        total += u64::from(i.size);
                    }
                    Err(_) => break,
                }
            }
            assert!(total <= code.len() as u64);
            for item in FoldedIter::new(&code) {
                if item.is_err() {
                    break;
                }
            }
        }
    }

    #[test]
    fn stack_behaviour_counts_are_consistent() {
        assert_eq!(OpCode::Add.info().pop.count(), Some(2));
        assert_eq!(OpCode::Add.info().push.count(), Some(1));
        assert_eq!(OpCode::Call.info().pop.count(), None);
        assert_eq!(OpCode::Ret.info().flow, FlowControl::Return);
        assert_eq!(OpCode::Br.info().flow, FlowControl::Branch);
        assert_eq!(OpCode::Brtrue.info().flow, FlowControl::CondBranch);
        assert_eq!(OpCode::Throw.info().flow, FlowControl::Throw);
        assert!(OpCode::Volatile.is_prefix());
        assert!(!OpCode::Nop.is_prefix());
    }
}
