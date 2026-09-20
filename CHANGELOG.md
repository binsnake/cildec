# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Exception clauses were silently dropped** from any method whose exception
  section declared a `DataSize` that omitted the section header. ECMA-335
  II.25.4.5 defines that size as `n*12+4`, counting the 4-byte header, but some
  Visual Basic compilers wrote `n*12`. Reading it as specified loses the last
  clause of every such section — a missing `finally` in five shipped
  framework assemblies. A conforming size is never a multiple of the clause
  size, so the two readings are distinguished exactly, with no risk of
  reinterpreting a valid section.
- `Names` printed a custom modifier on a by-reference parameter or return type
  in the wrong place. `Param ::= CustomMod* [BYREF] Type` (II.23.2.10) puts the
  modifier on the reference, not on the referent, so `in T` now renders as
  `!0& modreq(InAttribute)` rather than `!0 modreq(InAttribute)&`.
- `Names` printed a group of custom modifiers in blob order. Each modifier
  wraps what follows it, so the first in the blob is outermost and is spelled
  last in ILAsm suffix form. `CustomMod` lists still carry the encoded order.

### Added

- `Names::local`, `Names::param` and `Names::field_sig`, so the nesting order of
  `pinned`, `byref` and custom modifiers lives in the library rather than in
  each caller. All three were places where a caller could get the order wrong
  silently.

- `tests/differential.rs`, which compares cildec against
  System.Reflection.Metadata over every .NET assembly on the machine — shared
  frameworks of every installed version, reference packs, the .NET Framework
  directories back to 1.x, and the GAC. On the development machine that is 4283
  assemblies and 4.2 million method bodies, spanning metadata written from 2005
  to 2026. The comparison covers the rows of nineteen tables beyond the type
  walk, including every signature blob, `Constant` values, the coded-index
  columns as raw tokens, properties with their `PropertySig`, events, accessors
  and marshalling descriptors.
- `tests/invariants.rs`, which checks the properties cildec must satisfy
  against itself over the same assemblies and needs no reference reader: a
  binary search over a sorted table against a linear scan of the same column,
  list ranges against owner lookups in both directions, every coded index
  round-tripped through decode and encode, instruction boundaries against the
  offset list, and a census of what strict mode rejects.
- `Tables::sort_key_column` and the free `sort_key_column`, which name the
  column a sorted table is ordered by, so a caller can verify the ordering or
  scan the column without guessing its index.

## [0.1.0] - 2026-09-20

First release. Reads ECMA-335 metadata and decodes CIL method bodies.

### Added

- **PE container** (II.25): `PeImage` for PE32 and PE32+, the section table, RVA
  translation, the data directories, and the CLI header with every directory
  range exposed, including the ones this crate does not decode (managed
  resources, the strong-name signature, vtable fixups, the ReadyToRun header).
- **Metadata root and streams** (II.24.2.1–2): `Metadata` over `#~` and `#-`,
  the four heaps, and unknown streams exposed as named ranges.
- **Heaps** (II.24.2.2–5): `#Strings` with both bytes and checked UTF-8, `#US`
  with raw UTF-16 code units and a lossy helper, `#Blob`, and `#GUID`.
- **Tables** (II.22, II.24.2.6): every table `0x00`–`0x2C` and the Portable PDB
  tables `0x30`–`0x37` as typed `Copy` rows, with row sizes and index widths
  computed from the stream header, `*Ptr` indirection applied by the typed
  accessors and bypassed by the raw ones, and `ExtraData` honoured.
- **Sorted-table lookups** (II.22): owner and parent lookups by binary search,
  with sortedness verified at parse time and a linear-scan fallback when an
  image lies about it.
- **Signatures** (II.23.1–2): compressed integers, and parsers for method,
  field, property, local-variable, `MethodSpec` and `TypeSpec` signatures, with
  a configurable recursion limit and blob-relative error offsets.
- **Method bodies** (II.25.4): tiny and fat headers, small and fat exception
  sections, chained `MoreSects`, unknown sections kept as bytes, and
  `validate_handlers` separate from `parse` so malformed exception tables still
  leave the code readable.
- **Instruction decoder** (III, VI.C): all 219 opcodes and prefixes with their
  static stack and flow facts, absolute branch and `switch` targets, widened
  short and macro operands, `canonical()`, and prefix folding that rejects an
  illegal prefix target.
- **Names** (`display`): qualified type names, token names, and an ILAsm-style
  signature printer, for error messages and test assertions.
- `Strictness` on every parser, with a `Diagnostic` list recording each
  tolerated deviation.
- Optional `serde` support behind the `serde` feature.

### Notes

- `constrained.` is accepted before `call` and `ldftn` in both strictness modes,
  not only `callvirt` as ECMA-335 6th edition says. Static abstract interface
  members make `constrained. call` ordinary compiler output, and the runtime
  accepts it.
- `Instruction::size` is a `u32` rather than the `u8` a fixed-size instruction
  would need, because a `switch` with more than 62 targets is longer than 255
  bytes.
- `ELEMENT_TYPE_INTERNAL` is reported as `Unsupported`. The `Type::Internal`
  variant exists for callers building their own types but is never produced by
  the parsers.
- A tiny method header reports `FatFlags(0)`: its remaining six bits are the
  code size, so it carries no `InitLocals` or `MoreSects` flag.
- `Names` caps token resolution at `Names::MAX_DEPTH` hops. Hostile metadata can
  make `TypeRef` scopes or `TypeSpec` signatures cyclic; beyond the cap a name
  renders as `Table[rid]` rather than recursing.
- A prefix with no instruction after it is an `InvalidPrefixTarget` from the
  folded iterator; the raw iterator still yields it as its own instruction.

[Unreleased]: https://github.com/binsnake/cildec/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/binsnake/cildec/releases/tag/v0.1.0
