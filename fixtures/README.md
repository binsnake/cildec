# Fixtures

Two small assemblies and their golden dumps. Both are checked in, because the
point of a fixture is that the test compares against bytes that did not change
when the decoder did.

| File | Built from | Built by |
|-|-|-|
| `Features.dll` | `src/Features/Features.cs` | the C# compiler in the pinned .NET SDK |
| `IlFeatures.dll` | `../tools/gen-fixtures/Program.cs` | `PersistedAssemblyBuilder` in the pinned .NET SDK |
| `golden/Features.txt` | `Features.dll` | `../tools/gen-golden` |
| `golden/IlFeatures.txt` | `IlFeatures.dll` | `../tools/gen-golden` |

## Provenance and reproducibility

The SDK is pinned by `../global.json` to **10.0.401**. `Features.csproj` sets
`Deterministic=true` and `DebugType=none`, so a rebuild from the same source
with the same SDK is byte-identical, MVID included. A different SDK patch level
will usually produce a different binary; when that happens, regenerate the
golden dumps in the same commit and say so in the changelog.

Regenerate everything from the repository root:

```bash
fixtures/build.sh          # or fixtures\build.ps1 on Windows
```

That runs, in order:

```bash
dotnet build fixtures/src/Features -c Release -o <tmp> && cp <tmp>/Features.dll fixtures/
dotnet run --project tools/gen-fixtures -- fixtures/IlFeatures.dll
dotnet run --project tools/gen-golden  -- fixtures/Features.dll   > fixtures/golden/Features.txt
dotnet run --project tools/gen-golden  -- fixtures/IlFeatures.dll > fixtures/golden/IlFeatures.txt
```

## How independent is the golden dump?

`tools/gen-golden` reads metadata, signatures, layouts and exception tables with
**System.Reflection.Metadata**, an implementation this crate shares no code and
no lineage with. Instruction mnemonics and operand shapes come from
**System.Reflection.Emit.OpCodes**, the runtime's own opcode table. So the
comparison is a genuine cross-check of the metadata and opcode data.

Two honest caveats:

1. The IL *walk* in `gen-golden` is written by hand in that tool, because
   System.Reflection.Metadata has no disassembler and `ildasm` emits a format
   too far from this one to normalise usefully. The walk is driven by the
   runtime's operand-shape table, so a wrong operand width is still caught; a
   shared misreading of ECMA-335 by both walks would not be.
2. `no.` (`0xFE 0x19`) is absent from `System.Reflection.Emit.OpCodes`. Both
   sides therefore take that one encoding from ECMA-335 III.2.2 directly. The
   same gap is why `tools/gen-opcodes` injects it: the generated table has 218
   opcodes from the runtime plus this one, for the 219 that VI.C defines.

The text format is line-oriented and shared by both sides; `tests/golden.rs`
compares it line by line and prints the first difference with context.

## What each fixture covers

`Features.cs` (C#):

- generic type with constraints, generic method, nested types two levels deep
- explicit and sequential layout, `FieldOffset`, packing
- P/Invoke with and without marshalling descriptors
- function pointers, multi-dimensional arrays, pointers, byrefs, pinned locals
- a field with an RVA (`ReadOnlySpan<byte>` initialiser)
- every short `ldc.i4` form, checked and unchecked conversions
- string literals including non-ASCII, a dense `switch`
- nested try/finally with `leave` chains, a catch with a filter
- `constrained. callvirt`, a `volatile.` read
- interface with an explicit implementation, events, properties, an indexer,
  custom attributes at assembly, type and method scope

`gen-fixtures` (`System.Reflection.Emit`), for what C# will not emit:

- a `vararg` method and a call site with a `SENTINEL`
- `calli` through a `StandAloneSig`
- a `fault` handler, and a filter nested inside a `finally`
- `tail. call`
- `no. { typecheck | nullcheck }`, hand-encoded
- an explicit `switch` jump table
- every `ldc` encoding and every `conv` opcode
- `unaligned.` + `volatile.` on a store, `initblk`, `cpblk`, `localloc`

`tests/golden.rs` asserts this coverage directly, so removing a feature from a
fixture fails the test rather than quietly shrinking it.

## The `#-` fixture

The uncompressed (edit-and-continue) table stream and its `*Ptr` indirection
tables are built byte by byte in `tests/enc.rs` rather than committed here. No
compiler emits such an image on demand, and the layout is small enough that
spelling it out in the test is clearer than a binary blob and needs no external
tool to reproduce.
