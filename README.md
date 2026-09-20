# cildec

A zero-dependency, panic-free decoder for **ECMA-335 metadata and CIL method
bodies**.

`cildec` reads a managed PE image — or a bare metadata blob — and exposes its
tables, heaps, signatures, method bodies and exception-handling tables as typed,
bounds-checked Rust values. It then decodes CIL into a typed instruction stream
with exact byte offsets and sizes, absolute branch targets, folded prefixes, and
the per-opcode static facts from ECMA-335 Partition VI, Annex C.

It is a *decoder*, not a runtime: it does not simulate the stack, build control
flow graphs, verify IL, or resolve across assemblies. It gives a consumer the
bytes as structures, accurately, on input it does not trust.

```toml
[dependencies]
cildec = "0.1"
```

## At a glance

- **Zero required dependencies.** `serde` is optional; `std` is on by default
  and only gates a file-reading convenience.
- **`#![forbid(unsafe_code)]`**, no reachable panic on any input, and no
  allocation sized by a declared count that has not been checked against the
  bytes that remain.
- **Lazy.** Opening an image parses headers and the table directory only.
- **Deterministic.** No hash-map iteration affects any output.
- **MSRV 1.85**, edition 2024, builds for `wasm32-unknown-unknown`.

## Example

Open an image, find a method by name, and print its instructions with resolved
call targets:

```rust,no_run
use cildec::{MethodBody, Names, PeImage, Rid, tables::MethodDefRow};

fn main() -> Result<(), cildec::Error> {
    let bytes = std::fs::read("Example.dll").unwrap();
    let image = PeImage::parse(&bytes)?;
    let metadata = image.metadata()?;
    let names = Names::new(&metadata);

    for (rid, row) in metadata.tables().iter::<MethodDefRow>() {
        let row = row?;
        if metadata.strings().str_opt(row.name) != Some("Main") {
            continue;
        }
        let Some(body) = MethodBody::from_image(&image, &row)? else { continue };
        println!("{}", names.method_def_full(Rid::new(rid))?);
        for folded in body.folded_instructions() {
            let instruction = folded?.instruction;
            print!("  IL_{:04x}: {}", instruction.offset, instruction.opcode.name());
            if let Some(token) = instruction.operand.token() {
                print!(" {}", names.token(token));
            }
            println!();
        }
    }
    Ok(())
}
```

There is a fuller version in [`examples/dump.rs`](examples/dump.rs):

```bash
cargo run --example dump -- Example.dll Main
```

## What it covers

| Area | ECMA-335 | Notes |
|-|-|-|
| PE container, CLI header | II.25 | PE32 and PE32+, RVA translation, every directory range exposed |
| Metadata root, streams | II.24.2.1–2 | `#~`, `#-`, `#Strings`, `#US`, `#Blob`, `#GUID`, plus unknown streams as ranges |
| Tables | II.22, II.24.2.6 | All of `0x00`–`0x2C` and the Portable PDB tables `0x30`–`0x37`, typed |
| Sorted-table lookups | II.22 | Binary search with a verified-sortedness fallback to a linear scan |
| Signatures | II.23.1–2 | Method, field, property, local, `MethodSpec`, `TypeSpec`, depth-bounded |
| Method bodies, EH | II.25.4 | Tiny and fat headers, small and fat EH sections, chained `MoreSects` |
| Instructions | III, VI.C | All 219 opcodes and prefixes, absolute branch targets, prefix folding |

## Strictness and real-world images

Real images deviate from the 2012 text. `Strictness::Permissive` (the default)
accepts the deviations below and records each as a `Diagnostic`;
`Strictness::Strict` rejects everything the specification rejects.

- Fat method headers whose declared size is not 3 dwords.
- Heaps with trailing garbage, invalid UTF-8, or unaligned sizes.
- Stream names without the NUL padding II.24.2.2 describes.
- Duplicate and unknown stream names; the first `#~`/`#-` wins and the rest are
  exposed as ranges.
- Present-flag bits for reserved table ids with zero rows.
- Tables the specification marks sorted that are not; lookups fall back to a
  linear scan rather than returning a wrong answer.
- A `MethodDef` RVA outside every section, which is a per-method error.
- Exception clauses with zero-length ranges or illegal nesting: `parse`
  succeeds so the code stays readable, and `validate_handlers` reports them.
- An exception section whose `DataSize` omits its own 4-byte header, which some
  Visual Basic compilers wrote. Reading it as the specification defines silently
  drops the last clause of every such section, so the two readings are told
  apart by arithmetic: a conforming size is always `n*12+4`, never a multiple
  of the clause size.
- `ELEMENT_TYPE_INTERNAL`, reported as `Unsupported` rather than misparsed.
- `32BITPREFERRED` without `32BITREQUIRED`; both flags are exposed.

One deviation is accepted in **both** modes, because the runtime defines the
language in practice: `constrained.` may precede `call` and `ldftn`, not only
`callvirt`. Static abstract interface members make `constrained. call` ordinary
compiler output.

## Testing

- Unit tests at every boundary the format defines: compressed integers at each
  encoding width, coded-index widths on both sides of each tag-bit threshold,
  heap index widths for every `HeapSizes` combination, tiny and fat headers,
  small and fat EH sections, `#-` streams with `*Ptr` indirection.
- An exhaustive opcode test that walks every encoding `0x00..=0xFF` and
  `0xFE 0x00..=0xFF` and checks size and round-trip.
- **Golden tests** comparing checked-in fixtures field by field against dumps
  produced by System.Reflection.Metadata.
- **Differential tests** running that same comparison against every .NET
  assembly on the machine — shared frameworks of every installed version,
  reference packs, the .NET Framework directories back to 1.x, and the GAC.
  On the development machine that is 4283 assemblies spanning metadata written
  from 2005 to 2026, compared line by line: types, signatures, layouts, locals,
  every instruction, every exception clause, and the rows of nineteen further
  tables.
- **Invariant tests** that need no reference implementation: a binary search
  over a sorted table must agree with a linear scan of the same column, a member
  reached through a list column must name the same owner in reverse, and every
  coded index must survive a decode and re-encode. Checked over 4286 real
  assemblies.
- **Fuzzing** with `cargo-fuzz` over five targets, with the corpus committed
  (one `.pack` per target) and replayed by `cargo test`.
- A **large-image smoke test** that walks every method body of a real
  `System.Private.CoreLib.dll` and asserts the instruction sizes tile the code
  exactly.

```bash
cargo test                                   # everything but the fuzzers
CILDEC_DIFF_ALL=1 cargo test --release --test differential -- --nocapture
CILDEC_DIFF_ALL=1 cargo test --release --test invariants -- --nocapture
CILDEC_SMOKE_DIR=/usr/share/dotnet cargo test --release --test smoke
fuzz/run-all.sh 300                          # a short fuzzing session
```

The differential test skips itself when no .NET SDK is installed, and by
default compares only the newest shared framework; `CILDEC_DIFF_ALL=1` compares
every installed version, and `CILDEC_DIFF_DIR` points it at any other directory
of assemblies.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo test --all-features && cargo test --release
cargo build --no-default-features
cargo +1.85 check --all-targets            # the MSRV
cargo check --target wasm32-unknown-unknown
cargo tree --no-default-features --edges normal   # must list this crate alone
```

`src/il/table.rs` is generated from the runtime's own opcode table and must not
be hand-edited; CI checks that it regenerates identically. `no.` is the one
opcode absent from `System.Reflection.Emit.OpCodes`, so the generator injects
it from ECMA-335 III.2.2.

```bash
dotnet run --project tools/gen-opcodes > src/il/table.rs
fixtures/build.sh                       # rebuild fixtures and golden dumps
fuzz/run-all.sh 300                     # a short fuzzing session
```

The fixtures are committed binaries built by the .NET SDK pinned in
`global.json`, with `Deterministic=true` so a rebuild from the same source and
SDK is byte-identical. A different SDK patch level usually changes the output;
regenerate the golden dumps in the same commit when that happens.

The dump format can only carry what *both* readers can express. Two gaps are
marked in `tests/common/dump.rs`: System.Reflection.Metadata cannot distinguish
a missing `ClassLayout` row from one of zeros, nor a missing `FieldRVA` row
from one that says zero, so degenerate rows are skipped on both sides. Three
tables (`FieldMarshal`, `MethodSemantics`, `NestedClass`) have no row
enumeration there and are reached through the members that own them.

The fuzz corpora are committed as one `fuzz/corpus/<target>.pack` per target —
a repeated `[u32 little-endian length][bytes]`, read by `tests/corpus.rs`
without any dependency. `fuzz/run-all.sh` unpacks before and repacks after. On
Windows the AddressSanitizer runtime libFuzzer links against is not on `PATH`;
that script adds the Visual Studio copy when it finds one.

Anything that trips a fuzz target lands in `fuzz/artifacts/<target>/`. Commit
it: `tests/corpus.rs` replays that directory on stable, so a committed crash
becomes a permanent regression test needing no nightly.

House rules for the parser: no `unsafe`, no reachable panic from the public API
on any input, never allocate on a declared count before checking it against the
bytes that remain, every loop over input makes progress, and no `HashMap`
iteration in a path that affects output.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
