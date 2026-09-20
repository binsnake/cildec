# Contributing

## The commands CI runs

Run these before opening a pull request; they are exactly what
`.github/workflows/ci.yml` runs.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo test --all-features
cargo test --release
CILDEC_DIFF_ALL=1 cargo test --release --test differential
CILDEC_DIFF_ALL=1 cargo test --release --test invariants
cargo build --no-default-features
cargo +1.85 check --all-targets
cargo check --target wasm32-unknown-unknown
cargo tree --no-default-features --edges normal
```

On Windows PowerShell, set `RUSTDOCFLAGS` with `$env:RUSTDOCFLAGS = '-D warnings'`.

The MSRV is **1.85** and is checked in CI. `cargo tree` must show no non-dev
dependencies when no features are enabled; adding one is a breaking change to
the crate's contract, not a detail.

## Fuzzing

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
fuzz/run-all.sh 300          # a short session; CI uses 60 seconds per target
```

On Windows the AddressSanitizer runtime libFuzzer links against is not on
`PATH` by default; `fuzz/run-all.sh` adds the Visual Studio copy when it finds
one. Without it the targets fail to start with `STATUS_DLL_NOT_FOUND`.

### The corpus is packed

The corpora are committed as one `fuzz/corpus/<target>.pack` per target, not as
directories of loose files: coverage-minimal is still nearly seven thousand
inputs averaging under 500 bytes, which costs about four times its own size in
filesystem slack and makes a checkout mostly corpus.

`fuzz/run-all.sh` unpacks before fuzzing and repacks afterwards, so the normal
workflow never touches the format. To do it by hand:

```bash
cargo run --release --example corpus-pack -- unpack fuzz/corpus
cargo run --release --example corpus-pack -- pack   fuzz/corpus
```

The format is a repeated `[u32 little-endian length][bytes]`, chosen so that
`tests/corpus.rs` can read it with no dependency. Packing writes entries in
sorted content order, so repacking an unchanged corpus produces no diff. The
unpacked `fuzz/corpus/<target>/` directories are git-ignored.

Any input that trips a target lands in `fuzz/artifacts/<target>/`. Commit it as
a loose file: `tests/corpus.rs` replays the packs, the unpacked directories and
`fuzz/artifacts` on stable, so a committed crash becomes a permanent regression
test that needs no nightly.

When you change a fuzz target, change its twin in `tests/corpus.rs` so the
replay keeps checking the same invariants.

## Differential testing

`tests/differential.rs` builds `tools/gen-golden`, dumps every assembly of every
installed .NET shared framework with System.Reflection.Metadata, dumps the same
assemblies with cildec, and compares them line by line. It needs a .NET SDK and
skips itself without one.

That comparison is the strongest correctness signal this project has: a
difference in any signature, layout, local, instruction operand or exception
clause shows up as a line that does not match. When it fails it writes the
cildec side beside the reference as `<index>.actual.txt` under
`target/differential/dumps`, so the two can be diffed directly.

Both dumpers share `tests/common/dump.rs` for the cildec side and the format it
prints; changing the format means changing `tools/gen-golden` to match, and
regenerating the committed fixture dumps with `fixtures/build.sh`.

The format can only carry what *both* readers can express. Two known gaps are
marked in the dumper: the reference reader cannot distinguish a missing
`ClassLayout` row from one of zeros, nor a missing `FieldRVA` row from one that
says zero, so degenerate rows are skipped on both sides. Three tables
(`FieldMarshal`, `MethodSemantics`, `NestedClass`) have no row enumeration
there at all and are reached through the members that own them instead.

`tests/invariants.rs` is the other half, and needs no reference reader: it
checks the properties cildec must satisfy against itself over the same
assemblies. Prefer adding to it when a property can be stated without a second
implementation, because it runs everywhere.

## Fixtures and golden dumps

The fixtures under `fixtures/` are committed binaries with committed dumps. See
[`fixtures/README.md`](fixtures/README.md) for the build recipe, the SDK pin,
and what each fixture is for. Regenerate with `fixtures/build.sh`.

A golden dump changing is a signal, not a chore: explain in the pull request why
the decoder now reports something different, and prefer adding a fixture over
loosening an assertion.

## The opcode table

`src/il/table.rs` is generated and must not be hand-edited:

```bash
dotnet run --project tools/gen-opcodes > src/il/table.rs
```

It is derived from `System.Reflection.Emit.OpCodes` so that no opcode fact is
transcribed by hand, with one documented exception: `no.` is absent from that
table and is injected by the generator from ECMA-335 III.2.2.

## What this crate will not do

The scope is deliberately closed. Stack simulation, control-flow graphs, IL
verification, cross-assembly resolution, custom-attribute blob decoding and
writing are all out. If you need one of those, the right shape is a crate that
depends on this one.

## House rules for the parser

This is a parser of untrusted bytes, so a few rules are not negotiable:

- No `unsafe`, enforced by `#![forbid(unsafe_code)]`.
- No reachable panic from the public API on any input. Slice with `get`,
  arithmetic with `checked_*` or an explicit `wrapping_*`, and never index with
  a value that came from the input.
- Never allocate on the basis of a declared count before checking it against the
  bytes that remain. Every element costs at least one byte, so the remaining
  length is always an upper bound on a count.
- Every loop over input must make progress on every iteration.
- No `HashMap` iteration in a path that affects output; two runs over the same
  bytes must produce identical results in identical order.
- `debug_assert!` is for internal invariants only, never for input validation.

New public items need rustdoc, and module docs name the ECMA-335 section they
implement. Where the crate deviates from the specification because a real image
does, say so at the point that handles it as well as in the README.
