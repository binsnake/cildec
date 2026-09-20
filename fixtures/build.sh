#!/usr/bin/env bash
# Rebuilds the fixtures and their golden dumps. Run from anywhere.
#
# The .NET SDK version is pinned by global.json; see fixtures/README.md for why
# a different patch level changes the output.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "building Features.dll"
dotnet build fixtures/src/Features -c Release -o "$tmp/features" --nologo
cp "$tmp/features/Features.dll" fixtures/Features.dll

echo "building IlFeatures.dll"
dotnet run --project tools/gen-fixtures -- fixtures/IlFeatures.dll

echo "regenerating golden dumps"
mkdir -p fixtures/golden
for name in Features IlFeatures; do
  dotnet run --project tools/gen-golden -- "fixtures/$name.dll" > "fixtures/golden/$name.txt"
done

echo "re-seeding the fuzz corpus"
cargo run --release --quiet --example corpus-pack -- unpack fuzz/corpus
for name in Features IlFeatures; do
  cargo run --release --example seed-corpus -- "fixtures/$name.dll" fuzz/corpus
done
cargo run --release --quiet --example corpus-pack -- pack fuzz/corpus

echo "done; run 'cargo test' to check the golden comparison"
