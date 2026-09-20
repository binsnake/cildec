#!/usr/bin/env bash
# Runs every fuzz target for a fixed wall-clock budget, in parallel.
#
#     fuzz/run-all.sh [seconds-per-target]
#
# Requires a nightly toolchain and cargo-fuzz:
#
#     rustup toolchain install nightly
#     cargo install cargo-fuzz --locked
#
# On Windows the AddressSanitizer runtime that libFuzzer links against is not on
# PATH by default; the block below adds the MSVC copy when it is present.
set -euo pipefail

seconds="${1:-14400}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

if [[ "${OS:-}" == "Windows_NT" ]]; then
  for candidate in "/c/Program Files/Microsoft Visual Studio/2022"/*/VC/Tools/MSVC/*/bin/Hostx64/x64; do
    if [[ -f "$candidate/clang_rt.asan_dynamic-x86_64.dll" ]]; then
      export PATH="$candidate:$PATH"
      break
    fi
  done
fi

# The committed corpora are one .pack per target; libFuzzer needs directories.
echo "unpacking corpora"
(cd .. && cargo run --release --quiet --example corpus-pack -- unpack fuzz/corpus)

mkdir -p logs
targets=(pe metadata body signature il)
pids=()

for target in "${targets[@]}"; do
  echo "starting $target for ${seconds}s"
  cargo +nightly fuzz run "$target" -- \
    -max_total_time="$seconds" \
    -rss_limit_mb=4096 \
    -print_final_stats=1 \
    >"logs/$target.log" 2>&1 &
  pids+=("$!")
done

status=0
for i in "${!pids[@]}"; do
  if wait "${pids[$i]}"; then
    echo "${targets[$i]}: clean"
  else
    echo "${targets[$i]}: FAILED (see logs/${targets[$i]}.log and artifacts/${targets[$i]}/)"
    status=1
  fi
done

# Fold whatever the session found back into the committed packs. Entries are
# written in sorted content order, so an unchanged corpus produces no diff.
echo "repacking corpora"
(cd .. && cargo run --release --quiet --example corpus-pack -- pack fuzz/corpus)

exit "$status"
