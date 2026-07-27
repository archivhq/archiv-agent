#!/usr/bin/env bash
# lint-no-clone — the Memory Law gate (docs/engineering/02-rust-standards.md §2).
#
# Two layers:
#   1. cargo clippy with clippy.toml disallowed-methods (String::from_utf8,
#      ToOwned::to_owned) at deny level.
#   2. grep for the deep-copy calls clippy cannot target on this toolchain
#      (`.to_vec(`, `.clone()`) in non-test pipeline sources. Sanctioned
#      refcount clones (`Bytes`, `Arc`) written as `Bytes::clone(&x)` /
#      `Arc::clone(&x)` are exempt — the explicit form is mandatory so the
#      gate can tell them apart from payload deep copies.
#
# Two reviewer-visible line markers exempt a single line (engineering/02 §2):
#   // SAFETY-PERF:   a sanctioned clone on the payload path, citing the arch
#                     doc section - triggers data-handling compliance review.
#   // NOT-A-PAYLOAD: a clone of provably non-payload data (config strings,
#                     rule ids in error messages) - outside the Memory Law.
# Every crate is still fully swept; each exemption is explicit and per-line.

set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> clippy layer (disallowed-methods, deny warnings)"
cargo clippy --all-targets --all-features -- -D warnings

echo "==> grep layer (payload deep-copy calls in non-test pipeline sources)"
fail=0
for f in crates/*/src/*.rs crates/*/src/**/*.rs; do
  [ -e "$f" ] || continue
  hits=$(awk '
    /#\[cfg\(test\)\]/ { exit }          # test modules sit below this marker
    /SAFETY-PERF:/     { next }          # sanctioned payload-path clone (review-tracked)
    /NOT-A-PAYLOAD:/   { next }          # provably non-payload clone (config/diagnostic)
    /Bytes::clone|Arc::clone/ { next }   # sanctioned refcount clones
    /^[[:space:]]*\/\// { next }         # comments
    /\.to_vec\(|\.clone\(\)/ { printf "%d: %s\n", FNR, $0 }
  ' "$f")
  if [ -n "$hits" ]; then
    while IFS= read -r line; do echo "DENY: $f:$line"; done <<<"$hits"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "lint-no-clone: payload deep-copy calls found (docs/architecture/core/02 §3.3)." >&2
  exit 1
fi
echo "lint-no-clone: clean"
