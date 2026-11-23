#!/usr/bin/env bash
# Local quality gates — replaces .github/workflows/ci.yml (deleted per the
# owner mandate: zero GitHub Actions; see issue #4).
#
# Required before every push/PR. All green or don't push.
#   ./scripts/gates.sh
#
# Mirrors every deleted CI job:
#   check -> cargo fmt --check, clippy (-D warnings), check --all-targets
#   test  -> cargo test
#   audit -> cargo audit (fails closed if cargo-audit is not installed)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

export CARGO_BUILD_JOBS=2

echo "==> fmt"
cargo fmt --all -- --check

echo "==> clippy"
cargo clippy --locked --all-targets --jobs 2 -- -D warnings

echo "==> check"
cargo check --locked --all-targets --jobs 2

echo "==> test"
cargo test --locked --jobs 2

echo "==> audit"
if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "error: cargo-audit not installed (gate fails closed)." >&2
  echo "install with: cargo install cargo-audit" >&2
  exit 1
fi
cargo audit

echo "gates passed: fmt, clippy, check, test, audit all green."
