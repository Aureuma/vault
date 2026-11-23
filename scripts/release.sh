#!/usr/bin/env bash
# Local release builder — replaces .github/workflows/release.yml (deleted per
# the owner mandate: zero GitHub Actions; see issue #4).
#
#   ./scripts/release.sh vX.Y.Z [--publish]
#
# Validates the tag against Cargo.toml, builds --release, packages
# dist/vault_<version>_<os>_<arch>.tar.gz, writes dist/checksums.txt,
# verifies the archives, and (with --publish) uploads them to the GitHub
# Release via gh. Mirrors the deleted workflow's resolve-tag / build /
# verify / publish steps, minus the Sigstore provenance attestation, which
# has no local equivalent (checksums remain the integrity record).
#
# Cross-compilation: set TARGETS to a space-separated list of Rust targets
# (equivalent of the old 4-way matrix):
#   TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin" ./scripts/release.sh v1.2.0
# Each target must already be installed (rustup target add <target>).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

TAG="${1:-}"
PUBLISH="${2:-}"

if [[ ! "${TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 vX.Y.Z [--publish]" >&2
  exit 2
fi
if [[ -n "${PUBLISH}" && "${PUBLISH}" != "--publish" ]]; then
  echo "usage: $0 vX.Y.Z [--publish]" >&2
  exit 2
fi

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
if [[ "v${VERSION}" != "${TAG}" ]]; then
  echo "error: tag ${TAG} does not match Cargo.toml version ${VERSION}" >&2
  exit 1
fi
echo "tag ${TAG} matches package version ${VERSION}"

HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
TARGETS="${TARGETS:-${HOST_TARGET}}"

rust_target_to_asset() {
  case "$1" in
    x86_64-unknown-linux-gnu) echo "linux_amd64" ;;
    aarch64-unknown-linux-gnu) echo "linux_arm64" ;;
    x86_64-apple-darwin) echo "darwin_amd64" ;;
    aarch64-apple-darwin) echo "darwin_arm64" ;;
    *) echo "error: no asset-name mapping for Rust target $1" >&2; exit 1 ;;
  esac
}

mkdir -p dist
rm -f dist/vault_"${VERSION}"_*.tar.gz dist/checksums.txt

for rust_target in ${TARGETS}; do
  asset_suffix="$(rust_target_to_asset "${rust_target}")"
  echo "==> build ${rust_target}"
  if [[ "${rust_target}" == "${HOST_TARGET}" ]]; then
    cargo build --locked --release --jobs 2 --bin vault
    bin="target/release/vault"
  else
    cargo build --locked --release --jobs 2 --target "${rust_target}" --bin vault
    bin="target/${rust_target}/release/vault"
  fi
  [[ -x "${bin}" ]] || { echo "error: missing ${bin}" >&2; exit 1; }
  "${bin}" --version
  archive="dist/vault_${VERSION}_${asset_suffix}.tar.gz"
  tar -czf "${archive}" -C "$(dirname "${bin}")" vault
done

(cd dist && sha256sum vault_"${VERSION}"_*.tar.gz > checksums.txt)
cat dist/checksums.txt

echo "==> verify archives"
for archive in dist/vault_"${VERSION}"_*.tar.gz; do
  [[ -f "${archive}" ]] || { echo "error: missing ${archive}" >&2; exit 1; }
  contents="$(tar -tzf "${archive}")"
  grep -qx "vault" <<<"${contents}" || { echo "error: ${archive} missing vault binary" >&2; exit 1; }
done
(cd dist && sha256sum -c checksums.txt)
echo "release archives verified for ${TAG}"
ls -lah dist

if [[ "${PUBLISH}" == "--publish" ]]; then
  gh release view "${TAG}" --repo Aureuma/vault >/dev/null
  # shellcheck disable=SC2086
  gh release upload "${TAG}" dist/vault_"${VERSION}"_*.tar.gz dist/checksums.txt --repo Aureuma/vault --clobber
  echo "uploaded release assets for ${TAG}"
else
  echo "validation-only run; pass --publish to upload to the GitHub Release."
fi
