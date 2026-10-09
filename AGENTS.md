# Repo Rules

## Scope
- `vault` owns dotenv cryptography and format: per-value ECIES encryption,
  the `encrypted:vault:` label, the keyring, the trust store, the pre-commit guard.
- `vault` owns NO policy, identity, or audit. That is
  [fort](https://github.com/Aureuma/fort)'s job; all remote/secret access goes
  through Fort. Direct `vault` secret commands are for Fort maintenance and
  isolated tests only.
- This repo has zero dependency on any other Aureuma codebase. Keep it that way.

## Format Invariants
- Current value label: `encrypted:vault:`. Anything else starting with
  `encrypted:` is refused on decrypt, never read as plaintext.
- `migrate` is the only code that understands retired labels, and only to
  relabel them in place (no re-encryption).
- Keyring is file-backed JSON (`~/.vault/keyring.json`, `0600`), one canonical
  keypair across all `repo/env` scopes.

## Working In This Repo
- Build: `cargo build --locked --release`. Test: `cargo test --locked`.
- Keep the CLI surface boring: existing subcommand patterns, file-backed secrets,
  no env-injected secret values.
- Docs live in `docs/VAULT.md`; keep it accurate when behavior changes.

## Version Source Of Truth
- The canonical hard-coded version source is the root `Cargo.toml` under `[package].version`.
- Do not add extra independently maintained repo version strings elsewhere.
