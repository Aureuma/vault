# vault

Standalone dotenv secrets tool: per-value ECIES encryption of `.env` files with a
local keyring, a pre-commit plaintext guard, and ciphertext designed to live in git.

This repo owns:

- the `vault` binary (CLI: keypair, status, check, hooks, encrypt, decrypt, restore,
  set, unset, get, list, run, trust, import-dotenv, migrate)
- the dotenv ciphertext format (`encrypted:vault:` prefix, `VAULT_PUBLIC_KEY` header)
- the keyring (`~/.vault/keyring.json`, override `VAULT_KEYRING_FILE`)
- the trust store and the managed git pre-commit hook

Policy, identity, and audit over this data are [fort](https://github.com/Aureuma/fort)'s
job. Encrypted material lives in the private `safe` repo. This repo has **zero**
dependency on any other Aureuma codebase.

See [docs/VAULT.md](docs/VAULT.md) for the format, keyring, commands, and
Fort boundary. The historical extraction record lives in
[plans/VAULT_EXTRACTION.md](plans/VAULT_EXTRACTION.md).

## Build & test

```bash
cargo build --locked --release
cargo test --locked
```
