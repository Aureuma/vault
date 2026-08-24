# vault

Standalone dotenv secrets tool: per-value ECIES encryption of `.env` files with a
local keyring, a pre-commit plaintext guard, and ciphertext designed to live in git.

Extracted from the `si` monorepo (formerly `si vault`). This repo owns:

- the `vault` binary (CLI: keypair, status, check, hooks, encrypt, decrypt, restore,
  set, unset, get, list, run, trust, import-dotenv, migrate)
- the dotenv ciphertext format (`encrypted:vault:` prefix, `VAULT_PUBLIC_KEY` header)
- the keyring (`~/.vault/keyring.json`, override `VAULT_KEYRING_FILE`)
- the trust store and the managed git pre-commit hook

Policy/authn/authz over this data is `fort`'s job (separate repo). Encrypted
material lives in the private `safe` repo. This repo has **zero** dependency on
the `si` codebase.

## Status

Extraction in progress — see [plans/VAULT_EXTRACTION.md](plans/VAULT_EXTRACTION.md)
for the complete migration plan, inventory, gates, and rollback procedure.
