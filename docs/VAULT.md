# `vault` — dotenv secrets encryption

`vault` encrypts the **values** of `.env` files in place, leaving keys and
comments readable, so ciphertext can live in git and secret changes review as
diffs. Extracted from the `si` monorepo; this repo has no `si` dependency.

## Format

- Encrypted values: `encrypted:vault:<base64 ECIES blob>` (secp256k1 + AES-GCM
  via the `ecies` crate). An empty plaintext is stored as the bare prefix.
- File header: `VAULT_PUBLIC_KEY=<compressed pubkey hex>` — inserted on encrypt,
  lets anyone **add** secrets without being able to read existing ones.
- Anything else starting with `encrypted:` is **refused** on decrypt — never
  read, never treated as plaintext. `vault migrate` is the only code that
  understands retired labels and relabels them in place (no re-encryption).

## Keyring

Private key material lives only in `~/.vault/keyring.json` (mode 0600), scoped
by `repo/env`; override with `VAULT_KEYRING_FILE`. A single canonical keypair
is enforced across scopes. This is a plain JSON state file, not the OS keychain.

## Commands

| Command | Purpose |
| --- | --- |
| `keypair` (`keygen`) | generate/load the scope keypair (`--rotate`) |
| `status` | keyring/file readiness for a target |
| `check` | refuse plaintext values (`--staged --all` = hook mode) |
| `hooks install\|status\|uninstall` | manage the git pre-commit guard |
| `encrypt` / `decrypt` | whole-file (`--stdout`, `--inplace`, `--reencrypt`) |
| `set` / `unset` / `get` / `list` | per-key operations (`get --reveal`) |
| `run` | decrypt into a child process env: `vault run -- <cmd>` |
| `restore` | restore the pre-decrypt backup (`.vault-restore/`) |
| `trust lookup` | trust-store fingerprint lookup |
| `import-dotenv` | bulk-import plaintext dotenv trees |
| `migrate` | relabel retired formats to the current one |

Shared target args: `--env-file/--file`, `--repo`, `--env`, `--scope`; `dev`/`prod`
inferred from `.env.dev`/`.env.prod` filenames.

## Runtime guard

When `DENY_LOCAL_SECRET_OPS=1` is set, secret operations (`decrypt`, `get`,
`unset`, …) refuse to run. Host runtimes set this for semi-trusted workers,
which must use the [fort](https://github.com/Aureuma/fort) policy API instead.

## Boundary

`vault` owns cryptography and the dotenv ciphertext format. Policy, identity,
and audit over this data are fort's job. Encrypted material lives in the
private `safe` repo, one directory per project, mode 0600 — note that
`git checkout`/`restore` recreates files with umask permissions, so re-assert
`0600` after any git operation that rewrites a `safe` file (fort refuses
group/other-readable secret files).
