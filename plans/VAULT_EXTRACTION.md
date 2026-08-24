# VAULT_EXTRACTION — extracting `si vault` into this repo, end to end

**Status:** EXECUTED 2026-08-24 — see the Execution Log at the end. **Author:** Claude (Opus), 2026-08-24, from a
4-way verified source inventory (si repo, fort repo, external consumers, baseline tests;
each inventory adversarially re-swept). Every file:line below was read, not assumed.

## 0. Objective and end-state invariants

Extract the `si vault` functionality out of `si` into this standalone `vault` repo
(github.com/Aureuma/vault, private), such that at steady state:

- **I1** — the `si` repo contains **zero** vault mentions or mechanics (code, docs,
  tests, CI, command manifest). Exception: git history and CHANGELOG history are not
  rewritten (see D-12).
- **I2** — this `vault` repo has **zero** dependency on si crates and **zero**
  `si-vault`/`si` naming in code, docs, formats, paths, or env vars.
- **I3** — `fort` (own repo, unchanged architecture) keeps working throughout, and at
  steady state contains no `si-vault` naming.
- **I4** — data in `safe` is migrated (prefix + header + keyring), and every consumer
  (fortd prod, viva, 9 pre-commit hooks, verdict runbooks, publish scripts, docs sites)
  is updated in lockstep.
- **I5** — all baseline-green test suites are green at every gate (§7), and production
  fortd never serves a wrong value at any point (see the ordering hazard in §3.1).

## 1. Naming decisions (fixed for this plan)

| Old | New | Notes |
|---|---|---|
| binary/subcommand `si vault` (alias `si creds`) | binary `vault` | no shim in si (I1); hooks/scripts repointed instead |
| crate `si-vault` | package `vault` (lib + bin in one crate) | repository=github.com/Aureuma/vault, version 0.1.0, license AGPL-3.0-only (D-1) |
| value prefix `encrypted:si-vault:` | `encrypted:vault:` | textual relabel; ECIES blobs unchanged (§4.1) |
| legacy bare prefix `encrypted:` | dropped at steady state | accepted by `vault migrate` only |
| header `SI_VAULT_PUBLIC_KEY` | `VAULT_PUBLIC_KEY` | §4.2 |
| keyring `~/.si/vault/si-vault-keyring.json` | `~/.vault/keyring.json` (0600) | env override `SI_VAULT_KEYRING_FILE` → `VAULT_KEYRING_FILE` |
| fortd keyring `/var/lib/fort/si-vault-keyring.json` | `/var/lib/fort/vault-keyring.json` | config-driven: fort/config/fortd.container.toml:5 (§5) |
| hook marker `# si-vault:hook pre-commit v1/v2` | `# vault:hook pre-commit v1` | hook execs `vault check --staged --all`; resolves `$VAULT_BIN` → PATH (no SI_BIN, no hardcoded dev-tree path — D-4) |
| restore dir `.si-vault-restore/` | `.vault-restore/` | ignore-file updates in 5 repos + releasemind CI globs (§6.7) |
| worker secret-ops block (documented only, never enforced) | env guard `DENY_LOCAL_SECRET_OPS=1` honored by `vault` | neutral name so si sets it without vault naming and vault reads it without si naming (D-2) |
| tool `import_dotenv_to_si_vault` (si-tools bin) | `vault import-dotenv` subcommand | drop dead `SI_VAULT_KEY_BACKEND`/`SI_VAULT_KEY_FILE` env vars (they were already no-ops: si-tools bin:169-170) |
| — (new) | `vault migrate` subcommand | reads all legacy formats, writes new; the only code that ever understands the old names after v0.2 |

**Decisions log:**
- **D-1 licence/version:** si-vault inherited AGPL-3.0-only from the si workspace
  (si/Cargo.toml:16-22). Keep AGPL-3.0-only; add LICENSE file in chunk C1.
- **D-2 worker guard:** docs/VAULT.md:23 claims vault secret commands are blocked in
  SI runtime workers, but **no enforcement code exists in si** (verified); it held via
  worker HOME isolation only. New: `vault` refuses `get/set/list/run/decrypt/encrypt/unset`
  when `DENY_LOCAL_SECRET_OPS=1`; si worker provisioning exports that var.
- **D-3 history:** fresh code import (no git-filter-repo). The old history is full of
  the names we are eliminating; provenance is recorded here instead.
- **D-4 hook resolution:** the 9 installed hooks hardcode
  `SI_BIN_DEFAULT=/home/shawn/Development/si/si` *before* PATH. New hook resolves
  `$VAULT_BIN`, else `vault` on PATH. No dev-tree hardcode.
- **D-5 trust store:** ported for CLI parity (si-vault crate is small; 3 tests), but it
  is vestigial — `~/.si/vault/trust.json` is 43 bytes and **no external consumer was
  found** (the claimed fort dependency was refuted on verification). Candidate for
  removal in a later release; not this migration's problem.
- **D-6 dual-read window:** vault v0.1 and fort F1 *read* both prefixes/headers and
  *write only new*. After safe is migrated and verified, vault v0.2 / fort F3 drop the
  legacy read (I2/I3). `vault migrate` keeps legacy parsing forever (quarantined there).
- **D-7 headerless files:** safe/luma/.env.dev, safe/sociara/.env.dev, safe/sociara/.env.prod
  hold 22 encrypted values but **no** public-key header. Migration adds `VAULT_PUBLIC_KEY`
  (the single canonical pubkey — both keyrings verifiably hold the same keypair).
- **D-8 keyring merge:** union-merge scopes. Same canonical keypair in both copies
  (verified by direct comparison); the home copy uniquely holds the `shawn/dev` scope,
  the /var/lib/fort copy is otherwise newer/superset. "Biggest file wins" would lose a
  scope — do the union. `backup_private_keys` must end **empty** in the fortd copy or
  fortd refuses to start (KeySprawl, fort/src/vaultbridge.rs:191-197).
- **D-9 snapshots:** ~/.viva/snapshots holds 1027 files with the old prefix (verbatim
  per-release copies of safe env files). Do **not** rewrite them. Document: restoring an
  old snapshot requires `vault migrate --env-file <restored>` before use. (§6.9)
- **D-10 empty-value ciphertexts:** fort stores empty plaintexts as the bare string
  `encrypted:si-vault:` with no payload (vaultbridge.rs:356-358). The migration rewrite
  must match the prefix with **optional** payload, not `prefix[A-Za-z0-9+/=]+`.
- **D-11 fort fallthrough hardening:** fort's `decrypt_value` returns any value not
  starting with the exact prefix **as plaintext** (vaultbridge.rs:369-371). During F1,
  make any *unrecognized* `encrypted:*` value a hard error. This both fixes the silent-
  corruption class bug and makes mis-ordered migration loudly fail instead of silently
  serving ciphertext strings as secrets.
- **D-12 history exemption:** CHANGELOG history entries (38 vault mentions in si) and
  immutable research/output logs (COREPaper/CORERepro: 445 generated files) are records,
  not live mechanics — exempt from I1's "zero mentions" (they describe the past).
  Verifier confirmed no live coupling.
- **D-13 viva settings:** legacy tunnel keys `vault_env`/`vault_env_file`/`vault_repo`
  in ~/.si/viva/settings.toml (only `vault_env_file` is still read, as a fallback):
  migrate the settings file to `fort_env_file` first, then delete the legacy alias from
  viva config code.

## 2. What moves, what changes (verified inventory)

### 2.1 Into this repo (from si)

| Source | Becomes |
|---|---|
| si/rust/crates/si-vault/src/lib.rs (250 lines: TrustStore v3, atomic 0600 writes, 3 tests) | `src/trust.rs` |
| si/rust/crates/si-cli/src/vault_compat.rs (1586 lines: full CLI, keyring model, dotenv parser/writer CRLF-preserving, ECIES via `ecies` 0.2.10, hook renderer, canonical-keypair invariant) | `src/` (split: cli.rs, keyring.rs, dotenv.rs, crypto.rs, hooks.rs) |
| si-cli couplings — exactly three (verified): `si_config::runtime::git_repo_root_from` (si-config/src/runtime.rs:159-176, ~30 lines with helpers), `OutputFormat` (main.rs:1068-1081), `show_vault_trust_lookup` + `VaultTrustLookupView` + render helpers (main.rs:1293-1304, 8489-8536), `default_home_dir()` (main.rs:10207-10212) | reimplemented locally (~100 lines) |
| si/rust/crates/si-tools/src/bin/import_dotenv_to_si_vault.rs | `vault import-dotenv` subcommand (dead env vars dropped) |
| si-cli vault tests (8 passing in integration binary) + si-vault's 3 unit tests | ported with renamed literals; `vault trust lookup` JSON shape kept as-is (found/matches/stored_fingerprint/trusted_at) |
| si/docs/VAULT.md lines 53-138 (Core Model, Quickstart, Encryption Behavior, Pre-commit Guard, Commands) | `docs/VAULT.md` here, renamed |
| si/.github/workflows/fort-vault-ci.yml (the si-vault path-filter parts) | this repo's own CI workflow |

New code (not ports): `vault migrate` (§4), `DENY_LOCAL_SECRET_OPS` guard (D-2).

CLI parity surface to preserve (from clap defs, vault_compat.rs:22-185):
`keypair|keygen [--rotate --format]`, `status`, `check [--file --vault-dir --staged --all
--include-examples]`, `hooks install|status|uninstall`, `encrypt [--stdout --reencrypt]`,
`decrypt [--stdout --inplace]`, `restore`, `set [--stdin --plain]`, `unset`, `get [--reveal]`,
`list|ls [--format]`, `run [--allow-plaintext --shell --shell-interactive --shell-path]`,
`trust lookup [--path --repo-root --file --fingerprint --format]`; shared target args
`--env-file/--file/--repo/--env/--scope` with dev/prod inference from `.env.dev`/`.env.prod`.

Cargo deps to carry: ecies 0.2.10 (default-features off; std, pure), hex, base64, sha2,
chrono, serde, serde_json, tempfile, thiserror, anyhow, clap.

### 2.2 Removed from si (chunk Z1)

- crates: `rust/crates/si-vault/` (whole), `si-cli/src/vault_compat.rs`,
  `si-tools/src/bin/import_dotenv_to_si_vault.rs`; workspace members list.
- si-cli/src/main.rs: `mod vault_compat` (:15), `use si_vault::TrustStore` (:54),
  `use vault_compat::…` (:80), `Command::Vault` (:178-181), dispatch (:4006), command-tree
  help entries `['vault']`/`['vault','trust']` (:4115-4116), `VaultTrustLookupView`
  (:1293-1304), `show_vault_trust_lookup` (:8489-8536).
- **npm publish rewire, not delete** (main.rs:512-525, 3165-3268): `si build npm vault`
  currently shells `si vault check/list` then `si vault run -- <current_exe> build npm
  publish…`. Rewire to shell the standalone `vault` binary (resolve via `$VAULT_BIN` →
  PATH), keeping the nested current_exe pattern. Same chunk as the removal or si's npm
  publishing breaks (verified call sites).
- **si-command-manifest**: vault command entries AND the compile-coupled
  `include_str!("…/docs/VAULT.md")` at si-command-manifest/src/lib.rs:142 plus the
  creds-alias test at :161 — deleting docs/VAULT.md without editing these **breaks the
  whole workspace build**.
- docs: docs/VAULT.md (lines 25-52 are actually the `si fort` wrapper contract → move
  into a new si docs/FORT.md, not into this repo), CLI_REFERENCE.md, SETTINGS.md,
  index.mdx, README, AGENTS.md mentions.
- CI: .github/workflows/fort-vault-ci.yml — path filters reference rust/crates/si-vault/**
  and also cover si-config/si-cli/si-tools and run the test-fort-spawn-matrix step; edit,
  don't delete blindly.
- si-config: `surf.tunnel.vault_key` legacy settings alias (rename/remove — settings
  migration note; verify no live settings.toml uses it first).
- tools/codex-skills/si-vault-ops skill dir + its sync channel (si_codex_init.rs /
  si_entrypoint.rs sync /opt/si/codex-skills into worker homes): delete skill; note that
  already-provisioned hosts keep a stale copy until re-provisioned (§6.10).

### 2.3 fort changes (stays in own repo; zero si-crate deps, verified)

- src/vaultbridge.rs: `ENCRYPTED_PREFIX` (:15) → dual-read in F1, new-only in F3;
  harden fallthrough (D-11); keyring filename comes from config, code needs no path change.
- config: fort/config/fortd.container.toml:5 `vault_keyring_file = "/var/lib/fort/si-vault-keyring.json"`
  → `/var/lib/fort/vault-keyring.json`; Dockerfile bakes this file into /etc/fort/fortd.toml
  (:13) so the rename reaches prod **only via image rebuild + `viva deploy --file
  fort/deploy/viva.api.prod.yaml`** (deploy yamls need no edit — verified; they mount the
  /var/lib/fort *directory* and safe RW at /safe).
- scripts/smoke-container.sh:15 keyring filename; scripts/e2e-si-vault.sh → rename file
  and its referenced test name.
- tests/e2e.rs:21,189,216 hardcode old prefix + keyring filename — update; **add** the
  missing tests: old-prefix read (F1 window), mixed-prefix file, unknown-prefix hard error,
  bare-empty-prefix value (D-10).
- docs: README (SI Vault mentions; :98,:172-173 `.si` paths), docs/GUIDING_PRINCIPLES.md
  (:50 documents legacy `encrypted:` acceptance the code never implemented — fix the false
  contract; :77 `~/.si/vault/keys/age.key`), AGENTS.md:48.
- **Not** renamed: `~/.si/fort/…` and `~/.si/codex/profiles/…` session paths and
  fort/src/cli.rs `is_codex_profile_refresh_token_path` (:1662-1677) which pattern-matches
  the literal `.si` component — the si *runtime* namespace is out of scope here (fort stays
  si-integrated for sessions). Flagged: if `.si` is ever retired, that guard silently stops
  matching (§8 risk R-9).
- fort set() rewrites files via BTreeMap (comments dropped, keys sorted;
  vaultbridge.rs:285-308) — irrelevant to migration itself but documented so nobody
  expects fort writes to preserve the migrated files' comments.

### 2.4 Everything else that references the old names (consumers inventory, verified)

| Where | What | Action |
|---|---|---|
| safe/.git/hooks/pre-commit **and identical hooks in 8 more repos**: viva, releasemind, ReleaseMindPaper, aureuma, core, surf, svelta-blog, homebrew-si | marker `si-vault:hook pre-commit v1`, `SI_BIN_DEFAULT=/home/shawn/Development/si/si` then PATH; execs `si vault check --staged --all` | replace via `vault hooks install` in **all 9** (hooks are .git-local, they do NOT travel with clones) |
| safe repo files | 22 tracked env files; `SI_VAULT_PUBLIC_KEY` headers; `encrypted:si-vault:` values; 3 headerless files (D-7) | `vault migrate` sweep, one commit (§4) |
| viva/src/vaultsi.rs:8 | **third** independent holder of the `encrypted:si-vault:` literal (marker detection) + shells `si fort` | update literal → rebuild viva → reinstall binary |
| viva config.rs | legacy `vault_env_file` settings fallback | D-13 |
| viva docs (CLOUDFLARE_TUNNEL.md:30,56,93; RELEASEMIND_FORT_DEPLOY_CONTRACT.md:14,59; CLI_REFERENCE) + CHANGELOG (history, exempt) | `si vault` / vault-path mentions | update refs |
| viva scripts control-plane-backup-offhost.sh / restore-offhost.sh | `SI_BIN=/home/shawn/Development/si/si` default; resolve creds via si | repoint (uses `si fort` — still valid post-extraction; only the stale-binary risk applies) |
| /etc/systemd/system/viva-post-boot-check.{service,timer} (+ nova/deploy/systemd/nova-api.service source) | fort consumers, fire every 10 min; read safe/viva/.env.prod markers | **stop timer during S1**; no code change (uses `si fort`, which remains) |
| verdict/ENV.md:21-22 + frontend/ENV.md | document `si vault decrypt/status` against safe paths | rewrite to `vault …` |
| verdict/.env + frontend/.env (local, decrypted) | carry `SI_VAULT_PUBLIC_KEY` header line | regenerate after migration (documented command does it) |
| svelta-docs (published site) | src/content/docs/VAULT.md (full page), RELEASING.md:50,109,112, index.mdx:27, NUCLEUS.md:166, incidental mentions in 6+ pages; tools/release/npm/publish-npm-from-vault.sh:101,114 hardcodes the si dev-tree binary | rewrite page → point at this repo; update publish script to `vault` |
| lingospeak README:182; luma/src/main.rs strings + luma/targets/products/*.yaml (`credential_path: si fort`) | policy prose / fort strings | doc updates; luma unaffected functionally (`si fort` remains) |
| lingospeak/.artifacts/** test scripts | hardcode `/home/shawn/Development/si/si fort …` | local-only (gitignored); fix opportunistically |
| ignore files in 5 repos + releasemind CI paths-ignore | `.si-vault-restore/` globs | rename to `.vault-restore/`; sweep for existing restore dirs before renaming |
| ~/.viva/snapshots/** | 1027 old-prefix copies | D-9, leave + document |
| stale binaries: repo-root si/si (14MB, Jun 1), ~/.local/bin/si (12MB, Jun 14), /opt/si/nova/si | all still contain `si vault`; hooks resolve the repo-root one FIRST | rebuild + reinstall all three in Z-phase; delete repo-root copy (untracked) |
| ~/.si/vault/{keys/, settings.toml, trust.json} | predate current keyring format / vestigial | archive alongside keyring backup (§4.3) |

## 3. Execution order (phases) — and why this order

### 3.1 The ordering hazard that dominates everything

fort's `decrypt_value` returns unrecognized values **as plaintext** (D-11). If safe is
migrated before fort can read the new prefix, production fortd serves the literal string
`encrypted:vault:…` as every secret value — silently. Therefore: **fort dual-read (F1)
deploys before any safe rewrite (S1)**, and the fallthrough hardening lands in F1 so any
future mis-order fails loudly.

Second hazard: the moment si loses `vault`, all 9 pre-commit hooks hard-fail every
commit (they exec the dev-tree si binary first). Therefore: **hook replacement (H)
completes before si removal (Z1)**.

### 3.2 Phase list

```
P0  this plan committed/pushed (done in this repo's first commits)
PRE preconditions: backups + freeze            (§4.3 backups; stop viva-post-boot-check.timer;
                                                no deploys during S/K phases)
C   build vault v0.1 here (chunks C1..C7)      gates A, B*, C* (*legacy-read mode against unmigrated safe)
F1  fort dual-read + hardening + tests          gate D; rebuild image; viva deploy fort spec; verify prod
S1  safe data migration (one commit)            gates C (all 22 files), F-prod spot checks
K   keyring union-merge + moves (both copies)   fortd config rename (F2) + rebuild + redeploy; gate E
H   replace hooks in all 9 repos                gate F (in safe + spot-check 2 others)
X   consumers: viva (code+settings+docs+rebuild+reinstall), verdict docs,
    svelta-docs (docs+publish script), lingospeak/luma docs           gates G, H
Z1  si removal + npm-publish rewire + manifest/CI/docs + rebuild + reinstall
    all three si binaries                       gate I
V2  vault v0.2: drop legacy read               gate A/B/C rerun
F3  fort: drop legacy prefix read              gate D rerun + prod verify
FIN final zero-remnant sweep + FINAL GATE       §7
```

Rollback boundaries: until F3/V2, every step is reversible — safe migration is one
revertable commit and dual-read binaries accept both formats; keyring originals are kept
(archived, 0600) until FIN; fortd rollback = redeploy previous image tag
(viva keeps release history, `keep_release_history = 3`).

## 4. Data migration mechanics

### 4.1 Value prefix (`vault migrate`)

The prefix is a label; the base64 ECIES blob is unchanged — **no re-encryption**.
Rewrite rules (per D-10): `encrypted:si-vault:<b64?>` → `encrypted:vault:<b64?>` including
the empty-payload bare form; also accept legacy bare `encrypted:<b64>` (still present per
consumer sweep) → `encrypted:vault:<b64>`. Everything else untouched; comments/order/CRLF
preserved (the ported dotenv writer already guarantees this — unlike fort's writer).

### 4.2 Header

`SI_VAULT_PUBLIC_KEY=<hex>` → `VAULT_PUBLIC_KEY=<hex>` (same value). Headerless files
(D-7): insert `VAULT_PUBLIC_KEY` as line 1 with the canonical pubkey. Verification per
file: `vault check` passes; `=`-line counts match baseline (verdict/.env baseline = 4:
1 header + 3 values; capture counts for **all 22 files before S1** — the gate compares
per-file, and the header rename itself must not change value counts).

### 4.3 Keyrings (phase K)

1. Backup first: tar czf of `~/.si/vault/` (keyring + keys/ + settings.toml + trust.json)
   and `/var/lib/fort/si-vault-keyring.json*` (5 .bak siblings, verified) → 0600 archive
   outside both repos.
2. Union-merge scopes from home (6645B, has `shawn/dev`) and fortd (8185B, newer
   otherwise) copies — same canonical keypair verified, so merge is scope-union only.
   Result must have **empty `backup_private_keys`** everywhere (D-8/KeySprawl) and pass
   the ported canonical_keypair invariant (vault_compat.rs:931-953 bails on mixed keys).
3. Write `~/.vault/keyring.json` (0600) and `/var/lib/fort/vault-keyring.json` (0600,
   fortd-owner).
4. F2: fortd.container.toml rename → image rebuild → `viva deploy --file
   fort/deploy/viva.api.prod.yaml` → `fort doctor` + authenticated `fort get` spot-check
   of one migrated value per env (values compared by length/hash, never printed).
5. Old keyring files stay in place (unread) until FIN, then archived away.

## 5. Commit plan (chunked, per repo, in execution order)

**vault (this repo, new; push to Aureuma/vault):**
- C1 `chore: scaffold` (done) + LICENSE (AGPL-3.0-only) + this plan (`docs: extraction plan`)
- C2 `feat: keyring + ECIES crypto + dotenv read/write` (lib, unit tests)
- C3 `feat: trust store` (port of si-vault crate + its 3 tests)
- C4 `feat: CLI` (full parity surface §2.1; DENY_LOCAL_SECRET_OPS guard)
- C5 `feat: hooks + migrate + import-dotenv` (hook v1 renderer D-4; `vault migrate` §4;
  legacy-read behind v0.1 default)
- C6 `test: port si-cli vault integration tests + new migration tests` + CI workflow
- C7 `docs: VAULT.md` (renamed content of si docs/VAULT.md:53-138)
- V2 `feat!: drop legacy format read` (after S1/K verified)

**fort:**
- F1 `feat: accept encrypted:vault: prefix; harden unknown-prefix handling; tests`
  (dual-read; D-11; e2e tests for old/new/mixed/empty/unknown)
- F2 `chore: rename keyring file + si-vault literals in scripts/docs`
  (fortd.container.toml, smoke-container.sh, e2e-si-vault.sh → e2e-vault.sh, README,
  GUIDING_PRINCIPLES incl. the false legacy-prefix claim, AGENTS.md)
- F3 `feat!: drop encrypted:si-vault: read` (after FIN sweep of safe + snapshots note)

**safe:**
- S1 `chore!: migrate ciphertext format (encrypted:vault:, VAULT_PUBLIC_KEY)` — one
  commit, all 22 files + 3 headerless-file headers; hook bypass NOT needed (new-format
  files pass old `check`? **No** — old si `check` doesn't know the new prefix, and the
  hook still points at si at this stage. Sequence inside S1: swap safe's hook to the new
  `vault` binary FIRST (hook is .git-local, uncommitted), then migrate, then commit.)

**si:**
- Z1 `refactor!: remove vault (extracted to Aureuma/vault); rewire npm publish to
  standalone vault binary` — crate, CLI module, manifest include_str!, command tree,
  workflows, docs (VAULT.md split: fort-wrapper §→ new docs/FORT.md), settings alias.
  Build + full test suite + reinstall binaries (~/.local/bin/si, /opt/si/nova/si; delete
  stale repo-root ./si).
- Z2 `docs: changelog entry` (D-12: history entries retained).

**viva:** X1 `refactor: encrypted-value marker → encrypted:vault:; drop vault_env_file
settings alias; docs` (+ rebuild/reinstall viva; migrate ~/.si/viva/settings.toml first, D-13).
**verdict:** X2 `docs: ENV.md/frontend ENV.md → vault binary` (+ regenerate local .envs).
**svelta-docs:** X3 `docs: retire SI Vault page → link Aureuma/vault; publish script → vault`.
**lingospeak/luma:** X4 small doc commits.

Push targets: vault → Aureuma/vault (create private, this session); safe/viva/others →
their existing remotes; fort/si → wherever their remotes live (fort remote to be
confirmed at execution time — inventory found deploy is local-image based).

## 6. Special cases (each verified)

1. **si-command-manifest include_str!** of docs/VAULT.md (lib.rs:142, test :161): edit in
   the same Z1 commit as the doc removal or the workspace stops compiling.
2. **9 hooks, not 1** — and they resolve the *stale dev-tree* si first (Jun 1 binary,
   older than installed v0.60.16). Split-brain already exists pre-refactor.
3. **fort empty-value form** `encrypted:si-vault:` with no payload (D-10).
4. **Old si `check` vs new files:** any repo whose hook still runs old si after S1 will
   flag `encrypted:vault:` values as plaintext → hook order in §5/S1 and phase H.
5. **`vault trust` JSON contract** kept byte-compatible (D-5) even though no consumer found.
6. **`si creds` alias** dies with `si vault` (I1); no shim (D-A below if pain emerges).
7. **`.si-vault-restore/`** ignore-glob renames in 5 repos + releasemind CI; sweep for
   live restore dirs before renaming, else orphaned plaintext restore output becomes
   commit-eligible.
8. **viva-post-boot-check.timer** every 10 min reads safe markers → stop/start around S1/K.
9. **~/.viva/snapshots** re-contamination path (D-9): documented, not rewritten.
10. **Stale worker skill copies** (/opt/si/codex-skills/si-vault-ops synced into worker
    homes): removed from si in Z1; already-provisioned hosts keep stale copies until
    re-provisioned — harmless (skill shells a command that no longer exists) but listed
    in the FIN sweep.
11. **svelta-docs publish fallback** (publish-npm-from-vault.sh) hardcodes the dev-tree si
    at :101 and the vault subcommand at :114 — update with X3 or npm disaster-recovery
    publishing breaks silently.
12. **luma/nova/lingospeak `si fort` usages are NOT touched** — `si fort` (the wrapper)
    stays in si. Only *vault* leaves. (README-level doc mentions updated in X4.)

## 7. Test/verification gates (baseline all-green, 2026-08-24)

Baseline: si workspace build 49s PASS; si-vault 3/3; si-cli 83/83 (8 vault-named);
fort build+test 25/25; `si vault status/check/decrypt` live PASS (verdict/.env = 3 keys,
4 `=`-lines); `si fort doctor` 200/200; viva tunnel render PASS; safe hook end-to-end
PASS (negative control confirmed: plaintext value → exit 1 naming the key).

- **GATE A** (every vault chunk): `cargo build && cargo test` here; ≥11 ported tests green.
- **GATE B** (CLI parity): `vault status && vault list --env-file safe/verdict/.env` →
  exactly GEMINI_API_KEY, VERDICT_AUTH_USER, VERDICT_AUTH_PASS, all `(encrypted)`.
- **GATE C** (decrypt parity, never values): per-file `=`-count equals the pre-S1
  captured baseline for **all 22** safe files; plus `vault check --all` exit 0.
- **GATE D** (fort chunks): fort `cargo test` ≥25 green **plus** the new prefix-matrix
  tests (old/new/mixed/empty/unknown-error).
- **GATE E** (before prod redeploy): e2e with new-prefix fixture + new keyring filename;
  after redeploy: `fort doctor` + authenticated spot `get` per env, hash-compared.
- **GATE F** (hooks): staged-plaintext negative control exits 1 under the new hook in
  safe; hook file contains no `si` references; spot-check 2 of the other 8 repos.
- **GATE G** (viva): `viva tunnel render --profile dev` + `viva tunnel doctor`; a no-op
  `viva deploy --dry-run` against one spec consuming safe env_files.
- **GATE H** (verdict): `grep -c 'si vault' ENV.md frontend/ENV.md` = 0; documented
  restore command executed into a scratch dir yields 4/`=`-count parity.
- **GATE I** (si): workspace build + full si-cli suite green with vault gone (83-8=75
  expected minus removed vault tests; exact count recorded at Z1); `si build npm vault`
  dry-path exercises the rewired external `vault` calls; grep sweep
  `rg -i 'si.?vault|SI_VAULT|vault_compat' si/` → only D-12-exempt CHANGELOG lines.
- **FINAL**: all gates rerun post V2/F3 + system sweep:
  `rg -l 'encrypted:si-vault:|SI_VAULT_PUBLIC_KEY|si-vault-keyring|\.si-vault-restore|si-vault:hook'`
  across /home/shawn/Development (excluding .git, archives, ~/.viva/snapshots, CORE*/output,
  CHANGELOGs) → **zero hits**; hooks in all 9 repos carry the new marker; fortd healthy;
  one full deploy of a viva-managed app end-to-end.

## 8. Risk register (top items)

- **R-1** fort silent plaintext fallthrough × migration mis-order → F1-before-S1 + D-11. 
- **R-2** 9-repo commit lockout on premature si removal → phase H before Z1.
- **R-3** keyring merge loses `shawn/dev` scope or trips KeySprawl → D-8 union + empty
  backup_private_keys + gate E.
- **R-4** live prod coupling: fortd bind-mounts safe RW; S1 edits are served in real time
  → dual-read deployed first; timer stopped; spot-check hashes after S1.
- **R-5** stale binaries resurrect old behavior (3 si copies + fort bin/.dist local
  leftovers) → explicit rebuild/reinstall/delete steps in Z1/F2.
- **R-6** headerless + empty-payload edge cases silently skipped by naive regex → D-7/D-10
  + migration tests in C6.
- **R-7** npm publish + svelta-docs fallback publish break quietly → rewire in Z1/X3,
  exercised in gate I.
- **R-8** viva legacy settings alias removed before settings migrated → D-13 order.
- **R-9** future `.si` namespace retirement silently disables fort's refresh-token path
  guard (cli.rs:1662-1677) — out of scope here; recorded for the next plan.
- **R-10** gitignored fort plans/bin/.dist exist only on this machine — any clone-based
  execution of F2 misses them; execute renames in the live working tree.

## 9. Open questions for the operator (defaults chosen, overridable)

1. Keyring home `~/.vault/` vs XDG `~/.config/vault/` — **default ~/.vault/** (shortest,
   mirrors old shape). 
2. Keep `vault trust` long-term? — ported now (D-5); revisit after FIN.
3. Vault binary distribution beyond this machine (homebrew tap? cargo install?) —
   out of scope; hooks resolve PATH so any later channel works.
4. Fort repo remote/publication — confirm at execution time (deploy is local-image;
   no remote found in inventory).
5. `si creds` users muscle-memory: acceptable loss? (I1 forbids a shim; a shell alias
   outside the repo is the escape hatch.)

---

# EXECUTION LOG — 2026-08-24

Executed end to end. Every gate in §7 passed. Final state: vault 18 tests,
fort 31, si 154, viva 70 — all green; all 22 `safe` files decrypt to
**byte-identical plaintext** vs the pre-migration baseline (sha256, all 0600);
production fortd healthy and serving; `marsmaria.com`, `ls-dev.lingospeak.ai`,
`surf-browser.aureuma.ai` all 200.

## Phase order actually used

`PRE → C → F1(+deploy) → H → S1 → K → F2(+deploy) → X → Z1 → V2 → F3(+deploy) → FIN`

**H moved earlier** (before S1 rather than after K): swapping the hooks first
removes the dependency on the stale dev-tree `si` binary immediately, and the
new hook reads both formats, so it is correct on either side of the migration.

## Two live bugs found and fixed that the plan had not predicted

1. **`git checkout` silently breaks fort.** Restoring a `safe` file with git
   recreates it at umask perms (0664). fort's `ensure_strict_secret_file`
   rejects `mode & 0o077 != 0`, so **every fort read of viva secrets had been
   failing with a 500** since an earlier unrelated `git checkout` of
   `viva/.env.{dev,prod}`. Fixed with `chmod 600`. **New standing rule: after
   any git operation that rewrites a `safe` file, re-assert 0600.** A `git
   revert` of S1 would reintroduce this.

2. **viva was a third holder of the ciphertext marker, on the serving path.**
   `viva/src/vaultsi.rs` gated `prepare_env_files` (used by deploy, tunnel,
   backup, umami) on `"encrypted:si-vault:"`. After S1 every file read as *not
   encrypted*, so viva would have passed ciphertext straight into containers as
   env values. Fixed to dual-read before any deploy ran. The plan listed viva
   as a marker holder but scored it a doc/rebuild task, not a serving-path
   correctness bug.

## Deviations from the plan, with reasons

- **`vault_compat.rs` ported as one module**, not split into cli/keyring/dotenv/
  crypto/hooks. The ECIES and dotenv paths are load-bearing; a faithful port is
  verifiable, a hand-split is not. Splitting remains cosmetic follow-up.
- **D-7 dropped: headerless files stay headerless.** `luma/.env.dev` and both
  `sociara` files gained no `VAULT_PUBLIC_KEY`. Adding one would have changed
  their line counts, weakening GATE C from a strict equality to an explained
  difference. They decrypt correctly without it (fort encrypts from the keyring,
  never the file header).
- **`surf.tunnel.vault_key` kept** in si-config. It is a legacy alias for
  `fort_key` — about fort keys, not the vault tool — and removing it would break
  any `settings.toml` still using it. No live settings use it.
- **Legacy reads rejected, not silently accepted** (V2/F3). `vault decrypt`
  fails with `run: vault migrate --env-file <path>`; fortd returns an error. A
  file left behind announces itself instead of working quietly forever.
- **`si build npm vault` rewired, not removed** — resolves `vault` via
  `VAULT_BIN` or PATH.
- **CHANGELOG history kept** (D-12), and `luma` turned out not to be a git repo,
  so its doc edits are local-only. `sociara` has no working remote; its commit
  is local.

## Things that must NOT be reverted casually

- Reverting S1 in `safe` re-introduces the legacy labels that fort now
  **rejects** → every read fails. Recovery: `vault migrate --dir .`, then
  `chmod 600`.
- `~/.viva/snapshots` still holds **1027** old-label copies. Restoring one
  requires `vault migrate --env-file <restored>` first; viva detects both
  labels, but `vault` and fort no longer decrypt the old one.
- Backups taken before the migration: `/home/shawn/vault-migration-backup-20260824/`
  (both keyrings + all 9 original hooks + pre-migration plaintext hashes +
  previous `si`/`viva` binaries + viva settings).

## Keyring consolidation result

Union-merged to **30 scopes** at `~/.vault/keyring.json` and
`/var/lib/fort/vault-keyring.json` (both 0600). Single canonical keypair
verified across both source copies before merging. Preserved: `shawn/dev`
(home-only) and `luma/dev`, `nova/prod`, `sociara/dev`, `sociara/prod`
(fortd-only) — a "newest file wins" merge would have dropped `shawn/dev`.

---

# FINALIZATION — 2026-08-24 (second pass, no fallbacks)

Operator directive: remove `si build npm vault` fully and keep **no fallback of
any kind**. Applied and verified:

- **si**: the whole vault-backed npm publish flow is deleted (clap variant with
  its `publishfromvault`/`publish-from-vault` aliases, dispatch,
  `run_publish_npm_from_vault`, `resolve_si_command` — its only caller —
  `resolve_vault_command`, `vault_key_exists`, the integration test, and the
  RELEASING.md line). Publishing is `si build corepack pnpm publish`; token
  supply is the operator's own outer wrapper.
- **si-config**: the `surf.tunnel.vault_key` → `fort_key` alias (field, merge,
  normalize fallback, tests) is removed. No live settings used it.
- **viva**: the `vault_env_file` → `fort_env_file` settings alias (field, silent
  fallback, legacy-acceptance test, doc row) is removed; live settings were
  migrated first. Rebuilt, reinstalled, tunnel render verified.
- **vault**: no legacy recognition outside `migrate`. `is_public_key_header`
  matches only `VAULT_PUBLIC_KEY`; the `LEGACY_*` consts are gone in favour of a
  generic `encrypted:` sentinel — decrypt refuses EVERY non-current label
  (old, bare, or unknown) with the `vault migrate` instruction; `check` still
  classifies sentinel values as ciphertext so it never demands encrypting
  ciphertext. Hook-marker detection relies on the old marker containing the new
  substring rather than naming it.
- **fort**: same sentinel treatment; strictly broader than before (a future
  unknown label is now rejected instead of enumerated-or-passed-through).
  Deployed: release 20260824t195743626835312-b1ec2fb5, healthy, serving.
- **svelta-docs**: `publish-npm-from-vault.sh` deleted (its si-side command no
  longer exists); RELEASING fallback-path prerequisite dropped in both copies;
  the Vault pointer page now states refusal, not readability, and the promised
  `docs/VAULT.md` in this repo (missed C7 chunk) now exists.
- **disk**: `~/.si/vault/` and `/var/lib/fort/si-vault-keyring.json*` (all
  `.bak`s) removed — recoverable only from the 2026-08-24 backup tars. Local
  verdict `.env`s regenerated with the new header.

**The one deliberate exception:** `vault migrate` still understands retired
labels — it is the converter that eliminates them (and the only recovery path
for the 1027 old-label viva snapshots), not a serving-path fallback. Deleting
it would orphan that data; say the word and it goes too.

Suites after finalization: vault 17, fort 31, si 153, viva 69 — all green.
All 22 safe files re-verified byte-identical to the pre-migration plaintext.
