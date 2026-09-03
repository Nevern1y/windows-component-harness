# Reforge

Reforge is a Windows-first, local-first environment reconstruction tool. It builds an inspectable dependency graph from a Windows machine, lets the user select a bounded subset, writes a portable `.reforge` package, and plans a safe rebuild or migration on another Windows target.

Reforge is not a disk image, a generic file backup utility, or a credential/session cloning tool. Every selected component remains visible as verified, partial, manual, unsupported, or failed.

## Current release boundary

The checked-in desktop artifact is intentionally **CLI-only**. The Tauri shell displays an informational notice; it does not register Tauri commands, native file dialogs, or filesystem/shell plugins. Use the `reforge` CLI for scan, package, plan, restore, resume, verification, and report workflows.

The current release targets Windows 11 x64 (`x86_64-pc-windows-msvc`). The engine is local-first: no account, hosted backend, paid API, or remote inventory is required. Provider installs may contact the explicitly selected provider source during a restore; Reforge does not fetch a package URL merely because it appears in package metadata.

Read the [support matrix](docs/support-matrix.md) before relying on an adapter. The [security model](docs/security.md) describes data that is deliberately excluded. The [recovery procedure](docs/recovery.md) covers interrupted runs, manual actions, reboot pauses, and migration safety.

## What is implemented

- bounded Windows host, known-folder, registration, runtime, provider, WSL, Docker, harness, and generic executable discovery;
- typed component identities, evidence, provenance, dependency closure, portability, and restore strategies;
- deterministic ZIP64 `.reforge` packages with canonical metadata, BLAKE3 object IDs, zstd object frames, size limits, and fail-closed inspection;
- rebuild and migration planning with target comparison, conflict classification, backups before file/config replacement, and no target deletion in MVP;
- typed restore operations, durable SQLite WAL journaling, manual-action acknowledgement, reboot pause/resume, and redacted verification reports;
- fixture-backed Rust tests, UI checks, CLI smoke coverage, and a disposable Hyper-V E2E harness.

## What is deliberately not promised

- complete coverage or automatic restore for every provider, browser, application, or Windows registration;
- Windows credentials, DPAPI-protected data, browser cookies/logins, OAuth sessions, or application-bound tokens;
- arbitrary command, script, hook, plugin, extension, installer, or unknown-binary execution from package data;
- direct PC transfer, disk-image restore, cross-platform operation, or full machine identity/driver/license cloning;
- automatic writes to system environment state, protected default-app `UserChoice` state, services, scheduled tasks, Windows features, or plaintext secret targets;
- full WSL distribution/package migration or unrestricted Docker VM/volume capture.

These cases are reported as partial, manual, unsupported, or reauthentication-required rather than silently omitted.

## Build from source

The repository pins the toolchain and frontend versions in `rust-toolchain.toml`, CI, and the lockfiles. On a Windows 11 x64 development machine:

```powershell
pnpm install --frozen-lockfile
cargo install typeshare-cli --version 1.13.4 --locked
pnpm --dir ui generate:types
pnpm run ui:build
pnpm run ui:check
cargo fmt --all -- --check
cargo build --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Build the CLI-only binary explicitly when a standalone executable is needed:

```powershell
cargo build -p reforge-cli --release --target x86_64-pc-windows-msvc --locked
$reforge = (Resolve-Path '.\\target\\x86_64-pc-windows-msvc\\release\\reforge.exe').Path
& $reforge --version
& $reforge --help
```

The packaged application does not require Node or pnpm after build. The desktop source remains in the workspace so its CLI-only boundary is compiled and checked, but it is not a control surface in this release.

## CLI workflow

Use a release binary as `reforge.exe`, or replace `reforge` below with `cargo run --locked -p reforge-cli --` while developing.

### 1. Check the host and scan

```powershell
reforge doctor --json
reforge scan --json
reforge inventory show --json
```

`scan` writes the authoritative inventory to the local Reforge state directory. Progress is written to stderr; `--json` emits one versioned JSON document on stdout. `inventory show` reads the last persisted inventory without rescanning.

The default state directory is `%LOCALAPPDATA%\\Reforge`. For an isolated run or test, set `REFORGE_STATE_DIR` to an absolute safe directory before invoking the CLI:

```powershell
$env:REFORGE_STATE_DIR = 'D:\\ReforgeRuns\\state'
```

The CLI rejects a relative state directory and rejects a state root that is not a regular, non-reparse directory.

### 2. Create and inspect a package

A selection file uses the canonical `SelectionInput` shape. This empty selection is valid and useful for a smoke test:

```json
{
  "components": [],
  "artifacts": [],
  "policy": {
    "secrets": "EXCLUDE",
    "large_data": "EXCLUDE",
    "unknown_binaries": "EXCLUDE",
    "max_bytes": null
  }
}
```

Replace the empty `components` array with component IDs from `inventory show` to create a useful package. Required dependencies are closed transitively. Ordinary config/data/export artifacts are selected according to the policy; secrets, large data, manual artifacts, and portable binaries require explicit policy/selection.

The empty selection is only a package-create/inspect smoke fixture; restore intentionally reports `FAILED` with `UNVERIFIED: no components were selected for restore`. Use at least one selected component when exercising the restore examples below.

```powershell
reforge package create `
  --output 'D:\\ReforgeRuns\\environment.reforge' `
  --selection 'D:\\ReforgeRuns\\selection.json' `
  --json

reforge package inspect 'D:\\ReforgeRuns\\environment.reforge' --json
```

Package creation refuses selected secret content unless an encrypted vault is supplied through a secure adapter. The current CLI does not expose secret-value collection, so a non-empty `--secret-selection` input returns `VAULT_REQUIRED`; it never copies the secret as ordinary package data. The package writer/reader vault APIs are covered separately in the support matrix.

Inspection validates the ZIP central directory, required metadata, canonical documents, object index, object frames, hashes, and optional signature metadata without extracting the archive. An unsigned package can be inspected, but restore still requires explicit approval.

### 3. Preview and execute a restore

`rebuild` targets a reinstalled/empty environment. `migrate` compares the package with the current non-empty target and exposes collisions before applying changes.

```powershell
reforge plan `
  --package 'D:\\ReforgeRuns\\environment.reforge' `
  --mode rebuild `
  --json

reforge restore `
  --package 'D:\\ReforgeRuns\\environment.reforge' `
  --mode rebuild `
  --yes-safe `
  --json
```

`plan` is a non-destructive preview and creates a durable run. `restore` requires `--yes-safe`, rechecks package trust and target compatibility, journals each typed operation, and writes a redacted report. File/config replacements use atomic writes and retain a sibling backup; migration never deletes target data.

For a non-empty target, use the same commands with `--mode migrate`:

```powershell
reforge plan --package 'D:\\ReforgeRuns\\environment.reforge' --mode migrate --json
reforge restore --package 'D:\\ReforgeRuns\\environment.reforge' --mode migrate --yes-safe --json
```

### 4. Resolve pauses and verify

A restore can stop for a manual action, reauthentication, a lock, an unsupported target, or a reboot. The report status and exit code make the pause machine-readable.

```powershell
reforge action list RUN_ID --json
reforge action acknowledge RUN_ID ACTION_ID --json
reforge resume RUN_ID --json
reforge verify RUN_ID --json
reforge report RUN_ID --output 'D:\\ReforgeRuns\\report.json' --json
```

Acknowledge an action only after the documented condition is resolved. `resume` reopens the existing package and journal, verifies the run identity and approval, and rechecks the target before continuing. Reforge does not create hidden `RunOnce` persistence; after a reboot, reopen the CLI and use the same run ID.

`target scan --json` is also available when a standalone normalized target snapshot is needed:

```powershell
reforge target scan --json
```

### Exit codes

| Code | Meaning |
|---:|---|
| 0 | Verified or already present. |
| 1 | Partial, skipped, unsupported, or failed report. |
| 2 | Invalid command, input, or package. |
| 3 | User action or reauthentication required. |
| 4 | Compatibility blocked. |
| 5 | Package trust or security policy blocked. |
| 6 | Interrupted, cancelled, or reboot pending. |

A successful process exit does not mean every selected component was restored: inspect the report status, component entries, warnings, manual actions, and verification evidence.

## Repository map

- `crates/reforge-domain`: canonical Rust model, IDs, redaction, schemas, and Typeshare source;
- `crates/reforge-platform-windows`: known folders, safe paths, processes, registry, PE, services, tasks, AppX/startup, and Windows API boundaries;
- `crates/reforge-discovery`: coordinator, evidence ledger, providers, harnesses, browser/editor adapters, deduplication, and recommendations;
- `crates/reforge-package`: canonical serialization, object store, ZIP64 reader/writer, optional signatures, and age vault boundary;
- `crates/reforge-restore`: target/diff/planner, typed operations, executor, journal, handlers, manual queue, and verification;
- `crates/reforge-cli`: the current control surface and shared application service;
- `src-tauri` and `ui`: the informational CLI-only desktop shell plus the future typed command UI source;
- `tests/vm`: disposable Hyper-V fixture procedure; never use it against a non-fixture VM.

The implementation contract and dependency order remain in [`REFORGE_IMPLEMENTATION_SPEC.md`](REFORGE_IMPLEMENTATION_SPEC.md).