# Reforge

Reforge is a terminal-first Windows tool for backing up the structure of a development environment and rebuilding or safely merging it on another Windows PC. It discovers applications, runtimes, package-manager state, configuration, and related evidence; writes an inspectable `.reforge` package; and keeps partial, manual, unsupported, and failed work visible.

Reforge is local-first. It is not a disk image, a general file-sync tool, or a credential/session cloner. Passwords, browser sessions, authentication state, and unknown executables are excluded by default.

## Quick Start

### Run an extracted Windows release

Extract the complete Windows x64 release archive, keep its files together, open PowerShell in that directory, and run:

```powershell
.\reforge
```

The archive contains `reforge.exe`, the launchers, and the install/uninstall scripts. It does not need Rust, Node.js, or pnpm. Release assets include SHA-256 checksum files and a signature for the CLI binary; verify downloaded assets according to your trust policy before running them.

### Run a source checkout

From the repository root, use the same command:

```powershell
.\reforge
```

The launcher prefers a ready Windows x64 `reforge.exe` beside the scripts, then a release binary already built under `target`. If neither exists, a complete source checkout can be built only with the toolchain pinned in `rust-toolchain.toml` (currently Rust 1.98.0), the `x86_64-pc-windows-msvc` target, and Visual Studio 2022 Build Tools with **Desktop development with C++** and a Windows SDK. The launcher reports missing prerequisites; it does not download a release executable or silently install a toolchain.

### Install for new terminals

From an extracted release or a build-ready checkout:

```powershell
.\install.ps1
```

The installer copies the CLI and its managed scripts to `%LOCALAPPDATA%\Reforge\bin` and adds that directory to the user PATH only when an equivalent entry is absent. Open a new terminal, then run `reforge` from any directory. Installation is user-level and does not require administrator privileges.

Because Windows resolves `reforge.exe` before `reforge.cmd`, uninstall through the script rather than a `reforge uninstall` command:

```powershell
.\uninstall.ps1
# Or, from any directory:
& "$env:LOCALAPPDATA\Reforge\bin\uninstall.ps1"
```

The install manifest records file hashes and whether this installer added the PATH entry. Uninstall removes one installer-owned PATH entry and only unchanged, installer-owned files. Modified or unrelated files, application state, and backup packages are preserved.

## Main menu

Running Reforge without arguments opens the keyboard UI:

```text
REFORGE
Backup & Restore your Windows setup
================================
> [1] Quick Backup
  [2] Custom Backup
  [3] Restore Backup
  [4] Browse Detected Components
  [5] Scan This PC
  [6] Backup History
  [7] Advanced
  [8] Settings
  [0] Exit
```

Use Up/Down and Enter, or a number shortcut. Use Space to toggle items in selection screens, Esc/Backspace to go back, and Ctrl+C to stop safely. On first use, Reforge explains its safety boundary and checks the host; continuing records that welcome acknowledgement so it is not shown on every launch. Reforge scans when a current inventory is needed.

## Backup workflows

### Quick Backup and presets

Choose **Quick Backup**, review the host check, then select a preset:

- **Recommended** — safe default for most users;
- **Developer PC** — applications, runtimes, tools, Git, and package managers;
- **AI Development** — AI harness configuration, MCP metadata, skills/instructions, and runtimes, without authentication state or executable hooks;
- **AI Workstation** — the same AI configuration boundary plus safely portable developer packages and dependencies;
- **Full Safe Backup** — everything currently classified as safely portable;
- **Minimal** — core applications and configuration;
- **Custom** — continue into manual component selection.

Reforge shows the proposed component counts and exclusions before writing anything. Required dependencies are added transitively. Confirm with Enter or switch to Custom when the recommendation is not the set you want. The selected preset is remembered as the next default; Settings can choose another default.

The default scan also recognizes additional local agent runtimes when their allowlisted roots exist: Antigravity (`.antigravity`), Hermes (`.hermes`), OMP (`.omp/agent`), and Orca (`%APPDATA%\\orca`). These adapters collect only reviewed text configuration, instructions, and skills surfaces. Authentication tokens, profiles, sessions, browser state, caches, databases, logs, provider key material, executable extensions, and unknown binaries remain excluded and are called out in component details.
When a known additional agent launcher is present on `PATH` (for example OpenClaude, GitHub Copilot, Cursor, Gemini, Aider, Goose, Kiro, Cline, Qwen Code, or OpenClaw), the scan adds a catalog-only **AI Harnesses** entry. It records only the launcher name and is marked `PARTIAL`, `MANUAL`, `UNVERIFIED`, and `WARNING`; no executable, configuration, credential, or session data is copied. Install and authenticate these agents separately on the target machine.

### Custom Backup

Choose **Custom Backup** to browse categories and components, toggle selections, inspect portability and restore badges, and review dependencies and warnings. Sensitive, large-data, manual, and portable-binary choices never become implicit authorization. The review screen remains the final checkpoint before package creation.

By default, packages are named `Reforge-YYYY-MM-DD-HHMMSS.reforge` and written to the Windows **Documents** known folder under `Reforge Backups` (typically `%USERPROFILE%\Documents\Reforge Backups`). Settings can point future backups and history at another folder.

## Restore workflow

Choose **Restore Backup** to select a package from the configured backup folder or enter another `.reforge` path. Reforge validates the archive and object hashes, shows trust and compatibility warnings, and identifies manual or reauthentication work before offering:

- **Recommended / Migration** — merge safely with the current PC and preserve target data;
- **Clean / Rebuild** — rebuild onto a fresh Windows installation while still honoring safety gates;
- **Advanced** — inspect or explicitly choose the planning mode.

Reforge creates and displays a journaled plan before execution. Review its operations, conflicts, backups, manual actions, and source evidence; execution starts only after explicit confirmation. Replacements in the supported user-file/config subset are backed up and written atomically. Migration does not delete target data.

Normal discovery, backup, inspection, planning, and supported user-level restore work runs without elevation. When a reviewed operation needs administrator rights, Reforge may offer a user-requested UAC restart. That boundary does not make protected Windows state universally restorable: services, tasks, Windows features, protected default-app choices, and other system mutations can remain manual or unsupported.

If a restore pauses, resolve the displayed action and resume the same run through **Advanced > Runs / Resume pending restore**. Reforge does not create hidden `RunOnce` or scheduled-task persistence. Always read the final component statuses and redacted report; process success does not mean every selected component was restored.

## History, scanning, and Settings

- **Backup History** lists packages in the configured backup folder. Open one to inspect it, verify integrity, restore it, show its location, or explicitly delete that package.
- **Browse Detected Components** explains what the latest inventory contains without creating a backup.
- **Scan This PC** refreshes the persisted inventory. A stale inventory is also refreshed when a workflow needs current data.
- **Advanced** exposes package inspection, plan preview, pending-run resume, manual actions, verification reports, diagnostics, inventory export, and CLI help.
- **Settings** can change the backup directory, restore the default Documents backup directory, choose the default backup preset, switch between ASCII and Unicode terminal appearance, and toggle warning detail. The normal view puts important warnings first; the detailed view paginates all warnings rather than hiding them. Credential exclusions and the core safety gates are not weakened by presentation settings.

The default application state directory is `%LOCALAPPDATA%\Reforge`. It contains `preferences.json`, inventory, run records, the SQLite journal, and redacted reports. Backup packages live in the configured backup folder instead, so uninstalling the launcher does not remove either state or backups. ASCII appearance is the default and is always used when `TERM=dumb`; Unicode can be enabled in Settings. For an isolated CLI run, set `REFORGE_STATE_DIR` to an absolute, non-reparse directory before starting Reforge.

## CLI and JSON compatibility

The terminal UI is a presentation layer over the existing application service and domain engine. It does not replace the explicit command contract:

```powershell
reforge                 # main menu
reforge backup          # guided Quick Backup flow
reforge restore         # guided restore chooser
reforge doctor --json
reforge scan --json
reforge inventory show --json
reforge restore --package <path> --mode <rebuild|migrate> --yes-safe --json
```

Automation subcommands continue to emit one versioned JSON document on stdout when `--json` is requested, with progress on stderr and the documented exit codes. Use explicit CLI options for scripts that need a selection file, package path, restore mode, durable run ID, or report path. There is no launcher-level `reforge uninstall` contract; use `uninstall.ps1` as shown above.

## Current runtime boundary and limitations

The supported release target is Windows 11 x64 (`x86_64-pc-windows-msvc`). The checked-in desktop artifact remains an informational CLI-only shell: it registers no Tauri commands, native file dialogs, or filesystem/shell plugins. The terminal command is the product control surface.

Read the [support matrix](docs/support-matrix.md) before relying on an adapter. The [security model](docs/security.md) describes deliberately excluded data and trust boundaries. The [recovery procedure](docs/recovery.md) covers interrupted runs, manual actions, reboot pauses, and migration recovery.

Important current boundaries remain explicit:

- browser and VS Code adapters are library-only/partial and are not registered in the default automatic CLI scan;
- the CLI does not collect secret values for an encrypted vault, so a non-empty secret selection fails with `VAULT_REQUIRED` rather than copying plaintext;
- provider/runtime installation is a typed, partial path with no latest-version fallback, arbitrary command execution, or unreviewed bootstrap download;
- Windows registration is observation-first; protected system writes, services, tasks, features, startup commands, and default-app `UserChoice` state are manual or unsupported;
- WSL and Docker support is partial and does not promise full distribution, mutable VM disk, unrestricted image, or volume capture;
- Reforge does not promise direct PC transfer, disk-image restore, cross-platform operation, complete provider/application coverage, or full machine identity, driver, and license cloning;
- credentials, DPAPI-protected data, browser cookies/logins, OAuth sessions, application-bound tokens, executable hooks/plugins/skills, and unknown binaries are never silently restored.

Every uncovered case remains visible as partial, manual, unsupported, reauthentication-required, or failed rather than being silently omitted.

## What is implemented

- bounded Windows host, known-folder, registration, runtime, provider, WSL, Docker, harness, and generic executable discovery;
- typed component identities, evidence, provenance, dependency closure, portability, and restore strategies;
- deterministic ZIP64 `.reforge` packages with canonical metadata, BLAKE3 object IDs, zstd object frames, size limits, and fail-closed inspection;
- rebuild and migration planning with target comparison, conflict classification, backups before file/config replacement, and no target deletion;
- typed restore operations, durable SQLite WAL journaling, manual-action acknowledgement, reboot pause/resume, and redacted verification reports;
- fixture-backed Rust tests, UI checks, CLI smoke coverage, and a disposable Hyper-V E2E harness.

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

Build the terminal binary alone when a standalone executable is needed:

```powershell
cargo build -p reforge-cli --release --target x86_64-pc-windows-msvc --locked
$reforge = (Resolve-Path '.\target\x86_64-pc-windows-msvc\release\reforge.exe').Path
& $reforge --version
& $reforge --help
```

The terminal binary does not require Node or pnpm after build. The desktop source remains in the workspace so its CLI-only boundary is compiled and checked, but it is not a control surface in this release.

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