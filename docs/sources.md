# Source ledger

This is the maintainer-facing source ledger for Reforge. Each row records the source label, exact URL, access date, software/version scope, and the implementation fact it supports. `UNVERIFIED` means the source page did not pin a version; version-specific behavior must be captured in an adapter fixture or downgraded to manual rather than inferred.

The canonical copy is Section 39 of [`REFORGE_IMPLEMENTATION_SPEC.md`](../REFORGE_IMPLEMENTATION_SPEC.md). Keep both copies synchronized when an external contract or implementation decision changes. Source URLs are evidence, not commands to execute, and appearing in a package never causes a URL fetch.

## Adapter-to-source map

| Adapter or boundary | Current implementation | Source rows to review |
|---|---|---|
| `WinGetAdapter` | Registered in the CLI coordinator; typed export, install, and exact verification path. | WinGet list, export, packages JSON schema, install |
| `WindowsRegistrationAdapter` | Registered; observation-only registry/AppX/startup/shortcut/service/task/feature/default-association path. | Windows Installer uninstall registry values, Application registration and App Paths, Known folders, Default Programs, QueryCurrentDefault, Default app association export/import, Environment variables, RegistryView, Task Scheduler 2.0 interfaces, Restart Manager, Reparse points, UAC |
| `GenericExecutableAdapter` and PE boundary | Registered; bounded executable identity, version, signer, hash, and source-correlation path. | Application registration and App Paths, GetFileVersionInfoW, WinVerifyTrust, Reparse points |
| `ChocolateyAdapter` / `ScoopAdapter` | Registered; bounded export parsing with source/script review boundaries. | Chocolatey export, Scoop export/import command reference |
| `JavaScriptAdapter` | Registered for npm, pnpm, Yarn, and Bun; structured package records and typed descriptors. | npm install, npm list, pnpm list, pnpm add/global, Bun package-manager utilities |
| Python/runtime adapters | Python adapter registered; pip/pipx/uv evidence is bounded and environment-sensitive. | pip list, pip install/report, pip inspect JSON report, uv CLI |
| Rust/Go/.NET/PowerShell provider adapters | Registered; source, ABI, runtime, and script/module risk remain explicit. | Cargo install, rustup basics, Rust standard library, relevant provider rows |
| `WslAdapter` | Registered; distro/config/prerequisite/export eligibility path. | WSL install, WSL basic commands/export/import, WSL configuration |
| `DockerAdapter` | Registered; contexts/images/volumes/credential-helper metadata and typed restore boundary. | Docker Desktop backup and restore, Docker image save, Docker volume backup/restore, Docker context export, Docker credential stores |
| Codex/Claude Code/OpenCode adapters | Registered; settings/MCP/artifact metadata path with no hook/plugin execution. | Codex configuration reference, Codex advanced configuration, Codex MCP, Codex authentication, Claude Code settings, Claude Code MCP, Claude Code plugins, OpenCode config |
| Browser adapters | Standalone and fixture-tested; not registered in current CLI `default_registry`. | Chromium user data directory, Chrome application-bound encryption, Chrome bookmarks, Edge user data directory policy, Edge sync, Firefox profile backup, Firefox profile manager, Firefox profile source |
| VS Code adapter | Standalone and fixture-tested; not registered in current CLI `default_registry`; extension restore handler exists. | VS Code CLI, VS Code extension marketplace/CLI, VS Code Settings Sync |
| Package/object/vault boundaries | Package reader/writer, object store, optional signatures, and age vault are library boundaries; CLI package creation is non-secret and unsigned. | age format, age Rust crate, zeroize Rust crate, ZIP Rust crate, zstd Rust crate, BLAKE3 Rust crate, Ed25519 Dalek, SQLite WAL, SQLite online backup |
| Domain/schema/CLI/runtime boundaries | Canonical Rust model, generated schemas/Typeshare, typed process runner, CLI envelope, and Tauri boundary. | Schemars, Typeshare, UUID Rust crate, Chrono Rust crate, URL Rust crate, async-trait, thiserror, Tokio process, Clap, Tauri architecture, Tauri capabilities, Tauri updater signing, Svelte 5 state/context guidance, Rust standard library |

The adapter map intentionally records that browser and VS Code discovery are not currently in the automatic CLI scan. Do not change their status to automatic until registration, end-to-end behavior, and verification evidence are implemented.

## Windows platform

| Source | URL | Date accessed | Software version | Fact used by Reforge |
|---|---|---|---|---|
| [WinGet list](https://learn.microsoft.com/en-us/windows/package-manager/winget/list) | `https://learn.microsoft.com/en-us/windows/package-manager/winget/list` | 2026-08-29 | WinGet 1.29.290 observed; docs updated 2026-07-21 | Enumerate installed applications with bounded exact queries for verification. The reviewed CLI has no JSON output option, so localized table/detail text is not parsed as structured identity/version data. |
| [WinGet export](https://learn.microsoft.com/en-us/windows/package-manager/winget/export) | `https://learn.microsoft.com/en-us/windows/package-manager/winget/export` | 2026-08-29 | WinGet 1.29.290 observed; docs updated 2026-07-21 | Use machine-readable package/source identifiers and optional versions for discovery and provenance; the export does not carry publisher metadata. |
| [WinGet packages JSON schema](https://github.com/microsoft/winget-cli/tree/master/schemas/JSON/packages) | `https://github.com/microsoft/winget-cli/tree/master/schemas/JSON/packages` | 2026-08-29 | Schema 1.0 and 2.0 reviewed | Accept the documented `Id`/`PackageIdentifier` spellings, required source details, and optional package versions without inventing absent fields. |
| [WinGet install](https://learn.microsoft.com/en-us/windows/package-manager/winget/install) | `https://learn.microsoft.com/en-us/windows/package-manager/winget/install` | 2026-08-29 | WinGet 1.29.290 observed; docs updated 2026-07-21 | Use exact ID/source/version selection and documented hash, silent, agreement, and reboot controls. |
| [WinGet Configuration](https://learn.microsoft.com/en-us/windows/package-manager/configuration/) | `https://learn.microsoft.com/en-us/windows/package-manager/configuration/` | 2026-08-29 | UNVERIFIED | Treat declarative configuration as a reviewed input, never as an unrestricted package command stream. |
| [Windows Installer uninstall registry values](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key) | `https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key` | 2026-08-29 | UNVERIFIED | Read display name, version, publisher, install location, and uninstall metadata as discovery evidence. |
| [Application registration and App Paths](https://learn.microsoft.com/en-us/windows/win32/shell/app-registration) | `https://learn.microsoft.com/en-us/windows/win32/shell/app-registration` | 2026-08-29 | UNVERIFIED | Correlate registered executable paths and application registration without treating registration as binary proof. |
| [Known folders / SHGetKnownFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath) | `https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath` | 2026-08-29 | UNVERIFIED | Resolve current-target known folders instead of hardcoding user or drive paths. |
| [Default Programs](https://learn.microsoft.com/en-us/windows/win32/shell/default-programs) | `https://learn.microsoft.com/en-us/windows/win32/shell/default-programs` | 2026-08-29 | UNVERIFIED | Discover registered default-program associations through supported Windows mechanisms. |
| [QueryCurrentDefault](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-iapplicationassociationregistration-querycurrentdefault) | `https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-iapplicationassociationregistration-querycurrentdefault` | 2026-08-29 | UNVERIFIED | Query current HTTP, HTTPS, and HTML associations; do not infer default status from installation alone. |
| [Default app association export/import](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/export-or-import-default-application-associations?view=windows-11) | `https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/export-or-import-default-application-associations?view=windows-11` | 2026-08-29 | Windows 11 reference | Use supported association export/import where policy permits; never write a guessed UserChoice hash. |
| [Environment variables](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables) | `https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables` | 2026-08-29 | UNVERIFIED | Distinguish process, user, and system environment scopes and broadcast persistent changes appropriately. |
| [GetFileVersionInfoW](https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfow) | `https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfow` | 2026-08-29 | UNVERIFIED | Read PE version-resource metadata without executing candidate binaries. |
| [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust) | `https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust` | 2026-08-29 | UNVERIFIED | Treat only a zero trust-provider return value as success and preserve nonzero results. |
| [RegistryView](https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registryview?view=net-10.0) | `https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registryview?view=net-10.0` | 2026-08-29 | .NET API view net-10.0 | Inspect both 32-bit and 64-bit registry views on 64-bit Windows. |
| [Task Scheduler 2.0 interfaces](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-2-0-interfaces) | `https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-2-0-interfaces` | 2026-08-29 | UNVERIFIED | Keep scheduled-task inspection and any future resume registration in a typed, explicit boundary. |
| [Restart Manager](https://learn.microsoft.com/en-us/windows/win32/rstmgr/about-restart-manager) | `https://learn.microsoft.com/en-us/windows/win32/rstmgr/about-restart-manager` | 2026-08-29 | UNVERIFIED | Detect applications that hold files and make quiescence/manual actions visible. |
| [Reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points) | `https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points` | 2026-08-29 | UNVERIFIED | Record and reject unsafe reparse traversal during discovery and restore. |
| [UAC](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works) | `https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works` | 2026-08-29 | UNVERIFIED | Use least privilege and an explicit elevation boundary instead of running the whole application elevated. |

## WSL, Docker, and SSH

| Source | URL | Date accessed | Software version | Fact used by Reforge |
|---|---|---|---|---|
| [WSL install](https://learn.microsoft.com/en-us/windows/wsl/install) | `https://learn.microsoft.com/en-us/windows/wsl/install` | 2026-08-29 | UNVERIFIED | Identify documented WSL prerequisites and installation behavior before importing distributions. |
| [WSL basic commands/export/import](https://learn.microsoft.com/en-us/windows/wsl/basic-commands) | `https://learn.microsoft.com/en-us/windows/wsl/basic-commands` | 2026-08-29 | UNVERIFIED | Use documented distribution listing, export, and import operations instead of copying VM disks. |
| [WSL configuration](https://learn.microsoft.com/en-us/windows/wsl/wsl-config) | `https://learn.microsoft.com/en-us/windows/wsl/wsl-config` | 2026-08-29 | UNVERIFIED | Treat `.wslconfig` and `wsl.conf` as separate, scoped configuration artifacts. |
| [Docker Desktop backup and restore](https://docs.docker.com/desktop/settings-and-maintenance/backup-and-restore/) | `https://docs.docker.com/desktop/settings-and-maintenance/backup-and-restore/` | 2026-08-29 | UNVERIFIED | Separate Docker Desktop backup state from images, volumes, contexts, and credential stores. |
| [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/) | `https://docs.docker.com/reference/cli/docker/image/save/` | 2026-08-29 | UNVERIFIED | Use typed image export/import for selected images and record size/provenance. |
| [Docker volume backup/restore](https://docs.docker.com/engine/storage/volumes/#back-up-restore-or-migrate-data-volumes) | `https://docs.docker.com/engine/storage/volumes/#back-up-restore-or-migrate-data-volumes` | 2026-08-29 | UNVERIFIED | Use documented volume backup/restore only with explicit size and quiescence policy. |
| [Docker context export](https://docs.docker.com/reference/cli/docker/context/export/) | `https://docs.docker.com/reference/cli/docker/context/export/` | 2026-08-29 | UNVERIFIED | Export Docker context metadata as a distinct portable artifact. |
| [Docker credential stores](https://docs.docker.com/reference/cli/docker/login/#credential-stores) | `https://docs.docker.com/reference/cli/docker/login/#credential-stores` | 2026-08-29 | UNVERIFIED | Record credential-helper references without copying active credential stores by default. |
| [OpenSSH for Windows overview](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-overview) | `https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-overview` | 2026-08-29 | UNVERIFIED | Treat OpenSSH configuration, known hosts, public keys, and encrypted private keys as separate states. |

## Browsers and VS Code

| Source | URL | Date accessed | Software version | Fact used by Reforge |
|---|---|---|---|---|
| [Chromium user data directory](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/user_data_dir.md) | `https://chromium.googlesource.com/chromium/src/+/HEAD/docs/user_data_dir.md` | 2026-08-29 | UNVERIFIED | Use browser-family-specific user-data roots and do not assume one universal profile path. |
| [Chrome application-bound encryption](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html) | `https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html` | 2026-08-29 | Chrome behavior described by 2024 source | Treat cookies and session material as OS/application-bound and require reauthentication. |
| [Chrome bookmarks](https://support.google.com/chrome/answer/96816) | `https://support.google.com/chrome/answer/96816` | 2026-08-29 | UNVERIFIED | Prefer supported bookmark export/sync semantics over copying protected session data. |
| [Edge user data directory policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/userdatadir) | `https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/userdatadir` | 2026-08-29 | UNVERIFIED | Respect Edge policy-selected user-data directories when locating profiles. |
| [Edge sync](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-enterprise-sync) | `https://learn.microsoft.com/en-us/deployedge/microsoft-edge-enterprise-sync` | 2026-08-29 | UNVERIFIED | Classify sync-restorable state separately from credentials and account sessions. |
| [Firefox profile backup](https://support.mozilla.org/en-US/kb/back-and-restore-information-firefox-profiles) | `https://support.mozilla.org/en-US/kb/back-and-restore-information-firefox-profiles` | 2026-08-29 | UNVERIFIED | Use Firefox-supported profile backup guidance for portable subsets and warn about locks/databases. |
| [Firefox profile manager](https://support.mozilla.org/en-US/kb/profile-manager-create-remove-switch-profiles) | `https://support.mozilla.org/en-US/kb/profile-manager-create-remove-switch-profiles` | 2026-08-29 | UNVERIFIED | Preserve profile identity and selection without assuming the default profile is the intended one. |
| [Firefox profile source](https://firefox-source-docs.mozilla.org/toolkit/profile/index.html) | `https://firefox-source-docs.mozilla.org/toolkit/profile/index.html` | 2026-08-29 | UNVERIFIED | Use upstream profile layout documentation for adapter-scoped state discovery. |
| [VS Code CLI](https://code.visualstudio.com/docs/configure/command-line) | `https://code.visualstudio.com/docs/configure/command-line` | 2026-08-29 | UNVERIFIED | Use documented CLI operations for extension/profile inspection where available. |
| [VS Code extension marketplace/CLI](https://code.visualstudio.com/docs/configure/extensions/extension-marketplace) | `https://code.visualstudio.com/docs/configure/extensions/extension-marketplace` | 2026-08-29 | UNVERIFIED | Record extension identity/source and reinstall through the documented marketplace/CLI path. |
| [VS Code Settings Sync](https://code.visualstudio.com/docs/configure/settings-sync) | `https://code.visualstudio.com/docs/configure/settings-sync` | 2026-08-29 | UNVERIFIED | Classify settings sync as account-mediated and do not promise session or credential portability. |

## AI harnesses

| Source | URL | Date accessed | Software version | Fact used by Reforge |
|---|---|---|---|---|
| [Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference) | `https://learn.chatgpt.com/docs/config-file/config-reference` | 2026-08-29 | UNVERIFIED | Parse documented Codex configuration fields and preserve scope without copying auth values. |
| [Codex advanced configuration](https://learn.chatgpt.com/docs/config-file/config-advanced) | `https://learn.chatgpt.com/docs/config-file/config-advanced` | 2026-08-29 | UNVERIFIED | Preserve documented advanced/profile configuration and mark unsupported fields rather than guessing. |
| [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) | `https://learn.chatgpt.com/docs/extend/mcp?surface=cli` | 2026-08-29 | UNVERIFIED | Normalize Codex MCP definitions into the shared typed MCP model. |
| [Codex authentication](https://learn.chatgpt.com/docs/auth) | `https://learn.chatgpt.com/docs/auth` | 2026-08-29 | UNVERIFIED | Record authentication mode and produce reauthentication actions instead of extracting sessions. |
| [Claude Code settings](https://code.claude.com/docs/en/settings) | `https://code.claude.com/docs/en/settings` | 2026-08-29 | UNVERIFIED | Preserve documented Claude Code settings by scope and ownership. |
| [Claude Code MCP](https://code.claude.com/docs/en/mcp) | `https://code.claude.com/docs/en/mcp` | 2026-08-29 | UNVERIFIED | Parse Claude MCP transports, commands, arguments, and secret references semantically. |
| [Claude Code plugins](https://code.claude.com/docs/en/plugins) | `https://code.claude.com/docs/en/plugins` | 2026-08-29 | UNVERIFIED | Treat plugins, hooks, and plugin commands as untrusted metadata/configuration, never auto-executed package instructions. |
| [OpenCode config](https://opencode.ai/docs/config/) | `https://opencode.ai/docs/config/` | 2026-08-29 | UNVERIFIED | Preserve OpenCode config precedence, managed ownership, JSONC, and environment references without evaluating interpolation. |

## Package managers, cryptography, formats, and domain tooling

| Source | URL | Date accessed | Software version | Fact used by Reforge |
|---|---|---|---|---|
| [Chocolatey export](https://docs.chocolatey.org/en-us/choco/commands/export/) | `https://docs.chocolatey.org/en-us/choco/commands/export/` | 2026-08-29 | UNVERIFIED | Use Chocolatey export only for provider-owned package identity and preserve provider provenance. |
| [Scoop export/import command reference](https://github.com/ScoopInstaller/Scoop/wiki/Commands#export) | `https://github.com/ScoopInstaller/Scoop/wiki/Commands#export` | 2026-08-29 | UNVERIFIED | Use documented Scoop export/import semantics and do not infer bucket/source data from names. |
| [npm install](https://docs.npmjs.com/cli/v11/commands/npm-install/) | `https://docs.npmjs.com/cli/v11/commands/npm-install/` | 2026-08-29 | npm CLI v11 | Reinstall npm packages through explicit package/version/source inputs. |
| [npm list](https://docs.npmjs.com/cli/v11/commands/npm-ls/) | `https://docs.npmjs.com/cli/v11/commands/npm-ls/` | 2026-08-29 | npm CLI v11 | Enumerate package trees and versions through structured/listing semantics. |
| [pnpm list](https://pnpm.io/cli/list) | `https://pnpm.io/cli/list` | 2026-08-29 | UNVERIFIED | Enumerate pnpm package identity and version without scraping human-oriented output where structured output exists. |
| [pnpm add/global](https://pnpm.io/cli/add) | `https://pnpm.io/cli/add` | 2026-08-29 | UNVERIFIED | Restore explicitly selected global/project packages with recorded scope. |
| [Bun package-manager utilities](https://bun.sh/docs/pm/cli/pm) | `https://bun.sh/docs/pm/cli/pm` | 2026-08-29 | UNVERIFIED | Use Bun's documented package-manager operations and preserve runtime/provider identity. |
| [pip list](https://pip.pypa.io/en/stable/cli/pip_list/) | `https://pip.pypa.io/en/stable/cli/pip_list/` | 2026-08-29 | Stable docs; exact version UNVERIFIED | Enumerate Python packages with environment scope and version. |
| [pip install/report](https://pip.pypa.io/en/stable/cli/pip_install/) | `https://pip.pypa.io/en/stable/cli/pip_install/` | 2026-08-29 | Stable docs; exact version UNVERIFIED | Restore Python packages from explicit requirements/source and retain report data. |
| [pip inspect JSON report](https://pip.pypa.io/en/stable/reference/inspect-report/) | `https://pip.pypa.io/en/stable/reference/inspect-report/` | 2026-08-29 | Stable docs; exact version UNVERIFIED | Prefer machine-readable package metadata for dependency/provenance evidence. |
| [uv CLI](https://docs.astral.sh/uv/reference/cli/) | `https://docs.astral.sh/uv/reference/cli/` | 2026-08-29 | UNVERIFIED | Treat uv environments and package operations as provider-scoped state. |
| [Cargo install](https://doc.rust-lang.org/cargo/commands/cargo-install.html) | `https://doc.rust-lang.org/cargo/commands/cargo-install.html` | 2026-08-29 | UNVERIFIED | Restore Cargo-installed binaries from explicit crate/version/source identity. |
| [rustup basics](https://rust-lang.github.io/rustup/basics.html) | `https://rust-lang.github.io/rustup/basics.html` | 2026-08-29 | UNVERIFIED | Separate rustup toolchain state from Cargo-installed tools and record target architecture. |
| [age format](https://age-encryption.org/v1) | `https://age-encryption.org/v1` | 2026-08-29 | age format v1 | Use the documented age file format for authenticated portable vault encryption. |
| [age Rust crate](https://docs.rs/age/latest/age/) | `https://docs.rs/age/latest/age/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Implement vault encryption through the maintained age crate, not custom cryptography. |
| [zeroize Rust crate](https://docs.rs/zeroize/latest/zeroize/) | `https://docs.rs/zeroize/latest/zeroize/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Clear secret buffers at their Rust ownership boundaries. |
| [ZIP Rust crate](https://docs.rs/zip/latest/zip/) | `https://docs.rs/zip/latest/zip/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Use ZIP/ZIP64 streaming with central-directory and extraction limits. |
| [zstd Rust crate](https://docs.rs/zstd/latest/zstd/) | `https://docs.rs/zstd/latest/zstd/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Compress bounded content-addressed object frames without loading large objects wholesale. |
| [SQLite WAL](https://www.sqlite.org/wal.html) | `https://www.sqlite.org/wal.html` | 2026-08-29 | UNVERIFIED | Use WAL semantics for durable journal reads/writes and crash recovery. |
| [SQLite online backup](https://www.sqlite.org/backup.html) | `https://www.sqlite.org/backup.html` | 2026-08-29 | UNVERIFIED | Use supported SQLite backup semantics for journal/diagnostic copying where needed. |
| [BLAKE3 Rust crate](https://docs.rs/blake3/latest/blake3/) | `https://docs.rs/blake3/latest/blake3/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Use BLAKE3-256 for canonical IDs and content-addressed object integrity. |
| [Schemars](https://github.com/gresau/schemars) | `https://github.com/gresau/schemars` | 2026-08-29 | UNVERIFIED | Generate JSON Schema from the canonical Rust domain model. |
| [Typeshare](https://github.com/1Password/typeshare) | `https://github.com/1Password/typeshare` | 2026-08-29 | UNVERIFIED | Generate checked-in TypeScript DTOs from the same canonical Rust model. |
| [Ed25519 Dalek](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/) | `https://docs.rs/ed25519-dalek/latest/ed25519_dalek/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Verify optional package signatures; signature validity does not establish trust. |
| [cargo-deny](https://embarkstudios.github.io/cargo-deny/) | `https://embarkstudios.github.io/cargo-deny/` | 2026-08-29 | UNVERIFIED | Check dependency licenses, sources, duplicates, and advisories in CI. |
| [RustSec / cargo-audit](https://rustsec.org/) | `https://rustsec.org/` | 2026-08-29 | UNVERIFIED | Audit Cargo.lock against Rust ecosystem security advisories. |
| [UUID Rust crate](https://docs.rs/uuid/latest/uuid/) | `https://docs.rs/uuid/latest/uuid/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Generate UUIDv7 run identifiers with explicit serialization. |
| [Chrono Rust crate](https://docs.rs/chrono/latest/chrono/) | `https://docs.rs/chrono/latest/chrono/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Serialize UTC timestamps in RFC 3339-compatible domain fields. |
| [URL Rust crate](https://docs.rs/url/latest/url/) | `https://docs.rs/url/latest/url/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Parse and validate URLs while rejecting embedded credential material where restricted. |
| [async-trait](https://docs.rs/async-trait/latest/async_trait/) | `https://docs.rs/async-trait/latest/async_trait/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Define dynamic async provider/adapter interfaces where object safety requires it. |
| [thiserror](https://docs.rs/thiserror/latest/thiserror/) | `https://docs.rs/thiserror/latest/thiserror/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Derive typed Rust error sources that map to stable Reforge error codes. |

## Technology evidence

| Source | URL | Date accessed | Software version | Fact used by Reforge |
|---|---|---|---|---|
| [Tauri architecture](https://v2.tauri.app/concept/architecture/) | `https://v2.tauri.app/concept/architecture/` | 2026-08-29 | Tauri 2 | Keep the Rust engine authoritative behind a narrow desktop command boundary. |
| [Tauri capabilities](https://v2.tauri.app/security/capabilities/) | `https://v2.tauri.app/security/capabilities/` | 2026-08-29 | Tauri 2 | Scope capabilities per window and do not grant broad filesystem or shell access. |
| [Tauri updater signing](https://v2.tauri.app/plugin/updater/) | `https://v2.tauri.app/plugin/updater/` | 2026-08-29 | Tauri 2 | Verify signed update artifacts before installation and keep signing keys outside packages. |
| [Svelte 5 state/context guidance](https://svelte.dev/docs/svelte) | `https://svelte.dev/docs/svelte` | 2026-08-29 | Svelte 5 | Use typed UI state/context without moving business rules into the frontend. |
| [Rust standard library](https://doc.rust-lang.org/std/) | `https://doc.rust-lang.org/std/` | 2026-08-29 | Stable/current; exact toolchain UNVERIFIED | Prefer standard memory-safe, streaming, and filesystem primitives before bespoke utilities. |
| [Tokio process](https://docs.rs/tokio/latest/tokio/process/index.html) | `https://docs.rs/tokio/latest/tokio/process/index.html` | 2026-08-29 | latest docs; exact version UNVERIFIED | Run bounded provider processes without shell interpolation and with cancellation/output limits. |
| [Clap](https://docs.rs/clap/latest/clap/) | `https://docs.rs/clap/latest/clap/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Define a stable typed CLI command tree and JSON envelope. |

## Updating the ledger

For each external claim:

1. prefer first-party vendor documentation or upstream source;
2. record the exact URL, access date, and observed version scope;
3. record the fixture and adapter that rely on the claim;
4. if the source is ambiguous or version behavior is not proven, mark it `UNVERIFIED` and make the adapter report a manual action;
5. update the support matrix and relevant task section in the specification in the same change.

Do not add a source URL as evidence for a behavior that the current adapter does not implement. Do not turn a source URL into an executable command, installer, or download fallback.