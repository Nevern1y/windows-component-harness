---
title: REFORGE Implementation Specification
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
created: 2026-08-29
research_basis: Windows 11 / current 2025-2026 documentation reviewed 2026-08-29
---

# REFORGE Implementation Specification

> Source of truth for implementation. This document defines the product boundary, contracts, data model, security invariants, repository layout, verification contract, and atomic implementation tasks. Implementers must not replace a specified behavior with a simpler approximation without recording a decision and updating this file.

**Normative language:** MUST, MUST NOT, SHOULD, SHOULD NOT, MAY have their RFC 2119 meanings. `UNVERIFIED` means that the behavior is not sufficiently supported by an authoritative source and MUST NOT be used as a security-critical or automatic restore assumption.

## 0. Executive decision

Build a Windows-first, local-first environment reconstruction system, not a disk image and not a generic file backup tool.

The first release is a Rust application with a Tauri 2 desktop shell, a Svelte 5 UI, a Rust CLI, a typed discovery graph, a ZIP64 package containing content-addressed objects, and an age-encrypted optional vault. Restoration is a declarative, journaled DAG of typed operations. A package may contain executable data explicitly selected as `PortableBinary`, but it MUST NOT contain executable shell commands or package-provided command instructions.

The MVP target is Windows 10 22H2 and Windows 11 on x64, with Windows 11 x64 as the primary test target. ARM64 is represented in the model but is not an MVP compatibility guarantee. The app requires a functioning WebView2 runtime for the desktop UI; the CLI and core engine do not.

The product promise is deliberately bounded:

> Reforge maximizes the amount of selected user environment state that can be reconstructed, reports every partial or impossible item, and never claims that machine-bound credentials, browser sessions, hardware state, or licenses were cloned.

## 1. Product definition

Reforge performs this pipeline:

```text
DISCOVER -> NORMALIZE -> EVIDENCE-RANK -> RECOMMEND -> SELECT
         -> PACKAGE -> INSPECT TARGET -> PLAN -> APPLY -> VERIFY
```

It has four first-class workflows:

1. **Automatic discovery:** scan a configured Windows machine without requiring the user to name installed tools.
2. **Manual pack:** let the user choose any discovered components and dependencies to create `*.reforge`.
3. **Reinstall mode:** restore a selected environment after Windows has been reinstalled.
4. **Migrate/clone mode:** compare a source package with a non-empty target and merge safely.

A future direct-transfer transport MUST use the same manifest, graph, object IDs, operation model, and journal semantics as a portable package. It is not an alternate data model.

## 2. Problem and scope boundary

A Windows machine accumulates software, runtimes, package-managed tools, configuration, shell state, editor state, browser state, AI harness state, and unique data. Users commonly do not know how those things were installed or which files contain secrets. Existing tools solve only slices: package export, dotfile synchronization, browser sync, disk imaging, or scripted workstation setup.

Reforge owns the missing correlation layer and the honest restore plan. It does **not** own:

- Windows licensing, activation, product keys, or DRM circumvention;
- account-session theft or cookie migration;
- arbitrary script execution from a package;
- full-drive imaging;
- undocumented installer flags;
- cloud inventory, telemetry, or a mandatory service;
- a guarantee that an unknown executable can be attributed to GitHub;
- removal of unrelated target state;
- cross-platform parity in the MVP.

## 3. Product principles

1. **Reconstruction over copying.** Reinstall a known package and restore its portable configuration; copy binaries only when reconstruction is not feasible and the user explicitly selects it.
2. **Evidence before inference.** Every identity and relationship has evidence, confidence, and provenance.
3. **Typed operations only.** A package describes desired state; trusted built-in code decides how to perform it.
4. **Secure by non-automation.** Unknown, privileged, destructive, credential, and machine-bound actions stop for user review.
5. **Target is never assumed empty.** Migrate means inspect, compare, merge, back up, and preserve.
6. **Local-first.** No account, paid API, cloud backend, or remote inventory is required.
7. **Failure is data.** Partial completion, access denied, lock, missing source, reboot, and reauthentication are visible states.
8. **Idempotent resume.** A crash or reboot must not require starting from zero and must not repeat a completed destructive action.
9. **Boring dependencies.** Prefer platform APIs and mature libraries over bespoke formats and custom cryptography.

## 4. Research method and evidence policy

Research used authoritative vendor documentation, upstream source/documentation, and current package-manager references available on 2026-08-29. The implementation must preserve the source URL and observed fact in the source index or adapter documentation.

Facts used as design constraints include:

- WinGet `export` produces JSON with sources, packages, identifiers, and optional versions; `list` includes applications found through other installation paths and can report unknown versions. WinGet `install` supports exact ID/source/version selection and has explicit security-hash, silent, agreement, and reboot controls.
- Windows uninstall registration contains display name/version/publisher/install location/uninstall string, but registry view matters on 64-bit Windows. Both 32-bit and 64-bit views must be inspected.
- `SHGetKnownFolderPath` is the source for current-user known-folder paths; hardcoded `C:\Users\...` paths are prohibited.
- Windows default-app selection is per user and modern Windows protects user choices; Reforge may inspect or launch the supported UI but must not write a guessed `UserChoice` hash.
- `WinVerifyTrust` returns success only when its return value is zero and verifies a trust-provider action; file version data comes through `GetFileVersionInfoW` and `VerQueryValue`.
- Environment blocks have user and system scopes; persistent system changes involve the environment registry and `WM_SETTINGCHANGE`, while a process environment is inherited by children.
- WSL provides documented distribution export/import commands and configuration files; Docker documents image save, volume backup, context export, and credential stores separately. Mutable VM state must not be copied blindly.
- Chromium/Edge profiles contain OS-bound encryption and browser-specific policies; Firefox profiles have their own profile manager and database/file layout. Browser portability is component-specific, not whole-profile by default.
- Codex, Claude Code, OpenCode, and VS Code expose documented configuration and extension mechanisms, but authentication state is often OS/account bound.
- WinGet configuration files and DSC resources are declarative but must be checked for trust before applying; Reforge must be at least as strict and will not import arbitrary configuration files as executable instructions.

If implementation behavior differs from these facts, the adapter MUST emit `UNVERIFIED` and downgrade to manual action rather than guessing.

## 5. Existing solutions and competitive gap

| Solution class | Strength | Boundary Reforge fills |
|---|---|---|
| WinGet export/import/configuration | Package identity and repeatable setup | Does not correlate all non-WinGet software, user data, browser state, secrets, AI tools, or target conflicts |
| Chocolatey/Scoop exports | Provider-specific package restoration | Does not produce one evidence-backed cross-provider graph |
| Boxstarter/WinUtil/scripts | Fast workstation automation | Imperative scripts are difficult to inspect, resume, trust, or reconcile with existing target state |
| chezmoi/yadm/Home Manager/Nix | Excellent declarative config/dotfiles | Do not discover opaque Windows installations, package ownership, account state, or machine features |
| Windows Backup / disk imaging | Broad backup or image recovery | Not selective environment reconstruction and often machine/identity-bound |
| Browser sync | Good supported preference/extension sync | Requires an account, excludes or protects secrets, and does not cover the whole development machine |
| Docker/WSL native export | Correct subsystem-specific data transfer | Does not plan dependencies with Windows applications and configuration |
| PC migration products | Broad commercial migration | Opaque policy, license/identity assumptions, and not an open local-first graph/package format |

**Gap:** an inspectable, selective, cross-provider graph that joins application identity, source provenance, portable state, dependency closure, target comparison, safe operations, and honest limitations.

## 6. Final architecture

```text
                 +-------------------+
                 | Svelte 5 UI       |
                 +---------+---------+
                           | typed Tauri commands/events
                 +---------v---------+
                 | Tauri 2 desktop   |
                 | command boundary  |
                 +---------+---------+
                           |
 +----------+  +-----------v----------+  +----------------+
 | CLI      +->| Application/Engine  |<-+| Journal        |
 +----------+  | discovery/plan/apply|  | SQLite WAL     |
                +--+-----+-----+-----+
                   |     |     |
        +----------+  +--v--+  +----------------+
        | Windows    |  |Package|  | Provider      |
        | platform   |  |format |  | adapters      |
        | APIs       |  |vault  |  | WinGet/...    |
        +------------+  +------+  +----------------+
```

The engine is UI-independent. Tauri and CLI call the same Rust application service. No business rule may exist only in Svelte.

## 7. Technology stack (settled)

### 7.1 Primary stack

- **Language:** Rust stable, 2024 edition; exact toolchain is pinned in `rust-toolchain.toml` and CI. Use the current stable version available when the bootstrap task is executed, then commit the resolved toolchain file.
- **Desktop:** Tauri 2.x with the official Windows WebView2 runtime model.
- **UI:** Svelte 5.x + TypeScript + Vite. Use Svelte runes (`$state`, `$derived`, `$props`) and module-scoped state/context; do not introduce SvelteKit server features.
- **CLI:** `clap` derive API with subcommands and a stable `--json` output envelope.
- **Persistence:** SQLite through `rusqlite` with bundled SQLite, WAL mode, a single writer actor, and read-only query connections.
- **Serialization:** `serde`, `serde_json`, `toml`, and `json5` for the documented TOML/JSON/JSONC-like config inputs; `schemars` generates JSON schemas and `typeshare` generates checked-in TypeScript DTOs from the Rust domain types. Canonical package serialization is a dedicated deterministic JSON serializer built on `serde_json::Value` rules below.
- **Supporting Rust crates:** `uuid` with v7 support, `chrono` for UTC/RFC 3339 timestamps, `url` with Serde support, `async-trait` for dynamic provider adapters, and `thiserror` for coded errors.
- **Windows APIs:** `windows` crate for Win32/COM/WinRT APIs, including registry, Shell Link, SCM, Task Scheduler, WinTrust, known folders, environment broadcasts, WSL process integration, and elevation.
- **Async/cancellation:** `tokio`, `tokio-util::sync::CancellationToken`; blocking Windows/file operations run through bounded `spawn_blocking` work, never on the UI thread.
- **Archive/content:** `zip` with ZIP64 support for the outer container; `zstd` frames for object payloads; BLAKE3-256 for content IDs.
- **Vault:** `age` crate using age v1-compatible encryption; `zeroize` for secret buffers. No custom KDF or cipher.
- **Optional package signatures:** `ed25519-dalek`; signature support is additive and never a substitute for package trust review.
- **Diagnostics:** `tracing` + `tracing-subscriber`; logs are structured and redacted before rendering or export.
- **Testing:** Rust built-in tests, `tempfile`, `assert_cmd`, `proptest` for path/format properties, Vitest + Testing Library for UI, and Playwright for desktop/browser-level smoke where available.
- **Frontend package manager:** pnpm, with lockfile committed. The target application does not require Node or pnpm after packaging.

### 7.2 Why not C#/.NET as the core

C#/.NET has excellent Windows APIs but adds a runtime/packaging choice and makes a future non-UI CLI/core distribution less uniform. Rust provides one memory-safe core, direct Win32 bindings, bounded binaries, strong streaming primitives, and one dependency graph shared by the GUI and CLI. Tauri keeps the GUI smaller than an embedded browser runtime while retaining accessible web UI development.

### 7.3 Tauri security decision

The UI MUST NOT receive broad filesystem or shell permissions. Use typed Rust commands and native dialogs only. Do not add a general-purpose filesystem plugin scope. If a dialog plugin is used, its capability file may expose only open/save dialog actions; path reads/writes remain in Rust after validation. Tauri capabilities MUST be explicit per window.

## 8. Repository structure

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml
package.json
pnpm-lock.yaml
pnpm-workspace.yaml
README.md
LICENSE-APACHE
REFORGE_IMPLEMENTATION_SPEC.md

crates/
  reforge-domain/
    src/lib.rs
    src/ids.rs
    src/model.rs
    src/schema.rs
    src/selection.rs
    src/error.rs
    src/redaction.rs
    tests/model_roundtrip.rs
  reforge-platform-windows/
    src/lib.rs
    src/known_folders.rs
    src/registry.rs
    src/process.rs
    src/pe.rs
    src/fs.rs
    src/shell_links.rs
    src/services.rs
    src/tasks.rs
    src/environment.rs
    src/features.rs
    src/privilege.rs
    tests/windows_fixtures.rs
  reforge-discovery/
    src/lib.rs
    src/coordinator.rs
    src/evidence.rs
    src/dedup.rs
    src/generic.rs
    src/providers/
    src/artifacts.rs
    src/recommend.rs
    src/harnesses/
    src/browsers/
    src/editors/vscode.rs
    tests/
  reforge-package/
    src/lib.rs
    src/canonical.rs
    src/content_store.rs
    src/writer.rs
    src/reader.rs
    src/vault.rs
    src/signature.rs
    fuzz/
      Cargo.toml
      fuzz_targets/package.rs
    tests/
  reforge-restore/
    src/lib.rs
    src/target.rs
    src/compatibility.rs
    src/diff.rs
    src/conflicts.rs
    src/planner.rs
    src/operations.rs
    src/executor.rs
    src/journal.rs
    src/verification.rs
    src/manual_actions.rs
    src/handlers/
    tests/
    migrations/
      0001_initial.sql
    fuzz/
      Cargo.toml
      fuzz_targets/operations.rs
  reforge-cli/
    src/main.rs
    tests/cli_smoke.rs
    src/report.rs
    src/secret_prompt.rs
  reforge-elevation-helper/
    Cargo.toml
    src/main.rs
    src/protocol.rs

src-tauri/
  Cargo.toml
  build.rs
  src/lib.rs
  src/main.rs
  src/commands.rs
  src/events.rs
  capabilities/main.json
  tauri.conf.json

ui/
  index.html
  package.json
  tsconfig.json
  vite.config.ts
  src/main.ts
  src/App.svelte
  src/app.css
  src/vite-env.d.ts
  src/lib/api.ts
  src/lib/types.ts
  src/lib/generated.ts
  src/lib/state.svelte.ts
  src/lib/components/
  src/routes/
  tests/

schemas/
  inventory.schema.json
  snapshot-manifest.schema.json
  package-manifest.schema.json
  restore-plan.schema.json
  restore-report.schema.json
  error.schema.json

tests/
  fixtures/
  integration/
  vm/Provision.ps1
  vm/Run-E2E.ps1
  vm/README.md

docs/
  support-matrix.md
  recovery.md
  security.md
  sources.md

.github/workflows/ci.yml
.github/workflows/windows-e2e.yml
.github/workflows/release.yml
```

Each crate exposes a small public surface. UI, CLI, providers, and platform code depend on domain contracts, never on each other's private implementation.

## 9. Domain model

### 9.1 Stable identifiers

```rust
pub struct ComponentId(pub String);    // cmp_<lowercase base32 BLAKE3>
pub struct ObjectId(pub String);       // obj_<lowercase hex BLAKE3-256>
pub struct RunId(pub uuid::Uuid);      // UUIDv7
pub struct OperationId(pub String);    // op_<RunId>_<ordinal>
pub struct EvidenceId(pub String);
pub struct SnapshotId(pub String);
```

`ComponentId` is BLAKE3 over a canonical identity tuple, not the display name or absolute path. Identity priority:

1. provider + stable provider-source identifier + package ID;
2. Windows package family name + publisher;
3. signed product name + publisher certificate fingerprint;
4. executable product name + publisher + normalized install role;
5. generic local identity containing normalized executable name and hash, marked `identity_quality=local`.

A path alone MUST NOT produce a portable identity. Provider-tier identity requires a stable source identifier; a mutable source display name is not sufficient. Publisher remains correlation evidence for provider packages but is not required by their canonical tuple because reviewed provider exports, including WinGet, do not carry it. Two items with the same display name but conflicting provider source/package identity remain separate components.

### 9.2 Core types

```rust
pub enum ComponentKind {
    Application, Package, Runtime, Tool, Harness, McpServer, Skill,
    Agent, Hook, Plugin, Browser, BrowserProfile, Editor, Extension,
    Configuration, DataArtifact, SecretReference, EnvironmentVariable,
    SystemFeature, Service, ScheduledTask, Shell, PortableBinary,
    WslDistribution, DockerContext, DockerImage, DockerVolume, Unknown,
}

pub enum Confidence { Confirmed, High, Medium, Low, Unknown }

pub enum Portability {
    Portable, SupportedExport, SyncRestorable, PartiallyPortable,
    ApplicationBound, UserBound, MachineBound, ReauthRequired,
    Unsupported, Unknown,
}

pub enum RestoreStrategy {
    Reinstall, ConfigPortable, DataPortable, ExportImport,
    PortableBinary, SecretExportable, ReauthRequired, MachineBound,
    Partial, Manual, Unknown,
}

pub struct Component {
    pub id: ComponentId,
    pub kind: ComponentKind,
    pub identity: Identity,
    pub display_name: String,
    pub version: Option<VersionValue>,
    pub architecture: Option<Architecture>,
    pub publisher: Option<Publisher>,
    pub provenance: Option<Provenance>,
    pub evidence: Vec<EvidenceRef>,
    pub confidence: Confidence,
    pub dependencies: Vec<DependencyEdge>,
    pub artifacts: Vec<ArtifactRef>,
    pub restore: RestoreDescriptor,
    pub compatibility: Compatibility,
    pub verification: Vec<VerificationRule>,
    pub selection: SelectionMetadata,
    pub extensions: BTreeMap<String, serde_json::Value>,
}
```

`Component` and versioned envelopes may preserve unknown input fields under a flattened `extensions` map only after schema validation; extension fields are opaque and never interpreted as operations. Identity and restore fields remain typed and closed.

### 9.2.1 Shared wire types

The domain crate owns every DTO crossing crate, CLI, Tauri, package, or UI boundaries. Discovery and restore crates implement behavior around these types; they MUST NOT define shadow models.

```rust
pub struct ProviderId(pub String);
pub struct ArtifactId(pub String);
pub struct PackageSpec {
    pub provider: ProviderId,
    pub id: String,
    pub version: Option<String>,
    pub source_name: Option<String>,
    pub source_identifier: Option<String>,
    pub source: Option<Url>,
    pub architecture: Option<Architecture>,
    pub installer_hash: Option<String>,
}
pub struct PackageInstallPolicy {
    pub accept_source_agreements: bool,
    pub accept_package_agreements: bool,
    pub silent: bool,
    pub allow_reboot: bool,
}

pub enum Architecture { X86, X64, Arm64, Neutral, Unknown }
pub enum AccountScope { User, Machine }
pub enum ConfigScope { Process, User, System, Project, Managed }
pub enum KnownFolderToken {
    UserProfile, RoamingAppData, LocalAppData, ProgramData,
    ProgramFiles, ProgramFilesX86, StartMenu, Desktop, Documents,
    UserSelected { id: String },
}
pub struct PathToken {
    pub root: KnownFolderToken,
    pub relative: String,
}
pub type TokenizedPath = PathToken;

pub enum ContentType { Utf8Text, Json, Jsonc, Toml, Binary, Archive, Unknown }
pub enum ArtifactPolicy { Config, Data, Export, PortableBinary, LargeOptIn, SecretReference, Manual }
pub struct ArtifactRef {
    pub id: ArtifactId,
    pub source_path: PathToken,
    pub scope: ConfigScope,
    pub size_bytes: u64,
    pub content_type: ContentType,
    pub policy: ArtifactPolicy,
    pub object: Option<ObjectId>,
}

pub struct Identity {
    pub provider_package: Option<(ProviderId, String)>,
    pub provider_source: Option<String>,
    pub package_family: Option<String>,
    pub product_name: Option<String>,
    pub executable_name: Option<String>,
    pub publisher: Option<String>,
    pub executable_hash: Option<String>,
    pub install_role: Option<String>,
    pub identity_quality: IdentityQuality,
}
pub enum IdentityQuality { Provider, PackageFamily, SignedProduct, Product, Local }
pub enum RiskLevel { Low, Medium, High, Critical }
pub struct Publisher { pub name: String, pub certificate_thumbprint: Option<String> }
pub struct Provenance {
    pub provider: Option<ProviderId>,
    pub package_id: Option<String>,
    pub source_url: Option<Url>,
    pub observed_version: Option<String>,
    pub adapter_id: String,
    pub adapter_version: String,
}
pub struct EvidenceRef { pub id: EvidenceId, pub strength: u8 }
pub struct VersionValue { pub raw: String, pub normalized: Option<String> }

pub struct RestoreDescriptor {
    pub primary: RestoreStrategy,
    pub alternatives: Vec<RestoreStrategy>,
    pub portability: Portability,
    pub requires_elevation: bool,
    pub requires_user_action: bool,
    pub rationale: Vec<String>,
}
pub struct Compatibility {
    pub required_os: Option<String>,
    pub required_architecture: Option<Architecture>,
    pub requires_provider: Option<ProviderId>,
    pub requires_runtime: Option<ComponentId>,
    pub requires_elevation: bool,
    pub requires_wsl: bool,
    pub requires_docker: bool,
}
pub struct SelectionMetadata {
    pub recommended: bool,
    pub score: i16,
    pub selected_by_default: bool,
    pub sensitive: bool,
    pub size_bytes: u64,
}

pub struct HostFacts {
    pub os_version: String,
    pub os_build: String,
    pub architecture: Architecture,
    pub elevated: bool,
    pub account_scope: AccountScope,
    pub sid_fingerprint: Option<String>, // local inventory only; never copied to a package
    pub known_folders: Vec<PathToken>,
    pub drives: Vec<DriveFact>,
    pub free_bytes: Vec<DriveFreeSpace>,
}
pub struct DriveFact { pub token: String, pub filesystem: Option<String> }
pub struct DriveFreeSpace { pub token: String, pub bytes: u64 }
pub struct SourceHostSummary {
    pub os_version: String,
    pub os_build: String,
    pub architecture: Architecture,
    pub known_folder_tokens: Vec<KnownFolderToken>,
}
pub struct TargetFacts {
    pub host: HostFacts,
    pub installed: Vec<InstalledFact>,
    pub providers: Vec<ProviderFact>,
    pub runtimes: Vec<RuntimeFact>,
    pub environment: Vec<EnvironmentFact>,
    pub fingerprint: String,
}
pub struct InstalledFact {
    pub kind: ComponentKind,
    pub identity: Identity,
    pub version: Option<VersionValue>,
    pub publisher: Option<Publisher>,
    pub provenance: Option<Provenance>,
}
pub struct ProviderFact { pub id: ProviderId, pub version: Option<VersionValue>, pub available: bool }
pub struct RuntimeFact { pub id: ComponentId, pub version: Option<VersionValue>, pub architecture: Option<Architecture> }
pub struct EnvironmentFact { pub scope: ConfigScope, pub name: String, pub value_hash: Option<String> }

pub enum McpTransport { Stdio, StreamableHttp, Sse, Unknown }
pub struct ExecutableRef {
    pub name: String,
    pub component: Option<ComponentId>,
    pub observed_path: Option<PathToken>,
}
pub struct McpServerSpec {
    pub name: String,
    pub scope: ConfigScope,
    pub transport: McpTransport,
    pub command: Option<ExecutableRef>,
    pub args: Vec<McpArgument>,
    pub cwd: Option<McpWorkingDirectory>,
    pub endpoint: Option<McpEndpoint>,
    pub environment: Vec<EnvBinding>,
    pub required_runtime: Option<ComponentId>,
    pub required_package: Option<PackageSpec>,
    pub source_config: ArtifactRef,
}

pub enum VerificationRule {
    ProviderIdentity { provider: ProviderId, package: PackageSpec },
    File { destination: TokenizedPath, object: Option<ObjectId> },
    FileVersion { destination: TokenizedPath, version: Option<VersionValue>, publisher: Option<Publisher> },
    ConfigParses { destination: TokenizedPath, content_type: ContentType },
    Environment { scope: ConfigScope, name: String, expected: SafeValueRef },
    McpRegistration { name: String, config: TokenizedPath },
    WslState { distro: String, version: Option<String> },
    DockerObject { kind: ComponentKind, identity: String },
    BrowserArtifact { profile: TokenizedPath },
    SecureTarget { secret: ComponentId },
}

pub struct RuntimeSpec { pub id: String, pub version: Option<String>, pub architecture: Option<Architecture> }
pub struct WslSpec { pub distribution: String, pub wsl_version: Option<u8> }
pub struct DockerImageSpec { pub repository: String, pub tag: Option<String>, pub image_id: Option<String> }
pub struct DockerVolumeSpec { pub name: String, pub driver: Option<String> }
pub enum FileMode { PreserveTarget, Replace, CreateOnly }
pub enum MergePolicy { PreserveUnknown, ReplaceKnownKeys, AppendUnique, ManualOnConflict }
pub enum ManualActionState { Pending, Acknowledged, Completed, Skipped }
pub struct ManualAction {
    pub id: String,
    pub component: Option<ComponentId>,
    pub title: String,
    pub reason: String,
    pub risk: RiskLevel,
    pub instructions: Vec<String>,
    pub docs_url: Option<Url>,
    pub state: ManualActionState,
    pub independent_operations_may_continue: bool,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub verification: Option<VerificationRule>,
}

pub struct PackageManifest {
    pub package_id: String,
    pub format_version: u16,
    pub created_at: DateTime<Utc>,
    pub source_host: SourceHostSummary,
    pub required_os: Option<String>,
    pub required_architecture: Option<Architecture>,
    pub component_ids: Vec<ComponentId>,
    pub warnings: Vec<String>,
    pub object_index_digest: String,
}
pub struct SnapshotManifest {
    pub snapshot_id: SnapshotId,
    pub base_snapshot_id: Option<SnapshotId>,
    pub package: PackageManifest,
    pub reused_objects: Vec<ObjectId>,
    pub new_objects: Vec<ObjectId>,
}
pub struct PackageGraph { pub components: Vec<Component>, pub edges: Vec<DependencyEdge> }
pub type ComponentGraph = PackageGraph;
pub struct ObjectIndex { pub objects: Vec<ObjectEntry> }
pub struct ObjectEntry { pub id: ObjectId, pub uncompressed_bytes: u64, pub compressed_bytes: u64, pub content_type: ContentType }
pub struct ChunkRef { pub id: ObjectId, pub uncompressed_bytes: u64 }
pub struct FileManifest {
    pub size_bytes: u64,
    pub chunks: Vec<ChunkRef>,
    pub content_type: ContentType,
    pub attributes: u32,
}
pub struct TransportReceipt { pub package_id: String, pub object_count: u64, pub index_digest: String }
pub struct Inventory {
    pub format_version: u16,
    pub scan_id: RunId,
    pub captured_at: DateTime<Utc>,
    pub host: HostFacts,
    pub graph: ComponentGraph,
    pub evidence: Vec<Evidence>,
    pub warnings: Vec<String>,
}
pub struct WireEnvelope<T> {
    pub schema_version: u16,
    pub request_id: String,
    pub payload: T,
}
pub enum ScanPhase { HostPreflight, PackageExports, WindowsRegistration, RuntimeProbes, KnownFolderConfig, AppAdapters, GenericExecutables, Correlation }
pub enum ProgressStatus { Started, Progress, Completed, Warning, WaitingForUser, Failed, Cancelled }
pub struct ProgressEvent {
    pub run_id: RunId,
    pub phase: ScanPhase,
    pub status: ProgressStatus,
    pub current_component: Option<ComponentId>,
    pub completed: u64,
    pub total: Option<u64>,
    pub bytes: Option<u64>,
    pub message: String,
}
pub enum RunStatus {
    Planned, WaitingForApproval, Running, WaitingForUser, WaitingForReboot,
    Completed, Partial, Failed, Cancelled, Interrupted,
}
pub enum OperationState {
    Pending, Running, Completed, Failed, Skipped,
    WaitingForUser, WaitingForReboot, Interrupted, Cancelled,
}
pub enum ApprovalState { Pending, Approved, Rejected }
 ```

`HostFacts.sid_fingerprint` is an in-memory/local-inventory compatibility fact. `SourceHostSummary` is the only host form allowed in a portable manifest and contains no SID, hostname, machine GUID, drive letter, absolute path, or free-space value. `PathToken.root` is resolved through a current-target known-folder map; `UserSelected` roots require an explicit target mapping before restore.

`TargetFacts`, `PackageSpec`, `VerificationRule`, `OperationKind`, and the package/restore DTOs are domain-owned even when their scanners or handlers live in another crate. The target scanner only populates `TargetFacts`; it does not redefine it. `source_path` is a token, never an absolute source path.
### 9.2.2 Restricted value references

All domain enums serialize as `SCREAMING_SNAKE_CASE`; struct fields serialize as `snake_case`; wrapper IDs serialize as their validated string value. Input parsers may accept documented provider spellings, but normalized domain output uses this convention. `extensions` is the sole opaque field and is never traversed as an operation source.
Operation-facing values are not arbitrary strings. The domain crate defines the following restricted references:

```rust
pub enum SafeValueRef {
    LiteralNonSecret(String),
    EnvironmentReference { name: String },
    SecretReference { id: ComponentId, label: String },
    RedactedUnknown,
}

pub struct EnvBinding {
    pub name: String,
    pub value: SafeValueRef,
}

pub type McpArgument = SafeValueRef;

pub enum McpWorkingDirectory {
    Tokenized(PathToken),
    EnvironmentReference { name: String },
    SecretReference { id: ComponentId, label: String },
    RedactedUnknown,
}

pub enum McpEndpoint {
    Public(Url),
    EnvironmentReference { name: String },
    SecretReference { id: ComponentId, label: String },
    RedactedUnknown,
}
```

`LiteralNonSecret` is constructed only after adapter classification. A secret reference contains an ID and label, never the secret value. `ExecutableRef` identifies an executable observed on the target or a built-in provider executable; it is not a package-supplied command string. `PathToken` contains only an allowlisted known-folder token plus a validated relative path. Any raw secret, unclassified endpoint, or unsafe path is represented as `RedactedUnknown` and becomes a warning/manual action.
`McpEndpoint::Public` accepts only an `http` or `https` URL without username, password, or secret-bearing query data; other schemes or uncertain redaction are `RedactedUnknown` and require review.

### 9.2.3 Path token grammar and write roots

`PathToken` is serialized as `{ "root": <known-folder-token>, "relative": <slash-separated-relative-path> }`. Construction is deterministic:

1. resolve the source path through `KnownFolderMap` and compute a relative path under the selected root;
2. reject a path that is outside the root, contains NUL, a drive/UNC prefix, an absolute separator, or a `..` segment;
3. convert separators to `/`, preserve case for display, and use case-insensitive comparison for Windows collision checks;
4. reject or record an existing reparse point before reading or writing; never follow it during validation;
5. at restore time, resolve against the target map, verify every existing path component remains under the expected root, then apply the handler's file/merge policy.

Empty `relative` is allowed only for a known-folder root itself. `.` segments are normalized away; `..` is always rejected rather than normalized. Generic `WriteFile`/merge operations may target user-profile, roaming/local AppData, Start Menu, Desktop, Documents, and explicitly mapped user-selected roots. `ProgramData` requires a typed privileged handler and explicit elevation; `ProgramFiles`, `ProgramFilesX86`, Windows directories, registry hives, and protected default-association state are never generic file-write destinations. A handler needing one of those targets must expose a separate reviewed operation or create a manual action.

### 9.3 Evidence and confidence

Every evidence item has:

```rust
pub enum EvidenceSource {
    Registry, AppPaths, Shortcut, FileMetadata, Authenticode,
    WinGet, Chocolatey, Scoop, Npm, Pnpm, Yarn, Bun,
    Python, Rust, Go, Dotnet, PowerShell, Wsl, Docker,
    Browser, Editor, Harness, UserSelected, Unknown,
}
pub struct Evidence {
    pub id: EvidenceId,
    pub source: EvidenceSource,
    pub locator: String,          // redacted path or registry key where required
    pub observed_at: DateTime<Utc>,
    pub summary: String,          // never secret content
    pub strength: u8,             // 0..=100, adapter-defined and documented
    pub independent_group: String,
}
```

Deterministic confidence algorithm:

- start at 0;
- add each evidence strength, capped at 100;
- add 10 for a second independent evidence group that agrees on identity;
- subtract 20 for conflicting publisher/version/source evidence;
- `Confirmed`: score >= 90 and at least two independent agreeing groups;
- `High`: score >= 75;
- `Medium`: score >= 45;
- `Low`: score >= 20;
- `Unknown`: below 20 or any identity-critical fact is `UNVERIFIED`.

The UI shows the reason list, not only the label. Confidence is not permission to restore; portability and risk are separate fields.

### 9.4 Dependency graph

Edges are typed:

```rust
pub enum DependencyKind {
    RequiredRuntime, RequiredPackage, InstalledThrough, Configures,
    UsesSecret, OptionalFeature, ProvidesExecutable, Contains,
    RestoresBefore, VerifiesWith, RelatedOnly,
}

pub struct DependencyEdge {
    pub from: ComponentId,
    pub to: ComponentId,
    pub kind: DependencyKind,
    pub required: bool,
    pub evidence: Vec<EvidenceId>,
    pub confidence: Confidence,
}
```

`required=true` edges are included automatically in a selected closure. Optional edges are displayed and selectable. Cycles are legal in discovery but make a restore plan `DEPENDENCY_CYCLE` until the planner can break a documented verification-only edge.

## 10. Discovery engine

Discovery is layered and bounded. It MUST NOT recursively enumerate every file on every drive.


`KnownFolderMap` is a local-only resolver returned by the Windows platform crate:

```rust
pub struct KnownFolderMap {
    pub entries: BTreeMap<KnownFolderToken, PathBuf>,
}
```

It is populated from `SHGetKnownFolderPath` and explicit user-selected mappings. Absolute `PathBuf` values may exist in process memory and local diagnostics only; they MUST NOT enter package metadata, operation DTOs, or redacted reports. `PathToken` is resolved against this map at the target boundary, then validated under the allowed root.
### 10.1 Scan phases

1. **Host preflight:** OS version/build, architecture, current SID, elevation, known folders, available drives, disk free space, locale, WebView2 only for GUI.
2. **Structured package exports:** run available provider exports/list commands with no user-supplied command text; capture stdout, stderr, exit code, and tool version.
3. **Windows registration:** inspect uninstall keys in HKLM/HKCU 32-bit and 64-bit views; App Paths; AppX/MSIX package metadata; services; scheduled tasks; startup entries; known default-app registrations.
4. **Runtime/tool probes:** resolve safe executable names from PATH and known package-manager roots; run version probes only from a built-in allowlist.
5. **Known-folder configuration:** inspect only adapter allowlists and user-selected roots under known folders; use `SHGetKnownFolderPath`.
6. **Editor/browser/harness adapters:** inspect documented locations and supported export/list commands.
7. **Generic executable pass:** inspect bounded roots (`PATH` directories, registered install locations, Start Menu shortcut targets, user-selected directories) and only shallowly enumerate likely executable files. Never follow reparse points.
8. **Correlation/deduplication:** produce graph nodes and edges from evidence; retain unmatched observations as `Unknown` rather than discarding them.

Each phase emits progress events and continues after individual access failures. A scan is successful with warnings if the host inventory is usable; an entirely failed phase is reported.

### 10.2 Windows application discovery

Inspect:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` and the 32-bit view;
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall` and the 32-bit view;
- App Paths under HKLM/HKCU;
- AppX/MSIX packages through the documented package manager API for the current user;
- Start Menu/Desktop `.lnk` targets through Shell Link COM;
- services through SCM enumeration;
- scheduled tasks through Task Scheduler 2.0 read APIs;
- `PATH`, user/system environment registry values, and shell startup locations;
- default file/protocol association query APIs.

Record registry view, scope, product code/package family, display/install metadata, executable target, and access errors. Never infer that a registry entry means the binary still exists.

### 10.3 Generic executable algorithm

For each candidate executable:

1. `symlink_metadata`/Win32 attributes; reject or record reparse points without traversal.
2. Read PE version resource using `GetFileVersionInfoSizeW`, `GetFileVersionInfoW`, and `VerQueryValue`.
3. Verify Authenticode with `WinVerifyTrust`; store status, signer subject, certificate thumbprint if available, and exact error code.
4. Compute BLAKE3 only for the main executable during discovery; compute all-file hashes only when packaging or explicitly requested.
5. Correlate with uninstall metadata, App Paths, shortcut target, PATH entry, package-manager export, and parent install root.
6. Assign source only when evidence matches package ID, publisher, path/install metadata, or a strong signed product identity. GitHub association from name alone is forbidden.
7. Emit `PortableBinary` as an explicit option when no trusted reinstall source exists; default restore is `Manual` unless the user selects it.

**GitHub release correlation:** Reforge may attach a GitHub repository, release, or asset only when a package manifest, user-provided source, exact signed publisher metadata, or a matching published-asset hash supplies strong evidence. Name matching, search-result similarity, and generic download URLs are insufficient; absent strong evidence, source remains unknown and restore stays portable/manual.

### 10.4 Environment and PATH

Capture raw values with scopes (`Process`, `User`, `System`) and a redacted display value. Split PATH using Windows semantics, preserve order, preserve raw token text, and normalize only for comparison. Values matching secret-name heuristics are never copied into ordinary metadata. A value may be a `SecretReference` only when an adapter identifies it as a required secret; a name match alone is `PotentialSecret` and remains redacted.
System-scope environment and PATH values are discovery/report inputs in MVP; they are not silently written. The only automatic environment write is `SetUserEnvironment` plus user PATH merge, both with non-secret values and explicit verification. A system-scope change becomes a privileged/manual action unless a later typed operation and policy are added.

### 10.5 Windows features and state

Capture selected optional features, virtualization/WSL prerequisites, OpenSSH feature state, developer mode, and default associations as desired-state observations. Do not snapshot an entire registry hive. Do not restore drivers, SID-bearing ACLs, machine GUIDs, hostname, hardware identifiers, or arbitrary scheduled tasks automatically.

## 11. Provider adapters

Shared adapter boundary types:

```rust
pub struct ProviderContext<'a> {
    pub host: &'a HostFacts,
    pub known_folders: &'a KnownFolderMap,
    pub runner: &'a ProcessRunner,
    pub cancellation: &'a CancellationToken,
}
pub struct DetectionResult {
    pub available: bool,
    pub version: Option<VersionValue>,
    pub evidence: Vec<Evidence>,
    pub warnings: Vec<String>,
}
pub enum Observation {
    Package { spec: PackageSpec, version: Option<VersionValue>, evidence: Vec<Evidence> },
    Executable { path: PathToken, identity: Identity, version: Option<VersionValue>, evidence: Vec<Evidence> },
    Runtime { spec: RuntimeSpec, evidence: Vec<Evidence> },
    Artifact { artifact: ArtifactRef, evidence: Vec<Evidence> },
    Registration { kind: ComponentKind, identity: Identity, evidence: Vec<Evidence> },
}
pub struct ProviderEnumeration {
    pub observations: Vec<Observation>,
    pub warnings: Vec<String>,
}
pub type ProviderResult<T> = Result<T, ErrorEnvelope>;
```

All adapters implement:
```rust
#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    fn id(&self) -> ProviderId;
    fn detect(&self, ctx: &ProviderContext) -> DetectionResult;
    async fn enumerate(&self, ctx: &ProviderContext) -> ProviderResult<ProviderEnumeration>;
    fn normalize(&self, observation: Observation) -> ProviderResult<Vec<Component>>;
    fn plan_install(&self, component: &Component, target: &TargetFacts, run_id: &RunId, first_ordinal: u64) -> ProviderResult<Vec<Operation>>;
    fn verify(&self, component: &Component, target: &TargetFacts) -> ProviderResult<Vec<VerificationRule>>;
}
```

An adapter owns its documented command/API details. It MUST use an argument vector, never a shell command string; use a current process environment with secrets omitted; enforce timeout/output/size limits; and retain versioned parser fixtures. Enumeration warnings are returned alongside observations because provider commands can report unmatched or partial items only after execution. Planning receives the restore `RunId` and the first planner-owned operation ordinal; adapters MUST NOT synthesize unrelated run identifiers or colliding ordinals.

| Provider | Initial adapter behavior | Restore behavior | Portability caveat |
|---|---|---|---|
| WinGet | `winget export` JSON plus registry correlation | exact ID/source/version; agreements and silent mode are explicit policy | source/version may disappear; installer may require reboot/admin |
| Chocolatey | documented `choco export --include-version-numbers` fixture | provider install operation with package ID/version | packages may run install scripts; always show source/license risk |
| Scoop | documented `scoop export` JSON | provider import or typed package operations | buckets/custom manifests are source-dependent |
| npm | global `npm ls --json --depth=0` when available | exact package/version using npm global mode | project `package.json`/lockfiles are data artifacts, not global packages |
| pnpm | global `pnpm ls --json --depth 0` when supported | exact package/version | global directory and package manager version matter |
| Yarn | detect classic/global state; no assumption about Berry global installs | restore only documented package/project forms | Yarn 1 and modern Yarn semantics differ |
| Bun | `bun pm` structured listing where supported | typed package operation | Bun versions/lockfile formats vary |
| pip | `python -m pip list --format=json` and `pip inspect` when available | exact requirement/environment recipe | interpreter and ABI are compatibility inputs |
| pipx | detect only if command and documented JSON output are available | otherwise manual action | exact current JSON contract must be fixture-tested |
| uv | `uv tool list`/`uv python`/`uv tree` where relevant | typed uv tool/python operation | uv-managed state is separate from system Python |
| Cargo/rustup | `cargo install --list`, `rustup toolchain list` | crate/source/version and toolchain operations | git/path installs need source evidence |
| Go | detect `go env`, binaries, module/debug metadata | only exact module source with strong evidence | installed binary often lacks reproducible source |
| PowerShell Gallery | documented `Get-InstalledModule`/module paths | `Install-Module` typed operation with trust/manual gate | scripts/modules are executable supply-chain inputs |
| dotnet tools | `dotnet tool list --global` where available | exact global tool package/version | runtime SDK compatibility matters |
| Conda | optional adapter, JSON export where available | environment export/import | large and platform-sensitive |

The table defines the reviewed adapter target, not a claim that every provider is MVP-complete. MVP acceptance requires the WinGet path; other adapters may provide discovery and fixture coverage while remaining `PARTIAL`/`MANUAL` until their source, installer, and verification behavior is proven on the target.

Provider installation itself is a typed `EnsureProvider` operation. If the provider is absent and there is no reviewed bootstrap recipe, create a manual action; never download an arbitrary URL from package metadata.

## 12. AI development environment

AI tooling is a first-class category, but configuration and credentials are separate objects.

### 12.1 Codex

Discover:

- user-level `.codex/config.toml` under the current home, or `$CODEX_HOME` when that environment variable is present;
- profile files next to the configured Codex home;
- project `.codex/config.toml` only as a project-scoped artifact and with its trust scope recorded;
- `AGENTS.md`, configured model-instruction files, hooks, agents, skills, and MCP server tables;
- auth storage mode (`auth.json`, keyring, or auto) without copying the credential by default.

Normalize `[mcp_servers.<id>]` tables into `McpServer` components. Preserve project scope and trust requirements. A `config.toml` file is not an executable operation.

### 12.2 Claude Code

Discover documented user/project settings, `.mcp.json`, `skills/<name>/SKILL.md`, `commands/`, `agents/`, `hooks/`, plugin manifests, and project instruction files. Preserve scope and namespace. A plugin's `bin` or hook command is metadata and a manual/supply-chain boundary, not an instruction to execute during restore.

Hook, plugin, skill, and agent files remain untrusted data. They require explicit selection/review before restore, and Reforge never executes them.

### 12.3 OpenCode

Discover the documented global config (`~/.config/opencode/opencode.json` on Windows-compatible home resolution), `tui.json`, `.opencode` directories, `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`, project `opencode.json`, and managed `%ProgramData%\opencode` configuration. Record configuration precedence and managed ownership. Parse JSON/JSONC without evaluating interpolation.

### 12.4 VS Code

Discover the `code` executable from PATH/App Paths/installation registration. Use the documented CLI list/version flags when available:

- `code --version`;
- `code --list-extensions --show-versions`;
- `code --install-extension <publisher.id>@<version>` for restore;
- `--profile` only with a profile identity already discovered.

Capture user settings, keybindings, snippets, profiles, extensions, and workspace recommendations as separate artifacts. Treat VS Code Settings Sync as an optional supported export/sync route, not as proof that local credentials are portable. Third-party extensions have their own permissions and must remain visible in the plan.

### 12.5 MCP normalization

Normalize each server into the canonical typed `McpServerSpec` defined in §9.2.1:

Its transport, command, arguments, working directory, endpoint, environment, runtime/package requirements, and source artifact are typed fields, not an untyped JSON map.

`ExecutableRef.name` is accepted only when it resolves to an observed executable or a built-in provider/runtime executable. `observed_path` is tokenized. An unresolved command is retained as untrusted metadata and produces a manual action; it is never executed or passed to an elevation helper.

Environment values use `SafeValueRef`: `LiteralNonSecret`, `EnvironmentReference`, `SecretReference`, or `RedactedUnknown`. Known secret fields (API keys, bearer tokens, passwords, private-key paths where content is involved) become references. Secret-bearing literals in MCP arguments, endpoints, or working-directory metadata are treated the same way. The original config is never copied unchanged when a secret field is detected.

## 13. Browser discovery and portability

Discover installed browsers through package/registry/App Paths/shortcut evidence and record default browser evidence by querying current associations. Do not assume Edge is the default merely because Windows includes it. If usage cannot be established, label `Installed` rather than `RecentlyActive`.

Browser states are independently classified:

| State | Default strategy |
|---|---|
| bookmarks/history export where a documented format exists | supported export/import or bounded data copy |
| preferences/themes | partial config copy after browser shutdown and schema check |
| extensions | reinstall from stable extension ID/source; copy only documented portable metadata |
| cookies/logins/session tokens | `ApplicationBound`/`UserBound`/`ReauthRequired`; do not copy |
| full Chromium profile | partial/manual; never promise encrypted data portability |
| Firefox profile | partial; profile/version/lock compatibility and database checks required |
| default browser | manual supported Windows UI; never edit protected user-choice registry |

Profile capture must detect running processes and file locks. It may request the user to close the browser; it MUST NOT kill it by default. A browser adapter may copy SQLite databases only after an adapter-specific quiescence check; it must not issue arbitrary `PRAGMA` statements against an unknown app database.

## 14. SSH, Docker, WSL, and shell state

### 14.1 SSH

Capture `known_hosts`, public keys, config host aliases, and file metadata by default. Private keys are `SecretExportable` only after explicit per-key selection and vault encryption. Preserve key paths through tokens. Never copy `known_hosts` entries into a trust decision without showing them. `ssh-agent` state and active sessions are machine/user-bound and require reinitialization.

### 14.2 Docker

Separate:

- CLI contexts: export/import when the documented Docker context format is available;
- images: `docker image save` objects, with image IDs and tags;
- volumes: explicit volume backup/restore operations with size estimate;
- containers: declarative metadata only unless the user selects a supported data export;
- credentials: config references and credential-helper metadata, not secrets.

Docker Desktop VM disk state is not copied blindly. A volume or image exceeding the package size policy becomes a separate optional object and is never silently included.

### 14.3 WSL

Capture distro name, WSL version, state, Windows prerequisites, `.wslconfig` and relevant `wsl.conf` files, and optional `wsl --export` data. Restore order is Windows prerequisites -> WSL enablement -> import distribution -> restore Windows-side references -> verify. Distribution export is a large data artifact and requires explicit selection. Do not assume Linux package lists or user IDs are portable across distributions.

### 14.4 Shells and Git

Capture PowerShell profiles, Windows Terminal settings when discoverable, Git user/config data, aliases, includes, credential-helper names, SSH references, and shell PATH changes. Never copy plaintext credential helper stores by default. Use Git config as data; no Git command is executed from package content.

## 15. Selection and recommendation

### 15.1 Automatic recommendation

The recommendation score is deterministic and explainable:

- +30 confirmed package/application identity;
- +20 executable is reachable through PATH or a Start Menu/App Paths registration;
- +20 selected component is a required dependency of another recommended component;
- +15 documented portable configuration exists;
- +10 user-facing application/editor/browser/harness category;
- +10 source/provenance is reproducible;
- −25 machine-bound or account-bound state;
- −20 destructive/privileged/manual-only operation;
- −15 large data artifact over the default size threshold;
- −10 unknown source or low-confidence identity.

Recommended selection is not automatic inclusion of secrets or large data. Every recommendation has explanation chips and a portability label.

```rust
pub struct RecommendationScore {
    pub component: ComponentId,
    pub score: i16,
    pub recommended: bool,
    pub chips: Vec<ExplanationChip>,
}
pub struct ExplanationChip { pub code: String, pub label: String, pub delta: i16 }
```

### 15.2 Manual pack

The user may select any component, including `Unknown`, and may choose artifact sub-items. Required dependencies are auto-added and shown. Unchecking a required dependency creates a `SELECTION_INCOMPLETE` warning and disables package creation until the user explicitly changes the component to `Manual`/`portable binary` mode.

Default policy:

- applications/runtimes: selected if recommended;
- configuration: selected when tied to a selected component;
- secrets: never selected by default;
- browser sessions/cookies: never selectable as portable; explanation only;
- large data: selectable with size confirmation;
- unknown binary: selectable only as portable binary with source/hash/signature report.

```rust
pub enum SecretSelectionPolicy { Exclude, VaultExplicit }
pub enum LargeDataSelectionPolicy { Exclude, RequireConfirmation }
pub enum UnknownBinarySelectionPolicy { Exclude, PortableBinaryExplicit }
pub struct SelectionPolicy {
    pub secrets: SecretSelectionPolicy,
    pub large_data: LargeDataSelectionPolicy,
    pub unknown_binaries: UnknownBinarySelectionPolicy,
    pub max_bytes: Option<u64>,
}
pub struct ArtifactSelection { pub artifact: ArtifactId, pub include: bool }
pub struct SelectionInput {
    pub components: Vec<ComponentId>,
    pub artifacts: Vec<ArtifactSelection>,
    pub policy: SelectionPolicy,
}
pub struct SelectionClosure {
    pub selected_components: Vec<ComponentId>,
    pub selected_artifacts: Vec<ArtifactId>,
    pub auto_added_dependencies: Vec<ComponentId>,
    pub total_bytes: u64,
    pub warnings: Vec<String>,
}
```

`SelectionClosure` is frozen before package writing. The writer consumes it read-only; changing a policy or artifact selection requires a new closure and a new package ID.

## 16. Package format (`.reforge`)

### 16.1 Container

A package is a ZIP64 file. The outer ZIP entries are stored or contain independently framed payloads; the package reader MUST support ZIP64 and MUST reject unsafe entry names. ZIP entry names use `/`, UTF-8, no absolute paths, no drive letters, no `..`, no NUL, and no reparse/symlink payload semantics.

```text
format/manifest.json       canonical UTF-8 JSON
format/graph.json          canonical dependency graph
format/selection.json      explicit user selection and policy
format/operations.json     typed restore descriptors, never executable command instructions
format/object-index.json   object IDs, sizes, media types, chunk lists
format/sources.json        source URL/claim IDs and adapter versions
objects/<object-id>.zst    zstd frame of canonical object bytes
objects/<object-id>.chunks/<n>.zst  fixed-size chunks for large objects
vault/age-v1.txt           optional canonical vault envelope containing age v1 payloads
signatures/manifest.json   optional signature metadata
signatures/manifest.sig    optional Ed25519 signature
```

The manifest includes package ID, format version, creation time, a `SourceHostSummary` with user/machine identifiers redacted or tokenized, required OS/architecture, component summaries, warnings, and an object index digest. It does not include plaintext secrets.

### 16.2 Canonical bytes and IDs

Canonical JSON rules:

- UTF-8 without BOM;
- object keys sorted lexicographically by Unicode scalar value;
- no insignificant whitespace;
- numbers emitted in one stable JSON representation; reject NaN/infinity;
- arrays preserve semantic order, except explicitly sorted sets;
- timestamps RFC 3339 UTC;
- paths use tokenized `/` form in package metadata;
- newline normalization only for text artifacts when the adapter declares it; binary bytes are exact.

`ObjectId = obj_ + lowercase hex(BLAKE3(uncompressed canonical bytes))`. The object index records both uncompressed length and compressed length. The writer hashes and compresses in bounded chunks; it MUST NOT read a large file into memory.

Large-file chunk size is exactly 8 MiB. A file manifest is itself an object that lists ordered chunk object IDs, original size, mode/attributes, and content type. Chunking is content-addressed and permits incremental snapshots to reuse unchanged chunks.

### 16.3 Integrity, signatures, and trust

Reader sequence:

1. validate ZIP central directory and package size/file-count limits;
2. read and validate manifest schema;
3. validate object-index digest;
4. validate each requested object ID after decompression;
5. verify optional signature if present;
6. show unsigned/untrusted warning before planning any restore;
7. only then allow the user to approve operations.

```rust
pub enum TrustState {
    Unchecked,
    IntegrityVerified,
    Unsigned,
    SignatureInvalid,
    SignatureValidUntrusted,
    SignatureValidTrusted,
    UserApproved,
    Rejected,
}
```

`IntegrityVerified` means only that schema, size, and content hashes passed. `SignatureInvalid` means a complete signature envelope failed strict cryptographic verification and can never be approved. `SignatureValidUntrusted` means a signature checked but its key is not in the user's trust store. `SignatureValidTrusted` means the valid key fingerprint matched an explicit out-of-band trust input; restore planning still requires `UserApproved`. `Rejected` is terminal for the current package load.

The mandatory BLAKE3 index detects accidental corruption and inconsistent objects. It does not prove publisher authenticity. Optional Ed25519 signatures cover canonical manifest bytes plus canonical object-index bytes. Coverage is exactly ASCII `REFORGE-PACKAGE-SIGNATURE-V1` followed by NUL, the manifest byte length as little-endian `u64`, the manifest bytes, the object-index byte length as little-endian `u64`, and the object-index bytes. `signatures/manifest.sig` is the raw 64-byte Ed25519 signature. Canonical `signatures/manifest.json` has format version `1`, algorithm `ED25519`, coverage identifier `REFORGE_PACKAGE_MANIFEST_AND_OBJECT_INDEX_V1`, the raw 32-byte public key as a JSON byte array, and fingerprint `ed25519_` plus lowercase hexadecimal BLAKE3-256 of that public key. Verification MUST use `ed25519-dalek` strict verification. A public key in the package is an identity hint, not trust; trust is granted only by the user or an out-of-band fingerprint. Package creation does not require signing.

### 16.4 Incremental snapshots

A future snapshot references previous package object IDs and includes only new objects. The canonical `SnapshotManifest` wrapper identifies the base snapshot and reused/new object IDs; its nested `PackageManifest`, graph, operation model, and object bytes remain the same. MVP writes standalone packages while using the same object ID/content-store implementation. No second container or object-ID scheme is permitted.

## 17. Secret vault

The vault-only in-memory model is separate from normal package DTOs:

```rust
pub enum SecretKind { ApiToken, Password, PrivateKey, Credential, Opaque }
pub enum SecretTarget {
    WindowsCredentialManager,
    ApplicationKeyring { application: String },
    EnvironmentVariable { name: String },
    ConfigField { destination: TokenizedPath },
    Manual,
}
pub struct SecretRecord {
    pub id: ComponentId,
    pub label: String,
    pub kind: SecretKind,
    pub target: SecretTarget,
    pub value: Zeroizing<Vec<u8>>, // in-memory only; never normal Serde output
}
pub struct VaultDocument {
    pub format_version: u16,
    pub records: Vec<SecretRecord>,
}
```

`VaultDocument` is constructed only after explicit per-secret approval and is serialized directly into the age-encrypted payload; `SecretRecord.value` MUST be excluded from normal manifests, logs, diagnostics, UI state, and journal rows. `EnvironmentVariable` and `ConfigField` targets remain manual unless the adapter proves a secure target policy.

The normal package contains only secret references and redacted metadata. When the user explicitly selects a secret:

1. show the secret label, source, target storage behavior, and risk;
2. read it through the adapter while keeping it out of logs/UI state;
3. place canonical secret records into an in-memory vault document;
4. generate an ephemeral X25519 identity and encrypt the document to its recipient with age v1;
5. encrypt that X25519 identity separately with the user passphrase using age's scrypt recipient and store both armored age payloads in the canonical vault envelope;
6. optionally show that same X25519 identity once as recovery material and require an explicit save/acknowledgement step before package publication;
7. zeroize plaintext buffers and do not persist the unencrypted recovery identity in the package.

The application MUST use `age` APIs and `zeroize`; no custom crypto or password KDF. Password/recovery input is never placed in command-line arguments. Best-effort memory locking MAY be used but must not be presented as guaranteed protection. Opaque user-selected files or portable binaries may contain undetected secrets; secret scanning is a warning aid, not a guarantee, and the UI MUST disclose that risk.

An age v1 scrypt stanza MUST be the only recipient stanza in its header (C2SP age v1, scrypt recipient type), so a passphrase recipient and an X25519 recipient MUST NOT be combined in one age file. Reforge therefore uses two nested, standard age v1 payloads: an X25519-encrypted vault plus a passphrase-encrypted copy of the generated X25519 identity. This preserves independent passphrase and recovery decryption without custom cryptography or a non-conformant mixed-recipient header.

A secret is restored only through an adapter-specific secure target. Plain environment variables and plaintext config files are classified `MANUAL_SECRET_REQUIRED` by default. If the user explicitly accepts plaintext target storage, the plan displays that fact and records it in the journal.

## 18. Restore strategy taxonomy

Each component has one primary strategy and optional alternatives:

- `REINSTALL`: trusted provider/package recipe; verify installed identity.
- `CONFIG_PORTABLE`: copy/merge documented config into tokenized destination.
- `DATA_PORTABLE`: copy unique user data with size/lock policy.
- `EXPORT_IMPORT`: use documented application/provider export/import.
- `PORTABLE_BINARY`: copy selected executable/files; verify hash/signature; no source claim.
- `SECRET_EXPORTABLE`: explicit vault-backed adapter restore.
- `REAUTH_REQUIRED`: restore non-secret config and create sign-in action.
- `MACHINE_BOUND`: report only; never automatic.
- `PARTIAL`: apply safe subset and list remainder.
- `MANUAL`: create action with exact reason/instructions.
- `UNKNOWN`: no automatic plan until user chooses a policy.

Portability and strategy are not inferred solely from file extension. Every strategy references adapter evidence and a verification rule.

## 19. Target analysis, modes, compatibility, and conflicts

### 19.1 Target modes

`REBUILD` means a fresh or mostly fresh Windows target where selected source state should be established. It still scans first and never erases unselected state.

`MIGRATE` means an existing target. It computes source desired state versus target current state and applies only safe deltas.

### 19.2 Compatibility facts

Compare:

- Windows version/build and supported feature set;
- x64/ARM64 architecture;
- available disk and package size;
- current user/SID scope versus source scope;
- elevation capability;
- provider/runtime availability;
- required WSL/Docker/virtualization support;
- package source reachability and version availability;
- application major version and schema compatibility where known.

Hostname, machine GUID, device IDs, hardware paths, driver state, and SIDs are never treated as portable configuration.

```rust
pub enum CompatibilityStatus { Ready, RequiresConfirmation, Blocked }
pub struct Blocker {
    pub code: ReforgeErrorCode,
    pub component: Option<ComponentId>,
    pub reason: String,
    pub required_action: Option<ManualAction>,
}
pub struct Confirmation {
    pub id: String,
    pub component: Option<ComponentId>,
    pub reason: String,
    pub risk: RiskLevel,
}
pub struct CompatibilityResult {
    pub status: CompatibilityStatus,
    pub blockers: Vec<Blocker>,
    pub confirmations: Vec<Confirmation>,
    pub warnings: Vec<String>,
}
```

`Blocked` is non-approvable until the blocker is resolved or the affected component is removed from the selection. `RequiresConfirmation` is approvable only after each confirmation is recorded in the journal; warnings alone do not block.

### 19.3 Conflict kinds and default resolution

```text
ALREADY_SATISFIED       -> verify, skip
VERSION_DIFFERENCE      -> keep newer target; prompt before downgrade/upgrade
CONFIG_DIFFERENCE       -> adapter merge or target backup + confirmation
DATA_COLLISION          -> never overwrite silently; backup and manual decision
SECRET_COLLISION        -> never auto-replace
PATH_COLLISION          -> case-insensitive dedupe; preserve target order; append source
PORT_COLLISION          -> manual
DEPENDENCY_CONFLICT     -> block dependent operation
ARCHITECTURE_CONFLICT   -> unsupported/manual
UNSUPPORTED_TARGET      -> manual report
```

Target files are backed up under a tokenized, per-run Reforge backup root before replacement. No operation deletes target data in MVP. A user-approved future cleanup operation would require a separate operation kind and explicit preview.

## 20. Restore plan DAG

The planner topologically sorts graph dependencies and operation prerequisites with a stable tie-breaker. Default phase order is:

1. inspect/validate package;
2. inspect target and compatibility;
3. bootstrap documented Windows prerequisites;
4. bootstrap providers/runtimes;
5. install packages/applications;
6. restore editor/configuration/data;
7. merge environment/PATH;
8. restore WSL/Docker selected artifacts;
9. restore AI harnesses/MCP/skills/hooks metadata;
10. restore browser portable state;
11. apply manual/privileged system actions;
12. restore explicitly approved secrets;
13. verify all selected components;
14. pause for reboot or manual actions and resume.

The planner may run independent operations concurrently only when their write roots and journal keys do not overlap. MVP execution uses one operation at a time for deterministic logs; provider download work may be bounded and concurrent before install.

## 21. Typed operation model

Allowed operation kinds:

```rust
pub enum OperationKind {
    EnsureProvider { provider: ProviderId },
    InstallPackage { provider: ProviderId, package: PackageSpec, policy: PackageInstallPolicy },
    EnsureRuntime { runtime: RuntimeSpec },
    WriteFile { destination: TokenizedPath, object: ObjectId, mode: FileMode },
    MergeJson { destination: TokenizedPath, object: ObjectId, policy: MergePolicy },
    MergeToml { destination: TokenizedPath, object: ObjectId, policy: MergePolicy },
    SetUserEnvironment { name: String, value: SafeValueRef },
    AppendUserPath { entries: Vec<TokenizedPath> },
    ImportWsl { distro: WslSpec, object: ObjectId },
    RestoreDockerImage { image: DockerImageSpec, object: ObjectId },
    RestoreDockerVolume { volume: DockerVolumeSpec, object: ObjectId },
    InstallVsCodeExtension { id: String, version: Option<String>, profile: Option<String> },
    RegisterMcp { server: McpServerSpec },
    OpenManualAction { action: ManualAction },
    RequireReboot { reason: String },
    Verify { rule: VerificationRule },
}
```

Operation handlers are fixed by kind:

| Kind | Allowed effect | Mandatory gate |
|---|---|---|
| `EnsureProvider` | resolve and probe one built-in provider executable | reviewed bootstrap recipe; otherwise manual |
| `InstallPackage` | invoke the selected provider with exact typed ID/source/version | source/version/agreement policy and target verification; no latest fallback |
| `EnsureRuntime` | invoke a reviewed runtime/provider recipe | exact runtime/architecture compatibility |
| `WriteFile` | stream one verified object to one tokenized destination | allowed root, backup, atomic replace, hash/length verification |
| `MergeJson` / `MergeToml` | parse one verified object and merge declared keys | schema/content check, explicit merge policy, backup on change |
| `SetUserEnvironment` / `AppendUserPath` | update current-user non-secret environment state | name/path validation, deduplication, broadcast, verification |
| `ImportWsl` | import one selected WSL export | WSL prerequisite and distro identity/size check |
| `RestoreDockerImage` / `RestoreDockerVolume` | restore one selected Docker object | Docker availability, size check, ID/tag or volume verification |
| `InstallVsCodeExtension` | request/install the exact extension identity/version | source/trust visibility and extension verification |
| `RegisterMcp` | write normalized MCP registration without secret literals | runtime/package reference check; never start the server |
| `OpenManualAction` / `RequireReboot` | journal a pause/action only | user acknowledgement or reboot resume |
| `Verify` | read and compare target state | no mutation |

No handler may broaden a kind's effect based on package data. Any provider installer, extension, hook, plugin, script, or unknown binary that needs execution remains visible as a supply-chain boundary and requires its typed handler's trust/manual policy.

The enum is wrapped by these canonical DTOs in `crates/reforge-domain/src/model.rs`:

```rust
pub enum Precondition {
    Always,
    TargetFingerprint { fingerprint: String },
    ComponentAbsent { component: ComponentId },
    ComponentVersion { component: ComponentId, minimum: Option<VersionValue> },
    ArtifactPresent { object: ObjectId },
    ManualApproval { action: String },
}
pub struct Operation {
    pub id: OperationId,
    pub component: ComponentId,
    pub kind: OperationKind,
    pub prerequisites: Vec<OperationId>,
    pub precondition: Precondition,
    pub idempotency_key: String,
    pub verification: Vec<VerificationRule>,
    pub requires_elevation: bool,
    pub non_idempotent: bool,
}
pub enum RestoreMode { Rebuild, Migration }
pub enum ConflictKind {
    AlreadySatisfied,
    VersionDifference,
    ConfigDifference,
    DataCollision,
    SecretCollision,
    PathCollision,
    PortCollision,
    DependencyConflict,
    ArchitectureConflict,
    UnsupportedTarget,
}
pub struct Conflict {
    pub id: String,
    pub component: Option<ComponentId>,
    pub kind: ConflictKind,
    pub source_summary: String,
    pub target_summary: String,
    pub resolution: ConflictResolution,
    pub requires_confirmation: bool,
}
pub enum ConflictResolution { Skip, Install, Replace, Merge, PreserveTarget, Manual }
pub struct RestorePlan {
    pub format_version: u16,
    pub run_id: RunId,
    pub package_id: String,
    pub mode: RestoreMode,
    pub target_fingerprint: String,
    pub selected_components: Vec<ComponentId>,
    pub operations: Vec<Operation>,
    pub conflicts: Vec<Conflict>,
    pub manual_actions: Vec<ManualAction>,
    pub warnings: Vec<String>,
}
```

Plan validation is mandatory before approval and again before execution. It MUST reject duplicate operation IDs or idempotency keys, missing prerequisite IDs, dependency cycles, object IDs absent from the package index, absolute/parent path tokens, writes to protected managed roots, implicit secret writes, and an elevation requirement without an explicit privileged operation boundary. It MUST also reject a `WriteFile`/merge pair that overlaps a write root unless the merge policy and prerequisite order make the result deterministic. Validation returns coded `SCHEMA_INVALID`, `DEPENDENCY_CYCLE`, `TARGET_CONFLICT`, or `SECURITY_POLICY` diagnostics; it never drops an invalid operation.

The planner emits a deterministic topological order with a stable tie-break `(component_id, operation_kind, normalized_destination, operation_id)`. The executor may schedule only operations whose prerequisites are complete and whose write roots do not overlap. A plan is data, not a script: no field in these DTOs may contain a shell command, executable path selected from package data, or opaque imperative step.

There is no `RunCommand`, `RunScript`, `Eval`, `PostInstallScript`, or operation containing a shell string. Provider adapters translate typed package specifications into trusted `Command` argument vectors at runtime. Command binaries are resolved from known provider executable names and checked against the target observation.

## 22. Executor, elevation, idempotency, and reboot

The platform process boundary is typed and internal:

```rust
pub enum BuiltinExecutable { WinGet, Chocolatey, Scoop, Npm, Pnpm, Yarn, Bun, Python, Pipx, Uv, Cargo, Rustup, Go, Dotnet, PowerShell, Wsl, Docker, Code }
pub enum TrustedExecutable { Builtin(BuiltinExecutable), Observed { component: ComponentId } }
pub struct CommandSpec {
    pub executable: TrustedExecutable,
    pub args: Vec<String>,
    pub timeout: Duration,
    pub output_limit_bytes: usize,
}
pub struct ProcessResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub cancelled: bool,
}
pub struct ProcessRunner;
pub struct ElevationRequest { pub run_id: RunId, pub operation: OperationId, pub nonce: String }
```

`ProcessRunner` resolves `BuiltinExecutable` to a known executable name and resolves `Observed` only through a component already observed on the target. It passes `args` directly to `CreateProcess`/equivalent without a shell, omits secrets from the inherited environment, applies timeout/output caps, and returns redacted `ProcessResult`. `ElevationRequest` contains no package path, executable path, or command text.

Each operation has a deterministic idempotency key from run ID, component ID, operation kind, normalized destination/package identity, and object ID.

Before execution:

1. evaluate preconditions and current target observation;
2. if already satisfied, journal `SKIPPED_ALREADY_SATISFIED`;
3. for file writes, create a backup, write a temp file beside destination, flush, validate bytes, then atomically replace;
4. for package installs, invoke the provider adapter with explicit args and capture exit code/output after redaction;
5. record result and verification evidence before moving to the next operation.

The normal GUI runs unelevated. Privileged operations use a separately installed signed helper launched through the Windows `runas` mechanism. The helper receives only a run ID/nonce, opens the local journal, validates that the run is user-approved and the operation belongs to the same user-created plan, and communicates over an ACL-restricted named pipe. No package path or command text is accepted as an elevation argument. If the helper is absent, the operation becomes a manual relaunch action.

A reboot-required result pauses the run as `WAITING_FOR_REBOOT`. MVP does not create hidden RunOnce persistence. The UI/CLI offers `resume <run-id>` after the user reopens Reforge. An optional future mode may create a one-shot Task Scheduler 2.0 logon task only after explicit user approval, with deletion journaled.

## 23. Restore journal

SQLite tables:

```sql
runs(id TEXT PRIMARY KEY, package_id TEXT NOT NULL, mode TEXT NOT NULL,
     target_fingerprint TEXT NOT NULL, status TEXT NOT NULL,
     approval_state TEXT NOT NULL, approved_at TEXT,
     created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
operations(id TEXT PRIMARY KEY, run_id TEXT NOT NULL, op_key TEXT NOT NULL UNIQUE,
     component_id TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL,
     attempt INTEGER NOT NULL, requires_elevation INTEGER NOT NULL,
     started_at TEXT, ended_at TEXT, input_json TEXT NOT NULL,
     result_json TEXT, error_json TEXT, backup_json TEXT);
events(seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
     time TEXT NOT NULL, level TEXT NOT NULL, event_json TEXT NOT NULL);
manual_actions(id TEXT PRIMARY KEY, run_id TEXT NOT NULL, state TEXT NOT NULL,
     title TEXT NOT NULL, reason TEXT NOT NULL, risk TEXT NOT NULL,
     instructions_json TEXT NOT NULL, acknowledged_at TEXT);
```

Run statuses are `PLANNED`, `WAITING_FOR_APPROVAL`, `RUNNING`, `WAITING_FOR_USER`, `WAITING_FOR_REBOOT`, `COMPLETED`, `PARTIAL`, `FAILED`, `CANCELLED`, and `INTERRUPTED`. Approval states are `PENDING`, `APPROVED`, and `REJECTED`; execution requires `APPROVED`.

Enable WAL, foreign keys, busy timeout, and a single writer. On startup, `RUNNING` operations become `INTERRUPTED`; the executor rechecks preconditions and verification. Non-idempotent operations are never blindly retried. Journal writes are flushed at operation state boundaries. The journal is local application state, not part of the portable package.

## 24. Verification and reporting

Every selected component has at least one verification rule:

- package: provider identity/version/source query;
- executable: exists, version metadata, signature state, optional hash;
- config: destination exists and semantic parse succeeds;
- PATH/environment: target scope contains expected non-secret entries;
- VS Code: extension ID/version enumeration;
- MCP: config parses, command/runtime reference exists, secret reference remains bound;
- WSL: distro registered and expected version/state visible;
- Docker: image/volume/context exists and IDs/tags match expected evidence;
- browser: profile/artifact parses and browser is not running during file validation;
- secret: secure target adapter acknowledges write, never log value.

Report statuses:

```text
VERIFIED, PARTIALLY_VERIFIED, ALREADY_PRESENT, SKIPPED,
WAITING_FOR_USER, REAUTH_REQUIRED, REBOOT_REQUIRED,
UNSUPPORTED, FAILED
```

```rust
pub enum ReportStatus {
    Verified, PartiallyVerified, AlreadyPresent, Skipped,
    WaitingForUser, ReauthRequired, RebootRequired, Unsupported, Failed,
}
pub struct VerificationEvidence {
    pub rule: VerificationRule,
    pub status: ReportStatus,
    pub summary: String,
    pub observed_at: DateTime<Utc>,
}
pub struct ComponentReport {
    pub component: ComponentId,
    pub status: ReportStatus,
    pub evidence: Vec<VerificationEvidence>,
    pub manual_actions: Vec<String>,
    pub warnings: Vec<String>,
}
pub struct ReportCounts {
    pub verified: u64,
    pub partial: u64,
    pub already_present: u64,
    pub waiting_for_user: u64,
    pub reauth_required: u64,
    pub reboot_required: u64,
    pub unsupported: u64,
    pub failed: u64,
}
pub struct RestoreReport {
    pub format_version: u16,
    pub run_id: RunId,
    pub package_id: String,
    pub status: ReportStatus,
    pub counts: ReportCounts,
    pub components: Vec<ComponentReport>,
    pub manual_actions: Vec<ManualAction>,
    pub warnings: Vec<String>,
    pub elapsed_ms: u64,
    pub bytes_written: u64,
}
```

Every selected component MUST have a `ComponentReport`; a missing report item is a verification failure, not an omitted item. `VerificationEvidence.summary` and report warnings are redacted bounded text and MUST NOT contain secret values or untokenized source paths.

Final report includes counts, bytes, elapsed time, failures, warnings, manual actions, source/provenance, and verification evidence. It never hides a failure behind a success count.

## 25. Manual action queue

Manual actions are first-class and resumable. Each action contains:

- title and component;
- why automation stopped;
- exact user action;
- risk level;
- optional official documentation link;
- whether independent operations may continue;
- acknowledgement state and timestamp;
- resulting verification rule.

Examples: sign in to browser/Codex/VS Code, close a locked browser, accept an EULA, choose a default browser in Windows Settings, enter a vault passphrase, install a missing provider, approve a third-party extension, or select an unknown source.

## 26. CLI contract

Commands:

```text
reforge scan [--json]
reforge inventory show [--json]
reforge package create --output <path> [--selection <path>] [--secret-selection <path>]
reforge package inspect <path> [--json]
reforge target scan [--json]
reforge plan --package <path> --mode rebuild|migrate [--json]
reforge restore --package <path> --mode rebuild|migrate [--yes-safe]
reforge resume <run-id>
reforge action list <run-id> [--json]
reforge action acknowledge <run-id> <action-id> [--json]
reforge verify <run-id> [--json]
reforge report <run-id> [--output <path>]
reforge doctor [--json]
reforge interactive
```
**Scope correction (2026-08-31):** `scan` has no user/machine/all selector. The current discovery contract has no end-to-end scope field, and adapters collect their documented current-user and machine observations together. A selector would falsely imply a verifiable filtered inventory; it requires a dedicated scoped-discovery contract before it can be exposed.


`--json` prints exactly one versioned JSON document to stdout; human progress goes to stderr. Exit codes:

```text
0 success; 1 partial/failure report; 2 invalid input/package;
3 user action required; 4 compatibility blocked; 5 security/trust blocked;
6 interrupted/reboot pending
```

No CLI option accepts a command string to execute. Paths are validated and displayed in normalized/tokenized form where possible.
`--secret-selection` names explicitly selected secret IDs; it never means include every discovered secret.

**Interactive CLI amendment (2026-09-02):** Add `reforge interactive` as a human-only, line-oriented wizard. It presents the complete workflow as numbered choices, displays the discovered inventory in bounded numbered pages, and builds `SelectionInput` from the chosen component numbers. It MUST call the same application service and validation boundaries as the declared subcommands; it MUST NOT execute shell text, expose secret values, select sensitive/secret components under the default exclusion policy, or change the existing non-interactive commands and JSON envelope. `--json` with `interactive` is invalid. Restore requires an exact `YES` confirmation, and the wizard retains the package path and run ID needed for inspect/plan/restore/resume/action/verify/report. Invalid input and EOF return to the menu or exit cleanly without mutating restore state. The amendment extends T047's exact implementation files with no new runtime dependency; its tests cover menu navigation, bounded numeric component selection, explicit restore confirmation, EOF, and rejection of `interactive --json`.

## 27. Desktop GUI and information architecture

Screens:

1. **Home:** Scan this PC, Open package, Resume run.
2. **Scan progress:** phase, current adapter, item counts, cancel, warnings.
3. **Scan results:** recommended summary, category counts, confidence/portability filters.
4. **Selection:** component tree with dependency closure, size, sensitivity, source, and explanation.
5. **Package review:** contents, vault choice, size estimate, warnings, create button.
6. **Target analysis:** target facts, source/target diff, compatibility blockers.
7. **Restore plan:** ordered operations, conflicts, manual actions, safe defaults.
8. **Restore progress:** per-item lifecycle, bytes, current operation, pause/resume, errors.
9. **Verification:** verified/partial/failed/reauth summary with evidence.
10. **Report/export:** save redacted report and diagnostic bundle.

Primary simple-user path is approximately: `Scan` -> `Create/Open` -> `Restore`. Advanced controls expose every component and operation. No spinner may conceal a stalled process; all long operations have progress, cancellation, and a log drawer.

UI requirements:

- keyboard navigation and visible focus;
- semantic headings and labels;
- no color-only status indicators;
- responsive layouts at 1024px and 1440px desktop widths, with a usable minimum 800px window;
- loading, empty, partial, error, and manual-action states;
- virtualized component list for large inventories;
- no secret values in Svelte state or browser devtools;
- event stream is append-only and mapped to typed models.

Tauri commands are small: `start_scan`, `cancel_run`, `get_inventory`, `create_package`, `inspect_package`, `build_plan`, `start_restore`, `resume_restore`, `get_run`, `ack_manual_action`, `save_report`. Tauri events carry progress/report deltas; the backend remains authoritative.

### 27.1 Current release control surface

The current desktop artifact is intentionally CLI-only. The desktop UI source and typed Tauri command implementations remain in the repository for a future desktop profile, but this release MUST NOT register those commands or native file-dialog plugins. The shell MAY display an informational notice only. There is no runtime setting, environment variable, or UI control that re-enables desktop control. Discovery, packaging, inspection, planning, restore, resume, verification, and report workflows are controlled through the CLI contract in Section 26.

### 27.2 Current implementation status recorded by T054

The current release documentation describes the checked-in control surface, not an unimplemented target. The production CLI registry in `crates/reforge-cli/src/main.rs::default_registry` registers WinGet, Chocolatey, Scoop, Python, Rust, Go, .NET, PowerShell, npm/pnpm/Yarn/Bun, Windows registration, Codex/Claude Code/OpenCode, WSL, Docker, and generic executable adapters. The standalone browser and VS Code discovery adapters are public and fixture-tested but are not registered with that coordinator; automatic `reforge scan` therefore MUST NOT promise browser or editor inventory until that integration and its end-to-end verification are added.

The package library implements optional Ed25519 signature inspection and the age/zeroize vault boundary, but the current CLI package-creation path emits unsigned packages and rejects non-empty secret selection because secure adapter value collection is not exposed. Documentation MUST describe these as library/partial capabilities and MUST NOT promise CLI secret export or signed local package creation.

`README.md`, `docs/support-matrix.md`, `docs/recovery.md`, `docs/security.md`, and `docs/sources.md` are the user and maintainer documentation for these boundaries. They are subordinate to this specification and MUST be updated with this section when the release control surface changes.

## 28. Error model

```rust
pub enum ReforgeErrorCode {
    AccessDenied, PathNotFound, FileLocked, InvalidPath, ReparsePoint,
    ProviderUnavailable, ProviderParseFailed, SourceUnavailable, VersionUnavailable,
    PackageNotFound, PackageCorrupt, PackageUntrusted,
    VaultRequired, VaultDecryptFailed, SecretNotPortable, ManualSecretRequired,
    SchemaInvalid, UnsupportedVersion, ArchitectureConflict, OsConflict,
    InsufficientDisk, DependencyCycle, SelectionIncomplete, TargetConflict,
    SecurityPolicy, ManualActionRequired, UserActionRequired, RebootRequired,
    OperationFailed, InstallFailed, VerificationFailed, Interrupted, Cancelled,
}
```


```rust
pub enum Retryability { Never, SafeRetry, RequiresUserAction, AfterReboot }
pub struct ErrorEnvelope {
    pub code: ReforgeErrorCode,
    pub message: String,
    pub technical_detail: Option<String>,
    pub component: Option<ComponentId>,
    pub operation: Option<OperationId>,
    pub retryability: Retryability,
    pub context_id: Option<String>,
}
```

`technical_detail` is optional bounded redacted text; `message` is safe for direct display. A boundary MUST discard the detail rather than emit it when redaction cannot prove safety.
Errors carry code, user message, technical detail, component/operation IDs, retryability, and redacted source context. Provider stdout/stderr is stored with secret patterns redacted and bounded. Do not catch all errors into `Unknown`.

## 29. Security threat model and invariants

Threats: malicious/tampered package, zip-slip/zip bomb, malicious path/reparse point, command injection, malicious installer or extension, privilege escalation, secret exposure, log/diagnostic leakage, interrupted non-idempotent restore, SID/ACL confusion, account-session theft, and accidental target deletion.

Mandatory mitigations:

- package is untrusted until schema, path, size, object hash, and trust review pass;
- allowlisted destination roots and tokenized paths only;
- reject absolute/parent/reparse traversal and unsafe archive entry names;
- package objects are never consumed for restore, and installers never run, before schema validation, object integrity checks, source/provider checks, and explicit user approval;
- OS Authenticode verification via WinTrust where applicable;
- age vault and zeroization for selected secrets;
- no plaintext secret in normal manifest, logs, CLI arguments, or UI state;
- least privilege and a constrained elevation helper;
- no automatic default-browser registry writes;
- no copying of DPAPI/App-Bound browser cookies/logins;
- no ACL/SID restoration; map files to current user and preserve target permissions unless explicitly supported;
- backups before target writes; no deletion in MVP;
- bounded archive/file/count/output sizes and cancellation;
- reparse points are recorded but not followed;
- no telemetry/network inventory; external provider network access and every source URL are visible in the plan, and source URLs are never fetched merely because they appear in a package;
- dependency/license/security scans in CI.

An unsigned package is allowed to inspect but displays a trust warning and requires an explicit restore approval. A signature verifies integrity/authorship only when the key is trusted out of band.

## 30. Licensing and supply chain

Reforge source code is licensed under Apache-2.0. It must not require a paid API or hosted service. Every dependency must pass license compatibility review before release. `cargo deny`/`cargo audit` or equivalent CI checks are required, but their output never replaces manual review of package/installer trust.

Release artifacts are signed through the Tauri updater signing mechanism. The signing key stays in release infrastructure and is never included in packages. The updater verifies signatures before installing an update. No specific publisher certificate is assumed until the release process obtains one.

## 31. MVP boundary

MVP must demonstrate the architecture end to end on a Windows 11 x64 VM with:

- scan and evidence-backed inventory;
- WinGet export/install/verification;
- uninstall registry/App Paths/PATH/known-folder discovery;
- generic signed/unsigned executable identification and explicit portable-binary path;
- Node, Python, Git, VS Code, and one shell configuration path;
- Codex, Claude Code, OpenCode configuration discovery with MCP normalization;
- skills/agents/hooks/plugins as metadata/config artifacts, not auto-executed code;
- browser installation/profile detection with bookmarks/config partial restore and reauth classification;
- package creation/inspection with ZIP64, object hashes, zstd, size limits;
- age vault with passphrase and optional recovery identity;
- rebuild and migrate planners with target diff/conflict preview;
- typed idempotent restore, journal, manual queue, reboot pause/resume;
- verification/report output;
- full VM scenario: source VM -> package -> clean target VM -> restore -> second target scan -> comparison.

MVP does not promise complete coverage or automatic restore for every listed package provider, every browser, arbitrary app adapters, automatic secrets into plaintext env vars, Docker volume migration, full WSL distro migration, direct PC transfer, or cross-platform operation. Where an adapter exists for one of these areas, MVP exposes only the typed safe subset and reports the remainder as partial/manual rather than implying full support.

## 32. Roadmap after MVP

1. complete and harden provider adapters beyond the WinGet-first MVP path for Chocolatey, Scoop, npm/pnpm/Bun/Yarn, pip/pipx/uv, Cargo/rustup, Go, PowerShell Gallery, dotnet, and Conda;
2. richer VS Code profiles and extension publisher trust workflow;
3. Docker image/context/volume export and WSL distribution transfer;
4. browser-specific supported exports and Firefox database adapters;
5. incremental package sets and remote/NAS object stores;
6. optional package signatures/trusted identities;
7. explicit Task Scheduler reboot resume;
8. LAN direct transfer using the same object stream protocol, mutual authentication, and integrity checks;
9. community adapter SDK with signed/reviewed manifests and sandboxed provider metadata;
10. ARM64 and additional Windows editions after compatibility fixtures exist.

## 33. Direct transfer design

Define a future `ObjectTransport` trait:

```rust
pub type TransportResult<T> = Result<T, ErrorEnvelope>;
pub trait ObjectTransport {
    async fn send_manifest(&mut self, manifest: PackageManifest) -> TransportResult<()>;
    async fn send_object(&mut self, id: ObjectId, reader: Box<dyn AsyncRead + Send + Unpin>) -> TransportResult<()>;
    async fn receive_missing(&mut self, ids: Vec<ObjectId>) -> TransportResult<()>;
    async fn finish(&mut self) -> TransportResult<TransportReceipt>;
}
```

The portable ZIP writer and LAN transport both consume the same `PackageGraph` and `ObjectStore`. The transport sends manifest first, target requests missing IDs, each object is verified before commit, and no restore begins until the target has a complete verified graph. MVP implements only the filesystem package transport.

## 34. Verification contract

Before declaring implementation complete:

- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` pass;
- `pnpm install --frozen-lockfile`, `pnpm check`, and UI tests pass;
- CLI smoke exercises `scan`, `package inspect`, `plan`, `restore`, `resume`, `verify`, and exit code behavior;
- package corruption, zip-slip, zip-bomb, path traversal, secret-redaction, vault wrong-passphrase, and command-injection fixtures fail closed;
- Windows integration tests exercise both registry views, known folders, environment scopes, PE metadata/signature result handling, reparse rejection, and elevation/manual fallback;
- VM E2E exercises source scan -> package -> clean target restore and source -> non-empty target migrate with a pre-existing newer package/config collision;
- after restore, a fresh target scan and verification report provide evidence for every selected item;
- manual actions, reauth, unsupported, partial, and failed items remain visible in the final report;
- no test depends on a real user's credentials, cloud account, browser cookies, or external private package.

## 35. Atomic implementation task contract

Every task below is independently reviewable. Each task MUST include an ID in its heading, a goal, an explicit reason it exists, dependencies, exact files to create, exact files to modify, types/interfaces, an exact algorithm, inputs, outputs, integration points, failure behavior, security considerations, unit tests, integration tests where applicable, and Definition of Done. To keep the task blocks compact, the current labels are normative grouped fields: `Goal` is the task's explicit `Why it exists` statement; `Inputs/outputs` contains the required `Inputs` and `Outputs` subfields; `Failure/security` contains the required `Failure behavior` and `Security considerations` subfields; and `Tests` contains the required `Unit tests` plus any applicable integration-test coverage. The `Exact files to create` and `Exact files to modify` fields are authoritative; the compact `Files` field is retained as a human-readable scope summary. Tasks may add helper files only when the exact field names their path or the task explicitly names its containing directory, and must not create alternate domain models.

The grouped labels are not optional shorthand: implementers and reviewers MUST read them as the corresponding atomic fields above. A task with no applicable integration test MUST state that fact in its `Tests` field or task-level review record; absence of an integration test is not permission to omit unit coverage. This convention preserves one auditable schema across all T001–T054 blocks and the inserted T013a task without duplicating identical prose.

### T001 — Scaffold workspace and toolchain

- **Goal:** create the Rust workspace, Tauri shell, Svelte/Vite app, pnpm lock, and CI skeleton.
- **Dependencies:** none.
- **Files:** `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `package.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `LICENSE-APACHE`, `crates/reforge-domain/Cargo.toml`, `crates/reforge-platform-windows/Cargo.toml`, `crates/reforge-discovery/Cargo.toml`, `crates/reforge-package/Cargo.toml`, `crates/reforge-restore/Cargo.toml`, `crates/reforge-cli/Cargo.toml`, `crates/reforge-elevation-helper/Cargo.toml`, `crates/reforge-domain/src/lib.rs`, `crates/reforge-platform-windows/src/lib.rs`, `crates/reforge-discovery/src/lib.rs`, `crates/reforge-package/src/lib.rs`, `crates/reforge-restore/src/lib.rs`, `crates/reforge-cli/src/main.rs`, `crates/reforge-elevation-helper/src/main.rs`, `src-tauri/Cargo.toml`, `src-tauri/build.rs`, `src-tauri/src/lib.rs`, `src-tauri/src/main.rs`, `src-tauri/icons/icon.ico`, `src-tauri/capabilities/main.json`, `src-tauri/tauri.conf.json`, `ui/package.json`, `ui/index.html`, `ui/vite.config.ts`, `ui/tsconfig.json`, `ui/src/main.ts`, `ui/src/App.svelte`, `ui/src/vite-env.d.ts`, `ui/src/app.css`, and `.github/workflows/ci.yml`.
- **Exact files to create:** `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `package.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `LICENSE-APACHE`, `crates/reforge-domain/Cargo.toml`, `crates/reforge-platform-windows/Cargo.toml`, `crates/reforge-discovery/Cargo.toml`, `crates/reforge-package/Cargo.toml`, `crates/reforge-restore/Cargo.toml`, `crates/reforge-cli/Cargo.toml`, `crates/reforge-elevation-helper/Cargo.toml`, `crates/reforge-domain/src/lib.rs`, `crates/reforge-platform-windows/src/lib.rs`, `crates/reforge-discovery/src/lib.rs`, `crates/reforge-package/src/lib.rs`, `crates/reforge-restore/src/lib.rs`, `crates/reforge-cli/src/main.rs`, `crates/reforge-elevation-helper/src/main.rs`, `src-tauri/Cargo.toml`, `src-tauri/build.rs`, `src-tauri/src/lib.rs`, `src-tauri/src/main.rs`, `src-tauri/icons/icon.ico`, `src-tauri/capabilities/main.json`, `src-tauri/tauri.conf.json`, `ui/package.json`, `ui/index.html`, `ui/vite.config.ts`, `ui/tsconfig.json`, `ui/src/main.ts`, `ui/src/App.svelte`, `ui/src/vite-env.d.ts`, `ui/src/app.css`, and `.github/workflows/ci.yml`.
- **Exact files to modify:** none; this is the clean-checkout bootstrap.
- **Types/interfaces involved:** Cargo workspace members, Tauri application entry, minimal capability, Vite/Svelte entry, and CI command matrix.
- **Exact algorithm:** Create the workspace and member manifests; pin the resolved stable toolchain; install the minimum Tauri/Svelte/Vite bootstrap; grant only explicit window capabilities; generate lockfiles; run the locked CLI, UI, and desktop build.
- **Inputs/outputs:** Input: clean checkout and installed Rust/pnpm/WebView2 development prerequisites. Output: buildable CLI, desktop shell, UI bundle, lockfiles, and CI definition.
- **Integration points:** All later crates, generated types, CLI, Tauri bridge, and UI consume this workspace; no provider or restore behavior is implemented here.
- **Change:** configure the exact workspace members and Windows target; pin the resolved stable toolchain; add Tauri 2 and Svelte 5; do not add broad Tauri permissions.
- **Tests:** build a hello CLI and launch a minimal Tauri window in a Windows development environment.
- **Failure/security:** build failures are surfaced; no shell plugin or unrestricted filesystem capability.
- **DoD:** clean checkout builds CLI and desktop shell; lockfiles are committed; CI invokes the same commands.
- **Bootstrap consistency note:** the original T001 list omitted the files required by the selected toolchains for a runnable clean build: Vite requires an HTML entry and Svelte root component, pnpm requires a workspace declaration for one root lockfile covering `ui`, the standard Tauri binary requires `src-tauri/src/main.rs` plus `build.rs`, `tauri-build` requires a Windows icon resource, and `svelte-check` requires an ambient `*.svelte` module declaration. This is the minimal correction; no product behavior is added.

### T002 — Define domain schema and generated TypeScript types

- **Goal:** establish one versioned wire/domain model.
- **Dependencies:** T001.
- **Files:** `crates/reforge-domain/src/model.rs`, `ids.rs`, `schema.rs`, `schemas/*.schema.json`, `ui/src/lib/generated.ts`, `ui/src/lib/types.ts`.
- **Exact files to create:** `crates/reforge-domain/src/model.rs`, `crates/reforge-domain/src/ids.rs`, `crates/reforge-domain/src/schema.rs`, `schemas/inventory.schema.json`, `schemas/package-manifest.schema.json`, `schemas/snapshot-manifest.schema.json`, `schemas/restore-plan.schema.json`, `schemas/error.schema.json`, `ui/src/lib/generated.ts`, and `ui/src/lib/types.ts`.
- **Exact files to modify:** `crates/reforge-domain/src/lib.rs`, `crates/reforge-domain/Cargo.toml`, `ui/package.json`, and `.github/workflows/ci.yml`.
- **Types/interfaces involved:** All canonical DTOs defined in §§9.2–9.4, 15, 19, 21, 24, and 28, including `Component`, `Inventory`, `Evidence`, `EvidenceSource`, `DependencyKind`, `DependencyEdge`, `TargetFacts`, `PackageManifest`, `SnapshotManifest`, `PackageGraph`, `ObjectIndex`, `Operation`, `OperationKind`, `RestorePlan`, `RestoreReport`, `ReportStatus`, `VerificationEvidence`, `ProgressEvent`, `RunStatus`, `OperationState`, `ArtifactRef`, `PathToken`, `ArtifactPolicy`, `VerificationRule`, `McpServerSpec`, `CompatibilityResult`, schema exports, Typeshare mappings, and versioned wire envelopes.
- **Exact algorithm:** Define every Serde-tagged Rust DTO in `model.rs` first, including evidence, graph, MCP, target, package, snapshot, selection, compatibility, operation, restore-plan, lifecycle, report, and error-envelope types; derive JSON Schema and Typeshare output; map UUID, RFC 3339 timestamps, URLs, and opaque IDs explicitly; reject unknown operations and invalid restricted references; compare generated files in CI. T046 may emit the standalone report schema from this canonical `RestoreReport`, but later crates MUST NOT add competing wire types.
- **Inputs/outputs:** Input: domain Rust definitions. Output: deserializable Rust model, JSON schemas, checked-in TypeScript DTOs, and schema-invalid errors for unsupported input.
- **Integration points:** Every crate, Tauri command, CLI envelope, package manifest, restore plan, provider adapter, and UI DTO imports this model.
- **Change:** Rust domain types are canonical; derive `schemars`/`typeshare` output into `schemas/*.schema.json` and `ui/src/lib/generated.ts`, define explicit mappings for UUID, RFC 3339 timestamps, URLs, and opaque IDs, reject unknown operation kinds, and make CI fail when generated files differ from source.
- **Tests:** JSON round-trip, missing required fields, unknown enum, forward-compatible `extensions`, deterministic serialization, invalid tokenized path, operation reference/cycle rejection, and MCP secret-reference redaction shape.
- **Failure/security:** schema errors use `SCHEMA_INVALID`; no untyped operation map; no absolute path or plaintext-secret fields in normal DTOs.
- **DoD:** CLI, Tauri, discovery, package, and restore crates import the same domain types; generated schema and TypeScript files are reproducible.

### T003 — Implement identifiers and canonical identity

- **Goal:** produce stable ComponentId/ObjectId/OperationId values.
- **Dependencies:** T002.
- **Files:** `crates/reforge-domain/src/ids.rs`, `canonical.rs` if needed, tests in `crates/reforge-domain/tests/model_roundtrip.rs`.
- **Exact files to create:** `crates/reforge-domain/tests/model_roundtrip.rs`.
- **Exact files to modify:** `crates/reforge-domain/src/ids.rs`.
- **Types/interfaces involved:** ComponentId, ObjectId, RunId, OperationId, EvidenceId, canonical identity tuple, and BLAKE3 encoding.
- **Exact algorithm:** Normalize only declared identity fields; serialize the canonical tuple; hash with the specified BLAKE3 encoding; validate prefixes and reject invalid/non-finite values; compare known vectors.
- **Inputs/outputs:** Input: identity facts with optional paths/publishers. Output: stable IDs independent of user/drive path where allowed, with local-quality fallback explicitly marked.
- **Integration points:** Discovery deduplication, package object indexing, operation journal keys, and cross-machine comparison rely on these IDs.
- **Change:** implement BLAKE3-based identities and identity priority; normalize case/path tokens only where specified.
- **Tests:** same identity across path/user changes; different publishers remain different; local fallback is marked low-quality; known vectors.
- **Failure/security:** reject invalid IDs and non-finite numbers.
- **DoD:** IDs are deterministic across process runs and documented in public Rust docs.

### T004 — Implement error and redacted diagnostics model

- **Goal:** make failures structured and safe to display.
- **Dependencies:** T002.
- **Files:** `crates/reforge-domain/src/error.rs`, `crates/reforge-restore/src/lib.rs`, logging setup files.
- **Exact files to create:** `crates/reforge-domain/src/error.rs` and `crates/reforge-domain/src/redaction.rs`.
- **Exact files to modify:** `crates/reforge-restore/src/lib.rs`, `crates/reforge-cli/src/main.rs`, and `src-tauri/src/lib.rs`.
- **Types/interfaces involved:** ReforgeErrorCode, coded error envelope, redaction policy, retryability, and diagnostic context IDs.
- **Exact algorithm:** Classify errors at boundaries; redact known secret/path/token patterns recursively; bound provider output; discard a diagnostic payload if redaction cannot prove safety; preserve component and operation IDs.
- **Inputs/outputs:** Input: provider/platform/restore errors and bounded stdout/stderr. Output: stable coded errors safe for CLI, UI, journal, and reports.
- **Integration points:** All adapters, executor transitions, CLI exit codes, Tauri events, and reports use the same error envelope.
- **Change:** implement error codes, retryability, context IDs, redaction of secret-like values, bounded provider output.
- **Tests:** redaction for API-key patterns, paths, command output, and nested JSON; preserve operation/component IDs.
- **Failure/security:** redaction failure must discard the diagnostic payload rather than emit raw content.
- **DoD:** no user-visible error is a plain `anyhow` string without a code.

### T005 — Build deterministic fixture and temp-root harness

- **Goal:** provide isolated test environments for files, registries, provider output, and package objects.
- **Dependencies:** T001-T004.
- **Files:** `tests/fixtures/*`, `crates/*/tests/support.rs`, `tests/integration/harness.rs`.
- **Exact files to create:** `tests/fixtures/mod.rs`, `tests/integration/harness.rs`, `crates/reforge-domain/tests/support.rs`, `crates/reforge-discovery/tests/support.rs`, `crates/reforge-package/tests/support.rs`, and `crates/reforge-restore/tests/support.rs`.
- **Exact files to modify:** none; fixture helpers are introduced before feature code.
- **Types/interfaces involved:** FixtureRoot, temporary token map, fake provider output, target inventory, lock/missing-file fixtures, and cleanup guards.
- **Exact algorithm:** Create every fixture beneath a temp root; expose deterministic builders; inject failures without using the real user profile; clean on both success and panic.
- **Inputs/outputs:** Input: test case parameters. Output: isolated fixture roots and deterministic observations/packages.
- **Integration points:** All non-VM unit/property/integration tests use the harness; VM tests are the only tests allowed to touch a Windows image.
- **Change:** create fixture builders for tokenized roots, fake package exports, locked/missing files, and target inventories.
- **Tests:** cleanup on success/failure; no fixture writes outside temp roots.
- **Failure/security:** reject fixture paths outside the fixture root.
- **DoD:** all non-VM tests use deterministic isolated fixtures.

### T006 — Implement Windows known-folder and host preflight

- **Goal:** resolve actual Windows host facts without hardcoded user paths.
- **Dependencies:** T002-T005.
- **Files:** `crates/reforge-platform-windows/src/known_folders.rs`, `src/lib.rs`, `crates/reforge-discovery/src/coordinator.rs`.
- **Exact files to create:** `crates/reforge-platform-windows/src/known_folders.rs`.
- **Exact files to modify:** `crates/reforge-platform-windows/src/lib.rs`.
- **Types/interfaces involved:** HostFacts, KnownFolderMap, architecture/elevation facts, and SHGetKnownFolderPath wrapper.
- **Exact algorithm:** Resolve current-user known folders through the Windows API; collect OS/build/architecture/elevation/drives/free-space; convert paths to tokens; return structured access errors without hardcoded user paths.
- **Inputs/outputs:** Input: current Windows process and API results. Output: typed HostFacts and token map consumed by discovery and target analysis.
- **Integration points:** Discovery coordinator preflight, path validation, target fingerprinting, package metadata redaction, and compatibility checks.
- **Change:** wrap `SHGetKnownFolderPath`, OS/build/architecture/elevation facts, and free-space queries.
- **Implementation note:** the mandated `BTreeMap<KnownFolderToken, PathBuf>` requires `KnownFolderToken` to implement `Ord`; T006 adds the minimal `Ord`/`PartialOrd` derives to the domain enum so the specified public map type is representable.
- **Tests:** current-user known folders exist/are tokenized; missing folder/API errors become evidence; path has no trailing separator assumption.
- **Failure/security:** never expand a package path into an arbitrary user; use current target known-folder map.
- **DoD:** discovery starts with a typed `HostFacts` record.

### T007 — Implement registry enumeration with both views

- **Goal:** enumerate uninstall/App Paths/environment roots safely.
- **Dependencies:** T006.
- **Files:** `crates/reforge-platform-windows/src/registry.rs`, tests/fixtures/registry fixtures.
- **Exact files to create:** `crates/reforge-platform-windows/src/registry.rs`, `tests/fixtures/registry/uninstall.json`, `tests/fixtures/registry/app_paths.json`, and `tests/fixtures/registry/environment.json`.
- **Exact files to modify:** `crates/reforge-platform-windows/src/lib.rs`.
- **Types/interfaces involved:** RegistryScope, RegistryView, typed registry observations, uninstall/App Paths/environment records.
- **Exact algorithm:** Open HKLM/HKCU in 32-bit and 64-bit views read-only; retain key/value types and access errors; normalize values without asserting binary presence; never write during discovery.
- **Inputs/outputs:** Input: registry roots and requested scopes. Output: evidence-bearing observations with scope/view and redacted values.
- **Integration points:** Windows registration adapters, generic correlation, environment discovery, and target scan consume these observations.
- **Change:** inspect HKLM/HKCU and 32/64 views; capture scope/view/key/value types and access errors.
- **Tests:** synthetic/Windows integration fixtures cover 32-bit and 64-bit entries, malformed values, access denied, and absent keys.
- **Failure/security:** never write registry during discovery; do not treat an uninstall entry as proof of a binary.
- **DoD:** registry observations include view and scope in evidence.

### T008 — Implement PE version and Authenticode inspection

- **Goal:** identify executable metadata and signer state.
- **Dependencies:** T006.
- **Files:** `crates/reforge-platform-windows/src/pe.rs`.
- **Exact files to create:** `crates/reforge-platform-windows/src/pe.rs` and `crates/reforge-platform-windows/tests/pe.rs`.
- **Exact files to modify:** `crates/reforge-platform-windows/src/lib.rs`.
- **Types/interfaces involved:** PE metadata, FileVersion, SignerStatus, WinTrust result, certificate fingerprint.
- **Exact algorithm:** Read version resources with the documented APIs; call WinVerifyTrust; treat only zero trust return as success; preserve exact nonzero errors; never load candidate binaries as code.
- **Inputs/outputs:** Input: executable path. Output: version/publisher/signature/hash metadata or coded inspection error.
- **Integration points:** Generic executable discovery, package portable-binary review, verification rules, and trust UX.
- **Change:** wrap version-info APIs and `WinVerifyTrust`; return exact status/error and signer metadata.
- **Tests:** signed fixture, unsigned fixture, malformed PE, missing file, non-zero trust status; `WinVerifyTrust` success only on zero.
- **Failure/security:** verification errors are not treated as trusted; do not load the file as code.
- **DoD:** generic executable discovery can show version/publisher/signature evidence.

### T009 — Implement reparse-safe file walker and atomic file primitives

- **Goal:** safely read/package/restore files.
- **Dependencies:** T005-T008.
- **Files:** `crates/reforge-platform-windows/src/process.rs` and `crates/reforge-platform-windows/src/fs.rs`.
- **Exact files to create:** `crates/reforge-platform-windows/src/process.rs` and `crates/reforge-platform-windows/src/fs.rs`.
- **Exact files to modify:** `crates/reforge-platform-windows/src/lib.rs`.
- **Types/interfaces involved:** SafePath, reparse-aware walker, bounded reader, atomic replacement, backup record, file attributes.
- **Exact algorithm:** Reject absolute/parent/drive package paths; inspect symlink/reparse metadata without traversal; stream bounded reads; write beside destination, flush, validate, backup, and atomically replace.
- **Inputs/outputs:** Input: tokenized path/object stream/destination root. Output: safe file observations, backups, or typed path/lock errors.
- **Integration points:** Content store, package reader/writer, file restore handlers, archive extraction, and all target writes use this boundary.
- **Change:** reject parent/absolute package paths, detect reparse points, stream reads, create temp + flush + atomic replace, preserve selected attributes only.
- **Tests:** traversal, drive path, junction/symlink/reparse, locked file, large file streaming, interrupted temp write, destination backup.
- **Failure/security:** no reparse traversal; no overwrite without backup.
- **DoD:** all package and restore file paths pass one shared validator.

### T010 — Implement process runner and constrained elevation protocol

- **Goal:** run trusted provider probes and privileged operations safely.
- **Dependencies:** T004, T009.
- **Files:** `crates/reforge-platform-windows/src/process.rs`, `privilege.rs`, `crates/reforge-elevation-helper/src/protocol.rs`, and `crates/reforge-elevation-helper/src/main.rs`.
- **Exact files to create:** `crates/reforge-platform-windows/src/privilege.rs` and `crates/reforge-elevation-helper/src/protocol.rs`.
- **Exact files to modify:** `crates/reforge-platform-windows/src/process.rs` and `crates/reforge-elevation-helper/src/main.rs`.
- **Types/interfaces involved:** Command argument vector, ProcessResult, CancellationToken, ElevationRequest, nonce, ACL-restricted named-pipe protocol.
- **Exact algorithm:** Resolve only built-in executable names; pass argv vectors with no shell; cap time/output; use runas with only run ID/nonce; helper reopens and validates the approved journal operation over the restricted pipe.
- **Inputs/outputs:** Input: trusted typed provider probe or approved privileged operation. Output: bounded result, manual fallback, timeout/cancel, or elevation error.
- **Integration points:** Every provider and restore handler uses the runner; Tauri/CLI never accepts a command string; helper is separately signed and packaged.
- **Change:** argument-vector process runner with timeout/cancellation/output caps; `runas` helper and ACL-restricted nonce pipe based on journal run ID.
- **Tests:** argument containing shell metacharacters remains literal; timeout/cancel; helper rejects wrong nonce/run; missing helper yields manual action.
- **Failure/security:** never invoke `cmd /c`/PowerShell with package-derived text; helper accepts no command strings.
- **DoD:** provider and restore code cannot call an untyped shell runner.

### T011 — Implement discovery coordinator and progress events

- **Goal:** orchestrate bounded scan phases and continue after item errors.
- **Dependencies:** T006-T010.
- **Files:** `crates/reforge-discovery/src/coordinator.rs`, `evidence.rs`, `lib.rs`.
- **Exact files to create:** `crates/reforge-discovery/src/coordinator.rs`, `crates/reforge-discovery/src/evidence.rs`, and `crates/reforge-discovery/src/providers/mod.rs`.
- **Exact files to modify:** `crates/reforge-discovery/src/lib.rs`.
- **Types/interfaces involved:** DiscoveryCoordinator, ScanPhase, ProgressEvent, CancellationToken, warning aggregation, adapter registry.
- **Exact algorithm:** Run bounded phases in deterministic adapter order; emit start/progress/end events; isolate adapter errors; stop promptly on cancellation; return inventory plus warnings.
- **Inputs/outputs:** Input: HostFacts, provider/harness registry, cancellation token. Output: Inventory, evidence, progress events, and warnings.
- **Integration points:** CLI and Tauri call the same coordinator; all later adapters register here.
- **Change:** phase scheduler, cancellation token, progress events, warning aggregation, deterministic adapter order.
- **Tests:** one adapter failure does not cancel others; cancellation exits promptly; repeated scan ordering is stable.
- **Failure/security:** errors are recorded with redaction; no silently dropped phase.
- **DoD:** CLI and Tauri can consume one `Inventory` result.

### T012 — Implement WinGet adapter

- **Goal:** discover and reinstall WinGet-owned/currently exportable apps.
- **Dependencies:** T011. This task also applies the approved minimal correction to the already-completed T002/T003 wire identity contracts documented below.
- **Files:** `crates/reforge-discovery/src/providers/winget.rs`, captured WinGet fixtures, provider tests, and the approved canonical provider-source correction.
- **Exact files to create:** `crates/reforge-discovery/src/providers/winget.rs`, `crates/reforge-discovery/tests/winget.rs`, `tests/fixtures/providers/winget/export.json`, `tests/fixtures/providers/winget/list.txt`, and `tests/fixtures/providers/winget/invalid.json`.
- **Exact files to modify:** `Cargo.toml`, `crates/reforge-discovery/Cargo.toml`, `crates/reforge-platform-windows/src/process.rs`, `crates/reforge-discovery/src/providers/mod.rs`, `crates/reforge-discovery/src/coordinator.rs`, `crates/reforge-domain/src/model.rs`, `crates/reforge-domain/src/ids.rs`, `crates/reforge-domain/tests/model_roundtrip.rs`, generated schemas/TypeScript DTOs, and this specification. The process runner gains a non-executing built-in availability check so synchronous adapter detection does not bypass the trusted process boundary.
- **Types/interfaces involved:** WinGetAdapter, stable provider-source identity, package source name/identifier/URL, package ID/version, export parser, exact list verification query, PackageInstallPolicy, and InstallPackage descriptor.
- **Exact algorithm:** Resolve the built-in WinGet executable; run a bounded `export --include-versions` call into a private temporary file; parse the documented schema and bounded warnings; preserve source name/identifier/URL, package ID, and optional version. Do not parse localized `list` tables as structured discovery data. Verification uses a bounded exact `list --id <id> --exact --source <name>` query for installed identity plus the typed expected version retained for target-fact comparison. Emit an exact install descriptor only when source name, stable source identifier, and version are present; otherwise emit a manual action rather than falling back to latest.
- **Inputs/outputs:** Input: provider context, captured WinGet export JSON, and bounded list output/status. Output: package components, provenance, typed operations, verification descriptors, warnings, or provider parse/unavailable errors.
- **Integration points:** Discovery coordinator, dependency graph, selection, package writer, provider executor, and WinGet verification.
- **Change:** invoke the documented export path and exact list verification path with bounded output; parse export schema, sources, package IDs, optional versions, and warnings; emit typed install operations with explicit agreement/silent/reboot policy.
- **Tests:** valid export, unknown package warning, duplicate sources, missing version, non-zero exit, exact source/version plan, verification query.
- **Failure/security:** no localized list-table parsing; no latest-version substitution; no source display name in canonical identity; source/package agreements default to unaccepted, silent mode defaults off, reboot defaults denied, and no ignored security-hash failure is representable.
- **DoD:** a WinGet package survives scan -> package -> plan -> verify in fixtures.

### T013 — Implement Windows registration adapters

- **Goal:** normalize uninstall entries, App Paths, shortcuts, services, tasks, and feature observations.
- **Dependencies:** T007-T012.
- **Files:** `crates/reforge-platform-windows/src/shell_links.rs`, `services.rs`, `tasks.rs`, `features.rs`, discovery adapters.
- **Exact files to create:** `crates/reforge-platform-windows/src/shell_links.rs`, `crates/reforge-platform-windows/src/services.rs`, `crates/reforge-platform-windows/src/tasks.rs`, `crates/reforge-platform-windows/src/features.rs`, and `crates/reforge-discovery/src/providers/windows_registration.rs`.
- **Exact files to modify:** `crates/reforge-platform-windows/src/lib.rs` and `crates/reforge-discovery/src/providers/mod.rs`.
- **Types/interfaces involved:** ShellLinkObservation, ServiceObservation, ScheduledTaskObservation, FeatureObservation, WindowsRegistrationAdapter.
- **Exact algorithm:** Read registered state through COM/SCM/Task Scheduler/feature APIs; retain access errors and ownership; convert services/tasks/features to manual/system-state descriptors; never create or start target registrations automatically.
- **Inputs/outputs:** Input: Windows registration APIs. Output: normalized observations and manual-capability records.
- **Integration points:** Registry/package correlation, target facts, compatibility blockers, evidence scoring, and report/manual actions.
- **Change:** read-only COM/Win32 wrappers; feature probe through a fixed structured provider path; no arbitrary task/service restoration.
- **Tests:** missing shortcut target, service/task metadata, access denial, feature output parse, default association observation.
- **Failure/security:** services/tasks/features default to manual/system-state strategies.
- **DoD:** inventory shows registered state with confidence/evidence and no automatic destructive operation.

### T013a — Complete current-user AppX/MSIX and startup discovery

- **Goal:** cover the remaining Windows-registration discovery requirements without widening T013 or creating restore behavior.
- **Dependencies:** T007-T013.
- **Files:** `Cargo.toml`, `crates/reforge-domain/src/model.rs`, `crates/reforge-platform-windows/src/appx.rs`, `startup.rs`, `known_folders.rs`, `registry.rs`, `shell_links.rs`, `lib.rs`, `crates/reforge-discovery/src/providers/windows_registration.rs`, generated schemas, and `ui/src/lib/generated.ts`.
- **Exact files to create:** `crates/reforge-platform-windows/src/appx.rs` and `crates/reforge-platform-windows/src/startup.rs`.
- **Exact files to modify:** `REFORGE_IMPLEMENTATION_SPEC.md`, `Cargo.toml`, `crates/reforge-domain/src/model.rs`, `crates/reforge-platform-windows/src/known_folders.rs`, `crates/reforge-platform-windows/src/registry.rs`, `crates/reforge-platform-windows/src/shell_links.rs`, `crates/reforge-platform-windows/src/lib.rs`, `crates/reforge-discovery/src/providers/windows_registration.rs`, `schemas/inventory.schema.json`, `schemas/package-manifest.schema.json`, `schemas/snapshot-manifest.schema.json`, `schemas/restore-plan.schema.json`, `schemas/restore-report.schema.json`, and `ui/src/lib/generated.ts`.
- **Types/interfaces involved:** `KnownFolderToken::Startup`, `AppxPackageObservation`, `AppxPackageSnapshot`, `AppxAccessError`, `StartupEntryObservation`, `StartupEntrySnapshot`, `StartupAccessError`, `RegistryRoot::CurrentUserRun`, and `WindowsRegistrationAdapter`.
- **Exact algorithm:** Resolve the current-user Startup known folder through `SHGetKnownFolderPath`; enumerate current-user packages only with the documented `PackageManager::FindPackagesForUser` empty-user form, bounded manual WinRT iteration, and validated/redacted package-family, product, publisher, and display metadata; enumerate only HKCU `Run` values in both registry views without exposing their command text; inspect one startup-folder level without following reparse points, retaining `.lnk` observations through the existing Shell Link COM path and non-shortcut entries as metadata only. Map AppX to the existing `Application` model and startup state to existing `Configuration`/`Shell` models. All outputs receive manual user-state descriptors; no package, startup entry, command, task, service, registry key, or association is created, started, registered, or changed.
- **Inputs/outputs:** Input: current-user Windows Package Manager, Shell, and registry APIs plus the existing known-folder map. Output: bounded, redacted AppX/MSIX and startup observations with confidence/evidence and manual-capability records.
- **Integration points:** Windows-registration inventory, generic correlation inputs, evidence scoring, report/manual actions, canonical schema generation, and TypeScript DTO generation.
- **Change:** add only the required current-user AppX/MSIX and shell/startup read paths; add the Startup folder token because the existing shared path model cannot name the documented `FOLDERID_Startup` boundary.
- **Tests:** deterministic AppX metadata and property-failure normalization; Startup folder file/reparse/access behavior; HKCU Run mapping that never retains command text; checked-in schema and TypeScript regeneration. No host-dependent package-manager fixture test applies: a CLI scan smoke may validate the native APIs but asserts no host package data.
- **Failure/security:** API and per-entry access failures remain redacted warnings; empty user input is the only PackageManager user selector, so no SID is retained; no absolute install path, Run value, target command, secret-like value, or reparse traversal crosses the platform boundary; all observations are manual and non-destructive.
- **DoD:** inventory exposes current-user AppX/MSIX and shell/startup state with confidence/evidence, preserves redacted access failures, and produces no automatic destructive operation.

### T014 — Implement generic PATH/runtime/executable correlation

- **Goal:** discover unknown tools and correlate them without hallucinating sources.
- **Dependencies:** T008-T013, T013a.
- **Files:** `crates/reforge-discovery/src/generic.rs`.
- **Exact files to create:** `crates/reforge-discovery/src/generic.rs`.
- **Exact files to modify:** `crates/reforge-discovery/src/lib.rs` and `crates/reforge-discovery/src/providers/mod.rs`.
- **Types/interfaces involved:** ExecutableCandidate, LocalIdentity, PathEvidence, source-correlation decision.
- **Exact algorithm:** Enumerate only bounded PATH/registered/user-selected roots shallowly; skip reparse points; inspect PE metadata; correlate independent evidence; emit local identity and portable/manual option when source is unproven.
- **Inputs/outputs:** Input: bounded roots and platform observations. Output: unknown or correlated executable components with confidence/provenance.
- **Integration points:** Deduplication, recommendation, portable-binary selection, package content store, and target comparison.
- **Change:** bounded candidate roots, PE metadata, BLAKE3 main hash, PATH/shortcut/registry/package correlations, local identity fallback.
- **Tests:** same binary through PATH and shortcut deduplicates; same name/different publisher stays separate; GitHub is not inferred from name.
- **Failure/security:** unknown source becomes portable/manual, never automatic download.
- **DoD:** an arbitrary `foo.exe` appears as a useful, honestly labeled component.

### T015 — Implement Chocolatey and Scoop provider adapters

- **Goal:** add reviewed package-provider coverage.
- **Dependencies:** T011, T010, T014.
- **Files:** `crates/reforge-discovery/src/providers/chocolatey.rs`, `scoop.rs`, fixtures.
- **Exact files to create:** `crates/reforge-discovery/src/providers/chocolatey.rs`, `crates/reforge-discovery/src/providers/scoop.rs`, `crates/reforge-discovery/tests/chocolatey.rs`, `crates/reforge-discovery/tests/scoop.rs`, `tests/fixtures/providers/chocolatey/list.json`, and `tests/fixtures/providers/scoop/list.json`.
- **Exact files to modify:** `crates/reforge-discovery/src/providers/mod.rs`.
- **Types/interfaces involved:** ChocolateyAdapter, ScoopAdapter, package source/bucket metadata, typed provider operations.
- **Exact algorithm:** Use documented export/list forms; parse version/source/bucket data; retain custom-source risk; produce typed operations only when provider/source evidence is sufficient; otherwise manual.
- **Inputs/outputs:** Input: bounded provider export/list output. Output: package observations and partial/manual restore descriptors.
- **Integration points:** Discovery coordinator, provider matrix, graph, selection, and provider executor; not required for WinGet MVP acceptance.
- **Change:** parse documented export formats and produce typed package/install/verify operations; retain bucket/source metadata.
- **Tests:** versioned exports, custom bucket, malformed JSON/XML, provider missing, script-risk warning.
- **Failure/security:** no provider import is run without trust/approval; custom manifests become manual if source cannot be verified.
- **DoD:** provider matrix tests and one Windows smoke path pass.

### T016 — Implement JavaScript global tool adapters

- **Goal:** discover npm/pnpm/Yarn/Bun global packages and project package artifacts.
- **Dependencies:** T011, T010, T015.
- **Files:** `crates/reforge-discovery/src/providers/javascript.rs`, fixtures.
- **Exact files to create:** `crates/reforge-discovery/src/providers/javascript.rs`, `crates/reforge-discovery/tests/javascript.rs`, `tests/fixtures/providers/javascript/npm-global.json`, `tests/fixtures/providers/javascript/pnpm-global.json`, `tests/fixtures/providers/javascript/yarn-global.json`, and `tests/fixtures/providers/javascript/bun-global.json`.
- **Exact files to modify:** `crates/reforge-discovery/src/providers/mod.rs`.
- **Types/interfaces involved:** JavaScriptPackage, NodePackageManager, global/project scope, lockfile artifact.
- **Exact algorithm:** Probe npm/pnpm/Yarn/Bun through allowlisted executable names; parse structured global listings; separate project manifests/lockfiles; preserve lifecycle-risk metadata and exact manager/version.
- **Inputs/outputs:** Input: manager output and project roots selected by adapter. Output: global package nodes plus project data artifacts.
- **Integration points:** Node runtime dependency closure, MCP required packages, package selection, and typed install planning.
- **Change:** use structured list commands where documented; distinguish global packages from project manifests/lockfiles; preserve package manager/version/source.
- **Tests:** global JSON, nested dependency, scoped package, absent manager, project lockfile artifact, Yarn Classic versus modern uncertainty.
- **Failure/security:** no `postinstall` execution is hidden; lifecycle risk is shown.
- **DoD:** Node/pnpm/MCP package closure is represented in the graph.

### T017 — Implement Python/Rust/Go/.NET/PowerShell adapters

- **Goal:** cover developer runtimes and tools with honest provenance.
- **Dependencies:** T011, T010, T016.
- **Files:** `crates/reforge-discovery/src/providers/python.rs`, `rust.rs`, `go.rs`, `dotnet.rs`, `powershell.rs`, fixtures.
- **Exact files to create:** `crates/reforge-discovery/src/providers/python.rs`, `crates/reforge-discovery/src/providers/rust.rs`, `crates/reforge-discovery/src/providers/go.rs`, `crates/reforge-discovery/src/providers/dotnet.rs`, `crates/reforge-discovery/src/providers/powershell.rs`, `crates/reforge-discovery/tests/python.rs`, `crates/reforge-discovery/tests/rust.rs`, `crates/reforge-discovery/tests/go.rs`, `crates/reforge-discovery/tests/dotnet.rs`, `crates/reforge-discovery/tests/powershell.rs`, `tests/fixtures/providers/python/list.json`, `tests/fixtures/providers/rust/list.json`, `tests/fixtures/providers/go/list.json`, `tests/fixtures/providers/dotnet/list.json`, and `tests/fixtures/providers/powershell/list.json`.
- **Exact files to modify:** `crates/reforge-discovery/src/providers/mod.rs`.
- **Types/interfaces involved:** RuntimeAdapter, interpreter ABI facts, package/source provenance, module/toolchain records.
- **Exact algorithm:** Run only built-in structured probes; distinguish registry/source/git/path/editable installs; preserve unknown source; mark scripts/modules manual unless a reviewed typed recipe exists.
- **Inputs/outputs:** Input: runtime executable results and package-manager reports. Output: runtime/tool/package components with compatibility and provenance.
- **Integration points:** Runtime bootstrap, graph required-runtime edges, provider install executor, and verification.
- **Change:** structured pip/uv probes, Cargo/rustup list, Go env/debug metadata, dotnet tool list, PowerShell module list; mark source unknown when needed.
- **Tests:** interpreter ABI mismatch, editable package, Cargo git/path, missing Go source, module prerelease, provider parse failures.
- **Failure/security:** no source invention; script/module restore is manual unless an approved typed recipe exists.
- **DoD:** runtime dependencies can be included in a selected closure.

### T018 — Implement config artifact collector and tokenized paths

- **Goal:** collect adapter-approved config/data with path portability.
- **Dependencies:** T006, T009, T011.
- **Files:** `crates/reforge-discovery/src/artifacts.rs` and `crates/reforge-discovery/src/lib.rs`.
- **Exact files to create:** `crates/reforge-discovery/src/artifacts.rs`.
- **Exact files to modify:** `crates/reforge-discovery/src/lib.rs`.
- **Types/interfaces involved:** ArtifactRef, PathToken, ArtifactPolicy, lock/size/text-binary metadata.
- **Exact algorithm:** Resolve known-folder tokens; apply adapter allowlists; reject paths outside roots/reparse traversal; inspect size/lock/newline/content class; create artifact references without absolute source paths.
- **Inputs/outputs:** Input: component adapter and selected roots. Output: bounded ArtifactRef records and warnings/size estimates.
- **Integration points:** Every harness/browser/editor/config adapter, package content store, selection policy, and restore path resolver.
- **Change:** roots/token map, allowlisted relative paths, file metadata, lock result, data size, text/binary classification.
- **Tests:** username/drive tokenization, path outside allowlist, lock/permission warnings, newline declaration.
- **Failure/security:** arbitrary recursive AppData scan is prohibited; large/unknown data requires selection.
- **DoD:** selected components reference portable `ArtifactRef`s, not absolute source paths.

### T022 — Implement MCP parser/normalizer and secret references

- **Goal:** provide one semantic MCP model for all harnesses.
- **Dependencies:** T002-T004, T018.
- **Files:** `crates/reforge-discovery/src/harnesses/mcp.rs`, the canonical domain MCP types from T002, and fixtures.
- **Exact files to create:** `crates/reforge-discovery/src/harnesses/mod.rs`, `crates/reforge-discovery/src/harnesses/mcp.rs`, `crates/reforge-discovery/tests/harnesses/mcp.rs`, `tests/fixtures/harnesses/mcp/stdio.json`, `tests/fixtures/harnesses/mcp/http.json`, and `tests/fixtures/harnesses/mcp/invalid.json`.
- **Exact files to modify:** `Cargo.toml`, `crates/reforge-discovery/Cargo.toml`, `crates/reforge-discovery/src/lib.rs`, and the generated `Cargo.lock` dependency entries; T022 creates and owns the harness module declaration and MUST NOT modify domain model, generated schemas, or generated TypeScript. **Correction:** §7.1 requires the `toml` and `json5` parser libraries, but T001 left both absent from the direct discovery dependency set (`cargo metadata` reports only `serde_json`), Rust requires the parent `lib.rs` to declare the new module, and Cargo requires an explicit `[[test]]` target for the mandated nested test path; these are the minimum required corrections and do not change the architecture.
- **Types/interfaces involved:** McpServerSpec, McpTransport, McpArgument, McpEndpoint, McpWorkingDirectory, EnvBinding, SafeValueRef.
- **Exact algorithm:** Parse TOML/JSON/JSON5 into typed shapes; recognize supported transports; validate command/runtime/package references; classify every env/arg/endpoint/cwd value; replace secret-bearing literals with ID-only references; reject unknown transport.
- **Inputs/outputs:** Input: harness-specific MCP configuration. Output: normalized server components, safe copied config, secret references, or manual parse errors.
- **Integration points:** Codex/Claude/OpenCode adapters, selection closure, package writer, RegisterMcp operation, secret vault, and MCP verification.
- **Change:** parse TOML/JSON/JSON5 shapes, recognize stdio/HTTP transports, command/args/cwd/runtime/package/env bindings, replace secret values with references in copied config, and populate the T002 domain types without introducing aliases or alternate schemas.
- **Tests:** each transport, command with spaces, secret-bearing argument/endpoint, environment reference, raw secret field, unknown field, missing runtime/package, malformed config.
- **Failure/security:** raw secret never enters normal artifact bytes or logs; unknown transport becomes manual.
- **DoD:** Context7-style `CONTEXT7_API_KEY` is represented as a secret reference, not plaintext.

### T019 — Implement Codex adapter

- **Goal:** discover Codex config, profiles, instructions, hooks, agents, skills, MCP, and auth references.
- **Dependencies:** T016, T018, T022.
- **Files:** `crates/reforge-discovery/src/harnesses/codex.rs`, fixtures based on documented TOML examples.
- **Exact files to create:** `crates/reforge-discovery/src/harnesses/codex.rs`, `crates/reforge-discovery/tests/harnesses/codex.rs`, `tests/fixtures/harnesses/codex/config.toml`, `tests/fixtures/harnesses/codex/config-mcp.toml`, and `tests/fixtures/harnesses/codex/invalid.toml`.
- **Exact files to modify:** `crates/reforge-discovery/src/harnesses/mod.rs`.
- **Types/interfaces involved:** CodexAdapter, ConfigScope, trust scope, auth mode, profile, instruction/skill/agent/hook records.
- **Exact algorithm:** Resolve `$CODEX_HOME` only from the current environment/known home; parse documented TOML; preserve user/project scope and trust; pass MCP tables to the shared normalizer; record auth mode without reading credential values.
- **Inputs/outputs:** Input: documented Codex config files and environment. Output: harness/config/MCP/secret-reference components and manual reauth actions.
- **Integration points:** MCP normalizer, config artifact collector, dependency graph, selection closure, and AI restore handlers.
- **Change:** parse user/project config, preserve scope/trust, normalize MCP and instruction files, classify auth storage without copying by default.
- **Tests:** `$CODEX_HOME`, profile, project trust, auth.json reference, keyring mode, MCP env reference, malformed TOML.
- **Failure/security:** project config never overrides machine-local policy silently; auth values are redacted.
- **DoD:** Codex setup produces install/runtime/config/secret-reference nodes.

### T020 — Implement Claude Code adapter

- **Goal:** discover Claude settings and extension structures.
- **Dependencies:** T018, T019, T022.
- **Files:** `crates/reforge-discovery/src/harnesses/claude.rs`, fixtures.
- **Exact files to create:** `crates/reforge-discovery/src/harnesses/claude.rs`, `crates/reforge-discovery/tests/harnesses/claude.rs`, `tests/fixtures/harnesses/claude/settings.json`, `tests/fixtures/harnesses/claude/mcp.json`, and `tests/fixtures/harnesses/claude/invalid.json`.
- **Exact files to modify:** `crates/reforge-discovery/src/harnesses/mod.rs`.
- **Types/interfaces involved:** ClaudeCodeAdapter, scope/namespace, settings, MCP, plugin, skill, agent, and hook records.
- **Exact algorithm:** Parse only documented user/project settings and extension layouts; preserve scope/namespace; normalize MCP; store hook/plugin command metadata as untrusted data; never execute it.
- **Inputs/outputs:** Input: Claude settings, `.mcp.json`, and extension files. Output: inspectable configuration/artifact nodes with secret references/manual boundaries.
- **Integration points:** MCP normalizer, artifact collector, selection, restore handler, and trust/manual queue.
- **Change:** parse documented settings/MCP/plugin/skill/agent/hook layouts and scopes; namespace plugins.
- **Tests:** standalone versus plugin layout, `.mcp.json`, hooks, `bin`, project/local settings, secret redaction.
- **Failure/security:** hook/plugin commands are metadata/manual, never executed during restore.
- **DoD:** Claude Code config is inspectable and planable without session theft.

### T021 — Implement OpenCode adapter

- **Goal:** discover OpenCode configuration and `.opencode` state.
- **Dependencies:** T018, T020, T022.
- **Files:** `crates/reforge-discovery/src/harnesses/opencode.rs`, fixtures.
- **Exact files to create:** `crates/reforge-discovery/src/harnesses/opencode.rs`, `crates/reforge-discovery/tests/harnesses/opencode.rs`, `tests/fixtures/harnesses/opencode/config.jsonc`, `tests/fixtures/harnesses/opencode/managed.jsonc`, and `tests/fixtures/harnesses/opencode/invalid.jsonc`.
- **Exact files to modify:** `crates/reforge-discovery/src/harnesses/mod.rs`.
- **Types/interfaces involved:** OpenCodeAdapter, config precedence, managed ownership, JSONC parser result, interpolation reference.
- **Exact algorithm:** Resolve documented global/project/custom/managed paths and environment-selected config; parse JSONC without evaluating interpolation; record precedence and policy ownership; normalize MCP/plugin metadata.
- **Inputs/outputs:** Input: OpenCode files and environment references. Output: scoped configuration graph nodes and manual overwrite decisions.
- **Integration points:** MCP normalizer, target conflict engine, artifact collector, and AI restore handlers.
- **Change:** parse JSON/JSONC, environment-selected config directories, managed config, precedence, MCP/plugin/instructions/agents/commands.
- **Tests:** global/project/custom/managed precedence, JSONC comments/trailing commas, env interpolation remains symbolic, malformed config.
- **Failure/security:** managed files are marked policy-owned; no silent overwrite.
- **DoD:** OpenCode state appears with provenance and scope.

### T023 — Implement browser and VS Code adapters

- **Goal:** discover browsers/profiles and VS Code extensions/settings.
- **Dependencies:** T008, T018, T021, T022.
- **Files:** `crates/reforge-discovery/src/browsers/`, `crates/reforge-discovery/src/editors/vscode.rs`, and browser/editor fixtures.
- **Exact files to create:** `crates/reforge-discovery/src/browsers/mod.rs`, `crates/reforge-discovery/src/browsers/chromium.rs`, `crates/reforge-discovery/src/browsers/firefox.rs`, `crates/reforge-discovery/src/browsers/generic.rs`, `crates/reforge-discovery/src/editors/vscode.rs`, `crates/reforge-discovery/tests/browsers.rs`, `crates/reforge-discovery/tests/editors_vscode.rs`, `tests/fixtures/browsers/chromium/profile.json`, `tests/fixtures/browsers/firefox/profile.json`, and `tests/fixtures/editors/vscode/extensions.json`.
- **Exact files to modify:** `crates/reforge-discovery/src/lib.rs` and `crates/reforge-discovery/src/providers/mod.rs`.
- **Types/interfaces involved:** BrowserAdapter, BrowserProfile, VSCodeAdapter, extension identity/version, portability classes.
- **Exact algorithm:** Discover browsers from independent registration/process/profile evidence; query default associations without writing UserChoice; detect locks; enumerate VS Code extensions via documented CLI; classify bookmarks/config/extensions versus reauth data.
- **Inputs/outputs:** Input: Windows/browser/editor observations and bounded documented profile roots. Output: partial portability records, artifact refs, and manual sign-in/close actions.
- **Integration points:** Generic discovery, config collector, recommendation, browser/VS Code restore handlers, verification, and report.
- **Change:** registry/App Paths/shortcut detection, documented profile roots where known, process/lock checks, `code` CLI extension enumeration, partial portability classes.
- **Tests:** Chrome/Edge/Firefox fixture metadata, Thorium unknown-source classification, running-process lock, bookmarks/extension IDs, default association query.
- **Failure/security:** no cookies/logins/session copy; no protected UserChoice writes.
- **DoD:** browser/editor inventory explicitly separates portable, partial, and reauth state.

### T024 — Implement Docker adapter

- **Goal:** discover Docker contexts/images/volumes/credential-helper references.
- **Dependencies:** T010, T018, T023.
- **Files:** `crates/reforge-discovery/src/providers/docker.rs`, fixtures.
- **Exact files to create:** `crates/reforge-discovery/src/providers/docker.rs`, `crates/reforge-discovery/tests/docker.rs`, `tests/fixtures/providers/docker/contexts.json`, `tests/fixtures/providers/docker/images.json`, and `tests/fixtures/providers/docker/volumes.json`.
- **Exact files to modify:** `crates/reforge-discovery/src/providers/mod.rs`.
- **Types/interfaces involved:** DockerAdapter, DockerContext, DockerImage, DockerVolume, credential-helper reference.
- **Exact algorithm:** Probe Docker through allowlisted CLI; collect context/image/volume metadata and size; separate credentials; refuse mutable VM disk capture; mark large objects opt-in.
- **Inputs/outputs:** Input: Docker CLI results and selected data roots. Output: typed Docker components, size estimates, and manual/partial states.
- **Integration points:** Dependency graph, selection size policy, Docker restore handlers, compatibility, and verification.
- **Change:** typed CLI probes and size estimates; separate config, images, volumes, containers, and credentials.
- **Tests:** absent daemon, context export metadata, image/volume size, credential helper, running-volume warning.
- **Failure/security:** no active mutable VM disk copy; credentials remain references/manual.
- **DoD:** Docker selection can choose config-only versus large data explicitly.

### T025 — Implement WSL adapter

- **Goal:** discover WSL distributions/configuration and prerequisites.
- **Dependencies:** T006, T010, T018, T024.
- **Files:** `crates/reforge-discovery/src/providers/wsl.rs`, fixtures.
- **Exact files to create:** `crates/reforge-discovery/src/providers/wsl.rs`, `crates/reforge-discovery/tests/wsl.rs`, `tests/fixtures/providers/wsl/list.txt`, `tests/fixtures/providers/wsl/status.txt`, `tests/fixtures/providers/wsl/.wslconfig`, and `tests/fixtures/providers/wsl/wsl.conf`.
- **Exact files to modify:** `crates/reforge-discovery/src/providers/mod.rs`.
- **Types/interfaces involved:** WslDistribution, WslPrerequisite, WslConfigArtifact, export eligibility/state.
- **Exact algorithm:** Run allowlisted `wsl` listing; record distro/version/running state and Windows prerequisites; collect `.wslconfig`/`wsl.conf` via tokens; offer export only as explicit large artifact; do not infer Linux packages/IDs.
- **Inputs/outputs:** Input: WSL command output and config files. Output: WSL graph nodes, prerequisite edges, optional export artifact, or partial/manual state.
- **Integration points:** Compatibility engine, restore phase ordering, WSL handler, target verification, and size review.
- **Change:** parse `wsl --list --verbose` safely, capture `.wslconfig`/`wsl.conf` artifacts and export eligibility, feature dependencies.
- **Tests:** no WSL, multiple distros, stopped/running distro, export failure, config tokenization.
- **Failure/security:** Linux package state is not inferred; distribution export requires explicit large-data selection.
- **DoD:** WSL restore plan orders prerequisites before import.

### T026 — Implement graph deduplication and edge evidence

- **Goal:** merge observations into normalized components and typed edges.
- **Dependencies:** T011-T025.
- **Files:** `crates/reforge-discovery/src/dedup.rs`, `evidence.rs`.
- **Exact files to create:** `crates/reforge-discovery/src/dedup.rs` and `crates/reforge-discovery/tests/graph.rs`.
- **Exact files to modify:** `crates/reforge-discovery/src/evidence.rs` and `crates/reforge-discovery/src/lib.rs`.
- **Types/interfaces involved:** Inventory, ComponentGraph, evidence groups, confidence algorithm, edge merge/conflict records.
- **Exact algorithm:** Group observations by identity priority; preserve conflicting publisher/source facts; merge only agreeing evidence; compute capped score and labels; retain cycles and optional edges deterministically.
- **Inputs/outputs:** Input: adapter observations and typed edges. Output: normalized graph, evidence index, conflicts, and confidence explanations.
- **Integration points:** Recommendation, selection closure, package manifest, target scanner, planner, reports, and all adapter outputs.
- **Change:** identity matching, evidence grouping, confidence algorithm, conflict preservation, cycle-safe graph.
- **Tests:** package+registry+executable merge, conflicting publisher, dependency cycle, optional edge, repeated scan stability.
- **Failure/security:** no low-confidence observation upgrades to fact without evidence.
- **DoD:** inventory is a graph with explainable confidence.

### T027 — Implement recommendation scorer

- **Goal:** generate automatic recommended selection.
- **Dependencies:** T026.
- **Files:** `crates/reforge-domain/src/selection.rs`, `crates/reforge-discovery/src/recommend.rs`.
- **Exact files to create:** `crates/reforge-discovery/src/recommend.rs`, `crates/reforge-domain/src/selection.rs`, and `crates/reforge-domain/tests/selection.rs`.
- **Exact files to modify:** `crates/reforge-domain/src/lib.rs`.
- **Types/interfaces involved:** RecommendationScore, ExplanationChip, SelectionMetadata.
- **Exact algorithm:** Apply the fixed score/penalty table; add required-dependency promotion; subtract machine-bound/large/manual risk; sort stably by score/category/ComponentId; never authorize sensitive state.
- **Inputs/outputs:** Input: normalized ComponentGraph. Output: deterministic recommended selection with explanation records.
- **Integration points:** UI/CLI scan results, manual selection, package review, and selection closure.
- **Change:** implement section 15 score and explanation records; keep secrets/large data opt-in.
- **Tests:** score boundaries, penalties, required dependency promotion, stable ordering, explanation completeness.
- **Failure/security:** recommendation never authorizes a secret or destructive operation.
- **DoD:** UI/CLI can show why each item is recommended.

### T028 — Implement selection closure and policy validation

- **Goal:** make manual selection dependency-safe.
- **Dependencies:** T026-T027.
- **Files:** `crates/reforge-domain/src/selection.rs`, `crates/reforge-restore/src/target.rs` if shared.
- **Exact files to create:** `crates/reforge-domain/tests/selection_policy.rs`.
- **Exact files to modify:** `crates/reforge-domain/src/selection.rs`.
- **Types/interfaces involved:** SelectionInput, SelectionClosure, ArtifactSelection, SelectionPolicy, SELECTION_INCOMPLETE.
- **Exact algorithm:** Start with user-selected components; recursively add required edges; expose optional edges; require explicit secret/size/unknown-binary policy; reject unresolved required closure; freeze the accepted selection.
- **Inputs/outputs:** Input: inventory graph and user policy. Output: immutable package selection or coded incomplete/size/trust warning.
- **Integration points:** Package writer, CLI secret-selection, GUI selection review, planner, and manifest provenance.
- **Change:** required closure, optional dependencies, per-artifact selection, secret/size policy, incomplete-selection errors.
- **Tests:** required dependency auto-add, unchecking required dependency, unknown binary opt-in, size confirmation, secret default exclusion.
- **Failure/security:** package creation blocked for unresolved required closure.
- **DoD:** selection is an explicit immutable input to package creation.

### T029 — Implement canonical JSON serialization

- **Goal:** make manifests and object IDs reproducible.
- **Dependencies:** T002-T004.
- **Files:** `crates/reforge-package/src/canonical.rs`, canonical tests.
- **Exact files to create:** `crates/reforge-package/src/canonical.rs` and `crates/reforge-package/tests/canonical.rs`.
- **Exact files to modify:** `crates/reforge-package/src/lib.rs`.
- **Types/interfaces involved:** CanonicalJson, canonical bytes, stable array policy, ObjectId input encoding.
- **Exact algorithm:** Reject non-finite numbers; recursively sort object keys; normalize declared timestamps/path tokens; preserve semantic array order; serialize UTF-8 without BOM; hash exact resulting bytes.
- **Inputs/outputs:** Input: Serde values and package domain objects. Output: deterministic bytes and known BLAKE3 vectors.
- **Integration points:** Object store, manifest/graph/selection/operations/index writers, signature coverage, and incremental resolver.
- **Change:** sorted object keys, stable numbers/timestamps/path tokens, explicit array ordering rules.
- **Tests:** equivalent maps hash identically; array semantics preserved; NaN rejected; Unicode/path fixtures; known hash vectors.
- **Failure/security:** non-canonical input is rejected or normalized only by declared rule.
- **DoD:** package metadata hash is identical across machines for identical semantic input.

### T030 — Implement streaming content store and chunker

- **Goal:** store files by BLAKE3 object ID with 8 MiB chunks.
- **Dependencies:** T009, T029.
- **Files:** `crates/reforge-package/src/content_store.rs`, tests.
- **Exact files to create:** `crates/reforge-package/src/content_store.rs` and `crates/reforge-package/tests/content_store.rs`.
- **Exact files to modify:** `Cargo.toml`, `Cargo.lock`, `crates/reforge-package/Cargo.toml`, and `crates/reforge-package/src/lib.rs`.
- **Types/interfaces involved:** ObjectStore, ObjectId, FileManifest, ChunkRef, bounded stream writer.
- **Exact algorithm:** Read in bounded chunks; hash uncompressed bytes; emit exact 8 MiB chunks except final; zstd-compress each object; verify length/hash before atomic commit; deduplicate existing IDs.
- **Inputs/outputs:** Input: file/object readers and size policy. Output: object IDs, file manifests, compressed objects, and resumable commits.
- **Integration points:** Artifact collector, package writer, ZIP reader, incremental resolver, restore object access, and size reporting.
- **Change:** bounded streaming read/hash/zstd write, object deduplication, file manifest/chunk references, metadata preservation.
- **Tests:** empty/small/exact-boundary/large files, duplicate content, interrupted write, hash mismatch, size limit.
- **Failure/security:** object commit is atomic only after hash/length verification.
- **DoD:** multi-gigabyte fixture can be processed without unbounded memory growth.

### T031 — Implement ZIP64 package writer/reader

- **Goal:** create and inspect safe `.reforge` containers.
- **Dependencies:** T028-T030.
- **Files:** `crates/reforge-package/src/writer.rs`, `reader.rs`, schemas/fixtures.
- **Exact files to create:** `crates/reforge-package/src/writer.rs`, `crates/reforge-package/src/reader.rs`, and `crates/reforge-package/tests/package.rs`.
- **Exact files to modify:** `Cargo.toml`, `Cargo.lock`, `crates/reforge-package/Cargo.toml`, and `crates/reforge-package/src/lib.rs`.
- **Types/interfaces involved:** PackageManifest, PackageGraph, ObjectIndex, PackageReader/Writer, ZIP64 limits.
- **Exact algorithm:** Write canonical required entries and validated object frames; read central directory with count/size/ratio limits; reject unsafe names/duplicates; validate schema/index/object hashes before exposing restore inputs.
- **Inputs/outputs:** Input: immutable selection graph and ObjectStore or package path. Output: inspectable `.reforge` file or coded package-corrupt/untrusted error.
- **Integration points:** CLI inspect, signature verifier, planner trust gate, vault reader, content resolver, and restore executor.
- **Change:** write required entries, ZIP64, safe names, manifest/object index, zstd object frames; reader validates limits and paths.
- **Tests:** round-trip, ZIP64 boundary fixture, corrupt central directory, path traversal, duplicate entry, compression bomb ratio, missing object.
- **Failure/security:** reader never extracts outside a caller-provided safe root.
- **DoD:** inspect-only `PackageReader` validates and reports a package without restoring or executing anything; `reforge package inspect` wiring remains owned by T047.

### T032 — Implement age vault and recovery identity flow

- **Goal:** encrypt explicitly selected secret records.
- **Dependencies:** T004, T029-T031.
- **Files:** `crates/reforge-package/src/vault.rs`, package writer/reader, UI/CLI secret prompts, manifests, and tests.
- **Exact files to create:** `crates/reforge-package/src/vault.rs`, `crates/reforge-cli/src/secret_prompt.rs`, `crates/reforge-package/tests/vault.rs`, and `crates/reforge-cli/tests/secret_prompt.rs`.
- **Exact files to modify:** `Cargo.toml`, `Cargo.lock`, `crates/reforge-package/Cargo.toml`, `crates/reforge-cli/Cargo.toml`, `crates/reforge-package/src/lib.rs`, `crates/reforge-package/src/writer.rs`, `crates/reforge-package/src/reader.rs`, and `crates/reforge-cli/src/main.rs`.
- **Types/interfaces involved:** VaultDocument, SecretRecord, EncryptedVault, pending one-time recovery acknowledgement, age scrypt recipient/identity, age X25519 recipient/identity, zeroizing buffers, secret-source/selection contract.
- **Exact algorithm:** Require explicit per-secret selection; read only approved values through the adapter boundary; build and canonically serialize the in-memory vault; generate an ephemeral X25519 identity and encrypt the vault to its recipient; separately encrypt the identity with an age scrypt passphrase recipient; store both armored age v1 payloads in one canonical envelope; optionally reveal the identity once and block package publication until acknowledgement; zeroize plaintext; never put password/recovery data in argv, logs, or normal manifest.
- **Inputs/outputs:** Input: approved SecretReference IDs, user-entered passphrase, and optional recovery-identity request. Output: encrypted vault entry and, when requested, one-time recovery acknowledgement, or VaultRequired/VaultDecryptFailed.
- **Integration points:** Package writer/reader, manual action queue, adapter secure targets, CLI/UI prompts, and restore plan approval.
- **Change:** standard age v1 X25519 vault plus a separately scrypt-encrypted X25519 identity, in-memory canonical vault, zeroization, no CLI argument passwords.
- **Tests:** decrypt with passphrase, decrypt with recovery identity, wrong input, empty vault, redacted package inspect, no secret in logs.
- **Failure/security:** wrong passphrase never falls back to plaintext; no unencrypted recovery identity enters the package; scrypt and X25519 stanzas are never mixed in one age header.
- **DoD:** vault lifecycle is auditable and package metadata remains secret-free.

### T033 — Implement optional package signature verification

- **Goal:** support integrity/authorship hints without pretending embedded keys establish trust.
- **Dependencies:** T029-T032.
- **Files:** `crates/reforge-package/src/signature.rs`, package writer/reader, domain trust state, generated contracts, manifests, and tests.
- **Exact files to create:** `crates/reforge-package/src/signature.rs` and `crates/reforge-package/tests/signature.rs`.
- **Exact files to modify:** `Cargo.toml`, `Cargo.lock`, `crates/reforge-package/Cargo.toml`, `crates/reforge-package/src/lib.rs`, `crates/reforge-package/src/writer.rs`, `crates/reforge-package/src/reader.rs`, `crates/reforge-package/tests/package.rs`, `crates/reforge-package/tests/vault.rs`, `crates/reforge-domain/src/model.rs`, affected checked-in schemas, `ui/src/lib/generated.ts`, and this specification.
- **Types/interfaces involved:** Ed25519 signature metadata, domain-separated canonical coverage bytes, public-key fingerprint, signature trust input, trust-state transition, and planning trust gate.
- **Exact algorithm:** Sign the versioned, length-delimited canonical manifest and object-index coverage with Ed25519; write canonical metadata and the raw signature as the two signature entries; verify strictly after package/object integrity checks; label embedded keys as hints; match trusted state only against an explicit out-of-band fingerprint; distinguish invalid from unsigned; never permit an invalid signature to be approved.
- **Inputs/outputs:** Input: package canonical bytes and optional out-of-band fingerprint/trust decision. Output: unsigned, signature-invalid, signed-trusted, signed-untrusted, user-approved, or rejected state.
- **Integration points:** Package writer/reader, planner trust gate, later CLI inspect, later GUI trust UX, and release/security documentation.
- **Change:** Ed25519 signature over domain-separated canonical manifest + object-index coverage; public-key fingerprint; explicit trust decision input.
- **Tests:** valid/tampered manifest/tampered object index/wrong key/unsigned package; trust-required plan gate.
- **Failure/security:** embedded public key is untrusted by default; invalid signatures are inspectable as invalid but cannot cross the planning approval gate.
- **DoD:** the package inspection contract distinguishes unsigned, signed-untrusted, signed-trusted, and invalid for the CLI/UI tasks that consume it later.

### T034 — Implement incremental package object resolver

- **Goal:** enable future snapshot chains without a new format.
- **Dependencies:** T030-T033.
- **Files:** `crates/reforge-package/src/content_store.rs`, `reader.rs`.
- **Exact files to create:** `crates/reforge-package/tests/incremental.rs`.
- **Exact files to modify:** `crates/reforge-package/src/content_store.rs` and `crates/reforge-package/src/reader.rs`.
- **Types/interfaces involved:** PackageSetResolver, ordered package roots, object conflict result.
- **Exact algorithm:** Resolve requested ObjectId from ordered package roots; verify bytes at each root; reject conflicting same-ID content; support standalone package without a base.
- **Inputs/outputs:** Input: package set and requested object IDs. Output: verified object stream or missing/conflict error.
- **Integration points:** Future snapshot chain, direct transport, package reader, object store, and restore object access.
- **Change:** resolve object IDs across ordered package roots; detect conflicting same-ID bytes; allow standalone package.
- **Tests:** base+delta reuse, missing base object, conflicting object bytes, deterministic resolution.
- **Failure/security:** conflicting object IDs block restore.
- **DoD:** MVP writer remains standalone but resolver contract is present and tested.

### T035 — Implement target scanner and facts

- **Goal:** create a normalized current target inventory using the same discovery contracts.
- **Dependencies:** T011-T026, T031.
- **Files:** `crates/reforge-restore/src/target.rs`.
- **Exact files to create:** `crates/reforge-restore/src/target.rs` and `crates/reforge-restore/tests/target.rs`.
- **Exact files to modify:** `crates/reforge-restore/src/lib.rs`.
- **Types/interfaces involved:** TargetFacts, target Inventory, target fingerprint, current-user/path/provider facts.
- **Exact algorithm:** Run the same bounded discovery contracts on the target; exclude secrets/hardware/machine IDs from fingerprint; normalize facts for source comparison.
- **Inputs/outputs:** Input: current target host. Output: TargetFacts and stable comparison fingerprint.
- **Integration points:** Compatibility engine, diff/conflict engine, planner, executor preconditions, migration mode, and verification.
- **Change:** target scan wrapper, target fingerprint excluding portable machine identifiers, current user/path/provider facts.
- **Tests:** source/target same package, absent package, newer version, architecture mismatch, fingerprint stability.
- **Failure/security:** target fingerprint does not include secrets or hardware IDs.
- **DoD:** planner consumes target facts instead of raw filesystem guesses.

### T036 — Implement compatibility engine

- **Goal:** block impossible or unsafe plans before execution.
- **Dependencies:** T035, T002.
- **Files:** `crates/reforge-restore/src/compatibility.rs`.
- **Exact files to create:** `crates/reforge-restore/src/compatibility.rs` and `crates/reforge-restore/tests/compatibility.rs`.
- **Exact files to modify:** `crates/reforge-restore/src/lib.rs`.
- **Types/interfaces involved:** CompatibilityResult, Blocker, Confirmation, architecture/OS/provider/runtime facts.
- **Exact algorithm:** Compare required OS/architecture/disk/elevation/provider/runtime/WSL/Docker facts; classify unknown privileged cases as blocked/manual; keep warnings separate from blockers.
- **Inputs/outputs:** Input: package requirements and TargetFacts. Output: READY, REQUIRES_CONFIRMATION, or BLOCKED with coded reasons.
- **Integration points:** Planner gate, GUI/CLI plan preview, manual actions, restore journal, and final report.
- **Change:** OS/architecture/disk/elevation/provider/runtime/WSL/Docker checks and structured blockers.
- **Tests:** each conflict class, warning versus blocker, free-space margin, missing provider manual path.
- **Failure/security:** unknown compatibility is not treated as compatible for privileged or destructive work.
- **DoD:** plan clearly separates `BLOCKED`, `REQUIRES_CONFIRMATION`, and `READY`.

### T037 — Implement source/target diff and conflict engine

- **Goal:** produce safe merge decisions.
- **Dependencies:** T026, T035-T036.
- **Files:** `crates/reforge-restore/src/diff.rs`, `conflicts.rs`.
- **Exact files to create:** `crates/reforge-restore/src/diff.rs`, `crates/reforge-restore/src/conflicts.rs`, and `crates/reforge-restore/tests/conflicts.rs`.
- **Exact files to modify:** `crates/reforge-restore/src/lib.rs`.
- **Types/interfaces involved:** TargetDiff, ConflictKind, ConflictResolution, backup requirement.
- **Exact algorithm:** Compare identity/version/source/config/data/secret/PATH/port/dependency state; apply safe defaults; keep newer target state; require confirmation for collisions; never delete unrelated target data.
- **Inputs/outputs:** Input: PackageGraph and TargetFacts. Output: complete diff with resolution choices and blockers.
- **Integration points:** Planner operation generation, migration mode, backup hooks, manual queue, UI conflict review, and report.
- **Change:** version/source/config/data/secret/PATH/port/dependency conflicts and defaults from section 19.
- **Tests:** newer target skip, older target prompt, config backup/merge, secret collision, path dedupe, unrelated target preservation.
- **Failure/security:** no silent target deletion/overwrite.
- **DoD:** every nontrivial difference is represented in the plan/report.

### T038 — Implement restore DAG planner

- **Goal:** turn selected graph + target diff into ordered typed operations.
- **Dependencies:** T028, T034-T037.
- **Files:** `crates/reforge-restore/src/planner.rs`, `operations.rs`.
- **Exact files to create:** `crates/reforge-restore/src/planner.rs`, `crates/reforge-restore/src/operations.rs`, and `crates/reforge-restore/tests/planner.rs`.
- **Exact files to modify:** `crates/reforge-restore/src/lib.rs`.
- **Types/interfaces involved:** OperationKind, Operation, RestorePlan, precondition, idempotency key, topological ordering.
- **Exact algorithm:** Close selected graph; add prerequisite and verification operations; topologically sort with stable tie-break; detect cycles; derive idempotency keys; emit only allowlisted typed operations.
- **Inputs/outputs:** Input: selection, package trust result, TargetDiff, compatibility result. Output: schema-valid inspectable RestorePlan.
- **Integration points:** Journal, typed executor, provider handlers, file/config handlers, manual queue, Tauri/CLI plan preview.
- **Change:** phase ordering, topological sort, stable tie-break, cycle detection, operation preconditions/idempotency keys.
- **Tests:** dependency order, cycle block, independent operation order, required runtime before MCP, WSL prerequisite order.
- **Failure/security:** package operation fields cannot create arbitrary execution steps.
- **DoD:** planner output is schema-valid and inspectable without execution.

### T039 — Implement journal schema and single-writer repository

- **Goal:** persist runs/operations/events/manual actions durably.
- **Dependencies:** T004, T038.
- **Files:** `crates/reforge-restore/src/journal.rs`, migrations, tests.
- **Exact files to create:** `crates/reforge-restore/src/journal.rs`, `crates/reforge-restore/migrations/0001_initial.sql`, and `crates/reforge-restore/tests/journal.rs`.
- **Exact files to modify:** `crates/reforge-restore/src/lib.rs`.
- **Types/interfaces involved:** SQLite schema, RunStatus, ApprovalState, OperationState, event/manual-action rows, single-writer repository.
- **Exact algorithm:** Initialize SQLite with WAL/foreign keys/busy timeout; migrate atomically; serialize writes through one actor; flush operation boundaries; mark RUNNING operations INTERRUPTED on startup.
- **Inputs/outputs:** Input: RestorePlan and lifecycle events. Output: durable run/operation/event/manual state and journal errors.
- **Integration points:** Executor resume, CLI/Tauri get_run/report, reboot pause, cancellation, and verification history.
- **Change:** SQLite WAL schema, migrations, transactions, redacted JSON payloads, run lifecycle, and explicit `approval_state`/`approved_at` transition before execution.
- **Tests:** migration, concurrent readers, writer serialization, crash state, unique idempotency key, event ordering.
- **Failure/security:** journal corruption returns a blocking error; no secret values.
- **DoD:** a run can be inspected after process termination.

### T040 — Implement typed executor and resume logic

- **Goal:** execute only approved operations with idempotent recovery.
- **Dependencies:** T009-T010, T038-T039.
- **Files:** `crates/reforge-restore/src/executor.rs`, operation handlers.
- **Exact files to create:** `crates/reforge-restore/src/executor.rs` and `crates/reforge-restore/tests/executor.rs`.
- **Exact files to modify:** `crates/reforge-restore/src/lib.rs` and `crates/reforge-restore/src/operations.rs`.
- **Types/interfaces involved:** Executor, OperationHandler, idempotency/retry policy, CancellationToken, backup hook.
- **Exact algorithm:** Require approved journal state; recheck preconditions; skip already-satisfied operations; execute one operation at a time; persist state/result/evidence; block unsafe non-idempotent retry; recover interrupted operations conservatively.
- **Inputs/outputs:** Input: approved RestorePlan, journal, target observation, object/package access. Output: journaled operation results, pause/manual/cancel states, or coded failure.
- **Integration points:** All restore handlers, elevation helper, progress events, manual queue, reboot resume, and final verification.
- **Change:** require `approval_state=APPROVED` before execution, then perform precondition checks, operation state transitions, cancellation, retry policy, interruption recovery, and backup hooks.
- **Tests:** already satisfied skip, successful file operation, failed provider, interruption before/after commit, non-idempotent retry block, cancellation.
- **Failure/security:** no operation runs without journal approval and schema validation.
- **DoD:** resume rechecks target and never repeats a verified completed operation.

### T041 — Implement safe file/config/env restore handlers

- **Goal:** restore portable state with token resolution and merge policies.
- **Dependencies:** T009, T030, T037, T040.
- **Files:** `crates/reforge-restore/src/handlers/files.rs`, `config.rs`, `environment.rs`.
- **Exact files to create:** `crates/reforge-restore/src/handlers/files.rs`, `crates/reforge-restore/src/handlers/config.rs`, `crates/reforge-restore/src/handlers/environment.rs`, `crates/reforge-restore/src/handlers/mod.rs`, `crates/reforge-restore/tests/handlers_files.rs`, `crates/reforge-restore/tests/handlers_config.rs`, and `crates/reforge-restore/tests/handlers_environment.rs`.
- **Exact files to modify:** `crates/reforge-restore/src/lib.rs`.
- **Types/interfaces involved:** WriteFile, MergeJson, MergeToml, SetUserEnvironment, AppendUserPath handlers and merge policies.
- **Exact algorithm:** Resolve tokenized destinations; backup before write; temp-write/flush/validate/replace; parse and merge only supported config; dedupe PATH case-insensitively preserving target order; set only non-secret user env and broadcast changes.
- **Inputs/outputs:** Input: typed operation plus verified object and current target. Output: changed/skipped/backup/manual result with verification facts.
- **Integration points:** Executor, target diff, journaling, known-folder map, verification engine, and migration safety policy.
- **Change:** backup/temp/atomic writes, JSON/TOML merge, user PATH dedupe, non-secret env policy and broadcast.
- **Tests:** collision backup, malformed target config, target order preservation, environment scope, protected root rejection.
- **Failure/security:** secret env values default to manual; no registry hive replacement.
- **DoD:** migrate mode preserves target and records resulting verification facts.

### T042 — Implement provider install executor handlers

- **Goal:** execute provider install operations through the constrained process boundary.
- **Dependencies:** T010, T012, T015-T017, T040-T041.
- **Files:** provider `plan_install`/executor bridges.
- **Exact files to create:** `crates/reforge-restore/src/handlers/providers.rs` and `crates/reforge-restore/tests/handlers_providers.rs`.
- **Exact files to modify:** `crates/reforge-restore/src/handlers/mod.rs`, `crates/reforge-discovery/src/providers/winget.rs`, `crates/reforge-discovery/src/providers/chocolatey.rs`, `crates/reforge-discovery/src/providers/scoop.rs`, `crates/reforge-discovery/src/providers/javascript.rs`, `crates/reforge-discovery/src/providers/python.rs`, `crates/reforge-discovery/src/providers/rust.rs`, `crates/reforge-discovery/src/providers/go.rs`, `crates/reforge-discovery/src/providers/dotnet.rs`, and `crates/reforge-discovery/src/providers/powershell.rs`.
- **Types/interfaces involved:** EnsureProvider, InstallPackage, provider process bridge, source/version/hash policy.
- **Exact algorithm:** Validate provider/package ID/source/version against package and target observations; resolve built-in provider executable; pass explicit argv; enforce source/hash/agreement/silent/reboot policy; verify installed identity/version.
- **Inputs/outputs:** Input: typed provider operation and TargetFacts. Output: install/skip/reboot/manual/failure result with bounded output.
- **Integration points:** WinGet MVP path, reviewed provider adapters, executor, journal, compatibility, and report.
- **Change:** exact identity/source/version, explicit agreement/silent policy, bounded process output, provider verification.
- **Tests:** already-installed, exact install args, provider missing, non-zero exit, reboot return, malicious package ID characters.
- **Failure/security:** no shell; no latest fallback; no ignored installer hash failure.
- **DoD:** provider installs are visible, resumable, and verifiable.

### T043 — Implement WSL/Docker restore handlers

- **Goal:** restore selected subsystem objects in dependency order.
- **Dependencies:** T024-T025, T040-T042.
- **Files:** `crates/reforge-restore/src/handlers/wsl.rs`, `docker.rs`.
- **Exact files to create:** `crates/reforge-restore/src/handlers/wsl.rs`, `crates/reforge-restore/src/handlers/docker.rs`, `crates/reforge-restore/tests/handlers_wsl.rs`, and `crates/reforge-restore/tests/handlers_docker.rs`.
- **Exact files to modify:** `crates/reforge-restore/src/lib.rs` and `crates/reforge-restore/src/handlers/mod.rs`.
- **Types/interfaces involved:** ImportWsl, RestoreDockerImage, RestoreDockerVolume, context metadata, size/prerequisite checks.
- **Exact algorithm:** Check prerequisites and size before operation; invoke only typed allowlisted WSL/Docker operations; restore selected exports/images/volumes; never copy mutable VM disks or credential stores; verify IDs/state.
- **Inputs/outputs:** Input: selected subsystem artifact and TargetFacts. Output: verified, partial, manual, skipped, or failed subsystem result.
- **Integration points:** WSL/Docker discovery, compatibility, selection size confirmation, executor, and final verification.
- **Change:** typed import/image/volume/context operations, size checks, prerequisite/manual actions.
- **Tests:** missing prerequisite, large artifact, import failure, image/volume verify, credential helper remains manual.
- **Failure/security:** no active VM disk extraction; no credential restore by default.
- **DoD:** selected WSL/Docker state reports precise partial outcomes.

### T044 — Implement AI/editor/browser restore handlers

- **Goal:** restore portable config and reinstallation state for user-facing tools.
- **Dependencies:** T020-T023, T040-T043.
- **Files:** `crates/reforge-restore/src/handlers/harnesses.rs`, `vscode.rs`, `browsers.rs`.
- **Exact files to create:** `crates/reforge-restore/src/handlers/harnesses.rs`, `crates/reforge-restore/src/handlers/vscode.rs`, `crates/reforge-restore/src/handlers/browsers.rs`, `crates/reforge-restore/tests/handlers_harnesses.rs`, `crates/reforge-restore/tests/handlers_vscode.rs`, and `crates/reforge-restore/tests/handlers_browsers.rs`.
- **Exact files to modify:** `crates/reforge-restore/src/lib.rs`, `crates/reforge-restore/src/handlers/mod.rs`, and `crates/reforge-cli/src/main.rs`.
- **Implementation erratum (2026-08-31):** `OperationHandler::handles` is keyed only by `OperationKind`, while browser portable-subset recognition is destination-path-sensitive. The existing CLI registers generic `WriteFile`/`MergeJson` handlers; registering a browser handler beside them triggers the executor's multiple-handler security rejection, and omitting it bypasses browser quiescence and subset enforcement. **Minimal correction:** add `crates/reforge-cli/src/main.rs` to T044's exact files to modify and replace those two generic registrations with one browser-aware composition handler. The operation schema and generic handler contracts remain unchanged.
- **Types/interfaces involved:** RegisterMcp, InstallVsCodeExtension, browser/config handlers, ReauthRequired/manual actions.
- **Exact algorithm:** Restore tokenized safe config; register MCP from normalized values without raw secrets; install extensions only from explicit IDs/versions; restore documented browser subset after quiescence; create sign-in/manual actions for protected state.
- **Inputs/outputs:** Input: typed AI/editor/browser components, objects, target facts, and optional vault reference. Output: partial/verified/reauth/manual results.
- **Integration points:** MCP normalizer, package reader, executor, secret gate, browser/editor verification, UI/CLI manual queue.
- **Change:** config writes/merges, MCP registration without secret values, VS Code extension install, browser portable subset, reauth actions.
- **Tests:** locked browser, extension version, missing runtime, config secret reference, unsupported profile item, default-browser manual action.
- **Failure/security:** hooks/plugins/extensions never auto-execute from package content.
- **DoD:** AI development pack restores configuration and tells the user exactly what still requires sign-in.

### T045 — Implement manual action queue and secret restore gate

- **Goal:** represent and continue through user-required actions.
- **Dependencies:** T032, T040, T044.
- **Files:** `crates/reforge-restore/src/manual_actions.rs`, UI/CLI handlers.
- **Exact files to create:** `crates/reforge-restore/src/manual_actions.rs` and `crates/reforge-restore/tests/manual_actions.rs`.
- **Exact files to modify:** `crates/reforge-restore/src/lib.rs`.
- **Implementation erratum (2026-08-31):** Section 26 exposed no way to inspect or acknowledge a manual action, while §27.1 makes the current artifact CLI-only and this task's DoD requires users to resolve blockers without restarting a run. That control path was therefore technically unreachable. **Minimal correction:** add the two `action` commands above and allow this task to modify `crates/reforge-restore/src/executor.rs`, `crates/reforge-cli/src/main.rs`, and `crates/reforge-cli/tests/cli_smoke.rs` alongside its listed queue files. A non-`OpenManualAction` `WAITING_FOR_USER` outcome must persist a redacted, operation-attempt-scoped action; a pending action blocks retry, an acknowledged/completed action permits retry, and a skipped action skips the blocked operation. No package or journal schema change is required.
- **Identity correction (2026-08-31):** §23 makes `manual_actions.id` globally unique. The planner emitted identical semantic action IDs for distinct runs, and `SecretRestoreGate` emitted identical per-secret IDs; persisting a second run would violate the required primary key. **Minimal correction:** producer-generated action IDs MUST incorporate the `run_id` before journal persistence; externally constructed `ManualAction` IDs remain subject to §23's global-uniqueness contract. This task may modify `crates/reforge-restore/src/planner.rs` and its planner tests to apply that scoped identity.
- **Types/interfaces involved:** ManualAction, acknowledgement state, risk/instructions, secret restore gate.
- **Exact algorithm:** Create actions whenever source/provider/lock/reauth/trust/secret policy blocks automation; persist acknowledgement; continue independent operations; decrypt vault only at secure adapter boundary; never include secret value in text.
- **Inputs/outputs:** Input: planner/executor outcomes and user acknowledgement. Output: resumable manual queue and secure-target decision.
- **Integration points:** Executor, journal, CLI/Tauri action commands, secret vault, reauth and final report.
- **Change:** create/ack/skip/complete actions; decrypt vault only at operation boundary; adapter secure target policy.
- **Tests:** action persistence, independent continuation, wrong vault input, plaintext target warning, reauth completion.
- **Failure/security:** no secret value in action title/instruction/log.
- **DoD:** user can resolve manual blockers without restarting the run.

### T046 — Implement verification engine and final reports

- **Goal:** verify every selected item and produce truthful results.
- **Dependencies:** T008, T023-T025, T040-T045.
- **Files:** `crates/reforge-restore/src/verification.rs`, report schemas, CLI report.
- **Exact files to create:** `crates/reforge-restore/src/verification.rs`, `crates/reforge-cli/src/report.rs`, and `schemas/restore-report.schema.json`.
- **Exact files to modify:** `crates/reforge-restore/src/lib.rs` and `ui/src/lib/generated.ts`.
- **Report materialization correction (2026-08-31):** §23 intentionally persists only queue fields, so dynamically generated secret-target actions do not retain the plan-only component field. T045 scopes generated secret-target IDs by `run_id` to satisfy the global journal primary key; without decoding that exact generated ID, the CLI report drops the action's component association and cannot explicitly qualify the affected selected component. **Minimal correction:** allow T046 to modify `crates/reforge-cli/src/main.rs` to infer the component only from the exact current-run `manual-action:<run-id>:secret-target:<component-id>` shape; reject other runs and unrecognized IDs. Add a focused unit test. No journal schema or compatibility path is added.
- **Types/interfaces involved:** VerificationRule, VerificationEvidence, ReportStatus, RestoreReport and aggregation.
- **Exact algorithm:** Run one or more rules per selected component; record evidence; aggregate verified/partial/manual/unsupported/failed without hiding failures; mark missing evidence UNVERIFIED; redact report output.
- **Inputs/outputs:** Input: target state, journal results, selected components, and rules. Output: versioned report JSON and human-readable CLI report.
- **Integration points:** Executor completion, CLI/UI report screens, package verification, VM E2E, metrics, and diagnostics.
- **Change:** rule execution, partial/failed status aggregation, redacted JSON/HTML-free CLI report.
- **Tests:** each rule category, partial result, hidden failure rejection, report counts, redaction.
- **Failure/security:** zero selected components is not reported as success; missing verification is `UNVERIFIED`.
- **DoD:** final report proves or explicitly qualifies each selected component.

### T047 — Implement CLI command surface and smoke tests

- **Goal:** expose engine workflows without GUI.
- **Dependencies:** T011, T031, T038-T046.
- **Files:** `crates/reforge-cli/src/main.rs`, `tests/cli_smoke.rs`.
- **Exact files to create:** `crates/reforge-cli/tests/cli_smoke.rs`.
- **Exact files to modify:** `crates/reforge-cli/src/main.rs`.
- **Types/interfaces involved:** Clap command tree, JSON envelope, exit-code mapping, progress-to-stderr.
- **Exact algorithm:** Parse only declared options; dispatch to application service; print exactly one JSON document for `--json`; keep progress on stderr; map partial/manual/block/security/interrupted states to fixed exit codes.
- **Inputs/outputs:** Input: CLI argv and local package/journal. Output: stdout envelope, stderr progress, exit code, and no secret leakage.
- **Integration points:** Core application service, package reader, planner, executor, report, and CI smoke workflow.
- **Change:** clap subcommands, JSON envelope, stderr progress, exit codes from section 26, resume/report flows.
- **Tests:** help, invalid package, scan fixture, inspect-only, plan no-execute, restore/manual exit code, resume.
- **Failure/security:** no shell escape option; secrets never echoed.
- **DoD:** CLI can complete fixture workflow end to end.

### T048 — Implement Tauri command/event bridge and capabilities

- **Goal:** prepare a typed Tauri bridge without enabling desktop control in the current CLI-only release.
- **Dependencies:** T010, T047.
- **Files:** `src-tauri/src/commands.rs`, `events.rs`, `capabilities/main.json`, `tauri.conf.json`, `ui/src/lib/api.ts`, and `ui/src/lib/state.svelte.ts`.
- **Exact files to create:** `src-tauri/src/commands.rs` and `src-tauri/src/events.rs`.
- **Exact files to modify:** `src-tauri/src/lib.rs`, `src-tauri/capabilities/main.json`, `src-tauri/tauri.conf.json`, `ui/src/lib/api.ts`, and `ui/src/lib/state.svelte.ts`.
- **Release-profile correction (2026-08-31):** the original runtime-enabled goal and DoD contradicted §27.1, which requires this release to register neither engine commands nor native dialog plugins. **Minimal correction:** retain the typed bridge, event, validation, cancellation, and native-selection code for a future profile, but `run()` MUST NOT construct `AppState`, call `invoke_handler`, or initialize a dialog plugin; the current UI remains hard-locked to its informational notice. Because scan scope is not represented end to end, `start_scan` has an empty request and its existing UI caller sends `{}`.
- **Types/interfaces involved:** Typed Tauri command DTOs, event envelopes, cancellation handles, native dialog result.
- **Exact algorithm:** Deserialize only typed request DTOs and domain payloads; validate paths through native dialogs/domain validators; call application service; emit typed progress/report deltas; preserve the bridge unregistered and expose no native dialog capability in the current release.
- **Inputs/outputs:** Input: future UI invoke requests and native dialog selections. Output: typed response/event or coded backend error for the future bridge; the current shell is informational only.
- **Integration points:** Svelte UI source, same CLI/application service, Tauri capabilities, cancellation/journal, trust approval, and the current CLI-only release policy.
- **Change:** typed future invoke commands, progress event schema, cancellation, native dialogs, and minimum capability permissions; hard-lock the current runtime from command/plugin registration and remove the obsolete scan-scope field from bridge callers.
- **Tests:** command serialization, cancellation, permission inspection, malformed UI request rejection.
- **Failure/security:** frontend cannot choose an arbitrary operation or filesystem path outside a native dialog/validated root; the current release frontend cannot reach engine controls.
- **DoD:** future bridge code compiles and rejects malformed/unsafe input; the current shell registers no engine commands or dialog plugins and displays only its informational notice.
**Verification note (2026-08-31):** the desktop shell was launched against the local UI dev server. Its accessibility state reported the title `Reforge · CLI only` and web content `CLI-only mode · Reforge`; no engine-control surface was available. The automated browser relay was unavailable because its extension was not connected, so this desktop accessibility check is the executed runtime proof.


### T049 — Implement Svelte state and core screens

- **Contract correction (2026-08-31):** the original runtime DoD conflicted with Section 27.1, which requires the current desktop artifact to remain CLI-only, and with T048's hard lock against command and dialog-plugin registration. This task implements and tests the typed future desktop-profile source only. It MUST NOT alter the current release's CLI-only runtime.
- **Goal:** deliver the typed future-profile scan/select/package/restore/verify path while preserving the current CLI-only desktop shell.
- **Dependencies:** T002, T048.
- **Files:** `ui/src/lib/api.ts`, `ui/src/lib/state.svelte.ts`, `ui/src/routes/`, `ui/src/lib/components/`, and `ui/src/app.css`.
- **Exact files to create:** `ui/src/lib/api.ts`, `ui/src/lib/state.svelte.ts`, `ui/src/routes/Home.svelte`, `ui/src/routes/ScanProgress.svelte`, `ui/src/routes/ScanResults.svelte`, `ui/src/routes/Selection.svelte`, `ui/src/routes/PackageReview.svelte`, `ui/src/routes/TargetAnalysis.svelte`, `ui/src/routes/RestorePlan.svelte`, `ui/src/routes/RestoreProgress.svelte`, `ui/src/routes/Verification.svelte`, `ui/src/routes/Report.svelte`, `ui/src/lib/components/ComponentTree.svelte`, `ui/src/lib/components/ProgressSummary.svelte`, `ui/src/lib/components/ConflictList.svelte`, `ui/src/lib/components/ManualActionList.svelte`, and `ui/src/lib/components/TrustNotice.svelte`.
- **Exact files to modify:** `ui/src/main.ts` and `ui/src/app.css`.
- **Types/interfaces involved:** Generated DTO imports, Svelte 5 runes/context, screen state machine, future backend API calls.
- **Exact algorithm:** Model scan/package/target/plan/restore/report lifecycle as typed state; subscribe to events; render loading/empty/error/manual states; keep the backend authoritative and exclude secret values from state. Preserve the current artifact's informational-only branch.
- **Inputs/outputs:** Input: typed future Tauri responses/events. Output: interactive future-profile scan/select/package/restore/verify screens; the current desktop artifact remains informational-only.
- **Integration points:** Future Tauri bridge commands, generated types, progress/trust UX, keyboard/accessibility tests, and the CLI-only release gate.
- **Change:** use Svelte 5 runes/context; components consume typed DTOs; implement loading/error/empty/manual states without removing the CLI-only runtime gate.
- **Tests:** Vitest component tests for selection closure, progress, conflict display, report counts, keyboard activation.
- **Failure/security:** do not store secret values in reactive state; unknown DTOs show an error state; no UI source may enable an engine-control surface in the current desktop artifact.
- **DoD:** the future desktop flow is represented by typed, backend-authoritative source and passing component tests; the current desktop runtime remains CLI-only, registers no bridge commands or dialog plugins, and exposes no control that re-enables them.

### T050 — Implement progress, accessibility, and trust UX

- **Scope correction (2026-08-31):** Section 27 and this task's algorithm require a virtualized component list, a log drawer for scan and restore, and keyboard focus when a global future-profile error arrives. The original exact file lists excluded the `ComponentTree`, typed activity state, progress routes, and the testable error-alert integration required to meet those requirements. This minimal correction admits only those integration points; it does not enable the current CLI-only desktop runtime.
- **Goal:** make long-running and risky future-profile operations understandable.
- **Dependencies:** T049.
- **Files:** `ui/src/lib/components/Progress*`, `Trust*`, `ManualAction*`, `ErrorAlert.svelte`, `ComponentTree.svelte`, `ui/src/lib/api.ts`, `ui/src/lib/state.svelte.ts`, `ui/src/routes/ScanProgress.svelte`, `ui/src/routes/RestoreProgress.svelte`, `ui/src/App.svelte`, `app.css`, and UI tests.
- **Exact files to create:** `ui/src/lib/components/ErrorAlert.svelte`, `ui/tests/a11y.test.ts`, and `ui/src/test-setup.ts`.
- **Exact files to modify:** `ui/src/lib/components/ProgressSummary.svelte`, `ui/src/lib/components/ConflictList.svelte`, `ui/src/lib/components/ManualActionList.svelte`, `ui/src/lib/components/TrustNotice.svelte`, `ui/src/lib/components/ComponentTree.svelte`, `ui/src/lib/api.ts`, `ui/src/lib/state.svelte.ts`, `ui/src/routes/ScanProgress.svelte`, `ui/src/routes/RestoreProgress.svelte`, `ui/src/App.svelte`, `ui/src/app.css`, and `ui/vite.config.ts`.
- **Types/interfaces involved:** Progress lifecycle, TrustState, ManualActionView, typed redacted activity rows, focus management, accessible status semantics.
- **Exact algorithm:** Render explicit lifecycle and trust states; project the append-only typed event stream into redacted activity rows; render a disclosure-based log drawer for scan and restore; move focus after attention/error/manual prompts; expose labels/live regions; use text/icons plus color; virtualize large component lists without losing keyboard semantics.
- **Inputs/outputs:** Input: typed state fixtures for progress/trust/manual/conflict/activity events. Output: accessible, responsive UI states and deterministic component tests.
- **Integration points:** Core Svelte screens, future Tauri events, package trust state, journal/manual actions, virtualized inventory interaction, and desktop smoke.
- **Change:** lifecycle visualization, warnings, signature trust states, manual queue, focus management, no-color-only statuses, bounded virtual rows, and a redacted activity log; preserve the CLI-only current-release gate.
- **Tests:** keyboard traversal including a virtualized large list, focus after attention/error/manual events, screen-reader labels, paused/reboot/manual states, activity-log contents, and large-list rendering bounds.
- **Failure/security:** trust approval is explicit and cannot be hidden behind the primary button; activity rows retain no raw event payload or secret value.
- **DoD:** the future-profile UI meets the accessibility and honest-progress requirements in Sections 27 and 34, while the current desktop artifact remains CLI-only.

**T051 host compatibility correction (2026-09-03):** The current Hyper-V PowerShell module exposes no `Stop-VM -Shutdown` parameter; an elevated provisioning run failed at that command before creating its checkpoints. T051 test infrastructure MUST feature-detect the parameter and use the existing forced-off fallback when it is unavailable. This changes only disposable VM lifecycle control, not Reforge package or restore operations.

### T051 — Implement VM fixtures and source-to-target E2E harness

- **Goal:** verify behavior on real Windows rather than only fake fixtures.
- **Dependencies:** T047-T050.
- **Files:** `tests/vm/Provision.ps1`, `tests/vm/Run-E2E.ps1`, `tests/vm/README.md`, `tests/integration/windows_e2e.rs`.
- **Exact files to create:** `tests/vm/Provision.ps1`, `tests/vm/Run-E2E.ps1`, `tests/vm/README.md`, and `tests/integration/windows_e2e.rs`.
- **Exact files to modify:** none; VM harness is added after product paths exist.
- **Types/interfaces involved:** Hyper-V Generation 2 fixture image, source/target scenario, reset/report collector.
- **Exact algorithm:** Provision known packages and collisions; snapshot source; scan/package; reset clean target; restore/re-scan; run non-empty migration and reboot/lock cases; collect redacted final report; reset between cases.
- **Inputs/outputs:** Input: Windows 11 x64 VM prerequisites and test fixture parameters. Output: reproducible E2E report with no hidden failures.
- **Integration points:** CLI/application service, Tauri-independent engine, all adapters, planner/executor, report, and release CI.
- **Change:** Hyper-V Generation 2 local test procedure; provision known packages/config collisions; collect reports; reset target snapshot between cases.
- **Tests:** source scan/package, clean rebuild restore, non-empty migration, newer target preservation, locked file/manual path, reboot pause/resume.
- **Failure/security:** VM scripts are test infrastructure only and are not accepted as package operations.
- **DoD:** documented command sequence produces a verified final report with no hidden failures.

### T052 — Implement security/property/fuzz tests

- **Goal:** make package and restore boundaries fail closed.
- **Dependencies:** T029-T046.
- **Files:** `crates/reforge-package/tests/*`, `crates/reforge-restore/tests/*`, fuzz/property targets.
- **Exact files to create:** `crates/reforge-package/tests/security.rs`, `crates/reforge-restore/tests/security.rs`, `crates/reforge-package/fuzz/Cargo.toml`, `crates/reforge-package/fuzz/fuzz_targets/package.rs`, `crates/reforge-restore/fuzz/Cargo.toml`, and `crates/reforge-restore/fuzz/fuzz_targets/operations.rs`.
- **Exact files to modify:** none.
- **Types/interfaces involved:** canonical path/package/operation types, package trust state, redaction policy, property/fuzz inputs, and fail-closed error results.
- **Exact algorithm:** Generate arbitrary tokenized paths/canonical values/chunk boundaries; feed zip-slip/zip-bomb/hash/schema/cycle/reparse/shell-metacharacter cases; assert fail-closed results and zero secret leakage.
- **Inputs/outputs:** Input: generated and corpus fixtures. Output: regression tests that fail on unsafe extraction, raw secret emission, or unsafe operation creation.
- **Integration points:** Package reader/writer, canonical serializer, planner, executor, redaction, vault, and CI security gates.
- **Change:** property tests for tokenized paths/canonical JSON/chunk boundaries; malicious package corpus; command argument tests.
- **Tests:** zip-slip, zip bomb, duplicate IDs, object hash mismatch, reparse, secret leakage, malformed schemas, dependency cycle, shell metacharacters.
- **Failure/security:** any unsafe extraction or raw secret emission fails CI.
- **DoD:** security contract has automated regression coverage.

### T053 — Implement release packaging and updater verification

- **Goal:** produce signed desktop/CLI artifacts reproducibly.
- **Dependencies:** T001, T048-T052.
- **Files:** `.github/workflows/ci.yml`, `.github/workflows/windows-e2e.yml`, `.github/workflows/release.yml`, `src-tauri/tauri.conf.json`, `src-tauri/capabilities/main.json`.
- **Exact files to create:** `.github/workflows/release.yml` and `.github/workflows/windows-e2e.yml`.
- **Exact files to modify:** `.github/workflows/ci.yml`, `src-tauri/tauri.conf.json`, and `src-tauri/capabilities/main.json`.
- **Types/interfaces involved:** Release matrix, Tauri updater signature configuration, artifact hashes, SBOM/license/security report.
- **Exact algorithm:** Build with locked Rust/pnpm dependencies; produce x64 artifacts; verify updater signatures and wrong-architecture rejection; generate hashes/SBOM; keep signing secrets in CI secret storage; publish only after tests.
- **Inputs/outputs:** Input: tagged commit and protected signing credentials. Output: inspectable signed desktop/CLI artifacts and release metadata.
- **Integration points:** CI, VM E2E, Tauri updater, package security review, and CLI-only distribution.
- **Change:** Windows build matrix, locked dependencies, Tauri updater signature verification, artifact hashes, license/security reports.
- **Tests:** update with invalid signature, valid signature, wrong architecture, CLI-only distribution.
- **Failure/security:** unsigned update is rejected; secrets are CI-protected.
- **DoD:** release workflow produces inspectable signed artifacts and a software bill of materials.

### T054 — Complete documentation and adapter source ledger

- **Goal:** keep implementation decisions and evidence maintainable.
- **Dependencies:** T006-T053, T013a.
- **Files:** `README.md`, `docs/support-matrix.md`, `docs/recovery.md`, `docs/security.md`, `docs/sources.md`, `REFORGE_IMPLEMENTATION_SPEC.md`.
- **Exact files to create:** `README.md`, `docs/support-matrix.md`, `docs/recovery.md`, `docs/security.md`, and `docs/sources.md`.
- **Exact files to modify:** `REFORGE_IMPLEMENTATION_SPEC.md`.
- **Types/interfaces involved:** Support matrix, recovery procedure, threat model, source ledger, adapter status.
- **Exact algorithm:** Copy only verified behavior and source URLs; document partial/manual/unsupported states and recovery; run link/check examples; update this specification when an implementation decision changes.
- **Inputs/outputs:** Input: implemented adapters, tests, and source index. Output: maintainer/user documentation that makes no unsupported credential/browser promise.
- **Integration points:** Release workflow, issue triage, adapter maintenance, VM procedure, and future contributor onboarding.
- **Change:** document supported/partial/unsupported matrix, provider source URLs, recovery procedure, privacy/security model, VM test procedure.
- **Tests:** links/checks in CI; examples use only documented commands.
- **Failure/security:** no documentation promises unsupported credential/browser behavior.
- **DoD:** a new implementer can follow the task order without inventing architecture.

## 36. Dependency order summary

```text
T001 -> T002 -> T003 -> T004 -> T005 -> T006 -> T007 -> T008
 -> T009 -> T010 -> T011 -> T012 -> T013 -> T013a -> T014 -> T015 -> T016
 -> T017 -> T018 -> T022 -> T019 -> T020 -> T021 -> T023 -> T024
 -> T025 -> T026 -> T027 -> T028 -> T029 -> T030 -> T031 -> T032
 -> T033 -> T034 -> T035 -> T036 -> T037 -> T038 -> T039 -> T040
 -> T041 -> T042 -> T043 -> T044 -> T045 -> T046 -> T047 -> T048
 -> T049 -> T050 -> T051 -> T052 -> T053 -> T054
```

Task IDs are stable identifiers, not execution order; follow the sequence above. This is a conservative topological order: tasks MAY run in parallel only after their dependencies complete and their exact file sets do not overlap. Shared domain/schema changes must land before adapter implementation. Do not let two branches create competing models for components, operations, errors, or package metadata.

## 37. Success metrics

Measure against a fixed fixture corpus and VM scenarios:

- percentage of selected components with a confirmed/high identity;
- percentage of selected components with a reproducible restore strategy;
- percentage verified after restore;
- number and category of manual actions;
- unsupported/partial/failed counts, never hidden;
- package size and scan/restore time by artifact category;
- crash/reboot resume correctness;
- false source-attribution rate;
- secret leakage count (must remain zero in tests and diagnostics);
- target data loss count (must remain zero in MVP tests).

Do not report “100% clone.” Report `verified`, `partial`, `manual`, `unsupported`, and `failed` counts.

## 38. Hard limitations to expose in product copy

- Windows credentials, DPAPI-protected data, browser cookies/logins, OAuth sessions, and app-bound secrets generally require reauthentication.
- A package cannot safely prove a random executable's original download source from its filename.
- A package manager may no longer offer the recorded version or source.
- Installers, extensions, PowerShell modules, hooks, and plugins are executable supply-chain inputs and may require review or interaction.
- Default apps and some system state are user/policy-controlled and cannot be safely set by registry copying.
- WSL and Docker data can be very large and platform/version sensitive.
- Running applications and SQLite/WAL/reparse files may not be safely capturable without quiescence.
- ACLs, SIDs, hostnames, hardware identifiers, drivers, licenses, and machine-bound state are not portable user configuration.
- An unsigned package's hashes detect corruption only; they do not establish author trust.

## 39. Source index

Every externally dependent claim is tied to one row below. Each row records the source label, exact URL, research access date, software/version scope, and the fact used by Reforge. `UNVERIFIED` in the version column means that the source page does not pin a version; implementation must record the observed version in the adapter fixture or source ledger before relying on version-specific behavior.

### Windows platform

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

### WSL, Docker, and SSH

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

### Browsers and VS Code

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

### AI harnesses

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

### Package managers, cryptography, formats, and domain tooling

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
| [async-trait Rust crate](https://docs.rs/async-trait/latest/async_trait/) | `https://docs.rs/async-trait/latest/async_trait/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Define dynamic async provider/adapter interfaces where object safety requires it. |
| [thiserror Rust crate](https://docs.rs/thiserror/latest/thiserror/) | `https://docs.rs/thiserror/latest/thiserror/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Derive typed Rust error sources that map to stable Reforge error codes. |

### Technology evidence

| Source | URL | Date accessed | Software version | Fact used by Reforge |
|---|---|---|---|---|
| [Tauri architecture](https://v2.tauri.app/concept/architecture/) | `https://v2.tauri.app/concept/architecture/` | 2026-08-29 | Tauri 2 | Keep the Rust engine authoritative behind a narrow desktop command boundary. |
| [Tauri capabilities](https://v2.tauri.app/security/capabilities/) | `https://v2.tauri.app/security/capabilities/` | 2026-08-29 | Tauri 2 | Scope capabilities per window and do not grant broad filesystem or shell access. |
| [Tauri updater signing](https://v2.tauri.app/plugin/updater/) | `https://v2.tauri.app/plugin/updater/` | 2026-08-29 | Tauri 2 | Verify signed update artifacts before installation and keep signing keys outside packages. |
| [Svelte 5 state/context guidance](https://svelte.dev/docs/svelte) | `https://svelte.dev/docs/svelte` | 2026-08-29 | Svelte 5 | Use typed UI state/context without moving business rules into the frontend. |
| [Rust standard library](https://doc.rust-lang.org/std/) | `https://doc.rust-lang.org/std/` | 2026-08-29 | Stable/current; exact toolchain UNVERIFIED | Prefer standard memory-safe, streaming, and filesystem primitives before bespoke utilities. |
| [Tokio process](https://docs.rs/tokio/latest/tokio/process/index.html) | `https://docs.rs/tokio/latest/tokio/process/index.html` | 2026-08-29 | latest docs; exact version UNVERIFIED | Run bounded provider processes without shell interpolation and with cancellation/output limits. |
| [Clap](https://docs.rs/clap/latest/clap/) | `https://docs.rs/clap/latest/clap/` | 2026-08-29 | latest docs; exact version UNVERIFIED | Define a stable typed CLI command tree and JSON envelope. |

## 40. Final implementation rule

The weaker coding model should work task by task:

```text
read the task -> inspect cited files/patterns -> implement the specified contract
-> add the listed behavior tests -> run the task-level checks
-> verify Definition of Done -> mark the task complete -> continue in dependency order
```

It MUST NOT:

- invent a second package format or operation model;
- add arbitrary command/script execution to make a scenario pass;
- copy credentials/cookies because a file exists;
- treat low-confidence correlations as facts;
- silently drop unsupported items;
- erase target state in migration mode;
- claim successful restore without verification evidence;
- skip source/provenance recording for a provider;
- replace age, BLAKE3, ZIP64, SQLite journal, or the typed Tauri boundary with ad-hoc alternatives.
