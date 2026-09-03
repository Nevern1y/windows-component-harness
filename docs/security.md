# Security model

Reforge treats the source machine, package, provider output, target filesystem, and restore operations as separate trust boundaries. The default posture is local-first, least privilege, fail closed, and honest reporting. A package can be structurally valid while still being untrusted for restore.

## Threats and controls

| Threat | Required control in the current implementation |
|---|---|
| Tampered or malicious package | Inspect ZIP central directory and required entries before trusting metadata; validate schemas, canonical bytes, derived operations/sources, object lengths, BLAKE3 IDs, and configured archive/count/ratio limits. Require explicit trust approval before plan/restore. |
| ZIP slip, ZIP bomb, or oversized object | Reject absolute, drive-prefixed, parent, NUL, unsafe, or reparse-like names; preflight central-directory bounds; enforce archive, entry, metadata, object, and decompression limits; validate zstd frames before use. |
| Path traversal or reparse traversal | Use domain `PathToken` plus platform `SafePath`; allow only validated known-folder tokens and relative paths; reject `..`, protected roots, symlinks/reparse points, case-insensitive collisions, and changed path components at the final write check. |
| Command injection | Provider/restore operations use typed operation kinds and reviewed `TrustedExecutable` identities with argument vectors. Package text cannot become a shell command, `cmd /c`, PowerShell script, elevation argument, or executable path. |
| Malicious installer, extension, module, hook, skill, or plugin | Keep source/provenance and trust visible; classify executable supply-chain inputs as manual/reviewed boundaries; never execute hook/plugin/skill/agent metadata during restore. |
| Privilege escalation | Normal control runs unelevated. System state is manual or requires a typed elevation boundary; the elevation protocol accepts run/operation identities and a nonce, not package paths or command text. |
| Secret exposure | Classify values as literals, environment references, secret references, or redacted unknowns. Normal manifests, package metadata, logs, UI state, journal rows, and reports contain IDs/labels or redacted values, never raw secret bytes. |
| Browser/account-session theft | Do not copy Windows credentials, DPAPI data, browser cookies/logins, OAuth sessions, or application-bound tokens. Report reauthentication/manual actions instead. |
| Diagnostic/log leakage | Bound and redact provider stdout/stderr and technical details before crossing a display/report boundary. If redaction cannot prove safety, discard the detail. |
| Interrupted non-idempotent restore | Journal operation state transitions in SQLite WAL; mark abandoned `RUNNING` work as `INTERRUPTED`; recheck package digests, approval, preconditions, and satisfaction before resume; never blindly retry non-idempotent operations. |
| Accidental target deletion | Back up before supported file/config replacement, use atomic same-directory replacement, preserve target data in migration, and expose no delete operation in MVP. |
| Dependency/supply-chain compromise | Keep Cargo/pnpm lockfiles committed; run license, advisory, SBOM, lint, format, and test gates in CI; use signed release/update artifacts when protected release credentials are present. |

## Package trust lifecycle

1. **Untrusted input:** a `.reforge` path is just a file supplied by a user or another source.
2. **Integrity inspection:** the reader verifies container structure, bounded metadata, canonical documents, derived operation/source records, object index, object content, and optional signature metadata.
3. **Trust decision:** unsigned packages remain inspectable but require explicit user approval. A signature can establish integrity/authorship only when the signer key is trusted out of band; signature validity alone is not package safety.
4. **Plan gate:** planning requires an approved trust decision and evaluates OS/architecture, target facts, compatibility, selection closure, conflicts, and manual actions.
5. **Restore gate:** `reforge restore` additionally requires `--yes-safe`, journals approval, rechecks the package, and executes only typed operations accepted by handlers.

Package source URLs are evidence and plan inputs. Reforge does not download a URL merely because it is present in a package. Provider network access is visible through the typed provider operation and remains subject to source, version, agreement, installer, and verification policy.

## Paths and files

### Tokenized paths

Portable package metadata never uses an arbitrary absolute host path as a destination. A path is represented by an allowlisted known-folder token plus a validated relative path. The domain and Windows boundary reject:

- absolute, UNC, drive-letter, device, stream, or NUL-containing forms;
- `..` segments and unsafe aliases;
- symlink/reparse traversal;
- final destinations that are not regular files where a file is required;
- protected Windows, Program Files, registry-hive, and protected default-association roots for generic writes.

Known-folder roots are resolved on the target through Windows APIs. A source path is not expanded into the source user's profile on another machine.

### Atomic replacement

For supported file/config operations, Reforge reads and validates the source object, writes a same-directory temporary file, flushes and hashes it, checks the destination again, and atomically creates or replaces the destination. Existing destinations are retained under a generated sibling backup name and the backup metadata is journaled. Temporary files are removed on pre-commit failure. Migration does not erase unknown target data.

### Configuration merges

JSON/JSONC/TOML input is parsed before merge. Only the declared merge policy applies. Unknown target keys are preserved where the policy says so; a collision that cannot be decided safely becomes a manual action. A malformed or secret-bearing configuration does not become a raw file copy.

## Process and provider boundary

The process runner resolves only built-in provider/runtime executable identities and passes an argument vector. It bounds timeout and output, supports cancellation, omits secrets from the child environment, and redacts captured output before persistence. Provider output is not a command source.

Provider operations retain exact package ID/source/version inputs. Reforge does not substitute the latest version, parse localized human tables as authoritative identity, or execute arbitrary installer commands embedded in package data. Provider scripts, lifecycle hooks, PowerShell modules, extensions, plugins, and unknown binaries are supply-chain inputs; their risk is visible in the plan/report.

The elevation helper boundary is separate from normal UI/CLI execution. Its protocol is versioned, bounded, nonce-bound, and identity-based. It rejects unknown fields and does not accept a package path, command line, argument vector, or environment values as an elevation request. If a reviewed elevation path is unavailable, the operation becomes manual.

## Secrets and account-bound state

The normal package contains secret references and redacted metadata only. The package library's vault boundary uses standard age v1 and `zeroize`; it does not use custom cryptography or a custom password KDF. The specified nested age design keeps the vault and passphrase-protected recovery identity in separate standard age payloads.

The current CLI does not expose secure adapter value collection. Therefore:

- default selection uses `secrets: EXCLUDE`;
- selecting secret content for ordinary object storage returns `VAULT_REQUIRED`;
- a non-empty `--secret-selection` is rejected rather than interpreted as “copy all secrets”;
- no password, API key, bearer token, private key content, or decrypted vault value is accepted as a CLI argument;
- plain environment variables and plaintext config targets remain manual unless an adapter proves a secure target policy.

Do not use a user profile, browser profile, cloud account, production credential, or real authentication database as a fixture. Browser bookmarks/configuration may be a portable or partial subset when an adapter is actually wired into the release; cookies, logins, session tokens, OAuth state, and app-bound encryption remain reauthentication/manual.

MCP data follows the same rule. A public endpoint must be HTTP(S) without username, password, query, or fragment data. Environment bindings and secret-bearing arguments/endpoints become symbolic references or `RedactedUnknown`; raw secret literals never enter normal artifact bytes.

## Windows state and privilege

Discovery may observe registry views, AppX/MSIX, startup, Shell Links, services, scheduled tasks, optional features, environment scopes, and default associations. Observation is not permission to mutate:

- current-user non-secret environment values have a narrow HKCU handler and broadcast verification;
- system environment values are report/manual inputs;
- services, tasks, features, startup command text, and protected default-app choices do not receive arbitrary automatic writes;
- default browser selection uses supported observation/UI boundaries and never guesses a protected `UserChoice` hash;
- the normal application is not run fully elevated.

## Journal, reports, and privacy

The SQLite journal is local application state, not package content. It stores typed operation identities, bounded redacted inputs/results/errors, backups, lifecycle events, and manual-action state. WAL mode and a single writer make state transitions durable. On startup, in-flight work is marked interrupted and must be rechecked before resume.

Verification is fail-closed: every selected component gets a report entry, missing definitions are reported as failures, and a terminal operation failure outranks a matching target observation. Report values are redacted before being returned or written. Reports must not contain raw source profile paths, secret-like values, browser session data, or unredacted provider output.

Reforge has no telemetry or remote inventory. The local CLI may invoke a selected provider's documented command, and the user can see that source/provider operation in the plan. The package reader never executes package metadata.

## Release and supply chain

Source is Apache-2.0. Rust and frontend lockfiles are committed. CI checks formatting, UI generation/check/build, Rust build/lint/tests, dependency advisories, license metadata, and SBOM generation. Release packaging uses protected Tauri signing credentials, verifies valid and mutated signatures independently, rejects wrong-architecture updater entries, hashes supplemental artifacts, and publishes only after verification. Signing keys are not stored in packages or the repository.

The checked-in Tauri configuration has updater artifacts disabled for the CLI-only local build. The release workflow supplies an ephemeral signed-release overlay and requires protected signing secrets; a local unsigned build must not be described as a signed release.

## Reporting a security issue

Do not include credentials, cookies, private keys, package contents, or unredacted reports in an issue. Preserve the smallest safe reproduction, the Reforge error code, component/operation IDs, package format version, adapter/provider version, and the relevant redacted journal/report excerpt. See [`docs/sources.md`](sources.md) for the external evidence behind the security constraints.