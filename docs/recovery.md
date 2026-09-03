# Recovery procedure

This procedure is for the current CLI-only release. Keep the `.reforge` package and the Reforge local state directory available until verification is complete. Do not delete or edit a package after a run is planned: the persisted run stores package digests and rejects a changed package.

## Safety rules

1. Work on the intended Windows 11 x64 target and confirm the target has enough free space for selected objects, temporary files, backups, and the journal.
2. Use `reforge doctor --json` before a scan or restore.
3. Inspect the package before approving restore. An unsigned package is inspectable but is not trusted by its hashes alone.
4. Use `plan` before `restore`. Use `--mode rebuild` only for a target that should receive a selected environment; use `--mode migrate` for a non-empty target.
5. Never treat a successful process exit as proof that every component was restored. Read the report status and every component entry.
6. Do not copy Windows credentials, browser cookies/logins, OAuth sessions, DPAPI data, or app-bound secret stores. Those states require reauthentication or a documented secure adapter target.

## First run

```powershell
reforge doctor --json
reforge scan --json
reforge inventory show --json
```

`scan` persists `inventory.json`. Progress is on stderr, so stdout remains one JSON document when `--json` is used. The normal state root is `%LOCALAPPDATA%\\Reforge`. For a disposable run, set an absolute directory before all commands:

```powershell
$env:REFORGE_STATE_DIR = 'D:\\ReforgeRuns\\state'
```

Do not point `REFORGE_STATE_DIR` at a reparse point, a relative path, or a directory shared with unrelated state.

## Package creation

Create a `SelectionInput` file using component IDs from `inventory show`. This is a valid empty smoke-test selection:

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

Then write and inspect the package:

```powershell
reforge package create `
  --output 'D:\\ReforgeRuns\\environment.reforge' `
  --selection 'D:\\ReforgeRuns\\selection.json' `
  --json

reforge package inspect 'D:\\ReforgeRuns\\environment.reforge' --json
```

Required dependencies are added transitively. Secret, large-data, manual, and portable-binary artifacts are not silently included. The current CLI does not collect secret values through a secure adapter: a non-empty `--secret-selection` is rejected with `VAULT_REQUIRED`. Keep that behavior; do not work around it by selecting the source file as ordinary data.

## Preview and restore

Preview the plan first:

```powershell
reforge plan `
  --package 'D:\\ReforgeRuns\\environment.reforge' `
  --mode rebuild `
  --json
```

The command prints a durable `run_id` and stores run state below the configured state root. It does not execute restore operations. For a non-empty target, use `--mode migrate`; the diff and conflict records are part of the plan.

After reviewing package trust, target facts, conflicts, backups, manual actions, source URLs, and compatibility, execute with explicit approval:

```powershell
reforge restore `
  --package 'D:\\ReforgeRuns\\environment.reforge' `
  --mode rebuild `
  --yes-safe `
  --json
```

The executor rechecks preconditions, skips already-satisfied idempotent work, writes operation state to the SQLite journal, and produces a redacted report. File and config replacement uses a same-directory temporary file and atomic replacement. When an existing destination is replaced, the original is retained as a generated sibling backup recorded in the operation result. MVP has no target-delete operation.

## Manual actions

A manual action means automation stopped intentionally. Common causes include a locked application, reauthentication, unsupported source/version, a protected system setting, an untrusted installer/extension, a target conflict, or a required elevation boundary.

List actions for the run:

```powershell
reforge action list RUN_ID --json
```

Resolve the documented condition outside Reforge, then acknowledge only the specific action that was resolved:

```powershell
reforge action acknowledge RUN_ID ACTION_ID --json
reforge resume RUN_ID --json
```

Acknowledgement is durable and bound to the run/action identity. If the same operation blocks again on a later attempt, Reforge can create a new attempt-bound action; an old acknowledgement does not silently authorize a new condition. Review the resulting report again.

Do not acknowledge a secret, browser-session, hook/plugin, protected registry, or unknown command action by merely confirming that a file exists. Those are explicit trust or reauthentication boundaries.

## Reboot-required runs

A provider installer may return a documented reboot-required result. Reforge records `WAITING_FOR_REBOOT`/`REBOOT_REQUIRED` and does not create hidden `RunOnce` persistence.

1. Save the run ID from the restore JSON output.
2. Do not delete the package or state directory.
3. Reboot Windows through the normal user-approved process.
4. Reopen the CLI after Windows starts.
5. Resume the same run:

```powershell
reforge resume RUN_ID --json
reforge verify RUN_ID --json
```

The same durable run ID is required. A new restore command creates a new run and can defeat idempotent resume reasoning.

## Crash, cancellation, or power loss

The journal is SQLite WAL-backed and uses a single writer. On the next journal open, operations left in `RUNNING` become `INTERRUPTED`, and the run is marked interrupted. Resume does not blindly repeat non-idempotent work: it reopens the package, checks persisted package digests and explicit approval, rescans the target, and re-evaluates operation satisfaction.

Use:

```powershell
reforge resume RUN_ID --json
```

If resume reports a package mismatch, restore the exact package file associated with the run. Do not edit the package, replace it with a similarly named file, or remove the journal to bypass the check. If the package is unavailable, preserve the state directory and report the run as unrecoverable rather than guessing.

Cancellation is represented in the report and exit code. Inspect the report before starting a new run; completed operations should not be repeated merely because the process was interrupted.

## Verify and export the report

Verification rescans the current target and compares it with the selected package/plan:

```powershell
reforge verify RUN_ID --json
reforge report RUN_ID --output 'D:\\ReforgeRuns\\report.json' --json
```

The report contains component status, counts, verification evidence, warnings, manual actions, elapsed time, and bytes written. It is redacted before persistence/serialization; it must not contain raw user paths such as `C:\\Users\\...`, secret literals, browser cookies, or provider output that failed redaction.

Report statuses include `VERIFIED`, `ALREADY_PRESENT`, `PARTIALLY_VERIFIED`, `WAITING_FOR_USER`, `REAUTH_REQUIRED`, `REBOOT_REQUIRED`, `UNSUPPORTED`, and `FAILED`. A partial or manual report is a valid honest outcome, not a successful clone claim.

## Migration recovery

Migration preserves target data by default:

- target configuration is parsed before merge;
- known keys can be replaced only by a declared merge policy;
- unknown target keys remain preserved where the policy allows;
- collisions become conflict/manual records instead of silent overwrites;
- replaced files receive a sibling backup;
- no operation deletes target data in MVP.

If a migration result is not acceptable, stop the run, retain the journal/report and the backup paths recorded in operation results, and restore the affected files manually from those backups after reviewing the report. Do not run an unreviewed cleanup command or delete the target to force a rebuild.

## Local state layout

The state root contains local, non-portable operational state such as:

- `inventory.json` — last discovery inventory;
- `target.json` — last normalized target scan;
- `objects\\` — content-store objects used while creating packages;
- `runs\\<run-id>.json` — package digests, trust state, and restore plan;
- `reports\\<run-id>.json` — persisted redacted report;
- `journal.sqlite` — durable runs, operations, events, and manual-action rows.

The journal is not copied into `.reforge` packages. Preserve the state root for resume and diagnostics; protect it with the same access controls as other local application state.

## Disposable Hyper-V E2E recovery

The VM harness is test infrastructure only. Read [`tests/vm/README.md`](../tests/vm/README.md) before using it. It requires two isolated Windows 11 x64 Generation 2 fixture VMs, an elevated PowerShell session, a disposable local administrator, a controlled free/open-source WinGet reboot fixture, and an external switch. It must never run against a production or non-fixture VM.

The runner resets the target checkpoint in a `finally` block. If the host loses power or the process is killed, leave the target powered off and restore the named clean checkpoint before rerunning:

```powershell
Stop-VM 'Reforge-E2E-Target' -TurnOff -Force
Restore-VMSnapshot -VMName 'Reforge-E2E-Target' -Name 'CleanBaseline' -Confirm:$false
```

The VM password is stored as DPAPI-protected `SecureString` material by the documented procedure; it is never serialized into the package or report. The VM scripts are not accepted as package operations and do not justify arbitrary command execution in the product.

## Exit codes during recovery

| Code | Meaning | Recovery action |
|---:|---|---|
| 0 | Verified or already present | Read the report and retain evidence. |
| 1 | Partial, skipped, unsupported, or failed report | Inspect component warnings/evidence; resolve listed actions or keep the partial result. |
| 2 | Invalid input/package/command | Fix the input or package path; do not retry a malformed package blindly. |
| 3 | User action or reauthentication required | Resolve the action, acknowledge it, and resume. |
| 4 | Compatibility blocked | Change target/package selection only after reviewing the compatibility record. |
| 5 | Trust/security blocked | Inspect package/source/policy; never bypass by copying files or commands. |
| 6 | Interrupted, cancelled, or reboot pending | Preserve state/package and resume the existing run after the condition is safe. |