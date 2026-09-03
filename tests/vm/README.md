# Reforge Windows VM E2E

This harness exercises the real `reforge.exe` CLI through PowerShell Direct on two isolated Hyper-V Generation 2 Windows 11 x64 virtual machines. It does not mock providers, the planner, the journal, restore handlers, or verification.

## Host prerequisites

- Windows 11 Pro/Enterprise with Hyper-V and the Hyper-V PowerShell module enabled.
- An elevated Windows PowerShell 5.1 or newer session.
- A prepared, standalone Windows 11 x64 VHDX with a local administrator account. PowerShell Direct must accept that account.
- App Installer/WinGet available to the VM account.
- An external Hyper-V switch that gives both VMs access to configured WinGet sources.
- A release `reforge.exe` built from the current checkout: `cargo build -p reforge-cli --release --locked`.
- Enough disk space on the selected non-system `VmRoot` drive for two independent copies of the base VHDX and their checkpoints.
- A controlled, free/open-source WinGet package whose installer deterministically exits with `3010` on a clean target. Pass its exact ID as `RebootPackageId`. The harness fails if no restore reaches `REBOOT_REQUIRED`; it never fakes or edits journal state to manufacture that lifecycle.

Use a disposable local administrator account created only in the base image. Do not use a Microsoft account, real browser profile, cloud credential, or production package source. The scripts never serialize the supplied `PSCredential`.

Use a non-system `VmRoot`, such as `D:\VMs\reforge-e2e`. `Provision.ps1` places each fixture VM's configuration, VHDX, checkpoints, and Smart Paging files below that root; it does not place fixture storage on the host `C:` drive.

The harness runs at most one guest at a time and leaves both fixture VMs powered off after provisioning and after every complete E2E run. This bounds guest startup memory to one `StartupMemoryBytes` allocation instead of two concurrent allocations.

## Create the fixtures

Run from the repository root in an elevated shell:

```powershell
$rebootPackageId = Read-Host 'Exact ID of the controlled FOSS reboot fixture package'

$credential = Get-Credential -UserName 'ReforgeVmAdmin'

.\tests\vm\Provision.ps1 `
  -BaseVhdx 'D:\VMs\bases\Windows11-E2E.vhdx' `
  -VmRoot 'D:\VMs\reforge-e2e' `
  -ReforgeExe '.\target\release\reforge.exe' `
  -Credential $credential `
  -SwitchName 'E2E External' `
  -FixturePackageId '7zip.7zip' `
  -RebootPackageId $rebootPackageId
```

`Provision.ps1` performs these concrete operations:

1. Copies the standalone base disk twice and creates `Reforge-E2E-Source` and `Reforge-E2E-Target` as Generation 2 VMs with Secure Boot.
2. Copies the built CLI into `C:\ReforgeE2E\bin` in each guest.
3. Installs the ordinary and controlled-reboot fixture packages only on the source VM.
4. Writes a portable Codex configuration fixture without real credentials.
5. Creates `SourceReady` and `CleanBaseline` checkpoints.
6. Writes a non-secret fixture marker in each guest and non-secret metadata to `<VmRoot>\provision.json`.

`RebootPackageId` must be distinct from every ordinary `FixturePackageId`. The runner verifies the marker, Windows 11 x64 guest, Generation 2 VM, provisioned executable, and named checkpoint before it restores a checkpoint. The script refuses to replace an existing named VM unless `-ResetExisting` is supplied. `-ResetExisting` affects only the two explicitly named fixture VMs and their directories under `VmRoot`.

## Run every scenario

Reuse the in-memory credential from provisioning:

```powershell
.\tests\vm\Run-E2E.ps1 `
  -Credential $credential `
  -ArtifactRoot 'D:\VMs\reforge-e2e-results' `
  -FixturePackageId '7zip.7zip' `
  -RebootPackageId $rebootPackageId
```

The runner resets the target to `CleanBaseline` before and after every scenario. It executes and validates:

- source scan, explicit fixture selection, package creation, and package inspection;
- clean-target rebuild, reboot pause/resume, fresh target scan, verification, and redacted report export;
- non-empty migration with installed packages and a future-dated Codex configuration collision, including preservation of the newer target file;
- a file locked with `FileShare.None`, requiring an explicit partial/manual outcome rather than silent success;
- source/target package rediscovery after restore;
- bounded reboot resume with the same durable run ID and a verified guest boot-time transition;
- report classification for every selected component, zero failed components, and rejection of raw `C:\Users\...` paths or secret-like report values.

The runner treats a fixture-checkpoint reset failure as a test failure unless another scenario has already failed, in which case it emits the reset failure without masking the original error. `summary.json` records `hidden_failures: 0` only after every assertion and final reset succeeds. Any failed command, missing collision, overwritten newer file, absent reboot pause, missing reboot, unknown component status, failed component, redaction violation, or failed final reset terminates the run with a nonzero exit.

## Invoke through the Rust integration entry point

The Rust entry point is intentionally ignored in ordinary workspace tests because it mutates disposable Windows images and requires host-only credentials. Store the VM password as a DPAPI-protected `SecureString`, not plaintext:

```powershell
New-Item -ItemType Directory -Path "$env:LOCALAPPDATA\Reforge" -Force | Out-Null
Read-Host 'VM password' -AsSecureString |
  ConvertFrom-SecureString |
  Set-Content -LiteralPath "$env:LOCALAPPDATA\Reforge\e2e-vm-password.txt"
$rebootPackageId = Read-Host 'Exact ID of the controlled FOSS reboot fixture package'


$env:REFORGE_E2E_USERNAME = 'ReforgeVmAdmin'
$env:REFORGE_E2E_PASSWORD_FILE = "$env:LOCALAPPDATA\Reforge\e2e-vm-password.txt"
$env:REFORGE_E2E_ARTIFACT_ROOT = 'D:\VMs\reforge-e2e-results'
$env:REFORGE_E2E_FIXTURE_PACKAGE_IDS = '7zip.7zip'
$env:REFORGE_E2E_REBOOT_PACKAGE_ID = $rebootPackageId

rustc --edition 2024 --test .\tests\integration\windows_e2e.rs -o .\target\windows-e2e-tests.exe
.\target\windows-e2e-tests.exe --ignored --exact hyper_v_source_to_target_e2e --nocapture
```

Optional environment variables are `REFORGE_E2E_POWERSHELL`, `REFORGE_E2E_RUNNER`, `REFORGE_E2E_SOURCE_VM`, `REFORGE_E2E_TARGET_VM`, `REFORGE_E2E_SOURCE_CHECKPOINT`, and `REFORGE_E2E_TARGET_CHECKPOINT`.

## Reset and rerun

`Run-E2E.ps1` restores the target checkpoint in a `finally` block for each scenario and powers it off. If the host loses power or the process is killed, restore `CleanBaseline` manually and leave the VM off before rerunning; the runner starts it when needed:

```powershell
Stop-VM 'Reforge-E2E-Target' -TurnOff -Force
Restore-VMSnapshot -VMName 'Reforge-E2E-Target' -Name 'CleanBaseline' -Confirm:$false
```

Never use these scripts against a non-fixture VM. VM scripts are test infrastructure; their PowerShell operations are not package operations and are never accepted by the Reforge planner or executor.
