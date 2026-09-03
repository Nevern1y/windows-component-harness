#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $BaseVhdx,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ [System.IO.Path]::IsPathRooted($_) })]
    [string] $VmRoot,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $ReforgeExe,

    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential] $Credential,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $SwitchName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$')]
    [string] $RebootPackageId,

    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$')]
    [string[]] $FixturePackageId = @('7zip.7zip'),

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string] $SourceVmName = 'Reforge-E2E-Source',

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string] $TargetVmName = 'Reforge-E2E-Target',

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string] $SourceCheckpoint = 'SourceReady',

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string] $TargetCheckpoint = 'CleanBaseline',

    [ValidateRange(2, 64)]
    [int] $ProcessorCount = 2,

    [ValidateRange(2147483648, 68719476736)]
    [UInt64] $StartupMemoryBytes = 4GB,

    [switch] $ResetExisting
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$guestRoot = 'C:\ReforgeE2E'
$guestExe = Join-Path $guestRoot 'bin\reforge.exe'
$allPackageIds = @($FixturePackageId + $RebootPackageId | Sort-Object -Unique)
if ($FixturePackageId -contains $RebootPackageId) {
    throw 'RebootPackageId must differ from every ordinary FixturePackageId.'
}

function Assert-HyperVPrerequisites {
    if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) {
        throw 'Hyper-V PowerShell cmdlets are unavailable. Enable Hyper-V and its management tools.'
    }
    if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
        throw "Hyper-V switch '$SwitchName' does not exist."
    }
    if ($SourceVmName -eq $TargetVmName) {
        throw 'SourceVmName and TargetVmName must be different.'
    }
    $base = Get-VHD -Path (Resolve-Path -LiteralPath $BaseVhdx).Path
    if ($base.VhdType -eq 'Differencing') {
        throw 'BaseVhdx must be a standalone Windows 11 x64 image, not a differencing disk.'
    }
}

function Remove-FixtureVm {
    param([Parameter(Mandatory = $true)][string] $Name)

    $vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if (-not $vm) {
        return
    }
    if (-not $ResetExisting) {
        throw "VM '$Name' already exists. Use -ResetExisting to replace only the named fixture VMs."
    }
    if ($vm.State -ne 'Off') {
        Stop-VM -VM $vm -TurnOff -Force
    }
    Remove-VM -VM $vm -Force
}

function New-FixtureVm {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $DiskPath
    )

    $basePath = (Resolve-Path -LiteralPath $BaseVhdx).Path
    $diskDirectory = Split-Path -Parent $DiskPath
    New-Item -ItemType Directory -Path $diskDirectory -Force | Out-Null
    Copy-Item -LiteralPath $basePath -Destination $DiskPath -Force

    $vm = New-VM -Name $Name -Generation 2 -MemoryStartupBytes $StartupMemoryBytes -VHDPath $DiskPath -SwitchName $SwitchName -Path $diskDirectory
    Set-VMProcessor -VM $vm -Count $ProcessorCount
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false -StartupBytes $StartupMemoryBytes
    Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
    Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing -AutomaticStopAction ShutDown -SnapshotFileLocation $diskDirectory -SmartPagingFilePath $diskDirectory
    Enable-VMIntegrationService -VM $vm -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
    return $vm
}

function New-GuestSession {
    param(
        [Parameter(Mandatory = $true)][string] $VmName,
        [int] $TimeoutSeconds = 300
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            return New-PSSession -VMName $VmName -Credential $Credential -ErrorAction Stop
        }
        catch {
            Start-Sleep -Seconds 3
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "PowerShell Direct did not become ready for '$VmName' within $TimeoutSeconds seconds."
}

function Initialize-GuestLayout {
    param([Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session)

    Invoke-Command -Session $Session -ScriptBlock {
        param($Root)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        if (-not [Environment]::Is64BitOperatingSystem) {
            throw 'Fixture guest must run a 64-bit operating system.'
        }
        $os = Get-CimInstance Win32_OperatingSystem
        if ($os.Caption -notmatch 'Windows 11') {
            throw "Fixture guest must run Windows 11; observed '$($os.Caption)'."
        }
        New-Item -ItemType Directory -Path (Join-Path $Root 'bin') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $Root 'fixture') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $Root 'out') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $Root 'state') -Force | Out-Null
        $marker = [ordered]@{ schema_version = 1; fixture = 'reforge-hyperv-e2e' } | ConvertTo-Json -Compress
        [System.IO.File]::WriteAllText((Join-Path $Root 'fixture\marker.json'), $marker, [System.Text.UTF8Encoding]::new($false))
    } -ArgumentList $guestRoot
    Copy-Item -LiteralPath (Resolve-Path -LiteralPath $ReforgeExe).Path -Destination $guestExe -ToSession $Session -Force
    Invoke-Command -Session $Session -ScriptBlock {
        param($Exe)
        $versionOutput = (& $Exe --version 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($versionOutput)) {
            throw 'Copied Reforge CLI failed its guest --version smoke check.'
        }
    } -ArgumentList $guestExe
}

function Invoke-WinGetInstall {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session,
        [Parameter(Mandatory = $true)][string[]] $PackageIds
    )

    return Invoke-Command -Session $Session -ScriptBlock {
        param([string[]] $Ids)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $winget = Get-Command winget.exe -ErrorAction Stop
        $rebootRequired = $false
        foreach ($id in $Ids) {
            $installOutput = (& $winget.Path install --id $id --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | Out-String)
            $exitCode = $LASTEXITCODE
            if ($exitCode -notin @(0, 3010)) {
                throw "winget install failed for '$id' with exit code $exitCode."
            }
            if ($exitCode -eq 3010) {
                $rebootRequired = $true
            }
            $null = $installOutput
        }
        return $rebootRequired
    } -ArgumentList (, $PackageIds)
}

function Assert-TargetPackagesAbsent {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session,
        [Parameter(Mandatory = $true)][string[]] $PackageIds
    )

    Invoke-Command -Session $Session -ScriptBlock {
        param([string[]] $Ids)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $winget = Get-Command winget.exe -ErrorAction Stop
        foreach ($id in $Ids) {
            $output = (& $winget.Path list --id $id --exact --accept-source-agreements --disable-interactivity 2>&1 | Out-String)
            if ($output -match [regex]::Escape($id)) {
                throw "Clean target baseline already contains fixture package '$id'."
            }
        }
    } -ArgumentList (, $PackageIds)
}

function Stop-FixtureGuest {
    param([Parameter(Mandatory = $true)][string] $VmName)

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    if ($vm.State -eq 'Off') {
        return
    }
    $stopVmCommand = Get-Command Stop-VM -ErrorAction Stop
    if ($stopVmCommand.Parameters.ContainsKey('Shutdown')) {
        Stop-VM -VM $vm -Shutdown -ErrorAction SilentlyContinue
    }
    else {
        Stop-VM -VM $vm -TurnOff -Force
        return
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    while ((Get-VM -Name $VmName).State -ne 'Off' -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds 2
    }
    if ((Get-VM -Name $VmName).State -ne 'Off') {
        Stop-VM -Name $VmName -TurnOff -Force
    }
}

function Restart-FixtureGuest {
    param([Parameter(Mandatory = $true)][string] $VmName)

    Stop-FixtureGuest -VmName $VmName
    Start-VM -Name $VmName | Out-Null
}

function Set-SourceFixtures {
    param([Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session)

    Invoke-Command -Session $Session -ScriptBlock {
        param($Root)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $codexHome = Join-Path $env:USERPROFILE '.codex'
        New-Item -ItemType Directory -Path $codexHome -Force | Out-Null
        $config = @'
model = "reforge-fixture-model"
model_reasoning_effort = "medium"
'@
        [System.IO.File]::WriteAllText((Join-Path $codexHome 'config.toml'), $config, [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $Root 'fixture\source-marker.txt'), 'source-ready', [System.Text.UTF8Encoding]::new($false))
        [Environment]::SetEnvironmentVariable('REFORGE_E2E_SECRET', 'REFORGE_VM_SECRET_SENTINEL', 'User')
        $env:REFORGE_E2E_SECRET = 'REFORGE_VM_SECRET_SENTINEL'
    } -ArgumentList $guestRoot
}

Assert-HyperVPrerequisites
if (-not $PSCmdlet.ShouldProcess("$SourceVmName, $TargetVmName", 'Replace named fixtures if requested and create isolated Hyper-V Generation 2 VMs')) {
    return
}
New-Item -ItemType Directory -Path $VmRoot -Force | Out-Null
Remove-FixtureVm -Name $SourceVmName
Remove-FixtureVm -Name $TargetVmName

$sourceDisk = Join-Path $VmRoot "$SourceVmName\disk.vhdx"
$targetDisk = Join-Path $VmRoot "$TargetVmName\disk.vhdx"
$fixtureDirectories = @((Split-Path -Parent $sourceDisk), (Split-Path -Parent $targetDisk))
if (-not $ResetExisting) {
    foreach ($directory in $fixtureDirectories) {
        if (Test-Path -LiteralPath $directory) {
            throw "Fixture directory '$directory' already exists. Use -ResetExisting to replace it."
        }
    }
}
if ($ResetExisting) {
    foreach ($directory in $fixtureDirectories) {
        if (Test-Path -LiteralPath $directory) {
            Remove-Item -LiteralPath $directory -Recurse -Force
        }
    }
}

$sourceVm = New-FixtureVm -Name $SourceVmName -DiskPath $sourceDisk
$targetVm = New-FixtureVm -Name $TargetVmName -DiskPath $targetDisk
$sourceSession = $null
$targetSession = $null
try {
    Start-VM -VM $sourceVm | Out-Null
    $sourceSession = New-GuestSession -VmName $SourceVmName
    Initialize-GuestLayout -Session $sourceSession
    $sourceNeedsReboot = [bool](Invoke-WinGetInstall -Session $sourceSession -PackageIds $allPackageIds)
    Set-SourceFixtures -Session $sourceSession
    Remove-PSSession $sourceSession
    $sourceSession = $null

    if ($sourceNeedsReboot) {
        Restart-FixtureGuest -VmName $SourceVmName
        $sourceSession = New-GuestSession -VmName $SourceVmName
        Remove-PSSession $sourceSession
        $sourceSession = $null
    }
    Stop-FixtureGuest -VmName $SourceVmName
    Checkpoint-VM -VM $sourceVm -SnapshotName $SourceCheckpoint | Out-Null

    Start-VM -VM $targetVm | Out-Null
    $targetSession = New-GuestSession -VmName $TargetVmName
    Initialize-GuestLayout -Session $targetSession
    Assert-TargetPackagesAbsent -Session $targetSession -PackageIds $allPackageIds
    Remove-PSSession $targetSession
    $targetSession = $null
    Stop-FixtureGuest -VmName $TargetVmName
    Checkpoint-VM -VM $targetVm -SnapshotName $TargetCheckpoint | Out-Null
}
finally {
    if ($sourceSession) { Remove-PSSession $sourceSession }
    if ($targetSession) { Remove-PSSession $targetSession }
    foreach ($vmName in @($SourceVmName, $TargetVmName)) {
        Stop-FixtureGuest -VmName $vmName
    }
}

$metadata = [ordered]@{
    schema_version = 1
    source_vm = $SourceVmName
    target_vm = $TargetVmName
    source_checkpoint = $SourceCheckpoint
    target_checkpoint = $TargetCheckpoint
    generation = 2
    architecture = 'x86_64'
    fixture_package_ids = @($FixturePackageId)
    reboot_package_id = $RebootPackageId
    guest_reforge = $guestExe
}
$metadataPath = Join-Path $VmRoot 'provision.json'
$metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
Write-Output $metadataPath
