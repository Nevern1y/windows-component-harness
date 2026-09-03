#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential] $Credential,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ [System.IO.Path]::IsPathRooted($_) })]
    [string] $ArtifactRoot,

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

    [ValidatePattern('^[A-Za-z]:\\[A-Za-z0-9._\\-]+$')]
    [string] $GuestRoot = 'C:\ReforgeE2E',

    [ValidateRange(1, 4)]
    [int] $MaximumReboots = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$guestExe = Join-Path $GuestRoot 'bin\reforge.exe'
$guestState = Join-Path $GuestRoot 'state'
$guestOut = Join-Path $GuestRoot 'out'
$guestPackage = Join-Path $guestOut 'source.reforge'
$guestSelection = Join-Path $guestOut 'selection.json'
$guestReport = Join-Path $guestOut 'report.json'
$guestFixtureMarker = Join-Path $GuestRoot 'fixture\marker.json'
$allPackageIds = @($FixturePackageId + $RebootPackageId | Sort-Object -Unique)
if ($FixturePackageId -contains $RebootPackageId) {
    throw 'RebootPackageId must differ from every ordinary FixturePackageId.'
}
$runDirectory = Join-Path $ArtifactRoot ((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N'))

function Assert-FixtureGuest {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session,
        [Parameter(Mandatory = $true)][string] $VmName
    )

    Invoke-Command -Session $Session -ScriptBlock {
        param($Marker, $Exe)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        if (-not (Test-Path -LiteralPath $Marker -PathType Leaf)) {
            throw 'Guest is missing the Reforge E2E fixture marker.'
        }
        $fixture = Get-Content -LiteralPath $Marker -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($fixture.schema_version -ne 1 -or $fixture.fixture -ne 'reforge-hyperv-e2e') {
            throw 'Guest fixture marker is invalid.'
        }
        if (-not [Environment]::Is64BitOperatingSystem) {
            throw 'Guest operating system is not 64-bit.'
        }
        $os = Get-CimInstance Win32_OperatingSystem
        if ($os.Caption -notmatch 'Windows 11') {
            throw "Guest is not Windows 11; observed '$($os.Caption)'."
        }
        if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) {
            throw 'Guest is missing the provisioned Reforge executable.'
        }
    } -ArgumentList $guestFixtureMarker, $guestExe
}

function Assert-VmContract {
    foreach ($entry in @(
        @{ Name = $SourceVmName; Checkpoint = $SourceCheckpoint },
        @{ Name = $TargetVmName; Checkpoint = $TargetCheckpoint }
    )) {
        $vm = Get-VM -Name $entry.Name -ErrorAction Stop
        if ($vm.Generation -ne 2) {
            throw "VM '$($entry.Name)' is Generation $($vm.Generation); T051 requires Generation 2."
        }
        if (-not (Get-VMSnapshot -VMName $entry.Name -Name $entry.Checkpoint -ErrorAction SilentlyContinue)) {
            throw "Checkpoint '$($entry.Checkpoint)' is missing from VM '$($entry.Name)'."
        }
        if ($vm.State -eq 'Off') {
            Start-VM -VM $vm -ErrorAction Stop | Out-Null
        }
        $session = $null
        try {
            $session = New-GuestSession -VmName $entry.Name
            Assert-FixtureGuest -Session $session -VmName $entry.Name
        }
        finally {
            if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
            $current = Get-VM -Name $entry.Name -ErrorAction SilentlyContinue
            if ($current -and $current.State -ne 'Off') {
                Stop-VM -VM $current -TurnOff -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Restore-FixtureCheckpoint {
    param(
        [Parameter(Mandatory = $true)][string] $VmName,
        [Parameter(Mandatory = $true)][string] $Checkpoint,
        [switch] $LeaveOff
    )

    $vm = Get-VM -Name $VmName
    if ($vm.State -ne 'Off') {
        Stop-VM -VM $vm -TurnOff -Force
    }
    $snapshot = Get-VMSnapshot -VMName $VmName -Name $Checkpoint
    Restore-VMSnapshot -VMSnapshot $snapshot -Confirm:$false
    if (-not $LeaveOff -and (Get-VM -Name $VmName).State -ne 'Running') {
        Start-VM -Name $VmName | Out-Null
    }
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

function Get-GuestBootTicks {
    param([Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session)

    return [Int64](Invoke-Command -Session $Session -ScriptBlock {
        [Int64]((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks)
    })
}

function Restart-GuestAndWait {
    param(
        [Parameter(Mandatory = $true)][string] $VmName,
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session,
        [int] $TimeoutSeconds = 300
    )

    $previousBootTicks = Get-GuestBootTicks -Session $Session
    Invoke-Command -Session $Session -ScriptBlock {
        $shutdown = Join-Path $env:SystemRoot 'System32\shutdown.exe'
        if (-not (Test-Path -LiteralPath $shutdown -PathType Leaf)) {
            throw 'Guest shutdown executable is unavailable.'
        }
        $process = Start-Process -FilePath $shutdown -ArgumentList @('/r', '/t', '0', '/f') -PassThru -WindowStyle Hidden
        Start-Sleep -Milliseconds 200
        if ($process.HasExited -and $process.ExitCode -ne 0) {
            throw "Guest reboot request exited $($process.ExitCode)."
        }
    }
    Remove-PSSession $Session -ErrorAction SilentlyContinue

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastError = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $candidate = $null
        try {
            $remaining = [Math]::Max(1, [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalSeconds))
            $candidate = New-GuestSession -VmName $VmName -TimeoutSeconds ([Math]::Min(15, $remaining))
            $currentBootTicks = Get-GuestBootTicks -Session $candidate
            if ($currentBootTicks -gt $previousBootTicks) {
                $ready = $candidate
                $candidate = $null
                return $ready
            }
            $lastError = 'PowerShell Direct reconnected before the guest boot time advanced.'
        }
        catch {
            $lastError = $_.Exception.Message
        }
        finally {
            if ($candidate) { Remove-PSSession $candidate -ErrorAction SilentlyContinue }
        }
        Start-Sleep -Seconds 3
    }
    throw "Guest '$VmName' did not complete a verified reboot within $TimeoutSeconds seconds. Last error: $lastError"
}


function Save-CommandArtifacts {
    param(
        [Parameter(Mandatory = $true)][string] $Scenario,
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)] $Result
    )

    $scenarioDirectory = Join-Path $runDirectory $Scenario
    New-Item -ItemType Directory -Path $scenarioDirectory -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $scenarioDirectory "$Name.stdout.json") -Value $Result.Stdout -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $scenarioDirectory "$Name.stderr.txt") -Value $Result.Stderr -Encoding UTF8
}

function Invoke-GuestReforge {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session,
        [Parameter(Mandatory = $true)][string] $Scenario,
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [int[]] $AllowedExitCodes = @(0)
    )

    $request = [pscustomobject]@{
        Exe = $guestExe
        State = $guestState
        Root = $GuestRoot
        Arguments = @($Arguments + '--json')
    }
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($Request)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        if (-not (Test-Path -LiteralPath $Request.Exe -PathType Leaf)) {
            throw "Reforge executable is missing at '$($Request.Exe)'."
        }
        New-Item -ItemType Directory -Path $Request.State -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $Request.Root 'out') -Force | Out-Null
        $env:REFORGE_STATE_DIR = $Request.State
        $stdoutPath = Join-Path $Request.Root ('out\stdout-' + [Guid]::NewGuid().ToString('N') + '.json')
        $stderrPath = Join-Path $Request.Root ('out\stderr-' + [Guid]::NewGuid().ToString('N') + '.txt')
        try {
            $commandArguments = [string[]]$Request.Arguments
            & $Request.Exe @commandArguments 1> $stdoutPath 2> $stderrPath
            $exitCode = $LASTEXITCODE
            $stdout = if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
            $stderr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
            [pscustomobject]@{ ExitCode = $exitCode; Stdout = $stdout; Stderr = $stderr }
        }
        finally {
            Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
        }
    } -ArgumentList $request

    Save-CommandArtifacts -Scenario $Scenario -Name $Name -Result $result
    if ($result.ExitCode -notin $AllowedExitCodes) {
        throw "Reforge command '$Name' exited $($result.ExitCode). See '$Scenario/$Name.stderr.txt'."
    }
    try {
        $envelope = $result.Stdout | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Reforge command '$Name' did not emit one valid JSON envelope."
    }
    if ($envelope.schema_version -ne 1 -or -not $envelope.request_id -or -not $envelope.payload) {
        throw "Reforge command '$Name' emitted an invalid CLI envelope."
    }
    return [pscustomobject]@{ ExitCode = $result.ExitCode; Envelope = $envelope }
}

function Initialize-SourcePackage {
    param([Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session)

    Invoke-Command -Session $Session -ScriptBlock {
        param($Root)
        Remove-Item -LiteralPath (Join-Path $Root 'state'), (Join-Path $Root 'out') -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path (Join-Path $Root 'state') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $Root 'out') -Force | Out-Null
    } -ArgumentList $GuestRoot

    $scan = Invoke-GuestReforge -Session $Session -Scenario 'source' -Name 'scan' -Arguments @('scan')
    if ($scan.Envelope.payload.status -ne 'ok') {
        throw 'Source scan did not complete successfully.'
    }
    $inventory = Invoke-GuestReforge -Session $Session -Scenario 'source' -Name 'inventory' -Arguments @('inventory', 'show')
    $inventoryPayload = $inventory.Envelope.payload.inventory
    $components = @($inventoryPayload.graph.components)
    if ($components.Count -eq 0) {
        throw 'Source inventory contains no components.'
    }

    $selected = New-Object System.Collections.Generic.List[string]
    foreach ($packageId in $allPackageIds) {
        $match = @($components | Where-Object {
            $_.identity.provider_package -and $_.identity.provider_package.Count -eq 2 -and
            [string]::Equals([string]$_.identity.provider_package[1], $packageId, [StringComparison]::OrdinalIgnoreCase)
        })
        if ($match.Count -eq 0) {
            throw "Source inventory did not discover fixture package '$packageId'."
        }
        foreach ($component in $match) { $selected.Add([string]$component.id) }
    }

    $configMatches = @($components | Where-Object {
        @($_.artifacts | Where-Object {
            $_.source_path.relative -and ([string]$_.source_path.relative).Replace('\', '/').EndsWith('.codex/config.toml', [StringComparison]::OrdinalIgnoreCase)
        }).Count -gt 0
    })
    if ($configMatches.Count -eq 0) {
        throw 'Source inventory did not discover the Codex configuration fixture.'
    }
    foreach ($component in $configMatches) { $selected.Add([string]$component.id) }
    $selectedIds = @($selected | Sort-Object -Unique)
    if ($selectedIds.Count -ne $selected.Count) {
        throw 'Fixture selection contained duplicate component IDs.'
    }

    $selectedArtifacts = @($components | Where-Object { $selectedIds -contains [string]$_.id } | ForEach-Object {
        foreach ($artifact in @($_.artifacts)) {
            [ordered]@{ artifact = [string]$artifact.id; include = $true }
        }
    } | Sort-Object -Property artifact -Unique)
    $selection = [ordered]@{
        components = $selectedIds
        artifacts = $selectedArtifacts
        policy = [ordered]@{
            secrets = 'EXCLUDE'
            large_data = 'EXCLUDE'
            unknown_binaries = 'EXCLUDE'
            max_bytes = $null
        }
    }
    $selectionJson = $selection | ConvertTo-Json -Depth 10
    Invoke-Command -Session $Session -ScriptBlock {
        param($Path, $Json)
        [System.IO.File]::WriteAllText($Path, $Json, [System.Text.UTF8Encoding]::new($false))
    } -ArgumentList $guestSelection, $selectionJson

    Invoke-GuestReforge -Session $Session -Scenario 'source' -Name 'package-create' -Arguments @('package', 'create', '--output', $guestPackage, '--selection', $guestSelection) | Out-Null
    $inspection = Invoke-GuestReforge -Session $Session -Scenario 'source' -Name 'package-inspect' -Arguments @('package', 'inspect', $guestPackage)
    if ([int]$inspection.Envelope.payload.selected_component_count -lt $selectedIds.Count) {
        throw 'Created package omitted explicitly selected fixture components.'
    }
    return [pscustomobject]@{ Inventory = $inventoryPayload; SelectedIds = $selectedIds }
}

function Copy-PackageToTarget {
    param([Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session)

    Copy-Item -LiteralPath (Join-Path $runDirectory 'source.reforge') -Destination $guestPackage -ToSession $Session -Force
}

function Install-TargetPackages {
    param([Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session)

    Invoke-Command -Session $Session -ScriptBlock {
        param([string[]] $Ids)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $winget = Get-Command winget.exe -ErrorAction Stop
        foreach ($id in $Ids) {
            $installOutput = (& $winget.Path install --id $id --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | Out-String)
            $exitCode = $LASTEXITCODE
            if ($exitCode -notin @(0, 3010)) {
                throw "winget install failed for target fixture '$id' with exit code $exitCode."
            }
            $null = $installOutput
        }
    } -ArgumentList (, $FixturePackageId)
}

function Set-TargetConfig {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session,
        [Parameter(Mandatory = $true)][string] $Content,
        [switch] $FutureTimestamp
    )

    Invoke-Command -Session $Session -ScriptBlock {
        param($Value, $Future)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $path = Join-Path $env:USERPROFILE '.codex\config.toml'
        New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
        [System.IO.File]::WriteAllText($path, $Value, [System.Text.UTF8Encoding]::new($false))
        if ($Future) { (Get-Item -LiteralPath $path).LastWriteTimeUtc = [DateTime]::UtcNow.AddDays(2) }
        return $path
    } -ArgumentList $Content, [bool]$FutureTimestamp
}

function Get-TargetConfig {
    param([Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session)
    return Invoke-Command -Session $Session -ScriptBlock {
        $path = Join-Path $env:USERPROFILE '.codex\config.toml'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
        return Get-Content -LiteralPath $path -Raw
    }
}

function Start-ConfigLock {
    param([Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session)

    return Invoke-Command -Session $Session -ScriptBlock {
        param($Root)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $config = Join-Path $env:USERPROFILE '.codex\config.toml'
        New-Item -ItemType Directory -Path (Split-Path -Parent $config) -Force | Out-Null
        if (-not (Test-Path -LiteralPath $config)) {
            [System.IO.File]::WriteAllText($config, 'model = "locked-target"', [System.Text.UTF8Encoding]::new($false))
        }
        $scriptPath = Join-Path $Root 'fixture\hold-lock.ps1'
        $readyPath = Join-Path $Root 'fixture\lock.ready'
        Remove-Item -LiteralPath $readyPath -Force -ErrorAction SilentlyContinue
        $script = @'
param([string] $Path, [string] $ReadyPath)
$stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
try {
    [System.IO.File]::WriteAllText($ReadyPath, [string]$PID)
    while ($true) { Start-Sleep -Seconds 1 }
}
finally { $stream.Dispose() }
'@
        [System.IO.File]::WriteAllText($scriptPath, $script, [System.Text.UTF8Encoding]::new($false))
        $process = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath, '-Path', $config, '-ReadyPath', $readyPath) -WindowStyle Hidden -PassThru
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not (Test-Path -LiteralPath $readyPath)) {
            if ($process.HasExited) { throw 'File-lock helper exited before acquiring the lock.' }
            if ([DateTime]::UtcNow -ge $deadline) { throw 'File-lock helper did not acquire the lock.' }
            Start-Sleep -Milliseconds 200
        }
        return $process.Id
    } -ArgumentList $GuestRoot
}

function Stop-ConfigLock {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session,
        [Parameter(Mandatory = $true)][int] $ProcessId
    )
    Invoke-Command -Session $Session -ScriptBlock {
        param($Id)
        Stop-Process -Id $Id -Force -ErrorAction SilentlyContinue
    } -ArgumentList $ProcessId
}

function Complete-Restore {
    param(
        [Parameter(Mandatory = $true)][string] $Scenario,
        [Parameter(Mandatory = $true)][ValidateSet('rebuild', 'migrate')][string] $Mode,
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session
    )

    $result = Invoke-GuestReforge -Session $Session -Scenario $Scenario -Name 'restore' -Arguments @('restore', '--package', $guestPackage, '--mode', $Mode, '--yes-safe') -AllowedExitCodes @(0, 1, 3, 6)
    $report = $result.Envelope.payload
    $sawReboot = $false
    $rebootCount = 0
    while ($report.status -eq 'REBOOT_REQUIRED') {
        $sawReboot = $true
        $rebootCount++
        if ($rebootCount -gt $MaximumReboots) {
            throw "Scenario '$Scenario' exceeded the reboot-resume bound."
        }
        $runId = [string]$report.run_id
        $Session = Restart-GuestAndWait -VmName $TargetVmName -Session $Session
        $result = Invoke-GuestReforge -Session $Session -Scenario $Scenario -Name "resume-$rebootCount" -Arguments @('resume', $runId) -AllowedExitCodes @(0, 1, 3, 6)
        $report = $result.Envelope.payload
    }
    return [pscustomobject]@{ Session = $Session; Report = $report; SawReboot = $sawReboot }
}

function Assert-ReportVisible {
    param(
        [Parameter(Mandatory = $true)] $Report,
        [Parameter(Mandatory = $true)][string] $Scenario,
        [switch] $RequireVerified
    )

    if (-not $Report.run_id -or -not $Report.counts -or @($Report.components).Count -eq 0) {
        throw "Scenario '$Scenario' did not produce a complete report."
    }
    if ([int]$Report.counts.failed -ne 0 -or @($Report.components | Where-Object { $_.status -eq 'FAILED' }).Count -ne 0 -or $Report.status -eq 'FAILED') {
        throw "Scenario '$Scenario' contains an explicit failed component or run."
    }
    $knownStatuses = @('VERIFIED', 'PARTIALLY_VERIFIED', 'ALREADY_PRESENT', 'SKIPPED', 'WAITING_FOR_USER', 'REAUTH_REQUIRED', 'REBOOT_REQUIRED', 'UNSUPPORTED')
    if ($Report.status -notin $knownStatuses) {
        throw "Scenario '$Scenario' has unknown report status '$($Report.status)'."
    }
    foreach ($component in @($Report.components)) {
        if ($component.status -notin $knownStatuses) {
            throw "Scenario '$Scenario' contains an unclassified component status '$($component.status)'."
        }
        $evidenceCount = @($component.evidence).Count + @($component.manual_actions).Count + @($component.warnings).Count
        if ($evidenceCount -eq 0) {
            throw "Scenario '$Scenario' component '$($component.component)' has no evidence, manual action, or warning."
        }
    }
    $countMap = [ordered]@{
        verified = @('VERIFIED'); partial = @('PARTIALLY_VERIFIED', 'SKIPPED'); already_present = @('ALREADY_PRESENT')
        waiting_for_user = @('WAITING_FOR_USER'); reauth_required = @('REAUTH_REQUIRED')
        reboot_required = @('REBOOT_REQUIRED'); unsupported = @('UNSUPPORTED'); failed = @('FAILED')
    }
    foreach ($field in $countMap.Keys) {
        $statuses = @($countMap[$field])
        $actual = @($Report.components | Where-Object { $_.status -in $statuses }).Count
        if ([int]$Report.counts.$field -ne $actual) {
            throw "Scenario '$Scenario' report count '$field' does not match its visible components."
        }
    }
    if ($RequireVerified -and $Report.status -notin @('VERIFIED', 'ALREADY_PRESENT')) {
        throw "Scenario '$Scenario' ended as '$($Report.status)' instead of a verified terminal state."
    }
}

function Assert-PackagesDiscovered {
    param(
        [Parameter(Mandatory = $true)] $Inventory,
        [Parameter(Mandatory = $true)][string] $Scenario
    )

    foreach ($packageId in $allPackageIds) {
        $matches = @($Inventory.graph.components | Where-Object {
            $_.identity.provider_package -and $_.identity.provider_package.Count -eq 2 -and
            [string]::Equals([string]$_.identity.provider_package[1], $packageId, [StringComparison]::OrdinalIgnoreCase)
        })
        if ($matches.Count -eq 0) {
            throw "Scenario '$Scenario' target scan did not rediscover '$packageId'."
        }
    }
}

function Export-FinalReport {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession] $Session,
        [Parameter(Mandatory = $true)][string] $Scenario,
        [Parameter(Mandatory = $true)][string] $RunId
    )

    Invoke-GuestReforge -Session $Session -Scenario $Scenario -Name 'report' -Arguments @('report', $RunId, '--output', $guestReport) -AllowedExitCodes @(0, 1, 3, 6) | Out-Null
    $hostPath = Join-Path (Join-Path $runDirectory $Scenario) 'final-report.json'
    Copy-Item -LiteralPath $guestReport -Destination $hostPath -FromSession $Session -Force
    $raw = Get-Content -LiteralPath $hostPath -Raw
    if ($raw -match '(?i)C:\\+Users\\+' -or $raw.Contains('REFORGE_VM_SECRET_SENTINEL')) {
        throw "Scenario '$Scenario' report contains an unredacted user path or fixture secret."
    }
    return $hostPath
}

function Invoke-TargetScenario {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][ValidateSet('rebuild', 'migrate')][string] $Mode,
        [scriptblock] $Prepare,
        [scriptblock] $After,
        [switch] $RequireVerified
    )

    Restore-FixtureCheckpoint -VmName $TargetVmName -Checkpoint $TargetCheckpoint
    $session = New-GuestSession -VmName $TargetVmName
    try {
        Copy-PackageToTarget -Session $session
        if ($Prepare) { & $Prepare $session }
        $completed = Complete-Restore -Scenario $Name -Mode $Mode -Session $session
        $session = $completed.Session
        Assert-ReportVisible -Report $completed.Report -Scenario $Name -RequireVerified:$RequireVerified
        if ($After) { & $After $session $completed.Report }
        $scan = Invoke-GuestReforge -Session $session -Scenario $Name -Name 'rescan' -Arguments @('scan')
        if ($scan.Envelope.payload.status -ne 'ok') { throw "Scenario '$Name' rescan did not complete." }
        $inventory = Invoke-GuestReforge -Session $session -Scenario $Name -Name 'inventory' -Arguments @('inventory', 'show')
        Assert-PackagesDiscovered -Inventory $inventory.Envelope.payload.inventory -Scenario $Name
        $verification = Invoke-GuestReforge -Session $session -Scenario $Name -Name 'verify' -Arguments @('verify', [string]$completed.Report.run_id) -AllowedExitCodes @(0, 1, 3, 6)
        Assert-ReportVisible -Report $verification.Envelope.payload -Scenario "$Name verification" -RequireVerified:$RequireVerified
        $reportPath = Export-FinalReport -Session $session -Scenario $Name -RunId ([string]$completed.Report.run_id)
        return [pscustomobject]@{
            name = $Name
            status = [string]$verification.Envelope.payload.status
            run_id = [string]$completed.Report.run_id
            saw_reboot_pause = [bool]$completed.SawReboot
            report = $reportPath
            component_count = @($verification.Envelope.payload.components).Count
        }
    }
    finally {
        if ($session) { Remove-PSSession $session }
        Restore-FixtureCheckpoint -VmName $TargetVmName -Checkpoint $TargetCheckpoint -LeaveOff
    }
}
Assert-VmContract
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
$sourceSession = $null
$runnerFailed = $false
$summary = $null
$summaryPath = $null
try {
    Restore-FixtureCheckpoint -VmName $SourceVmName -Checkpoint $SourceCheckpoint
    $sourceSession = New-GuestSession -VmName $SourceVmName
    try {
        $source = Initialize-SourcePackage -Session $sourceSession
        Copy-Item -LiteralPath $guestPackage -Destination (Join-Path $runDirectory 'source.reforge') -FromSession $sourceSession -Force
    }
    finally {
        if ($sourceSession) { Remove-PSSession $sourceSession }
        $sourceSession = $null
    }
    Restore-FixtureCheckpoint -VmName $SourceVmName -Checkpoint $SourceCheckpoint -LeaveOff

$results = New-Object System.Collections.Generic.List[object]
$script:cleanExpectedFragment = 'model = "reforge-fixture-model"'
$clean = Invoke-TargetScenario -Name 'clean-rebuild' -Mode rebuild -RequireVerified -After {
    param($session, $report)
    $null = $report
    $actual = Get-TargetConfig -Session $session
    if (-not $actual -or -not $actual.Contains($script:cleanExpectedFragment)) {
        throw 'Clean rebuild did not restore the selected Codex configuration.'
    }
}
$results.Add($clean)

$script:newerContent = "model = `"newer-target-model`"`r`nmodel_reasoning_effort = `"high`"`r`n"
$migration = Invoke-TargetScenario -Name 'nonempty-migration' -Mode migrate -Prepare {
    param($session)
    Install-TargetPackages -Session $session
    Set-TargetConfig -Session $session -Content $script:newerContent -FutureTimestamp | Out-Null
    $plan = Invoke-GuestReforge -Session $session -Scenario 'nonempty-migration' -Name 'plan' -Arguments @('plan', '--package', $guestPackage, '--mode', 'migrate')
    if (@($plan.Envelope.payload.plan.conflicts).Count -eq 0) {
        throw 'Migration plan did not expose the pre-existing target collision.'
    }
} -After {
    param($session, $report)
    $null = $report
    $actual = Get-TargetConfig -Session $session
    if ($actual -ne $script:newerContent) {
        throw 'Migration overwrote the newer target Codex configuration.'
    }
}
$results.Add($migration)

$script:lockProcessId = 0
$script:lockedContent = "model = `"locked-target`"`r`n"
$locked = Invoke-TargetScenario -Name 'locked-file' -Mode migrate -Prepare {
    param($session)
    Set-TargetConfig -Session $session -Content $script:lockedContent | Out-Null
    $script:lockProcessId = Start-ConfigLock -Session $session
} -After {
    param($session, $report)
    try {
        $explicit = ([int]$report.counts.waiting_for_user -gt 0) -or ([int]$report.counts.partial -gt 0) -or @($report.manual_actions).Count -gt 0
        if (-not $explicit) {
            throw 'Locked-file scenario did not expose a partial/manual outcome.'
        }
    }
    finally {
        if ($script:lockProcessId -gt 0) {
            Stop-ConfigLock -Session $session -ProcessId $script:lockProcessId
            $script:lockProcessId = 0
        }
    }
    $actual = Get-TargetConfig -Session $session
    if ($actual -ne $script:lockedContent) {
        throw 'Locked-file scenario changed the protected target configuration.'
    }
}
$results.Add($locked)

if (@($results | Where-Object { $_.saw_reboot_pause }).Count -eq 0) {
    throw "Controlled reboot package '$RebootPackageId' did not produce a REBOOT_REQUIRED pause in any restore scenario."
}

$summary = [ordered]@{
    schema_version = 1
    completed_at = (Get-Date).ToUniversalTime().ToString('o')
    source_vm = $SourceVmName
    target_vm = $TargetVmName
    fixture_package_ids = @($FixturePackageId)
    reboot_package_id = $RebootPackageId
    selected_component_count = @($source.SelectedIds).Count
    scenarios = @($results)
    hidden_failures = 0
}
$summaryPath = Join-Path $runDirectory 'summary.json'
}
catch {
    $runnerFailed = $true
    throw
}
finally {
    $resetFailures = New-Object System.Collections.Generic.List[string]
    if ($sourceSession) { Remove-PSSession $sourceSession -ErrorAction SilentlyContinue }
    foreach ($reset in @(
        @{ Name = $SourceVmName; Checkpoint = $SourceCheckpoint },
        @{ Name = $TargetVmName; Checkpoint = $TargetCheckpoint }
    )) {
        try {
            Restore-FixtureCheckpoint -VmName $reset.Name -Checkpoint $reset.Checkpoint -LeaveOff
        }
        catch {
            $resetFailures.Add("$($reset.Name): $($_.Exception.Message)")
        }
    }
    if ($resetFailures.Count -gt 0) {
        $message = "Failed to restore one or more fixture checkpoints: $($resetFailures -join '; ')"
        if ($runnerFailed) {
            Write-Warning $message
        }
        else {
            throw $message
        }
    }
    if (-not $runnerFailed) {
        if (-not $summary -or -not $summaryPath) {
            throw 'VM E2E completed without a summary payload.'
        }
        $summary | ConvertTo-Json -Depth 8 -Compress | Set-Content -LiteralPath $summaryPath -Encoding UTF8
        Write-Output $summaryPath
    }
}
