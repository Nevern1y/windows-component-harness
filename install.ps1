[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot

function Get-NormalizedPathEntry {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string] $Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }
    $trimmed = $Value.Trim().Trim([char] '"')
    $expanded = [Environment]::ExpandEnvironmentVariables($trimmed)
    try {
        return [System.IO.Path]::GetFullPath($expanded).TrimEnd([char] '\')
    } catch {
        return $expanded.TrimEnd([char] '\')
    }
}

function Test-EquivalentPathEntry {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string] $Left,
        [AllowEmptyString()]
        [string] $Right
    )

    return [string]::Equals(
        (Get-NormalizedPathEntry -Value $Left),
        (Get-NormalizedPathEntry -Value $Right),
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-NotReparsePoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [Parameter(Mandatory = $true)]
        [string] $Description
    )

    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Description must not be a symbolic link or reparse point: $Path"
        }
    }
}

function Copy-ManagedFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Source,
        [Parameter(Mandatory = $true)]
        [string] $Destination
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Required distribution file is missing: $Source"
    }
    $sourcePath = [System.IO.Path]::GetFullPath($Source)
    $destinationPath = [System.IO.Path]::GetFullPath($Destination)
    if ([string]::Equals(
        $sourcePath,
        $destinationPath,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        return
    }
    if (Test-Path -LiteralPath $destinationPath -PathType Container) {
        throw "An install destination is a directory instead of a file: $destinationPath"
    }
    Assert-NotReparsePoint -Path $destinationPath -Description 'An install destination'

    $temporary = Join-Path (Split-Path -Parent $destinationPath) `
        ('.' + [System.IO.Path]::GetFileName($destinationPath) + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        Copy-Item -LiteralPath $sourcePath -Destination $temporary -Force
        if (Test-Path -LiteralPath $destinationPath -PathType Leaf) {
            [System.IO.File]::Replace($temporary, $destinationPath, [System.Management.Automation.Language.NullString]::Value)
        } else {
            [System.IO.File]::Move($temporary, $destinationPath)
        }
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Write-ManifestAtomically {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [Parameter(Mandatory = $true)]
        [string] $Json
    )

    Assert-NotReparsePoint -Path $Path -Description 'The install manifest'
    $temporary = Join-Path (Split-Path -Parent $Path) `
        ('.manifest.' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
        [System.IO.File]::WriteAllText($temporary, $Json, $utf8NoBom)
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [System.IO.File]::Replace($temporary, $Path, [System.Management.Automation.Language.NullString]::Value)
        } else {
            [System.IO.File]::Move($temporary, $Path)
        }
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

if (-not $env:LOCALAPPDATA) {
    throw 'LOCALAPPDATA is not available; cannot choose a user-level install directory.'
}

$launcherPath = Join-Path $repoRoot 'reforge-launch.ps1'
if (-not (Test-Path -LiteralPath $launcherPath -PathType Leaf)) {
    throw "Reforge launcher not found: $launcherPath"
}
. $launcherPath
$sourceBinary = Resolve-ReforgeCliBinary -Root $repoRoot
$reforgeRoot = Join-Path $env:LOCALAPPDATA 'Reforge'
$installDir = Join-Path $reforgeRoot 'bin'
Assert-NotReparsePoint -Path $reforgeRoot -Description 'The Reforge user directory'
Assert-NotReparsePoint -Path $installDir -Description 'The Reforge install directory'
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
$installDir = [System.IO.Path]::GetFullPath($installDir)
$manifestPath = Join-Path $installDir '.reforge-install.json'

$previousPathOwnership = $false
if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    Assert-NotReparsePoint -Path $manifestPath -Description 'The install manifest'
    try {
        $previousManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $schemaProperty = $previousManifest.PSObject.Properties['schemaVersion']
        $directoryProperty = $previousManifest.PSObject.Properties['installDirectory']
        $ownershipProperty = $previousManifest.PSObject.Properties['pathEntryAddedByInstaller']
        if ($null -eq $schemaProperty -or [int] $schemaProperty.Value -ne 1 -or
            $null -eq $directoryProperty -or
            -not (Test-EquivalentPathEntry -Left ([string] $directoryProperty.Value) -Right $installDir) -or
            $null -eq $ownershipProperty -or -not ($ownershipProperty.Value -is [bool])) {
            throw 'The existing install manifest has an unexpected schema or install directory.'
        }
        $previousPathOwnership = [bool] $ownershipProperty.Value
    } catch {
        throw "The existing Reforge install manifest is invalid. No files or PATH entries were changed. $($_.Exception.Message)"
    }
}

$managedSources = @(
    [pscustomobject] @{ Name = 'reforge.exe'; Source = $sourceBinary },
    [pscustomobject] @{ Name = 'reforge.cmd'; Source = (Join-Path $repoRoot 'reforge.cmd') },
    [pscustomobject] @{ Name = 'reforge-launch.ps1'; Source = $launcherPath },
    [pscustomobject] @{ Name = 'uninstall.ps1'; Source = (Join-Path $repoRoot 'uninstall.ps1') }
)
$installedFiles = @()
foreach ($managedSource in $managedSources) {
    $destination = Join-Path $installDir $managedSource.Name
    Copy-ManagedFile -Source $managedSource.Source -Destination $destination
    $installedFiles += [ordered] @{
        name = $managedSource.Name
        sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$currentPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$pathEntries = @()
if (-not [string]::IsNullOrEmpty($currentPath)) {
    $pathEntries = @($currentPath.Split([char] ';'))
}
$matchingPathEntries = @($pathEntries | Where-Object {
    Test-EquivalentPathEntry -Left $_ -Right $installDir
})
$pathAlreadyPresent = $matchingPathEntries.Count -gt 0
$pathEntryAdded = -not $pathAlreadyPresent
$pathOwnedByInstaller = $pathEntryAdded -or ($previousPathOwnership -and $matchingPathEntries.Count -eq 1)
if ($previousPathOwnership -and $matchingPathEntries.Count -gt 1) {
    Write-Warning 'Multiple equivalent Reforge PATH entries exist and ownership is ambiguous. None will be removed by uninstall.'
}

$manifest = [ordered] @{
    schemaVersion = 1
    installDirectory = $installDir
    files = $installedFiles
    pathEntry = $installDir
    pathEntryAddedByInstaller = $pathOwnedByInstaller
}
$manifestJson = $manifest | ConvertTo-Json -Depth 5
Write-ManifestAtomically -Path $manifestPath -Json $manifestJson

if ($pathEntryAdded) {
    if ([string]::IsNullOrEmpty($currentPath)) {
        $updatedPath = $installDir
    } elseif ($currentPath.EndsWith(';', [System.StringComparison]::Ordinal)) {
        $updatedPath = $currentPath + $installDir
    } else {
        $updatedPath = $currentPath + ';' + $installDir
    }
    [Environment]::SetEnvironmentVariable('Path', $updatedPath, 'User')
    Write-Host "Installed Reforge in $installDir and added it to the user PATH."
} elseif ($pathOwnedByInstaller) {
    Write-Host "Updated Reforge in $installDir; its installer-managed PATH entry was already present."
} else {
    Write-Host "Installed Reforge in $installDir. The equivalent user PATH entry already existed and was left untouched."
}

Write-Host "Open a new terminal, then run 'reforge'."
Write-Host "Uninstall with: & '$installDir\uninstall.ps1'"
Write-Host 'Installation is user-level. Reforge state and backup packages are not modified.'
