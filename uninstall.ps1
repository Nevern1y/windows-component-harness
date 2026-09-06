[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

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

function Test-ReparsePoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $item = Get-Item -LiteralPath $Path -Force
    return ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
}

if (-not $env:LOCALAPPDATA) {
    throw 'LOCALAPPDATA is not available; cannot locate the user-level Reforge installation.'
}
$reforgeRoot = Join-Path $env:LOCALAPPDATA 'Reforge'
$installDir = [System.IO.Path]::GetFullPath((Join-Path $reforgeRoot 'bin'))
$manifestPath = Join-Path $installDir '.reforge-install.json'

if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    Write-Host "No installer-owned Reforge installation was found at $installDir. Nothing was changed."
    Write-Host 'Existing Reforge state and backup packages were kept.'
    exit 0
}
if ((Test-ReparsePoint -Path $reforgeRoot) -or
    (Test-ReparsePoint -Path $installDir) -or
    (Test-ReparsePoint -Path $manifestPath)) {
    throw 'The Reforge install path or manifest is a reparse point. Uninstall stopped without following it.'
}

try {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $schemaProperty = $manifest.PSObject.Properties['schemaVersion']
    $directoryProperty = $manifest.PSObject.Properties['installDirectory']
    $filesProperty = $manifest.PSObject.Properties['files']
    $pathProperty = $manifest.PSObject.Properties['pathEntry']
    $ownershipProperty = $manifest.PSObject.Properties['pathEntryAddedByInstaller']
    if ($null -eq $schemaProperty -or [int] $schemaProperty.Value -ne 1 -or
        $null -eq $directoryProperty -or
        -not (Test-EquivalentPathEntry -Left ([string] $directoryProperty.Value) -Right $installDir) -or
        $null -eq $filesProperty -or $null -eq $pathProperty -or
        -not (Test-EquivalentPathEntry -Left ([string] $pathProperty.Value) -Right $installDir) -or
        $null -eq $ownershipProperty -or -not ($ownershipProperty.Value -is [bool])) {
        throw 'Unexpected schema, ownership data, or install directory.'
    }
} catch {
    throw "The Reforge install manifest is invalid. No files or PATH entries were changed. $($_.Exception.Message)"
}

$allowedFiles = @('reforge.exe', 'reforge.cmd', 'reforge-launch.ps1', 'uninstall.ps1')
$managedFiles = @()
$seenFiles = @{}
try {
    foreach ($record in @($filesProperty.Value)) {
        $nameProperty = $record.PSObject.Properties['name']
        $hashProperty = $record.PSObject.Properties['sha256']
        if ($null -eq $nameProperty -or $null -eq $hashProperty) {
            throw 'A managed-file record is incomplete.'
        }
        $name = [string] $nameProperty.Value
        $hash = ([string] $hashProperty.Value).ToLowerInvariant()
        if ($allowedFiles -notcontains $name -or
            [System.IO.Path]::GetFileName($name) -ne $name -or
            $hash -notmatch '^[0-9a-f]{64}$' -or
            $seenFiles.ContainsKey($name)) {
            throw "Invalid managed-file record for '$name'."
        }
        $seenFiles[$name] = $true
        $managedFiles += [pscustomobject] @{ Name = $name; Sha256 = $hash }
    }
    if ($managedFiles.Count -ne $allowedFiles.Count) {
        throw 'The managed-file list is incomplete.'
    }
    foreach ($expectedName in $allowedFiles) {
        if (-not $seenFiles.ContainsKey($expectedName)) {
            throw "The managed-file list is missing '$expectedName'."
        }
    }
} catch {
    throw "The Reforge install manifest cannot be trusted. No files or PATH entries were changed. $($_.Exception.Message)"
}

$preservedFiles = @()
$removalFailures = @()
$removalCandidates = @()
foreach ($managedFile in $managedFiles) {
    $path = Join-Path $installDir $managedFile.Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        continue
    }
    if (Test-ReparsePoint -Path $path) {
        $preservedFiles += $managedFile.Name
        Write-Warning "Preserved reparse-point file: $path"
        continue
    }
    try {
        $currentHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    } catch {
        $preservedFiles += $managedFile.Name
        Write-Warning "Preserved unreadable file '$path': $($_.Exception.Message)"
        continue
    }
    if ($currentHash -ne $managedFile.Sha256) {
        $preservedFiles += $managedFile.Name
        Write-Warning "Preserved modified file: $path"
        continue
    }
    $removalCandidates += [pscustomobject] @{ Name = $managedFile.Name; Path = $path }
}


$pathEntryRemoved = $false
$pathEntryAmbiguous = $false
if ([bool] $ownershipProperty.Value) {
    $currentPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not [string]::IsNullOrEmpty($currentPath)) {
        $entries = New-Object 'System.Collections.Generic.List[string]'
        $matchingIndexes = @()
        foreach ($entry in $currentPath.Split([char] ';')) {
            $entries.Add($entry)
            if (Test-EquivalentPathEntry -Left $entry -Right ([string] $pathProperty.Value)) {
                $matchingIndexes += $entries.Count - 1
            }
        }
        if ($matchingIndexes.Count -eq 1) {
            $entries.RemoveAt($matchingIndexes[0])
            $updatedPath = $null
            if ($entries.Count -gt 0) {
                $updatedPath = $entries -join ';'
            }
            [Environment]::SetEnvironmentVariable('Path', $updatedPath, 'User')
            $pathEntryRemoved = $true
        } elseif ($matchingIndexes.Count -gt 1) {
            $pathEntryAmbiguous = $true
            Write-Warning 'Multiple equivalent Reforge PATH entries exist. Uninstall preserved all of them rather than remove an entry of uncertain ownership.'
        }
    }
}
$ordinaryCandidates = @($removalCandidates | Where-Object { $_.Name -ne 'uninstall.ps1' })
$uninstallerCandidate = @($removalCandidates | Where-Object { $_.Name -eq 'uninstall.ps1' } | Select-Object -First 1)
foreach ($candidate in $ordinaryCandidates) {
    try {
        Remove-Item -LiteralPath $candidate.Path -Force
    } catch {
        $removalFailures += $candidate.Name
        Write-Warning "Could not remove installer-owned file '$($candidate.Path)': $($_.Exception.Message)"
    }
}
if ($removalFailures.Count -eq 0 -and $uninstallerCandidate.Count -eq 1) {
    try {
        Remove-Item -LiteralPath $uninstallerCandidate[0].Path -Force
    } catch {
        $removalFailures += $uninstallerCandidate[0].Name
        Write-Warning "Could not remove installer-owned file '$($uninstallerCandidate[0].Path)': $($_.Exception.Message)"
    }
}


if ($removalFailures.Count -eq 0) {
    Remove-Item -LiteralPath $manifestPath -Force
    if ((Test-Path -LiteralPath $installDir -PathType Container) -and
        @(Get-ChildItem -LiteralPath $installDir -Force).Count -eq 0) {
        Remove-Item -LiteralPath $installDir -Force
    }
} else {
    Write-Warning 'The install manifest was kept so removal can be retried.'
}

if ($pathEntryRemoved) {
    Write-Host 'Removed the one user PATH entry recorded as installer-owned.'
} elseif ($pathEntryAmbiguous) {
    Write-Host 'The user PATH was left unchanged because equivalent entries could not be distinguished safely.'
} elseif ([bool] $ownershipProperty.Value) {
    Write-Host 'The recorded installer-owned PATH entry was already absent.'
} else {
    Write-Host 'The user PATH was not changed because the installer did not add its existing entry.'
}
if ($preservedFiles.Count -gt 0) {
    Write-Host "Preserved files that no longer matched the installer manifest: $($preservedFiles -join ', ')."
}
if ($removalFailures.Count -eq 0) {
    Write-Host 'Removed installer-owned Reforge files that still matched the install manifest.'
} else {
    Write-Host "Files still awaiting removal: $($removalFailures -join ', ')."
}
Write-Host 'Existing Reforge state, backup packages, and unrelated files were kept.'
