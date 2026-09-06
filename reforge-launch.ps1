[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true, Position = 0)]
    [string[]] $Arguments = @()
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-ReforgeWindowsExecutable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }

    $stream = $null
    $reader = $null
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        if ($stream.Length -lt 64) {
            return $false
        }

        $reader = New-Object -TypeName System.IO.BinaryReader -ArgumentList $stream
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            return $false
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or ([int64] $peOffset + 6) -gt $stream.Length) {
            return $false
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            return $false
        }
        return $reader.ReadUInt16() -eq 0x8664
    } catch {
        return $false
    } finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        } elseif ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Get-ReforgePinnedToolchain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root
    )

    $toolchainPath = Join-Path $Root 'rust-toolchain.toml'
    if (-not (Test-Path -LiteralPath $toolchainPath -PathType Leaf)) {
        throw "Pinned toolchain file not found: $toolchainPath"
    }
    $toolchainText = Get-Content -LiteralPath $toolchainPath -Raw
    $channel = [regex]::Match(
        $toolchainText,
        '^\s*channel\s*=\s*"([^"]+)"\s*$',
        [System.Text.RegularExpressions.RegexOptions]::Multiline
    )
    if (-not $channel.Success -or $channel.Groups[1].Value -notmatch '^\d+\.\d+\.\d+$') {
        throw 'rust-toolchain.toml does not contain an exact Rust version channel.'
    }
    return $channel.Groups[1].Value
}

function Resolve-ReforgeCliBinary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root
    )

    $rootPath = [System.IO.Path]::GetFullPath($Root)
    $targetTriple = 'x86_64-pc-windows-msvc'
    $candidates = @(
        (Join-Path $rootPath 'reforge.exe'),
        (Join-Path $rootPath "target\$targetTriple\release\reforge.exe"),
        (Join-Path $rootPath 'target\release\reforge.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-ReforgeWindowsExecutable -Path $candidate) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
    }

    $requiredSourceFiles = @(
        (Join-Path $rootPath 'Cargo.toml'),
        (Join-Path $rootPath 'Cargo.lock'),
        (Join-Path $rootPath 'rust-toolchain.toml'),
        (Join-Path $rootPath 'crates\reforge-cli\Cargo.toml')
    )
    $missingSourceFiles = @($requiredSourceFiles | Where-Object {
        -not (Test-Path -LiteralPath $_ -PathType Leaf)
    })
    if ($missingSourceFiles.Count -ne 0) {
        throw @"
No runnable Windows x64 reforge.exe was found beside the launcher.
This does not appear to be a complete source checkout, so Reforge will not download or build anything automatically.
Extract every file from the Windows x64 release archive again; reforge.exe, reforge.cmd, and reforge-launch.ps1 must remain together.
"@
    }

    $pinnedToolchain = Get-ReforgePinnedToolchain -Root $rootPath
    $rustup = Get-Command rustup.exe -ErrorAction SilentlyContinue
    $buildProgram = $null
    $buildArguments = @()

    if ($null -ne $rustup) {
        $toolchainLines = @(& $rustup.Source toolchain list 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw 'rustup could not list installed toolchains.'
        }
        $toolchainPattern = (
            '^' + [regex]::Escape($pinnedToolchain) +
            '(?:-' + [regex]::Escape($targetTriple) + ')?(?:\s|$)'
        )
        $toolchainInstalled = @($toolchainLines | Where-Object {
            $_.ToString() -match $toolchainPattern
        }).Count -gt 0
        if (-not $toolchainInstalled) {
            throw @"
Reforge source is present, but the pinned Rust toolchain $pinnedToolchain is not installed.
Install it explicitly with:
  rustup toolchain install $pinnedToolchain --profile minimal --target $targetTriple
Also install Visual Studio 2022 Build Tools with "Desktop development with C++" and a Windows SDK, then run .\reforge again.
The launcher does not download a release executable or silently install prerequisites.
"@
        }
        $buildProgram = $rustup.Source
        $buildArguments = @(
            'run', $pinnedToolchain, 'cargo', 'build', '--locked',
            '-p', 'reforge-cli', '--release', '--target', $targetTriple
        )
    } else {
        $cargo = Get-Command cargo.exe -ErrorAction SilentlyContinue
        $rustc = Get-Command rustc.exe -ErrorAction SilentlyContinue
        if ($null -eq $cargo -or $null -eq $rustc) {
            throw @"
Reforge source is present, but a Rust toolchain was not found.
Install rustup and the pinned Rust toolchain $pinnedToolchain for $targetTriple.
Also install Visual Studio 2022 Build Tools with "Desktop development with C++" and a Windows SDK, then run .\reforge again.
The launcher does not download a release executable or silently install prerequisites.
"@
        }
        $rustVersion = (& $rustc.Source --version 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $rustVersion -notmatch (
            '^rustc\s+' + [regex]::Escape($pinnedToolchain) + '(?:\s|$)'
        )) {
            throw "Reforge requires rustc $pinnedToolchain; the active compiler reported '$rustVersion'."
        }
        $buildProgram = $cargo.Source
        $buildArguments = @(
            'build', '--locked', '-p', 'reforge-cli', '--release',
            '--target', $targetTriple
        )
    }

    Write-Host "No ready Reforge binary was found. Building the CLI with pinned Rust $pinnedToolchain..."
    $build = Start-Process -FilePath $buildProgram -ArgumentList $buildArguments `
        -WorkingDirectory $rootPath -NoNewWindow -Wait -PassThru
    if ($build.ExitCode -ne 0) {
        throw @"
Reforge build failed with exit code $($build.ExitCode).
Confirm that Visual Studio 2022 Build Tools includes "Desktop development with C++" and a Windows SDK. Then rerun:
  cargo build --locked -p reforge-cli --release --target $targetTriple
"@
    }

    $builtBinary = Join-Path $rootPath "target\$targetTriple\release\reforge.exe"
    if (-not (Test-ReforgeWindowsExecutable -Path $builtBinary)) {
        throw "The build completed without producing a runnable Windows x64 binary at $builtBinary."
    }
    return [System.IO.Path]::GetFullPath($builtBinary)
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        $binary = Resolve-ReforgeCliBinary -Root $PSScriptRoot
    } catch {
        [Console]::Error.WriteLine("reforge: $($_.Exception.Message)")
        exit 1
    }

    & $binary @Arguments
    exit $LASTEXITCODE
}
