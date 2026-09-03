#![cfg(windows)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} must be set for the ignored Hyper-V E2E test"))
}

fn absolute_existing_file(name: &str) -> PathBuf {
    let path = PathBuf::from(required_env(name));
    assert!(path.is_absolute(), "{name} must be an absolute path");
    assert!(path.is_file(), "{name} does not name an existing file");
    path
}

fn default_runner() -> PathBuf {
    let root = env::current_dir().expect("read current repository directory");
    root.join("tests").join("vm").join("Run-E2E.ps1")
}

fn optional_env(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

#[test]
#[ignore = "requires elevated Hyper-V, disposable Windows 11 VMs, and DPAPI-protected fixture credentials"]
fn hyper_v_source_to_target_e2e() {
    let runner = env::var_os("REFORGE_E2E_RUNNER")
        .map(PathBuf::from)
        .unwrap_or_else(default_runner);
    assert!(
        runner.is_absolute(),
        "REFORGE_E2E_RUNNER must be absolute when set"
    );
    assert!(
        runner.is_file(),
        "VM E2E runner is missing at {}",
        runner.display()
    );

    let password_file = absolute_existing_file("REFORGE_E2E_PASSWORD_FILE");
    let artifact_root = PathBuf::from(required_env("REFORGE_E2E_ARTIFACT_ROOT"));
    assert!(
        artifact_root.is_absolute(),
        "REFORGE_E2E_ARTIFACT_ROOT must be an absolute path"
    );

    let username = required_env("REFORGE_E2E_USERNAME");
    let fixture_packages = required_env("REFORGE_E2E_FIXTURE_PACKAGE_IDS");
    assert!(
        fixture_packages
            .split(';')
            .all(|value| !value.trim().is_empty()),
        "REFORGE_E2E_FIXTURE_PACKAGE_IDS must be a semicolon-separated list without empty IDs"
    );
    let reboot_package = required_env("REFORGE_E2E_REBOOT_PACKAGE_ID");
    let powershell = optional_env("REFORGE_E2E_POWERSHELL", "powershell.exe");

    let command = concat!(
        "$ErrorActionPreference = 'Stop'; ",
        "$protected = (Get-Content -LiteralPath $env:REFORGE_E2E_PASSWORD_FILE -Raw).Trim(); ",
        "$secure = $protected | ConvertTo-SecureString; ",
        "$credential = [pscredential]::new($env:REFORGE_E2E_USERNAME, $secure); ",
        "$parameters = @{ ",
        "Credential = $credential; ",
        "ArtifactRoot = $env:REFORGE_E2E_ARTIFACT_ROOT; ",
        "FixturePackageId = [string[]]($env:REFORGE_E2E_FIXTURE_PACKAGE_IDS -split ';'); ",
        "RebootPackageId = $env:REFORGE_E2E_REBOOT_PACKAGE_ID; ",
        "SourceVmName = $env:REFORGE_E2E_SOURCE_VM; ",
        "TargetVmName = $env:REFORGE_E2E_TARGET_VM; ",
        "SourceCheckpoint = $env:REFORGE_E2E_SOURCE_CHECKPOINT; ",
        "TargetCheckpoint = $env:REFORGE_E2E_TARGET_CHECKPOINT ",
        "}; ",
        "& $env:REFORGE_E2E_RUNNER @parameters"
    );

    let output = Command::new(powershell)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ])
        .env("REFORGE_E2E_RUNNER", &runner)
        .env("REFORGE_E2E_PASSWORD_FILE", &password_file)
        .env("REFORGE_E2E_ARTIFACT_ROOT", &artifact_root)
        .env("REFORGE_E2E_USERNAME", username)
        .env("REFORGE_E2E_FIXTURE_PACKAGE_IDS", fixture_packages)
        .env("REFORGE_E2E_REBOOT_PACKAGE_ID", reboot_package)
        .env(
            "REFORGE_E2E_SOURCE_VM",
            optional_env("REFORGE_E2E_SOURCE_VM", "Reforge-E2E-Source"),
        )
        .env(
            "REFORGE_E2E_TARGET_VM",
            optional_env("REFORGE_E2E_TARGET_VM", "Reforge-E2E-Target"),
        )
        .env(
            "REFORGE_E2E_SOURCE_CHECKPOINT",
            optional_env("REFORGE_E2E_SOURCE_CHECKPOINT", "SourceReady"),
        )
        .env(
            "REFORGE_E2E_TARGET_CHECKPOINT",
            optional_env("REFORGE_E2E_TARGET_CHECKPOINT", "CleanBaseline"),
        )
        .output()
        .expect("launch PowerShell VM E2E runner");

    assert!(
        output.status.success(),
        "VM E2E runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary_line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .expect("runner prints summary path")
        .trim()
        .to_owned();
    let summary_path = Path::new(&summary_line);
    assert!(
        summary_path.is_absolute(),
        "runner summary path must be absolute"
    );
    let summary = fs::read_to_string(summary_path).expect("read VM E2E summary");
    assert!(summary.contains("\"schema_version\":1"));
    assert!(summary.contains("\"hidden_failures\":0"));
    for scenario in ["clean-rebuild", "nonempty-migration", "locked-file"] {
        assert!(
            summary.contains(scenario),
            "summary omitted scenario {scenario}"
        );
    }
}
