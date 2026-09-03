//! Structured, read-only Windows optional-feature observations.
//!
//! The live probe is one fixed PowerShell program. It contains no package,
//! path, environment, or user-controlled command text; its JSON output is
//! parsed and bounded before it reaches discovery.

use std::{collections::BTreeSet, ffi::OsString, time::Duration};

use reforge_domain::{ErrorEnvelope, ReforgeErrorCode};
use serde_json::Value;

use crate::{BuiltinExecutable, CommandSpec, TrustedExecutable};

const FEATURE_PROBE_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const FEATURE_PROBE_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_FEATURE_ROWS: usize = 256;
const MAX_FEATURE_NAME_CHARS: usize = 256;

const FEATURE_PROBE_SCRIPT: &str = concat!(
    "$names = @(",
    "'Microsoft-Windows-Subsystem-Linux',",
    "'VirtualMachinePlatform',",
    "'Microsoft-Hyper-V-All',",
    "'OpenSSH.Client~~~~0.0.1.0',",
    "'Containers-DisposableClientVM'",
    "); ",
    "$items = @(); ",
    "$optional = Get-WindowsOptionalFeature -Online -ErrorAction Stop; ",
    "$items += @($optional | Where-Object { $names -contains $_.FeatureName } | ForEach-Object { ",
    "[pscustomobject]@{ FeatureName = $_.FeatureName; State = [string]$_.State; RestartNeeded = ($_.RestartNeeded -eq $true) } }); ",
    "$devState = 'Disabled'; ",
    "$dev = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock' -Name AllowDevelopmentWithoutDevLicense -ErrorAction SilentlyContinue; ",
    "if ($dev -and $dev.AllowDevelopmentWithoutDevLicense -eq 1) { $devState = 'Enabled' }; ",
    "$items += [pscustomobject]@{ FeatureName = 'DeveloperMode'; State = $devState; RestartNeeded = $false }; ",
    "$items | ConvertTo-Json -Compress"
);

/// State reported by Windows optional-feature APIs.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FeatureState {
    Enabled,
    Disabled,
    EnablePending,
    DisablePending,
    Staged,
    Removed,
    Unknown,
}

impl FeatureState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "Enabled",
            Self::Disabled => "Disabled",
            Self::EnablePending => "EnablePending",
            Self::DisablePending => "DisablePending",
            Self::Staged => "Staged",
            Self::Removed => "Removed",
            Self::Unknown => "Unknown",
        }
    }
}

/// One bounded optional-feature observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureObservation {
    pub name: String,
    pub state: FeatureState,
    pub restart_required: bool,
}

/// Build the only feature process command permitted by the platform layer.
pub fn feature_probe_command() -> Result<CommandSpec, Box<ErrorEnvelope>> {
    CommandSpec::new(
        TrustedExecutable::Builtin(BuiltinExecutable::PowerShell),
        [
            OsString::from("-NoLogo"),
            OsString::from("-NoProfile"),
            OsString::from("-NonInteractive"),
            OsString::from("-Command"),
            OsString::from(FEATURE_PROBE_SCRIPT),
        ],
        FEATURE_PROBE_TIMEOUT,
        FEATURE_PROBE_OUTPUT_BYTES,
    )
}

/// Parse the bounded JSON output produced by [`feature_probe_command`].
///
/// PowerShell emits a single object for one row and an array for multiple
/// rows, so both shapes are accepted. Unknown feature states remain
/// `FeatureState::Unknown` and are therefore never suitable for an automatic
/// restore decision.
pub fn parse_feature_output(stdout: &str) -> Result<Vec<FeatureObservation>, Box<ErrorEnvelope>> {
    if stdout.is_empty() || stdout.len() > FEATURE_PROBE_OUTPUT_BYTES {
        return Err(parse_error(
            "feature probe output is outside the reviewed bound",
        ));
    }
    let document: Value = serde_json::from_str(stdout)
        .map_err(|_| parse_error("feature probe output is not valid JSON"))?;
    let rows = match document {
        Value::Array(rows) => rows,
        Value::Object(row) => vec![Value::Object(row)],
        _ => return Err(parse_error("feature probe JSON must be an object or array")),
    };
    if rows.len() > MAX_FEATURE_ROWS {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "feature probe returned too many rows",
        )));
    }

    let mut names = BTreeSet::new();
    let mut observations = Vec::with_capacity(rows.len());
    for row in rows {
        let object = row
            .as_object()
            .ok_or_else(|| parse_error("feature probe row is not an object"))?;
        let name = required_string(object, &["FeatureName", "feature_name", "name"])?;
        validate_name(&name)?;
        if !names.insert(name.to_ascii_lowercase()) {
            return Err(parse_error(
                "feature probe contains duplicate feature names",
            ));
        }
        let state = required_string(object, &["State", "state"])?;
        let restart_required = optional_bool(object, &["RestartNeeded", "restart_needed"])?;
        observations.push(FeatureObservation {
            name,
            state: parse_state(&state),
            restart_required,
        });
    }
    Ok(observations)
}

fn required_string(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Result<String, Box<ErrorEnvelope>> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| parse_error("feature probe row is missing required text"))
}

fn optional_bool(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Result<bool, Box<ErrorEnvelope>> {
    let Some(value) = keys.iter().find_map(|key| object.get(*key)) else {
        return Ok(false);
    };
    if let Some(value) = value.as_bool() {
        return Ok(value);
    }
    if let Some(value) = value.as_str() {
        return match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" | "" => Ok(false),
            _ => Err(parse_error("feature probe restart flag is not boolean")),
        };
    }
    Err(parse_error("feature probe restart flag is not boolean"))
}

fn validate_name(name: &str) -> Result<(), Box<ErrorEnvelope>> {
    if name.chars().count() > MAX_FEATURE_NAME_CHARS
        || name.chars().any(|character| character.is_control())
    {
        return Err(parse_error("feature probe name is invalid"));
    }
    Ok(())
}

fn parse_state(value: &str) -> FeatureState {
    match value.trim().to_ascii_lowercase().as_str() {
        "enabled" => FeatureState::Enabled,
        "disabled" => FeatureState::Disabled,
        "enablepending" | "enable_pending" => FeatureState::EnablePending,
        "disablepending" | "disable_pending" => FeatureState::DisablePending,
        "staged" => FeatureState::Staged,
        "removed" => FeatureState::Removed,
        _ => FeatureState::Unknown,
    }
}

fn parse_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::ProviderParseFailed,
            "Windows feature probe output could not be parsed",
        )
        .with_technical_detail(detail),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_and_multiple_powershell_json_shapes() {
        let single = parse_feature_output(
            r#"{"FeatureName":"DeveloperMode","State":"Enabled","RestartNeeded":false}"#,
        )
        .expect("single feature object");
        assert_eq!(single[0].state, FeatureState::Enabled);

        let multiple = parse_feature_output(
            r#"[{"FeatureName":"VirtualMachinePlatform","State":"EnablePending","RestartNeeded":true},{"FeatureName":"Mystery","State":"Future","RestartNeeded":false}]"#,
        )
        .expect("feature array");
        assert_eq!(multiple[0].state, FeatureState::EnablePending);
        assert_eq!(multiple[1].state, FeatureState::Unknown);
        assert!(multiple[0].restart_required);
    }

    #[test]
    fn malformed_or_duplicate_feature_rows_fail_closed() {
        assert!(parse_feature_output("[]junk").is_err());
        assert!(
            parse_feature_output(
                r#"[{"FeatureName":"X","State":"Enabled"},{"FeatureName":"x","State":"Disabled"}]"#,
            )
            .is_err()
        );
    }

    #[test]
    fn feature_command_contains_only_fixed_provider_script() {
        let command = feature_probe_command().expect("feature command");
        assert!(command.args.iter().any(|arg| arg == FEATURE_PROBE_SCRIPT));
    }
}
