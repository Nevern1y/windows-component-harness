//! Conservative redaction for diagnostics and provider output.
//!
//! Redaction is deliberately fail-closed: malformed control data, invalid
//! UTF-8, malformed private-key material, and over-large recursive JSON are
//! discarded rather than returned to a user-visible boundary.

use std::{borrow::Cow, str};

use serde_json::{Map, Value};

/// Default maximum size of one redacted diagnostic text value.
pub const DEFAULT_MAX_REDACTED_BYTES: usize = 16 * 1024;

/// Maximum recursive JSON depth accepted by the default policy.
pub const DEFAULT_MAX_REDACTION_DEPTH: usize = 32;

const REDACTED: &str = "<REDACTED>";
const REDACTED_PATH: &str = "<PATH>";
const TRUNCATED: &str = "…[truncated]";

const SENSITIVE_KEYS: &[&str] = &[
    "apikey",
    "api_key",
    "api-key",
    "accesstoken",
    "access_token",
    "auth_token",
    "authtoken",
    "refresh_token",
    "refreshtoken",
    "client_secret",
    "clientsecret",
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "private_key",
    "privatekey",
    "credential",
    "credentials",
];

const PATH_KEYS: &[&str] = &[
    "path",
    "sourcepath",
    "destination",
    "cwd",
    "workingdirectory",
    "installpath",
    "executablepath",
    "workingdir",
];

const SECRET_PREFIXES: &[&str] = &[
    "github_pat_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "sk-",
    "ctx7sk-",
    "npm_",
    "pypi-",
    "hf_",
    "AKIA",
    "ASIA",
    "AIza",
];

/// Redaction limits used for one diagnostic boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactionPolicy {
    max_bytes: usize,
    max_depth: usize,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_REDACTED_BYTES,
            max_depth: DEFAULT_MAX_REDACTION_DEPTH,
        }
    }
}

impl RedactionPolicy {
    /// Create a policy with a maximum UTF-8 byte length for each text value.
    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            ..Self::default()
        }
    }

    /// Create a policy with explicit text and recursive-depth limits.
    pub fn with_limits(max_bytes: usize, max_depth: usize) -> Self {
        Self {
            max_bytes,
            max_depth,
        }
    }

    /// Return the text limit configured for this policy.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Return the recursive JSON depth limit configured for this policy.
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Classify secret-bearing keys without treating diagnostic path keys as secrets.
    pub fn is_sensitive_key(&self, key: &str) -> bool {
        is_sensitive_key(&normalize_key(key))
    }

    /// Redact known secrets, paths, and token patterns from text.
    pub fn redact_text(&self, input: &str) -> Option<String> {
        redact_text_with_policy(input, self, true)
    }

    /// Show local paths in an interactive terminal while retaining secret filtering.
    /// Diagnostics, logs and reports must keep using `redact_text` instead.
    pub fn redact_interactive_text(&self, input: &str) -> Option<String> {
        redact_text_with_policy(input, self, false)
    }

    /// Recursively redact a JSON diagnostic and enforce the policy bounds.
    pub fn redact_json(&self, input: &Value) -> Option<Value> {
        let redacted = redact_json_value(input, self, 0)?;
        let encoded = serde_json::to_vec(&redacted).ok()?;
        if encoded.len() > self.max_bytes {
            return None;
        }
        Some(redacted)
    }

    /// Parse, redact, and serialize a JSON diagnostic.
    pub fn redact_json_str(&self, input: &str) -> Option<String> {
        let value: Value = serde_json::from_str(input).ok()?;
        let redacted = self.redact_json(&value)?;
        serde_json::to_string(&redacted).ok()
    }

    /// Decode and redact bounded provider stdout and stderr independently.
    pub fn redact_provider_output(&self, stdout: &[u8], stderr: &[u8]) -> RedactedProviderOutput {
        RedactedProviderOutput {
            stdout: str::from_utf8(stdout)
                .ok()
                .and_then(|value| self.redact_text(value)),
            stderr: str::from_utf8(stderr)
                .ok()
                .and_then(|value| self.redact_text(value)),
        }
    }
}

/// Provider output after UTF-8 validation, redaction, and per-stream bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedProviderOutput {
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

/// Redact text using the default fail-closed policy.
pub fn redact_text(input: &str) -> Option<String> {
    RedactionPolicy::default().redact_text(input)
}

/// Redact JSON recursively using the default fail-closed policy.
pub fn redact_json(input: &Value) -> Option<Value> {
    RedactionPolicy::default().redact_json(input)
}

/// Decode and redact provider output using the default policy.
pub fn redact_provider_output(stdout: &[u8], stderr: &[u8]) -> RedactedProviderOutput {
    RedactionPolicy::default().redact_provider_output(stdout, stderr)
}

/// Validate a context ID before putting it into an error envelope.
pub fn sanitize_context_id(input: &str) -> Option<String> {
    if input.is_empty() || input.len() > 128 || !input.is_ascii() {
        return None;
    }
    if input
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || b"-_.:~".contains(&byte)))
    {
        return None;
    }
    Some(input.to_owned())
}

fn redact_text_with_policy(
    input: &str,
    policy: &RedactionPolicy,
    hide_paths: bool,
) -> Option<String> {
    if input
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return None;
    }

    let mut output = String::with_capacity(input.len().min(policy.max_bytes));
    let mut index = 0;
    while index < input.len() {
        if let Some(end) = match_private_key(input, index)? {
            output.push_str(REDACTED);
            index = end;
            continue;
        }
        if let Some(end) = match_sensitive_assignment(input, index)? {
            output.push_str(REDACTED);
            index = end;
            continue;
        }
        if let Some(end) = match_bearer_token(input, index) {
            output.push_str(REDACTED);
            index = end;
            continue;
        }
        if let Some(end) = match_prefixed_secret(input, index) {
            output.push_str(REDACTED);
            index = end;
            continue;
        }
        if hide_paths && let Some(end) = match_path(input, index) {
            output.push_str(REDACTED_PATH);
            index = end;
            continue;
        }

        let character = input[index..].chars().next()?;
        output.push(character);
        index += character.len_utf8();
    }

    Some(truncate_utf8(&output, policy.max_bytes))
}

fn redact_json_value(input: &Value, policy: &RedactionPolicy, depth: usize) -> Option<Value> {
    if depth > policy.max_depth {
        return None;
    }
    match input {
        Value::Null | Value::Bool(_) | Value::Number(_) => Some(input.clone()),
        Value::String(value) => policy.redact_text(value).map(Value::String),
        Value::Array(values) => values
            .iter()
            .map(|value| redact_json_value(value, policy, depth + 1))
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        Value::Object(values) => {
            let mut redacted = Map::with_capacity(values.len());
            for (key, value) in values {
                let normalized_key = normalize_key(key);
                let value = if is_sensitive_key(&normalized_key) {
                    Value::String(REDACTED.to_owned())
                } else if is_path_key(&normalized_key) {
                    match value {
                        Value::String(_) => Value::String(REDACTED_PATH.to_owned()),
                        _ => redact_json_value(value, policy, depth + 1)?,
                    }
                } else {
                    redact_json_value(value, policy, depth + 1)?
                };
                redacted.insert(key.clone(), value);
            }
            Some(Value::Object(redacted))
        }
    }
}

fn match_private_key(input: &str, index: usize) -> Option<Option<usize>> {
    if !is_boundary_before(input, index) || !starts_with_at(input, index, "-----BEGIN ") {
        return Some(None);
    }
    let body_start = index + "-----BEGIN ".len();
    let end_marker = input[body_start..].find("-----END ")?;
    let end_start = body_start + end_marker;
    let end_line = input[end_start..].find("-----")?;
    Some(Some(end_start + end_line + "-----".len()))
}

fn match_sensitive_assignment(input: &str, index: usize) -> Option<Option<usize>> {
    if !is_boundary_before(input, index) {
        return Some(None);
    }
    for key in SENSITIVE_KEYS {
        if !starts_with_ascii_case_insensitive(input, index, key) {
            continue;
        }
        let mut cursor = index + key.len();
        if let Some(character) = input[cursor..].chars().next()
            && (character.is_ascii_alphanumeric() || character == '_')
        {
            continue;
        }

        let mut quoted_key = false;
        if matches!(input[cursor..].chars().next(), Some('"' | '\'')) {
            quoted_key = true;
            cursor += input[cursor..].chars().next()?.len_utf8();
        }
        while matches!(input[cursor..].chars().next(), Some(character) if character.is_ascii_whitespace())
        {
            cursor += input[cursor..].chars().next()?.len_utf8();
        }
        if !matches!(input[cursor..].chars().next(), Some('=' | ':')) {
            continue;
        }
        cursor += input[cursor..].chars().next()?.len_utf8();
        while matches!(input[cursor..].chars().next(), Some(character) if character.is_ascii_whitespace())
        {
            cursor += input[cursor..].chars().next()?.len_utf8();
        }
        let quote = if matches!(input[cursor..].chars().next(), Some('"' | '\'')) {
            let quote = input[cursor..].chars().next()?;
            cursor += quote.len_utf8();
            Some(quote)
        } else {
            None
        };
        if quote.is_none()
            && let Some(end) = match_bearer_token(input, cursor)
        {
            return Some(Some(end));
        }
        let value_start = cursor;
        let end = if let Some(quote) = quote {
            let end = input[cursor..].find(quote).map(|offset| cursor + offset)?;
            end + quote.len_utf8()
        } else {
            while let Some(character) = input[cursor..].chars().next() {
                if character.is_ascii_whitespace() || ",;]}>)".contains(character) {
                    break;
                }
                cursor += character.len_utf8();
            }
            cursor
        };
        if end == value_start && !quoted_key {
            return Some(Some(cursor));
        }
        return Some(Some(end));
    }
    Some(None)
}

fn match_bearer_token(input: &str, index: usize) -> Option<usize> {
    if !is_boundary_before(input, index)
        || !starts_with_ascii_case_insensitive(input, index, "bearer")
    {
        return None;
    }
    let mut cursor = index + "bearer".len();
    if !matches!(input[cursor..].chars().next(), Some(character) if character.is_ascii_whitespace())
    {
        return None;
    }
    while matches!(input[cursor..].chars().next(), Some(character) if character.is_ascii_whitespace())
    {
        cursor += input[cursor..].chars().next()?.len_utf8();
    }
    let start = cursor;
    while let Some(character) = input[cursor..].chars().next() {
        if character.is_ascii_whitespace() || ",;]}>)\"'".contains(character) {
            break;
        }
        cursor += character.len_utf8();
    }
    (cursor > start).then_some(cursor)
}

fn match_prefixed_secret(input: &str, index: usize) -> Option<usize> {
    if !is_boundary_before(input, index) {
        return None;
    }
    for prefix in SECRET_PREFIXES {
        if !starts_with_at(input, index, prefix) {
            continue;
        }
        let mut cursor = index + prefix.len();
        let start = cursor;
        while let Some(character) = input[cursor..].chars().next() {
            if character.is_ascii_whitespace() || ",;]}>)\"'".contains(character) {
                break;
            }
            cursor += character.len_utf8();
        }
        if cursor > start {
            return Some(cursor);
        }
    }

    if starts_with_at(input, index, "eyJ")
        && input[index..]
            .split_whitespace()
            .next()?
            .matches('.')
            .count()
            >= 2
    {
        let mut cursor = index;
        while let Some(character) = input[cursor..].chars().next() {
            if character.is_ascii_whitespace() || ",;]}>)\"'".contains(character) {
                break;
            }
            cursor += character.len_utf8();
        }
        return (cursor > index).then_some(cursor);
    }
    None
}

fn match_path(input: &str, index: usize) -> Option<usize> {
    if !is_boundary_before(input, index) || !path_start(input, index) {
        return None;
    }
    let mut cursor = index;
    while let Some(character) = input[cursor..].chars().next() {
        if character.is_ascii_whitespace() || "\r\n\t\"'<>|,;]}>)".contains(character) {
            break;
        }
        cursor += character.len_utf8();
    }
    (cursor > index).then_some(cursor)
}

fn path_start(input: &str, index: usize) -> bool {
    let rest = &input[index..];
    let bytes = rest.as_bytes();
    let drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    let unc = bytes.starts_with(br"\\");
    let unix = [
        "/home/", "/Users/", "/mnt/", "/var/", "/tmp/", "/opt/", "/etc/", "/root/",
    ]
    .iter()
    .any(|prefix| rest.starts_with(prefix));
    let tokenized = [
        "%USERPROFILE%",
        "%APPDATA%",
        "%LOCALAPPDATA%",
        "%PROGRAMDATA%",
        "$HOME/",
        "${HOME}/",
    ]
    .iter()
    .any(|prefix| rest.starts_with(prefix));
    drive || unc || unix || tokenized
}

fn normalize_key(key: &str) -> Cow<'_, str> {
    if key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Cow::Owned(
            key.bytes()
                .filter(|byte| byte.is_ascii_alphanumeric())
                .map(|byte| byte.to_ascii_lowercase() as char)
                .collect(),
        )
    } else {
        Cow::Owned(
            key.chars()
                .filter(|character| character.is_ascii_alphanumeric())
                .flat_map(char::to_lowercase)
                .collect(),
        )
    }
}

fn is_sensitive_key(key: &str) -> bool {
    SENSITIVE_KEYS.contains(&key)
        || key.contains("apikey")
        || key.ends_with("token")
        || key.ends_with("secret")
        || key.ends_with("password")
}

fn is_path_key(key: &str) -> bool {
    PATH_KEYS.contains(&key)
}

fn is_boundary_before(input: &str, index: usize) -> bool {
    input[..index]
        .chars()
        .next_back()
        .is_none_or(|character| !(character.is_ascii_alphanumeric() || character == '_'))
}

fn starts_with_at(input: &str, index: usize, needle: &str) -> bool {
    input[index..].starts_with(needle)
}

fn starts_with_ascii_case_insensitive(input: &str, index: usize, needle: &str) -> bool {
    input
        .as_bytes()
        .get(index..)
        .and_then(|bytes| bytes.get(..needle.len()))
        .is_some_and(|bytes| bytes.eq_ignore_ascii_case(needle.as_bytes()))
}

fn truncate_utf8(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_owned();
    }
    if max_bytes <= TRUNCATED.len() {
        let mut end = max_bytes;
        while end > 0 && !TRUNCATED.is_char_boundary(end) {
            end -= 1;
        }
        return TRUNCATED[..end].to_owned();
    }
    let mut end = max_bytes - TRUNCATED.len();
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    let mut output = String::with_capacity(max_bytes);
    output.push_str(&input[..end]);
    output.push_str(TRUNCATED);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_api_keys_and_bearer_tokens() {
        let value = redact_text("api_key=super-secret Bearer abc.def.ghi").unwrap();
        assert_eq!(value, "<REDACTED> <REDACTED>");
        assert!(!value.contains("super-secret"));
        assert!(!value.contains("abc.def.ghi"));
    }

    #[test]
    fn redacts_windows_and_posix_paths() {
        let value = redact_text(
            r#"failed C:\Users\Alice\Documents\secret.txt /home/alice/.config/reforge"#,
        )
        .unwrap();
        assert!(!value.contains("Alice"));
        assert!(!value.contains("alice"));
        assert!(value.matches(REDACTED_PATH).count() >= 2);
    }

    #[test]
    fn interactive_locations_remain_readable_but_secret_values_do_not() {
        let policy = RedactionPolicy::default();
        let path = r"C:\Users\Alice\Documents\Reforge Backups\backup.reforge";
        let message = format!("Location: {path} CONTEXT7_API_KEY=ctx7sk-synthetic-secret");
        let display = policy.redact_interactive_text(&message).unwrap();
        assert!(display.contains(path));
        assert!(!display.contains("ctx7sk-synthetic-secret"));
        assert!(!policy.redact_text(&message).unwrap().contains("Alice"));
    }

    #[test]
    fn provider_output_is_bounded_and_invalid_utf8_is_discarded() {
        let policy = RedactionPolicy::with_max_bytes(24);
        let output = policy.redact_provider_output(b"01234567890123456789012345", &[0xff]);
        assert!(output.stdout.as_ref().unwrap().len() <= 24);
        assert!(output.stdout.as_ref().unwrap().ends_with(TRUNCATED));
        assert!(output.stderr.is_none());
    }

    #[test]
    fn nested_json_replaces_sensitive_values_and_paths() {
        let input = json!({
            "token": "do-not-emit",
            "nested": [{"api_key": "also-secret"}],
            "path": r"C:\Users\Alice\config.json",
            "message": "Authorization: Bearer hidden-token"
        });
        let value = redact_json(&input).unwrap();
        assert_eq!(value["token"], REDACTED);
        assert_eq!(value["nested"][0]["api_key"], REDACTED);
        assert_eq!(value["path"], REDACTED_PATH);
        assert_eq!(value["message"], REDACTED);
    }

    #[test]
    fn unsafe_controls_are_discarded() {
        assert!(redact_text("output\u{1b}[2J").is_none());
        assert!(redact_json(&json!({"output": "safe\u{0}"})).is_none());
    }

    #[test]
    fn context_ids_accept_only_safe_ascii_tokens() {
        assert_eq!(
            sanitize_context_id("run-1:step_2"),
            Some("run-1:step_2".to_owned())
        );
        assert!(sanitize_context_id("C:\\Users\\Alice").is_none());
        assert!(sanitize_context_id("contains whitespace").is_none());
    }
}
