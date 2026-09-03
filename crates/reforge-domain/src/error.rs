//! Structured, user-safe error construction for Reforge boundaries.
//!
//! The wire error types live in [`crate::model`] so every boundary shares one
//! schema. This module adds safe constructors, retry classification, and
//! display/serialization behavior without introducing a competing error DTO.

use std::{fmt, io};

use crate::{
    ComponentId, ErrorEnvelope, OperationId, ReforgeErrorCode, Retryability,
    redaction::{RedactionPolicy, redact_text, sanitize_context_id},
};

/// Maximum UTF-8 byte length of a directly displayed error message.
pub const MAX_ERROR_MESSAGE_BYTES: usize = 1_024;

/// Construct an error envelope and discard technical detail that cannot be
/// proven safe after redaction.
pub fn coded_error(
    code: ReforgeErrorCode,
    message: impl Into<String>,
    technical_detail: Option<&str>,
    component: Option<ComponentId>,
    operation: Option<OperationId>,
    context_id: Option<&str>,
) -> ErrorEnvelope {
    let mut envelope = ErrorEnvelope::new(code, message);
    envelope.component = component;
    envelope.operation = operation;
    envelope.context_id = context_id.and_then(sanitize_context_id);
    if let Some(detail) = technical_detail {
        envelope.technical_detail = redact_text(detail);
    }
    envelope
}

impl ReforgeErrorCode {
    /// Return the conservative retry policy associated with this code.
    pub fn default_retryability(&self) -> Retryability {
        match self {
            Self::FileLocked
            | Self::ProviderUnavailable
            | Self::SourceUnavailable
            | Self::Interrupted
            | Self::Cancelled => Retryability::SafeRetry,
            Self::ManualActionRequired
            | Self::UserActionRequired
            | Self::AccessDenied
            | Self::PackageUntrusted
            | Self::VaultRequired
            | Self::ManualSecretRequired
            | Self::SecretNotPortable
            | Self::SelectionIncomplete
            | Self::SecurityPolicy
            | Self::TargetConflict
            | Self::ArchitectureConflict
            | Self::OsConflict => Retryability::RequiresUserAction,
            Self::RebootRequired => Retryability::AfterReboot,
            Self::PathNotFound
            | Self::InvalidPath
            | Self::ReparsePoint
            | Self::ProviderParseFailed
            | Self::VersionUnavailable
            | Self::PackageNotFound
            | Self::PackageCorrupt
            | Self::VaultDecryptFailed
            | Self::SchemaInvalid
            | Self::UnsupportedVersion
            | Self::InsufficientDisk
            | Self::DependencyCycle
            | Self::OperationFailed
            | Self::InstallFailed
            | Self::VerificationFailed => Retryability::Never,
        }
    }
}

impl ErrorEnvelope {
    /// Create a safe envelope with no source detail or boundary context.
    pub fn new(code: ReforgeErrorCode, message: impl Into<String>) -> Self {
        let message = message.into();
        let message = RedactionPolicy::with_max_bytes(MAX_ERROR_MESSAGE_BYTES)
            .redact_text(&message)
            .unwrap_or_else(|| "The operation could not be completed safely.".to_owned());
        Self {
            retryability: code.default_retryability(),
            code,
            message,
            technical_detail: None,
            component: None,
            operation: None,
            context_id: None,
        }
    }

    /// Attach bounded redacted technical detail. Unsafe detail is discarded.
    pub fn with_technical_detail(mut self, detail: impl AsRef<str>) -> Self {
        self.technical_detail = redact_text(detail.as_ref());
        self
    }

    /// Attach a JSON diagnostic after recursive redaction and size checks.
    pub fn with_json_detail(mut self, detail: &serde_json::Value) -> Self {
        self.technical_detail = RedactionPolicy::default()
            .redact_json(detail)
            .and_then(|redacted| serde_json::to_string(&redacted).ok());
        self
    }

    /// Override the retry policy when the boundary has stronger knowledge.
    pub fn with_retryability(mut self, retryability: Retryability) -> Self {
        self.retryability = retryability;
        self
    }

    /// Attach component and operation correlation identifiers.
    pub fn with_ids(
        mut self,
        component: Option<ComponentId>,
        operation: Option<OperationId>,
    ) -> Self {
        self.component = component;
        self.operation = operation;
        self
    }

    /// Attach a bounded, transport-safe diagnostic context identifier.
    pub fn with_context_id(mut self, context_id: impl AsRef<str>) -> Self {
        self.context_id = sanitize_context_id(context_id.as_ref());
        self
    }

    /// Classify an I/O failure and retain only redacted source detail.
    pub fn from_io_error(error: &io::Error, message: impl Into<String>) -> Self {
        Self::new(classify_io_error(error.kind()), message).with_technical_detail(error.to_string())
    }

    /// Serialize this already-safe envelope for the CLI or Tauri boundary.
    pub fn to_json(&self) -> String {
        serialize_error(self)
    }
}

impl fmt::Display for ReforgeErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AccessDenied => "ACCESS_DENIED",
            Self::PathNotFound => "PATH_NOT_FOUND",
            Self::FileLocked => "FILE_LOCKED",
            Self::InvalidPath => "INVALID_PATH",
            Self::ReparsePoint => "REPARSE_POINT",
            Self::ProviderUnavailable => "PROVIDER_UNAVAILABLE",
            Self::ProviderParseFailed => "PROVIDER_PARSE_FAILED",
            Self::SourceUnavailable => "SOURCE_UNAVAILABLE",
            Self::VersionUnavailable => "VERSION_UNAVAILABLE",
            Self::PackageNotFound => "PACKAGE_NOT_FOUND",
            Self::PackageCorrupt => "PACKAGE_CORRUPT",
            Self::PackageUntrusted => "PACKAGE_UNTRUSTED",
            Self::VaultRequired => "VAULT_REQUIRED",
            Self::VaultDecryptFailed => "VAULT_DECRYPT_FAILED",
            Self::SecretNotPortable => "SECRET_NOT_PORTABLE",
            Self::ManualSecretRequired => "MANUAL_SECRET_REQUIRED",
            Self::SchemaInvalid => "SCHEMA_INVALID",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::ArchitectureConflict => "ARCHITECTURE_CONFLICT",
            Self::OsConflict => "OS_CONFLICT",
            Self::InsufficientDisk => "INSUFFICIENT_DISK",
            Self::DependencyCycle => "DEPENDENCY_CYCLE",
            Self::SelectionIncomplete => "SELECTION_INCOMPLETE",
            Self::TargetConflict => "TARGET_CONFLICT",
            Self::SecurityPolicy => "SECURITY_POLICY",
            Self::ManualActionRequired => "MANUAL_ACTION_REQUIRED",
            Self::UserActionRequired => "USER_ACTION_REQUIRED",
            Self::RebootRequired => "REBOOT_REQUIRED",
            Self::OperationFailed => "OPERATION_FAILED",
            Self::InstallFailed => "INSTALL_FAILED",
            Self::VerificationFailed => "VERIFICATION_FAILED",
            Self::Interrupted => "INTERRUPTED",
            Self::Cancelled => "CANCELLED",
        })
    }
}

impl fmt::Display for Retryability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Never => "NEVER",
            Self::SafeRetry => "SAFE_RETRY",
            Self::RequiresUserAction => "REQUIRES_USER_ACTION",
            Self::AfterReboot => "AFTER_REBOOT",
        })
    }
}

impl fmt::Display for ErrorEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ErrorEnvelope {}

/// Map standard I/O kinds to the stable Reforge error taxonomy.
pub fn classify_io_error(kind: io::ErrorKind) -> ReforgeErrorCode {
    match kind {
        io::ErrorKind::PermissionDenied => ReforgeErrorCode::AccessDenied,
        io::ErrorKind::NotFound => ReforgeErrorCode::PathNotFound,
        io::ErrorKind::AlreadyExists => ReforgeErrorCode::TargetConflict,
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => ReforgeErrorCode::FileLocked,
        io::ErrorKind::InvalidInput => ReforgeErrorCode::InvalidPath,
        io::ErrorKind::Interrupted => ReforgeErrorCode::Interrupted,
        _ => ReforgeErrorCode::OperationFailed,
    }
}

/// Serialize an error envelope without exposing source strings outside the
/// envelope's already-redacted technical detail field.
pub fn serialize_error(error: &ErrorEnvelope) -> String {
    serde_json::to_string(error).unwrap_or_else(|_| {
        r#"{"code":"OPERATION_FAILED","message":"The operation could not be completed safely.","retryability":"NEVER"}"#.to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ComponentId, ObjectId, OperationId, RunId};
    use uuid::Uuid;

    #[test]
    fn error_constructor_preserves_correlation_ids_and_redacts_detail() {
        let component = ComponentId::new(format!("cmp_{}", "a".repeat(52))).unwrap();
        let run = RunId::new(Uuid::now_v7()).unwrap();
        let operation = OperationId::for_run(&run, 4).unwrap();
        let error = coded_error(
            ReforgeErrorCode::OperationFailed,
            "Unable to continue",
            Some("api_key=super-secret"),
            Some(component.clone()),
            Some(operation.clone()),
            Some("run-42"),
        );

        assert_eq!(error.component, Some(component));
        assert_eq!(error.operation, Some(operation));
        assert_eq!(error.context_id.as_deref(), Some("run-42"));
        assert_eq!(error.technical_detail.as_deref(), Some("<REDACTED>"));
    }

    #[test]
    fn unsafe_detail_is_discarded_instead_of_emitted() {
        let error = ErrorEnvelope::new(ReforgeErrorCode::OperationFailed, "failed")
            .with_technical_detail("bad\u{1b}[31moutput");
        assert!(error.technical_detail.is_none());
    }

    #[test]
    fn retry_defaults_are_conservative_and_codes_are_displayable() {
        assert_eq!(
            ReforgeErrorCode::FileLocked.default_retryability(),
            Retryability::SafeRetry
        );
        assert_eq!(
            ReforgeErrorCode::RebootRequired.default_retryability(),
            Retryability::AfterReboot
        );
        assert_eq!(ReforgeErrorCode::AccessDenied.to_string(), "ACCESS_DENIED");
        assert_eq!(
            Retryability::RequiresUserAction.to_string(),
            "REQUIRES_USER_ACTION"
        );
    }

    #[test]
    fn io_classification_does_not_expose_source_text() {
        let source = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "C:\\Users\\Alice\\secret.txt",
        );
        let error = ErrorEnvelope::from_io_error(&source, "Cannot read the selected file");
        assert_eq!(error.code, ReforgeErrorCode::AccessDenied);
        assert_eq!(error.technical_detail.as_deref(), Some("<PATH>"));
        assert_eq!(ObjectId::from_content(b"stable").as_str().len(), 68);
    }
}
