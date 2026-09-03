//! Human-readable and JSON-safe restore report formatting.
//!
//! Formatting deliberately emits plain text only.  The restore verifier has
//! already removed unsafe free-form values, and this module applies the same
//! redaction boundary again before serialization or terminal display.

use std::fmt::Write as _;

use reforge_domain::{ManualActionState, ReportStatus, RestoreReport};
use reforge_restore::redact_restore_report;

/// Format a final report for a terminal without HTML or unbounded diagnostics.
pub fn format_report(report: &RestoreReport) -> String {
    let report = redact_restore_report(report.clone());
    let mut output = String::new();
    let _ = writeln!(output, "Restore report: {}", status_label(&report.status));
    let _ = writeln!(output, "Run: {}", report.run_id);
    let _ = writeln!(output, "Package: {}", report.package_id);
    let _ = writeln!(
        output,
        "Counts: verified={} partial={} already_present={} waiting_for_user={} reauth_required={} reboot_required={} unsupported={} failed={}",
        report.counts.verified,
        report.counts.partial,
        report.counts.already_present,
        report.counts.waiting_for_user,
        report.counts.reauth_required,
        report.counts.reboot_required,
        report.counts.unsupported,
        report.counts.failed,
    );
    let _ = writeln!(
        output,
        "Metrics: elapsed_ms={} bytes_written={}",
        report.elapsed_ms, report.bytes_written
    );

    if !report.components.is_empty() {
        output.push_str("Components:\n");
        for component in &report.components {
            let _ = writeln!(
                output,
                "- {}: {}",
                component.component,
                status_label(&component.status)
            );
            for evidence in &component.evidence {
                let _ = writeln!(
                    output,
                    "  - {}: {}",
                    status_label(&evidence.status),
                    evidence.summary
                );
            }
            for action in &component.manual_actions {
                let _ = writeln!(output, "  - manual action: {action}");
            }
            for warning in &component.warnings {
                let _ = writeln!(output, "  - warning: {warning}");
            }
        }
    }

    if !report.manual_actions.is_empty() {
        output.push_str("Manual actions:\n");
        for action in &report.manual_actions {
            let _ = writeln!(
                output,
                "- {} [{}]: {}",
                action.id,
                manual_action_label(&action.state),
                action.title
            );
            let _ = writeln!(output, "  reason: {}", action.reason);
            for instruction in &action.instructions {
                let _ = writeln!(output, "  - {instruction}");
            }
        }
    }

    if !report.warnings.is_empty() {
        output.push_str("Warnings:\n");
        for warning in &report.warnings {
            let _ = writeln!(output, "- {warning}");
        }
    }
    output
}

/// Serialize a final report as indented, redacted JSON.
pub fn format_report_json(report: &RestoreReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&redact_restore_report(report.clone()))
}

fn status_label(status: &ReportStatus) -> &'static str {
    match status {
        ReportStatus::Verified => "VERIFIED",
        ReportStatus::PartiallyVerified => "PARTIALLY_VERIFIED",
        ReportStatus::AlreadyPresent => "ALREADY_PRESENT",
        ReportStatus::Skipped => "SKIPPED",
        ReportStatus::WaitingForUser => "WAITING_FOR_USER",
        ReportStatus::ReauthRequired => "REAUTH_REQUIRED",
        ReportStatus::RebootRequired => "REBOOT_REQUIRED",
        ReportStatus::Unsupported => "UNSUPPORTED",
        ReportStatus::Failed => "FAILED",
    }
}

fn manual_action_label(state: &ManualActionState) -> &'static str {
    match state {
        ManualActionState::Pending => "PENDING",
        ManualActionState::Acknowledged => "ACKNOWLEDGED",
        ManualActionState::Completed => "COMPLETED",
        ManualActionState::Skipped => "SKIPPED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reforge_domain::{ComponentId, ReportCounts, RunId};

    fn report() -> RestoreReport {
        RestoreReport {
            format_version: 1,
            run_id: RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned())
                .expect("run ID"),
            package_id: "package".to_owned(),
            status: ReportStatus::Failed,
            counts: ReportCounts {
                verified: 0,
                partial: 0,
                already_present: 0,
                waiting_for_user: 0,
                reauth_required: 0,
                reboot_required: 0,
                unsupported: 0,
                failed: 1,
            },
            components: vec![reforge_domain::ComponentReport {
                component: ComponentId::new(format!("cmp_{}", "a".repeat(52))).expect("component"),
                status: ReportStatus::Failed,
                evidence: Vec::new(),
                manual_actions: Vec::new(),
                warnings: vec!["api_key=secret C:\\Users\\Alice\\file".to_owned()],
            }],
            manual_actions: Vec::new(),
            warnings: vec!["api_key=secret".to_owned()],
            elapsed_ms: 1,
            bytes_written: 2,
        }
    }

    #[test]
    fn formatter_is_plain_text_and_redacted() {
        let output = format_report(&report());
        assert!(output.contains("Restore report: FAILED"));
        assert!(!output.contains("secret"));
        assert!(!output.contains("Alice"));
        assert!(!output.contains("<html"));
    }

    #[test]
    fn json_formatter_preserves_wire_status() {
        let value: serde_json::Value =
            serde_json::from_str(&format_report_json(&report()).expect("JSON")).expect("value");
        assert_eq!(value["status"], "FAILED");
        assert_eq!(value["counts"]["failed"], 1);
    }
}
