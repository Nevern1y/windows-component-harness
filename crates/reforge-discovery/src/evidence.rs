//! Bounded, redaction-preserving discovery evidence aggregation.

use std::collections::{BTreeMap, BTreeSet};

use reforge_domain::{
    Confidence, ErrorEnvelope, Evidence, EvidenceId, ProviderId, RedactionPolicy, ReforgeErrorCode,
};

const MAX_EVIDENCE_RECORDS: usize = 100_000;
const MAX_WARNINGS: usize = 4_096;
const MAX_EVIDENCE_TEXT_BYTES: usize = 8 * 1024;
const WARNING_OMISSION: &str =
    "Additional discovery warnings were omitted after the reviewed limit";

#[derive(Default)]
pub(crate) struct EvidenceLedger {
    records: BTreeMap<EvidenceId, Evidence>,
}

impl EvidenceLedger {
    pub(crate) fn insert(&mut self, mut evidence: Evidence) -> Result<(), Box<ErrorEnvelope>> {
        if evidence.strength > 100 {
            return Err(evidence_error("evidence strength exceeds 100"));
        }
        evidence.locator = redact_evidence_text(&evidence.locator)?;
        evidence.summary = redact_evidence_text(&evidence.summary)?;
        evidence.independent_group = redact_evidence_text(&evidence.independent_group)?;

        if let Some(existing) = self.records.get(&evidence.id) {
            if existing == &evidence {
                return Ok(());
            }
            return Err(evidence_error(
                "one evidence ID was reused for conflicting observations",
            ));
        }
        if self.records.len() >= MAX_EVIDENCE_RECORDS {
            return Err(evidence_error(
                "discovery evidence exceeds the reviewed record bound",
            ));
        }
        self.records.insert(evidence.id.clone(), evidence);
        Ok(())
    }

    pub(crate) fn into_records(self) -> Vec<Evidence> {
        self.records.into_values().collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceConfidence {
    pub(crate) confidence: Confidence,
    pub(crate) score: u8,
    pub(crate) independent_groups: usize,
    pub(crate) explanations: Vec<String>,
    pub(crate) unverified: bool,
}

pub(crate) fn confidence_for_evidence(
    evidence_ids: &[EvidenceId],
    records: &BTreeMap<EvidenceId, Evidence>,
    identity_unverified: bool,
    conflicting_facts: bool,
) -> EvidenceConfidence {
    let mut total = 0u16;
    let mut groups = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut missing = false;
    let mut missing_count = 0usize;
    for evidence_id in evidence_ids {
        if !seen.insert(evidence_id) {
            continue;
        }
        let Some(record) = records.get(evidence_id) else {
            missing = true;
            missing_count = missing_count.saturating_add(1);
            continue;
        };
        total = total.saturating_add(u16::from(record.strength));
        groups.insert(record.independent_group.as_str());
    }

    let mut score = total.min(100) as u8;
    let mut explanations = vec![format!(
        "{} supporting evidence record(s) contributed {} point(s)",
        seen.len().saturating_sub(missing_count),
        score
    )];
    if groups.len() >= 2 {
        score = score.saturating_add(10).min(100);
        explanations.push("Two independent evidence groups agree on the identity".to_owned());
    } else {
        explanations.push("Fewer than two independent evidence groups were observed".to_owned());
    }
    if conflicting_facts {
        score = score.saturating_sub(20);
        explanations
            .push("Conflicting publisher, version, or source facts reduced confidence".to_owned());
    }
    if missing {
        explanations.push("A referenced evidence record was unavailable".to_owned());
    }
    if identity_unverified {
        explanations.push("The observation has no supported identity tuple".to_owned());
    }
    if evidence_ids.is_empty() {
        explanations.push("No supporting evidence was recorded".to_owned());
    }

    let unverified = identity_unverified || missing || evidence_ids.is_empty();
    let confidence = if unverified {
        Confidence::Unknown
    } else if score >= 90 && groups.len() >= 2 && !conflicting_facts {
        Confidence::Confirmed
    } else if score >= 75 {
        Confidence::High
    } else if score >= 45 {
        Confidence::Medium
    } else if score >= 20 {
        Confidence::Low
    } else {
        Confidence::Unknown
    };
    EvidenceConfidence {
        confidence,
        score,
        independent_groups: groups.len(),
        explanations,
        unverified,
    }
}

#[derive(Default)]
pub(crate) struct WarningLedger {
    warnings: BTreeSet<String>,
    omitted: bool,
}

impl WarningLedger {
    pub(crate) fn push(&mut self, warning: impl AsRef<str>) {
        let Some(warning) = RedactionPolicy::default().redact_text(warning.as_ref()) else {
            self.record_omission();
            return;
        };
        if self.warnings.len() < MAX_WARNINGS.saturating_sub(1) {
            self.warnings.insert(warning);
        } else {
            self.record_omission();
        }
    }

    pub(crate) fn push_error(&mut self, adapter: &ProviderId, error: &ErrorEnvelope) {
        let mut warning = format!("{} [{}]: {}", adapter, error.code, error.message);
        if let Some(detail) = &error.technical_detail {
            warning.push_str(" — ");
            warning.push_str(detail);
        }
        self.push(warning);
    }

    pub(crate) fn into_warnings(mut self) -> Vec<String> {
        if self.omitted {
            self.warnings.insert(WARNING_OMISSION.to_owned());
        }
        self.warnings.into_iter().collect()
    }

    fn record_omission(&mut self) {
        self.omitted = true;
    }
}

fn redact_evidence_text(value: &str) -> Result<String, Box<ErrorEnvelope>> {
    RedactionPolicy::with_max_bytes(MAX_EVIDENCE_TEXT_BYTES)
        .redact_text(value)
        .ok_or_else(|| evidence_error("evidence text could not be safely redacted"))
}

fn evidence_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "Discovery evidence failed validation",
        )
        .with_technical_detail(detail),
    )
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use reforge_domain::EvidenceSource;

    use super::*;

    #[test]
    fn conflicting_evidence_ids_are_rejected() {
        let mut ledger = EvidenceLedger::default();
        ledger.insert(evidence("first")).expect("first evidence");
        let error = ledger
            .insert(evidence("second"))
            .expect_err("conflict must fail");
        assert_eq!(error.code, ReforgeErrorCode::SchemaInvalid);
    }

    #[test]
    fn warning_paths_and_secret_patterns_are_redacted() {
        let mut ledger = WarningLedger::default();
        ledger.push(r"C:\Users\alice\secret.txt token=top-secret");
        let warnings = ledger.into_warnings();
        assert_eq!(warnings.len(), 1);
        assert!(!warnings[0].contains("alice"));
        assert!(!warnings[0].contains("top-secret"));
    }

    fn evidence(summary: &str) -> Evidence {
        Evidence {
            id: EvidenceId::new("evidence-1").expect("evidence ID"),
            source: EvidenceSource::Unknown,
            locator: "local:test".to_owned(),
            observed_at: Utc::now(),
            summary: summary.to_owned(),
            strength: 50,
            independent_group: "test".to_owned(),
        }
    }
}
