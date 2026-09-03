//! Deterministic, cancellation-aware discovery phase orchestration.

use std::time::Duration;

use chrono::Utc;
use reforge_domain::{
    Component, DependencyEdge, ErrorEnvelope, HostFacts, Inventory, ProgressEvent, ProgressStatus,
    ReforgeErrorCode, RunId, ScanPhase,
};
use reforge_platform_windows::{CancellationToken, KnownFolderMap, ProcessRunner};
use uuid::Uuid;

use crate::{
    dedup::deduplicate_graph,
    evidence::{EvidenceLedger, WarningLedger},
    providers::{AdapterRegistry, ProviderContext, ProviderResult},
};

const FORMAT_VERSION: u16 = 1;
const ADAPTER_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_OBSERVATIONS_PER_ADAPTER: usize = 100_000;
const MAX_EVIDENCE_PER_ADAPTER: usize = 100_000;
const MAX_WARNINGS_PER_ADAPTER: usize = 4_096;
const MAX_COMPONENTS: usize = 250_000;
const MAX_EDGES: usize = 1_000_000;

const SCAN_PHASES: [ScanPhase; 8] = [
    ScanPhase::HostPreflight,
    ScanPhase::PackageExports,
    ScanPhase::WindowsRegistration,
    ScanPhase::RuntimeProbes,
    ScanPhase::KnownFolderConfig,
    ScanPhase::AppAdapters,
    ScanPhase::GenericExecutables,
    ScanPhase::Correlation,
];

pub struct DiscoveryCoordinator {
    registry: AdapterRegistry,
}

impl DiscoveryCoordinator {
    pub fn new(registry: AdapterRegistry) -> Self {
        Self { registry }
    }

    pub fn registry(&self) -> &AdapterRegistry {
        &self.registry
    }

    /// Run every declared phase and stream typed progress to the supplied sink.
    /// Individual adapter and observation failures become redacted warnings;
    /// cancellation and global safety-bound failures stop the scan.
    pub async fn scan<F>(
        &self,
        host: HostFacts,
        known_folders: &KnownFolderMap,
        runner: &ProcessRunner,
        cancellation: &CancellationToken,
        progress: F,
    ) -> ProviderResult<Inventory>
    where
        F: Fn(ProgressEvent) + Send + Sync,
    {
        let scan_id = RunId::new(Uuid::now_v7())
            .map_err(|_| scan_error("could not construct a UUIDv7 scan identity"))?;
        self.scan_with_id(
            scan_id,
            host,
            known_folders,
            runner,
            cancellation,
            &progress,
        )
        .await
    }

    pub async fn scan_with_id(
        &self,
        scan_id: RunId,
        host: HostFacts,
        known_folders: &KnownFolderMap,
        runner: &ProcessRunner,
        cancellation: &CancellationToken,
        progress: &(dyn Fn(ProgressEvent) + Send + Sync),
    ) -> ProviderResult<Inventory> {
        let mut evidence = EvidenceLedger::default();
        let mut warnings = WarningLedger::default();
        let mut components = Vec::<Component>::new();
        let mut edges = Vec::<DependencyEdge>::new();

        for phase in &SCAN_PHASES {
            if cancellation.is_cancelled() {
                emit(
                    progress,
                    &scan_id,
                    phase,
                    ProgressStatus::Cancelled,
                    0,
                    None,
                    "Discovery cancelled",
                );
                return Err(cancelled_error());
            }

            let registrations: Vec<_> = self.registry.for_phase(phase).collect();
            let total = registrations.len() as u64;
            emit(
                progress,
                &scan_id,
                phase,
                ProgressStatus::Started,
                0,
                Some(total),
                &format!("{} phase started", phase_label(phase)),
            );

            let mut attempted = 0u64;
            let mut succeeded = 0u64;
            let mut completed = 0u64;

            for registration in registrations {
                if cancellation.is_cancelled() {
                    emit(
                        progress,
                        &scan_id,
                        phase,
                        ProgressStatus::Cancelled,
                        completed,
                        Some(total),
                        "Discovery cancelled",
                    );
                    return Err(cancelled_error());
                }

                let adapter = registration.adapter();
                let context = ProviderContext {
                    host: &host,
                    known_folders,
                    runner,
                    cancellation,
                };
                let detection = adapter.detect(&context);
                let mut adapter_invalid = false;

                if detection.evidence.len() > MAX_EVIDENCE_PER_ADAPTER {
                    let error = adapter_bound_error("detection evidence");
                    warnings.push_error(registration.id(), &error);
                    adapter_invalid = true;
                } else {
                    for record in detection.evidence {
                        if let Err(error) = evidence.insert(record) {
                            warnings.push_error(registration.id(), &error);
                            adapter_invalid = true;
                        }
                    }
                }

                if detection.warnings.len() > MAX_WARNINGS_PER_ADAPTER {
                    let error = adapter_bound_error("detection warnings");
                    warnings.push_error(registration.id(), &error);
                    adapter_invalid = true;
                } else {
                    if !detection.warnings.is_empty() {
                        emit(
                            progress,
                            &scan_id,
                            phase,
                            ProgressStatus::Warning,
                            completed,
                            Some(total),
                            &format!("{} reported detection warnings", registration.id()),
                        );
                    }
                    for warning in detection.warnings {
                        warnings.push(format!("{}: {warning}", registration.id()));
                    }
                }

                if adapter_invalid {
                    attempted += u64::from(detection.available);
                    completed += 1;
                    emit_adapter_progress(
                        progress,
                        &scan_id,
                        phase,
                        registration.id().as_str(),
                        completed,
                        total,
                        "failed validation",
                    );
                    continue;
                }

                if !detection.available {
                    completed += 1;
                    emit_adapter_progress(
                        progress,
                        &scan_id,
                        phase,
                        registration.id().as_str(),
                        completed,
                        total,
                        "unavailable",
                    );
                    continue;
                }
                attempted += 1;

                let enumeration = tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        emit(
                            progress,
                            &scan_id,
                            phase,
                            ProgressStatus::Cancelled,
                            completed,
                            Some(total),
                            "Discovery cancelled",
                        );
                        return Err(cancelled_error());
                    }
                    result = tokio::time::timeout(ADAPTER_TIMEOUT, adapter.enumerate(&context)) => result,
                };

                let enumeration = match enumeration {
                    Ok(Ok(enumeration)) => enumeration,
                    Ok(Err(error)) => {
                        warnings.push_error(registration.id(), &error);
                        completed += 1;
                        emit_adapter_warning(
                            progress,
                            &scan_id,
                            phase,
                            registration.id().as_str(),
                            completed,
                            total,
                            "enumeration failed",
                        );
                        continue;
                    }
                    Err(_) => {
                        let error = adapter_timeout_error();
                        warnings.push_error(registration.id(), &error);
                        completed += 1;
                        emit_adapter_warning(
                            progress,
                            &scan_id,
                            phase,
                            registration.id().as_str(),
                            completed,
                            total,
                            "timed out",
                        );
                        continue;
                    }
                };

                if enumeration.warnings.len() > MAX_WARNINGS_PER_ADAPTER {
                    warnings.push_error(
                        registration.id(),
                        &adapter_bound_error("enumeration warnings"),
                    );
                    completed += 1;
                    emit_adapter_warning(
                        progress,
                        &scan_id,
                        phase,
                        registration.id().as_str(),
                        completed,
                        total,
                        "exceeded warning limit",
                    );
                    continue;
                }
                if !enumeration.warnings.is_empty() {
                    emit(
                        progress,
                        &scan_id,
                        phase,
                        ProgressStatus::Warning,
                        completed,
                        Some(total),
                        &format!("{} reported enumeration warnings", registration.id()),
                    );
                }
                for warning in enumeration.warnings {
                    warnings.push(format!("{}: {warning}", registration.id()));
                }
                let observations = enumeration.observations;

                if observations.len() > MAX_OBSERVATIONS_PER_ADAPTER {
                    let error = adapter_bound_error("observations");
                    warnings.push_error(registration.id(), &error);
                    completed += 1;
                    emit_adapter_warning(
                        progress,
                        &scan_id,
                        phase,
                        registration.id().as_str(),
                        completed,
                        total,
                        "exceeded observation limit",
                    );
                    continue;
                }

                let empty = observations.is_empty();
                let mut normalized_any = false;
                for observation in observations {
                    if cancellation.is_cancelled() {
                        emit(
                            progress,
                            &scan_id,
                            phase,
                            ProgressStatus::Cancelled,
                            completed,
                            Some(total),
                            "Discovery cancelled",
                        );
                        return Err(cancelled_error());
                    }
                    if observation.evidence().len() > MAX_EVIDENCE_PER_ADAPTER {
                        warnings.push_error(
                            registration.id(),
                            &adapter_bound_error("observation evidence"),
                        );
                        continue;
                    }
                    for record in observation.evidence().iter().cloned() {
                        if let Err(error) = evidence.insert(record) {
                            warnings.push_error(registration.id(), &error);
                        }
                    }

                    match adapter.normalize(observation) {
                        Ok(normalized) => {
                            if !normalized.is_empty() {
                                normalized_any = true;
                            }
                            append_components(&mut components, &mut edges, normalized)?;
                        }
                        Err(error) => warnings.push_error(registration.id(), &error),
                    }
                }

                if empty || normalized_any {
                    succeeded += 1;
                }
                completed += 1;
                emit_adapter_progress(
                    progress,
                    &scan_id,
                    phase,
                    registration.id().as_str(),
                    completed,
                    total,
                    if empty || normalized_any {
                        "completed"
                    } else {
                        "produced no valid components"
                    },
                );
            }

            let (status, message) = if attempted > 0 && succeeded == 0 {
                (
                    ProgressStatus::Failed,
                    format!("{} phase failed", phase_label(phase)),
                )
            } else {
                (
                    ProgressStatus::Completed,
                    format!("{} phase completed", phase_label(phase)),
                )
            };
            emit(
                progress,
                &scan_id,
                phase,
                status,
                completed,
                Some(total),
                &message,
            );
        }

        let evidence = evidence.into_records();
        let graph = deduplicate_graph(components, edges, &evidence)?;
        Ok(Inventory {
            format_version: FORMAT_VERSION,
            scan_id,
            captured_at: Utc::now(),
            host,
            graph,
            evidence,
            warnings: warnings.into_warnings(),
        })
    }
}

fn append_components(
    components: &mut Vec<Component>,
    edges: &mut Vec<DependencyEdge>,
    normalized: Vec<Component>,
) -> ProviderResult<()> {
    let next_components = components
        .len()
        .checked_add(normalized.len())
        .ok_or_else(|| scan_error("component count overflow"))?;
    let added_edges = normalized.iter().try_fold(0usize, |count, component| {
        count
            .checked_add(component.dependencies.len())
            .ok_or_else(|| scan_error("dependency edge count overflow"))
    })?;
    let next_edges = edges
        .len()
        .checked_add(added_edges)
        .ok_or_else(|| scan_error("dependency edge count overflow"))?;
    if next_components > MAX_COMPONENTS || next_edges > MAX_EDGES {
        return Err(scan_error("discovery graph exceeds the reviewed bound"));
    }
    for component in normalized {
        edges.extend(component.dependencies.iter().cloned());
        components.push(component);
    }
    Ok(())
}

fn emit_adapter_progress(
    progress: &(dyn Fn(ProgressEvent) + Send + Sync),
    scan_id: &RunId,
    phase: &ScanPhase,
    adapter: &str,
    completed: u64,
    total: u64,
    result: &str,
) {
    emit(
        progress,
        scan_id,
        phase,
        ProgressStatus::Progress,
        completed,
        Some(total),
        &format!("{adapter}: {result}"),
    );
}

fn emit_adapter_warning(
    progress: &(dyn Fn(ProgressEvent) + Send + Sync),
    scan_id: &RunId,
    phase: &ScanPhase,
    adapter: &str,
    completed: u64,
    total: u64,
    result: &str,
) {
    emit(
        progress,
        scan_id,
        phase,
        ProgressStatus::Warning,
        completed,
        Some(total),
        &format!("{adapter}: {result}"),
    );
}

fn emit(
    progress: &(dyn Fn(ProgressEvent) + Send + Sync),
    scan_id: &RunId,
    phase: &ScanPhase,
    status: ProgressStatus,
    completed: u64,
    total: Option<u64>,
    message: &str,
) {
    progress(ProgressEvent {
        run_id: scan_id.clone(),
        phase: phase.clone(),
        status,
        current_component: None,
        completed,
        total,
        bytes: None,
        message: message.to_owned(),
    });
}

fn phase_label(phase: &ScanPhase) -> &'static str {
    match phase {
        ScanPhase::HostPreflight => "Host preflight",
        ScanPhase::PackageExports => "Package exports",
        ScanPhase::WindowsRegistration => "Windows registration",
        ScanPhase::RuntimeProbes => "Runtime probes",
        ScanPhase::KnownFolderConfig => "Known-folder configuration",
        ScanPhase::AppAdapters => "Application adapters",
        ScanPhase::GenericExecutables => "Generic executables",
        ScanPhase::Correlation => "Correlation",
    }
}

fn cancelled_error() -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::Cancelled,
        "Discovery was cancelled",
    ))
}

fn adapter_timeout_error() -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::ProviderUnavailable,
            "A discovery adapter timed out",
        )
        .with_technical_detail("adapter exceeded the coordinator timeout"),
    )
}

fn adapter_bound_error(output: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "A discovery adapter exceeded a safety bound",
        )
        .with_technical_detail(format!("adapter {output} exceeded the reviewed limit")),
    )
}

fn scan_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "Discovery could not produce a bounded inventory",
        )
        .with_technical_detail(detail),
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Mutex, time::Instant};

    use async_trait::async_trait;
    use reforge_domain::{
        AccountScope, Architecture, DriveFact, DriveFreeSpace, Operation, ProviderId, TargetFacts,
        VerificationRule,
    };

    use super::*;
    use crate::providers::{DetectionResult, Observation, ProviderAdapter};

    enum Behavior {
        Empty,
        Fail,
        Pending,
    }

    struct TestAdapter {
        id: ProviderId,
        behavior: Behavior,
    }

    impl TestAdapter {
        fn new(id: &str, behavior: Behavior) -> Self {
            Self {
                id: ProviderId::new(id).expect("provider ID"),
                behavior,
            }
        }
    }

    #[async_trait]
    impl ProviderAdapter for TestAdapter {
        fn id(&self) -> ProviderId {
            self.id.clone()
        }

        fn detect(&self, _context: &ProviderContext<'_>) -> DetectionResult {
            DetectionResult {
                available: true,
                version: None,
                evidence: Vec::new(),
                warnings: Vec::new(),
            }
        }

        async fn enumerate(
            &self,
            _context: &ProviderContext<'_>,
        ) -> ProviderResult<crate::providers::ProviderEnumeration> {
            match self.behavior {
                Behavior::Empty => Ok(crate::providers::ProviderEnumeration::empty()),
                Behavior::Fail => Err(Box::new(ErrorEnvelope::new(
                    ReforgeErrorCode::ProviderParseFailed,
                    "fixture adapter failed",
                ))),
                Behavior::Pending => std::future::pending().await,
            }
        }

        fn normalize(&self, _observation: Observation) -> ProviderResult<Vec<Component>> {
            Ok(Vec::new())
        }

        fn plan_install(
            &self,
            _component: &Component,
            _target: &TargetFacts,
            _run_id: &RunId,
            _first_ordinal: u64,
        ) -> ProviderResult<Vec<Operation>> {
            Ok(Vec::new())
        }

        fn verify(
            &self,
            _component: &Component,
            _target: &TargetFacts,
        ) -> ProviderResult<Vec<VerificationRule>> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn one_adapter_failure_does_not_cancel_the_next() {
        let mut registry = AdapterRegistry::new();
        registry
            .register(
                ScanPhase::PackageExports,
                std::sync::Arc::new(TestAdapter::new("a-fail", Behavior::Fail)),
            )
            .expect("register failing adapter");
        registry
            .register(
                ScanPhase::PackageExports,
                std::sync::Arc::new(TestAdapter::new("b-ok", Behavior::Empty)),
            )
            .expect("register successful adapter");
        let coordinator = DiscoveryCoordinator::new(registry);
        let events = Mutex::new(Vec::new());
        let inventory = coordinator
            .scan(
                host(),
                &known_folders(),
                &ProcessRunner::new(),
                &CancellationToken::new(),
                |event| events.lock().expect("event lock").push(event),
            )
            .await
            .expect("scan with warning");

        assert!(
            inventory
                .warnings
                .iter()
                .any(|warning| warning.contains("a-fail"))
        );
        assert!(
            events
                .into_inner()
                .expect("events")
                .iter()
                .any(|event| event.message == "b-ok: completed")
        );
    }

    #[tokio::test]
    async fn entirely_failed_phase_is_reported_and_scan_continues() {
        let mut registry = AdapterRegistry::new();
        registry
            .register(
                ScanPhase::PackageExports,
                std::sync::Arc::new(TestAdapter::new("only-failure", Behavior::Fail)),
            )
            .expect("register failing adapter");
        let coordinator = DiscoveryCoordinator::new(registry);
        let events = Mutex::new(Vec::new());
        coordinator
            .scan(
                host(),
                &known_folders(),
                &ProcessRunner::new(),
                &CancellationToken::new(),
                |event| events.lock().expect("event lock").push(event),
            )
            .await
            .expect("failed phase remains an inventory with warnings");

        let events = events.into_inner().expect("events");
        assert!(events.iter().any(|event| {
            event.phase == ScanPhase::PackageExports && event.status == ProgressStatus::Failed
        }));
        assert!(events.iter().any(|event| {
            event.phase == ScanPhase::Correlation && event.status == ProgressStatus::Completed
        }));
    }

    #[tokio::test]
    async fn cancellation_interrupts_a_pending_adapter() {
        let mut registry = AdapterRegistry::new();
        registry
            .register(
                ScanPhase::PackageExports,
                std::sync::Arc::new(TestAdapter::new("pending", Behavior::Pending)),
            )
            .expect("register pending adapter");
        let coordinator = DiscoveryCoordinator::new(registry);
        let cancellation = CancellationToken::new();
        let trigger = cancellation.clone();
        let started = Instant::now();
        let folders = known_folders();
        let runner = ProcessRunner::new();
        let scan = coordinator.scan(host(), &folders, &runner, &cancellation, |_| {});
        let cancel = async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            trigger.cancel();
        };
        let (result, ()) = tokio::join!(scan, cancel);
        let error = result.expect_err("scan must cancel");
        assert_eq!(error.code, ReforgeErrorCode::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn adapter_execution_order_is_stable() {
        let mut registry = AdapterRegistry::new();
        registry
            .register(
                ScanPhase::RuntimeProbes,
                std::sync::Arc::new(TestAdapter::new("z-last", Behavior::Empty)),
            )
            .expect("register z");
        registry
            .register(
                ScanPhase::RuntimeProbes,
                std::sync::Arc::new(TestAdapter::new("a-first", Behavior::Empty)),
            )
            .expect("register a");
        let coordinator = DiscoveryCoordinator::new(registry);

        let first = scan_messages(&coordinator).await;
        let second = scan_messages(&coordinator).await;
        assert_eq!(first, second);
        assert_eq!(first, ["a-first: completed", "z-last: completed"]);
    }

    async fn scan_messages(coordinator: &DiscoveryCoordinator) -> Vec<String> {
        let events = Mutex::new(Vec::new());
        coordinator
            .scan(
                host(),
                &known_folders(),
                &ProcessRunner::new(),
                &CancellationToken::new(),
                |event| events.lock().expect("event lock").push(event),
            )
            .await
            .expect("scan");
        events
            .into_inner()
            .expect("events")
            .into_iter()
            .filter(|event| {
                event.phase == ScanPhase::RuntimeProbes && event.status == ProgressStatus::Progress
            })
            .map(|event| event.message)
            .collect()
    }

    fn known_folders() -> KnownFolderMap {
        KnownFolderMap::from_entries(BTreeMap::new())
    }

    fn host() -> HostFacts {
        HostFacts {
            os_version: "Windows 11".to_owned(),
            os_build: "26100".to_owned(),
            architecture: Architecture::X64,
            elevated: false,
            account_scope: AccountScope::User,
            sid_fingerprint: Some("fixture".to_owned()),
            known_folders: Vec::new(),
            drives: Vec::<DriveFact>::new(),
            free_bytes: Vec::<DriveFreeSpace>::new(),
        }
    }
}
