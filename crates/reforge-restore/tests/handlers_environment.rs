#![allow(dead_code)]

mod support;

use std::{collections::BTreeMap, sync::Arc};

use reforge_domain::{
    KnownFolderToken, ObjectIndex, Operation, OperationId, OperationKind, Precondition, RunId,
    SafeValueRef,
};
use reforge_platform_windows::CancellationToken;
use reforge_platform_windows::KnownFolderMap;
use reforge_restore::{
    EnvironmentRestoreHandler, ExecutionContext, MemoryUserEnvironment, OperationDisposition,
    OperationHandler, OperationSatisfaction,
};
use support::FixtureRoot;

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID")
}

fn component_id() -> reforge_domain::ComponentId {
    reforge_domain::ComponentId::new(format!("cmp_{}", "e".repeat(52))).expect("component ID")
}

fn roots(fixture: &FixtureRoot) -> KnownFolderMap {
    KnownFolderMap::from_entries(BTreeMap::from([
        (
            KnownFolderToken::UserProfile,
            fixture.tokens().user_profile.clone(),
        ),
        (
            KnownFolderToken::RoamingAppData,
            fixture.tokens().user_profile.clone(),
        ),
    ]))
}

fn operation(kind: OperationKind) -> Operation {
    Operation {
        id: OperationId::for_run(&run_id(), 0).expect("operation ID"),
        component: component_id(),
        kind,
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key: "restore-v1:environment-handler-test".to_owned(),
        verification: Vec::new(),
        requires_elevation: false,
        non_idempotent: false,
    }
}

fn context<'a>(
    target: &'a reforge_domain::TargetFacts,
    index: &'a ObjectIndex,
) -> ExecutionContext<'a> {
    ExecutionContext::new(target, index)
}

#[tokio::test]
async fn set_user_environment_persists_safe_value_and_broadcasts() {
    let fixture = FixtureRoot::new("handlers-environment-set").expect("fixture root");
    let backend = Arc::new(MemoryUserEnvironment::default());
    let handler = EnvironmentRestoreHandler::new(roots(&fixture)).with_backend(backend.clone());
    let operation = operation(OperationKind::SetUserEnvironment {
        name: "EDITOR_THEME".to_owned(),
        value: SafeValueRef::LiteralNonSecret("dark".to_owned()),
    });
    let target = support::fixtures::target_facts();
    let index = ObjectIndex {
        objects: Vec::new(),
    };
    let outcome = handler
        .execute(
            &operation,
            &context(&target, &index),
            &CancellationToken::new(),
        )
        .await
        .expect("environment update");
    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    assert_eq!(backend.value("editor_theme").as_deref(), Some("dark"));
    assert_eq!(backend.broadcast_count(), 1);
}

#[tokio::test]
async fn append_user_path_preserves_target_order_and_deduplicates() {
    let fixture = FixtureRoot::new("handlers-environment-path").expect("fixture root");
    let profile = fixture.tokens().user_profile.display().to_string();
    let existing = format!("C:\\Tools;{profile}");
    let backend = Arc::new(MemoryUserEnvironment::with_values([(
        "Path".to_owned(),
        existing,
    )]));
    let handler = EnvironmentRestoreHandler::new(roots(&fixture)).with_backend(backend.clone());
    let operation = operation(OperationKind::AppendUserPath {
        entries: vec![
            reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "").expect("token"),
            reforge_domain::PathToken::new(KnownFolderToken::RoamingAppData, "").expect("token"),
            reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "bin").expect("token"),
        ],
    });
    let target = support::fixtures::target_facts();
    let index = ObjectIndex {
        objects: Vec::new(),
    };
    let outcome = handler
        .execute(
            &operation,
            &context(&target, &index),
            &CancellationToken::new(),
        )
        .await
        .expect("PATH update");
    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    let updated = backend.value("PATH").expect("updated PATH");
    let path_entries = updated.split(';').collect::<Vec<_>>();
    assert_eq!(path_entries.first(), Some(&"C:\\Tools"));
    assert_eq!(
        path_entries
            .iter()
            .filter(|entry| entry.eq_ignore_ascii_case(&profile))
            .count(),
        1,
    );
    assert!(
        path_entries
            .last()
            .is_some_and(|entry| entry.ends_with("\\bin"))
    );
    assert_eq!(backend.broadcast_count(), 1);
}

#[tokio::test]
async fn secret_like_environment_write_becomes_manual_without_side_effects() {
    let fixture = FixtureRoot::new("handlers-environment-secret").expect("fixture root");
    let backend = Arc::new(MemoryUserEnvironment::default());
    let handler = EnvironmentRestoreHandler::new(roots(&fixture)).with_backend(backend.clone());
    let operation = operation(OperationKind::SetUserEnvironment {
        name: "SERVICE_API_TOKEN".to_owned(),
        value: SafeValueRef::LiteralNonSecret("not persisted".to_owned()),
    });
    let target = support::fixtures::target_facts();
    let index = ObjectIndex {
        objects: Vec::new(),
    };
    let outcome = handler
        .execute(
            &operation,
            &context(&target, &index),
            &CancellationToken::new(),
        )
        .await
        .expect("manual environment outcome");
    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    assert!(backend.value("SERVICE_API_TOKEN").is_none());
    assert_eq!(backend.broadcast_count(), 0);
}

#[tokio::test]
async fn matching_user_environment_is_reported_satisfied() {
    let fixture = FixtureRoot::new("handlers-environment-satisfied").expect("fixture root");
    let backend = Arc::new(MemoryUserEnvironment::with_values([(
        "EDITOR_THEME".to_owned(),
        "dark".to_owned(),
    )]));
    let handler = EnvironmentRestoreHandler::new(roots(&fixture)).with_backend(backend);
    let operation = operation(OperationKind::SetUserEnvironment {
        name: "EDITOR_THEME".to_owned(),
        value: SafeValueRef::LiteralNonSecret("dark".to_owned()),
    });
    let target = support::fixtures::target_facts();
    let index = ObjectIndex {
        objects: Vec::new(),
    };
    let satisfaction = handler
        .is_satisfied(
            &operation,
            &context(&target, &index),
            &CancellationToken::new(),
        )
        .await
        .expect("satisfaction check");
    assert!(matches!(
        satisfaction,
        OperationSatisfaction::Satisfied { .. }
    ));
}
