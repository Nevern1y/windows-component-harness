//! Deterministic, explainable component recommendations.
//!
//! This module scores a normalized graph only.  It never mutates the graph,
//! selects artifacts, reads secrets, or authorizes restore operations.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, VecDeque},
};

use reforge_domain::{
    ArtifactPolicy, Component, ComponentGraph, ComponentId, ComponentKind, Confidence,
    ExplanationChip, KnownFolderToken, Portability, RecommendationScore, RestoreStrategy,
    VerificationRule,
};
use serde_json::Value;

const DEFAULT_LARGE_ARTIFACT_THRESHOLD_BYTES: u64 = 16 * 1024 * 1024;

const CODE_CONFIRMED_IDENTITY: &str = "confirmed_identity";
const CODE_REACHABLE_EXECUTABLE: &str = "reachable_executable";
const CODE_REQUIRED_DEPENDENCY: &str = "required_dependency";
const CODE_PORTABLE_CONFIGURATION: &str = "portable_configuration";
const CODE_USER_FACING_CATEGORY: &str = "user_facing_category";
const CODE_REPRODUCIBLE_SOURCE: &str = "reproducible_source";
const CODE_MACHINE_ACCOUNT_BOUND: &str = "machine_or_account_bound";
const CODE_MANUAL_PRIVILEGED: &str = "manual_or_privileged";
const CODE_LARGE_DATA: &str = "large_data";
const CODE_UNKNOWN_SOURCE: &str = "unknown_source_or_low_confidence";
const CODE_SENSITIVE: &str = "sensitive_state_excluded";
const CODE_NO_SIGNAL: &str = "no_qualifying_signal";

/// Score every component in a graph and return the stable recommendation order.
///
/// The score applies the fixed table in §15.1.  `recommended` is an automatic
/// suggestion only: sensitive, large, machine/account-bound, privileged, and
/// manual-only components are never marked recommended even when their numeric
/// score is positive.  Required dependency promotion is applied to a fixed
/// point so dependency chains and legal cycles remain deterministic.
pub fn recommend(graph: &ComponentGraph) -> Vec<RecommendationScore> {
    let mut components = graph.components.iter().collect::<Vec<_>>();
    components.sort_by(component_order);

    let component_indexes = components
        .iter()
        .enumerate()
        .map(|(index, component)| (component.id.clone(), index))
        .collect::<BTreeMap<_, _>>();

    let mut scored = components
        .iter()
        .map(|component| score_component(component))
        .collect::<Vec<_>>();

    let required_dependencies = required_dependencies(graph, &component_indexes);
    let mut queue = scored
        .iter()
        .enumerate()
        .filter_map(|(index, score)| score.recommended.then_some(index))
        .collect::<VecDeque<_>>();

    while let Some(source_index) = queue.pop_front() {
        let source_id = &scored[source_index].component.id;
        let Some(targets) = required_dependencies.get(source_id) else {
            continue;
        };
        for target_id in targets {
            let Some(&target_index) = component_indexes.get(target_id) else {
                continue;
            };
            if target_index == source_index || scored[target_index].promoted {
                continue;
            }
            let target = &mut scored[target_index];
            target.promoted = true;
            add_chip(
                &mut target.score,
                &mut target.chips,
                CODE_REQUIRED_DEPENDENCY,
                "Required dependency of a recommended component",
                20,
            );
            if scored[target_index].auto_allowed
                && scored[target_index].score > 0
                && !scored[target_index].recommended
            {
                scored[target_index].recommended = true;
                queue.push_back(target_index);
            }
        }
    }

    let mut output = scored
        .into_iter()
        .map(|score| RecommendationScore {
            component: score.component.id.clone(),
            score: score.score,
            recommended: score.recommended,
            chips: score.chips,
        })
        .collect::<Vec<_>>();
    output.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| {
                component_category(components[component_indexes[&left.component]]).cmp(
                    &component_category(components[component_indexes[&right.component]]),
                )
            })
            .then_with(|| left.component.cmp(&right.component))
    });
    output
}

struct ScoredComponent<'a> {
    component: &'a Component,
    score: i16,
    chips: Vec<ExplanationChip>,
    auto_allowed: bool,
    recommended: bool,
    promoted: bool,
}

fn score_component(component: &Component) -> ScoredComponent<'_> {
    let sensitive = is_sensitive(component);
    let large = is_large(component);
    let machine_or_account_bound = is_machine_or_account_bound(component);
    let manual_or_privileged = is_manual_or_privileged(component);
    let mut score = 0;
    let mut chips = Vec::new();

    if matches!(
        component.kind,
        ComponentKind::Package | ComponentKind::Application
    ) && component.confidence == Confidence::Confirmed
    {
        add_chip(
            &mut score,
            &mut chips,
            CODE_CONFIRMED_IDENTITY,
            "Confirmed package or application identity",
            30,
        );
    }
    if executable_is_reachable(component) {
        add_chip(
            &mut score,
            &mut chips,
            CODE_REACHABLE_EXECUTABLE,
            "Executable reachability was observed",
            20,
        );
    }
    if has_portable_configuration(component) {
        add_chip(
            &mut score,
            &mut chips,
            CODE_PORTABLE_CONFIGURATION,
            "Documented portable configuration is available",
            15,
        );
    }
    if matches!(
        component.kind,
        ComponentKind::Application
            | ComponentKind::Editor
            | ComponentKind::Browser
            | ComponentKind::Harness
    ) {
        add_chip(
            &mut score,
            &mut chips,
            CODE_USER_FACING_CATEGORY,
            "User-facing application category",
            10,
        );
    }
    if has_reproducible_source(component) {
        add_chip(
            &mut score,
            &mut chips,
            CODE_REPRODUCIBLE_SOURCE,
            "Source and provenance are reproducible",
            10,
        );
    }
    if machine_or_account_bound {
        add_chip(
            &mut score,
            &mut chips,
            CODE_MACHINE_ACCOUNT_BOUND,
            "State is bound to a machine or account",
            -25,
        );
    }
    if manual_or_privileged {
        add_chip(
            &mut score,
            &mut chips,
            CODE_MANUAL_PRIVILEGED,
            "Restore requires privileged or manual review",
            -20,
        );
    }
    if large {
        add_chip(
            &mut score,
            &mut chips,
            CODE_LARGE_DATA,
            "Large data requires explicit selection",
            -15,
        );
    }
    if is_low_confidence(component) || !has_reproducible_source(component) {
        add_chip(
            &mut score,
            &mut chips,
            CODE_UNKNOWN_SOURCE,
            "Source or identity confidence is incomplete",
            -10,
        );
    }

    let auto_allowed = !sensitive
        && !large
        && !machine_or_account_bound
        && !manual_or_privileged
        && !matches!(component.restore.primary, RestoreStrategy::SecretExportable);
    if sensitive {
        chips.push(ExplanationChip {
            code: CODE_SENSITIVE.to_owned(),
            label: "Sensitive state is never automatically selected".to_owned(),
            delta: 0,
        });
    }
    if chips.is_empty() {
        chips.push(ExplanationChip {
            code: CODE_NO_SIGNAL.to_owned(),
            label: "No qualifying recommendation signal was observed".to_owned(),
            delta: 0,
        });
    }

    ScoredComponent {
        component,
        score,
        chips,
        auto_allowed,
        recommended: auto_allowed && score > 0,
        promoted: false,
    }
}

fn add_chip(
    score: &mut i16,
    chips: &mut Vec<ExplanationChip>,
    code: &str,
    label: &str,
    delta: i16,
) {
    *score = score.saturating_add(delta);
    chips.push(ExplanationChip {
        code: code.to_owned(),
        label: label.to_owned(),
        delta,
    });
}

fn required_dependencies(
    graph: &ComponentGraph,
    indexes: &BTreeMap<ComponentId, usize>,
) -> BTreeMap<ComponentId, BTreeSet<ComponentId>> {
    let mut required = BTreeMap::<ComponentId, BTreeSet<ComponentId>>::new();
    for edge in graph.edges.iter().chain(
        graph
            .components
            .iter()
            .flat_map(|component| component.dependencies.iter()),
    ) {
        if edge.required && indexes.contains_key(&edge.from) && indexes.contains_key(&edge.to) {
            required
                .entry(edge.from.clone())
                .or_default()
                .insert(edge.to.clone());
        }
    }
    required
}

fn executable_is_reachable(component: &Component) -> bool {
    if explicit_reachability_hint(component) {
        return true;
    }
    component.verification.iter().any(|rule| {
        matches!(
            rule,
            VerificationRule::FileVersion { destination, .. }
                if matches!(destination.root, KnownFolderToken::StartMenu)
        )
    })
}

fn explicit_reachability_hint(component: &Component) -> bool {
    for key in [
        "reachable",
        "executable_reachable",
        "path_reachable",
        "start_menu_or_app_paths",
    ] {
        if component.extensions.get(key) == Some(&Value::Bool(true)) {
            return true;
        }
    }
    let Some(value) = component.extensions.get("reachability") else {
        return false;
    };
    match value {
        Value::String(value) => reachability_label(value),
        Value::Array(values) => values
            .iter()
            .any(|value| value.as_str().is_some_and(reachability_label)),
        _ => false,
    }
}

fn reachability_label(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "path" | "app_paths" | "start_menu" | "shortcut"
    )
}

fn has_portable_configuration(component: &Component) -> bool {
    matches!(
        component.restore.primary,
        RestoreStrategy::ConfigPortable | RestoreStrategy::ExportImport
    ) || component.artifacts.iter().any(|artifact| {
        matches!(
            artifact.policy,
            ArtifactPolicy::Config | ArtifactPolicy::Export
        )
    })
}

fn has_reproducible_source(component: &Component) -> bool {
    component.provenance.as_ref().is_some_and(|provenance| {
        provenance.source_url.is_some()
            || (provenance.provider.is_some()
                && provenance
                    .package_id
                    .as_ref()
                    .is_some_and(|package_id| !package_id.trim().is_empty()))
    })
}

fn is_low_confidence(component: &Component) -> bool {
    matches!(component.confidence, Confidence::Low | Confidence::Unknown)
}

fn is_machine_or_account_bound(component: &Component) -> bool {
    matches!(
        component.restore.portability,
        Portability::MachineBound
            | Portability::UserBound
            | Portability::ApplicationBound
            | Portability::ReauthRequired
    ) || matches!(
        component.restore.primary,
        RestoreStrategy::MachineBound | RestoreStrategy::ReauthRequired
    )
}

fn is_manual_or_privileged(component: &Component) -> bool {
    component.restore.requires_elevation
        || component.compatibility.requires_elevation
        || matches!(
            component.restore.primary,
            RestoreStrategy::Manual
                | RestoreStrategy::PortableBinary
                | RestoreStrategy::Partial
                | RestoreStrategy::Unknown
        )
        || matches!(
            component.kind,
            ComponentKind::Service | ComponentKind::ScheduledTask | ComponentKind::SystemFeature
        )
}

fn is_sensitive(component: &Component) -> bool {
    component.selection.sensitive
        || matches!(component.kind, ComponentKind::SecretReference)
        || matches!(component.restore.primary, RestoreStrategy::SecretExportable)
        || component
            .artifacts
            .iter()
            .any(|artifact| matches!(artifact.policy, ArtifactPolicy::SecretReference))
}

fn is_large(component: &Component) -> bool {
    component.selection.size_bytes > DEFAULT_LARGE_ARTIFACT_THRESHOLD_BYTES
        || component.artifacts.iter().any(|artifact| {
            artifact.size_bytes > DEFAULT_LARGE_ARTIFACT_THRESHOLD_BYTES
                || matches!(artifact.policy, ArtifactPolicy::LargeOptIn)
        })
        || component.extensions.get("large_data") == Some(&Value::Bool(true))
}

fn component_order(left: &&Component, right: &&Component) -> Ordering {
    left.id
        .cmp(&right.id)
        .then_with(|| component_category(left).cmp(&component_category(right)))
        .then_with(|| left.display_name.cmp(&right.display_name))
}

fn component_category(component: &Component) -> u8 {
    match component.kind {
        ComponentKind::Application => 0,
        ComponentKind::Package => 1,
        ComponentKind::Runtime => 2,
        ComponentKind::Tool => 3,
        ComponentKind::Harness => 4,
        ComponentKind::McpServer => 5,
        ComponentKind::Skill => 6,
        ComponentKind::Agent => 7,
        ComponentKind::Hook => 8,
        ComponentKind::Plugin => 9,
        ComponentKind::Browser => 10,
        ComponentKind::BrowserProfile => 11,
        ComponentKind::Editor => 12,
        ComponentKind::Extension => 13,
        ComponentKind::Configuration => 14,
        ComponentKind::DataArtifact => 15,
        ComponentKind::SecretReference => 16,
        ComponentKind::EnvironmentVariable => 17,
        ComponentKind::SystemFeature => 18,
        ComponentKind::Service => 19,
        ComponentKind::ScheduledTask => 20,
        ComponentKind::Shell => 21,
        ComponentKind::PortableBinary => 22,
        ComponentKind::WslDistribution => 23,
        ComponentKind::DockerContext => 24,
        ComponentKind::DockerImage => 25,
        ComponentKind::DockerVolume => 26,
        ComponentKind::Unknown => 27,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reforge_domain::{
        ArtifactId, ArtifactRef, Compatibility, ConfigScope, ContentType, DependencyEdge, Identity,
        IdentityQuality, PathToken, Provenance, Publisher, RestoreDescriptor, SelectionMetadata,
        VersionValue,
    };
    use url::Url;

    fn id(suffix: char) -> ComponentId {
        ComponentId::new(format!("cmp_{}", suffix.to_string().repeat(52))).expect("component ID")
    }

    fn identity() -> Identity {
        Identity {
            provider_package: None,
            provider_source: None,
            package_family: None,
            product_name: Some("Example".to_owned()),
            executable_name: Some("example.exe".to_owned()),
            publisher: Some("Example Publisher".to_owned()),
            executable_hash: Some("hash".to_owned()),
            install_role: Some("application".to_owned()),
            identity_quality: IdentityQuality::Product,
        }
    }

    fn component(id: ComponentId, kind: ComponentKind) -> Component {
        Component {
            id,
            kind,
            identity: identity(),
            display_name: "Example".to_owned(),
            version: Some(VersionValue {
                raw: "1.0".to_owned(),
                normalized: Some("1.0.0".to_owned()),
            }),
            architecture: None,
            publisher: Some(Publisher {
                name: "Example Publisher".to_owned(),
                certificate_thumbprint: None,
            }),
            provenance: None,
            evidence: Vec::new(),
            confidence: Confidence::Medium,
            dependencies: Vec::new(),
            artifacts: Vec::new(),
            restore: RestoreDescriptor {
                primary: RestoreStrategy::Reinstall,
                alternatives: Vec::new(),
                portability: Portability::SupportedExport,
                requires_elevation: false,
                requires_user_action: false,
                rationale: Vec::new(),
            },
            compatibility: Compatibility {
                required_os: None,
                required_architecture: None,
                requires_provider: None,
                requires_runtime: None,
                requires_elevation: false,
                requires_wsl: false,
                requires_docker: false,
            },
            verification: Vec::new(),
            selection: SelectionMetadata {
                recommended: false,
                score: 0,
                selected_by_default: false,
                sensitive: false,
                size_bytes: 0,
            },
            extensions: BTreeMap::new(),
        }
    }

    fn reproducible(mut component: Component) -> Component {
        component.confidence = Confidence::Confirmed;
        component.provenance = Some(Provenance {
            provider: Some(reforge_domain::ProviderId::new("winget").expect("provider")),
            package_id: Some("Example.App".to_owned()),
            source_url: Some(Url::parse("https://example.test/source").expect("source")),
            observed_version: Some("1.0".to_owned()),
            adapter_id: "fixture".to_owned(),
            adapter_version: "1".to_owned(),
        });
        component
            .extensions
            .insert("executable_reachable".to_owned(), Value::Bool(true));
        component.artifacts.push(ArtifactRef {
            id: ArtifactId::new("fixture-config").expect("artifact ID"),
            source_path: PathToken::new(KnownFolderToken::UserProfile, "config.json")
                .expect("path token"),
            scope: ConfigScope::User,
            size_bytes: 100,
            content_type: ContentType::Json,
            policy: ArtifactPolicy::Config,
            object: None,
        });
        component
    }

    #[test]
    fn fixed_positive_score_and_explanations_are_complete() {
        let component = reproducible(component(id('a'), ComponentKind::Application));
        let scores = recommend(&ComponentGraph {
            components: vec![component],
            edges: Vec::new(),
        });
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].score, 85);
        assert!(scores[0].recommended);
        assert_eq!(
            scores[0]
                .chips
                .iter()
                .map(|chip| chip.delta as i32)
                .sum::<i32>(),
            scores[0].score as i32
        );
    }

    #[test]
    fn penalties_block_unsafe_automatic_recommendation() {
        let mut component = component(id('a'), ComponentKind::DataArtifact);
        component.confidence = Confidence::Unknown;
        component.restore.primary = RestoreStrategy::Manual;
        component.restore.portability = Portability::MachineBound;
        component.selection.size_bytes = DEFAULT_LARGE_ARTIFACT_THRESHOLD_BYTES + 1;
        let scores = recommend(&ComponentGraph {
            components: vec![component],
            edges: Vec::new(),
        });
        assert_eq!(scores[0].score, -70);
        assert!(!scores[0].recommended);
    }

    #[test]
    fn required_dependencies_promote_recursively_once() {
        let root = reproducible(component(id('a'), ComponentKind::Application));
        let mut dependency = component(id('b'), ComponentKind::Runtime);
        dependency.confidence = Confidence::Unknown;
        let mut transitive = component(id('c'), ComponentKind::Tool);
        transitive.confidence = Confidence::Unknown;
        dependency.dependencies.push(DependencyEdge {
            from: dependency.id.clone(),
            to: transitive.id.clone(),
            kind: reforge_domain::DependencyKind::RequiredRuntime,
            required: true,
            evidence: Vec::new(),
            confidence: Confidence::High,
        });
        let edges = vec![DependencyEdge {
            from: root.id.clone(),
            to: dependency.id.clone(),
            kind: reforge_domain::DependencyKind::RequiredRuntime,
            required: true,
            evidence: Vec::new(),
            confidence: Confidence::High,
        }];
        let scores = recommend(&ComponentGraph {
            components: vec![transitive, dependency, root],
            edges,
        });
        let dependency_score = scores
            .iter()
            .find(|score| score.component == id('b'))
            .expect("dependency recommendation");
        let transitive_score = scores
            .iter()
            .find(|score| score.component == id('c'))
            .expect("transitive recommendation");
        assert_eq!(dependency_score.score, 10);
        assert!(dependency_score.recommended);
        assert_eq!(transitive_score.score, 10);
        assert!(transitive_score.recommended);
        assert_eq!(
            dependency_score
                .chips
                .iter()
                .filter(|chip| chip.code == CODE_REQUIRED_DEPENDENCY)
                .count(),
            1
        );
    }

    #[test]
    fn sensitive_and_large_items_are_never_recommended() {
        let mut secret = component(id('a'), ComponentKind::SecretReference);
        secret.confidence = Confidence::Confirmed;
        let mut large = reproducible(component(id('b'), ComponentKind::DataArtifact));
        large.selection.size_bytes = DEFAULT_LARGE_ARTIFACT_THRESHOLD_BYTES + 1;
        let scores = recommend(&ComponentGraph {
            components: vec![secret, large],
            edges: Vec::new(),
        });
        assert!(scores.iter().all(|score| !score.recommended));
        assert!(
            scores
                .iter()
                .flat_map(|score| score.chips.iter())
                .any(|chip| chip.code == CODE_SENSITIVE)
        );
    }

    #[test]
    fn output_order_is_score_then_category_then_component_id() {
        let mut application = reproducible(component(id('b'), ComponentKind::Application));
        let mut package = reproducible(component(id('a'), ComponentKind::Package));
        application.extensions.clear();
        package.extensions.clear();
        let scores = recommend(&ComponentGraph {
            components: vec![application, package],
            edges: Vec::new(),
        });
        assert_eq!(scores[0].component, id('b'));
        assert_eq!(scores[1].component, id('a'));
    }
}
