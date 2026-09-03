//! Deterministic component and dependency-graph normalization.
//!
//! Provider adapters intentionally emit observations independently. This module
//! is the single merge boundary: it correlates only supported identity facts,
//! preserves conflicts as inspectable metadata, and rewrites all graph edges
//! to the selected canonical component IDs.

use std::collections::{BTreeMap, BTreeSet};

use reforge_domain::{
    ArtifactId, ArtifactRef, Compatibility, Component, ComponentId, ComponentKind, DependencyEdge,
    DependencyKind, ErrorEnvelope, Evidence, EvidenceId, Identity, IdentityQuality, PackageGraph,
    Publisher, RedactionPolicy, RestoreDescriptor, VerificationRule,
};
use serde_json::{Value, json};

use crate::{
    ProviderResult,
    evidence::{EvidenceConfidence, confidence_for_evidence},
};

const MAX_COMPONENTS: usize = 250_000;
const MAX_EDGES: usize = 1_000_000;
const MAX_FACT_BYTES: usize = 2 * 1024;

/// Normalize independently-produced components and edges into one graph.
///
/// Components merge only when a supported identity key agrees and no higher-
/// priority identity fact conflicts. Provider/package identity conflicts are
/// hard merge boundaries; lower-quality observations cannot bridge them.
/// Unmatched input is retained with `Confidence::Unknown` rather than discarded.
pub fn deduplicate_graph(
    components: Vec<Component>,
    edges: Vec<DependencyEdge>,
    evidence: &[Evidence],
) -> ProviderResult<PackageGraph> {
    if components.len() > MAX_COMPONENTS {
        return Err(graph_error("component graph exceeds the reviewed bound"));
    }
    let embedded_edges = components
        .iter()
        .try_fold(0usize, |count, component| {
            count.checked_add(component.dependencies.len())
        })
        .ok_or_else(|| graph_error("dependency graph edge count overflow"))?;
    let total_edges = edges
        .len()
        .checked_add(embedded_edges)
        .ok_or_else(|| graph_error("dependency graph edge count overflow"))?;
    if total_edges > MAX_EDGES {
        return Err(graph_error("dependency graph exceeds the reviewed bound"));
    }
    let evidence_records = evidence_records(evidence)?;

    for component in &components {
        if component
            .evidence
            .iter()
            .any(|reference| reference.strength > 100)
        {
            return Err(graph_error("component evidence strength exceeds 100"));
        }
    }
    if edges
        .iter()
        .chain(
            components
                .iter()
                .flat_map(|component| component.dependencies.iter()),
        )
        .any(|edge| {
            edge.evidence.iter().any(|evidence_id| {
                evidence_records
                    .get(evidence_id)
                    .is_some_and(|record| record.strength > 100)
            })
        })
    {
        return Err(graph_error("edge evidence strength exceeds 100"));
    }

    let mut components = components;
    components.sort_by(component_order);
    let groups = build_groups(&components);

    let mut component_mapping = BTreeMap::<ComponentId, ComponentId>::new();
    let mut normalized_components = Vec::with_capacity(groups.len());
    for group in groups {
        let merged = merge_component(&group, &components, &evidence_records)?;
        for index in group {
            let source_id = components[index].id.clone();
            component_mapping.insert(source_id, merged.id.clone());
        }
        normalized_components.push(merged);
    }

    let mut normalized_edges =
        merge_edges(&components, &edges, &component_mapping, &evidence_records)?;
    normalized_components.sort_by(|left, right| left.id.cmp(&right.id));
    normalized_edges.sort_by(edge_order);

    for component in &mut normalized_components {
        component.dependencies = normalized_edges
            .iter()
            .filter(|edge| edge.from == component.id)
            .cloned()
            .collect();
    }

    Ok(PackageGraph {
        components: normalized_components,
        edges: normalized_edges,
    })
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProviderKey {
    provider: String,
    source: String,
    package: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum IdentityKey {
    Provider(ProviderKey),
    PackageFamily {
        family: String,
        publisher: String,
    },
    SignedProduct {
        product: String,
        certificate: String,
    },
    ExecutableProduct {
        product: String,
        publisher: String,
        install_role: String,
    },
    LocalExecutable {
        executable: String,
        hash: String,
    },
    Opaque(ComponentId),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EdgeKey {
    from: ComponentId,
    to: ComponentId,
    kind: u8,
    required: bool,
}

struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<u8>,
    identity_keys: Vec<BTreeSet<IdentityKey>>,
}

impl UnionFind {
    fn new(components: &[Component]) -> Self {
        let identity_keys = components
            .iter()
            .map(|component| {
                identity_keys_without_fallback(component)
                    .into_iter()
                    .collect::<BTreeSet<_>>()
            })
            .collect();
        Self {
            parent: (0..components.len()).collect(),
            rank: vec![0; components.len()],
            identity_keys,
        }
    }

    fn root(&mut self, index: usize) -> usize {
        if self.parent[index] != index {
            let parent = self.parent[index];
            self.parent[index] = self.root(parent);
        }
        self.parent[index]
    }

    fn union_if_compatible(&mut self, left: usize, right: usize) {
        let mut left_root = self.root(left);
        let mut right_root = self.root(right);
        if left_root == right_root {
            return;
        }
        if identity_priority_conflicts(
            &self.identity_keys[left_root],
            &self.identity_keys[right_root],
        ) {
            return;
        }
        let mut identity_keys = self.identity_keys[left_root].clone();
        identity_keys.extend(self.identity_keys[right_root].iter().cloned());
        if self.rank[left_root] < self.rank[right_root] {
            std::mem::swap(&mut left_root, &mut right_root);
        }
        self.parent[right_root] = left_root;
        self.identity_keys[left_root] = identity_keys;
        if self.rank[left_root] == self.rank[right_root] {
            self.rank[left_root] = self.rank[left_root].saturating_add(1);
        }
    }
}

fn identity_priority_conflicts(
    left: &BTreeSet<IdentityKey>,
    right: &BTreeSet<IdentityKey>,
) -> bool {
    let mut shared_higher_identity = false;
    for tier in 0..=4 {
        let left_keys = left
            .iter()
            .filter(|key| identity_key_tier(key) == tier)
            .collect::<Vec<_>>();
        let right_keys = right
            .iter()
            .filter(|key| identity_key_tier(key) == tier)
            .collect::<Vec<_>>();
        let shared_identity = left_keys
            .iter()
            .any(|left_key| right_keys.contains(left_key));
        let conflicting_identity =
            !left_keys.is_empty() && !right_keys.is_empty() && !shared_identity;
        if conflicting_identity && !shared_higher_identity {
            return true;
        }
        shared_higher_identity |= shared_identity;
    }
    false
}

fn identity_key_tier(key: &IdentityKey) -> u8 {
    match key {
        IdentityKey::Provider(_) => 0,
        IdentityKey::PackageFamily { .. } => 1,
        IdentityKey::SignedProduct { .. } => 2,
        IdentityKey::ExecutableProduct { .. } => 3,
        IdentityKey::LocalExecutable { .. } => 4,
        IdentityKey::Opaque(_) => u8::MAX,
    }
}

fn build_groups(components: &[Component]) -> Vec<Vec<usize>> {
    let mut union_find = UnionFind::new(components);
    let mut key_members = BTreeMap::<IdentityKey, BTreeMap<Option<ProviderKey>, Vec<usize>>>::new();
    let mut id_members = BTreeMap::<ComponentId, Vec<usize>>::new();

    for (index, component) in components.iter().enumerate() {
        let provider = provider_key(component);
        for key in identity_keys(component) {
            key_members
                .entry(key)
                .or_default()
                .entry(provider.clone())
                .or_default()
                .push(index);
        }
        id_members
            .entry(component.id.clone())
            .or_default()
            .push(index);
    }

    for buckets in key_members.into_values() {
        for members in buckets.values() {
            union_members(&mut union_find, members);
        }
        let provider_buckets = buckets
            .iter()
            .filter(|(provider, _)| provider.is_some())
            .collect::<Vec<_>>();
        if provider_buckets.len() == 1 {
            let Some(unowned) = buckets.get(&None) else {
                continue;
            };
            let owned = provider_buckets[0].1;
            for &unowned_index in unowned {
                for &owned_index in owned {
                    union_find.union_if_compatible(unowned_index, owned_index);
                }
            }
        }
    }
    for members in id_members.values() {
        union_members(&mut union_find, members);
    }

    let mut groups = BTreeMap::<usize, Vec<usize>>::new();
    for index in 0..components.len() {
        let root = union_find.root(index);
        groups.entry(root).or_default().push(index);
    }
    groups.into_values().collect()
}

fn union_members(union_find: &mut UnionFind, members: &[usize]) {
    let Some((&first, rest)) = members.split_first() else {
        return;
    };
    for &member in rest {
        union_find.union_if_compatible(first, member);
    }
}

fn identity_keys(component: &Component) -> Vec<IdentityKey> {
    let mut keys = BTreeSet::new();
    if let Some(provider) = provider_key(component) {
        keys.insert(IdentityKey::Provider(provider));
    }
    let publisher = publisher_name(component);
    if let (Some(family), Some(publisher)) = (
        normalized(component.identity.package_family.as_deref()),
        publisher.clone(),
    ) {
        keys.insert(IdentityKey::PackageFamily { family, publisher });
    }
    if let (Some(product), Some(certificate)) = (
        normalized(component.identity.product_name.as_deref()),
        component
            .publisher
            .as_ref()
            .and_then(|publisher| normalized(publisher.certificate_thumbprint.as_deref())),
    ) {
        keys.insert(IdentityKey::SignedProduct {
            product,
            certificate,
        });
    }
    if let (Some(product), Some(publisher), Some(install_role)) = (
        normalized(component.identity.product_name.as_deref()),
        publisher,
        normalized(component.identity.install_role.as_deref()),
    ) {
        keys.insert(IdentityKey::ExecutableProduct {
            product,
            publisher,
            install_role,
        });
    }
    if let (Some(executable), Some(hash)) = (
        normalized(component.identity.executable_name.as_deref()),
        normalized(component.identity.executable_hash.as_deref()),
    ) {
        keys.insert(IdentityKey::LocalExecutable { executable, hash });
    }
    if keys.is_empty() {
        keys.insert(IdentityKey::Opaque(component.id.clone()));
    }
    keys.into_iter().collect()
}

fn provider_key(component: &Component) -> Option<ProviderKey> {
    let (provider, package) = component.identity.provider_package.as_ref()?;
    Some(ProviderKey {
        provider: normalized(Some(provider.as_str()))?,
        source: normalized(component.identity.provider_source.as_deref())?,
        package: normalized(Some(package.as_str()))?,
    })
}

fn publisher_name(component: &Component) -> Option<String> {
    component
        .publisher
        .as_ref()
        .and_then(|publisher| normalized(Some(publisher.name.as_str())))
        .or_else(|| normalized(component.identity.publisher.as_deref()))
}

fn normalized(value: Option<&str>) -> Option<String> {
    let value = value?.trim().to_lowercase();
    if value.is_empty() || value.chars().any(char::is_control) {
        None
    } else {
        Some(value)
    }
}

fn component_order(left: &Component, right: &Component) -> std::cmp::Ordering {
    left.id
        .cmp(&right.id)
        .then_with(|| component_kind_order(&left.kind).cmp(&component_kind_order(&right.kind)))
        .then_with(|| left.display_name.cmp(&right.display_name))
}

fn component_kind_order(kind: &ComponentKind) -> u8 {
    match kind {
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

fn identity_quality_order(quality: &IdentityQuality) -> u8 {
    match quality {
        IdentityQuality::Provider => 5,
        IdentityQuality::PackageFamily => 4,
        IdentityQuality::SignedProduct => 3,
        IdentityQuality::Product => 2,
        IdentityQuality::Local => 1,
    }
}

fn merge_component(
    members: &[usize],
    components: &[Component],
    evidence_records: &BTreeMap<EvidenceId, Evidence>,
) -> ProviderResult<Component> {
    let base_index = members
        .iter()
        .copied()
        .max_by(|left, right| {
            identity_quality_order(&components[*left].identity.identity_quality)
                .cmp(&identity_quality_order(
                    &components[*right].identity.identity_quality,
                ))
                .then_with(|| components[*right].id.cmp(&components[*left].id))
        })
        .ok_or_else(|| graph_error("component group was unexpectedly empty"))?;
    let base = &components[base_index];
    let identity_unverified = members
        .iter()
        .any(|&index| identity_keys_without_fallback(&components[index]).is_empty());
    let conflicts = collect_conflicts(members, components);
    let conflicting_facts = conflicts.has_any();
    let mut merged = base.clone();

    merged.identity = merge_identity(members, components, &base.identity);
    merged.publisher = merge_publisher(members, components, base.publisher.clone());
    merged.version = merge_version(members, components, base.version.clone());
    merged.provenance = base.provenance.clone().or_else(|| {
        members
            .iter()
            .filter_map(|&index| components[index].provenance.clone())
            .next()
    });
    if merged.display_name.is_empty() {
        merged.display_name = members
            .iter()
            .map(|&index| components[index].display_name.as_str())
            .filter(|value| !value.is_empty())
            .min()
            .unwrap_or("Unknown component")
            .to_owned();
    }
    merged.restore = merge_restore(members, components, &base.restore);
    merged.compatibility = merge_compatibility(members, components, &base.compatibility);
    merged.selection = merge_selection(members, components, &base.selection);
    merged.artifacts = merge_artifacts(members, components);
    merged.verification = merge_verification(members, components)?;
    merged.evidence = merge_evidence_refs(members, components);
    merged.extensions = base.extensions.clone();

    match ComponentId::from_identity(&merged.identity, merged.publisher.as_ref()) {
        Ok(canonical) => {
            merged.id = canonical.id;
            merged.identity.identity_quality = canonical.quality;
        }
        Err(_) => {
            merged.identity = base.identity.clone();
            merged.publisher = base.publisher.clone();
            merged.id = base.id.clone();
        }
    }

    let confidence = confidence_for_evidence(
        &merged
            .evidence
            .iter()
            .map(|reference| reference.id.clone())
            .collect::<Vec<_>>(),
        evidence_records,
        identity_unverified,
        conflicting_facts,
    );
    merged.confidence = confidence.confidence.clone();
    append_merge_metadata(&mut merged, members, components, &conflicts, &confidence);
    Ok(merged)
}

fn identity_keys_without_fallback(component: &Component) -> Vec<IdentityKey> {
    identity_keys(component)
        .into_iter()
        .filter(|key| !matches!(key, IdentityKey::Opaque(_)))
        .collect()
}

fn merge_identity(members: &[usize], components: &[Component], base: &Identity) -> Identity {
    let mut merged = base.clone();
    if merged.provider_package.is_none() {
        merged.provider_package = unique_value(
            members
                .iter()
                .map(|&index| components[index].identity.provider_package.clone()),
        );
    }
    if merged.provider_source.is_none() {
        merged.provider_source = unique_value(
            members
                .iter()
                .map(|&index| components[index].identity.provider_source.clone()),
        );
    }
    if merged.package_family.is_none() {
        merged.package_family = unique_value(
            members
                .iter()
                .map(|&index| components[index].identity.package_family.clone()),
        );
    }
    if merged.product_name.is_none() {
        merged.product_name = unique_value(
            members
                .iter()
                .map(|&index| components[index].identity.product_name.clone()),
        );
    }
    if merged.executable_name.is_none() {
        merged.executable_name = unique_value(
            members
                .iter()
                .map(|&index| components[index].identity.executable_name.clone()),
        );
    }
    if merged.publisher.is_none() {
        merged.publisher = unique_value(
            members
                .iter()
                .map(|&index| components[index].identity.publisher.clone()),
        );
    }
    if merged.executable_hash.is_none() {
        merged.executable_hash = unique_value(
            members
                .iter()
                .map(|&index| components[index].identity.executable_hash.clone()),
        );
    }
    if merged.install_role.is_none() {
        merged.install_role = unique_value(
            members
                .iter()
                .map(|&index| components[index].identity.install_role.clone()),
        );
    }
    merged
}

fn unique_value<T>(values: impl Iterator<Item = Option<T>>) -> Option<T>
where
    T: Ord,
{
    let values = values.flatten().collect::<BTreeSet<_>>();
    (values.len() == 1).then(|| values.into_iter().next().expect("one value"))
}

fn merge_publisher(
    members: &[usize],
    components: &[Component],
    base: Option<Publisher>,
) -> Option<Publisher> {
    if base.is_some() {
        return base;
    }
    let mut values = BTreeMap::<String, Option<String>>::new();
    for &index in members {
        let Some(publisher) = components[index].publisher.as_ref() else {
            continue;
        };
        values
            .entry(publisher.name.clone())
            .or_insert_with(|| publisher.certificate_thumbprint.clone());
    }
    if values.len() != 1 {
        return None;
    }
    let (name, certificate_thumbprint) = values.into_iter().next()?;
    Some(Publisher {
        name,
        certificate_thumbprint,
    })
}

fn merge_version(
    members: &[usize],
    components: &[Component],
    base: Option<reforge_domain::VersionValue>,
) -> Option<reforge_domain::VersionValue> {
    base.or_else(|| {
        members
            .iter()
            .filter_map(|&index| components[index].version.clone())
            .min_by(|left, right| {
                left.raw
                    .cmp(&right.raw)
                    .then_with(|| left.normalized.cmp(&right.normalized))
            })
    })
}

fn merge_restore(
    members: &[usize],
    components: &[Component],
    base: &RestoreDescriptor,
) -> RestoreDescriptor {
    let mut merged = base.clone();
    for &index in members {
        let restore = &components[index].restore;
        if restore.requires_elevation {
            merged.requires_elevation = true;
        }
        if restore.requires_user_action {
            merged.requires_user_action = true;
        }
        for strategy in restore
            .alternatives
            .iter()
            .chain(std::iter::once(&restore.primary))
        {
            if *strategy != merged.primary && !merged.alternatives.contains(strategy) {
                merged.alternatives.push(strategy.clone());
            }
        }
        for rationale in &restore.rationale {
            if !merged.rationale.contains(rationale) {
                merged.rationale.push(rationale.clone());
            }
        }
    }
    merged
}

fn merge_compatibility(
    members: &[usize],
    components: &[Component],
    base: &Compatibility,
) -> Compatibility {
    let mut merged = base.clone();
    for &index in members {
        let compatibility = &components[index].compatibility;
        merged.required_os = merged
            .required_os
            .clone()
            .or_else(|| compatibility.required_os.clone());
        merged.required_architecture = merged
            .required_architecture
            .clone()
            .or_else(|| compatibility.required_architecture.clone());
        merged.requires_provider = merged
            .requires_provider
            .clone()
            .or_else(|| compatibility.requires_provider.clone());
        merged.requires_runtime = merged
            .requires_runtime
            .clone()
            .or_else(|| compatibility.requires_runtime.clone());
        merged.requires_elevation |= compatibility.requires_elevation;
        merged.requires_wsl |= compatibility.requires_wsl;
        merged.requires_docker |= compatibility.requires_docker;
    }
    merged
}

fn merge_selection(
    members: &[usize],
    components: &[Component],
    base: &reforge_domain::SelectionMetadata,
) -> reforge_domain::SelectionMetadata {
    let mut merged = base.clone();
    for &index in members {
        let selection = &components[index].selection;
        merged.recommended |= selection.recommended;
        merged.selected_by_default |= selection.selected_by_default;
        merged.sensitive |= selection.sensitive;
        merged.score = merged.score.max(selection.score);
        merged.size_bytes = merged.size_bytes.max(selection.size_bytes);
    }
    merged
}

fn merge_artifacts(members: &[usize], components: &[Component]) -> Vec<ArtifactRef> {
    let mut artifacts = BTreeMap::<ArtifactId, ArtifactRef>::new();
    for &index in members {
        for artifact in &components[index].artifacts {
            artifacts
                .entry(artifact.id.clone())
                .or_insert_with(|| artifact.clone());
        }
    }
    artifacts.into_values().collect()
}

fn merge_verification(
    members: &[usize],
    components: &[Component],
) -> ProviderResult<Vec<VerificationRule>> {
    let mut rules = BTreeMap::<String, VerificationRule>::new();
    for &index in members {
        for rule in &components[index].verification {
            let key = serde_json::to_string(rule)
                .map_err(|_| graph_error("verification rule could not be canonicalized"))?;
            rules.entry(key).or_insert_with(|| rule.clone());
        }
    }
    Ok(rules.into_values().collect())
}

fn merge_evidence_refs(
    members: &[usize],
    components: &[Component],
) -> Vec<reforge_domain::EvidenceRef> {
    let mut references = BTreeMap::<EvidenceId, u8>::new();
    for &index in members {
        for reference in &components[index].evidence {
            references
                .entry(reference.id.clone())
                .and_modify(|strength| *strength = (*strength).max(reference.strength))
                .or_insert(reference.strength);
        }
    }
    references
        .into_iter()
        .map(|(id, strength)| reforge_domain::EvidenceRef { id, strength })
        .collect()
}

#[derive(Default)]
struct Conflicts {
    publisher: BTreeSet<String>,
    version: BTreeSet<String>,
    source: BTreeSet<String>,
}

impl Conflicts {
    fn has_any(&self) -> bool {
        self.publisher.len() > 1 || self.version.len() > 1 || self.source.len() > 1
    }
}

fn collect_conflicts(members: &[usize], components: &[Component]) -> Conflicts {
    let mut conflicts = Conflicts::default();
    for &index in members {
        let component = &components[index];
        if let Some(publisher) = component.publisher.as_ref()
            && let Some(publisher) = normalized(Some(publisher.name.as_str()))
        {
            conflicts.publisher.insert(publisher);
        }
        if let Some(publisher) = component.identity.publisher.as_deref()
            && let Some(publisher) = normalized(Some(publisher))
        {
            conflicts.publisher.insert(publisher);
        }
        if let Some(version) = component.version.as_ref() {
            let value = version.normalized.as_deref().unwrap_or(&version.raw);
            if let Some(value) = normalized(Some(value)) {
                conflicts.version.insert(value);
            }
        }
        if let Some(source) = component.identity.provider_source.as_deref()
            && let Some(source) = normalized(Some(source))
        {
            conflicts.source.insert(source);
        }
        if let Some(provenance) = component.provenance.as_ref()
            && let Some(source) = provenance.source_url.as_ref()
        {
            conflicts.source.insert(source.to_string());
        }
    }
    conflicts
}

fn append_merge_metadata(
    component: &mut Component,
    members: &[usize],
    components: &[Component],
    conflicts: &Conflicts,
    confidence: &EvidenceConfidence,
) {
    let member_ids = members
        .iter()
        .map(|&index| components[index].id.to_string())
        .collect::<Vec<_>>();
    let mut metadata = serde_json::Map::new();
    metadata.insert("member_component_ids".to_owned(), json!(member_ids));
    metadata.insert("confidence_score".to_owned(), json!(confidence.score));
    metadata.insert(
        "independent_evidence_groups".to_owned(),
        json!(confidence.independent_groups),
    );
    metadata.insert("unverified".to_owned(), json!(confidence.unverified));
    metadata.insert(
        "confidence_explanation".to_owned(),
        json!(confidence.explanations),
    );
    let mut conflict_metadata = serde_json::Map::new();
    if conflicts.publisher.len() > 1 {
        conflict_metadata.insert(
            "publisher".to_owned(),
            json!(safe_facts(&conflicts.publisher)),
        );
    }
    if conflicts.version.len() > 1 {
        conflict_metadata.insert("version".to_owned(), json!(safe_facts(&conflicts.version)));
    }
    if conflicts.source.len() > 1 {
        conflict_metadata.insert("source".to_owned(), json!(safe_facts(&conflicts.source)));
    }
    if !conflict_metadata.is_empty() {
        metadata.insert("conflicts".to_owned(), Value::Object(conflict_metadata));
    }
    component
        .extensions
        .insert("reforge_dedup".to_owned(), Value::Object(metadata));
}

fn safe_facts(values: &BTreeSet<String>) -> Vec<String> {
    values
        .iter()
        .map(|value| {
            RedactionPolicy::with_max_bytes(MAX_FACT_BYTES)
                .redact_text(value)
                .unwrap_or_else(|| "<REDACTED>".to_owned())
        })
        .collect()
}

fn evidence_records(evidence: &[Evidence]) -> ProviderResult<BTreeMap<EvidenceId, Evidence>> {
    let mut records = BTreeMap::new();
    for record in evidence {
        if record.strength > 100 {
            return Err(graph_error("evidence strength exceeds 100"));
        }
        if let Some(existing) = records.get(&record.id)
            && existing != record
        {
            return Err(graph_error(
                "evidence ID was reused for conflicting records",
            ));
        }
        records.insert(record.id.clone(), record.clone());
    }
    Ok(records)
}

fn merge_edges(
    components: &[Component],
    edges: &[DependencyEdge],
    component_mapping: &BTreeMap<ComponentId, ComponentId>,
    evidence_records: &BTreeMap<EvidenceId, Evidence>,
) -> ProviderResult<Vec<DependencyEdge>> {
    let mut merged = BTreeMap::<EdgeKey, DependencyEdge>::new();
    for edge in edges.iter().chain(
        components
            .iter()
            .flat_map(|component| component.dependencies.iter()),
    ) {
        let mut edge = edge.clone();
        edge.from = component_mapping
            .get(&edge.from)
            .cloned()
            .unwrap_or(edge.from);
        edge.to = component_mapping.get(&edge.to).cloned().unwrap_or(edge.to);
        let key = EdgeKey {
            from: edge.from.clone(),
            to: edge.to.clone(),
            kind: dependency_kind_order(&edge.kind),
            required: edge.required,
        };
        if let Some(existing) = merged.get_mut(&key) {
            existing.evidence.extend(edge.evidence);
            existing.evidence.sort();
            existing.evidence.dedup();
        } else {
            edge.evidence.sort();
            edge.evidence.dedup();
            merged.insert(key, edge);
        }
    }

    let mut output = Vec::with_capacity(merged.len());
    for mut edge in merged.into_values() {
        let confidence = confidence_for_evidence(&edge.evidence, evidence_records, false, false);
        edge.confidence = confidence.confidence;
        output.push(edge);
    }
    Ok(output)
}

fn edge_order(left: &DependencyEdge, right: &DependencyEdge) -> std::cmp::Ordering {
    left.from
        .cmp(&right.from)
        .then_with(|| left.to.cmp(&right.to))
        .then_with(|| dependency_kind_order(&left.kind).cmp(&dependency_kind_order(&right.kind)))
        .then_with(|| left.required.cmp(&right.required).reverse())
        .then_with(|| left.evidence.cmp(&right.evidence))
}

fn dependency_kind_order(kind: &DependencyKind) -> u8 {
    match kind {
        DependencyKind::RequiredRuntime => 0,
        DependencyKind::RequiredPackage => 1,
        DependencyKind::InstalledThrough => 2,
        DependencyKind::Configures => 3,
        DependencyKind::UsesSecret => 4,
        DependencyKind::OptionalFeature => 5,
        DependencyKind::ProvidesExecutable => 6,
        DependencyKind::Contains => 7,
        DependencyKind::RestoresBefore => 8,
        DependencyKind::VerifiesWith => 9,
        DependencyKind::RelatedOnly => 10,
    }
}

fn graph_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            reforge_domain::ReforgeErrorCode::SchemaInvalid,
            "Discovery graph failed validation",
        )
        .with_technical_detail(detail),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use reforge_domain::{Confidence, RestoreStrategy};

    #[test]
    fn provider_conflicts_do_not_merge_through_lower_identity_keys() {
        let mut first = fixture_component("one", "publisher", "hash", Some("provider-a"));
        let mut second = fixture_component("one", "publisher", "hash", Some("provider-b"));
        first.identity.provider_source = Some("source-a".to_owned());
        second.identity.provider_source = Some("source-b".to_owned());
        let graph = deduplicate_graph(vec![first, second], Vec::new(), &[]).expect("graph");
        assert_eq!(graph.components.len(), 2);
    }

    #[test]
    fn duplicate_edges_merge_and_cycles_are_retained() {
        let first = fixture_component("one", "publisher", "hash-a", None);
        let second = fixture_component("two", "publisher", "hash-b", None);
        let evidence = fixture_evidence("edge");
        let edges = vec![
            edge(&first, &second, true, evidence.id.clone()),
            edge(&second, &first, true, evidence.id.clone()),
            edge(&first, &second, true, evidence.id.clone()),
        ];
        let graph = deduplicate_graph(vec![first, second], edges, &[evidence]).expect("graph");
        assert_eq!(graph.edges.len(), 2);
        assert!(graph.edges.iter().any(|edge| edge.from != edge.to));
    }

    fn fixture_component(
        name: &str,
        publisher: &str,
        hash: &str,
        provider: Option<&str>,
    ) -> Component {
        let identity = Identity {
            provider_package: provider.map(|provider| {
                (
                    reforge_domain::ProviderId::new(provider).expect("provider"),
                    name.to_owned(),
                )
            }),
            provider_source: provider.map(|_| "source".to_owned()),
            package_family: None,
            product_name: Some(name.to_owned()),
            executable_name: Some(format!("{name}.exe")),
            publisher: Some(publisher.to_owned()),
            executable_hash: Some(hash.to_owned()),
            install_role: Some("application".to_owned()),
            identity_quality: IdentityQuality::Local,
        };
        let publisher = Publisher {
            name: publisher.to_owned(),
            certificate_thumbprint: None,
        };
        let id = ComponentId::from_identity(&identity, Some(&publisher))
            .expect("identity")
            .id;
        Component {
            id,
            kind: ComponentKind::Application,
            identity,
            display_name: name.to_owned(),
            version: None,
            architecture: None,
            publisher: Some(publisher),
            provenance: None,
            evidence: Vec::new(),
            confidence: Confidence::Unknown,
            dependencies: Vec::new(),
            artifacts: Vec::new(),
            restore: RestoreDescriptor {
                primary: RestoreStrategy::Manual,
                alternatives: Vec::new(),
                portability: reforge_domain::Portability::Unknown,
                requires_elevation: false,
                requires_user_action: true,
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
            selection: reforge_domain::SelectionMetadata {
                recommended: false,
                score: 0,
                selected_by_default: false,
                sensitive: false,
                size_bytes: 0,
            },
            extensions: BTreeMap::new(),
        }
    }

    fn fixture_evidence(label: &str) -> Evidence {
        Evidence {
            id: EvidenceId::new(format!("evidence-{label}")).expect("evidence ID"),
            source: reforge_domain::EvidenceSource::Unknown,
            locator: label.to_owned(),
            observed_at: chrono::Utc::now(),
            summary: label.to_owned(),
            strength: 80,
            independent_group: label.to_owned(),
        }
    }

    fn edge(
        from: &Component,
        to: &Component,
        required: bool,
        evidence: EvidenceId,
    ) -> DependencyEdge {
        DependencyEdge {
            from: from.id.clone(),
            to: to.id.clone(),
            kind: DependencyKind::RequiredPackage,
            required,
            evidence: vec![evidence],
            confidence: Confidence::Unknown,
        }
    }
}
