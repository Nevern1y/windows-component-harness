//! Normalized target facts derived from the bounded discovery inventory.
//!
//! This module never probes raw filesystem state. The caller supplies the
//! canonical `Inventory` produced by the discovery coordinator plus current
//! provider/environment detections that use the same adapter boundaries.

use std::collections::{BTreeMap, BTreeSet};

use reforge_domain::{
    ComponentKind, ConfigScope, EnvironmentFact, HostFacts, InstalledFact, Inventory, ObjectId,
    ProviderFact, ProviderId, ReforgeErrorCode, RuntimeFact, TargetFacts,
};
use reforge_package::canonicalize;

use crate::{RestoreResult, restore_error};

const MAX_TARGET_COMPONENTS: usize = 250_000;
const MAX_PROVIDER_FACTS: usize = 256;
const MAX_ENVIRONMENT_FACTS: usize = 100_000;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 32 * 1024;

/// Converts one bounded target discovery inventory into stable comparison
/// facts. No host paths, package bytes, or secret values are read here.
#[derive(Clone, Copy, Debug, Default)]
pub struct TargetScanner;

impl TargetScanner {
    pub fn new() -> Self {
        Self
    }

    /// Normalize an inventory and derive available providers from its observed
    /// components. Call `scan_with_current_facts` when explicit provider
    /// detections or non-secret environment hashes are available.
    pub fn scan(&self, inventory: Inventory) -> RestoreResult<TargetFacts> {
        self.scan_with_current_facts(inventory, Vec::new(), Vec::new())
    }

    /// Normalize current provider detections and environment facts alongside
    /// the inventory. Environment values must already be represented as
    /// content IDs; raw values are rejected by construction.
    pub fn scan_with_current_facts(
        &self,
        inventory: Inventory,
        provider_facts: Vec<ProviderFact>,
        environment_facts: Vec<EnvironmentFact>,
    ) -> RestoreResult<TargetFacts> {
        if inventory.graph.components.len() > MAX_TARGET_COMPONENTS {
            return Err(schema_error(
                "target inventory exceeds the bounded component count",
            ));
        }
        if provider_facts.len() > MAX_PROVIDER_FACTS {
            return Err(schema_error(
                "target provider facts exceed the bounded provider count",
            ));
        }
        if environment_facts.len() > MAX_ENVIRONMENT_FACTS {
            return Err(schema_error(
                "target environment facts exceed the bounded environment count",
            ));
        }

        let host = normalize_host(inventory.host)?;
        let mut installed = Vec::new();
        let mut runtimes = BTreeMap::new();
        let mut observed_providers = BTreeSet::<ProviderId>::new();

        for component in inventory.graph.components {
            let excluded_from_target_identity = matches!(
                component.kind,
                ComponentKind::SecretReference | ComponentKind::EnvironmentVariable
            );
            if !excluded_from_target_identity {
                if let Some((provider, _)) = &component.identity.provider_package {
                    observed_providers.insert(provider.clone());
                }
                if let Some(provider) = component
                    .provenance
                    .as_ref()
                    .and_then(|provenance| provenance.provider.as_ref())
                {
                    observed_providers.insert(provider.clone());
                }
            }

            match component.kind {
                ComponentKind::Runtime => {
                    let fact = RuntimeFact {
                        id: component.id,
                        version: component.version,
                        architecture: component.architecture,
                    };
                    match runtimes.entry(fact.id.clone()) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(fact);
                        }
                        std::collections::btree_map::Entry::Occupied(entry)
                            if entry.get() == &fact => {}
                        std::collections::btree_map::Entry::Occupied(_) => {
                            return Err(schema_error(
                                "target inventory contains conflicting runtime facts",
                            ));
                        }
                    }
                }
                ComponentKind::SecretReference | ComponentKind::EnvironmentVariable => {}
                kind => installed.push(InstalledFact {
                    kind,
                    identity: component.identity,
                    version: component.version,
                    publisher: component.publisher,
                    provenance: component.provenance,
                }),
            }
        }

        let installed = normalize_installed(installed)?;
        let providers = normalize_providers(provider_facts, observed_providers)?;
        let runtimes = runtimes.into_values().collect();
        let environment = normalize_environment(environment_facts)?;
        let mut facts = TargetFacts {
            host,
            installed,
            providers,
            runtimes,
            environment,
            fingerprint: String::new(),
        };
        facts.fingerprint = target_fingerprint(&facts)?;
        Ok(facts)
    }
}

fn normalize_host(mut host: HostFacts) -> RestoreResult<HostFacts> {
    for path in &host.known_folders {
        path.validate()
            .map_err(|_| schema_error("target known-folder token is invalid"))?;
        if !path.relative.is_empty() {
            return Err(schema_error(
                "target host known folders must identify token roots",
            ));
        }
    }
    host.known_folders.sort_by(|left, right| {
        left.root
            .cmp(&right.root)
            .then_with(|| left.relative.cmp(&right.relative))
    });
    host.known_folders.dedup();

    host.drives.sort_by(|left, right| {
        left.token
            .cmp(&right.token)
            .then_with(|| left.filesystem.cmp(&right.filesystem))
    });
    for pair in host.drives.windows(2) {
        if pair[0].token == pair[1].token && pair[0] != pair[1] {
            return Err(schema_error("target host contains conflicting drive facts"));
        }
    }
    host.drives.dedup();

    host.free_bytes.sort_by(|left, right| {
        left.token
            .cmp(&right.token)
            .then_with(|| left.bytes.cmp(&right.bytes))
    });
    for pair in host.free_bytes.windows(2) {
        if pair[0].token == pair[1].token && pair[0] != pair[1] {
            return Err(schema_error(
                "target host contains conflicting free-space facts",
            ));
        }
    }
    host.free_bytes.dedup();
    Ok(host)
}

fn normalize_installed(facts: Vec<InstalledFact>) -> RestoreResult<Vec<InstalledFact>> {
    let mut keyed = Vec::with_capacity(facts.len());
    for fact in facts {
        let key = canonicalize(&fact)?.into_bytes();
        keyed.push((key, fact));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);
    Ok(keyed.into_iter().map(|(_, fact)| fact).collect())
}

fn normalize_providers(
    facts: Vec<ProviderFact>,
    observed: BTreeSet<ProviderId>,
) -> RestoreResult<Vec<ProviderFact>> {
    let mut providers = BTreeMap::<ProviderId, ProviderFact>::new();
    for fact in facts {
        match providers.entry(fact.id.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(fact);
            }
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &fact => {}
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(schema_error(
                    "target contains conflicting provider detection facts",
                ));
            }
        }
    }
    for id in observed {
        providers.entry(id.clone()).or_insert(ProviderFact {
            id,
            version: None,
            available: true,
        });
    }
    Ok(providers.into_values().collect())
}

fn normalize_environment(facts: Vec<EnvironmentFact>) -> RestoreResult<Vec<EnvironmentFact>> {
    let mut environment = BTreeMap::<(u8, String), EnvironmentFact>::new();
    for mut fact in facts {
        if fact.name.is_empty()
            || fact.name.len() > MAX_ENVIRONMENT_NAME_BYTES
            || fact.name.contains(['\0', '='])
            || fact.name.chars().any(char::is_control)
        {
            return Err(schema_error("target environment variable name is invalid"));
        }
        fact.name = fact.name.to_uppercase();
        if let Some(hash) = &fact.value_hash {
            ObjectId::new(hash.clone())
                .map_err(|_| schema_error("target environment value hash is invalid"))?;
        }
        let key = (scope_rank(&fact.scope), fact.name.clone());
        match environment.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(fact);
            }
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &fact => {}
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(schema_error(
                    "target contains conflicting environment facts",
                ));
            }
        }
    }
    Ok(environment.into_values().collect())
}

fn scope_rank(scope: &ConfigScope) -> u8 {
    match scope {
        ConfigScope::Process => 0,
        ConfigScope::User => 1,
        ConfigScope::System => 2,
        ConfigScope::Project => 3,
        ConfigScope::Managed => 4,
    }
}

fn target_fingerprint(facts: &TargetFacts) -> RestoreResult<String> {
    let mut projection = facts.clone();
    projection.fingerprint.clear();

    // Local identity and volatile/hardware facts remain available to target
    // checks but never enter the stable comparison fingerprint.
    projection.host.sid_fingerprint = None;
    projection.host.drives.clear();
    projection.host.free_bytes.clear();
    for path in &mut projection.host.known_folders {
        path.relative.clear();
    }
    for installed in &mut projection.installed {
        installed.provenance = None;
    }
    // A value hash can still correlate or disclose low-entropy secrets. Names
    // and scopes are sufficient for stable presence comparison.
    for variable in &mut projection.environment {
        variable.value_hash = None;
    }

    let canonical = canonicalize(&projection)?;
    let digest = canonical.object_id();
    let hex = digest
        .as_str()
        .strip_prefix("obj_")
        .expect("canonical object IDs always carry the obj_ prefix");
    Ok(format!("target_{hex}"))
}

fn schema_error(message: &str) -> Box<reforge_domain::ErrorEnvelope> {
    restore_error(
        ReforgeErrorCode::SchemaInvalid,
        message,
        None,
        None,
        None,
        None,
    )
}
