#[allow(
    dead_code,
    reason = "shared fixture harness exposes scenarios used by other suites"
)]
#[path = "../../../tests/fixtures/mod.rs"]
mod fixtures;

use std::{
    cell::Cell,
    fs,
    io::{Cursor, Read},
    rc::Rc,
};

use fixtures::FixtureRoot;
use reforge_domain::{
    Architecture, ComponentId, ErrorEnvelope, LargeDataSelectionPolicy, ObjectIndex, PackageGraph,
    PackageManifest, ReforgeErrorCode, SecretSelectionPolicy, SelectionInput, SelectionPolicy,
    SourceHostSummary, UnknownBinarySelectionPolicy,
};
use reforge_package::{
    EncryptedVault, ExposeSecret, ObjectStore, PackageReader, PackageWriteRequest, PackageWriter,
    SecretDescriptor, SecretKind, SecretRecord, SecretSelection, SecretSource, SecretString,
    SecretTarget, VaultDocument, collect_approved_vault,
};
use zeroize::Zeroizing;

const PASSPHRASE: &str = "correct horse battery staple";
const SECRET_VALUE: &[u8] = b"super-secret-package-value-927451";

fn component_id(character: char) -> ComponentId {
    ComponentId::new(format!("cmp_{}", character.to_string().repeat(52)))
        .expect("valid component ID")
}

fn record(id_character: char, label: &str, value: &[u8]) -> SecretRecord {
    SecretRecord::new(
        component_id(id_character),
        label,
        SecretKind::ApiToken,
        SecretTarget::WindowsCredentialManager,
        Zeroizing::new(value.to_vec()),
    )
    .expect("valid secret record")
}

fn encrypted_vault(request_recovery: bool) -> (EncryptedVault, Option<SecretString>) {
    let document = VaultDocument::new(vec![
        record('b', "SECOND_TOKEN", b"second-value"),
        record('a', "PRIMARY_TOKEN", SECRET_VALUE),
    ])
    .expect("non-empty vault");
    let mut pending = document
        .encrypt(SecretString::from(PASSPHRASE.to_owned()), request_recovery)
        .expect("age encryption");
    let recovery = pending
        .take_recovery_identity()
        .expect("one-time recovery access")
        .map(|material| SecretString::from(material.identity().expose_secret().to_owned()));
    if request_recovery {
        pending
            .acknowledge_recovery_saved()
            .expect("recovery acknowledgement");
    }
    (
        pending.finish().expect("publishable encrypted vault"),
        recovery,
    )
}

fn age_header(payload: &str) -> String {
    let mut decoded = Vec::new();
    age::armor::ArmoredReader::new(Cursor::new(payload.as_bytes()))
        .read_to_end(&mut decoded)
        .expect("decode armored age payload");
    let separator = decoded
        .windows(b"\n---".len())
        .position(|window| window == b"\n---")
        .expect("age header separator");
    String::from_utf8(decoded[..separator].to_vec()).expect("UTF-8 age header")
}

#[test]
fn decrypts_independently_with_passphrase_and_recovery_identity() {
    let document = VaultDocument::new(vec![
        record('b', "SECOND_TOKEN", b"second-value"),
        record('a', "PRIMARY_TOKEN", SECRET_VALUE),
    ])
    .expect("non-empty vault");
    let mut pending = document
        .encrypt(SecretString::from(PASSPHRASE.to_owned()), true)
        .expect("age encryption");

    let not_acknowledged = pending.finish().unwrap_err();
    assert_eq!(not_acknowledged.code, ReforgeErrorCode::UserActionRequired);
    let recovery = pending
        .take_recovery_identity()
        .expect("first recovery reveal")
        .expect("requested recovery identity");
    assert!(
        recovery
            .identity()
            .expose_secret()
            .starts_with("AGE-SECRET-KEY-")
    );
    assert!(!format!("{recovery:?}").contains(recovery.identity().expose_secret()));
    assert_eq!(
        pending.take_recovery_identity().unwrap_err().code,
        ReforgeErrorCode::UserActionRequired
    );
    assert_eq!(
        pending.finish().unwrap_err().code,
        ReforgeErrorCode::UserActionRequired
    );
    pending
        .acknowledge_recovery_saved()
        .expect("explicit acknowledgement");
    let encrypted = pending.finish().expect("acknowledged vault");

    assert!(
        !encrypted
            .as_bytes()
            .windows(SECRET_VALUE.len())
            .any(|window| window == SECRET_VALUE)
    );
    assert!(
        !encrypted
            .as_bytes()
            .windows(recovery.identity().expose_secret().len())
            .any(|window| window == recovery.identity().expose_secret().as_bytes())
    );

    let passphrase_document = encrypted
        .decrypt_with_passphrase(SecretString::from(PASSPHRASE.to_owned()))
        .expect("passphrase decryption");
    assert_eq!(passphrase_document.records.len(), 2);
    assert_eq!(passphrase_document.records[0].id, component_id('a'));
    assert_eq!(passphrase_document.records[0].expose_value(), SECRET_VALUE);

    let recovery_document = encrypted
        .decrypt_with_recovery_identity(recovery.identity())
        .expect("recovery decryption");
    assert_eq!(recovery_document.records[0].expose_value(), SECRET_VALUE);
    assert_eq!(recovery_document.records[1].expose_value(), b"second-value");

    let wrong_passphrase = encrypted
        .decrypt_with_passphrase(SecretString::from("wrong passphrase".to_owned()))
        .unwrap_err();
    assert_eq!(wrong_passphrase.code, ReforgeErrorCode::VaultDecryptFailed);
    assert!(!wrong_passphrase.to_json().contains(PASSPHRASE));

    let wrong_identity = age::x25519::Identity::generate().to_string();
    let wrong_recovery = encrypted
        .decrypt_with_recovery_identity(&wrong_identity)
        .unwrap_err();
    assert_eq!(wrong_recovery.code, ReforgeErrorCode::VaultDecryptFailed);
    assert!(
        !wrong_recovery
            .to_json()
            .contains(wrong_identity.expose_secret())
    );
}

#[test]
fn vault_envelope_uses_separate_bounded_age_payloads() {
    let (encrypted, _) = encrypted_vault(false);
    let envelope: serde_json::Value =
        serde_json::from_slice(encrypted.as_bytes()).expect("canonical vault envelope");
    let passphrase_identity = envelope["passphrase_identity"]
        .as_str()
        .expect("passphrase identity payload");
    let vault = envelope["vault"].as_str().expect("vault payload");
    let passphrase_header = age_header(passphrase_identity);
    let vault_header = age_header(vault);

    let passphrase_stanzas: Vec<_> = passphrase_header
        .lines()
        .filter_map(|line| line.strip_prefix("-> "))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    let vault_stanzas: Vec<_> = vault_header
        .lines()
        .filter_map(|line| line.strip_prefix("-> "))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert_eq!(passphrase_stanzas, ["scrypt"]);
    assert!(vault_stanzas.contains(&"X25519"));
    assert!(!vault_stanzas.contains(&"scrypt"));
    assert!(
        vault_stanzas
            .iter()
            .all(|stanza| *stanza == "X25519" || stanza.ends_with("-grease")),
        "unexpected vault stanzas: {vault_stanzas:?}"
    );

    let work_factor = passphrase_header
        .lines()
        .find_map(|line| line.strip_prefix("-> scrypt "))
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("scrypt work factor")
        .parse::<u8>()
        .expect("numeric scrypt work factor");
    assert_eq!(work_factor, 16);
}

#[test]
fn empty_vault_and_empty_selection_are_rejected() {
    assert_eq!(
        VaultDocument::new(Vec::new()).unwrap_err().code,
        ReforgeErrorCode::VaultRequired
    );
    let selection = SecretSelection::new(Vec::new()).expect("valid empty selection value");
    let mut sources: Vec<&mut dyn SecretSource> = Vec::new();
    assert_eq!(
        collect_approved_vault(&selection, &mut sources)
            .unwrap_err()
            .code,
        ReforgeErrorCode::VaultRequired
    );
}

struct TrackingSource {
    descriptor: SecretDescriptor,
    reads: Rc<Cell<usize>>,
    secure_target: bool,
    value: Option<Zeroizing<Vec<u8>>>,
}

impl SecretSource for TrackingSource {
    fn descriptor(&self) -> &SecretDescriptor {
        &self.descriptor
    }

    fn read_secret(&mut self) -> Result<Zeroizing<Vec<u8>>, Box<ErrorEnvelope>> {
        self.reads.set(self.reads.get() + 1);
        self.value.take().ok_or_else(|| {
            Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::OperationFailed,
                "source was read more than once",
            ))
        })
    }

    fn secure_target_policy_proven(&self) -> bool {
        self.secure_target
    }
}

#[test]
fn collection_reads_only_approved_sources_and_defaults_plaintext_targets_to_manual() {
    let selected_reads = Rc::new(Cell::new(0));
    let unselected_reads = Rc::new(Cell::new(0));
    let selected_id = component_id('a');
    let mut selected = TrackingSource {
        descriptor: SecretDescriptor::new(
            selected_id.clone(),
            "CONTEXT7_API_KEY",
            SecretKind::ApiToken,
            "environment variable reference",
            SecretTarget::EnvironmentVariable {
                name: "CONTEXT7_API_KEY".to_owned(),
            },
            "Plaintext environment storage requires a manual action",
        )
        .expect("descriptor"),
        reads: Rc::clone(&selected_reads),
        secure_target: false,
        value: Some(Zeroizing::new(SECRET_VALUE.to_vec())),
    };
    let mut unselected = TrackingSource {
        descriptor: SecretDescriptor::new(
            component_id('b'),
            "UNSELECTED_TOKEN",
            SecretKind::ApiToken,
            "application keyring",
            SecretTarget::ApplicationKeyring {
                application: "fixture".to_owned(),
            },
            "Application credential",
        )
        .expect("descriptor"),
        reads: Rc::clone(&unselected_reads),
        secure_target: true,
        value: Some(Zeroizing::new(b"must-not-be-read".to_vec())),
    };
    let selection = SecretSelection::new([selected_id]).expect("explicit selection");
    let mut sources: Vec<&mut dyn SecretSource> = vec![&mut unselected, &mut selected];

    let document = collect_approved_vault(&selection, &mut sources).expect("approved vault");
    assert_eq!(selected_reads.get(), 1);
    assert_eq!(unselected_reads.get(), 0);
    assert!(matches!(document.records[0].target, SecretTarget::Manual));
    assert_eq!(document.records[0].expose_value(), SECRET_VALUE);
    let debug = format!("{document:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(std::str::from_utf8(SECRET_VALUE).unwrap()));
}

struct FailingSource {
    descriptor: SecretDescriptor,
}

impl SecretSource for FailingSource {
    fn descriptor(&self) -> &SecretDescriptor {
        &self.descriptor
    }

    fn read_secret(&mut self) -> Result<Zeroizing<Vec<u8>>, Box<ErrorEnvelope>> {
        Err(Box::new(
            ErrorEnvelope::new(ReforgeErrorCode::OperationFailed, "adapter failure")
                .with_technical_detail("leaked-source-secret-556677"),
        ))
    }
}

#[test]
fn adapter_failures_are_bounded_before_crossing_the_vault_boundary() {
    let id = component_id('a');
    let mut source = FailingSource {
        descriptor: SecretDescriptor::new(
            id.clone(),
            "FAIL_TOKEN",
            SecretKind::Opaque,
            "fixture source",
            SecretTarget::Manual,
            "fixture risk",
        )
        .unwrap(),
    };
    let selection = SecretSelection::new([id]).unwrap();
    let mut sources: Vec<&mut dyn SecretSource> = vec![&mut source];
    let error = collect_approved_vault(&selection, &mut sources).unwrap_err();
    assert_eq!(error.code, ReforgeErrorCode::OperationFailed);
    assert!(!error.to_json().contains("leaked-source-secret-556677"));
}

struct EmptyPackageCase {
    _temp: FixtureRoot,
    store: ObjectStore,
    manifest: PackageManifest,
    graph: PackageGraph,
    object_index: ObjectIndex,
    selection: SelectionInput,
}

impl EmptyPackageCase {
    fn new() -> Self {
        let temp = FixtureRoot::new("vault-package").expect("temporary package root");
        let store = ObjectStore::open(temp.root().join("store")).expect("object store");
        let graph = PackageGraph {
            components: Vec::new(),
            edges: Vec::new(),
        };
        let object_index = ObjectIndex {
            objects: Vec::new(),
        };
        let manifest = PackageManifest {
            package_id: "pkg_vault_fixture".to_owned(),
            format_version: 1,
            created_at: "2026-08-30T12:00:00Z".parse().expect("timestamp"),
            source_host: SourceHostSummary {
                os_version: "Windows 11".to_owned(),
                os_build: "26200".to_owned(),
                architecture: Architecture::X64,
                known_folder_tokens: Vec::new(),
            },
            required_os: Some("windows".to_owned()),
            required_architecture: Some(Architecture::X64),
            component_ids: Vec::new(),
            warnings: Vec::new(),
            object_index_digest: PackageWriter::object_index_digest(&object_index)
                .expect("object index digest"),
        };
        let selection = SelectionInput {
            components: Vec::new(),
            artifacts: Vec::new(),
            policy: SelectionPolicy {
                secrets: SecretSelectionPolicy::VaultExplicit,
                large_data: LargeDataSelectionPolicy::RequireConfirmation,
                unknown_binaries: UnknownBinarySelectionPolicy::Exclude,
                max_bytes: None,
            },
        };
        Self {
            _temp: temp,
            store,
            manifest,
            graph,
            object_index,
            selection,
        }
    }
}

#[test]
fn package_inspection_exposes_only_encrypted_vault_and_redacted_metadata() {
    let case = EmptyPackageCase::new();
    let (vault, recovery) = encrypted_vault(true);
    let recovery = recovery.expect("recovery identity");
    let package_path = case._temp.root().join("vault.reforge");
    PackageWriter::default()
        .write(
            &package_path,
            PackageWriteRequest {
                manifest: &case.manifest,
                graph: &case.graph,
                selection: &case.selection,
                object_index: &case.object_index,
                signature: None,
                vault: Some(&vault),
            },
            &case.store,
        )
        .expect("vault package write");

    let package_bytes = fs::read(&package_path).expect("package bytes");
    for forbidden in [
        SECRET_VALUE,
        PASSPHRASE.as_bytes(),
        recovery.expose_secret().as_bytes(),
    ] {
        assert!(
            !package_bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden)
        );
    }

    let inspected = PackageReader::new(&package_path)
        .inspect()
        .expect("valid package inspection");
    assert!(inspected.has_vault);
    let inspected_vault = inspected.encrypted_vault().expect("encrypted vault entry");
    let decrypted = inspected_vault
        .decrypt_with_passphrase(SecretString::from(PASSPHRASE.to_owned()))
        .expect("package vault decryption");
    assert_eq!(decrypted.records[0].expose_value(), SECRET_VALUE);
    let inspection_debug = format!("{inspected:?}");
    assert!(!inspection_debug.contains(std::str::from_utf8(SECRET_VALUE).unwrap()));
    assert!(!inspection_debug.contains(PASSPHRASE));
    assert!(!inspection_debug.contains(recovery.expose_secret()));
}

#[test]
fn package_writer_requires_vault_policy_to_match_entry_presence() {
    let mut case = EmptyPackageCase::new();
    let missing_path = case._temp.root().join("missing.reforge");
    let missing = PackageWriter::default()
        .write(
            &missing_path,
            PackageWriteRequest {
                manifest: &case.manifest,
                graph: &case.graph,
                selection: &case.selection,
                object_index: &case.object_index,
                signature: None,
                vault: None,
            },
            &case.store,
        )
        .unwrap_err();
    assert_eq!(missing.code, ReforgeErrorCode::VaultRequired);
    assert!(!missing_path.exists());

    let (vault, _) = encrypted_vault(false);
    case.selection.policy.secrets = SecretSelectionPolicy::Exclude;
    let excluded_path = case._temp.root().join("excluded.reforge");
    let excluded = PackageWriter::default()
        .write(
            &excluded_path,
            PackageWriteRequest {
                manifest: &case.manifest,
                graph: &case.graph,
                selection: &case.selection,
                object_index: &case.object_index,
                signature: None,
                vault: Some(&vault),
            },
            &case.store,
        )
        .unwrap_err();
    assert_eq!(excluded.code, ReforgeErrorCode::SecurityPolicy);
    assert!(!excluded_path.exists());
}
