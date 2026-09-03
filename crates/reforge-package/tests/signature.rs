#[allow(
    dead_code,
    reason = "shared fixture harness exposes scenarios used by other suites"
)]
#[path = "../../../tests/fixtures/mod.rs"]
mod fixtures;

use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use fixtures::FixtureRoot;
use reforge_domain::{
    Architecture, ContentType, LargeDataSelectionPolicy, ObjectEntry, ObjectId, ObjectIndex,
    PackageGraph, PackageManifest, ReforgeErrorCode, SecretSelectionPolicy, SelectionInput,
    SelectionPolicy, SourceHostSummary, TrustState, UnknownBinarySelectionPolicy,
};
use reforge_package::{
    ObjectStore, PackageReader, PackageSignature, PackageWriteRequest, PackageWriter,
    PublicKeyFingerprint, SigningKey, TrustDecision, apply_trust_decision, canonicalize,
    require_plan_approval, signature_coverage_bytes,
};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

const SIGNATURE_ENTRY: &str = "signatures/manifest.sig";
const SIGNATURE_DOMAIN: &[u8] = b"REFORGE-PACKAGE-SIGNATURE-V1\0";

struct EmptyPackageCase {
    temp: FixtureRoot,
    store: ObjectStore,
    manifest: PackageManifest,
    graph: PackageGraph,
    object_index: ObjectIndex,
    selection: SelectionInput,
}

impl EmptyPackageCase {
    fn new() -> Self {
        let temp = FixtureRoot::new("signature-package").expect("temporary package root");
        let store = ObjectStore::open(temp.root().join("store")).expect("object store");
        let graph = PackageGraph {
            components: Vec::new(),
            edges: Vec::new(),
        };
        let object_index = ObjectIndex {
            objects: Vec::new(),
        };
        let manifest = PackageManifest {
            package_id: "pkg_signature_fixture".to_owned(),
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
                secrets: SecretSelectionPolicy::Exclude,
                large_data: LargeDataSelectionPolicy::RequireConfirmation,
                unknown_binaries: UnknownBinarySelectionPolicy::Exclude,
                max_bytes: None,
            },
        };
        Self {
            temp,
            store,
            manifest,
            graph,
            object_index,
            selection,
        }
    }

    fn signature(&self, signing_key: &SigningKey) -> PackageSignature {
        PackageSignature::sign_documents(signing_key, &self.manifest, &self.object_index)
            .expect("package signature")
    }

    fn write(&self, name: &str, signature: Option<&PackageSignature>) -> PathBuf {
        let path = self.temp.root().join(name);
        PackageWriter::default()
            .write(
                &path,
                PackageWriteRequest {
                    manifest: &self.manifest,
                    graph: &self.graph,
                    selection: &self.selection,
                    object_index: &self.object_index,
                    signature,
                    vault: None,
                },
                &self.store,
            )
            .expect("package write");
        path
    }
}

fn signing_key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

#[test]
fn strict_signature_covers_domain_separated_manifest_and_object_index() {
    let case = EmptyPackageCase::new();
    let key = signing_key(7);
    let signature = case.signature(&key);
    assert!(
        signature
            .verify_documents(&case.manifest, &case.object_index)
            .expect("signature verification")
    );

    let manifest_bytes = canonicalize(&case.manifest).unwrap().into_bytes();
    let index_bytes = canonicalize(&case.object_index).unwrap().into_bytes();
    let coverage = signature_coverage_bytes(&manifest_bytes, &index_bytes).unwrap();
    assert!(coverage.starts_with(SIGNATURE_DOMAIN));
    let manifest_length_offset = SIGNATURE_DOMAIN.len();
    let manifest_length = u64::from_le_bytes(
        coverage[manifest_length_offset..manifest_length_offset + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(manifest_length, manifest_bytes.len() as u64);
    let index_length_offset = manifest_length_offset + 8 + manifest_bytes.len();
    let index_length = u64::from_le_bytes(
        coverage[index_length_offset..index_length_offset + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(index_length, index_bytes.len() as u64);
    assert_eq!(&coverage[index_length_offset + 8..], index_bytes.as_slice());
    assert_eq!(
        coverage.len(),
        SIGNATURE_DOMAIN.len() + 8 + manifest_bytes.len() + 8 + index_bytes.len()
    );

    let mut tampered_manifest = case.manifest.clone();
    tampered_manifest
        .warnings
        .push("post-signature mutation".to_owned());
    assert!(
        !signature
            .verify_documents(&tampered_manifest, &case.object_index)
            .unwrap()
    );

    let tampered_index = ObjectIndex {
        objects: vec![ObjectEntry {
            id: ObjectId::from_content(b"tampered object"),
            uncompressed_bytes: 15,
            compressed_bytes: 12,
            content_type: ContentType::Binary,
        }],
    };
    assert!(
        !signature
            .verify_documents(&case.manifest, &tampered_index)
            .unwrap()
    );

    let wrong_key = signing_key(9);
    let mut wrong_metadata = signature.metadata().clone();
    wrong_metadata.public_key = wrong_key.verifying_key().to_bytes();
    wrong_metadata.public_key_fingerprint =
        PublicKeyFingerprint::from_public_key(&wrong_metadata.public_key);
    let wrong_key_signature = PackageSignature::from_entries(
        canonicalize(&wrong_metadata).unwrap().into_bytes(),
        signature.signature_bytes().to_vec(),
    )
    .unwrap();
    assert!(
        !wrong_key_signature
            .verify_documents(&case.manifest, &case.object_index)
            .unwrap()
    );
}

#[test]
fn malformed_signature_metadata_and_lengths_fail_closed() {
    let case = EmptyPackageCase::new();
    let signature = case.signature(&signing_key(3));

    let mut mismatched_fingerprint = signature.metadata().clone();
    mismatched_fingerprint.public_key_fingerprint =
        PublicKeyFingerprint::from_public_key(&[22; 32]);
    let error = PackageSignature::from_entries(
        canonicalize(&mismatched_fingerprint).unwrap().into_bytes(),
        signature.signature_bytes().to_vec(),
    )
    .unwrap_err();
    assert_eq!(error.code, ReforgeErrorCode::PackageCorrupt);

    let short = PackageSignature::from_entries(signature.metadata_bytes().to_vec(), vec![0; 63])
        .unwrap_err();
    assert_eq!(short.code, ReforgeErrorCode::PackageCorrupt);

    let mut noncanonical = signature.metadata_bytes().to_vec();
    noncanonical.push(b'\n');
    let noncanonical =
        PackageSignature::from_entries(noncanonical, signature.signature_bytes().to_vec())
            .unwrap_err();
    assert_eq!(noncanonical.code, ReforgeErrorCode::PackageCorrupt);
}

#[test]
fn reader_distinguishes_unsigned_untrusted_and_out_of_band_trusted() {
    let case = EmptyPackageCase::new();
    let signature = case.signature(&signing_key(11));
    let signed_path = case.write("signed.reforge", Some(&signature));

    let untrusted = PackageReader::new(&signed_path)
        .inspect()
        .expect("signed package inspection");
    assert_eq!(untrusted.trust, TrustState::SignatureValidUntrusted);
    assert_eq!(
        untrusted
            .signature_metadata()
            .expect("signature metadata")
            .public_key_fingerprint,
        signature.metadata().public_key_fingerprint
    );
    assert!(untrusted.require_plan_approval().is_err());
    assert!(
        untrusted
            .warnings
            .iter()
            .any(|warning| warning == "Package signature is valid, but its signer is not trusted")
    );

    let trusted_fingerprint = signature.metadata().public_key_fingerprint.clone();
    let mut trusted = PackageReader::new(&signed_path)
        .with_trusted_signer(trusted_fingerprint)
        .inspect()
        .expect("trusted signer inspection");
    assert_eq!(trusted.trust, TrustState::SignatureValidTrusted);
    assert!(trusted.require_plan_approval().is_err());
    trusted
        .decide_trust(TrustDecision::Approve)
        .expect("explicit package approval");
    assert_eq!(trusted.trust, TrustState::UserApproved);
    trusted
        .require_plan_approval()
        .expect("approved planning gate");

    let unsigned_path = case.write("unsigned.reforge", None);
    let mut unsigned = PackageReader::new(unsigned_path)
        .inspect()
        .expect("unsigned package inspection");
    assert_eq!(unsigned.trust, TrustState::Unsigned);
    assert!(unsigned.signature_metadata().is_none());
    assert!(unsigned.require_plan_approval().is_err());
    unsigned
        .decide_trust(TrustDecision::Approve)
        .expect("explicit unsigned approval");
    unsigned.require_plan_approval().unwrap();
}

#[test]
fn invalid_signature_is_visible_but_can_never_cross_the_plan_gate() {
    let case = EmptyPackageCase::new();
    let signature = case.signature(&signing_key(13));
    let signed_path = case.write("valid-before-mutation.reforge", Some(&signature));
    let invalid_path = case.temp.root().join("invalid-signature.reforge");
    rewrite_package(&signed_path, &invalid_path, true, false);

    let mut inspected = PackageReader::new(&invalid_path)
        .inspect()
        .expect("invalid signature remains inspectable");
    assert_eq!(inspected.trust, TrustState::SignatureInvalid);
    assert!(
        inspected
            .warnings
            .iter()
            .any(|warning| warning == "Package signature is invalid")
    );
    assert_eq!(
        inspected
            .decide_trust(TrustDecision::Approve)
            .unwrap_err()
            .code,
        ReforgeErrorCode::PackageUntrusted
    );
    assert_eq!(
        inspected.require_plan_approval().unwrap_err().code,
        ReforgeErrorCode::PackageUntrusted
    );
    inspected
        .decide_trust(TrustDecision::Reject)
        .expect("explicit rejection");
    assert_eq!(inspected.trust, TrustState::Rejected);
}

#[test]
fn incomplete_signature_envelope_is_package_corruption() {
    let case = EmptyPackageCase::new();
    let signature = case.signature(&signing_key(17));
    let signed_path = case.write("complete.reforge", Some(&signature));
    let incomplete_path = case.temp.root().join("incomplete.reforge");
    rewrite_package(&signed_path, &incomplete_path, false, true);

    let error = PackageReader::new(incomplete_path).inspect().unwrap_err();
    assert_eq!(error.code, ReforgeErrorCode::PackageCorrupt);
}

#[test]
fn trust_transition_gate_requires_explicit_approval_and_rejection_is_terminal() {
    for state in [
        TrustState::Unsigned,
        TrustState::SignatureValidUntrusted,
        TrustState::SignatureValidTrusted,
    ] {
        assert!(require_plan_approval(&state).is_err());
        let approved = apply_trust_decision(state, TrustDecision::Approve).unwrap();
        assert_eq!(approved, TrustState::UserApproved);
        require_plan_approval(&approved).unwrap();
    }
    assert_eq!(
        apply_trust_decision(TrustState::IntegrityVerified, TrustDecision::Approve)
            .unwrap_err()
            .code,
        ReforgeErrorCode::PackageUntrusted
    );
    assert_eq!(
        apply_trust_decision(TrustState::SignatureInvalid, TrustDecision::Approve)
            .unwrap_err()
            .code,
        ReforgeErrorCode::PackageUntrusted
    );
    let rejected =
        apply_trust_decision(TrustState::Unsigned, TrustDecision::Reject).expect("rejection");
    assert_eq!(rejected, TrustState::Rejected);
    assert!(apply_trust_decision(rejected, TrustDecision::Approve).is_err());
}

fn rewrite_package(
    source: &Path,
    destination: &Path,
    corrupt_signature: bool,
    omit_signature: bool,
) {
    let source = File::open(source).expect("open source package");
    let mut source = ZipArchive::new(source).expect("source ZIP");
    let destination = File::create(destination).expect("create rewritten package");
    let mut destination = ZipWriter::new(destination);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .large_file(true)
        .unix_permissions(0o600);

    for index in 0..source.len() {
        let mut entry = source.by_index(index).expect("source entry");
        let name = entry.name().to_owned();
        if omit_signature && name == SIGNATURE_ENTRY {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).expect("source entry bytes");
        if corrupt_signature && name == SIGNATURE_ENTRY {
            bytes[0] ^= 0x80;
        }
        destination
            .start_file(name, options)
            .expect("rewritten entry");
        destination
            .write_all(&bytes)
            .expect("write rewritten entry");
    }
    destination.finish().expect("finish rewritten package");
}
