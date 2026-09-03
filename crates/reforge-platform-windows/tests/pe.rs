#[allow(dead_code)]
#[path = "../../../tests/fixtures/mod.rs"]
mod fixtures;

use std::path::PathBuf;

use fixtures::FixtureRoot;
use reforge_domain::ReforgeErrorCode;
use reforge_platform_windows::{SignerStatus, inspect_pe};

fn system_kernel32() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .expect("SystemRoot is available on Windows")
        .join("System32")
        .join("kernel32.dll")
}

#[test]
fn signed_system_fixture_returns_version_hash_and_signer_evidence() {
    let metadata = inspect_pe(system_kernel32()).expect("kernel32.dll should be inspectable");
    assert!(metadata.executable_hash.starts_with("blake3:"));
    assert_eq!(metadata.signature.status, SignerStatus::Trusted);
    assert_eq!(metadata.signature.wintrust_status, 0);
    assert!(metadata.signature.signer_subject.is_some());
    assert!(metadata.signature.certificate_fingerprint.is_some());
    assert!(metadata.file_version.is_some());
    assert!(metadata.publisher.is_some());
}

#[test]
fn unsigned_fixture_is_never_reported_as_trusted() {
    let fixture = FixtureRoot::new("pe-unsigned").unwrap();
    let mut image = vec![0u8; 0x58];
    image[0..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    image[0x40..0x44].copy_from_slice(b"PE\0\0");
    let path = fixture.write_file("unsigned.exe", image).unwrap();

    let metadata = inspect_pe(path).expect("structural unsigned fixture should be inspectable");
    assert_ne!(metadata.signature.wintrust_status, 0);
    assert_ne!(metadata.signature.status, SignerStatus::Trusted);
}

#[test]
fn malformed_and_missing_files_return_coded_errors() {
    let fixture = FixtureRoot::new("pe-errors").unwrap();
    let malformed = fixture.write_file("malformed.exe", b"not a PE").unwrap();
    let missing = fixture.missing_file("missing.exe").unwrap();

    let malformed_error = inspect_pe(malformed).unwrap_err();
    assert_eq!(malformed_error.code, ReforgeErrorCode::VersionUnavailable);
    let missing_error = inspect_pe(missing).unwrap_err();
    assert_eq!(missing_error.code, ReforgeErrorCode::PathNotFound);
}

#[test]
fn nonzero_trust_status_is_preserved_and_not_trusted() {
    assert_eq!(
        SignerStatus::from_wintrust_status(1),
        SignerStatus::Untrusted
    );
    assert_eq!(
        SignerStatus::from_wintrust_status(-1),
        SignerStatus::Untrusted
    );
}
