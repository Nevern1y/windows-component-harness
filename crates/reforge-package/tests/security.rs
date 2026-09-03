#[allow(
    dead_code,
    reason = "shared fixture harness exposes scenarios used by other suites"
)]
#[path = "../../../tests/fixtures/mod.rs"]
mod fixtures;

use std::{
    fs::{self, File},
    io::{Cursor, Write},
    path::Path,
};

use fixtures::FixtureRoot;
use reforge_domain::{
    ContentType, KnownFolderToken, ObjectId, ObjectIndex, PathToken, ReforgeErrorCode,
};
use reforge_package::{
    BoundedStreamWriter, CanonicalJson, FILE_CHUNK_BYTES, ObjectStore, PackageLimits,
    PackageReader, PackageWriter,
};
use serde_json::{Map, Value, json};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

const CENTRAL_SIGNATURE: &[u8; 4] = b"PK\x01\x02";
const LOCAL_SIGNATURE: &[u8; 4] = b"PK\x03\x04";

fn deterministic_bytes(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

#[test]
fn arbitrary_tokenized_paths_are_normalized_or_rejected() {
    let roots = [
        KnownFolderToken::UserProfile,
        KnownFolderToken::RoamingAppData,
        KnownFolderToken::Documents,
        KnownFolderToken::UserSelected {
            id: "portable-root".to_owned(),
        },
    ];
    let unsafe_fragments = ["..", ":", "\0", "\u{1b}"];

    for case in 0..2_048u64 {
        let mut relative = String::new();
        for (index, byte) in deterministic_bytes(1 + (case as usize % 48), case)
            .into_iter()
            .enumerate()
        {
            if index != 0 && byte % 7 == 0 {
                relative.push(if byte & 1 == 0 { '/' } else { '\\' });
            }
            relative.push(char::from(b'a' + byte % 26));
        }
        if case % 11 == 0 {
            relative.insert_str(
                0,
                unsafe_fragments[(case as usize / 11) % unsafe_fragments.len()],
            );
        }
        if case % 13 == 0 {
            relative.insert(0, '\\');
        }

        let root = roots[case as usize % roots.len()].clone();
        match PathToken::new(root, &relative) {
            Ok(token) => {
                token.validate().expect("constructor returns a valid token");
                assert!(!token.relative.contains('\\'));
                assert!(!token.relative.split('/').any(|segment| segment == ".."));
                let encoded = serde_json::to_vec(&token).expect("token JSON");
                let decoded: PathToken =
                    serde_json::from_slice(&encoded).expect("canonical token round trip");
                assert_eq!(decoded, token);
            }
            Err(_) => {
                assert!(
                    relative.starts_with(['/', '\\'])
                        || (relative.len() >= 2 && relative.as_bytes()[1] == b':')
                        || relative.split(['/', '\\']).any(|segment| segment == "..")
                        || relative.contains(':')
                        || relative.chars().any(char::is_control),
                    "safe-looking path was unexpectedly rejected: {relative:?}"
                );
            }
        }
    }
}

#[test]
fn canonical_json_is_independent_of_insertion_order() {
    for case in 0..1_024u64 {
        let keys: Vec<_> = (0..(1 + case as usize % 32))
            .map(|index| {
                format!(
                    "key-{index:02}-{:02x}",
                    deterministic_bytes(1, case + index as u64)[0]
                )
            })
            .collect();
        let mut forward = Map::new();
        for (index, key) in keys.iter().enumerate() {
            forward.insert(key.clone(), json!([case, index, key]));
        }
        let mut reverse = Map::new();
        for (index, key) in keys.iter().enumerate().rev() {
            reverse.insert(key.clone(), json!([case, index, key]));
        }

        let forward = CanonicalJson::from_value(&Value::Object(forward)).expect("canonical JSON");
        let reverse = CanonicalJson::from_value(&Value::Object(reverse)).expect("canonical JSON");
        assert_eq!(forward.as_bytes(), reverse.as_bytes());
        assert_eq!(forward.object_id(), reverse.object_id());
        assert_eq!(
            forward.object_id(),
            &ObjectId::from_content(forward.as_bytes())
        );
    }
}

#[test]
fn generated_chunk_boundaries_preserve_size_order_and_identity() {
    let fixture = FixtureRoot::new("security-chunks").expect("fixture root");
    let store = ObjectStore::open(fixture.root().join("store")).expect("object store");
    let mut lengths = vec![
        0,
        1,
        FILE_CHUNK_BYTES - 1,
        FILE_CHUNK_BYTES,
        FILE_CHUNK_BYTES + 1,
        2 * FILE_CHUNK_BYTES - 1,
        2 * FILE_CHUNK_BYTES,
        2 * FILE_CHUNK_BYTES + 1,
    ];
    lengths.extend((0..8u64).map(|case| {
        (case as usize * 524_287 + deterministic_bytes(1, case)[0] as usize)
            % (2 * FILE_CHUNK_BYTES + 257)
    }));

    for (case, length) in lengths.into_iter().enumerate() {
        let bytes = deterministic_bytes(length, case as u64 + 1);
        let stored = store
            .store_file(Cursor::new(&bytes), ContentType::Binary, 0)
            .expect("bounded file storage");
        assert_eq!(stored.manifest.size_bytes, length as u64);
        assert_eq!(
            stored
                .manifest
                .chunks
                .iter()
                .map(|chunk| chunk.uncompressed_bytes)
                .sum::<u64>(),
            length as u64
        );
        assert_eq!(stored.chunk_objects.len(), stored.manifest.chunks.len());
        for (index, chunk) in stored.manifest.chunks.iter().enumerate() {
            let start = index * FILE_CHUNK_BYTES;
            let end = (start + chunk.uncompressed_bytes as usize).min(bytes.len());
            assert_eq!(chunk.id, ObjectId::from_content(&bytes[start..end]));
            assert!(chunk.uncompressed_bytes <= FILE_CHUNK_BYTES as u64);
            if index + 1 != stored.manifest.chunks.len() {
                assert_eq!(chunk.uncompressed_bytes, FILE_CHUNK_BYTES as u64);
            }
        }
    }
}

#[test]
fn bounded_stream_never_forwards_the_over_limit_write() {
    for limit in [0u64, 1, 31, 4_096, 65_535] {
        let bytes = deterministic_bytes(limit as usize + 1, limit + 17);
        let mut writer = BoundedStreamWriter::new(Vec::new(), limit);
        let error = writer
            .write_all(&bytes)
            .expect_err("over-limit stream must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let (output, digest) = writer.finish();
        assert!(output.is_empty());
        assert_eq!(digest.bytes, 0);
    }
}

#[test]
fn duplicate_ids_and_verified_object_hash_mismatches_fail_closed() {
    let source_fixture = FixtureRoot::new("security-index-source").expect("fixture root");
    let source_store =
        ObjectStore::open(source_fixture.root().join("store")).expect("object store");
    let entry = source_store
        .put_object(Cursor::new(b"expected object"), ContentType::Binary)
        .expect("stored object")
        .entry;
    let duplicate_index = ObjectIndex {
        objects: vec![entry.clone(), entry.clone()],
    };
    assert_eq!(
        PackageWriter::object_index_digest(&duplicate_index)
            .expect_err("duplicate object IDs must be rejected")
            .code,
        ReforgeErrorCode::SchemaInvalid
    );

    let fixture = FixtureRoot::new("security-hash-mismatch").expect("fixture root");
    let store = ObjectStore::open(fixture.root().join("store")).expect("object store");
    let mismatch = store
        .put_verified_object(
            Cursor::new(b"expected objecx"),
            &entry.id,
            b"expected object".len() as u64,
            ContentType::Binary,
        )
        .expect_err("mismatched object identity must be rejected");
    assert_eq!(mismatch.code, ReforgeErrorCode::PackageCorrupt);
    assert!(
        fs::read_dir(fixture.root().join("store/objects"))
            .expect("object directory")
            .next()
            .is_none()
    );
}

#[test]
fn zip_slip_bomb_and_malformed_schema_corpus_is_rejected_without_extraction() {
    let fixture = FixtureRoot::new("security-package-corpus").expect("fixture root");

    let slip = fixture.root().join("zip-slip.reforge");
    create_raw_zip(&slip, &[("../escape.txt", b"owned")]);
    assert_eq!(
        PackageReader::new(&slip)
            .inspect()
            .expect_err("zip-slip entry must be rejected")
            .code,
        ReforgeErrorCode::SecurityPolicy
    );
    assert!(!fixture.root().join("escape.txt").exists());

    let bomb = fixture.root().join("zip-bomb.reforge");
    create_raw_zip(&bomb, &[("format/manifest.json", b"x")]);
    patch_declared_sizes(&bomb, 1, 1_000_000);
    assert_eq!(
        PackageReader::new(&bomb)
            .inspect()
            .expect_err("declared compression bomb must be rejected")
            .code,
        ReforgeErrorCode::SecurityPolicy
    );

    let malformed = fixture.root().join("malformed-schema.reforge");
    create_raw_zip(
        &malformed,
        &[
            (
                "format/manifest.json",
                br#"{"format_version":1,"unknown":true}"#,
            ),
            ("format/graph.json", b"{}"),
            ("format/selection.json", b"{}"),
            ("format/operations.json", b"{}"),
            ("format/object-index.json", b"{}"),
            ("format/sources.json", b"{}"),
        ],
    );
    assert_eq!(
        PackageReader::new(&malformed)
            .inspect()
            .expect_err("malformed metadata must be rejected")
            .code,
        ReforgeErrorCode::SchemaInvalid
    );
}

#[test]
fn archive_size_limit_is_enforced_before_zip_parsing() {
    let fixture = FixtureRoot::new("security-package-limit").expect("fixture root");
    let path = fixture
        .write_file("oversized.reforge", b"not a package")
        .expect("fixture file");
    let limits = PackageLimits {
        max_archive_bytes: 4,
        ..PackageLimits::default()
    };
    let error = PackageReader::with_limits(path, limits)
        .expect("valid limits")
        .inspect()
        .expect_err("archive bound must be enforced");
    assert_eq!(error.code, ReforgeErrorCode::SecurityPolicy);
}

fn create_raw_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = File::create(path).expect("ZIP fixture");
    let mut archive = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, bytes) in entries {
        archive.start_file(*name, options).expect("ZIP entry");
        archive.write_all(bytes).expect("ZIP bytes");
    }
    archive.finish().expect("ZIP finish");
}

fn patch_declared_sizes(path: &Path, compressed_size: u32, uncompressed_size: u32) {
    let mut bytes = fs::read(path).expect("ZIP bytes");
    let local = find_subslice(&bytes, LOCAL_SIGNATURE).expect("local header");
    bytes[local + 18..local + 22].copy_from_slice(&compressed_size.to_le_bytes());
    bytes[local + 22..local + 26].copy_from_slice(&uncompressed_size.to_le_bytes());

    let central = find_subslice(&bytes, CENTRAL_SIGNATURE).expect("central header");
    bytes[central + 20..central + 24].copy_from_slice(&compressed_size.to_le_bytes());
    bytes[central + 24..central + 28].copy_from_slice(&uncompressed_size.to_le_bytes());
    fs::write(path, bytes).expect("patched ZIP");
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}
