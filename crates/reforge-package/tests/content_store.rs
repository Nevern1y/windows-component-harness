#![allow(dead_code)]

mod support;

use std::{
    collections::BTreeSet,
    fs,
    io::{self, Cursor, Read},
};

use reforge_domain::{ContentType, ObjectId, ReforgeErrorCode};
use reforge_package::{ContentStoreLimits, FILE_CHUNK_BYTES, ObjectStore};
use support::FixtureRoot;

fn fixture_store(label: &str) -> (FixtureRoot, ObjectStore) {
    let fixture = FixtureRoot::new(label).expect("fixture root");
    let root = fixture.create_dir("store").expect("store root");
    let store = ObjectStore::open(root).expect("object store");
    (fixture, store)
}

fn object_names(store: &ObjectStore) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(store.root().join("objects"))
        .expect("object directory")
        .map(|entry| {
            entry
                .expect("object entry")
                .file_name()
                .into_string()
                .expect("Unicode object name")
        })
        .collect();
    names.sort();
    names
}

fn patterned_bytes(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

#[test]
fn empty_small_boundary_and_large_files_have_exact_chunk_shapes() {
    let (_fixture, store) = fixture_store("content-boundaries");
    let cases = [
        (Vec::new(), Vec::<u64>::new()),
        (b"small object".to_vec(), vec![12]),
        (
            patterned_bytes(FILE_CHUNK_BYTES),
            vec![FILE_CHUNK_BYTES as u64],
        ),
        (
            patterned_bytes(FILE_CHUNK_BYTES + 37),
            vec![FILE_CHUNK_BYTES as u64, 37],
        ),
    ];

    for (index, (bytes, expected_chunks)) in cases.into_iter().enumerate() {
        let attributes = 0x20 + index as u32;
        let stored = store
            .store_file(Cursor::new(&bytes), ContentType::Binary, attributes)
            .expect("stored file");

        assert_eq!(stored.manifest.size_bytes, bytes.len() as u64);
        assert_eq!(stored.manifest.attributes, attributes);
        assert_eq!(stored.manifest.content_type, ContentType::Binary);
        assert_eq!(
            stored
                .manifest
                .chunks
                .iter()
                .map(|chunk| chunk.uncompressed_bytes)
                .collect::<Vec<_>>(),
            expected_chunks
        );
        assert_eq!(stored.chunk_objects.len(), expected_chunks.len());
        store
            .verify_object(&stored.manifest_object.entry)
            .expect("verified manifest object");
        for chunk in &stored.chunk_objects {
            store
                .verify_object(&chunk.entry)
                .expect("verified chunk object");
        }
    }
}

#[test]
fn duplicate_content_reuses_chunks_and_manifest_objects() {
    let (_fixture, store) = fixture_store("content-dedup");
    let contents = b"the same canonical bytes";

    let first = store
        .store_file(Cursor::new(contents), ContentType::Utf8Text, 7)
        .expect("first store");
    let second = store
        .store_file(Cursor::new(contents), ContentType::Utf8Text, 7)
        .expect("second store");

    assert!(!first.chunk_objects[0].deduplicated);
    assert!(!first.manifest_object.deduplicated);
    assert!(second.chunk_objects[0].deduplicated);
    assert!(second.manifest_object.deduplicated);
    assert_eq!(first.manifest, second.manifest);
    assert_eq!(
        first.manifest_object.entry.id,
        second.manifest_object.entry.id
    );
    assert_eq!(object_names(&store).len(), 2);
}

#[test]
fn interrupted_object_write_removes_staging_file_and_commits_nothing() {
    let (_fixture, store) = fixture_store("content-interrupted-object");
    let mut reader = FailingReader {
        remaining_before_failure: 128,
        failed: false,
    };

    let error = store
        .put_object(&mut reader, ContentType::Binary)
        .expect_err("interrupted stream");

    assert_eq!(error.code, ReforgeErrorCode::OperationFailed);
    assert!(object_names(&store).is_empty());
}

#[test]
fn completed_chunks_survive_interruption_and_are_reused_on_resume() {
    let (_fixture, store) = fixture_store("content-resume");
    let bytes = patterned_bytes(FILE_CHUNK_BYTES + 19);
    let mut interrupted = FailAfter::new(&bytes, FILE_CHUNK_BYTES + 5);

    let error = store
        .store_file(&mut interrupted, ContentType::Binary, 0)
        .expect_err("second chunk read fails");
    assert_eq!(error.code, ReforgeErrorCode::OperationFailed);
    assert_eq!(object_names(&store).len(), 1);

    let resumed = store
        .store_file(Cursor::new(&bytes), ContentType::Binary, 0)
        .expect("resumed file");
    assert_eq!(resumed.chunk_objects.len(), 2);
    assert!(resumed.chunk_objects[0].deduplicated);
    assert!(!resumed.chunk_objects[1].deduplicated);
    assert!(!resumed.manifest_object.deduplicated);
    assert!(
        object_names(&store)
            .iter()
            .all(|name| !name.ends_with(".tmp"))
    );
}

#[test]
fn expected_hash_mismatch_never_reaches_a_final_object_name() {
    let (_fixture, store) = fixture_store("content-hash-mismatch");
    let expected = ObjectId::from_content(b"expected");

    let error = store
        .put_verified_object(
            Cursor::new(b"different"),
            &expected,
            b"different".len() as u64,
            ContentType::Binary,
        )
        .expect_err("hash mismatch");

    assert_eq!(error.code, ReforgeErrorCode::PackageCorrupt);
    assert!(object_names(&store).is_empty());
}

#[test]
fn object_and_file_size_limits_fail_before_manifest_commit() {
    let fixture = FixtureRoot::new("content-limits").expect("fixture root");
    let object_root = fixture.create_dir("object-store").expect("object root");
    let limits = ContentStoreLimits::new(FILE_CHUNK_BYTES as u64, u64::MAX).expect("valid limits");
    let object_store = ObjectStore::with_limits(object_root, limits).expect("object store");
    let mut oversized = ZeroReader::new(FILE_CHUNK_BYTES as u64 + 1);

    let error = object_store
        .put_object(&mut oversized, ContentType::Binary)
        .expect_err("oversized object");
    assert_eq!(error.code, ReforgeErrorCode::SecurityPolicy);
    assert!(object_names(&object_store).is_empty());

    let file_root = fixture.create_dir("file-store").expect("file root");
    let file_limits =
        ContentStoreLimits::new(FILE_CHUNK_BYTES as u64, 3).expect("valid file limits");
    let file_store = ObjectStore::with_limits(file_root, file_limits).expect("file store");
    let error = file_store
        .store_file(Cursor::new(b"four"), ContentType::Binary, 0)
        .expect_err("oversized file");
    assert_eq!(error.code, ReforgeErrorCode::SecurityPolicy);
    assert!(object_names(&file_store).is_empty());
}

#[test]
fn corrupt_existing_object_is_not_accepted_as_a_duplicate() {
    let (_fixture, store) = fixture_store("content-corrupt-duplicate");
    let bytes = b"verify before deduplicating";
    let first = store
        .put_object(Cursor::new(bytes), ContentType::Binary)
        .expect("first object");
    let path = store
        .root()
        .join("objects")
        .join(format!("{}.zst", first.entry.id.as_str()));
    fs::write(path, b"not a zstd frame").expect("corrupt object");

    let error = store
        .put_object(Cursor::new(bytes), ContentType::Binary)
        .expect_err("corrupt duplicate");
    assert_eq!(error.code, ReforgeErrorCode::PackageCorrupt);
}

#[test]
fn multi_gigabyte_stream_keeps_data_buffer_bounded() {
    let fixture = FixtureRoot::new("content-multi-gigabyte").expect("fixture root");
    let root = fixture.create_dir("store").expect("store root");
    let size = 2 * 1024_u64 * 1024 * 1024 + 17;
    let limits = ContentStoreLimits::new(64 * 1024 * 1024, size).expect("valid limits");
    let store = ObjectStore::with_limits(root, limits).expect("object store");
    let mut reader = ZeroReader::new(size);

    let stored = store
        .store_file(&mut reader, ContentType::Binary, 0)
        .expect("multi-gigabyte file");

    assert_eq!(stored.manifest.size_bytes, size);
    assert_eq!(stored.manifest.chunks.len(), 257);
    assert_eq!(
        stored.manifest.chunks.last().unwrap().uncompressed_bytes,
        17
    );
    assert!(reader.max_requested <= FILE_CHUNK_BYTES);
    let unique: BTreeSet<_> = stored
        .manifest
        .chunks
        .iter()
        .map(|chunk| chunk.id.clone())
        .collect();
    assert_eq!(unique.len(), 2);
}

struct FailingReader {
    remaining_before_failure: usize,
    failed: bool,
}

impl Read for FailingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining_before_failure == 0 {
            self.failed = true;
            return Err(io::Error::other("fixture interruption"));
        }
        let read = buffer.len().min(self.remaining_before_failure);
        buffer[..read].fill(0x5a);
        self.remaining_before_failure -= read;
        Ok(read)
    }
}

struct FailAfter<'a> {
    bytes: &'a [u8],
    position: usize,
    fail_at: usize,
}

impl<'a> FailAfter<'a> {
    fn new(bytes: &'a [u8], fail_at: usize) -> Self {
        Self {
            bytes,
            position: 0,
            fail_at,
        }
    }
}

impl Read for FailAfter<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.fail_at {
            return Err(io::Error::other("fixture interruption"));
        }
        let available = self.bytes.len().min(self.fail_at) - self.position;
        let read = buffer.len().min(available);
        buffer[..read].copy_from_slice(&self.bytes[self.position..self.position + read]);
        self.position += read;
        Ok(read)
    }
}

struct ZeroReader {
    remaining: u64,
    max_requested: usize,
}

impl ZeroReader {
    fn new(remaining: u64) -> Self {
        Self {
            remaining,
            max_requested: 0,
        }
    }
}

impl Read for ZeroReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.max_requested = self.max_requested.max(buffer.len());
        let read =
            usize::try_from(self.remaining.min(buffer.len() as u64)).expect("bounded read length");
        buffer[..read].fill(0);
        self.remaining -= read as u64;
        Ok(read)
    }
}
