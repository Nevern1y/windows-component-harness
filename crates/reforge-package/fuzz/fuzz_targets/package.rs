#![no_main]

use std::{fs, io::Write};

use libfuzzer_sys::fuzz_target;
use reforge_domain::{KnownFolderToken, ObjectId, PathToken};
use reforge_package::{BoundedStreamWriter, CanonicalJson, PackageReader};
use serde_json::Value;

const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(value) = serde_json::from_slice::<Value>(data)
        && let Ok(first) = CanonicalJson::from_value(&value)
    {
        let reparsed: Value = serde_json::from_slice(first.as_bytes())
            .expect("canonical serializer must emit valid JSON");
        let second =
            CanonicalJson::from_value(&reparsed).expect("canonical JSON must canonicalize again");
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_eq!(first.object_id(), second.object_id());
        assert_eq!(first.object_id(), &ObjectId::from_content(first.as_bytes()));
    }

    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(token) = PathToken::new(KnownFolderToken::Documents, text)
    {
        token.validate().expect("constructed token must validate");
        assert!(!token.relative.contains('\\'));
        assert!(!token.relative.split('/').any(|segment| segment == ".."));
    }

    let limit = data.first().copied().unwrap_or_default() as u64;
    let payload = data.get(1..).unwrap_or_default();
    let mut bounded = BoundedStreamWriter::new(Vec::new(), limit);
    let result = bounded.write_all(payload);
    let (forwarded, digest) = bounded.finish();
    if payload.len() as u64 <= limit {
        result.expect("in-bound stream must be accepted");
        assert_eq!(forwarded, payload);
        assert_eq!(digest.bytes, payload.len() as u64);
        assert_eq!(digest.blake3, *blake3::hash(payload).as_bytes());
    } else {
        assert!(result.is_err());
        assert!(forwarded.is_empty());
        assert_eq!(digest.bytes, 0);
    }

    let digest = blake3::hash(data).to_hex();
    let path = std::env::temp_dir().join(format!(
        "reforge-package-fuzz-{}-{}.reforge",
        std::process::id(),
        &digest[..16]
    ));
    if fs::write(&path, data).is_ok() {
        let _ = PackageReader::new(&path).inspect();
        let _ = fs::remove_file(path);
    }
});
