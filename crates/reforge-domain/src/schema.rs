//! JSON Schema generation for the canonical wire documents.

use std::{fs, io, path::Path};

use schemars::{JsonSchema, schema_for};
use serde_json::Value;

use crate::model::{
    ErrorEnvelope, Inventory, PackageManifest, RestorePlan, RestoreReport, SnapshotManifest,
};

/// Schema version for all Reforge wire documents in this release.
pub const SCHEMA_VERSION: u16 = 1;

/// Return the checked-in schema documents in deterministic filename order.
pub fn schema_documents() -> [(&'static str, Value); 6] {
    [
        ("inventory.schema.json", schema_json::<Inventory>()),
        (
            "package-manifest.schema.json",
            schema_json::<PackageManifest>(),
        ),
        (
            "snapshot-manifest.schema.json",
            schema_json::<SnapshotManifest>(),
        ),
        ("restore-plan.schema.json", schema_json::<RestorePlan>()),
        ("restore-report.schema.json", schema_json::<RestoreReport>()),
        ("error.schema.json", schema_json::<ErrorEnvelope>()),
    ]
}

/// Generate one JSON Schema value from a canonical domain type.
pub fn schema_json<T: JsonSchema>() -> Value {
    let schema =
        serde_json::to_value(schema_for!(T)).expect("JsonSchema output must be serializable");
    canonicalize_json(schema)
}

const ORDER_INSENSITIVE_ARRAY_KEYS: [&str; 6] =
    ["allOf", "anyOf", "enum", "oneOf", "required", "type"];

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.into_iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = serde_json::Map::with_capacity(entries.len());
            for (key, value) in entries {
                let value = canonicalize_json(value);
                let value = if ORDER_INSENSITIVE_ARRAY_KEYS.contains(&key.as_str()) {
                    sort_schema_set(value)
                } else {
                    value
                };
                sorted.insert(key, value);
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        other => other,
    }
}

fn sort_schema_set(value: Value) -> Value {
    let Value::Array(mut values) = value else {
        return value;
    };
    values.sort_unstable_by(|left, right| {
        let left = serde_json::to_vec(left).expect("canonical schema value must serialize");
        let right = serde_json::to_vec(right).expect("canonical schema value must serialize");
        left.cmp(&right)
    });
    Value::Array(values)
}

/// Write all canonical schemas beneath `directory`.
///
/// The checked-in schema drift test and release tooling use the same function,
/// so generation cannot silently diverge from the Rust model.
pub fn write_schema_documents(directory: impl AsRef<Path>) -> io::Result<()> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory)?;
    for (name, schema) in schema_documents() {
        let path = directory.join(name);
        let bytes =
            serde_json::to_vec_pretty(&schema).expect("JsonSchema output must be serializable");
        fs::write(path, [bytes.as_slice(), b"\n"].concat())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use super::*;

    #[test]
    fn checked_in_schemas_match_the_canonical_model() {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas");
        if env::var_os("REFORGE_UPDATE_SCHEMAS").is_some() {
            write_schema_documents(&directory).expect("write generated schemas");
            return;
        }

        for (name, schema) in schema_documents() {
            let path = directory.join(name);
            let expected =
                serde_json::to_vec_pretty(&schema).expect("JsonSchema output must be serializable");
            let expected = [expected.as_slice(), b"\n"].concat();
            let actual = fs::read(&path).unwrap_or_else(|error| {
                panic!("missing generated schema {}: {error}", path.display())
            });
            assert_eq!(
                actual,
                expected,
                "generated schema is stale: {}",
                path.display()
            );
        }
    }
}
