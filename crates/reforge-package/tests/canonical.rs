use reforge_domain::ObjectId;
use reforge_package::{CanonicalJson, canonical_bytes, canonical_object_id, canonicalize};
use serde::Serialize;

#[test]
fn public_api_emits_one_canonical_document_and_matching_object_id() {
    let value = serde_json::json!({
        "z": ["first", "second"],
        "a": {"b": true, "a": null}
    });

    let document = CanonicalJson::from_value(&value).expect("canonical document");
    assert_eq!(
        document.as_bytes(),
        br#"{"a":{"a":null,"b":true},"z":["first","second"]}"#
    );
    assert_eq!(
        document.object_id(),
        &ObjectId::from_content(document.as_bytes())
    );
    assert_eq!(canonical_bytes(&value).unwrap(), document.as_bytes());
    assert_eq!(canonical_object_id(&value).unwrap(), *document.object_id());
}

#[test]
fn typed_values_use_the_same_path_and_timestamp_rules() {
    #[derive(Serialize)]
    struct Metadata {
        relative: String,
        created_at: String,
    }

    let metadata = Metadata {
        relative: String::from("config\\editor\\settings.json"),
        created_at: String::from("2026-08-30T02:00:00+02:00"),
    };

    assert_eq!(
        canonicalize(&metadata).unwrap().as_bytes(),
        br#"{"created_at":"2026-08-30T00:00:00Z","relative":"config/editor/settings.json"}"#
    );
}
