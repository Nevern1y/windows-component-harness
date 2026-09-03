//! Deterministic JSON encoding for package metadata and object identifiers.
//!
//! Canonicalization is deliberately performed on a `serde_json::Value` tree:
//! object keys are sorted at the final encoding boundary, while arrays remain
//! in their input order. Domain values can use [`canonicalize`] to cross this
//! boundary without first exposing an alternate wire representation.

use chrono::{DateTime, SecondsFormat, Utc};
use reforge_domain::{ErrorEnvelope, ObjectId, ReforgeErrorCode};
use serde::{Serialize, Serializer};
use serde_json::{Map, Number, Value};

/// A canonical UTF-8 JSON document and the ID of its exact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalJson {
    bytes: Vec<u8>,
    object_id: ObjectId,
}

impl CanonicalJson {
    /// Canonicalize one JSON value without performing a second serialization.
    pub fn from_value(value: &Value) -> Result<Self, Box<ErrorEnvelope>> {
        let bytes = canonical_value_bytes(value)?;
        let object_id = ObjectId::from_content(&bytes);
        Ok(Self { bytes, object_id })
    }

    /// Return the exact bytes covered by the object ID.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the content-addressed ID for [`Self::as_bytes`].
    pub fn object_id(&self) -> &ObjectId {
        &self.object_id
    }

    /// Consume the document and return its canonical bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Serialize a Serde value using Reforge's canonical JSON rules.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<CanonicalJson, Box<ErrorEnvelope>> {
    // The serde_json Value serializer coerces non-finite floats to null.
    // Intercept numeric callbacks before delegating to that serializer.
    let value = checked_to_value(value).map_err(|_| serialization_error())?;
    CanonicalJson::from_value(&value)
}

fn checked_to_value<T: ?Sized + Serialize>(value: &T) -> Result<Value, serde_json::Error> {
    value.serialize(CheckedValueSerializer)
}

#[derive(Clone, Copy, Debug, Default)]
struct CheckedValueSerializer;

impl Serializer for CheckedValueSerializer {
    type Ok = Value;
    type Error = serde_json::Error;
    type SerializeSeq = CheckedSeq;
    type SerializeTuple = CheckedSeq;
    type SerializeTupleStruct = CheckedSeq;
    type SerializeTupleVariant = CheckedTupleVariant;
    type SerializeMap = CheckedMap;
    type SerializeStruct = CheckedMap;
    type SerializeStructVariant = CheckedStructVariant;

    fn serialize_bool(self, value: bool) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Bool(value))
    }

    fn serialize_i8(self, value: i8) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Number(value.into()))
    }

    fn serialize_i16(self, value: i16) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Number(value.into()))
    }

    fn serialize_i32(self, value: i32) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Number(value.into()))
    }

    fn serialize_i64(self, value: i64) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Number(value.into()))
    }

    fn serialize_i128(self, value: i128) -> Result<Self::Ok, Self::Error> {
        serde_json::value::Serializer.serialize_i128(value)
    }

    fn serialize_u8(self, value: u8) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Number(value.into()))
    }

    fn serialize_u16(self, value: u16) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Number(value.into()))
    }

    fn serialize_u32(self, value: u32) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Number(value.into()))
    }

    fn serialize_u64(self, value: u64) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Number(value.into()))
    }

    fn serialize_u128(self, value: u128) -> Result<Self::Ok, Self::Error> {
        serde_json::value::Serializer.serialize_u128(value)
    }

    fn serialize_f32(self, value: f32) -> Result<Self::Ok, Self::Error> {
        if !value.is_finite() {
            return Err(non_finite_number_error());
        }
        serde_json::value::Serializer.serialize_f32(value)
    }

    fn serialize_f64(self, value: f64) -> Result<Self::Ok, Self::Error> {
        if !value.is_finite() {
            return Err(non_finite_number_error());
        }
        serde_json::value::Serializer.serialize_f64(value)
    }

    fn serialize_char(self, value: char) -> Result<Self::Ok, Self::Error> {
        Ok(Value::String(value.to_string()))
    }

    fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
        Ok(Value::String(value.to_owned()))
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Array(
            value
                .iter()
                .map(|byte| Value::Number((*byte).into()))
                .collect(),
        ))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Null)
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        checked_to_value(value)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Null)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.serialize_unit()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        checked_to_value(value)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        let mut object = Map::new();
        object.insert(variant.to_owned(), checked_to_value(value)?);
        Ok(Value::Object(object))
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(CheckedSeq {
            values: Vec::with_capacity(len.unwrap_or_default()),
        })
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(CheckedTupleVariant {
            variant: variant.to_owned(),
            values: Vec::with_capacity(len),
        })
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(CheckedMap {
            values: Map::with_capacity(len.unwrap_or_default()),
            pending_key: None,
        })
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(CheckedStructVariant {
            variant: variant.to_owned(),
            values: Map::with_capacity(len),
        })
    }

    fn collect_str<T: ?Sized + std::fmt::Display>(
        self,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.serialize_str(&value.to_string())
    }
}

fn non_finite_number_error() -> serde_json::Error {
    <serde_json::Error as serde::ser::Error>::custom("non-finite number")
}

struct CheckedSeq {
    values: Vec<Value>,
}

impl serde::ser::SerializeSeq for CheckedSeq {
    type Ok = Value;
    type Error = serde_json::Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.values.push(checked_to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Array(self.values))
    }
}

impl serde::ser::SerializeTuple for CheckedSeq {
    type Ok = Value;
    type Error = serde_json::Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.values.push(checked_to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Array(self.values))
    }
}

impl serde::ser::SerializeTupleStruct for CheckedSeq {
    type Ok = Value;
    type Error = serde_json::Error;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.values.push(checked_to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Array(self.values))
    }
}

struct CheckedTupleVariant {
    variant: String,
    values: Vec<Value>,
}

impl serde::ser::SerializeTupleVariant for CheckedTupleVariant {
    type Ok = Value;
    type Error = serde_json::Error;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.values.push(checked_to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let mut object = Map::new();
        object.insert(self.variant, Value::Array(self.values));
        Ok(Value::Object(object))
    }
}

struct CheckedMap {
    values: Map<String, Value>,
    pending_key: Option<String>,
}

impl serde::ser::SerializeMap for CheckedMap {
    type Ok = Value;
    type Error = serde_json::Error;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.pending_key = Some(map_key(&checked_to_value(key)?)?);
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        let key = self.pending_key.take().ok_or_else(|| {
            <serde_json::Error as serde::ser::Error>::custom("map value without key")
        })?;
        self.values.insert(key, checked_to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Object(self.values))
    }
}

impl serde::ser::SerializeStruct for CheckedMap {
    type Ok = Value;
    type Error = serde_json::Error;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.values.insert(key.to_owned(), checked_to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Value::Object(self.values))
    }
}

fn map_key(value: &Value) -> Result<String, serde_json::Error> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => Err(
            <serde_json::Error as serde::ser::Error>::custom("map key must be a scalar"),
        ),
    }
}

struct CheckedStructVariant {
    variant: String,
    values: Map<String, Value>,
}

impl serde::ser::SerializeStructVariant for CheckedStructVariant {
    type Ok = Value;
    type Error = serde_json::Error;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.values.insert(key.to_owned(), checked_to_value(value)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let mut object = Map::new();
        object.insert(self.variant, Value::Object(self.values));
        Ok(Value::Object(object))
    }
}

/// Return canonical JSON bytes for a Serde value.
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, Box<ErrorEnvelope>> {
    Ok(canonicalize(value)?.into_bytes())
}

/// Derive an object ID from a value's uncompressed canonical JSON bytes.
pub fn canonical_object_id<T: Serialize>(value: &T) -> Result<ObjectId, Box<ErrorEnvelope>> {
    Ok(canonicalize(value)?.object_id().clone())
}

fn canonical_value_bytes(value: &Value) -> Result<Vec<u8>, Box<ErrorEnvelope>> {
    let mut bytes = Vec::new();
    write_value(value, None, &mut bytes)?;
    Ok(bytes)
}

fn write_value(
    value: &Value,
    field_name: Option<&str>,
    output: &mut Vec<u8>,
) -> Result<(), Box<ErrorEnvelope>> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => write_number(value, output)?,
        Value::String(value) => write_string(value, field_name, output)?,
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                // Array order is semantic. A field's normalization rule does
                // not turn an array into a sorted set or reorder its members.
                write_value(value, None, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => write_object(values, output)?,
    }
    Ok(())
}

fn write_object(
    values: &Map<String, Value>,
    output: &mut Vec<u8>,
) -> Result<(), Box<ErrorEnvelope>> {
    // serde_json::Map is not part of the canonical contract: sort explicitly
    // even when its selected backing map happens to be ordered.
    let mut entries: Vec<_> = values.iter().collect();
    entries.sort_by_key(|(left, _)| *left);

    output.push(b'{');
    for (index, (key, value)) in entries.into_iter().enumerate() {
        if index != 0 {
            output.push(b',');
        }
        write_json_string(key, output)?;
        output.push(b':');
        write_value(value, Some(key), output)?;
    }
    output.push(b'}');
    Ok(())
}

fn write_number(value: &Number, output: &mut Vec<u8>) -> Result<(), Box<ErrorEnvelope>> {
    // serde_json does not normally construct non-finite numbers. Keep this
    // guard at the package boundary so a future/custom Number representation
    // cannot silently enter an object ID.
    if let Some(float) = value.as_f64()
        && !float.is_finite()
    {
        return Err(canonical_error(
            "canonical JSON contains a non-finite number",
        ));
    }

    output.extend_from_slice(value.to_string().as_bytes());
    Ok(())
}

fn write_string(
    value: &str,
    field_name: Option<&str>,
    output: &mut Vec<u8>,
) -> Result<(), Box<ErrorEnvelope>> {
    let normalized = match field_name {
        Some(name) if is_timestamp_field(name) => normalize_timestamp(value)?,
        Some(name) if is_path_field(name) => normalize_path(value)?,
        _ => None,
    };

    match normalized {
        Some(value) => write_json_string(&value, output),
        None => write_json_string(value, output),
    }
}

fn write_json_string(value: &str, output: &mut Vec<u8>) -> Result<(), Box<ErrorEnvelope>> {
    let encoded = serde_json::to_vec(value).map_err(|_| serialization_error())?;
    output.extend_from_slice(&encoded);
    Ok(())
}

fn is_timestamp_field(field_name: &str) -> bool {
    matches!(
        field_name,
        "acknowledged_at"
            | "captured_at"
            | "completed_at"
            | "created_at"
            | "observed_at"
            | "started_at"
            | "timestamp"
            | "updated_at"
    )
}

fn is_path_field(field_name: &str) -> bool {
    matches!(
        field_name,
        "destination" | "path" | "relative" | "source_path"
    )
}

fn normalize_timestamp(value: &str) -> Result<Option<String>, Box<ErrorEnvelope>> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| canonical_error("declared timestamp is not valid RFC 3339"))?;
    Ok(Some(
        parsed
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::AutoSi, true),
    ))
}

fn normalize_path(value: &str) -> Result<Option<String>, Box<ErrorEnvelope>> {
    if value.contains('\0') {
        return Err(canonical_error("declared path contains a NUL byte"));
    }

    let value = value.replace('\\', "/");
    if value.starts_with('/') || value.starts_with("//") || has_drive_prefix(&value) {
        return Err(canonical_error(
            "declared path must be a relative token path",
        ));
    }

    let mut segments = Vec::new();
    for segment in value.split('/') {
        match segment {
            "" | "." => {}
            ".." => return Err(canonical_error("declared path contains a parent segment")),
            segment if segment.contains(':') => {
                return Err(canonical_error(
                    "declared path contains a drive or URI prefix",
                ));
            }
            segment => segments.push(segment),
        }
    }

    Ok(Some(segments.join("/")))
}

fn has_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn serialization_error() -> Box<ErrorEnvelope> {
    canonical_error("value could not be represented as canonical JSON")
}

fn canonical_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(ReforgeErrorCode::SchemaInvalid, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_keys_are_sorted_and_hashes_are_stable() {
        let first = serde_json::json!({"z": 1, "a": {"y": true, "b": null}});
        let second = serde_json::json!({"a": {"b": null, "y": true}, "z": 1});

        let first = canonicalize(&first).expect("first canonical value");
        let second = canonicalize(&second).expect("second canonical value");

        assert_eq!(first.as_bytes(), br#"{"a":{"b":null,"y":true},"z":1}"#);
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_eq!(first.object_id(), second.object_id());
    }

    #[test]
    fn arrays_preserve_semantic_order() {
        let first = canonical_bytes(&serde_json::json!(["first", "second"])).unwrap();
        let second = canonical_bytes(&serde_json::json!(["second", "first"])).unwrap();

        assert_eq!(first, br#"["first","second"]"#);
        assert_ne!(first, second);
    }

    #[test]
    fn non_finite_numbers_are_rejected_before_object_id_generation() {
        struct NonFinite;

        impl Serialize for NonFinite {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_f64(f64::NAN)
            }
        }

        let error = canonicalize(&NonFinite).expect_err("NaN must be rejected");
        assert_eq!(error.code, ReforgeErrorCode::SchemaInvalid);
    }

    #[test]
    fn declared_timestamps_and_paths_are_normalized() {
        let input = serde_json::json!({
            "relative": "tools\\.\\bin/config.json",
            "observed_at": "2026-08-29T14:34:56+02:00",
            "label": "keep\\backslash"
        });

        let canonical = canonical_bytes(&input).expect("canonical value");
        assert_eq!(
            canonical,
            br#"{"label":"keep\\backslash","observed_at":"2026-08-29T12:34:56Z","relative":"tools/bin/config.json"}"#
        );
    }

    #[test]
    fn unicode_is_utf8_without_a_bom_and_hash_vector_is_stable() {
        let canonical = canonical_bytes(&serde_json::json!({"ключ": "значение"})).unwrap();
        assert!(!canonical.starts_with(&[0xEF, 0xBB, 0xBF]));
        assert!(std::str::from_utf8(&canonical).is_ok());

        // BLAKE3's published empty-content vector also exercises the domain
        // ObjectId encoding used by canonical documents.
        assert_eq!(
            ObjectId::from_content(b"canonical bytes").as_str(),
            "obj_64898bcd43e0bd5a7f0919c759c0712cfc828de98d07d0599ff0545a1014c80d"
        );
    }

    #[test]
    fn invalid_declared_path_and_timestamp_are_rejected() {
        for input in [
            serde_json::json!({"path": "../outside"}),
            serde_json::json!({"path": "C:/outside"}),
            serde_json::json!({"created_at": "not-a-timestamp"}),
        ] {
            let error = canonicalize(&input).expect_err("unsafe declared value");
            assert_eq!(error.code, ReforgeErrorCode::SchemaInvalid);
        }
    }
}
