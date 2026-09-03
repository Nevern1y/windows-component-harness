//! Versioned, bounded protocol shared by the unelevated launcher and helper.
//!
//! Requests intentionally contain identities only. Paths, commands, arguments,
//! and environment values are rejected by `deny_unknown_fields`.

use reforge_domain::{OperationId, RunId};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

pub const JOURNAL_DIRECTORY: &str = "Reforge";
pub const JOURNAL_FILE_NAME: &str = "journal.sqlite3";

pub fn pipe_name(run_id: &RunId, nonce: &str) -> Result<String, ProtocolError> {
    if !is_valid_nonce(nonce) {
        return Err(ProtocolError::InvalidNonce);
    }
    Ok(format!(r"\\.\pipe\reforge-{}-{nonce}", run_id.as_str()))
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ElevationRequest {
    pub protocol_version: u16,
    pub run_id: RunId,
    pub operation: OperationId,
    pub nonce: String,
}

impl ElevationRequest {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if !is_valid_nonce(&self.nonce) {
            return Err(ProtocolError::InvalidNonce);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ElevationResponse {
    Authorized {
        run_id: RunId,
        operation: OperationId,
    },
    Rejected {
        reason: RejectionReason,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RejectionReason {
    ApprovalMissing,
    OperationMissing,
    OperationNotElevated,
    OperationAlreadyCompleted,
    WrongRun,
    WrongNonce,
    InvalidRequest,
    JournalUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    EmptyFrame,
    FrameTooLarge,
    InvalidJson,
    UnsupportedVersion,
    InvalidNonce,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::EmptyFrame => "elevation protocol frame is empty",
            Self::FrameTooLarge => "elevation protocol frame exceeds the limit",
            Self::InvalidJson => "elevation protocol frame is invalid JSON",
            Self::UnsupportedVersion => "elevation protocol version is unsupported",
            Self::InvalidNonce => "elevation protocol nonce is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProtocolError {}

pub fn encode_request(request: &ElevationRequest) -> Result<Vec<u8>, ProtocolError> {
    request.validate()?;
    encode_frame(request)
}

pub fn decode_request(bytes: &[u8]) -> Result<ElevationRequest, ProtocolError> {
    let request: ElevationRequest = decode_frame(bytes)?;
    request.validate()?;
    Ok(request)
}

pub fn encode_response(response: &ElevationResponse) -> Result<Vec<u8>, ProtocolError> {
    encode_frame(response)
}

pub fn decode_response(bytes: &[u8]) -> Result<ElevationResponse, ProtocolError> {
    decode_frame(bytes)
}

fn encode_frame(value: &impl Serialize) -> Result<Vec<u8>, ProtocolError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ProtocolError::InvalidJson)?;
    if bytes.is_empty() {
        return Err(ProtocolError::EmptyFrame);
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    Ok(bytes)
}

fn decode_frame<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::EmptyFrame);
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidJson)
}

pub fn is_valid_nonce(nonce: &str) -> bool {
    nonce.len() == 64
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ElevationRequest {
        ElevationRequest {
            protocol_version: PROTOCOL_VERSION,
            run_id: RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned())
                .expect("valid run ID"),
            operation: OperationId::new("op_018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31_1")
                .expect("valid operation ID"),
            nonce: "a".repeat(64),
        }
    }

    #[test]
    fn request_round_trips_without_command_fields() {
        let request = request();
        let bytes = encode_request(&request).expect("encode");
        assert_eq!(decode_request(&bytes).expect("decode"), request);
        let json = String::from_utf8(bytes).expect("UTF-8");
        assert!(!json.contains("command"));
        assert!(!json.contains("path"));
    }

    #[test]
    fn unknown_command_field_is_rejected() {
        let mut value = serde_json::to_value(request()).expect("serialize");
        value["command"] = serde_json::json!("cmd /c whoami");
        let bytes = serde_json::to_vec(&value).expect("serialize");
        assert_eq!(decode_request(&bytes), Err(ProtocolError::InvalidJson));
    }

    #[test]
    fn malformed_nonce_is_rejected() {
        let mut request = request();
        request.nonce = "../journal.db".to_owned();
        assert_eq!(request.validate(), Err(ProtocolError::InvalidNonce));
    }

    #[test]
    fn oversized_frame_is_rejected_before_json_decode() {
        let bytes = vec![b' '; MAX_FRAME_BYTES + 1];
        assert_eq!(decode_request(&bytes), Err(ProtocolError::FrameTooLarge));
    }
}
