pub mod commands;
pub mod events;

use reforge_domain::{ErrorEnvelope, ReforgeErrorCode};

/// The current desktop artifact is intentionally informational only.
///
/// The command implementations remain compiled for the future desktop
/// profile, but this build does not register an invoke handler or any native
/// capability that can control the Reforge engine. CLI is the only control
/// surface until this policy is changed explicitly in the specification.
pub const CLI_ONLY_BUILD: bool = true;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> Result<(), Box<ErrorEnvelope>> {
    if !CLI_ONLY_BUILD {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "Desktop control is disabled; use the Reforge CLI",
        )));
    }

    // Deliberately do not construct AppState, register Tauri commands, or
    // install native plugins here. Keeping the implementations in commands.rs
    // preserves the full feature set without exposing an app control path.
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .map_err(|error| {
            Box::new(
                ErrorEnvelope::new(
                    ReforgeErrorCode::OperationFailed,
                    "The desktop shell could not start",
                )
                .with_technical_detail(error.to_string()),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::CLI_ONLY_BUILD;

    #[test]
    fn desktop_artifact_is_hard_locked_to_cli_only_mode() {
        const {
            assert!(CLI_ONLY_BUILD);
        }
    }
}
