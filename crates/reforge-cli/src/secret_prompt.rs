//! Interactive secret input and one-time recovery presentation.
//!
//! Passphrases are read from the terminal without echo and are never accepted
//! as command-line arguments.

use std::io::{self, BufRead, IsTerminal, Write};

use reforge_domain::{ErrorEnvelope, ReforgeErrorCode};
use reforge_package::{ExposeSecret, PendingVault, SecretString};

/// Injectable hidden-input boundary used by the real terminal and tests.
pub trait HiddenSecretInput {
    fn read_hidden(&mut self, prompt: &str) -> io::Result<SecretString>;
}

/// Reads directly from the controlling terminal with input echo disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct TerminalHiddenSecretInput;

impl HiddenSecretInput for TerminalHiddenSecretInput {
    fn read_hidden(&mut self, prompt: &str) -> io::Result<SecretString> {
        rpassword::prompt_password(prompt).map(SecretString::from)
    }
}

/// Prompt for a passphrase used to open an existing vault.
pub fn read_vault_passphrase(
    input: &mut impl HiddenSecretInput,
) -> Result<SecretString, Box<ErrorEnvelope>> {
    let passphrase = input
        .read_hidden("Vault passphrase: ")
        .map_err(|error| prompt_io_error("Read vault passphrase", &error))?;
    reject_empty(passphrase)
}

/// Prompt twice when creating a vault so a mistyped passphrase cannot make the
/// package unrecoverable.
pub fn read_new_vault_passphrase(
    input: &mut impl HiddenSecretInput,
) -> Result<SecretString, Box<ErrorEnvelope>> {
    let passphrase = input
        .read_hidden("New vault passphrase: ")
        .map_err(|error| prompt_io_error("Read new vault passphrase", &error))?;
    let confirmation = input
        .read_hidden("Confirm vault passphrase: ")
        .map_err(|error| prompt_io_error("Read vault passphrase confirmation", &error))?;
    let passphrase = reject_empty(passphrase)?;
    if passphrase.expose_secret() != confirmation.expose_secret() {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::UserActionRequired,
            "Vault passphrase confirmation does not match",
        )));
    }
    Ok(passphrase)
}

/// Narrow UI boundary for displaying recovery material exactly once and
/// collecting a separate explicit acknowledgement.
pub trait RecoveryIdentityPresenter {
    fn show_once(&mut self, recipient: &str, identity: &SecretString) -> io::Result<()>;

    fn confirm_saved(&mut self) -> io::Result<bool>;
}

/// Console presenter. It refuses redirected input/output so a recovery identity
/// is not accidentally written into a pipeline or process log.
#[derive(Clone, Copy, Debug, Default)]
pub struct TerminalRecoveryIdentityPresenter;

impl RecoveryIdentityPresenter for TerminalRecoveryIdentityPresenter {
    fn show_once(&mut self, recipient: &str, identity: &SecretString) -> io::Result<()> {
        let stdout = io::stdout();
        if !stdout.is_terminal() || !io::stdin().is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "recovery identity requires an interactive terminal",
            ));
        }
        let mut output = stdout.lock();
        writeln!(
            output,
            "Recovery recipient: {recipient}\nRecovery identity (shown once): {}",
            identity.expose_secret()
        )?;
        output.flush()
    }

    fn confirm_saved(&mut self) -> io::Result<bool> {
        let stdout = io::stdout();
        if !stdout.is_terminal() || !io::stdin().is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "recovery acknowledgement requires an interactive terminal",
            ));
        }
        {
            let mut output = stdout.lock();
            write!(output, "Type I SAVED IT to acknowledge secure storage: ")?;
            output.flush()?;
        }
        let mut acknowledgement = String::new();
        io::stdin().lock().read_line(&mut acknowledgement)?;
        Ok(acknowledgement.trim_end() == "I SAVED IT")
    }
}

/// Reveal optional recovery material once and unlock package publication only
/// after an explicit acknowledgement.
pub fn present_recovery_identity(
    pending: &mut PendingVault,
    presenter: &mut impl RecoveryIdentityPresenter,
) -> Result<(), Box<ErrorEnvelope>> {
    let Some(recovery) = pending.take_recovery_identity()? else {
        return Ok(());
    };
    presenter
        .show_once(recovery.recipient(), recovery.identity())
        .map_err(|error| prompt_io_error("Display recovery identity", &error))?;
    let saved = presenter
        .confirm_saved()
        .map_err(|error| prompt_io_error("Read recovery acknowledgement", &error))?;
    if !saved {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::UserActionRequired,
            "Recovery identity was not acknowledged as saved",
        )));
    }
    pending.acknowledge_recovery_saved()
}

fn reject_empty(passphrase: SecretString) -> Result<SecretString, Box<ErrorEnvelope>> {
    if passphrase.expose_secret().is_empty() {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::VaultRequired,
            "Vault passphrase must not be empty",
        )));
    }
    Ok(passphrase)
}

fn prompt_io_error(message: &str, error: &io::Error) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::from_io_error(error, message))
}
