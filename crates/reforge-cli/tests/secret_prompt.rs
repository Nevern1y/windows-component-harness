#[path = "../src/secret_prompt.rs"]
mod secret_prompt;

use std::{collections::VecDeque, io, process::Command};

use reforge_domain::{ComponentId, ReforgeErrorCode};
use reforge_package::{
    ExposeSecret, SecretKind, SecretRecord, SecretString, SecretTarget, VaultDocument,
};
use secret_prompt::{
    HiddenSecretInput, RecoveryIdentityPresenter, TerminalHiddenSecretInput,
    TerminalRecoveryIdentityPresenter, present_recovery_identity, read_new_vault_passphrase,
    read_vault_passphrase,
};
use zeroize::Zeroizing;

struct ScriptedInput {
    values: VecDeque<&'static str>,
    prompts: Vec<String>,
}

impl ScriptedInput {
    fn new(values: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            values: values.into_iter().collect(),
            prompts: Vec::new(),
        }
    }
}

impl HiddenSecretInput for ScriptedInput {
    fn read_hidden(&mut self, prompt: &str) -> io::Result<SecretString> {
        self.prompts.push(prompt.to_owned());
        self.values
            .pop_front()
            .map(|value| SecretString::from(value.to_owned()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no scripted input"))
    }
}

#[test]
fn new_passphrase_is_hidden_confirmed_and_never_debugged() {
    let _ = TerminalHiddenSecretInput;
    let _ = TerminalRecoveryIdentityPresenter;
    let mut input = ScriptedInput::new(["vault-passphrase-4488", "vault-passphrase-4488"]);
    let passphrase = read_new_vault_passphrase(&mut input).expect("matching passphrase");
    assert_eq!(passphrase.expose_secret(), "vault-passphrase-4488");
    assert_eq!(input.prompts.len(), 2);
    assert!(!format!("{passphrase:?}").contains(passphrase.expose_secret()));

    let mut mismatch = ScriptedInput::new(["first-secret-1122", "second-secret-3344"]);
    let error = read_new_vault_passphrase(&mut mismatch).unwrap_err();
    assert_eq!(error.code, ReforgeErrorCode::UserActionRequired);
    assert!(!error.to_json().contains("first-secret-1122"));
    assert!(!error.to_json().contains("second-secret-3344"));

    let mut empty = ScriptedInput::new([""]);
    assert_eq!(
        read_vault_passphrase(&mut empty).unwrap_err().code,
        ReforgeErrorCode::VaultRequired
    );
}

struct RecordingPresenter {
    shown: usize,
    confirmed: bool,
    saw_valid_identity: bool,
    saw_recipient: bool,
}

impl RecoveryIdentityPresenter for RecordingPresenter {
    fn show_once(&mut self, recipient: &str, identity: &SecretString) -> io::Result<()> {
        self.shown += 1;
        self.saw_valid_identity = identity.expose_secret().starts_with("AGE-SECRET-KEY-");
        self.saw_recipient = recipient.starts_with("age1");
        Ok(())
    }

    fn confirm_saved(&mut self) -> io::Result<bool> {
        Ok(self.confirmed)
    }
}

#[test]
fn recovery_presenter_unlocks_publication_only_after_explicit_acknowledgement() {
    let record = SecretRecord::new(
        ComponentId::new(format!("cmp_{}", "a".repeat(52))).unwrap(),
        "CLI_TOKEN",
        SecretKind::ApiToken,
        SecretTarget::WindowsCredentialManager,
        Zeroizing::new(b"cli-secret-value-778899".to_vec()),
    )
    .unwrap();
    let mut pending = VaultDocument::new(vec![record])
        .unwrap()
        .encrypt(SecretString::from("cli-vault-passphrase".to_owned()), true)
        .unwrap();
    let mut presenter = RecordingPresenter {
        shown: 0,
        confirmed: true,
        saw_valid_identity: false,
        saw_recipient: false,
    };

    present_recovery_identity(&mut pending, &mut presenter).expect("acknowledged recovery");
    assert_eq!(presenter.shown, 1);
    assert!(presenter.saw_valid_identity);
    assert!(presenter.saw_recipient);
    pending.finish().expect("publishable vault");
    assert_eq!(
        present_recovery_identity(&mut pending, &mut presenter)
            .unwrap_err()
            .code,
        ReforgeErrorCode::UserActionRequired
    );
    assert_eq!(presenter.shown, 1);
}

#[test]
fn command_line_rejects_passphrase_arguments_without_echoing_the_value() {
    let argv_secret = "argv-secret-must-not-appear-661199";
    let output = Command::new(env!("CARGO_BIN_EXE_reforge"))
        .args(["--passphrase", argv_secret])
        .output()
        .expect("run CLI");
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(!stdout.contains(argv_secret));
    assert!(!stderr.contains(argv_secret));

    let help = Command::new(env!("CARGO_BIN_EXE_reforge"))
        .arg("--help")
        .output()
        .expect("run CLI help");
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).expect("UTF-8 help");
    assert!(!help.to_ascii_lowercase().contains("passphrase"));
}
