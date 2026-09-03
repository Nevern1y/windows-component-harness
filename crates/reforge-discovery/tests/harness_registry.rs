use std::collections::BTreeMap;

use reforge_discovery::{
    ProviderAdapter, ProviderContext,
    harnesses::{HarnessKind, HarnessRegistryAdapter},
};
use reforge_domain::{AccountScope, Architecture, HostFacts, KnownFolderToken, ReforgeErrorCode};
use reforge_platform_windows::{CancellationToken, KnownFolderMap, ProcessRunner};

#[tokio::test]
async fn registry_adapters_dispatch_all_documented_harnesses_without_configured_roots() {
    let host = HostFacts {
        os_version: "fixture".to_owned(),
        os_build: "fixture".to_owned(),
        architecture: Architecture::X64,
        elevated: false,
        account_scope: AccountScope::User,
        sid_fingerprint: None,
        known_folders: Vec::new(),
        drives: Vec::new(),
        free_bytes: Vec::new(),
    };
    let known_folders = KnownFolderMap::from_entries(BTreeMap::<KnownFolderToken, _>::new());
    let runner = ProcessRunner::new();
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let context = ProviderContext {
        host: &host,
        known_folders: &known_folders,
        runner: &runner,
        cancellation: &cancellation,
    };

    for kind in HarnessKind::ALL {
        let adapter = HarnessRegistryAdapter::new(kind);
        let detection = adapter.detect(&context);
        assert!(!detection.available, "{kind:?} must not invent roots");
        assert_eq!(detection.warnings, Vec::<String>::new());
        let error = adapter
            .enumerate(&context)
            .await
            .expect_err("cancelled discovery must stop before reading process environment");
        assert_eq!(error.code, ReforgeErrorCode::Cancelled);
    }
}
