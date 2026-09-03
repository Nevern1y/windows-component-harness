use reforge_domain::{
    ComponentId, Identity, IdentityQuality, ObjectId, OperationId, ProviderId, Publisher, RunId,
};

fn empty_identity() -> Identity {
    Identity {
        provider_package: None,
        provider_source: None,
        package_family: None,
        product_name: None,
        executable_name: None,
        publisher: None,
        executable_hash: None,
        install_role: None,
        identity_quality: IdentityQuality::Local,
    }
}

#[test]
fn component_identity_uses_provider_tuple_and_normalizes_declared_fields() {
    let first = Identity {
        provider_package: Some((
            ProviderId::new("WinGet").expect("provider ID"),
            " Contoso.App ".to_owned(),
        )),
        provider_source: Some("Microsoft.Winget.Source_8wekyb3d8bbwe".to_owned()),
        publisher: Some("Contoso, Ltd.".to_owned()),
        identity_quality: IdentityQuality::Provider,
        ..empty_identity()
    };
    let second = Identity {
        provider_package: Some((ProviderId::new("winget").unwrap(), "contoso.app".to_owned())),
        provider_source: Some("microsoft.winget.source_8wekyb3d8bbwe".to_owned()),
        publisher: Some("different publisher evidence".to_owned()),
        identity_quality: IdentityQuality::Provider,
        ..empty_identity()
    };

    let first_result = ComponentId::from_identity(&first, None).expect("canonical identity");
    let second_result = ComponentId::from_identity(&second, None).expect("canonical identity");
    assert_eq!(
        first_result.id.as_str(),
        "cmp_6dh3r5klcpthhdzi2tl3uo7blw4mtxjfdcev7pgneu7bkn2nypjq"
    );

    assert_eq!(first_result.quality, IdentityQuality::Provider);
    assert_eq!(first_result.id, second_result.id);
    assert_eq!(first_result.id.as_str().len(), 56);
    assert!(first_result.id.as_str().starts_with("cmp_"));
}

#[test]
fn local_identity_ignores_user_and_drive_path_changes_but_requires_hash() {
    let first = Identity {
        executable_name: Some(r"C:\Users\Alice\bin\Tool.EXE".to_owned()),
        executable_hash: Some("ABCDEF0123".to_owned()),
        identity_quality: IdentityQuality::Local,
        ..empty_identity()
    };
    let second = Identity {
        executable_name: Some(r"D:\Users\Bob\bin\tool.exe".to_owned()),
        executable_hash: Some("abcdef0123".to_owned()),
        identity_quality: IdentityQuality::Local,
        ..empty_identity()
    };

    let first_result = ComponentId::from_identity(&first, None).expect("local identity");
    let second_result = ComponentId::from_identity(&second, None).expect("local identity");

    assert_eq!(first_result.quality, IdentityQuality::Local);
    assert_eq!(first_result.id, second_result.id);

    let without_hash = Identity {
        executable_name: Some("tool.exe".to_owned()),
        identity_quality: IdentityQuality::Local,
        ..empty_identity()
    };
    assert!(ComponentId::from_identity(&without_hash, None).is_err());
}

#[test]
fn publisher_changes_keep_product_identities_separate() {
    let base = Identity {
        product_name: Some("Contoso Editor".to_owned()),
        publisher: Some("Contoso".to_owned()),
        install_role: Some("main".to_owned()),
        identity_quality: IdentityQuality::Product,
        ..empty_identity()
    };
    let other = Identity {
        publisher: Some("Other Publisher".to_owned()),
        ..base.clone()
    };

    let first = ComponentId::from_identity(
        &base,
        Some(&Publisher {
            name: "Contoso".to_owned(),
            certificate_thumbprint: None,
        }),
    )
    .expect("product identity");
    let second = ComponentId::from_identity(
        &other,
        Some(&Publisher {
            name: "Other Publisher".to_owned(),
            certificate_thumbprint: None,
        }),
    )
    .expect("product identity");

    assert_eq!(first.quality, IdentityQuality::Product);
    assert_eq!(second.quality, IdentityQuality::Product);
    assert_ne!(first.id, second.id);
}

#[test]
fn signed_product_uses_certificate_thumbprint_before_product_fallback() {
    let identity = Identity {
        product_name: Some("Contoso Editor".to_owned()),
        identity_quality: IdentityQuality::SignedProduct,
        ..empty_identity()
    };
    let publisher = Publisher {
        name: "Contoso".to_owned(),
        certificate_thumbprint: Some("AA BB CC".to_owned()),
    };

    let result = ComponentId::from_identity(&identity, Some(&publisher)).expect("signed identity");
    assert_eq!(result.quality, IdentityQuality::SignedProduct);
}

#[test]
fn object_and_operation_ids_are_canonical_and_validated() {
    let object = ObjectId::from_content(b"canonical bytes");
    assert_eq!(
        object.as_str(),
        "obj_64898bcd43e0bd5a7f0919c759c0712cfc828de98d07d0599ff0545a1014c80d"
    );
    assert!(object.as_str().starts_with("obj_"));
    assert_eq!(object.as_str().len(), 68);
    assert_eq!(ObjectId::new(object.as_str().to_owned()).unwrap(), object);

    let run = RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).unwrap();
    let operation = OperationId::for_run(&run, 7).expect("operation ID");
    assert_eq!(
        operation.as_str(),
        "op_018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31_7"
    );
    assert_eq!(
        OperationId::new(operation.as_str().to_owned()).unwrap(),
        operation
    );

    assert!(ComponentId::new(format!("cmp_{}", "A".repeat(52))).is_err());
    assert!(ObjectId::new("obj_not-a-hex-digest".to_owned()).is_err());
}

#[test]
fn identity_without_supported_tuple_is_rejected() {
    let identity = empty_identity();
    assert!(ComponentId::from_identity(&identity, None).is_err());
}
