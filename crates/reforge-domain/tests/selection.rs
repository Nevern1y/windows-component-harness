use reforge_domain::{ComponentId, ExplanationChip, RecommendationScore};

#[test]
fn recommendation_score_round_trips_with_explanation_chips() {
    let score = RecommendationScore {
        component: ComponentId::new(format!("cmp_{}", "a".repeat(52))).expect("component ID"),
        score: 35,
        recommended: true,
        chips: vec![ExplanationChip {
            code: "portable_configuration".to_owned(),
            label: "Documented portable configuration is available".to_owned(),
            delta: 15,
        }],
    };

    let encoded = serde_json::to_value(&score).expect("recommendation JSON");
    assert_eq!(encoded["component"], score.component.as_str());
    assert_eq!(encoded["score"], 35);
    assert_eq!(encoded["recommended"], true);
    assert_eq!(encoded["chips"][0]["delta"], 15);

    let decoded: RecommendationScore = serde_json::from_value(encoded).expect("round trip");
    assert_eq!(decoded, score);
}

#[test]
fn recommendation_score_rejects_unknown_fields() {
    let value = serde_json::json!({
        "component": format!("cmp_{}", "a".repeat(52)),
        "score": 0,
        "recommended": false,
        "chips": [],
        "unexpected": true
    });
    assert!(serde_json::from_value::<RecommendationScore>(value).is_err());
}
