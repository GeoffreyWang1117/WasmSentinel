//! Feature set v1 and the embedded MLP against a fixture computed by the
//! NumPy training code (train/verify_wasm_parity.py --write-golden). Keeps the
//! Rust port honest without needing Python in the test environment.

use ml_detector::{adfa_features, MlpDetector, HIDDEN_SIZES, INPUT_SIZE};
use serde::Deserialize;

#[derive(Deserialize)]
struct Golden {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    syscalls: Vec<u32>,
    features: Vec<f32>,
    score: f32,
}

const GOLDEN: &str = include_str!("../train/fixtures/features_golden.json");

#[test]
fn features_and_scores_match_numpy_reference() {
    let golden: Golden = serde_json::from_str(GOLDEN).expect("fixture parses");
    assert!(golden.cases.len() >= 10, "fixture too small");
    let mlp = MlpDetector::with_embedded_weights();
    assert_eq!(mlp.get_config().hidden_sizes, HIDDEN_SIZES.to_vec());
    assert_eq!(mlp.get_config().input_size, INPUT_SIZE);

    let mut worst_feature = 0f32;
    let mut worst_score = 0f32;
    for (i, case) in golden.cases.iter().enumerate() {
        let f = adfa_features(&case.syscalls);
        assert_eq!(f.len(), case.features.len(), "case {i}: feature length");
        for (j, (a, b)) in f.iter().zip(&case.features).enumerate() {
            let d = (a - b).abs();
            worst_feature = worst_feature.max(d);
            assert!(d < 1e-6, "case {i} feature {j}: rust {a} vs numpy {b}");
        }
        let s = mlp.score(&f);
        let d = (s - case.score).abs();
        worst_score = worst_score.max(d);
        assert!(
            d < 1e-5,
            "case {i} (len {}): rust score {s} vs numpy {}",
            case.syscalls.len(),
            case.score
        );
    }
    eprintln!("max |feature diff| {worst_feature:e}, max |score diff| {worst_score:e}");
}
