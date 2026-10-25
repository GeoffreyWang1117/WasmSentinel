//! The embedded random forest against probabilities computed by scikit-learn
//! on the same sequences (train/train_rf.py writes the fixture). Checks the
//! exporter's layout, the f32 threshold rounding and the traversal without
//! needing Python in the test environment.

use ml_detector::{adfa_features, Forest, RF_N_NODES, RF_N_TREES};
use serde::Deserialize;

#[derive(Deserialize)]
struct Golden {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    syscalls: Vec<u32>,
    prob: f64,
}

const GOLDEN: &str = include_str!("../train/fixtures/forest_golden.json");

#[test]
fn forest_matches_sklearn_reference() {
    let golden: Golden = serde_json::from_str(GOLDEN).expect("fixture parses");
    assert!(golden.cases.len() >= 10, "fixture too small");
    let forest = Forest::embedded();
    assert_eq!(forest.n_trees(), RF_N_TREES);
    assert_eq!(forest.n_nodes(), RF_N_NODES);

    let mut worst = 0f64;
    for (i, case) in golden.cases.iter().enumerate() {
        let s = forest.score(&adfa_features(&case.syscalls)) as f64;
        let d = (s - case.prob).abs();
        worst = worst.max(d);
        assert!(
            d < 1e-6,
            "case {i} (len {}): rust {s} vs sklearn {}",
            case.syscalls.len(),
            case.prob
        );
    }
    eprintln!(
        "max |prob diff| {worst:e} over {} cases",
        golden.cases.len()
    );
}
