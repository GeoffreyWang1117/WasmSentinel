//! E2 helper: score syscall traces with the embedded model compiled natively
//! (same crate, same code as the Wasm module) and time it.
//!
//!   cargo run --release --example native_score -- --repeat 200 trace1.txt trace2.txt ...
//!
//! Prints one JSON object per trace: {"path", "len", "score", "ns_per_call"}
//! (median of `repeat` timed calls), then a summary line.

use std::time::Instant;

use ml_detector::{adfa_features, MlpDetector};

fn load_trace(path: &str) -> Vec<u32> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|t| t.parse::<u32>().ok())
        .collect()
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut repeat = 100usize;
    if let Some(i) = args.iter().position(|a| a == "--repeat") {
        repeat = args[i + 1].parse().expect("--repeat N");
        args.drain(i..=i + 1);
    }
    let mlp = MlpDetector::with_embedded_weights();
    let mut all_ns: Vec<f64> = Vec::new();
    for path in &args {
        let seq = load_trace(path);
        let mut score = 0f32;
        let mut samples = Vec::with_capacity(repeat);
        for _ in 0..repeat {
            let t = Instant::now();
            score = mlp.score(&adfa_features(std::hint::black_box(&seq)));
            samples.push(t.elapsed().as_nanos() as f64);
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = samples[samples.len() / 2];
        all_ns.push(median);
        println!(
            "{{\"path\":{:?},\"len\":{},\"score\":{:.8},\"ns_per_call\":{:.0}}}",
            path,
            seq.len(),
            score,
            median
        );
    }
    if !all_ns.is_empty() {
        all_ns.sort_by(|a, b| a.partial_cmp(b).unwrap());
        eprintln!(
            "native: {} traces, median {:.0} ns/call, p90 {:.0} ns/call",
            all_ns.len(),
            all_ns[all_ns.len() / 2],
            all_ns[(all_ns.len() * 9 / 10).min(all_ns.len() - 1)]
        );
    }
}
