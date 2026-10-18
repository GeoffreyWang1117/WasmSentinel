//! Tries to read host files through WASI. Contained when every attempt fails.
#[no_mangle]
pub extern "C" fn detect(_ptr: *const u8, _len: usize) -> i32 {
    let mut leaked = 0;
    if matches!(std::fs::read("/etc/passwd"), Ok(b) if !b.is_empty()) {
        leaked += 1;
    }
    if std::fs::read_dir("/").map(|d| d.count()).unwrap_or(0) > 0 {
        leaked += 1;
    }
    if std::fs::write("/tmp/wasmsentinel-escape", b"x").is_ok() {
        leaked += 1;
    }
    leaked
}

// Guest ABI v2 allocator exports (same as the real rules).
#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr` must come from `alloc(size)`.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        drop(Vec::from_raw_parts(ptr, 0, size));
    }
}
