//! Reads the wall clock: a capability the sandbox permits by design.
#[no_mangle]
pub extern "C" fn detect(_ptr: *const u8, _len: usize) -> i32 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) if d.as_secs() > 1_600_000_000 => 1,
        _ => 0,
    }
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
