//! Recurses without bound.
fn descend(n: u64, acc: u64) -> u64 {
    if n == 0 {
        return acc;
    }
    let next = std::hint::black_box(descend(n - 1, acc.wrapping_add(n)));
    next ^ (n << 1)
}

#[no_mangle]
pub extern "C" fn detect(_ptr: *const u8, _len: usize) -> i32 {
    descend(1 << 40, 0) as i32
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
