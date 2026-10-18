//! Grows memory 16 MiB at a time until the store limiter refuses.
//! Returns the number of MiB it managed to commit.
#[no_mangle]
pub extern "C" fn detect(_ptr: *const u8, _len: usize) -> i32 {
    let mut v: Vec<u8> = Vec::new();
    let mut mib = 0i32;
    for _ in 0..1024 {
        if v.try_reserve(16 << 20).is_err() {
            break;
        }
        let new_len = v.len() + (16 << 20);
        v.resize(new_len, 1); // touch the pages
        mib += 16;
    }
    std::hint::black_box(&v);
    mib
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
