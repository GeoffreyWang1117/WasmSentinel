//! Writes 8 MiB to stdout and stderr. Contained when nothing reaches the host terminal.
use std::io::Write;

#[no_mangle]
pub extern "C" fn detect(_ptr: *const u8, _len: usize) -> i32 {
    let chunk = [b'A'; 4096];
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    for _ in 0..1024 {
        let _ = out.write_all(&chunk);
        let _ = err.write_all(&chunk);
    }
    let _ = out.flush();
    0
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
