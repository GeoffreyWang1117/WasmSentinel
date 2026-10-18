//! Opens a TCP connection. Contained when the connect fails (no sockets in WASI p1).
#[no_mangle]
pub extern "C" fn detect(_ptr: *const u8, _len: usize) -> i32 {
    match std::net::TcpStream::connect("127.0.0.1:22") {
        Ok(_) => 9,
        Err(_) => 0,
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
