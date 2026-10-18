;; Probes the WASI capabilities the host hands out:
;;   returns environ_count * 1000 + args_count * 100 + fd_write(stdout) errno
;; A zero-capability WASI must report 0 environment variables and 0 arguments, and
;; writing to stdout must not reach the host terminal (errno 0 = discarded, 8 = EBADF).
(module
  (import "wasi_snapshot_preview1" "environ_sizes_get" (func $environ_sizes_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_sizes_get" (func $args_sizes_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2)
  (func (export "alloc") (param i32) (result i32) (i32.const 4096))
  (func (export "dealloc") (param i32 i32))
  (func (export "detect") (param $ptr i32) (param $len i32) (result i32)
    (local $errno i32)
    ;; scratch: [0]=count [4]=bufsize [8]=iov.base [12]=iov.len [16]=nwritten
    (drop (call $environ_sizes_get (i32.const 0) (i32.const 4)))
    (local.set $errno (i32.mul (i32.load (i32.const 0)) (i32.const 1000)))
    (drop (call $args_sizes_get (i32.const 0) (i32.const 4)))
    (local.set $errno (i32.add (local.get $errno) (i32.mul (i32.load (i32.const 0)) (i32.const 100))))
    (i32.store (i32.const 8) (local.get $ptr))
    (i32.store (i32.const 12) (local.get $len))
    (i32.add (local.get $errno)
             (call $fd_write (i32.const 1) (i32.const 8) (i32.const 1) (i32.const 16)))))
