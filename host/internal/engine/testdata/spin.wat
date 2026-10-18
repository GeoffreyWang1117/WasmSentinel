;; detect never returns: exercises the fuel budget and the epoch deadline.
(module
  (memory (export "memory") 2)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "dealloc") (param i32 i32))
  (func (export "detect") (param i32 i32) (result i32)
    (loop $l (br $l))
    (i32.const 0)))
