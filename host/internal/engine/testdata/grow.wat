;; detect grows memory one page at a time until the store limiter refuses, then
;; returns the number of pages it reached.
(module
  (memory (export "memory") 2)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "dealloc") (param i32 i32))
  (func (export "detect") (param i32 i32) (result i32)
    (loop $l
      (br_if $l (i32.ne (memory.grow (i32.const 1)) (i32.const -1))))
    (memory.size)))
