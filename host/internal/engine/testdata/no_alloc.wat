;; Pre-v2 module: exports detect but no allocator. Loading must fail with a clear error.
(module
  (memory (export "memory") 1)
  (func (export "detect") (param i32 i32) (result i32) (i32.const 0)))
