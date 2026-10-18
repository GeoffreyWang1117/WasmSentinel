;; Flags every event with level 9.
(module
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "alloc") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $size)))
    (drop (memory.grow (i32.const 2)))
    (local.get $ptr))
  (func (export "dealloc") (param i32 i32))
  (func (export "detect") (param i32 i32) (result i32) (i32.const 9)))
