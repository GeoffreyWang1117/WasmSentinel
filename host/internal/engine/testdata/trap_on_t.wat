;; detect traps (unreachable) when the payload starts with 'T', otherwise returns 1.
(module
  (memory (export "memory") 2)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "dealloc") (param i32 i32))
  (func (export "detect") (param $ptr i32) (param $len i32) (result i32)
    (if (i32.and (i32.gt_u (local.get $len) (i32.const 0))
                 (i32.eq (i32.load8_u (local.get $ptr)) (i32.const 84)))
      (then (unreachable)))
    (i32.const 1)))
