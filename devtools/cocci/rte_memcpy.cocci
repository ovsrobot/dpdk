//
// rte_memcpy should not be used for simple fixed size structure
// because compiler's are smart enough to inline these.
//
@@
expression src, dst; constant size;
@@
(
- rte_memcpy(dst, src, size)
+ memcpy(dst, src, size)
)
