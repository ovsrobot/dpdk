//
// rte_memcpy should not be used for simple fixed size structure
// because compiler's are smart enough to inline these.
//
@@
expression src, dst, E;
constant size;
@@
(
- rte_memcpy(dst, src, sizeof(E))
+ memcpy(dst, src, sizeof(E))
|
- rte_memcpy(dst, src, size)
+ memcpy(dst, src, size)
)
