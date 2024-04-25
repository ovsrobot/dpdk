//
// Prefer use of calloc over zmalloc when allocating multiple objects
//
@@
expression name, T, num, socket, align;
@@
(
- rte_zmalloc(name, num * sizeof(T), align)
+ rte_calloc(name, num, sizeof(T), align)
|
- rte_zmalloc(name, sizeof(T) * num, align)
+ rte_calloc(name, num, sizeof(T), align)
|
- rte_zmalloc_socket(name, num * sizeof(T), align, socket)
+ rte_calloc_socket(name, num, sizeof(T), align, socket)
|
- rte_zmalloc_socket(name, sizeof(T) * num, align, socket)
+ rte_calloc_socket(name, num, sizeof(T), align, socket)
)
