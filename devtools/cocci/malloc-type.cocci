//
// The allocation name field in malloc routines was never
// implemented and should be NULL
//
@@
expression T != NULL;
expression num, socket, size, align;
@@
(
- rte_malloc(T, size, align)
+ rte_malloc(NULL, size, align)
|
- rte_zmalloc(T, size, align)
+ rte_zmalloc(NULL,  size, align)
|
- rte_calloc(T, num, size, align)
+ rte_calloc(NULL, num, size, align)
|
- rte_malloc_socket(T, size, align, socket)
+ rte_malloc_socket(NULL, size, align, socket)
|
- rte_zmalloc_socket(T, size, align, socket)
+ rte_zmalloc_socket(NULL, size, align, socket)
|
- rte_calloc_socket(T, num, size, align, socket)
+ rte_calloc_socket(NULL, num, size, align, socket)
)
