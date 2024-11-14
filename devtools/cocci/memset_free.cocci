// Replace calls to memset before free
@@
expression E, size;
@@
(
- memset(E, 0, size);
- free(E);
+ rte_memset_sensitive(E, 0, size);
+ free(E);
)

// replace to memset before rte_free
@@
expression E, size;
@@
(
- memset(E, 0, size);
- rte_free(E);
+ rte_free_sensitive(E);
)
