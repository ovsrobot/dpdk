//
// Replace simple loops freeing mbufs one-by-one with rte_pktmbuf_free_bulk().
//
// rte_pktmbuf_free_bulk() handles NULL entries internally, so per-element
// NULL guards are folded in as well.  Loops whose body does more than the
// free (clearing the slot, bookkeeping, etc.) are not matched.
//
@@
expression A, N;
identifier i;
@@

(
- for (i = 0; i < N; i++)
-     rte_pktmbuf_free(A[i]);
+ rte_pktmbuf_free_bulk(A, N);
|
- for (i = 0; i < N; ++i)
-     rte_pktmbuf_free(A[i]);
+ rte_pktmbuf_free_bulk(A, N);
|
- for (i = 0; i < N; i++)
-     if (A[i] != NULL)
-         rte_pktmbuf_free(A[i]);
+ rte_pktmbuf_free_bulk(A, N);
|
- for (i = 0; i < N; i++)
-     if (A[i])
-         rte_pktmbuf_free(A[i]);
+ rte_pktmbuf_free_bulk(A, N);
)

@@
expression A, N;
identifier i;
type T;
@@

(
- for (T i = 0; i < N; i++)
-     rte_pktmbuf_free(A[i]);
+ rte_pktmbuf_free_bulk(A, N);
|
- for (T i = 0; i < N; ++i)
-     rte_pktmbuf_free(A[i]);
+ rte_pktmbuf_free_bulk(A, N);
|
- for (T i = 0; i < N; i++)
-     if (A[i] != NULL)
-         rte_pktmbuf_free(A[i]);
+ rte_pktmbuf_free_bulk(A, N);
|
- for (T i = 0; i < N; i++)
-     if (A[i])
-         rte_pktmbuf_free(A[i]);
+ rte_pktmbuf_free_bulk(A, N);
)
