/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Ericsson AB
 */

#ifndef _RTE_FASTMEM_H_
#define _RTE_FASTMEM_H_

/**
 * @file
 *
 * RTE Fastmem
 *
 * @warning
 * @b EXPERIMENTAL:
 * All functions in this file may be changed or removed without prior notice.
 *
 * The fastmem library is a fast, general-purpose small-object
 * allocator for DPDK applications. It is intended to allow an
 * application to replace its many per-type mempools — each sized
 * for a single object type (a connection, a session, a work item,
 * a timer, etc.) — with a single allocator that handles arbitrary
 * object sizes, grows on demand, and offers mempool-level
 * performance for the common allocation and free paths.
 *
 * Like mempool, fastmem is backed by huge pages, is NUMA-aware,
 * supports bulk operations, and uses per-lcore caches to reduce
 * shared-state contention. Unlike mempool, it does not require the
 * caller to declare object sizes or counts up front.
 *
 * There is a single, global fastmem instance per process. The
 * instance is brought up with rte_fastmem_init() and torn down with
 * rte_fastmem_deinit(). Allocations are made with
 * rte_fastmem_alloc() and freed with rte_fastmem_free().
 *
 * The allocator is bounded to small-object allocations. Requests
 * larger than rte_fastmem_max_size() are rejected; callers with
 * such needs should use rte_malloc() directly.
 *
 * Backing memory is reserved from DPDK memzones. Once reserved,
 * backing memory is not returned to the system during the
 * allocator's lifetime. Callers that need predictable latency may
 * pre-reserve backing memory up front using rte_fastmem_reserve(),
 * avoiding memzone-reservation overhead during steady-state
 * operation.
 *
 * Alignment argument, @c align:
 *   If non-zero, @c align specifies an exact minimum alignment and
 *   must be a power of 2. If zero, the default alignment is
 *   @c RTE_CACHE_LINE_SIZE, so that objects obtained from distinct
 *   calls cannot false-share a cache line.
 *
 * Threads and per-lcore caches:
 *   Allocate and free calls from EAL threads are served through a
 *   per-lcore cache, which makes the common path lock-free.
 *   Unregistered non-EAL threads do not use a cache; their
 *   allocate and free calls go directly to shared state, take an
 *   internal lock, and cost more per call.
 *
 * Non-preemptible caller:
 *   Callers should not be preemptible while inside a fastmem call.
 *   Fastmem uses internal spinlocks; if a caller is preempted
 *   while holding one, any other thread that subsequently needs
 *   the same lock stalls until the preempted caller resumes.
 */

#include <stddef.h>
#include <stdint.h>

#include <rte_bitops.h>
#include <rte_common.h>
#include <rte_compat.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Flag for rte_fastmem_alloc() and its variants: initialize the
 * returned memory to zero before returning it to the caller.
 */
#define RTE_FASTMEM_F_ZERO RTE_BIT32(0)

/**
 * Initialize the fastmem allocator.
 *
 * Sets up the library's internal state. Must be called before any
 * allocation call. Typically called once per process, after
 * rte_eal_init() and before the application's worker threads begin
 * making allocations.
 *
 * Initialization does not pre-reserve any backing memory; memzones
 * are reserved lazily as allocations require. An application that
 * wants to avoid memzone-reservation latency on the allocation
 * path should follow rte_fastmem_init() with one or more calls to
 * rte_fastmem_reserve().
 *
 * This function is not thread-safe and must not be called
 * concurrently with any other fastmem function.
 *
 * @return
 *  - 0: Success.
 *  - -EBUSY: The allocator is already initialized.
 *  - -ENOMEM: Unable to allocate internal state.
 */
__rte_experimental
int
rte_fastmem_init(void);

/**
 * Tear down the fastmem allocator.
 *
 * Releases the library's internal state and frees all backing
 * memzones. After this call, no fastmem allocations or frees may
 * be made until rte_fastmem_init() is called again.
 *
 * The caller is responsible for ensuring that no fastmem-allocated
 * objects remain in use. Outstanding allocations at deinit time
 * result in undefined behavior.
 *
 * This function is not thread-safe and must not be called
 * concurrently with any other fastmem function.
 */
__rte_experimental
void
rte_fastmem_deinit(void);

/**
 * Pre-reserve backing memory.
 *
 * Ensures that at least @p size bytes of memzone-backed memory are
 * available to the allocator on @p socket_id, reserving additional
 * memzones from EAL as needed to reach that total. Subsequent
 * allocations served from the pre-reserved memory do not incur
 * memzone-reservation cost.
 *
 * The reservation is cumulative: repeated calls to
 * rte_fastmem_reserve() with the same @p socket_id grow the
 * reservation monotonically. Reserved memory is never returned to
 * the system during the allocator's lifetime.
 *
 * A typical use is to call rte_fastmem_reserve() once at
 * application startup, with a size chosen to cover the expected
 * steady-state working set. Allocations and frees during
 * steady-state operation then avoid memzone reservations entirely.
 *
 * @param size
 *  The minimum amount of backing memory, in bytes, to make
 *  available on @p socket_id. The allocator may reserve more than
 *  the requested amount due to internal rounding (e.g., to memzone
 *  or block granularity).
 *
 * @param socket_id
 *  The NUMA socket on which to reserve memory, or SOCKET_ID_ANY
 *  to leave the choice to the allocator. With SOCKET_ID_ANY, the
 *  allocator starts on the calling lcore's socket (or the first
 *  configured socket if the caller is not bound to one) and falls
 *  back to other sockets if the preferred socket cannot satisfy
 *  the reservation.
 *
 * @return
 *  - 0: Success.
 *  - -ENOMEM: Insufficient huge-page memory to satisfy the request.
 *  - -EINVAL: Invalid @p socket_id.
 */
__rte_experimental
int
rte_fastmem_reserve(size_t size, int socket_id);

/**
 * Set the maximum backing memory that may be reserved on a socket.
 *
 * Once the limit is reached, allocations that would require new
 * backing memory on the constrained socket fail with ENOMEM.
 * Already-reserved memory is not released.
 *
 * Setting a limit below the current reserved amount is allowed and
 * prevents further growth.
 *
 * @param socket_id
 *  The NUMA socket to constrain, or SOCKET_ID_ANY to apply the
 *  limit to all sockets.
 * @param max_bytes
 *  Maximum backing memory in bytes, or SIZE_MAX for unlimited (the default).
 * @return
 *  - 0: Success.
 *  - -EINVAL: Fastmem not initialized, or invalid @p socket_id.
 */
__rte_experimental
int
rte_fastmem_set_limit(int socket_id, size_t max_bytes);

/**
 * Get the maximum backing memory limit for a socket.
 *
 * @param socket_id
 *  The NUMA socket to query.
 * @return
 *  The limit in bytes, or SIZE_MAX if unlimited.
 */
__rte_experimental
size_t
rte_fastmem_get_limit(int socket_id);

/**
 * Retrieve the largest allocation size the allocator supports.
 *
 * Requests larger than this size are rejected by the allocation
 * functions. The returned value is a property of the allocator
 * implementation and does not change across the lifetime of the
 * process.
 *
 * @return
 *  The largest supported allocation size, in bytes.
 */
__rte_experimental
size_t
rte_fastmem_max_size(void);

/**
 * Allocate an object from the fastmem allocator.
 *
 * Allocates at least @p size bytes, aligned to at least @p align
 * bytes. The returned memory is backed by huge pages and is
 * DMA-usable; its IOVA can be obtained via rte_fastmem_virt2iova().
 *
 * On NUMA systems, the memory is allocated on the socket of the
 * calling lcore. Use rte_fastmem_alloc_socket() to target a
 * specific socket.
 *
 * The allocated memory must be freed with rte_fastmem_free(). An
 * allocation may be freed from any lcore, not only the lcore that
 * made the allocation.
 *
 * This function is MT-safe.
 *
 * @param size
 *  Requested allocation size, in bytes. Must not exceed
 *  rte_fastmem_max_size().
 *
 * @param align
 *  If 0, the returned pointer will be aligned to at least
 *  @c RTE_CACHE_LINE_SIZE. Otherwise, the returned pointer will
 *  be aligned on a multiple of @p align, which must be a power of
 *  2.
 *
 * @param flags
 *  A bitwise OR of zero or more RTE_FASTMEM_F_* flags. Use
 *  RTE_FASTMEM_F_ZERO to obtain zero-initialized memory.
 *
 * @return
 *  - A pointer to the allocated object on success.
 *  - NULL on failure, with @c rte_errno set:
 *    - E2BIG: @p size exceeds rte_fastmem_max_size().
 *    - EINVAL: Invalid @p align (not a power of two).
 *    - ENOMEM: Allocation could not be served from existing
 *      backing memory and no additional memzone could be reserved.
 */
__rte_experimental
void *
rte_fastmem_alloc(size_t size, size_t align, unsigned int flags)
	__rte_alloc_size(1) __rte_alloc_align(2);

/**
 * Allocate an object on a specific NUMA socket.
 *
 * Like rte_fastmem_alloc(), but targets the specified NUMA socket
 * rather than the socket of the calling lcore. Use this variant
 * when the lifetime or access pattern of the allocation is not
 * tied to the calling lcore's socket.
 *
 * This function is MT-safe.
 *
 * @param size
 *  Requested allocation size, in bytes. Must not exceed
 *  rte_fastmem_max_size().
 *
 * @param align
 *  If 0, the returned pointer will be aligned to at least
 *  @c RTE_CACHE_LINE_SIZE. Otherwise, the returned pointer will
 *  be aligned on a multiple of @p align, which must be a power of
 *  2.
 *
 * @param flags
 *  A bitwise OR of zero or more RTE_FASTMEM_F_* flags.
 *
 * @param socket_id
 *  The NUMA socket on which to allocate, or SOCKET_ID_ANY to
 *  leave the choice to the allocator. With SOCKET_ID_ANY, the
 *  allocator starts on the calling lcore's socket (or the first
 *  configured socket if the caller is not bound to one) and falls
 *  back to other sockets if the preferred socket cannot satisfy
 *  the request.
 *
 * @return
 *  - A pointer to the allocated object on success.
 *  - NULL on failure, with @c rte_errno set (see rte_fastmem_alloc()).
 */
__rte_experimental
void *
rte_fastmem_alloc_socket(size_t size, size_t align, unsigned int flags,
		int socket_id)
	__rte_alloc_size(1) __rte_alloc_align(2);

/**
 * Free an object previously allocated by the fastmem allocator.
 *
 * @p ptr must have been returned by a prior call to any fastmem
 * allocation function, or be NULL. If @p ptr is NULL, no operation
 * is performed.
 *
 * Free may be called from any lcore, regardless of which lcore
 * made the original allocation.
 *
 * This function is MT-safe.
 *
 * @param ptr
 *  Pointer to an object previously allocated by fastmem, or NULL.
 */
__rte_experimental
void
rte_fastmem_free(void *ptr);

/**
 * Allocate multiple objects in bulk.
 *
 * Allocates @p n objects, each of size at least @p size and aligned
 * to at least @p align bytes, and stores the resulting pointers
 * into @p ptrs. All @p n objects have the same size and alignment.
 *
 * On NUMA systems, the memory is allocated on the socket of the
 * calling lcore. Use rte_fastmem_alloc_bulk_socket() to target a
 * specific socket.
 *
 * The bulk path amortizes per-object overhead and is typically
 * faster than @p n individual calls to rte_fastmem_alloc().
 *
 * On failure no objects are allocated and @p ptrs is left
 * untouched.
 *
 * This function is MT-safe.
 *
 * @param ptrs
 *  An array of at least @p n pointers into which the newly
 *  allocated object pointers are written.
 *
 * @param n
 *  The number of objects to allocate.
 *
 * @param size
 *  Requested size of each object, in bytes. Must not exceed
 *  rte_fastmem_max_size().
 *
 * @param align
 *  If 0, returned pointers will be aligned to at least
 *  @c RTE_CACHE_LINE_SIZE. Otherwise, returned pointers will be
 *  aligned on a multiple of @p align, which must be a power of 2.
 *
 * @param flags
 *  A bitwise OR of zero or more RTE_FASTMEM_F_* flags.
 *
 * @return
 *  - 0: All @p n objects were allocated and stored in @p ptrs.
 *  - -E2BIG: @p size exceeds rte_fastmem_max_size().
 *  - -EINVAL: Invalid @p align.
 *  - -ENOMEM: Not enough objects could be allocated to fill the
 *    request.
 */
__rte_experimental
int
rte_fastmem_alloc_bulk(void **ptrs, unsigned int n, size_t size, size_t align,
		unsigned int flags);

/**
 * Allocate multiple objects in bulk on a specific NUMA socket.
 *
 * Like rte_fastmem_alloc_bulk(), but targets the specified NUMA
 * socket rather than the socket of the calling lcore.
 *
 * This function is MT-safe.
 *
 * @param ptrs
 *  An array of at least @p n pointers into which the newly
 *  allocated object pointers are written.
 *
 * @param n
 *  The number of objects to allocate.
 *
 * @param size
 *  Requested size of each object, in bytes. Must not exceed
 *  rte_fastmem_max_size().
 *
 * @param align
 *  If 0, returned pointers will be aligned to at least
 *  @c RTE_CACHE_LINE_SIZE. Otherwise, returned pointers will be
 *  aligned on a multiple of @p align, which must be a power of 2.
 *
 * @param flags
 *  A bitwise OR of zero or more RTE_FASTMEM_F_* flags.
 *
 * @param socket_id
 *  The NUMA socket on which to allocate, or SOCKET_ID_ANY to
 *  leave the choice to the allocator. With SOCKET_ID_ANY, the
 *  allocator starts on the calling lcore's socket (or the first
 *  configured socket if the caller is not bound to one) and falls
 *  back to other sockets if the preferred socket cannot satisfy
 *  the request.
 *
 * @return
 *  - 0: All @p n objects were allocated and stored in @p ptrs.
 *  - Negative errno on failure (see rte_fastmem_alloc_bulk()).
 */
__rte_experimental
int
rte_fastmem_alloc_bulk_socket(void **ptrs, unsigned int n, size_t size,
		size_t align, unsigned int flags, int socket_id);

/**
 * Free multiple objects in bulk.
 *
 * Frees the @p n objects pointed to by @p ptrs. Each pointer in
 * the array must have been returned by a prior fastmem allocation
 * call and must not have been freed. The objects need not have
 * the same size, alignment, or socket.
 *
 * The bulk path amortizes per-object overhead and is typically
 * faster than @p n individual calls to rte_fastmem_free().
 *
 * This function is MT-safe.
 *
 * @param ptrs
 *  An array of @p n pointers to fastmem-allocated objects.
 *
 * @param n
 *  The number of objects to free.
 */
__rte_experimental
void
rte_fastmem_free_bulk(void **ptrs, unsigned int n);

/**
 * Opaque handle encoding a (size class, NUMA socket) pair.
 *
 * Obtained via rte_fastmem_hlookup(). Passing a handle to
 * rte_fastmem_halloc() avoids the per-call size-class
 * lookup and socket resolution, improving allocation throughput
 * for fixed-size objects.
 */
typedef uint32_t rte_fastmem_handle_t;

/**
 * Look up a handle for a given object size and NUMA socket.
 *
 * The returned handle encodes the size class and socket, and can
 * be passed to rte_fastmem_halloc() to allocate objects
 * without repeating the class lookup.
 *
 * @param size
 *  Object size in bytes. Must not exceed rte_fastmem_max_size().
 *
 * @param align
 *  Alignment requirement (power of two), or 0 for the default
 *  (RTE_CACHE_LINE_SIZE).
 *
 * @param socket_id
 *  NUMA socket to allocate from.
 *
 * @param[out] handle
 *  On success, set to the resolved handle.
 *
 * @return
 *  - 0: Success.
 *  - -EINVAL: Invalid alignment or socket_id.
 *  - -E2BIG: @p size exceeds rte_fastmem_max_size().
 */
__rte_experimental
int
rte_fastmem_hlookup(size_t size, size_t align, int socket_id,
		rte_fastmem_handle_t *handle);

/**
 * Allocate an object using a pre-resolved handle.
 *
 * Equivalent to rte_fastmem_alloc() but skips the size-class
 * lookup and socket resolution, using the pre-resolved handle
 * instead.
 *
 * @param handle
 *  A handle previously obtained from rte_fastmem_hlookup().
 *
 * @param flags
 *  Allocation flags (e.g., RTE_FASTMEM_F_ZERO).
 *
 * @return
 *  A pointer to the allocated object, or NULL on failure
 *  (rte_errno is set).
 */
__rte_experimental
void *
rte_fastmem_halloc(rte_fastmem_handle_t handle, unsigned int flags);

/**
 * Bulk-allocate objects using a pre-resolved handle.
 *
 * Equivalent to rte_fastmem_alloc_bulk() but uses a pre-resolved
 * handle. All-or-nothing semantics apply.
 *
 * @param handle
 *  A handle previously obtained from rte_fastmem_hlookup().
 *
 * @param[out] ptrs
 *  Array to receive @p n allocated pointers.
 *
 * @param n
 *  Number of objects to allocate.
 *
 * @param flags
 *  Allocation flags (e.g., RTE_FASTMEM_F_ZERO).
 *
 * @return
 *  - 0: All @p n objects allocated successfully.
 *  - -ENOMEM: Allocation failed; no objects were allocated.
 */
__rte_experimental
int
rte_fastmem_halloc_bulk(rte_fastmem_handle_t handle,
		void **ptrs, unsigned int n, unsigned int flags);

/**
 * Free an object using a pre-resolved handle.
 *
 * Equivalent to rte_fastmem_free() but skips the slab-header
 * lookup by using the class and socket encoded in the handle.
 *
 * @param handle
 *  A handle previously obtained from rte_fastmem_hlookup().
 *
 * @param ptr
 *  A pointer previously returned by a fastmem allocation function.
 *  Must belong to the same size class and socket as @p handle.
 *  NULL is permitted (no-op).
 */
__rte_experimental
void
rte_fastmem_hfree(rte_fastmem_handle_t handle, void *ptr);

/**
 * Bulk-free objects using a pre-resolved handle.
 *
 * Equivalent to rte_fastmem_free_bulk() but skips per-object
 * slab-header lookups.
 *
 * All objects must belong to the same size class and socket as
 * @p handle.
 *
 * @param handle
 *  A handle previously obtained from rte_fastmem_hlookup().
 *
 * @param ptrs
 *  An array of @p n pointers to fastmem-allocated objects.
 *
 * @param n
 *  The number of objects to free.
 */
__rte_experimental
void
rte_fastmem_hfree_bulk(rte_fastmem_handle_t handle,
		void **ptrs, unsigned int n);

/**
 * Obtain the IOVA for a fastmem-allocated pointer.
 *
 * Translates a virtual address returned by a fastmem allocation
 * function into the corresponding IOVA, suitable for use in device
 * DMA descriptors.
 *
 * The returned IOVA is valid for the lifetime of the allocation.
 *
 * @p ptr must have been returned by a prior fastmem allocation
 * function. Passing any other pointer results in undefined
 * behavior.
 *
 * @param ptr
 *  A pointer previously returned by a fastmem allocation
 *  function.
 *
 * @return
 *  The IOVA corresponding to @p ptr.
 */
__rte_experimental
rte_iova_t
rte_fastmem_virt2iova(const void *ptr);

/**
 * Flush the calling lcore's per-lcore caches.
 *
 * Drains every cached object from the calling lcore's
 * per-(size class, NUMA socket) caches back to their shared
 * bins, and releases the cache state itself. A subsequent
 * allocation or free on this lcore lazily recreates any caches
 * it needs.
 *
 * This is useful in applications that have finished a bursty
 * phase and want to release memory that would otherwise sit idle
 * in caches. It is also useful in tests that want to observe
 * bin-level state without per-lcore caching hiding activity.
 *
 * The call has no effect when invoked from a non-EAL thread.
 *
 * This function is not thread-safe with respect to concurrent
 * allocations or frees on the calling lcore; call it only when
 * the calling lcore is not making other fastmem calls.
 */
__rte_experimental
void
rte_fastmem_cache_flush(void);

/**
 * Global summary statistics.
 */
struct rte_fastmem_stats {
	uint64_t bytes_backing;  /**< Bytes of backing memory (memzones) reserved from EAL. */
	uint64_t bytes_in_use;   /**< Approximate bytes in live objects. */
	uint64_t alloc_total;    /**< Total successful alloc operations (hits + misses). */
	uint64_t free_total;     /**< Total free operations (hits + misses). */
	uint64_t alloc_nomem;    /**< Alloc attempts that failed with ENOMEM. */
	unsigned int n_classes;  /**< Number of size classes. */
};

/**
 * Per-size-class statistics (aggregated across all lcores).
 *
 * Allocation and free counters count individual objects, not
 * operations. A bulk allocation of 32 objects that hits the cache
 * increments alloc_cache_hits by 32.
 */
struct rte_fastmem_class_stats {
	size_t class_size;             /**< Usable size of this class (bytes). */
	uint64_t in_use;               /**< Objects currently live (allocs - frees). */
	uint64_t alloc_cache_hits;     /**< Allocs served from a per-lcore cache. */
	uint64_t alloc_cache_misses;   /**< Allocs that triggered a bin refill. */
	uint64_t alloc_nomem;          /**< Alloc attempts that failed with ENOMEM. */
	uint64_t free_cache_hits;      /**< Frees absorbed by a per-lcore cache. */
	uint64_t free_cache_misses;    /**< Frees that triggered a bin drain. */
	uint64_t slab_acquires;        /**< Slabs pulled from the free pool. */
	uint64_t slab_releases;        /**< Slabs returned to the free pool. */
	uint32_t slabs_partial;        /**< Current partial slab count. */
	uint32_t slabs_full;           /**< Current full slab count. */
};

/**
 * Per-lcore statistics (aggregated across all classes).
 */
struct rte_fastmem_lcore_stats {
	uint64_t alloc_cache_hits;     /**< Allocs served from this lcore's caches. */
	uint64_t alloc_cache_misses;   /**< Allocs that missed this lcore's caches. */
	uint64_t alloc_nomem;          /**< Alloc attempts that failed with ENOMEM. */
	uint64_t free_cache_hits;      /**< Frees absorbed by this lcore's caches. */
	uint64_t free_cache_misses;    /**< Frees that bypassed this lcore's caches. */
};

/**
 * Per-lcore, per-class statistics (no aggregation).
 */
struct rte_fastmem_lcore_class_stats {
	size_t class_size;             /**< Usable size of this class (bytes). */
	uint64_t alloc_cache_hits;     /**< Allocs served from cache. */
	uint64_t alloc_cache_misses;   /**< Allocs that triggered a bin refill. */
	uint64_t alloc_nomem;          /**< Alloc attempts that failed with ENOMEM. */
	uint64_t free_cache_hits;      /**< Frees absorbed by cache. */
	uint64_t free_cache_misses;    /**< Frees that triggered a bin drain. */
};

/**
 * Get the number of size classes and optionally their sizes.
 *
 * @param[out] sizes
 *   If non-NULL, filled with the size (in bytes) of each class.
 *   The caller must provide space for at least the returned number
 *   of entries.
 *
 * @return
 *   The number of size classes.
 */
__rte_experimental
unsigned int
rte_fastmem_classes(size_t *sizes);

/**
 * Retrieve global summary statistics.
 *
 * @param[out] stats
 *   Structure to fill.
 *
 * @return
 *  - 0: Success.
 *  - -EINVAL: @p stats is NULL or fastmem is not initialized.
 */
__rte_experimental
int
rte_fastmem_stats(struct rte_fastmem_stats *stats);

/**
 * Retrieve statistics for a single size class.
 *
 * @param class_size
 *   Exact size of the class to query (must match one of the values
 *   returned by rte_fastmem_classes()).
 * @param[out] stats
 *   Structure to fill.
 *
 * @return
 *  - 0: Success.
 *  - -EINVAL: @p stats is NULL, fastmem is not initialized, or
 *    @p class_size does not match any size class.
 */
__rte_experimental
int
rte_fastmem_stats_class(size_t class_size,
		struct rte_fastmem_class_stats *stats);

/**
 * Retrieve per-lcore statistics (aggregated across all classes).
 *
 * @param lcore_id
 *   The lcore to query.
 * @param[out] stats
 *   Structure to fill.
 *
 * @return
 *  - 0: Success.
 *  - -EINVAL: @p stats is NULL, fastmem is not initialized, or
 *    @p lcore_id is invalid.
 */
__rte_experimental
int
rte_fastmem_stats_lcore(unsigned int lcore_id,
		struct rte_fastmem_lcore_stats *stats);

/**
 * Retrieve per-lcore, per-class statistics.
 *
 * @param lcore_id
 *   The lcore to query.
 * @param class_size
 *   Exact size of the class to query.
 * @param[out] stats
 *   Structure to fill.
 *
 * @return
 *  - 0: Success.
 *  - -EINVAL: @p stats is NULL, fastmem is not initialized,
 *    @p lcore_id is invalid, or @p class_size does not match any
 *    size class.
 */
__rte_experimental
int
rte_fastmem_stats_lcore_class(unsigned int lcore_id, size_t class_size,
		struct rte_fastmem_lcore_class_stats *stats);

/**
 * Reset all statistics counters to zero.
 *
 * Zeroes per-lcore cache counters and per-bin counters. Does not
 * affect the allocator's operational state.
 */
__rte_experimental
void
rte_fastmem_stats_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_FASTMEM_H_ */
