/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#ifndef _RTE_LCORE_VAR_H_
#define _RTE_LCORE_VAR_H_

/**
 * @file
 *
 * RTE Lcore variables
 *
 * This API provides a mechanism to create and access per-lcore id
 * variables in a space- and cycle-efficient manner.
 *
 * A per-lcore id variable (or lcore variable for short) has one value
 * for each EAL thread and registered non-EAL thread. There is one
 * instance for each current and future lcore id-equipped thread, with
 * a total of RTE_MAX_LCORE instances. The value of an lcore variable
 * for a particular lcore id is independent from other values (for
 * other lcore ids) within the same lcore variable.
 *
 * In order to access the values of an lcore variable, a handle is
 * used. The type of the handle is a pointer to the value's type
 * (e.g., for an @c uint32_t lcore variable, the handle is a
 * <code>uint32_t *</code>. The handle type is used to inform the
 * access macros the type of the values. A handle may be passed
 * between modules and threads just like any pointer, but its value
 * must be treated as a an opaque identifier. An allocated handle
 * never has the value NULL.
 *
 * @b Creation
 *
 * An lcore variable is created in two steps:
 *  1. Define an lcore variable handle by using @ref RTE_LCORE_VAR_HANDLE.
 *  2. Allocate lcore variable storage and initialize the handle with
 *     a unique identifier by @ref RTE_LCORE_VAR_ALLOC or
 *     @ref RTE_LCORE_VAR_INIT. Allocation generally occurs the time of
 *     module initialization, but may be done at any time.
 *
 * An lcore variable is not tied to the owning thread's lifetime. It's
 * available for use by any thread immediately after having been
 * allocated, and continues to be available throughout the lifetime of
 * the EAL.
 *
 * Lcore variables cannot and need not be freed.
 *
 * @b Access
 *
 * The value of any lcore variable for any lcore id may be accessed
 * from any thread (including unregistered threads), but it should
 * only be *frequently* read from or written to by the owner.
 *
 * Values of the same lcore variable but owned by two different lcore
 * ids may be frequently read or written by the owners without risking
 * false sharing.
 *
 * An appropriate synchronization mechanism (e.g., atomic loads and
 * stores) should employed to assure there are no data races between
 * the owning thread and any non-owner threads accessing the same
 * lcore variable instance.
 *
 * The value of the lcore variable for a particular lcore id is
 * accessed using @ref RTE_LCORE_VAR_LCORE_VALUE.
 *
 * A common pattern is for an EAL thread or a registered non-EAL
 * thread to access its own lcore variable value. For this purpose, a
 * short-hand exists in the form of @ref RTE_LCORE_VAR_VALUE.
 *
 * Although the handle (as defined by @ref RTE_LCORE_VAR_HANDLE) is a
 * pointer with the same type as the value, it may not be directly
 * dereferenced and must be treated as an opaque identifier.
 *
 * Lcore variable handles and value pointers may be freely passed
 * between different threads.
 *
 * @b Storage
 *
 * An lcore variable's values may by of a primitive type like @c int,
 * but would more typically be a @c struct.
 *
 * The lcore variable handle introduces a per-variable (not
 * per-value/per-lcore id) overhead of @c sizeof(void *) bytes, so
 * there are some memory footprint gains to be made by organizing all
 * per-lcore id data for a particular module as one lcore variable
 * (e.g., as a struct).
 *
 * An application may choose to define an lcore variable handle, which
 * it then it goes on to never allocate.
 *
 * The size of an lcore variable's value must be less than the DPDK
 * build-time constant @c RTE_MAX_LCORE_VAR.
 *
 * The lcore variable are stored in a series of lcore buffers, which
 * are allocated from the libc heap. Heap allocation failures are
 * treated as fatal.
 *
 * Lcore variables should generally *not* be @ref __rte_cache_aligned
 * and need *not* include a @ref RTE_CACHE_GUARD field, since the use
 * of these constructs are designed to avoid false sharing. In the
 * case of an lcore variable instance, the thread most recently
 * accessing nearby data structures should almost-always be the lcore
 * variables' owner. Adding padding will increase the effective memory
 * working set size, potentially reducing performance.
 *
 * Lcore variable values take on an initial value of zero.
 *
 * @b Example
 *
 * Below is an example of the use of an lcore variable:
 *
 * @code{.c}
 * struct foo_lcore_state {
 *         int a;
 *         long b;
 * };
 *
 * static RTE_LCORE_VAR_HANDLE(struct foo_lcore_state, lcore_states);
 *
 * long foo_get_a_plus_b(void)
 * {
 *         struct foo_lcore_state *state = RTE_LCORE_VAR_VALUE(lcore_states);
 *
 *         return state->a + state->b;
 * }
 *
 * RTE_INIT(rte_foo_init)
 * {
 *         RTE_LCORE_VAR_ALLOC(lcore_states);
 *
 *         unsigned int lcore_id;
 *         struct foo_lcore_state *state;
 *         RTE_LCORE_VAR_FOREACH_VALUE(lcore_id, state, lcore_states) {
 *                 (initialize 'state')
 *         }
 *
 *         (other initialization)
 * }
 * @endcode
 *
 *
 * @b Alternatives
 *
 * Lcore variables are designed to replace a pattern exemplified below:
 * @code{.c}
 * struct __rte_cache_aligned foo_lcore_state {
 *         int a;
 *         long b;
 *         RTE_CACHE_GUARD;
 * };
 *
 * static struct foo_lcore_state lcore_states[RTE_MAX_LCORE];
 * @endcode
 *
 * This scheme is simple and effective, but has one drawback: the data
 * is organized so that objects related to all lcores for a particular
 * module is kept close in memory. At a bare minimum, this requires
 * sizing data structures (e.g., using `__rte_cache_aligned`) to an
 * even number of cache lines to avoid false sharing. With CPU
 * hardware prefetching and memory loads resulting from speculative
 * execution (functions which seemingly are getting more eager faster
 * than they are getting more intelligent), one or more "guard" cache
 * lines may be required to separate one lcore's data from another's.
 *
 * Lcore variables have the upside of working with, not against, the
 * CPU's assumptions and for example next-line prefetchers may well
 * work the way its designers intended (i.e., to the benefit, not
 * detriment, of system performance).
 *
 * Another alternative to @ref rte_lcore_var.h is the @ref
 * rte_per_lcore.h API, which makes use of thread-local storage (TLS,
 * e.g., GCC __thread or C11 _Thread_local). The main differences
 * between by using the various forms of TLS (e.g., @ref
 * RTE_DEFINE_PER_LCORE or _Thread_local) and the use of lcore
 * variables are:
 *
 *   * The existence and non-existence of a thread-local variable
 *     instance follow that of particular thread's. The data cannot be
 *     accessed before the thread has been created, nor after it has
 *     exited. As a result, thread-local variables must be initialized in
 *     a "lazy" manner (e.g., at the point of thread creation). Lcore
 *     variables may be accessed immediately after having been
 *     allocated (which may be prior any thread beyond the main
 *     thread is running).
 *   * A thread-local variable is duplicated across all threads in the
 *     process, including unregistered non-EAL threads (i.e.,
 *     "regular" threads). For DPDK applications heavily relying on
 *     multi-threading (in conjunction to DPDK's "one thread per core"
 *     pattern), either by having many concurrent threads or
 *     creating/destroying threads at a high rate, an excessive use of
 *     thread-local variables may cause inefficiencies (e.g.,
 *     increased thread creation overhead due to thread-local storage
 *     initialization or increased total RAM footprint usage). Lcore
 *     variables *only* exist for threads with an lcore id.
 *   * If data in thread-local storage may be shared between threads
 *     (i.e., can a pointer to a thread-local variable be passed to
 *     and successfully dereferenced by non-owning thread) depends on
 *     the details of the TLS implementation. With GCC __thread and
 *     GCC _Thread_local, such data sharing is supported. In the C11
 *     standard, the result of accessing another thread's
 *     _Thread_local object is implementation-defined. Lcore variable
 *     instances may be accessed reliably by any thread.
 */

#include <stddef.h>
#include <stdalign.h>

#include <rte_common.h>
#include <rte_config.h>
#include <rte_lcore.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Given the lcore variable type, produces the type of the lcore
 * variable handle.
 */
#define RTE_LCORE_VAR_HANDLE_TYPE(type)		\
	type *

/**
 * Define an lcore variable handle.
 *
 * This macro defines a variable which is used as a handle to access
 * the various instances of a per-lcore id variable.
 *
 * The aim with this macro is to make clear at the point of
 * declaration that this is an lcore handle, rather than a regular
 * pointer.
 *
 * Add @b static as a prefix in case the lcore variable is only to be
 * accessed from a particular translation unit.
 */
#define RTE_LCORE_VAR_HANDLE(type, name)	\
	RTE_LCORE_VAR_HANDLE_TYPE(type) name

/**
 * Allocate space for an lcore variable, and initialize its handle.
 *
 * The values of the lcore variable are initialized to zero.
 */
#define RTE_LCORE_VAR_ALLOC_SIZE_ALIGN(handle, size, align)	\
	handle = rte_lcore_var_alloc(size, align)

/**
 * Allocate space for an lcore variable, and initialize its handle,
 * with values aligned for any type of object.
 *
 * The values of the lcore variable are initialized to zero.
 */
#define RTE_LCORE_VAR_ALLOC_SIZE(handle, size)	\
	RTE_LCORE_VAR_ALLOC_SIZE_ALIGN(handle, size, 0)

/**
 * Allocate space for an lcore variable of the size and alignment requirements
 * suggested by the handle pointer type, and initialize its handle.
 *
 * The values of the lcore variable are initialized to zero.
 */
#define RTE_LCORE_VAR_ALLOC(handle)					\
	RTE_LCORE_VAR_ALLOC_SIZE_ALIGN(handle, sizeof(*(handle)),	\
				       alignof(typeof(*(handle))))

/**
 * Allocate an explicitly-sized, explicitly-aligned lcore variable by
 * means of a @ref RTE_INIT constructor.
 *
 * The values of the lcore variable are initialized to zero.
 */
#define RTE_LCORE_VAR_INIT_SIZE_ALIGN(name, size, align)		\
	RTE_INIT(rte_lcore_var_init_ ## name)				\
	{								\
		RTE_LCORE_VAR_ALLOC_SIZE_ALIGN(name, size, align);	\
	}

/**
 * Allocate an explicitly-sized lcore variable by means of a @ref
 * RTE_INIT constructor.
 *
 * The values of the lcore variable are initialized to zero.
 */
#define RTE_LCORE_VAR_INIT_SIZE(name, size)		\
	RTE_LCORE_VAR_INIT_SIZE_ALIGN(name, size, 0)

/**
 * Allocate an lcore variable by means of a @ref RTE_INIT constructor.
 *
 * The values of the lcore variable are initialized to zero.
 */
#define RTE_LCORE_VAR_INIT(name)					\
	RTE_INIT(rte_lcore_var_init_ ## name)				\
	{								\
		RTE_LCORE_VAR_ALLOC(name);				\
	}

/**
 * Get void pointer to lcore variable instance with the specified
 * lcore id.
 *
 * @param lcore_id
 *   The lcore id specifying which of the @c RTE_MAX_LCORE value
 *   instances should be accessed. The lcore id need not be valid
 *   (e.g., may be @ref LCORE_ID_ANY), but in such a case, the pointer
 *   is also not valid (and thus should not be dereferenced).
 * @param handle
 *   The lcore variable handle.
 */
static inline void *
rte_lcore_var_lcore_ptr(unsigned int lcore_id, void *handle)
{
	return RTE_PTR_ADD(handle, lcore_id * RTE_MAX_LCORE_VAR);
}

/**
 * Get pointer to lcore variable instance with the specified lcore id.
 *
 * @param lcore_id
 *   The lcore id specifying which of the @c RTE_MAX_LCORE value
 *   instances should be accessed. The lcore id need not be valid
 *   (e.g., may be @ref LCORE_ID_ANY), but in such a case, the pointer
 *   is also not valid (and thus should not be dereferenced).
 * @param handle
 *   The lcore variable handle.
 */
#define RTE_LCORE_VAR_LCORE_VALUE(lcore_id, handle)			\
	((typeof(handle))rte_lcore_var_lcore_ptr(lcore_id, handle))

/**
 * Get pointer to lcore variable instance of the current thread.
 *
 * May only be used by EAL threads and registered non-EAL threads.
 */
#define RTE_LCORE_VAR_VALUE(handle) \
	RTE_LCORE_VAR_LCORE_VALUE(rte_lcore_id(), handle)

/**
 * Iterate over each lcore id's value for an lcore variable.
 *
 * @param lcore_id
 *   An <code>unsigned int</code> variable successively set to the
 *   lcore id of every valid lcore id (up to @c RTE_MAX_LCORE).
 * @param value
 *   A pointer variable successively set to point to lcore variable
 *   value instance of the current lcore id being processed.
 * @param handle
 *   The lcore variable handle.
 */
#define RTE_LCORE_VAR_FOREACH_VALUE(lcore_id, value, handle)		\
	for ((lcore_id) =						\
		     (((value) = RTE_LCORE_VAR_LCORE_VALUE(0, handle)), 0); \
	     (lcore_id) < RTE_MAX_LCORE;				\
	     (lcore_id)++, (value) = RTE_LCORE_VAR_LCORE_VALUE(lcore_id, \
							       handle))

/**
 * Allocate space in the per-lcore id buffers for an lcore variable.
 *
 * The pointer returned is only an opaque identifer of the variable. To
 * get an actual pointer to a particular instance of the variable use
 * @ref RTE_LCORE_VAR_VALUE or @ref RTE_LCORE_VAR_LCORE_VALUE.
 *
 * The lcore variable values' memory is set to zero.
 *
 * The allocation is always successful, barring a fatal exhaustion of
 * the per-lcore id buffer space.
 *
 * rte_lcore_var_alloc() is not multi-thread safe.
 *
 * @param size
 *   The size (in bytes) of the variable's per-lcore id value. Must be > 0.
 * @param align
 *   If 0, the values will be suitably aligned for any kind of type
 *   (i.e., alignof(max_align_t)). Otherwise, the values will be aligned
 *   on a multiple of *align*, which must be a power of 2 and equal or
 *   less than @c RTE_CACHE_LINE_SIZE.
 * @return
 *   The variable's handle, stored in a void pointer value. The value
 *   is always non-NULL.
 */
__rte_experimental
void *
rte_lcore_var_alloc(size_t size, size_t align);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_LCORE_VAR_H_ */
