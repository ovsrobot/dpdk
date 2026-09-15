/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RTE_RANDOM_H_
#define _RTE_RANDOM_H_

/**
 * @file
 *
 * Random number generation.
 *
 * A fast pseudo-random generator for general use, and access to the
 * random source of the operating system for values which must not be
 * predictable.
 */

#include <stddef.h>
#include <stdint.h>

#include <rte_compat.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Seed the pseudo-random generator.
 *
 * The generator is automatically seeded by the EAL init from the
 * random source provided by the operating system, so there is no need
 * to re-seed it to get unpredictable values. Seeding it explicitly is
 * useful to make a run repeatable.
 *
 * This function is not multi-thread safe in regards to other
 * rte_srand() calls, nor is it in relation to concurrent rte_rand(),
 * rte_rand32(), rte_rand_max() or rte_drand() calls.
 *
 * @param seedval
 *   The value of the seed.
 */
void
rte_srand(uint64_t seedval);

/**
 * Get a pseudo-random value.
 *
 * The generator is not cryptographically secure.
 *
 * rte_rand(), rte_rand32(), rte_rand_max() and rte_drand() are
 * multi-thread safe, with the exception that they may not be called
 * by multiple _unregistered_ non-EAL threads in parallel.
 *
 * @return
 *   A pseudo-random value between 0 and (1<<64)-1.
 */
uint64_t
rte_rand(void);

/**
 * Get a 32 bit pseudo-random value.
 *
 * Prefer this over truncating the result of rte_rand() since not
 * every generator produces equally good values in all bit positions.
 *
 * The generator is not cryptographically secure.
 *
 * This function is multi-thread safe, with the exception that it may
 * not be called by multiple _unregistered_ non-EAL threads in parallel.
 *
 * @return
 *   A pseudo-random value between 0 and (1<<32)-1.
 */
uint32_t
rte_rand32(void);

/**
 * Generates a pseudo-random number with an upper bound.
 *
 * This function returns an uniformly distributed (unbiased) random
 * number less than a user-specified maximum value.
 *
 * rte_rand(), rte_rand32(), rte_rand_max() and rte_drand() are
 * multi-thread safe, with the exception that they may not be called
 * by multiple _unregistered_ non-EAL threads in parallel.
 *
 * @param upper_bound
 *   The upper bound of the generated number.
 * @return
 *   A pseudo-random value between 0 and (upper_bound-1).
 */
uint64_t
rte_rand_max(uint64_t upper_bound);

/**
 * Generates a pseudo-random floating point number.
 *
 * This function returns a non-negative double-precision floating random
 * number uniformly distributed over the interval [0.0, 1.0).
 *
 * The generator is not cryptographically secure.
 *
 * rte_rand(), rte_rand32(), rte_rand_max() and rte_drand() are
 * multi-thread safe, with the exception that they may not be called
 * by multiple _unregistered_ non-EAL threads in parallel.
 *
 * @return
 *   A pseudo-random value between 0 and 1.0.
 */
double rte_drand(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Fill a buffer with random bytes from the system random generator.
 *
 * The bytes are drawn from the same source as the urandom device and
 * are suitable for cryptographic purposes such as keys, hash seeds and
 * MAC addresses. Unlike rte_rand() the generator state is not
 * recoverable from the output.
 *
 * If the system random source has not been initialized yet this call
 * blocks until enough entropy is available. Once initialized it never
 * blocks.
 *
 * It is several orders of magnitude slower than rte_rand() because it
 * may enter the kernel on every call, and is not meant to be used on
 * the datapath.
 *
 * This function is multi-thread safe.
 *
 * @param buf
 *   Buffer to fill with random bytes.
 * @param len
 *   Number of bytes to write. There is no upper limit, larger requests
 *   are split internally. A length of zero succeeds without doing
 *   anything.
 * @return
 *   0 on success and the buffer is filled completely.
 *   A negative errno if the system random generator failed, the
 *   contents of the buffer are then undefined.
 */
__rte_experimental
int
rte_random_bytes(void *buf, size_t len);

#ifdef __cplusplus
}
#endif


#endif /* _RTE_RANDOM_H_ */
