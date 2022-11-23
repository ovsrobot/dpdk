/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022 Microsoft Corporation
 */

#ifndef _RTE_BITCOUNT_H_
#define _RTE_BITCOUNT_H_

#include <rte_compat.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef RTE_TOOLCHAIN_MSVC

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the count of leading 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of leading zero bits.
 */
__rte_experimental
static inline unsigned int
rte_clz(unsigned int v)
{
	unsigned long rv;

	(void)_BitScanReverse(&rv, v);

	return (unsigned int)rv;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the count of leading 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of leading zero bits.
 */
__rte_experimental
static inline unsigned int
rte_clzl(unsigned long v)
{
	unsigned long rv;

	(void)_BitScanReverse(&rv, v);

	return (unsigned int)rv;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the count of leading 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of leading zero bits.
 */
__rte_experimental
static inline unsigned int
rte_clzll(unsigned long long v)
{
	unsigned long rv;

	(void)_BitScanReverse64(&rv, v);

	return (unsigned int)rv;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the count of trailing 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of trailing zero bits.
 */
__rte_experimental
static inline unsigned int
rte_ctz(unsigned int v)
{
	unsigned long rv;

	(void)_BitScanForward(&rv, v);

	return (unsigned int)rv;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the count of trailing 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of trailing zero bits.
 */
__rte_experimental
static inline unsigned int
rte_ctzl(unsigned long v)
{
	unsigned long rv;

	(void)_BitScanForward(&rv, v);

	return (unsigned int)rv;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the count of trailing 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of trailing zero bits.
 */
__rte_experimental
static inline unsigned int
rte_ctzll(unsigned long long v)
{
	unsigned long rv;

	(void)_BitScanForward64(&rv, v);

	return (unsigned int)rv;
}

#else

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the count of leading 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of leading zero bits.
 */
__rte_experimental
static inline unsigned int
rte_clz(unsigned int v)
{
	return (unsigned int)__builtin_clz(v);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the count of leading 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of leading zero bits.
 */
__rte_experimental
static inline unsigned int
rte_clzl(unsigned long v)
{
	return (unsigned int)__builtin_clzl(v);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the count of leading 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of leading zero bits.
 */
__rte_experimental
static inline unsigned int
rte_clzll(unsigned long v)
{
	return (unsigned int)__builtin_clzll(v);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the count of trailing 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of trailing zero bits.
 */
__rte_experimental
static inline unsigned int
rte_ctz(unsigned int v)
{
	return (unsigned int)__builtin_ctz(v);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the count of trailing 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of trailing zero bits.
 */
__rte_experimental
static inline unsigned int
rte_ctzl(unsigned long v)
{
	return (unsigned int)__builtin_ctzl(v);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the count of trailing 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of trailing zero bits.
 */
__rte_experimental
static inline unsigned int
rte_ctzll(unsigned long v)
{
	return (unsigned int)__builtin_ctzll(v);
}

#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_BITCOUNT_H_ */

