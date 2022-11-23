/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022 Microsoft Corporation
 */

#ifndef EAL_BITCOUNT_H
#define EAL_BITCOUNT_H

#include <rte_compat.h>

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
static inline unsigned
rte_clz(unsigned int v)
{
	unsigned long rv;

	(void)_BitScanReverse(&rv, v);

	return (unsigned)rv;
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
static inline unsigned
rte_clzl(unsigned long v)
{
	unsigned long rv;

	(void)_BitScanReverse(&rv, v);

	return (unsigned)rv;
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
static inline unsigned
rte_clzll(unsigned long long v)
{
	unsigned long rv;

	(void)_BitScanReverse64(&rv, v);

	return (unsigned)rv;
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
static inline unsigned
rte_ctz(unsigned int v)
{
	unsigned long rv;

	(void)_BitScanForward(&rv, v);

	return (unsigned)rv;
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
static inline unsigned
rte_ctzl(unsigned long v)
{
	unsigned long rv;

	(void)_BitScanForward(&rv, v);

	return (unsigned)rv;
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
static inline unsigned
rte_ctzll(unsigned long long v)
{
	unsigned long rv;

	(void)_BitScanForward64(&rv, v);

	return (unsigned)rv;
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
static inline unsigned
rte_clz(unsigned int v)
{
	return (unsigned)__builtin_clz(v);
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
static inline unsigned
rte_clzl(unsigned long v)
{
	return (unsigned)__builtin_clzl(v);
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
static inline unsigned
rte_clzll(unsigned long v)
{
	return (unsigned)__builtin_clzll(v);
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
static inline unsigned
rte_ctz(unsigned int v)
{
	return (unsigned)__builtin_ctz(v);
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
static inline unsigned
rte_ctzl(unsigned long v)
{
	return (unsigned)__builtin_ctzl(v);
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
static inline unsigned
rte_ctzll(unsigned long v)
{
	return (unsigned)__builtin_ctzll(v);
}

#endif

#endif /* EAL_BITCOUNT_H */

