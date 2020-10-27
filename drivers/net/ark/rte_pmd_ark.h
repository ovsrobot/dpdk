/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Atomic Rules LLC
 */

#ifndef RTE_PMD_ARK_H
#define RTE_PMD_ARK_H

/**
 * @file
 * ARK driver-specific API
 */

#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

typedef uint64_t rte_pmd_ark_userdata_t;
extern int rte_pmd_ark_userdata_dynfield_offset;

/** mbuf dynamic field for custom ARK data */
#define RTE_PMD_ARK_USERDATA_DYNFIELD_NAME "rte_net_ark_dynfield_userdata"

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Read user data from mbuf.
 *
 * @param mbuf Structure to read from.
 * @return user data
 */
__rte_experimental
static inline rte_pmd_ark_userdata_t
rte_pmd_ark_mbuf_userdata_get(const struct rte_mbuf *mbuf)
{
	return *RTE_MBUF_DYNFIELD(mbuf, rte_pmd_ark_userdata_dynfield_offset,
			rte_pmd_ark_userdata_t *);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Write user data to mbuf.
 *
 * @param mbuf Structure to write into.
 */
__rte_experimental
static inline void
rte_pmd_ark_mbuf_userdata_set(struct rte_mbuf *mbuf,
		rte_pmd_ark_userdata_t data)
{
	*RTE_MBUF_DYNFIELD(mbuf, rte_pmd_ark_userdata_dynfield_offset,
			rte_pmd_ark_userdata_t *) = data;
}

#endif /* RTE_PMD_ARK_H */
