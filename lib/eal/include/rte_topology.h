/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RTE_TOPO_TOPO_H_
#define _RTE_TOPO_TOPO_H_

/**
 * @file
 *
 * API for lcore and socket manipulation
 */
#include <rte_lcore.h>
#include <rte_bitops.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The lcore grouping with in the L1 Domain.
 */
#define RTE_TOPO_DOMAIN_L1  RTE_BIT32(0)
/**
 * The lcore grouping with in the L2 Domain.
 */
#define RTE_TOPO_DOMAIN_L2  RTE_BIT32(1)
/**
 * The lcore grouping with in the L3 Domain.
 */
#define RTE_TOPO_DOMAIN_L3  RTE_BIT32(2)
/**
 * The lcore grouping with in the L4 Domain.
 */
#define RTE_TOPO_DOMAIN_L4  RTE_BIT32(3)
/**
 * The lcore grouping with in the IO Domain.
 */
#define RTE_TOPO_DOMAIN_NUMA  RTE_BIT32(4)
/**
 * The lcore grouping with in the SMT Domain (Like L1 Domain).
 */
#define RTE_TOPO_DOMAIN_SMT RTE_TOPO_DOMAIN_L1
/**
 * The lcore grouping based on Domains (L1|L2|L3|L4|NUMA).
 */
#define RTE_TOPO_DOMAIN_ALL (RTE_TOPO_DOMAIN_L1 |	\
				RTE_TOPO_DOMAIN_L2 |	\
				RTE_TOPO_DOMAIN_L3 |	\
				RTE_TOPO_DOMAIN_L4 |	\
				RTE_TOPO_DOMAIN_NUMA)
/**
 * The mask for all bits set for domain
 */
#define RTE_TOPO_DOMAIN_MAX RTE_GENMASK32(31, 0)
#define RTE_TOPO_DOMAIN_LCORE_POS_MAX RTE_GENMASK32(31, 0)


/**
 * Get count for selected domain.
 *
 * @param domain_sel
 *   Domain selection, RTE_TOPO_DOMAIN_[L1|L2|L3|L4|NUMA].
 * @return
 *   Number of domains, or 0 if:
 *   - hwloc not available
 *   - Invalid domain selector
 *   - Domain type doesn't exist on system
 *
 * @note valid for EAL args of lcore and coremask.
 *
 */
__rte_experimental
unsigned int rte_topo_get_domain_count(unsigned int domain_sel);

/**
 * Get count for lcores in a domain.
 *
 * @param domain_sel
 *   Domain selection, RTE_TOPO_DOMAIN_[L1|L2|L3|L4|NUMA].
 * @param domain_indx
 *   Domain Index, valid range from 0 to (rte_topo_get_domain_count - 1).
 * @return
 *   total count for lcore in a selected index of a domain.
 *
 * @note valid for EAL args of lcore and coremask.
 *
 */
__rte_experimental
unsigned int
rte_topo_get_lcore_count_from_domain(unsigned int domain_sel, unsigned int domain_indx);

/**
 * Get domain index using lcore & domain.
 *
 * @param domain_sel
 *   Domain selection, RTE_TOPO_DOMAIN_[L1|L2|L3|L4|NUMA].
 * @param lcore
 *   valid lcore within valid selected domain.
 * @return
 *   < 0, invalid domain index
 *   >= 0, valid domain index
 *
 * @note valid for EAL args of lcore and coremask.
 *
 */
__rte_experimental
int
rte_topo_get_domain_index_from_lcore(unsigned int domain_sel, uint16_t lcore);

/**
 * Get n'th lcore from a selected domain.
 *
 * @param domain_sel
 *   Domain selection, RTE_TOPO_DOMAIN_[L1|L2|L3|L4|NUMA].
 * @param domain_indx
 *   Domain Index, valid range from 0 to (rte_topo_get_domain_count - 1).
 * @param lcore_pos
 *   lcore position, valid range from 0 to (dpdk_enabled_lcores in the domain -1)
 * @return
 *   lcore from the list for the selected domain.
 *
 * @note valid for EAL args of lcore and coremask.
 *
 */
__rte_experimental
unsigned int
rte_topo_get_nth_lcore_in_domain(unsigned int domain_sel,
unsigned int domain_indx, unsigned int lcore_pos);

#ifdef RTE_HAS_CPUSET
/**
 * Return cpuset for all lcores in selected domain.
 *
 * @param domain_sel
 *   Domain selection, RTE_TOPO_DOMAIN_[L1|L2|L3|L4|NUMA].
 * @param domain_indx
 *   Domain Index, valid range from 0 to (rte_topo_get_domain_count - 1).
 * @return
 *   cpuset for all lcores from the selected domain.
 *
 * @note valid for EAL args of lcore and coremask.
 *
 */
__rte_experimental
rte_cpuset_t
rte_topo_get_lcore_cpuset_in_domain(unsigned int domain_sel, unsigned int domain_indx);
#endif

/**
 * Return TRUE|FALSE if main lcore in available in selected domain.
 *
 * @param domain_sel
 *   Domain selection, RTE_TOPO_DOMAIN_[L1|L2|L3|L4|NUMA].
 * @param domain_indx
 *   Domain Index, valid range from 0 to (rte_topo_get_domain_count - 1).
 * @return
 *   Check if main lcore is avaialable in the selected domain.
 *
 * @note valid for EAL args of lcore and coremask.
 *
 */
__rte_experimental
bool
rte_topo_is_main_lcore_in_domain(unsigned int domain_sel, unsigned int domain_indx);

/**
 * Get the enabled lcores from next domain based on extended flag.
 *
 * @param lcore
 *   The current lcore (reference).
 * @param skip_main
 *   If true, do not return the ID of the main lcore.
 * @param wrap
 *   If true, go back to first core of flag based domain when last core is reached.
 *   If false, return RTE_MAX_LCORE when no more cores are available.
 * @param flag
 *   Allows user to select various domain as specified under RTE_TOPO_DOMAIN_[L1|L2|L3|L4|NUMA]
 *
 * @return
 *   The next lcore_id or RTE_MAX_LCORE if not found.
 *
 * @note valid for EAL args of lcore and coremask.
 *
 */
__rte_experimental
unsigned int
rte_topo_get_next_lcore(uint16_t lcore,
bool skip_main, bool wrap, uint32_t flag);

/**
 * Get the Nth (first|last) lcores from next domain based on extended flag.
 *
 * @param domain_indx
 *   Domain Index, valid range from 0 to (rte_topo_get_domain_count - 1).
 * @param lcore_pos
 *   lcore position, valid range from 0 to (dpdk_enabled_lcores in the domain -1)
 * @param wrap
 *   If true, go back to first core of flag based domain when last core is reached.
 *   If false, return RTE_MAX_LCORE when no more cores are available.
 * @param flag
 *   Allows user to select various domain as specified under RTE_TOPO_DOMAIN_(L1|L2|L3|L4|NUMA)
 *
 * @return
 *   The next lcore_id or RTE_MAX_LCORE if not found.
 *
 * @note valid for EAL args of lcore and coremask.
 *
 */
__rte_experimental
unsigned int
rte_topo_get_nth_lcore_from_domain(unsigned int domain_indx, unsigned int lcore_pos,
int wrap, uint32_t flag);

/**
 * Dump an internal topo_config to a file.
 *
 * Dump all fields for struct topology_config fields,
 *
 * @param f
 *   A pointer to a file for output
 */
__rte_experimental
void
rte_topo_dump(FILE *f);

#define RTE_TOPO_FOREACH_DOMAIN(domain_index, flag)	\
	const unsigned int domain_count = rte_topo_get_domain_count(flag);	\
	for (domain_index = 0; domain_index < domain_count; domain_index++)

#define RTE_TOPO_FOREACH_WORKER_DOMAIN(domain_index, flag)	\
	const unsigned int domain_count = rte_topo_get_domain_count(flag);	\
	for (domain_index += (rte_topo_is_main_lcore_in_domain(domain_index, flag)) ? 1 : 0;	\
		domain_index < domain_count;	\
		domain_index += (rte_topo_is_main_lcore_in_domain(domain_index + 1, flag)) ? 2 : 1)

#define RTE_TOPO_FOREACH_LCORE_IN_DOMAIN(lcore, domain_indx, lcore_pos, flag)	\
	for (lcore = rte_topo_get_nth_lcore_from_domain(domain_indx, lcore_pos, 0, flag);	\
		lcore < RTE_MAX_LCORE;	\
		lcore = rte_topo_get_nth_lcore_from_domain(domain_indx, ++lcore_pos, 0, flag))

#define RTE_TOPO_FOREACH_WORKER_LCORE_IN_DOMAIN(lcore, domain_indx, flag)	\
	lcore = rte_topo_get_nth_lcore_from_domain(domain, 0, 0, flag);	\
	uint16_t main_lcore = rte_get_main_lcore();	\
	for (lcore = (lcore != main_lcore) ? \
		lcore : rte_topo_get_next_lcore(lcore, 1, 0, flag);	\
		lcore < RTE_MAX_LCORE;	\
		lcore = rte_topo_get_next_lcore(lcore, 1, 0, flag))

#ifdef __cplusplus
}
#endif


#endif /* _RTE_TOPO_TOPO_H_ */
