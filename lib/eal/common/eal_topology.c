/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 AMD Corporation
 */

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <rte_topology.h>
#include <rte_malloc.h>

#include <eal_export.h>
#include "eal_private.h"

struct topology_config topo_cnfg;

#ifdef RTE_LIBHWLOC_PROBE
static inline bool is_valid_single_domain(unsigned int domainbits)
{
	if ((domainbits == 0) || (domainbits & ~RTE_TOPO_DOMAIN_ALL))
		return false;

	return (__builtin_popcount(domainbits) == 1);
}

static unsigned int
get_domain_count(unsigned int domain_sel)
{
	if (is_valid_single_domain(domain_sel) == false)
		return 0;

	unsigned int domain_cnt =
		(domain_sel & RTE_TOPO_DOMAIN_NUMA) ? topo_cnfg.numa_count :
		(domain_sel & RTE_TOPO_DOMAIN_L4) ? topo_cnfg.l4_count :
		(domain_sel & RTE_TOPO_DOMAIN_L3) ? topo_cnfg.l3_count :
		(domain_sel & RTE_TOPO_DOMAIN_L2) ? topo_cnfg.l2_count :
		(domain_sel & RTE_TOPO_DOMAIN_L1) ? topo_cnfg.l1_count : 0;

	return domain_cnt;
}

static struct core_domain_mapping *
get_domain_lcore_mapping(unsigned int domain_sel, unsigned int domain_indx)
{
	if (is_valid_single_domain(domain_sel) == false)
		return NULL;

	if (domain_indx >= get_domain_count(domain_sel))
		return NULL;

	struct core_domain_mapping *ptr =
		(domain_sel & RTE_TOPO_DOMAIN_NUMA) ? topo_cnfg.numa[domain_indx] :
		(domain_sel & RTE_TOPO_DOMAIN_L4) ? topo_cnfg.l4[domain_indx] :
		(domain_sel & RTE_TOPO_DOMAIN_L3) ? topo_cnfg.l3[domain_indx] :
		(domain_sel & RTE_TOPO_DOMAIN_L2) ? topo_cnfg.l2[domain_indx] :
		(domain_sel & RTE_TOPO_DOMAIN_L1) ? topo_cnfg.l1[domain_indx] : NULL;

	return ptr;
}

static unsigned int
get_domain_lcore_count(unsigned int domain_sel)
{
	if (is_valid_single_domain(domain_sel) == false)
		return 0;

	return ((domain_sel & RTE_TOPO_DOMAIN_NUMA) ? topo_cnfg.numa_core_count :
		(domain_sel & RTE_TOPO_DOMAIN_L4) ? topo_cnfg.l4_core_count :
		(domain_sel & RTE_TOPO_DOMAIN_L3) ? topo_cnfg.l3_core_count :
		(domain_sel & RTE_TOPO_DOMAIN_L2) ? topo_cnfg.l2_core_count :
		(domain_sel & RTE_TOPO_DOMAIN_L1) ? topo_cnfg.l1_core_count : 0);
}

static unsigned int
get_lcore_count_from_domain_index(unsigned int domain_sel, unsigned int domain_indx)
{
	if ((is_valid_single_domain(domain_sel) == false) ||
		(domain_indx >= get_domain_count(domain_sel)))
		return 0;

	struct core_domain_mapping *ptr = get_domain_lcore_mapping(domain_sel, domain_indx);
	if (ptr == NULL)
		return 0;

	return ptr->core_count;
}

static uint16_t
get_lcore_from_domain_position(unsigned int domain_sel, unsigned int domain_indx, unsigned int pos)
{
	if (pos >= RTE_MAX_LCORE)
		return RTE_MAX_LCORE;

	struct core_domain_mapping *ptr = get_domain_lcore_mapping(domain_sel, domain_indx);
	if (ptr == NULL)
		return RTE_MAX_LCORE;

	if (pos >= ptr->core_count)
		return RTE_MAX_LCORE;

	return ptr->cores[pos];
}
#endif

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_topo_get_domain_index_from_lcore, 26.07)
int
rte_topo_get_domain_index_from_lcore(unsigned int domain_sel, uint16_t lcore)
{
#ifdef RTE_LIBHWLOC_PROBE
	if (!rte_lcore_is_enabled(lcore))
		return -1;

	if (is_valid_single_domain(domain_sel) == false)
		return -2;

	return ((domain_sel & RTE_TOPO_DOMAIN_NUMA) ? topo_cnfg.lcore_map[lcore].numa_domain :
		(domain_sel & RTE_TOPO_DOMAIN_L4) ? topo_cnfg.lcore_map[lcore].l4_domain :
		(domain_sel & RTE_TOPO_DOMAIN_L3) ? topo_cnfg.lcore_map[lcore].l3_domain :
		(domain_sel & RTE_TOPO_DOMAIN_L2) ? topo_cnfg.lcore_map[lcore].l2_domain :
		(domain_sel & RTE_TOPO_DOMAIN_L1) ? topo_cnfg.lcore_map[lcore].l1_domain : -3);
#else
	RTE_SET_USED(domain_sel);
	RTE_SET_USED(lcore);
	return -3;
#endif
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_topo_get_domain_count, 26.07)
unsigned int rte_topo_get_domain_count(unsigned int domain_sel)
{
#ifdef RTE_LIBHWLOC_PROBE
	return get_domain_count(domain_sel);
#else
	RTE_SET_USED(domain_sel);
#endif

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_topo_get_lcore_count_from_domain, 26.07)
unsigned int
rte_topo_get_lcore_count_from_domain(unsigned int domain_sel __rte_unused,
unsigned int domain_indx __rte_unused)
{
#ifdef RTE_LIBHWLOC_PROBE
	return get_lcore_count_from_domain_index(domain_sel, domain_indx);
#else
	RTE_SET_USED(domain_sel);
	RTE_SET_USED(domain_indx);
#endif
	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_topo_get_nth_lcore_in_domain, 26.07)
unsigned int
rte_topo_get_nth_lcore_in_domain(unsigned int domain_sel __rte_unused,
unsigned int domain_indx __rte_unused, unsigned int lcore_pos __rte_unused)
{
#ifdef RTE_LIBHWLOC_PROBE
	return get_lcore_from_domain_position(domain_sel, domain_indx, lcore_pos);
#else
	RTE_SET_USED(domain_sel);
	RTE_SET_USED(domain_indx);
	RTE_SET_USED(lcore_pos);
#endif
	return RTE_MAX_LCORE;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_topo_get_lcore_cpuset_in_domain, 26.07)
rte_cpuset_t
rte_topo_get_lcore_cpuset_in_domain(unsigned int domain_sel __rte_unused,
unsigned int domain_indx __rte_unused)
{
	rte_cpuset_t ret_cpu_set;
	CPU_ZERO(&ret_cpu_set);

#ifdef RTE_LIBHWLOC_PROBE
	const struct core_domain_mapping *ptr = get_domain_lcore_mapping(domain_sel, domain_indx);

	if ((ptr == NULL) || (ptr->core_count == 0))
		return ret_cpu_set;

	CPU_OR(&ret_cpu_set, &ret_cpu_set, &ptr->core_set);
#else
	RTE_SET_USED(domain_sel);
	RTE_SET_USED(domain_indx);
#endif

	return ret_cpu_set;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_topo_is_main_lcore_in_domain, 26.07)
bool
rte_topo_is_main_lcore_in_domain(unsigned int domain_sel __rte_unused,
unsigned int domain_indx __rte_unused)
{
#ifdef RTE_LIBHWLOC_PROBE
	const unsigned int main_lcore = rte_get_main_lcore();
	const struct core_domain_mapping *ptr = get_domain_lcore_mapping(domain_sel, domain_indx);

	if ((ptr == NULL) || (ptr->core_count == 0))
		return false;

	return CPU_ISSET(main_lcore, &ptr->core_set);
#else
	RTE_SET_USED(domain_sel);
	RTE_SET_USED(domain_indx);
#endif

	return false;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_topo_get_nth_lcore_from_domain, 26.07)
unsigned int
rte_topo_get_nth_lcore_from_domain(unsigned int domain_indx __rte_unused,
unsigned int lcore_pos __rte_unused,
int wrap __rte_unused, uint32_t flag __rte_unused)
{
#ifdef RTE_LIBHWLOC_PROBE
	const unsigned int lcore_in_domain = get_domain_lcore_count(flag);
	const unsigned int domain_count = get_domain_count(flag);

	if ((domain_count == 0) || (lcore_in_domain <= 1))
		return RTE_MAX_LCORE;

	const bool find_first_lcore_in_first_domain =
			((domain_indx == RTE_TOPO_DOMAIN_MAX) &&
				(lcore_pos == RTE_TOPO_DOMAIN_LCORE_POS_MAX)) ? true : false;
	const bool find_domain_from_lcore_pos =
			((domain_indx == RTE_TOPO_DOMAIN_MAX) &&
				(lcore_pos < RTE_TOPO_DOMAIN_LCORE_POS_MAX)) ? true : false;

	struct core_domain_mapping *ptr = NULL;

	/* if user has passed invalid lcore id, get the first valid lcore */
	if (find_first_lcore_in_first_domain) {
		for (unsigned int domain_index = 0; domain_index < domain_count; domain_index++) {
			ptr = get_domain_lcore_mapping(flag, domain_index);
			if ((ptr == NULL) || (ptr->core_count == 0))
				continue;

			/* get first lcore from valid domain based on the flag */
			for (unsigned int i = 0; i < ptr->core_count; i++) {
				uint16_t lcore = ptr->cores[i];

				EAL_LOG(DEBUG, "Found lcore (%u) in domain (%d) at pos %u",
					lcore, domain_index, i);
				return lcore;
			}
		}

		return RTE_MAX_LCORE;
	}

	/* if user has passed lcore pos, get lcore from matching domian */
	if (find_domain_from_lcore_pos) {
		for (unsigned int domain_index = 0; domain_index < domain_count; domain_index++) {
			unsigned int pos_lcore = lcore_pos;
			ptr = get_domain_lcore_mapping(flag, domain_index);
			if ((ptr == NULL) || (ptr->core_count == 0))
				continue;

			if (wrap)
				pos_lcore = (ptr->core_count > lcore_pos) ?
					lcore_pos : lcore_pos %  ptr->core_count;

			/* get first lcore from valid domain based on the flag */
			for (unsigned int i = pos_lcore; i < ptr->core_count; i++) {
				uint16_t lcore = ptr->cores[i];

				EAL_LOG(DEBUG, "Found lcore (%u) in domain (%d) at pos %u",
					lcore, domain_index, i);
				return lcore;
			}
		}

		return RTE_MAX_LCORE;
	}

	if (wrap)
		domain_indx = domain_indx % domain_count;

	/* get cores set in domain_indx */
	ptr = get_domain_lcore_mapping(flag, domain_indx);
	if ((ptr == NULL) || (ptr->core_count == 0))
		return RTE_MAX_LCORE;

	if (wrap)
		lcore_pos = lcore_pos % ptr->core_count;

	if (lcore_pos >= ptr->core_count)
		return RTE_MAX_LCORE;

	EAL_LOG(DEBUG, "lcore pos (%u) from domain (%u)", lcore_pos, domain_indx);

	bool wrap_once = false;
	unsigned int new_lcore_pos = lcore_pos;

	while (1) {
		if (new_lcore_pos >= ptr->core_count) {
			if (!wrap)
				return RTE_MAX_LCORE;

			if ((wrap == true) && (wrap_once == true))
				return RTE_MAX_LCORE;

			new_lcore_pos = 0;
			wrap_once = true;
		}

		/* check if the domain has cores_to_skip */
		uint16_t new_lcore = ptr->cores[new_lcore_pos];

		EAL_LOG(DEBUG, "Selected core (%u) at position %u", new_lcore, new_lcore_pos);
		return new_lcore;
	}

#else
	RTE_SET_USED(domain_indx);
	RTE_SET_USED(lcore_pos);
	RTE_SET_USED(wrap);
	RTE_SET_USED(flag);
#endif

	return RTE_MAX_LCORE;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_topo_get_next_lcore, 26.07)
unsigned int
rte_topo_get_next_lcore(uint16_t lcore __rte_unused,
bool skip_main __rte_unused, bool wrap __rte_unused, uint32_t flag __rte_unused)
{
#ifdef RTE_LIBHWLOC_PROBE
	const uint16_t main_lcore = rte_get_main_lcore();
	const unsigned int lcore_in_domain = get_domain_lcore_count(flag);
	const unsigned int domain_count = get_domain_count(flag);

	if ((domain_count == 0) || (lcore_in_domain <= 1))
		return RTE_MAX_LCORE;

	if (wrap)
		lcore = lcore % RTE_MAX_LCORE;

	if ((lcore >= RTE_MAX_LCORE) && (wrap == false))
		return RTE_MAX_LCORE;

	int lcore_domain = rte_topo_get_domain_index_from_lcore(flag, lcore);
	if (lcore_domain < 0)
		return RTE_MAX_LCORE;

	struct core_domain_mapping *ptr = get_domain_lcore_mapping(flag, lcore_domain);
	if ((ptr == NULL) || (ptr->core_count == 0))
		return RTE_MAX_LCORE;

	unsigned int lcore_pos = RTE_TOPO_DOMAIN_LCORE_POS_MAX;
	for (unsigned int i = 0; i < ptr->core_count; i++) {
		uint16_t find_lcore = ptr->cores[i];

		if (lcore == find_lcore) {
			lcore_pos = i;
			break;
		}
	}

	if (lcore_pos == RTE_TOPO_DOMAIN_LCORE_POS_MAX)
		return RTE_MAX_LCORE;

	EAL_LOG(DEBUG, "lcore pos (%u) from domain (%u)", lcore_pos, lcore_domain);

	bool wrap_once = false;
	unsigned int new_lcore_pos = lcore_pos + 1;

	while (1) {
		if (new_lcore_pos >= ptr->core_count) {
			if (!wrap)
				return RTE_MAX_LCORE;

			if ((wrap == true) && (wrap_once == true))
				return RTE_MAX_LCORE;

			new_lcore_pos = 0;
			wrap_once = true;
		}

		/* check if the domain has cores_to_skip */
		uint16_t new_lcore = ptr->cores[new_lcore_pos];
		bool main_in_domain = rte_topo_is_main_lcore_in_domain(flag, lcore_domain);

		if (main_in_domain) {
			if ((skip_main) && (new_lcore == main_lcore)) {
				new_lcore_pos++;
				continue;
			}
		}

		EAL_LOG(DEBUG, "Selected core (%u) at position %u", new_lcore, new_lcore_pos);
		return new_lcore;
	}

#else
	RTE_SET_USED(skip_main);
	RTE_SET_USED(wrap);
	RTE_SET_USED(flag);
#endif

	return RTE_MAX_LCORE;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_topo_dump, 26.07)
void
rte_topo_dump(FILE *f)
{
#ifdef RTE_LIBHWLOC_PROBE
	static const unsigned int domain_types[] = {
		RTE_TOPO_DOMAIN_NUMA,
		RTE_TOPO_DOMAIN_L4,
		RTE_TOPO_DOMAIN_L3,
		RTE_TOPO_DOMAIN_L2,
		RTE_TOPO_DOMAIN_L1
	};

	fprintf(f, "| %15s | %15s | %15s | %15s |\n",
		"Domain-Name", "Domains", "Domains-with-lcore", "Domain-total-lcore");
	fprintf(f, "----------------------------------------------------------------------------------------------\n");
	for (unsigned int d = 0; d < RTE_DIM(domain_types); d++) {
		unsigned int domain = RTE_TOPO_DOMAIN_MAX;
		unsigned int domain_valid_count = 0;
		unsigned int domain_valid_lcore_count = 0;

		RTE_TOPO_FOREACH_DOMAIN(domain, domain_types[d]) {
			if (rte_topo_get_lcore_count_from_domain(domain_types[d], domain))
				domain_valid_count += 1;
			domain_valid_lcore_count +=
				rte_topo_get_lcore_count_from_domain(domain_types[d], domain);
		}

		fprintf(f, "| %15s | %15u | %15u | %15u |\n",
			(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
			(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
			(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
			(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
			(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL,
			rte_topo_get_domain_count(domain_types[d]),
			domain_valid_count,
			domain_valid_lcore_count);
	}
	fprintf(f, "----------------------------------------------------------------------------------------------\n\n");

	fprintf(f, "| %15s | %15s | %15s |\n",
		"Domain-Name", "Domain-Index", "lcores");
	fprintf(f, "----------------------------------------------------------------------------------------------");
	for (unsigned int d = 0; d < RTE_DIM(domain_types); d++) {
		unsigned int domain = RTE_TOPO_DOMAIN_MAX;

		RTE_TOPO_FOREACH_DOMAIN(domain, domain_types[d]) {
			if (rte_topo_get_lcore_count_from_domain(domain_types[d], domain) == 0)
				continue;

			fprintf(f, "\n| %15s | %15u | ",
				(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL,
				domain);

			uint16_t lcore = RTE_MAX_LCORE;
			unsigned int pos = 0;
			RTE_TOPO_FOREACH_LCORE_IN_DOMAIN(lcore, domain, pos, domain_types[d])
				fprintf(f, " %u ", lcore);
		}
	}
	fprintf(f, "\n----------------------------------------------------------------------------------------------\n\n");

	fprintf(f, "| %10s |  %10s | %10s | %10s | %10s | %10s | %10s |\n",
		"lcore", "cpu", "NUMA-Index", "L4-Index", "L3-Index", "L2-Index", "L1-Index");
	fprintf(f, "------------------------------------------------------------------------------\n");
	for (unsigned int i = 0; i < RTE_MAX_LCORE; i++) {
		if (rte_lcore_is_enabled(i) == false)
			continue;

		fprintf(f, "| %10u |  %10u | %10u | %10u | %10u | %10u | %10u |\n",
			i,
			topo_cnfg.lcore_map[i].cpu,
			topo_cnfg.lcore_map[i].numa_domain,
			topo_cnfg.lcore_map[i].l4_domain,
			topo_cnfg.lcore_map[i].l3_domain,
			topo_cnfg.lcore_map[i].l2_domain,
			topo_cnfg.lcore_map[i].l1_domain);
	}
	fprintf(f, "------------------------------------------------------------------------------\n\n");

	fprintf(f, "| %10s |  %10s | %10s | %10s | %10s | %10s | %10s |\n",
		"lcore", "cpu", "NUMA-cacheid", "L4-cacheid", "L3-cacheid", "L2-cacheid", "L1-cacheid");
	fprintf(f, "------------------------------------------------------------------------------\n");
	for (unsigned int i = 0; i < RTE_MAX_LCORE; i++) {
		if (rte_lcore_is_enabled(i) == false)
			continue;

		fprintf(f, "| %10u |  %10u | %10u | %10u | %10u | %10u | %10u |\n",
			i,
			topo_cnfg.lcore_map[i].cpu,
			topo_cnfg.lcore_map[i].numa_cacheid,
			topo_cnfg.lcore_map[i].l4_cacheid,
			topo_cnfg.lcore_map[i].l3_cacheid,
			topo_cnfg.lcore_map[i].l2_cacheid,
			topo_cnfg.lcore_map[i].l1_cacheid);
	}
	fprintf(f, "------------------------------------------------------------------------------\n\n");

#else
	RTE_SET_USED(f);
#endif
}

#ifdef RTE_LIBHWLOC_PROBE
static int
lcore_to_core(unsigned int lcore)
{
	rte_cpuset_t cpu;
	CPU_ZERO(&cpu);

	cpu = rte_lcore_cpuset(lcore);

	for (int i = 0; i < RTE_TOPO_MAX_CPU_CORES; i++) {
		if (CPU_ISSET(i, &cpu))
			return i;
	}

	return -1;
}

static int
eal_topology_map_layer(hwloc_topology_t topology, int depth,
uint16_t *layer_cnt, struct core_domain_mapping ***layer_ptr,
uint16_t *total_core_cnt, const char *layer_name)
{
	if (depth == HWLOC_TYPE_DEPTH_UNKNOWN || *layer_cnt == 0)
		return 0;

	*layer_ptr = rte_malloc(NULL, sizeof(struct core_domain_mapping *) * (*layer_cnt), 0);
	if (*layer_ptr == NULL)
		return -1;

	/* create lcore-domain-mapping */
	for (uint16_t j = 0; j < *layer_cnt; j++) {
		hwloc_obj_t obj = hwloc_get_obj_by_depth(topology, depth, j);
		int cpu_count = hwloc_bitmap_weight(obj->cpuset);
		if (cpu_count == -1)
			continue;

		struct core_domain_mapping *dm =
			rte_zmalloc(NULL, sizeof(struct core_domain_mapping), 0);
		if (!dm)
			return -1;

		(*layer_ptr)[j] = dm;
		CPU_ZERO(&dm->core_set);
		dm->core_count = 0;

		dm->cores = rte_malloc(NULL, sizeof(uint16_t) * cpu_count, 0);
		if (!dm->cores)
			return -1;
	}

	/* populate lcore-mapping */
	for (uint16_t j = 0; j < *layer_cnt; j++) {
		hwloc_obj_t obj = hwloc_get_obj_by_depth(topology, depth, j);
		if (!obj || hwloc_bitmap_iszero(obj->cpuset))
			continue;

		int cpu_id = -1;
		while ((cpu_id = hwloc_bitmap_next(obj->cpuset, cpu_id)) != -1) {
			if (!rte_lcore_is_enabled(cpu_id))
				continue;

			EAL_LOG(DEBUG, " %s domain (%u) lcore %u, logical %u, os %u",
				layer_name, j, cpu_id, obj->logical_index, obj->os_index);

			int cpu_core = lcore_to_core(cpu_id);
			if (cpu_core == -1)
				return -1;

			topo_cnfg.lcore_map[cpu_id].cpu = (uint16_t) cpu_core;

			for (uint16_t k = 0; k < *layer_cnt; k++) {
				hwloc_obj_t obj_core =
					hwloc_get_obj_by_depth(topology, depth, k);
				int cpu_count_core =
					hwloc_bitmap_weight(obj_core->cpuset);
				if (cpu_count_core == -1)
					continue;

				if (hwloc_bitmap_isset(obj_core->cpuset,
					topo_cnfg.lcore_map[cpu_id]. cpu)) {
					if (strncmp(layer_name, "NUMA", 4) == 0) {
						topo_cnfg.lcore_map[cpu_id].numa_domain = k;
						topo_cnfg.lcore_map[cpu_id].numa_cacheid =
							obj_core->logical_index;
					} else if (strncmp(layer_name, "L4", 2) == 0) {
						topo_cnfg.lcore_map[cpu_id].l4_domain = k;
						topo_cnfg.lcore_map[cpu_id].l4_cacheid =
							obj_core->logical_index;
					} else if (strncmp(layer_name, "L3", 2) == 0) {
						topo_cnfg.lcore_map[cpu_id].l3_domain = k;
						topo_cnfg.lcore_map[cpu_id].l3_cacheid =
							obj_core->logical_index;
					} else if (strncmp(layer_name, "L2", 2) == 0) {
						topo_cnfg.lcore_map[cpu_id].l2_domain = k;
						topo_cnfg.lcore_map[cpu_id].l2_cacheid =
							obj_core->logical_index;
					} else if (strncmp(layer_name, "L1", 2) == 0) {
						topo_cnfg.lcore_map[cpu_id].l1_domain = k;
						topo_cnfg.lcore_map[cpu_id].l1_cacheid =
							obj_core->logical_index;
					}

					/* populate lcore-domain-mapping */
					struct core_domain_mapping *dm = (*layer_ptr)[k];
					if (dm == NULL)
						return -2;

					dm->cores[dm->core_count++] = (uint16_t)cpu_id;
					CPU_SET(cpu_id, &dm->core_set);

					(*total_core_cnt)++;
					break;
				}
			}
		}
	}

	return 0;
}
#endif

/*
 * Use HWLOC library to parse L1|L2|L3|NUMA-IO on the running target machine.
 * Store the topology structure in memory.
 */
RTE_EXPORT_INTERNAL_SYMBOL(rte_eal_topology_init)
int rte_eal_topology_init(void)
{
#ifdef RTE_LIBHWLOC_PROBE
	memset(&topo_cnfg, 0, sizeof(struct topology_config));

	if (hwloc_topology_init(&topo_cnfg.topology) < 0)
		return -1;

	if (hwloc_topology_load(topo_cnfg.topology) < 0) {
		hwloc_topology_destroy(topo_cnfg.topology);
		return -2;
	}

	struct {
		int depth;
		uint16_t *count;
		struct core_domain_mapping ***ptr;
		uint16_t *total_cores;
		const char *name;
	} layers[] = {
		{ hwloc_get_type_depth(topo_cnfg.topology, HWLOC_OBJ_L1CACHE),
			&topo_cnfg.l1_count, &topo_cnfg.l1, &topo_cnfg.l1_core_count, "L1" },
		{ hwloc_get_type_depth(topo_cnfg.topology, HWLOC_OBJ_L2CACHE),
			&topo_cnfg.l2_count, &topo_cnfg.l2, &topo_cnfg.l2_core_count, "L2" },
		{ hwloc_get_type_depth(topo_cnfg.topology, HWLOC_OBJ_L3CACHE),
			&topo_cnfg.l3_count, &topo_cnfg.l3, &topo_cnfg.l3_core_count, "L3" },
		{ hwloc_get_type_depth(topo_cnfg.topology, HWLOC_OBJ_L4CACHE),
			&topo_cnfg.l4_count, &topo_cnfg.l4, &topo_cnfg.l4_core_count, "L4" },
		{ hwloc_get_type_depth(topo_cnfg.topology, HWLOC_OBJ_NUMANODE),
			&topo_cnfg.numa_count, &topo_cnfg.numa, &topo_cnfg.numa_core_count, "NUMA" }
	};

	for (int i = 0; i < 5; i++) {
		*layers[i].count = hwloc_get_nbobjs_by_depth(topo_cnfg.topology, layers[i].depth);
		if (eal_topology_map_layer(topo_cnfg.topology, layers[i].depth, layers[i].count,
			layers[i].ptr, layers[i].total_cores, layers[i].name) < 0) {
			rte_eal_topology_release();
			return -1;
		}
	}

	hwloc_topology_destroy(topo_cnfg.topology);
	topo_cnfg.topology = NULL;
#endif

	return 0;
}


#ifdef RTE_LIBHWLOC_PROBE
struct domain_store {
	struct core_domain_mapping **map;
	uint16_t count;
	uint16_t core_count;
	const char *name;
};

static void
release_domain(struct domain_store *d)
{
	if (!d->map) {
		d->count = 0;
		d->core_count = 0;
		return;
	}

	for (int i = 0; i < d->count; i++) {
		if (!d->map[i])
			continue;
		rte_free(d->map[i]->cores);
		d->map[i]->cores = NULL;
		rte_free(d->map[i]);
		d->map[i] = NULL;
	}

	rte_free(d->map);
	d->map = NULL;
}
#endif

/*
 * release HWLOC topology structure memory
 */
RTE_EXPORT_INTERNAL_SYMBOL(rte_eal_topology_release)
int
rte_eal_topology_release(void)
{
#ifdef RTE_LIBHWLOC_PROBE

	struct domain_store domains[] = {
		{ topo_cnfg.l1,   topo_cnfg.l1_count,   topo_cnfg.l1_core_count,   "L1"   },
		{ topo_cnfg.l2,   topo_cnfg.l2_count,   topo_cnfg.l2_core_count,   "L2"   },
		{ topo_cnfg.l3,   topo_cnfg.l3_count,   topo_cnfg.l3_core_count,   "L3"   },
		{ topo_cnfg.l4,   topo_cnfg.l4_count,   topo_cnfg.l4_core_count,   "L4"   },
		{ topo_cnfg.numa, topo_cnfg.numa_count,  topo_cnfg.numa_core_count, "NUMA" },
	};

	for (unsigned int d = 0; d < RTE_DIM(domains); d++) {
		EAL_LOG(DEBUG, "release %s domain memory", domains[d].name);
		release_domain(&domains[d]);
	}
#endif

	return 0;
}
