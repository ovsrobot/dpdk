/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_log.h>
#ifndef RTE_EXEC_ENV_WINDOWS
#include <rte_telemetry.h>
#endif
#include <rte_malloc.h>

#include "eal_private.h"
#include "eal_thread.h"

unsigned int rte_get_main_lcore(void)
{
	return rte_eal_get_configuration()->main_lcore;
}

unsigned int rte_lcore_count(void)
{
	return rte_eal_get_configuration()->lcore_count;
}

int rte_lcore_index(int lcore_id)
{
	if (unlikely(lcore_id >= RTE_MAX_LCORE))
		return -1;

	if (lcore_id < 0) {
		if (rte_lcore_id() == LCORE_ID_ANY)
			return -1;

		lcore_id = (int)rte_lcore_id();
	}

	return lcore_config[lcore_id].core_index;
}

int rte_lcore_to_cpu_id(int lcore_id)
{
	if (unlikely(lcore_id >= RTE_MAX_LCORE))
		return -1;

	if (lcore_id < 0) {
		if (rte_lcore_id() == LCORE_ID_ANY)
			return -1;

		lcore_id = (int)rte_lcore_id();
	}

	return lcore_config[lcore_id].core_id;
}

rte_cpuset_t rte_lcore_cpuset(unsigned int lcore_id)
{
	return lcore_config[lcore_id].cpuset;
}

enum rte_lcore_role_t
rte_eal_lcore_role(unsigned int lcore_id)
{
	struct rte_config *cfg = rte_eal_get_configuration();

	if (lcore_id >= RTE_MAX_LCORE)
		return ROLE_OFF;
	return cfg->lcore_role[lcore_id];
}

int
rte_lcore_has_role(unsigned int lcore_id, enum rte_lcore_role_t role)
{
	struct rte_config *cfg = rte_eal_get_configuration();

	if (lcore_id >= RTE_MAX_LCORE)
		return -EINVAL;

	return cfg->lcore_role[lcore_id] == role;
}

int rte_lcore_is_enabled(unsigned int lcore_id)
{
	struct rte_config *cfg = rte_eal_get_configuration();

	if (lcore_id >= RTE_MAX_LCORE)
		return 0;
	return cfg->lcore_role[lcore_id] == ROLE_RTE;
}

unsigned int rte_get_next_lcore(unsigned int i, int skip_main, int wrap)
{
	i++;
	if (wrap)
		i %= RTE_MAX_LCORE;

	while (i < RTE_MAX_LCORE) {
		if (!rte_lcore_is_enabled(i) ||
		    (skip_main && (i == rte_get_main_lcore()))) {
			i++;
			if (wrap)
				i %= RTE_MAX_LCORE;
			continue;
		}
		break;
	}
	return i;
}

#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
static struct core_domain_mapping *
get_domain_lcore_mapping(unsigned int domain_sel, unsigned int domain_indx)
{
	struct core_domain_mapping *ptr =
		(domain_sel & RTE_LCORE_DOMAIN_IO) ? topo_cnfg.io[domain_indx] :
		(domain_sel & RTE_LCORE_DOMAIN_L4) ? topo_cnfg.l4[domain_indx] :
		(domain_sel & RTE_LCORE_DOMAIN_L3) ? topo_cnfg.l3[domain_indx] :
		(domain_sel & RTE_LCORE_DOMAIN_L2) ? topo_cnfg.l2[domain_indx] :
		(domain_sel & RTE_LCORE_DOMAIN_L1) ? topo_cnfg.l1[domain_indx] : NULL;

	return ptr;
}

static unsigned int
get_domain_lcore_count(unsigned int domain_sel)
{
	return ((domain_sel & RTE_LCORE_DOMAIN_IO) ? topo_cnfg.io_core_count :
		(domain_sel & RTE_LCORE_DOMAIN_L4) ? topo_cnfg.l4_core_count :
		(domain_sel & RTE_LCORE_DOMAIN_L3) ? topo_cnfg.l3_core_count :
		(domain_sel & RTE_LCORE_DOMAIN_L2) ? topo_cnfg.l2_core_count :
		(domain_sel & RTE_LCORE_DOMAIN_L1) ? topo_cnfg.l1_core_count : 0);
}
#endif

unsigned int rte_get_domain_count(unsigned int domain_sel __rte_unused)
{
	unsigned int domain_cnt = 0;

#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
	if (domain_sel & RTE_LCORE_DOMAIN_ALL) {
		domain_cnt =
			(domain_sel & RTE_LCORE_DOMAIN_IO) ? topo_cnfg.io_count :
			(domain_sel & RTE_LCORE_DOMAIN_L4) ? topo_cnfg.l4_count :
			(domain_sel & RTE_LCORE_DOMAIN_L3) ? topo_cnfg.l3_count :
			(domain_sel & RTE_LCORE_DOMAIN_L2) ? topo_cnfg.l2_count :
			(domain_sel & RTE_LCORE_DOMAIN_L1) ? topo_cnfg.l1_count : 0;
	}
#endif

	return domain_cnt;
}

unsigned int
rte_lcore_count_from_domain(unsigned int domain_sel __rte_unused,
unsigned int domain_indx __rte_unused)
{
	unsigned int core_cnt = 0;

#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
	unsigned int domain_cnt = 0;

	if ((domain_sel & RTE_LCORE_DOMAIN_ALL) == 0)
		return core_cnt;

	domain_cnt = rte_get_domain_count(domain_sel);

	if (domain_cnt == 0)
		return core_cnt;

	if ((domain_indx != RTE_LCORE_DOMAIN_LCORES_ALL) && (domain_indx >= domain_cnt))
		return core_cnt;

	core_cnt = (domain_sel & RTE_LCORE_DOMAIN_IO) ? topo_cnfg.io_core_count :
			(domain_sel & RTE_LCORE_DOMAIN_L4) ? topo_cnfg.l3_core_count :
			(domain_sel & RTE_LCORE_DOMAIN_L3) ? topo_cnfg.l3_core_count :
			(domain_sel & RTE_LCORE_DOMAIN_L2) ? topo_cnfg.l2_core_count :
			(domain_sel & RTE_LCORE_DOMAIN_L1) ? topo_cnfg.l1_core_count : 0;

	if ((domain_indx != RTE_LCORE_DOMAIN_LCORES_ALL) && (core_cnt)) {
		struct core_domain_mapping *ptr = get_domain_lcore_mapping(domain_sel, domain_indx);
		core_cnt = ptr->core_count;
	}
#endif

	return core_cnt;
}

unsigned int
rte_get_lcore_in_domain(unsigned int domain_sel __rte_unused,
unsigned int domain_indx __rte_unused, unsigned int lcore_pos __rte_unused)
{
	uint16_t sel_core = RTE_MAX_LCORE;

#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
	unsigned int domain_cnt = 0;
	unsigned int core_cnt = 0;

	if (domain_sel & RTE_LCORE_DOMAIN_ALL) {
		domain_cnt = rte_get_domain_count(domain_sel);
		if (domain_cnt == 0)
			return sel_core;

		core_cnt = rte_lcore_count_from_domain(domain_sel, RTE_LCORE_DOMAIN_LCORES_ALL);
		if (core_cnt == 0)
			return sel_core;

		struct core_domain_mapping *ptr = get_domain_lcore_mapping(domain_sel, domain_indx);
		if ((ptr) && (ptr->core_count)) {
			if (lcore_pos < ptr->core_count)
				sel_core = ptr->cores[lcore_pos];
		}
	}
#endif

	return sel_core;
}

rte_cpuset_t
rte_lcore_cpuset_in_domain(unsigned int domain_sel __rte_unused,
unsigned int domain_indx __rte_unused)
{
	rte_cpuset_t ret_cpu_set;
	CPU_ZERO(&ret_cpu_set);

#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
	struct core_domain_mapping *ptr = NULL;
	unsigned int domain_count = rte_get_domain_count(domain_sel);

	if ((domain_count == 0) || (domain_indx > domain_count))
		return ret_cpu_set;

	ptr = get_domain_lcore_mapping(domain_sel, domain_indx);
	if (ptr->core_count == 0)
		return ret_cpu_set;

	CPU_OR(&ret_cpu_set, &ret_cpu_set, &ptr->core_set);
#endif

	return ret_cpu_set;
}

bool
rte_lcore_is_main_in_domain(unsigned int domain_sel __rte_unused,
unsigned int domain_indx __rte_unused)
{
	bool is_main_in_domain = false;

#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
	struct core_domain_mapping *ptr = NULL;
	unsigned int main_lcore = rte_get_main_lcore();
	unsigned int domain_count = rte_get_domain_count(domain_sel);

	if ((domain_count == 0) || (domain_indx > domain_count))
		return is_main_in_domain;

	ptr = get_domain_lcore_mapping(domain_sel, domain_indx);
	if (ptr->core_count == 0)
		return is_main_in_domain;

	is_main_in_domain = CPU_ISSET(main_lcore, &ptr->core_set);
#endif

	return is_main_in_domain;
}

unsigned int
rte_get_next_lcore_from_domain(unsigned int indx __rte_unused,
int skip_main __rte_unused, int wrap __rte_unused, uint32_t flag __rte_unused)
{
	if (indx >= RTE_MAX_LCORE) {
#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
		if (get_domain_lcore_count(flag) == 0)
			return RTE_MAX_LCORE;
#endif
		indx = rte_get_next_lcore(-1, skip_main, wrap);
		return indx;
	}
	uint16_t usr_lcore = indx % RTE_MAX_LCORE;
	uint16_t sel_domain_core = RTE_MAX_LCORE;

	EAL_LOG(DEBUG, "lcore (%u), skip main lcore (%d), wrap (%d), flag (%u)",
		usr_lcore, skip_main, wrap, flag);

	/* check the input lcore indx */
	if (!rte_lcore_is_enabled(indx)) {
		EAL_LOG(ERR, "User input lcore (%u) is not enabled!!!", indx);
		return sel_domain_core;
	}

	if ((rte_lcore_count() == 1)) {
		EAL_LOG(DEBUG, "only 1 lcore in dpdk process!!!");
		sel_domain_core = wrap ? indx : sel_domain_core;
		return sel_domain_core;
	}

#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
	uint16_t main_lcore = rte_get_main_lcore();
	uint16_t sel_domain = 0xffff;
	uint16_t sel_domain_core_index = 0xffff;
	uint16_t sel_domain_core_count = 0;

	struct core_domain_mapping *ptr = NULL;
	uint16_t domain_count = 0;
	uint16_t domain_core_count = 0;
	uint16_t *domain_core_list = NULL;

	domain_count = rte_get_domain_count(flag);
	if (domain_count == 0) {
		EAL_LOG(DEBUG, "No domain found for cores with flag (%u)!!!", flag);
		return sel_domain_core;
	}

	/* identify the lcore to get the domain to start from */
	for (int i = 0; (i < domain_count) && (sel_domain_core_index == 0xffff); i++) {
		ptr = get_domain_lcore_mapping(flag, i);

		domain_core_count = ptr->core_count;
		domain_core_list = ptr->cores;

		for (int j = 0; j < domain_core_count; j++) {
			if (usr_lcore == domain_core_list[j]) {
				sel_domain_core_index = j;
				sel_domain_core_count = domain_core_count;
				sel_domain = i;
				break;
			}
		}
	}

	if (sel_domain_core_count == 1) {
		EAL_LOG(DEBUG, "there is no more lcore in the domain!!!");
		return sel_domain_core;
	}

	EAL_LOG(DEBUG, "selected: domain (%u), core: count %u, index %u, core: current %u",
		sel_domain, sel_domain_core_count, sel_domain_core_index,
		domain_core_list[sel_domain_core_index]);

	/* get next lcore from the selected domain */
	/* next lcore is always `sel_domain_core_index + 1`, but needs boundary check */
	bool lcore_found = false;
	uint16_t next_domain_lcore_index = sel_domain_core_index + 1;
	while (false == lcore_found) {

		if (next_domain_lcore_index >= sel_domain_core_count) {
			if (wrap) {
				next_domain_lcore_index = 0;
				continue;
			}
			break;
		}

		/* check if main lcore skip */
		if ((domain_core_list[next_domain_lcore_index] == main_lcore) && (skip_main)) {
			next_domain_lcore_index += 1;
			continue;
		}

		lcore_found = true;
	}
	if (true == lcore_found)
		sel_domain_core = domain_core_list[next_domain_lcore_index];
#endif

	EAL_LOG(DEBUG, "Selected core (%u)", sel_domain_core);
	return sel_domain_core;
}

unsigned int
rte_get_next_lcore_from_next_domain(unsigned int indx __rte_unused,
int skip_main __rte_unused, int wrap __rte_unused,
uint32_t flag __rte_unused, int cores_to_skip __rte_unused)
{
	if (indx >= RTE_MAX_LCORE) {
#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
		if (get_domain_lcore_count(flag) == 0)
			return RTE_MAX_LCORE;
#endif
		indx = rte_get_next_lcore(-1, skip_main, wrap);
		return indx;
	}

	uint16_t sel_domain_core = RTE_MAX_LCORE;
	uint16_t usr_lcore = indx % RTE_MAX_LCORE;

	EAL_LOG(DEBUG, "lcore (%u), skip main lcore (%d), wrap (%d), flag (%u)",
		usr_lcore, skip_main, wrap, flag);

	/* check the input lcore indx */
	if (!rte_lcore_is_enabled(indx)) {
		EAL_LOG(DEBUG, "User input lcore (%u) is not enabled!!!", indx);
		return sel_domain_core;
	}

#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
	uint16_t main_lcore = rte_get_main_lcore();

	uint16_t sel_domain = 0xffff;
	uint16_t sel_domain_core_index = 0xffff;

	uint16_t domain_count = 0;
	uint16_t domain_core_count = 0;
	uint16_t *domain_core_list = NULL;

	domain_count = rte_get_domain_count(flag);
	if (domain_count == 0) {
		EAL_LOG(DEBUG, "No Domains found for the flag (%u)!!!", flag);
		return sel_domain_core;
	}

	/* identify the lcore to get the domain to start from */
	struct core_domain_mapping *ptr = NULL;
	for (int i = 0; (i < domain_count) && (sel_domain_core_index == 0xffff); i++) {
		ptr = get_domain_lcore_mapping(flag, i);
		domain_core_count = ptr->core_count;
		domain_core_list = ptr->cores;

		for (int j = 0; j < domain_core_count; j++) {
			if (usr_lcore == domain_core_list[j]) {
				sel_domain_core_index = j;
				sel_domain = i;
				break;
			}
		}
	}

	if (sel_domain_core_index == 0xffff) {
		EAL_LOG(DEBUG, "Invalid lcore %u for the flag (%u)!!!", indx, flag);
		return sel_domain_core;
	}

	EAL_LOG(DEBUG, "Selected - core_index (%u); domain (%u), core_count (%u), cores (%p)",
		sel_domain_core_index, sel_domain, domain_core_count, domain_core_list);

	uint16_t skip_cores = (cores_to_skip >= 0) ? cores_to_skip : (0 - cores_to_skip);

	/* get the next domain & valid lcore */
	sel_domain = (((1 + sel_domain) == domain_count) && (wrap)) ? 0 : (1 + sel_domain);
	sel_domain_core_index = 0xffff;

	bool iter_loop = false;
	for (int i = sel_domain; (i < domain_count) && (sel_domain_core == RTE_MAX_LCORE); i++) {
		ptr = get_domain_lcore_mapping(flag, i);

		domain_core_count = ptr->core_count;
		domain_core_list = ptr->cores;

		/* check if we have cores to iterate from this domain */
		if (skip_cores >= domain_core_count)
			continue;

		if (((1 + sel_domain) == domain_count) && (wrap)) {
			if (iter_loop == true)
				break;

			iter_loop = true;
		}

		sel_domain_core_index = (cores_to_skip >= 0) ? skip_cores :
					(domain_core_count - skip_cores);
		sel_domain_core = domain_core_list[sel_domain_core_index];

		if ((skip_main) && (sel_domain_core == main_lcore)) {
			sel_domain_core_index = 0xffff;
			sel_domain_core = RTE_MAX_LCORE;
			continue;
		}
	}
#endif

	EAL_LOG(DEBUG, "Selected core (%u)", sel_domain_core);
	return sel_domain_core;
}

unsigned int
rte_lcore_to_socket_id(unsigned int lcore_id)
{
	return lcore_config[lcore_id].socket_id;
}

static int
socket_id_cmp(const void *a, const void *b)
{
	const int *lcore_id_a = a;
	const int *lcore_id_b = b;

	if (*lcore_id_a < *lcore_id_b)
		return -1;
	if (*lcore_id_a > *lcore_id_b)
		return 1;
	return 0;
}



/*
 * Use HWLOC library to parse L1|L2|L3|NUMA-IO on the running target machine.
 * Store the topology structure in memory.
 */
int
rte_eal_topology_init(void)
{
#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
	memset(&topo_cnfg, 0, sizeof(struct topology_config));

	hwloc_topology_init(&topo_cnfg.topology);
	hwloc_topology_load(topo_cnfg.topology);

	int l1_depth = hwloc_get_type_depth(topo_cnfg.topology, HWLOC_OBJ_L1CACHE);
	int l2_depth = hwloc_get_type_depth(topo_cnfg.topology, HWLOC_OBJ_L2CACHE);
	int l3_depth = hwloc_get_type_depth(topo_cnfg.topology, HWLOC_OBJ_L3CACHE);
	int l4_depth = hwloc_get_type_depth(topo_cnfg.topology, HWLOC_OBJ_L4CACHE);
	int io_depth = hwloc_get_type_depth(topo_cnfg.topology, HWLOC_OBJ_NUMANODE);

	EAL_LOG(DEBUG, "TOPOLOGY - depth: l1 %d, l2 %d, l3 %d, l4 %d, io %d",
		l1_depth, l2_depth, l3_depth, l4_depth, io_depth);

	topo_cnfg.l1_count = hwloc_get_nbobjs_by_depth(topo_cnfg.topology, l1_depth);
	topo_cnfg.l2_count = hwloc_get_nbobjs_by_depth(topo_cnfg.topology, l2_depth);
	topo_cnfg.l3_count = hwloc_get_nbobjs_by_depth(topo_cnfg.topology, l3_depth);
	topo_cnfg.l4_count = hwloc_get_nbobjs_by_depth(topo_cnfg.topology, l4_depth);
	topo_cnfg.io_count = hwloc_get_nbobjs_by_depth(topo_cnfg.topology, io_depth);

	EAL_LOG(DEBUG, "TOPOLOGY - obj count: l1 %d, l2 %d, l3 %d, l4 %d, io %d",
		topo_cnfg.l1_count, topo_cnfg.l2_count,
		topo_cnfg.l3_count, topo_cnfg.l4_count,
		topo_cnfg.io_count);

	if ((l1_depth) && (topo_cnfg.l1_count)) {
		topo_cnfg.l1 = rte_malloc(NULL,
				sizeof(struct core_domain_mapping *) * topo_cnfg.l1_count, 0);
		if (topo_cnfg.l1 == NULL) {
			rte_eal_topology_release();
			return -1;
		}

		for (int j = 0; j < topo_cnfg.l1_count; j++) {
			hwloc_obj_t obj = hwloc_get_obj_by_depth(topo_cnfg.topology, l1_depth, j);
			unsigned int first_cpu = hwloc_bitmap_first(obj->cpuset);
			unsigned int cpu_count = hwloc_bitmap_weight(obj->cpuset);

			topo_cnfg.l1[j] = rte_malloc(NULL, sizeof(struct core_domain_mapping), 0);
			if (topo_cnfg.l1[j] == NULL) {
				rte_eal_topology_release();
				return -1;
			}

			topo_cnfg.l1[j]->core_count = 0;
			topo_cnfg.l1[j]->cores = rte_malloc(NULL, sizeof(uint16_t) * cpu_count, 0);
			if (topo_cnfg.l1[j]->cores == NULL) {
				rte_eal_topology_release();
				return -1;
			}

			signed int cpu_id = first_cpu;
			unsigned int cpu_index = 0;
			do {
				if (rte_lcore_is_enabled(cpu_id)) {
					EAL_LOG(DEBUG, " L1|SMT domain (%u) lcore %u", j, cpu_id);
					topo_cnfg.l1[j]->cores[cpu_index] = cpu_id;
					cpu_index++;

					CPU_SET(cpu_id, &topo_cnfg.l1[j]->core_set);
					topo_cnfg.l1[j]->core_count += 1;
					topo_cnfg.l1_core_count += 1;
				}
				cpu_id = hwloc_bitmap_next(obj->cpuset, cpu_id);
				cpu_count -= 1;
			} while ((cpu_id != -1) && (cpu_count));
		}
	}

	if ((l2_depth) && (topo_cnfg.l2_count)) {
		topo_cnfg.l2 = rte_malloc(NULL,
				sizeof(struct core_domain_mapping *) * topo_cnfg.l2_count, 0);
		if (topo_cnfg.l2 == NULL) {
			rte_eal_topology_release();
			return -1;
		}

		for (int j = 0; j < topo_cnfg.l2_count; j++) {
			hwloc_obj_t obj = hwloc_get_obj_by_depth(topo_cnfg.topology, l2_depth, j);
			unsigned int first_cpu = hwloc_bitmap_first(obj->cpuset);
			unsigned int cpu_count = hwloc_bitmap_weight(obj->cpuset);

			topo_cnfg.l2[j] = rte_malloc(NULL, sizeof(struct core_domain_mapping), 0);
			if (topo_cnfg.l2[j] == NULL) {
				rte_eal_topology_release();
				return -1;
			}

			topo_cnfg.l2[j]->core_count = 0;
			topo_cnfg.l2[j]->cores = rte_malloc(NULL, sizeof(uint16_t) * cpu_count, 0);
			if (topo_cnfg.l2[j]->cores == NULL) {
				rte_eal_topology_release();
				return -1;
			}

			signed int cpu_id = first_cpu;
			unsigned int cpu_index = 0;
			do {
				if (rte_lcore_is_enabled(cpu_id)) {
					EAL_LOG(DEBUG, " L2 domain (%u) lcore %u", j, cpu_id);
					topo_cnfg.l2[j]->cores[cpu_index] = cpu_id;
					cpu_index++;

					CPU_SET(cpu_id, &topo_cnfg.l2[j]->core_set);
					topo_cnfg.l2[j]->core_count += 1;
					topo_cnfg.l2_core_count += 1;
				}
				cpu_id = hwloc_bitmap_next(obj->cpuset, cpu_id);
				cpu_count -= 1;
			} while ((cpu_id != -1) && (cpu_count));
		}
	}

	if ((l3_depth) && (topo_cnfg.l3_count)) {
		topo_cnfg.l3 = rte_malloc(NULL,
				sizeof(struct core_domain_mapping *) * topo_cnfg.l3_count, 0);
		if (topo_cnfg.l3 == NULL) {
			rte_eal_topology_release();
			return -1;
		}

		for (int j = 0; j < topo_cnfg.l3_count; j++) {
			hwloc_obj_t obj = hwloc_get_obj_by_depth(topo_cnfg.topology, l3_depth, j);
			unsigned int first_cpu = hwloc_bitmap_first(obj->cpuset);
			unsigned int cpu_count = hwloc_bitmap_weight(obj->cpuset);

			topo_cnfg.l3[j] = rte_malloc(NULL, sizeof(struct core_domain_mapping), 0);
			if (topo_cnfg.l3[j] == NULL) {
				rte_eal_topology_release();
				return -1;
			}

			topo_cnfg.l3[j]->core_count = 0;
			topo_cnfg.l3[j]->cores = rte_malloc(NULL, sizeof(uint16_t) * cpu_count, 0);
			if (topo_cnfg.l3[j]->cores == NULL) {
				rte_eal_topology_release();
				return -1;
			}

			signed int cpu_id = first_cpu;
			unsigned int cpu_index = 0;
			do {
				if (rte_lcore_is_enabled(cpu_id)) {
					EAL_LOG(DEBUG, " L3 domain (%u) lcore %u", j, cpu_id);
					topo_cnfg.l3[j]->cores[cpu_index] = cpu_id;
					cpu_index++;

					CPU_SET(cpu_id, &topo_cnfg.l3[j]->core_set);
					topo_cnfg.l3[j]->core_count += 1;
					topo_cnfg.l3_core_count += 1;
				}
				cpu_id = hwloc_bitmap_next(obj->cpuset, cpu_id);
				cpu_count -= 1;
			} while ((cpu_id != -1) && (cpu_count));
		}
	}

	if ((l4_depth) && (topo_cnfg.l4_count)) {
		topo_cnfg.l4 = rte_malloc(NULL,
				sizeof(struct core_domain_mapping *) * topo_cnfg.l4_count, 0);
		if (topo_cnfg.l4 == NULL) {
			rte_eal_topology_release();
			return -1;
		}

		for (int j = 0; j < topo_cnfg.l4_count; j++) {
			hwloc_obj_t obj = hwloc_get_obj_by_depth(topo_cnfg.topology, l4_depth, j);
			unsigned int first_cpu = hwloc_bitmap_first(obj->cpuset);
			unsigned int cpu_count = hwloc_bitmap_weight(obj->cpuset);

			topo_cnfg.l4[j] = rte_malloc(NULL, sizeof(struct core_domain_mapping), 0);
			if (topo_cnfg.l4[j] == NULL) {
				rte_eal_topology_release();
				return -1;
			}

			topo_cnfg.l4[j]->core_count = 0;
			topo_cnfg.l4[j]->cores = rte_malloc(NULL, sizeof(uint16_t) * cpu_count, 0);
			if (topo_cnfg.l4[j]->cores == NULL) {
				rte_eal_topology_release();
				return -1;
			}

			signed int cpu_id = first_cpu;
			unsigned int cpu_index = 0;
			do {
				if (rte_lcore_is_enabled(cpu_id)) {
					EAL_LOG(DEBUG, " L4 domain (%u) lcore %u", j, cpu_id);
					topo_cnfg.l4[j]->cores[cpu_index] = cpu_id;
					cpu_index++;

					CPU_SET(cpu_id, &topo_cnfg.l3[j]->core_set);
					topo_cnfg.l4[j]->core_count += 1;
					topo_cnfg.l4_core_count += 1;
				}
				cpu_id = hwloc_bitmap_next(obj->cpuset, cpu_id);
				cpu_count -= 1;
			} while ((cpu_id != -1) && (cpu_count));
		}
	}

	if ((io_depth) && (topo_cnfg.io_count)) {
		topo_cnfg.io = rte_malloc(NULL,
				sizeof(struct core_domain_mapping *) * topo_cnfg.io_count, 0);
		if (topo_cnfg.io == NULL) {
			rte_eal_topology_release();
			return -1;
		}

		for (int j = 0; j < topo_cnfg.io_count; j++) {
			hwloc_obj_t obj = hwloc_get_obj_by_depth(topo_cnfg.topology, io_depth, j);
			unsigned int first_cpu = hwloc_bitmap_first(obj->cpuset);
			unsigned int cpu_count = hwloc_bitmap_weight(obj->cpuset);

			topo_cnfg.io[j] = rte_malloc(NULL, sizeof(struct core_domain_mapping), 0);
			if (topo_cnfg.io[j] == NULL) {
				rte_eal_topology_release();
				return -1;
			}

			topo_cnfg.io[j]->core_count = 0;
			topo_cnfg.io[j]->cores = rte_malloc(NULL, sizeof(uint16_t) * cpu_count, 0);
			if (topo_cnfg.io[j]->cores == NULL) {
				rte_eal_topology_release();
				return -1;
			}

			signed int cpu_id = first_cpu;
			unsigned int cpu_index = 0;
			do {
				if (rte_lcore_is_enabled(cpu_id)) {
					EAL_LOG(DEBUG, " IO domain (%u) lcore %u", j, cpu_id);
					topo_cnfg.io[j]->cores[cpu_index] = cpu_id;
					cpu_index++;

					CPU_SET(cpu_id, &topo_cnfg.io[j]->core_set);
					topo_cnfg.io[j]->core_count += 1;
					topo_cnfg.io_core_count += 1;
				}
				cpu_id = hwloc_bitmap_next(obj->cpuset, cpu_id);
				cpu_count -= 1;
			} while ((cpu_id != -1) && (cpu_count));
		}
	}

	hwloc_topology_destroy(topo_cnfg.topology);
	topo_cnfg.topology = NULL;

	EAL_LOG(INFO, "TOPOLOGY - core count: l1 %u, l2 %u, l3 %u, l4 %u, io %u",
		topo_cnfg.l1_core_count, topo_cnfg.l2_core_count,
		topo_cnfg.l3_core_count, topo_cnfg.l4_core_count,
		topo_cnfg.io_core_count);
#endif

	return 0;
}

/*
 * release HWLOC topology structure memory
 */
int
rte_eal_topology_release(void)
{
#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
	EAL_LOG(DEBUG, "release l1 domain memory!");
	for (int i = 0; i < topo_cnfg.l1_count; i++) {
		if (topo_cnfg.l1[i]->cores) {
			rte_free(topo_cnfg.l1[i]->cores);
			topo_cnfg.l1[i]->core_count = 0;
		}
	}

	if (topo_cnfg.l1_count) {
		rte_free(topo_cnfg.l1);
		topo_cnfg.l1 = NULL;
		topo_cnfg.l1_count = 0;
	}

	EAL_LOG(DEBUG, "release l2 domain memory!");
	for (int i = 0; i < topo_cnfg.l2_count; i++) {
		if (topo_cnfg.l2[i]->cores) {
			rte_free(topo_cnfg.l2[i]->cores);
			topo_cnfg.l2[i]->core_count = 0;
		}
	}

	if (topo_cnfg.l2_count) {
		rte_free(topo_cnfg.l2);
		topo_cnfg.l2 = NULL;
		topo_cnfg.l2_count = 0;
	}

	EAL_LOG(DEBUG, "release l3 domain memory!");
	for (int i = 0; i < topo_cnfg.l3_count; i++) {
		if (topo_cnfg.l3[i]->cores) {
			rte_free(topo_cnfg.l3[i]->cores);
			topo_cnfg.l3[i]->core_count = 0;
		}
	}

	if (topo_cnfg.l3_count) {
		rte_free(topo_cnfg.l3);
		topo_cnfg.l3 = NULL;
		topo_cnfg.l3_count = 0;
	}

	EAL_LOG(DEBUG, "release l4 domain memory!");
	for (int i = 0; i < topo_cnfg.l4_count; i++) {
		if (topo_cnfg.l4[i]->cores) {
			rte_free(topo_cnfg.l4[i]->cores);
			topo_cnfg.l4[i]->core_count = 0;
		}
	}

	if (topo_cnfg.l4_count) {
		rte_free(topo_cnfg.l4);
		topo_cnfg.l4 = NULL;
		topo_cnfg.l4_count = 0;
	}

	EAL_LOG(DEBUG, "release IO domain memory!");
	for (int i = 0; i < topo_cnfg.io_count; i++) {
		if (topo_cnfg.io[i]->cores) {
			rte_free(topo_cnfg.io[i]->cores);
			topo_cnfg.io[i]->core_count = 0;
		}
	}

	if (topo_cnfg.io_count) {
		rte_free(topo_cnfg.io);
		topo_cnfg.io = NULL;
		topo_cnfg.io_count = 0;
	}
#endif

	return 0;
}

/*
 * Parse /sys/devices/system/cpu to get the number of physical and logical
 * processors on the machine. The function will fill the cpu_info
 * structure.
 */
int
rte_eal_cpu_init(void)
{
	/* pointer to global configuration */
	struct rte_config *config = rte_eal_get_configuration();
	unsigned lcore_id;
	unsigned count = 0;
	unsigned int socket_id, prev_socket_id;
	int lcore_to_socket_id[RTE_MAX_LCORE];

	/*
	 * Parse the maximum set of logical cores, detect the subset of running
	 * ones and enable them by default.
	 */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		lcore_config[lcore_id].core_index = count;

		/* init cpuset for per lcore config */
		CPU_ZERO(&lcore_config[lcore_id].cpuset);

		/* find socket first */
		socket_id = eal_cpu_socket_id(lcore_id);
		lcore_to_socket_id[lcore_id] = socket_id;

		if (eal_cpu_detected(lcore_id) == 0) {
			config->lcore_role[lcore_id] = ROLE_OFF;
			lcore_config[lcore_id].core_index = -1;
			continue;
		}

		/* By default, lcore 1:1 map to cpu id */
		CPU_SET(lcore_id, &lcore_config[lcore_id].cpuset);

		/* By default, each detected core is enabled */
		config->lcore_role[lcore_id] = ROLE_RTE;
		lcore_config[lcore_id].core_role = ROLE_RTE;
		lcore_config[lcore_id].core_id = eal_cpu_core_id(lcore_id);
		lcore_config[lcore_id].socket_id = socket_id;
		EAL_LOG(DEBUG, "Detected lcore %u as "
				"core %u on socket %u",
				lcore_id, lcore_config[lcore_id].core_id,
				lcore_config[lcore_id].socket_id);
		count++;
	}
	for (; lcore_id < CPU_SETSIZE; lcore_id++) {
		if (eal_cpu_detected(lcore_id) == 0)
			continue;
		EAL_LOG(DEBUG, "Skipped lcore %u as core %u on socket %u",
			lcore_id, eal_cpu_core_id(lcore_id),
			eal_cpu_socket_id(lcore_id));
	}

	/* Set the count of enabled logical cores of the EAL configuration */
	config->lcore_count = count;
	EAL_LOG(DEBUG,
			"Maximum logical cores by configuration: %u",
			RTE_MAX_LCORE);
	EAL_LOG(INFO, "Detected CPU lcores: %u", config->lcore_count);

	/* sort all socket id's in ascending order */
	qsort(lcore_to_socket_id, RTE_DIM(lcore_to_socket_id),
			sizeof(lcore_to_socket_id[0]), socket_id_cmp);

	prev_socket_id = -1;
	config->numa_node_count = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		socket_id = lcore_to_socket_id[lcore_id];
		if (socket_id != prev_socket_id)
			config->numa_nodes[config->numa_node_count++] =
					socket_id;
		prev_socket_id = socket_id;
	}
	EAL_LOG(INFO, "Detected NUMA nodes: %u", config->numa_node_count);

	return 0;
}

unsigned int
rte_socket_count(void)
{
	const struct rte_config *config = rte_eal_get_configuration();
	return config->numa_node_count;
}

int
rte_socket_id_by_idx(unsigned int idx)
{
	const struct rte_config *config = rte_eal_get_configuration();
	if (idx >= config->numa_node_count) {
		rte_errno = EINVAL;
		return -1;
	}
	return config->numa_nodes[idx];
}

static rte_rwlock_t lcore_lock = RTE_RWLOCK_INITIALIZER;
struct lcore_callback {
	TAILQ_ENTRY(lcore_callback) next;
	char *name;
	rte_lcore_init_cb init;
	rte_lcore_uninit_cb uninit;
	void *arg;
};
static TAILQ_HEAD(lcore_callbacks_head, lcore_callback) lcore_callbacks =
	TAILQ_HEAD_INITIALIZER(lcore_callbacks);

static int
callback_init(struct lcore_callback *callback, unsigned int lcore_id)
{
	if (callback->init == NULL)
		return 0;
	EAL_LOG(DEBUG, "Call init for lcore callback %s, lcore_id %u",
		callback->name, lcore_id);
	return callback->init(lcore_id, callback->arg);
}

static void
callback_uninit(struct lcore_callback *callback, unsigned int lcore_id)
{
	if (callback->uninit == NULL)
		return;
	EAL_LOG(DEBUG, "Call uninit for lcore callback %s, lcore_id %u",
		callback->name, lcore_id);
	callback->uninit(lcore_id, callback->arg);
}

static void
free_callback(struct lcore_callback *callback)
{
	free(callback->name);
	free(callback);
}

void *
rte_lcore_callback_register(const char *name, rte_lcore_init_cb init,
	rte_lcore_uninit_cb uninit, void *arg)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	struct lcore_callback *callback;
	unsigned int lcore_id;

	if (name == NULL)
		return NULL;
	callback = calloc(1, sizeof(*callback));
	if (callback == NULL)
		return NULL;
	if (asprintf(&callback->name, "%s-%p", name, arg) == -1) {
		free(callback);
		return NULL;
	}
	callback->init = init;
	callback->uninit = uninit;
	callback->arg = arg;
	rte_rwlock_write_lock(&lcore_lock);
	if (callback->init == NULL)
		goto no_init;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (cfg->lcore_role[lcore_id] == ROLE_OFF)
			continue;
		if (callback_init(callback, lcore_id) == 0)
			continue;
		/* Callback refused init for this lcore, uninitialize all
		 * previous lcore.
		 */
		while (lcore_id-- != 0) {
			if (cfg->lcore_role[lcore_id] == ROLE_OFF)
				continue;
			callback_uninit(callback, lcore_id);
		}
		free_callback(callback);
		callback = NULL;
		goto out;
	}
no_init:
	TAILQ_INSERT_TAIL(&lcore_callbacks, callback, next);
	EAL_LOG(DEBUG, "Registered new lcore callback %s (%sinit, %suninit).",
		callback->name, callback->init == NULL ? "NO " : "",
		callback->uninit == NULL ? "NO " : "");
out:
	rte_rwlock_write_unlock(&lcore_lock);
	return callback;
}

void
rte_lcore_callback_unregister(void *handle)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	struct lcore_callback *callback = handle;
	unsigned int lcore_id;

	if (callback == NULL)
		return;
	rte_rwlock_write_lock(&lcore_lock);
	if (callback->uninit == NULL)
		goto no_uninit;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (cfg->lcore_role[lcore_id] == ROLE_OFF)
			continue;
		callback_uninit(callback, lcore_id);
	}
no_uninit:
	TAILQ_REMOVE(&lcore_callbacks, callback, next);
	rte_rwlock_write_unlock(&lcore_lock);
	EAL_LOG(DEBUG, "Unregistered lcore callback %s-%p.",
		callback->name, callback->arg);
	free_callback(callback);
}

unsigned int
eal_lcore_non_eal_allocate(void)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	struct lcore_callback *callback;
	struct lcore_callback *prev;
	unsigned int lcore_id;

	rte_rwlock_write_lock(&lcore_lock);
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (cfg->lcore_role[lcore_id] != ROLE_OFF)
			continue;
		cfg->lcore_role[lcore_id] = ROLE_NON_EAL;
		cfg->lcore_count++;
		break;
	}
	if (lcore_id == RTE_MAX_LCORE) {
		EAL_LOG(DEBUG, "No lcore available.");
		goto out;
	}
	TAILQ_FOREACH(callback, &lcore_callbacks, next) {
		if (callback_init(callback, lcore_id) == 0)
			continue;
		/* Callback refused init for this lcore, call uninit for all
		 * previous callbacks.
		 */
		prev = TAILQ_PREV(callback, lcore_callbacks_head, next);
		while (prev != NULL) {
			callback_uninit(prev, lcore_id);
			prev = TAILQ_PREV(prev, lcore_callbacks_head, next);
		}
		EAL_LOG(DEBUG, "Initialization refused for lcore %u.",
			lcore_id);
		cfg->lcore_role[lcore_id] = ROLE_OFF;
		cfg->lcore_count--;
		lcore_id = RTE_MAX_LCORE;
		goto out;
	}
out:
	rte_rwlock_write_unlock(&lcore_lock);
	return lcore_id;
}

void
eal_lcore_non_eal_release(unsigned int lcore_id)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	struct lcore_callback *callback;

	rte_rwlock_write_lock(&lcore_lock);
	if (cfg->lcore_role[lcore_id] != ROLE_NON_EAL)
		goto out;
	TAILQ_FOREACH(callback, &lcore_callbacks, next)
		callback_uninit(callback, lcore_id);
	cfg->lcore_role[lcore_id] = ROLE_OFF;
	cfg->lcore_count--;
out:
	rte_rwlock_write_unlock(&lcore_lock);
}

int
rte_lcore_iterate(rte_lcore_iterate_cb cb, void *arg)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	unsigned int lcore_id;
	int ret = 0;

	rte_rwlock_read_lock(&lcore_lock);
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (cfg->lcore_role[lcore_id] == ROLE_OFF)
			continue;
		ret = cb(lcore_id, arg);
		if (ret != 0)
			break;
	}
	rte_rwlock_read_unlock(&lcore_lock);
	return ret;
}

static const char *
lcore_role_str(enum rte_lcore_role_t role)
{
	switch (role) {
	case ROLE_RTE:
		return "RTE";
	case ROLE_SERVICE:
		return "SERVICE";
	case ROLE_NON_EAL:
		return "NON_EAL";
	default:
		return "UNKNOWN";
	}
}

static rte_lcore_usage_cb lcore_usage_cb;

void
rte_lcore_register_usage_cb(rte_lcore_usage_cb cb)
{
	lcore_usage_cb = cb;
}

static float
calc_usage_ratio(const struct rte_lcore_usage *usage)
{
	return usage->total_cycles != 0 ?
		(usage->busy_cycles * 100.0) / usage->total_cycles : (float)0;
}

static int
lcore_dump_cb(unsigned int lcore_id, void *arg)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	char cpuset[RTE_CPU_AFFINITY_STR_LEN];
	struct rte_lcore_usage usage;
	rte_lcore_usage_cb usage_cb;
	char *usage_str = NULL;
	FILE *f = arg;
	int ret;

	/* The callback may not set all the fields in the structure, so clear it here. */
	memset(&usage, 0, sizeof(usage));
	/* Guard against concurrent modification of lcore_usage_cb. */
	usage_cb = lcore_usage_cb;
	if (usage_cb != NULL && usage_cb(lcore_id, &usage) == 0) {
		if (asprintf(&usage_str, ", busy cycles %"PRIu64"/%"PRIu64" (ratio %.02f%%)",
				usage.busy_cycles, usage.total_cycles,
				calc_usage_ratio(&usage)) < 0) {
			return -ENOMEM;
		}
	}
	ret = eal_thread_dump_affinity(&lcore_config[lcore_id].cpuset, cpuset,
		sizeof(cpuset));
	fprintf(f, "lcore %u, socket %u, role %s, cpuset %s%s%s\n", lcore_id,
		rte_lcore_to_socket_id(lcore_id),
		lcore_role_str(cfg->lcore_role[lcore_id]), cpuset,
		ret == 0 ? "" : "...", usage_str != NULL ? usage_str : "");
	free(usage_str);

	return 0;
}

void
rte_lcore_dump(FILE *f)
{
	rte_lcore_iterate(lcore_dump_cb, f);
}

#ifndef RTE_EXEC_ENV_WINDOWS
static int
lcore_telemetry_id_cb(unsigned int lcore_id, void *arg)
{
	struct rte_tel_data *d = arg;

	return rte_tel_data_add_array_int(d, lcore_id);
}

static int
handle_lcore_list(const char *cmd __rte_unused, const char *params __rte_unused,
	struct rte_tel_data *d)
{
	int ret;

	ret = rte_tel_data_start_array(d, RTE_TEL_INT_VAL);
	if (ret == 0)
		ret = rte_lcore_iterate(lcore_telemetry_id_cb, d);

	return ret;
}

struct lcore_telemetry_info {
	unsigned int lcore_id;
	struct rte_tel_data *d;
};

static void
format_usage_ratio(char *buf, uint16_t size, const struct rte_lcore_usage *usage)
{
	float ratio = calc_usage_ratio(usage);
	snprintf(buf, size, "%.02f%%", ratio);
}

static int
lcore_telemetry_info_cb(unsigned int lcore_id, void *arg)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	struct lcore_telemetry_info *info = arg;
	char ratio_str[RTE_TEL_MAX_STRING_LEN];
	struct rte_lcore_usage usage;
	struct rte_tel_data *cpuset;
	rte_lcore_usage_cb usage_cb;
	unsigned int cpu;

	if (lcore_id != info->lcore_id)
		return 0;

	rte_tel_data_start_dict(info->d);
	rte_tel_data_add_dict_int(info->d, "lcore_id", lcore_id);
	rte_tel_data_add_dict_int(info->d, "socket", rte_lcore_to_socket_id(lcore_id));
	rte_tel_data_add_dict_string(info->d, "role", lcore_role_str(cfg->lcore_role[lcore_id]));
	cpuset = rte_tel_data_alloc();
	if (cpuset == NULL)
		return -ENOMEM;
	rte_tel_data_start_array(cpuset, RTE_TEL_INT_VAL);
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &lcore_config[lcore_id].cpuset))
			rte_tel_data_add_array_int(cpuset, cpu);
	}
	rte_tel_data_add_dict_container(info->d, "cpuset", cpuset, 0);
	/* The callback may not set all the fields in the structure, so clear it here. */
	memset(&usage, 0, sizeof(usage));
	/* Guard against concurrent modification of lcore_usage_cb. */
	usage_cb = lcore_usage_cb;
	if (usage_cb != NULL && usage_cb(lcore_id, &usage) == 0) {
		rte_tel_data_add_dict_uint(info->d, "total_cycles", usage.total_cycles);
		rte_tel_data_add_dict_uint(info->d, "busy_cycles", usage.busy_cycles);
		format_usage_ratio(ratio_str, sizeof(ratio_str), &usage);
		rte_tel_data_add_dict_string(info->d, "usage_ratio", ratio_str);
	}

	/* Return non-zero positive value to stop iterating over lcore_id. */
	return 1;
}

static int
handle_lcore_info(const char *cmd __rte_unused, const char *params, struct rte_tel_data *d)
{
	struct lcore_telemetry_info info = { .d = d };
	unsigned long lcore_id;
	char *endptr;

	if (params == NULL)
		return -EINVAL;
	errno = 0;
	lcore_id = strtoul(params, &endptr, 10);
	if (errno)
		return -errno;
	if (*params == '\0' || *endptr != '\0' || lcore_id >= RTE_MAX_LCORE)
		return -EINVAL;

	info.lcore_id = lcore_id;

	return rte_lcore_iterate(lcore_telemetry_info_cb, &info);
}

struct lcore_telemetry_usage {
	struct rte_tel_data *lcore_ids;
	struct rte_tel_data *total_cycles;
	struct rte_tel_data *busy_cycles;
	struct rte_tel_data *usage_ratio;
};

static int
lcore_telemetry_usage_cb(unsigned int lcore_id, void *arg)
{
	char ratio_str[RTE_TEL_MAX_STRING_LEN];
	struct lcore_telemetry_usage *u = arg;
	struct rte_lcore_usage usage;
	rte_lcore_usage_cb usage_cb;

	/* The callback may not set all the fields in the structure, so clear it here. */
	memset(&usage, 0, sizeof(usage));
	/* Guard against concurrent modification of lcore_usage_cb. */
	usage_cb = lcore_usage_cb;
	if (usage_cb != NULL && usage_cb(lcore_id, &usage) == 0) {
		rte_tel_data_add_array_uint(u->lcore_ids, lcore_id);
		rte_tel_data_add_array_uint(u->total_cycles, usage.total_cycles);
		rte_tel_data_add_array_uint(u->busy_cycles, usage.busy_cycles);
		format_usage_ratio(ratio_str, sizeof(ratio_str), &usage);
		rte_tel_data_add_array_string(u->usage_ratio, ratio_str);
	}

	return 0;
}

static int
handle_lcore_usage(const char *cmd __rte_unused, const char *params __rte_unused,
	struct rte_tel_data *d)
{
	struct lcore_telemetry_usage usage;
	struct rte_tel_data *total_cycles;
	struct rte_tel_data *busy_cycles;
	struct rte_tel_data *usage_ratio;
	struct rte_tel_data *lcore_ids;

	lcore_ids = rte_tel_data_alloc();
	total_cycles = rte_tel_data_alloc();
	busy_cycles = rte_tel_data_alloc();
	usage_ratio = rte_tel_data_alloc();
	if (lcore_ids == NULL || total_cycles == NULL || busy_cycles == NULL ||
	    usage_ratio == NULL) {
		rte_tel_data_free(lcore_ids);
		rte_tel_data_free(total_cycles);
		rte_tel_data_free(busy_cycles);
		rte_tel_data_free(usage_ratio);
		return -ENOMEM;
	}

	rte_tel_data_start_dict(d);
	rte_tel_data_start_array(lcore_ids, RTE_TEL_UINT_VAL);
	rte_tel_data_start_array(total_cycles, RTE_TEL_UINT_VAL);
	rte_tel_data_start_array(busy_cycles, RTE_TEL_UINT_VAL);
	rte_tel_data_start_array(usage_ratio, RTE_TEL_STRING_VAL);
	rte_tel_data_add_dict_container(d, "lcore_ids", lcore_ids, 0);
	rte_tel_data_add_dict_container(d, "total_cycles", total_cycles, 0);
	rte_tel_data_add_dict_container(d, "busy_cycles", busy_cycles, 0);
	rte_tel_data_add_dict_container(d, "usage_ratio", usage_ratio, 0);
	usage.lcore_ids = lcore_ids;
	usage.total_cycles = total_cycles;
	usage.busy_cycles = busy_cycles;
	usage.usage_ratio = usage_ratio;

	return rte_lcore_iterate(lcore_telemetry_usage_cb, &usage);
}

RTE_INIT(lcore_telemetry)
{
	rte_telemetry_register_cmd("/eal/lcore/list", handle_lcore_list,
		"List of lcore ids. Takes no parameters");
	rte_telemetry_register_cmd("/eal/lcore/info", handle_lcore_info,
		"Returns lcore info. Parameters: int lcore_id");
	rte_telemetry_register_cmd("/eal/lcore/usage", handle_lcore_usage,
		"Returns lcore cycles usage. Takes no parameters");
}
#endif /* !RTE_EXEC_ENV_WINDOWS */
