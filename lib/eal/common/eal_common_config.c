/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Mellanox Technologies, Ltd
 */

#include <pthread.h>

#include <rte_string_fns.h>
#include <rte_thread.h>
#include <eal_export.h>
#include "eal_internal_cfg.h"
#include "eal_private.h"
#include "eal_filesystem.h"
#include "eal_hugepages.h"
#include "eal_memcfg.h"

/* early configuration structure, when memory config is not mmapped */
static struct rte_mem_config early_mem_config = {
	.mlock = RTE_RWLOCK_INITIALIZER,
	.qlock = RTE_RWLOCK_INITIALIZER,
	.mplock = RTE_RWLOCK_INITIALIZER,
	.tlock = RTE_SPINLOCK_INITIALIZER,
	.ethdev_lock = RTE_SPINLOCK_INITIALIZER,
	.memory_hotplug_lock = RTE_RWLOCK_INITIALIZER,
};

/* platform-specific runtime dir */
static char runtime_dir[UNIX_PATH_MAX];

/* user-provided EAL configuration */
static struct eal_user_cfg eal_user_cfg;

/* internal runtime configuration */
static struct eal_runtime_state eal_runtime_state = {
	.mem_config = &early_mem_config,
};

RTE_EXPORT_SYMBOL(rte_eal_get_runtime_dir)
const char *
rte_eal_get_runtime_dir(void)
{
	return runtime_dir;
}

int
eal_set_runtime_dir(const char *run_dir)
{
	/* runtime directory limited by maximum allowable unix domain socket */
	if (strlcpy(runtime_dir, run_dir, UNIX_PATH_MAX) >= UNIX_PATH_MAX) {
		EAL_LOG(ERR, "Runtime directory string too long");
		return -1;
	}

	return 0;
}

/* Return a pointer to the memory config structure */
struct rte_mem_config *
eal_get_mcfg(void)
{
	return eal_get_runtime_state()->mem_config;
}

/* Return a pointer to the user configuration structure */
struct eal_user_cfg *
eal_get_user_configuration(void)
{
	return &eal_user_cfg;
}

/* Return a pointer to the platform state structure */
const struct eal_platform_info *
eal_get_platform_info(void)
{
	/* platform-discovered and runtime EAL state */
	static struct eal_platform_info eal_platform_info;
	static rte_spinlock_t init_lock = RTE_SPINLOCK_INITIALIZER;
	static RTE_ATOMIC(bool) initialized;

	if (unlikely(!rte_atomic_load_explicit(&initialized, rte_memory_order_acquire))) {
		struct eal_platform_info discovered_info = { 0 };

		rte_spinlock_lock(&init_lock);
		if (rte_atomic_load_explicit(&initialized, rte_memory_order_relaxed)) {
			rte_spinlock_unlock(&init_lock);
			return &eal_platform_info;
		}
		if (rte_eal_cpu_init(&discovered_info) < 0) {
			EAL_LOG(ERR, "Failed to initialise CPU information");
			goto fail;
		}
		if (eal_get_platform_hp_info(&discovered_info) < 0) {
			EAL_LOG(ERR, "Failed to get platform hugepage information");
			goto fail;
		}
		eal_platform_info = discovered_info;
		rte_atomic_store_explicit(&initialized, true, rte_memory_order_release);
		rte_spinlock_unlock(&init_lock);
		return &eal_platform_info;

fail:
		free(discovered_info.cpu_info);
		free(discovered_info.numa_nodes);
		rte_spinlock_unlock(&init_lock);
		return NULL;
	}

	return &eal_platform_info;
}

/* Return a pointer to the runtime state structure */
struct eal_runtime_state *
eal_get_runtime_state(void)
{
	return &eal_runtime_state;
}

RTE_EXPORT_SYMBOL(rte_eal_iova_mode)
enum rte_iova_mode
rte_eal_iova_mode(void)
{
	return eal_get_runtime_state()->iova_mode;
}

/* Get the EAL base address */
RTE_EXPORT_INTERNAL_SYMBOL(rte_eal_get_baseaddr)
uint64_t
rte_eal_get_baseaddr(void)
{
	return (eal_user_cfg.base_virtaddr != 0) ?
		       (uint64_t) eal_user_cfg.base_virtaddr :
		       eal_get_baseaddr();
}

RTE_EXPORT_SYMBOL(rte_eal_process_type)
enum rte_proc_type_t
rte_eal_process_type(void)
{
	return eal_get_runtime_state()->process_type;
}

/* Return user provided mbuf pool ops name */
RTE_EXPORT_SYMBOL(rte_eal_mbuf_user_pool_ops)
const char *
rte_eal_mbuf_user_pool_ops(void)
{
	return eal_user_cfg.user_mbuf_pool_ops_name;
}

/* return non-zero if hugepages are enabled. */
RTE_EXPORT_SYMBOL(rte_eal_has_hugepages)
int
rte_eal_has_hugepages(void)
{
	return !eal_user_cfg.no_hugetlbfs;
}

RTE_EXPORT_SYMBOL(rte_eal_has_pci)
int
rte_eal_has_pci(void)
{
	return !eal_user_cfg.no_pci;
}

static void
compute_ctrl_threads_cpuset(void)
{
	struct eal_runtime_state *runtime_state = eal_get_runtime_state();
	rte_cpuset_t *cpuset = &runtime_state->ctrl_cpuset;
	rte_cpuset_t default_set;
	unsigned int lcore_id;

	CPU_ZERO(cpuset);
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_has_role(lcore_id, ROLE_OFF))
			continue;
		RTE_CPU_OR(cpuset, cpuset, &runtime_state->lcore_cfg[lcore_id].cpuset);
	}
	RTE_CPU_NOT(cpuset, cpuset);

	if (rte_thread_get_affinity_by_id(rte_thread_self(), &default_set) != 0)
		CPU_ZERO(&default_set);

	RTE_CPU_AND(cpuset, cpuset, &default_set);

	/* if no remaining cpu, use main lcore cpu affinity */
	if (!CPU_COUNT(cpuset)) {
		memcpy(cpuset, &runtime_state->lcore_cfg[rte_get_main_lcore()].cpuset,
			sizeof(*cpuset));
	}

	/* log the computed control thread cpuset for debugging */
	char *cpuset_str = eal_cpuset_to_str(cpuset);
	if (cpuset_str != NULL) {
		EAL_LOG(DEBUG, "Control threads will use cores: %s", cpuset_str);
		free(cpuset_str);
	}
}

static int
eal_apply_lcore_config(void)
{
	const struct eal_user_cfg *user_cfg = eal_get_user_configuration();

	/* lcore_cpusets[] is always populated at parse time for all input forms */
	struct eal_runtime_state *runtime_state = eal_get_runtime_state();
	unsigned int i;
	unsigned int count = 0;

	rte_bitset_clear_all(runtime_state->core_indices, RTE_MAX_LCORE);
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		if (user_cfg->lcore_cpusets[i] == NULL) {
			runtime_state->lcore_cfg[i].role = ROLE_OFF;
			runtime_state->lcore_cfg[i].core_index = -1;
			CPU_ZERO(&runtime_state->lcore_cfg[i].cpuset);
			runtime_state->lcore_cfg[i].first_cpu = UINT16_MAX;
			continue;
		}
		rte_bitset_set(runtime_state->core_indices, count);
		runtime_state->lcore_cfg[i].role = ROLE_RTE;
		runtime_state->lcore_cfg[i].core_index = count++;
		memcpy(&runtime_state->lcore_cfg[i].cpuset,
			user_cfg->lcore_cpusets[i], sizeof(rte_cpuset_t));
		runtime_state->lcore_cfg[i].first_cpu =
			(uint16_t)(RTE_CPU_FFS(&runtime_state->lcore_cfg[i].cpuset) - 1);
	}
	if (count == 0) {
		EAL_LOG(ERR, "No valid lcores in core list");
		return -1;
	}
	runtime_state->lcore_count = count;
	return 0;
}

int
eal_apply_runtime_state(void)
{
	const struct eal_user_cfg *user_cfg = eal_get_user_configuration();
	struct eal_runtime_state *runtime_state = eal_get_runtime_state();

	for (unsigned int i = 0; i < MAX_HUGEPAGE_SIZES; i++)
		runtime_state->hugepage_info[i].lock_descriptor = -1;

	if (eal_apply_lcore_config() < 0)
		return -1;

	/* Apply service core roles: service_cpuset bits are lcore IDs */
	if (CPU_COUNT(&user_cfg->service_cpuset) > 0) {
		unsigned int i;
		char *cpuset_str;

		for (i = 0; i < RTE_MAX_LCORE; i++) {
			if (!CPU_ISSET(i, &user_cfg->service_cpuset))
				continue;
			if (eal_cpu_detected(i) == 0) {
				EAL_LOG(ERR, "Requested service lcore %u unavailable", i);
				return -1;
			}
			if (runtime_state->lcore_cfg[i].role != ROLE_RTE) {
				EAL_LOG(WARNING,
					"service lcore %u is not in the enabled lcore set; please ensure -c or -l includes service cores",
					i);
			}
			runtime_state->lcore_cfg[i].role = ROLE_SERVICE;
		}
		cpuset_str = eal_cpuset_to_str(&user_cfg->service_cpuset);
		if (cpuset_str != NULL) {
			EAL_LOG(DEBUG, "Service cores configured: %s", cpuset_str);
			free(cpuset_str);
		}
	}

	/* set the main lcore */
	if (user_cfg->main_lcore != -1) {
		runtime_state->main_lcore = user_cfg->main_lcore;
	} else {
		/* default main lcore is the first one */
		runtime_state->main_lcore = rte_get_next_lcore(-1, 0, 0);
		if (runtime_state->main_lcore >= RTE_MAX_LCORE) {
			EAL_LOG(ERR, "Main lcore is not enabled for DPDK");
			return -1;
		}
	}

#ifndef RTE_EXEC_ENV_WINDOWS
	/* create runtime data directory. In no_shconf mode, skip any errors */
	if (eal_create_runtime_dir() < 0) {
		if (!user_cfg->no_shconf) {
			EAL_LOG(ERR, "Cannot create runtime directory");
			return -1;
		}
		EAL_LOG(WARNING, "No DPDK runtime directory created");
	}
#endif

	runtime_state->process_type = (user_cfg->process_type == RTE_PROC_AUTO) ?
			eal_proc_type_detect() :
			user_cfg->process_type;

	compute_ctrl_threads_cpuset();

	return 0;
}

int
eal_apply_hugepage_mem_sz_limits(void)
{
	const struct eal_user_cfg *user_cfg = eal_get_user_configuration();
	const struct eal_platform_info *platform_info = eal_get_platform_info();
	struct eal_runtime_state *runtime_state = eal_get_runtime_state();
	unsigned int i;

	for (i = 0; i < platform_info->num_hugepage_sizes; i++) {
		unsigned int j;
		const uint64_t pagesz = platform_info->hugepage_sizes[i].size;
		uint64_t limit;

		/* assign default limits */
		limit = RTE_MIN((uint64_t)RTE_MAX_MEM_MB_PER_TYPE << 20,
				(uint64_t)RTE_MAX_MEMSEG_PER_TYPE * pagesz);

		/* override with user value for matching page size */
		for (j = 0; j < user_cfg->num_pagesz_mem_overrides; j++) {
			if (user_cfg->pagesz_mem_overrides[j].pagesz == pagesz)
				limit = user_cfg->pagesz_mem_overrides[j].limit;
		}

		runtime_state->hugepage_mem_sz_limits[i] = limit;
	}

	return 0;
}
