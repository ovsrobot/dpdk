/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Mellanox Technologies, Ltd
 */

#include <rte_string_fns.h>

#include <eal_export.h>
#include "eal_internal_cfg.h"
#include "eal_private.h"
#include "eal_filesystem.h"
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

/* Address of global and public configuration */
static struct rte_config rte_config = {
	.mem_config = &early_mem_config,
};

/* platform-specific runtime dir */
static char runtime_dir[UNIX_PATH_MAX];

/* user-provided EAL configuration */
static struct eal_user_cfg eal_user_cfg;

/* platform-discovered and runtime EAL state */
static struct eal_platform_info eal_platform_info;

/* internal runtime configuration */
static struct eal_runtime_state eal_runtime_state;

/* internal configuration */
static struct internal_config internal_config;

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

/* Return a pointer to the configuration structure */
struct rte_config *
rte_eal_get_configuration(void)
{
	return &rte_config;
}

/* Return a pointer to the internal configuration structure */
struct internal_config *
eal_get_internal_configuration(void)
{
	return &internal_config;
}

/* Return a pointer to the user configuration structure */
struct eal_user_cfg *
eal_get_user_configuration(void)
{
	return &eal_user_cfg;
}

/* Return a pointer to the platform state structure */
struct eal_platform_info *
eal_get_platform_info(void)
{
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
	return rte_eal_get_configuration()->iova_mode;
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
	return rte_config.process_type;
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
