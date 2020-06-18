/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Mellanox Technologies, Ltd
 */
#include <string.h>

#include <rte_os.h>

#include <eal_private.h>
#include <eal_memcfg.h>

/* early configuration structure, when memory config is not mmapped */
static struct rte_mem_config early_mem_config;

/* Address of global and public configuration */
static struct rte_config rte_config = {
	.mem_config = &early_mem_config,
};

/* platform-specific runtime dir */
static char runtime_dir[PATH_MAX];

/* internal configuration */
struct internal_config internal_config;

/* Allow the application to print its usage message too if set */
static rte_usage_hook_t	rte_application_usage_hook = NULL;

const char *
rte_eal_get_runtime_dir(void)
{
	return runtime_dir;
}

void
rte_eal_set_runtime_dir(char *run_dir, size_t size)
{
	strncpy(runtime_dir, run_dir, size);
}

/* Return a pointer to the configuration structure */
struct rte_config *
rte_eal_get_configuration(void)
{
	return &rte_config;
}

/* Return a pointer to theinternal configuration structure */
struct internal_config *
rte_eal_get_internal_configuration(void)
{
	return &internal_config;
}

/* Return a pointer to rte_usage_hook_t */
rte_usage_hook_t *
rte_eal_get_application_usage_hook(void)
{
	return &rte_application_usage_hook;
}

enum rte_iova_mode
rte_eal_iova_mode(void)
{
	return rte_eal_get_configuration()->iova_mode;
}

enum rte_proc_type_t
rte_eal_process_type(void)
{
	return rte_config.process_type;
}

void
rte_eal_config_remap(void *mem_cfg_addr)
{
	memcpy(mem_cfg_addr, &early_mem_config, sizeof(early_mem_config));
	rte_config.mem_config = mem_cfg_addr;

	/* store address of the config in the config itself so that secondary
	 * processes could later map the config into this exact location
	 */
	rte_config.mem_config->mem_cfg_addr = (uintptr_t) mem_cfg_addr;

	rte_config.mem_config->dma_maskbits = 0;
}

/* Return user provided mbuf pool ops name */
const char *
rte_eal_mbuf_user_pool_ops(void)
{
	return internal_config.user_mbuf_pool_ops_name;
}

/* Set a per-application usage message */
rte_usage_hook_t
rte_set_application_usage_hook(rte_usage_hook_t usage_func)
{
	rte_usage_hook_t	old_func;

	/* Will be NULL on the first call to denote the last usage routine. */
	old_func = rte_application_usage_hook;
	rte_application_usage_hook = usage_func;

	return old_func;
}

/* return non-zero if hugepages are enabled. */
int
rte_eal_has_hugepages(void)
{
	return !internal_config.no_hugetlbfs;
}

int
rte_eal_has_pci(void)
{
	return !internal_config.no_pci;
}
