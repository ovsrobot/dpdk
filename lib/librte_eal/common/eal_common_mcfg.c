/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <rte_eal_memconfig.h>
#include <rte_version.h>

#include "eal_internal_cfg.h"
#include "eal_memcfg.h"
#include "eal_private.h"

void
eal_mcfg_complete(void)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	struct rte_mem_config *mcfg = cfg->mem_config;

	/* ALL shared mem_config related INIT DONE */
	if (cfg->process_type == RTE_PROC_PRIMARY)
		mcfg->magic = RTE_MAGIC;

	internal_config.init_complete = 1;
}

void
eal_mcfg_wait_complete(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;

	/* wait until shared mem_config finish initialising */
	while (mcfg->magic != RTE_MAGIC)
		rte_pause();
}

int
eal_mcfg_check_version(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;

	/* check if version from memconfig matches compiled in macro */
	if (mcfg->version != RTE_VERSION)
		return -1;

	return 0;
}

enum mp_status {
	MP_UNKNOWN,
	MP_FORBIDDEN,
	MP_ENABLED,
};

static bool
eal_mcfg_set_mp_status(enum mp_status status)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	uint8_t expected;
	uint8_t desired;

	expected = MP_UNKNOWN;
	desired = status;
	if (__atomic_compare_exchange_n(&mcfg->mp_status, &expected, desired,
			false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
		return true;

	return __atomic_load_n(&mcfg->mp_status, __ATOMIC_RELAXED) == desired;
}

bool
eal_mcfg_forbid_multiprocess(void)
{
	assert(rte_eal_get_configuration()->process_type == RTE_PROC_PRIMARY);
	return eal_mcfg_set_mp_status(MP_FORBIDDEN);
}

bool
eal_mcfg_enable_multiprocess(void)
{
	assert(rte_eal_get_configuration()->process_type == RTE_PROC_SECONDARY);
	return eal_mcfg_set_mp_status(MP_ENABLED);
}

void
eal_mcfg_update_internal(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;

	internal_config.legacy_mem = mcfg->legacy_mem;
	internal_config.single_file_segments = mcfg->single_file_segments;
}

void
eal_mcfg_update_from_internal(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;

	mcfg->legacy_mem = internal_config.legacy_mem;
	mcfg->single_file_segments = internal_config.single_file_segments;
	/* record current DPDK version */
	mcfg->version = RTE_VERSION;
}

void
rte_mcfg_mem_read_lock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_read_lock(&mcfg->memory_hotplug_lock);
}

void
rte_mcfg_mem_read_unlock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_read_unlock(&mcfg->memory_hotplug_lock);
}

void
rte_mcfg_mem_write_lock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_write_lock(&mcfg->memory_hotplug_lock);
}

void
rte_mcfg_mem_write_unlock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_write_unlock(&mcfg->memory_hotplug_lock);
}

void
rte_mcfg_tailq_read_lock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_read_lock(&mcfg->qlock);
}

void
rte_mcfg_tailq_read_unlock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_read_unlock(&mcfg->qlock);
}

void
rte_mcfg_tailq_write_lock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_write_lock(&mcfg->qlock);
}

void
rte_mcfg_tailq_write_unlock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_write_unlock(&mcfg->qlock);
}

void
rte_mcfg_mempool_read_lock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_read_lock(&mcfg->mplock);
}

void
rte_mcfg_mempool_read_unlock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_read_unlock(&mcfg->mplock);
}

void
rte_mcfg_mempool_write_lock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_write_lock(&mcfg->mplock);
}

void
rte_mcfg_mempool_write_unlock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_write_unlock(&mcfg->mplock);
}

void
rte_mcfg_timer_lock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_spinlock_lock(&mcfg->tlock);
}

void
rte_mcfg_timer_unlock(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	rte_spinlock_unlock(&mcfg->tlock);
}

bool
rte_mcfg_get_single_file_segments(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	return (bool)mcfg->single_file_segments;
}
