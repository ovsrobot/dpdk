/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>

#include "../sssnic_log.h"
#include "sssnic_workq.h"

/* Consume num_entries and increase CI
 * Return the first entry address of previous CI position
 */
void *
sssnic_workq_consume(struct sssnic_workq *workq, uint16_t num_entries,
	uint16_t *ci)
{
	void *e;
	uint16_t current_ci;

	if (workq->idle_entries + num_entries > workq->num_entries)
		return NULL;

	current_ci = sssnic_workq_ci_get(workq);
	e = (void *)sssnic_workq_entry_get(workq, current_ci);
	workq->idle_entries += num_entries;
	workq->ci += num_entries;
	if (ci != NULL)
		*ci = current_ci;

	return e;
}

/* Produce num_entries and increase pi.
 * Return the first entry address of previous PI position
 */
void *
sssnic_workq_produce(struct sssnic_workq *workq, uint16_t num_entries,
	uint16_t *pi)
{
	void *e;
	uint16_t current_pi;

	if (workq->idle_entries < num_entries)
		return NULL;

	current_pi = sssnic_workq_pi_get(workq);
	e = (void *)sssnic_workq_entry_get(workq, current_pi);
	workq->idle_entries -= num_entries;
	workq->pi += num_entries;
	if (pi != NULL)
		*pi = current_pi;

	return e;
}

static int
sssnic_workq_init(struct sssnic_workq *workq, const char *name, int socket_id,
	uint32_t entry_size, uint32_t depth)
{
	char zname[RTE_MEMZONE_NAMESIZE];

	if (!rte_is_power_of_2(entry_size)) {
		PMD_DRV_LOG(ERR,
			"The entry size(%u) of workq(%s) is not power of 2",
			entry_size, name);
		return -EINVAL;
	}

	if (!rte_is_power_of_2(depth)) {
		PMD_DRV_LOG(ERR, "The depth(%u) of workq(%s) is not power of 2",
			depth, name);
		return -EINVAL;
	}

	workq->buf_size = entry_size * depth;
	workq->entry_size = entry_size;
	workq->entry_shift = rte_log2_u32(entry_size);
	workq->num_entries = depth;
	workq->idle_entries = depth;
	workq->index_mask = depth - 1;

	snprintf(zname, sizeof(zname), "%s_mz", name);
	workq->buf_mz = rte_memzone_reserve_aligned(zname, workq->buf_size,
		socket_id, RTE_MEMZONE_IOVA_CONTIG, RTE_PGSIZE_256K);
	if (workq->buf_mz == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc DMA memory for %s", name);
		return -ENOMEM;
	}
	workq->buf_addr = workq->buf_mz->addr;
	workq->buf_phyaddr = workq->buf_mz->iova;

	return 0;
}

static void
sssnic_workq_cleanup(struct sssnic_workq *workq)
{
	if (workq != NULL && workq->buf_mz != NULL)
		rte_memzone_free(workq->buf_mz);
}

/* Cleanup a work queue and free it*/
void
sssnic_workq_destroy(struct sssnic_workq *workq)
{
	if (workq != NULL) {
		sssnic_workq_cleanup(workq);
		rte_free(workq);
	}
}

/*Create a work queue and initialize*/
struct sssnic_workq *
sssnic_workq_new(const char *name, int socket_id, uint32_t entry_size,
	uint32_t depth)
{
	int ret;
	struct sssnic_workq *workq;

	if (name == NULL) {
		PMD_DRV_LOG(ERR, "Bad parameter, workq name is NULL");
		return NULL;
	}

	workq = rte_zmalloc(name, sizeof(struct sssnic_workq), 0);
	if (workq == NULL) {
		PMD_DRV_LOG(ERR, "Could not alloc memory for  %s", name);
		return NULL;
	}
	ret = sssnic_workq_init(workq, name, socket_id, entry_size, depth);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to initialize %s", name);
		rte_free(workq);
		return NULL;
	}

	return workq;
}
