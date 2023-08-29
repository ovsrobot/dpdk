/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_WORKQ_H_
#define _SSSNIC_WORKQ_H_

struct sssnic_workq {
	/* DMA buffer of entries*/
	const struct rte_memzone *buf_mz;
	/* Virtual address of DMA buffer */
	uint8_t *buf_addr;
	/* Physic address of DMA buffer */
	uint64_t buf_phyaddr;
	/* DMA buffer size */
	uint32_t buf_size;
	/* element size */
	uint32_t entry_size;
	/* number of bits of entry size */
	uint16_t entry_shift;
	/* Max number of entries in buf */
	uint16_t num_entries;
	/* Number of entries not be used */
	uint16_t idle_entries;
	/* Consumer index */
	uint16_t ci;
	/* Producer index */
	uint16_t pi;
	/* CI and PI mask */
	uint16_t index_mask;
} __rte_cache_aligned;

#define SSSNIC_WORKQ_ENTRY_CAST(workq, idx, type)                              \
	(((type *)((workq)->buf_addr)) + (idx))
#define SSSNIC_WORKQ_BUF_PHYADDR(workq) ((workq)->buf_phyaddr)

static inline void *
sssnic_workq_entry_get(struct sssnic_workq *workq, uint32_t index)
{
	return (void *)(workq->buf_addr + (index << workq->entry_shift));
}

/* Return the entry address of current CI position. */
static inline void *
sssnic_workq_peek(struct sssnic_workq *workq)
{
	if ((workq->idle_entries + 1) > workq->num_entries)
		return NULL;

	return sssnic_workq_entry_get(workq, workq->ci & workq->index_mask);
}

static inline uint16_t
sssnic_workq_num_used_entries(struct sssnic_workq *workq)
{
	return workq->num_entries - workq->idle_entries;
}

static inline uint16_t
sssnic_workq_num_idle_entries(struct sssnic_workq *workq)
{
	return workq->idle_entries;
}

static inline uint16_t
sssnic_workq_ci_get(struct sssnic_workq *workq)
{
	return workq->ci & workq->index_mask;
}

static inline uint16_t
sssnic_workq_pi_get(struct sssnic_workq *workq)
{
	return workq->pi & workq->index_mask;
}

static inline void
sssnic_workq_consume_fast(struct sssnic_workq *workq, uint16_t num_entries)
{
	workq->idle_entries += num_entries;
	workq->ci += num_entries;
}

static inline void
sssnic_workq_produce_fast(struct sssnic_workq *workq, uint16_t num_entries)
{
	workq->idle_entries -= num_entries;
	workq->pi += num_entries;
}

static inline void
sssnic_workq_reset(struct sssnic_workq *workq)
{
	workq->ci = 0;
	workq->pi = 0;
	workq->idle_entries = workq->num_entries;
}

void *sssnic_workq_consume(struct sssnic_workq *workq, uint16_t num_entries,
	uint16_t *ci);
void *sssnic_workq_produce(struct sssnic_workq *workq, uint16_t num_entries,
	uint16_t *pi);

struct sssnic_workq *sssnic_workq_new(const char *name, int socket_id,
	uint32_t entry_size, uint32_t depth);
void sssnic_workq_destroy(struct sssnic_workq *workq);

#endif /* _SSSNIC_WORKQ_H_ */
