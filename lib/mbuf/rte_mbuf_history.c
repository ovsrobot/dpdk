/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 NVIDIA Corporation & Affiliates
 */

#include <rte_mbuf_history.h>
#include <rte_mbuf_dyn.h>
#include <rte_log.h>
#include <rte_errno.h>
#include <eal_export.h>
#include <rte_mempool.h>
#include <rte_tailq.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

/* Global offset for the history field */
int rte_mbuf_history_field_offset = -1;
RTE_EXPORT_SYMBOL(rte_mbuf_history_field_offset);

#if RTE_MBUF_HISTORY_DEBUG
/* Dynamic field definition for mbuf history */
static const struct rte_mbuf_dynfield mbuf_dynfield_history = {
	.name = RTE_MBUF_DYNFIELD_HISTORY_NAME,
	.size = sizeof(uint64_t),
	.align = RTE_ALIGN(sizeof(uint64_t), 8),
};

/* Context structure for combined statistics counting and mbuf history printing */
struct count_and_print_ctx {
	uint64_t *stats;
	FILE *f;
};

static void
mbuf_history_count_stats_and_print(struct rte_mempool *mp __rte_unused, void *opaque,
					void *obj, unsigned obj_idx __rte_unused)
{
	struct count_and_print_ctx *ctx = (struct count_and_print_ctx *)opaque;

	struct rte_mbuf *mbuf = (struct rte_mbuf *)obj;

	if (obj == NULL || ctx == NULL || ctx->stats == NULL || ctx->f == NULL)
		return;

	/* Get mbuf history */
	uint64_t history = rte_mbuf_history_get(mbuf);

	ctx->stats[0]++; /* n_total */

	if (history == 0) {
		ctx->stats[1]++; /* n_never */
		return;
	}

	/* Extract the most recent operation */
	uint64_t op = history & RTE_MBUF_HISTORY_MASK;

	switch (op) {
	case RTE_MBUF_FREE:
		ctx->stats[2]++; /* n_free */
		break;
	case RTE_MBUF_PMD_FREE:
		ctx->stats[3]++; /* n_pmd_free */
		break;
	case RTE_MBUF_PMD_TX:
		ctx->stats[4]++; /* n_pmd_tx */
		break;
	case RTE_MBUF_APP_RX:
		ctx->stats[5]++; /* n_app_rx */
		break;
	case RTE_MBUF_PMD_ALLOC:
		ctx->stats[6]++; /* n_pmd_alloc */
		break;
	case RTE_MBUF_ALLOC:
		ctx->stats[7]++; /* n_alloc */
		break;
	case RTE_MBUF_BUSY_TX:
		ctx->stats[8]++; /* n_busy_tx */
		break;
	default:
		break;
	}

	/* Print the mbuf history value */
	fprintf(ctx->f, "mbuf %p: %016" PRIX64 "\n", mbuf, history);

}

static void
mbuf_history_get_stat(struct rte_mempool *mp, void *arg)
{
	FILE *f = (FILE *)arg;
	uint64_t stats[9] = {0};

	if (f == NULL)
		return;

	/* Output mempool header */
	fprintf(f, "=== Mempool: %s ===\n", mp->name);

	/* Create context structure for combined counting and printing */
	struct count_and_print_ctx ctx = { .stats = stats, .f = f };

	/* Single pass: collect statistics and print mbuf history */
	rte_mempool_obj_iter(mp, mbuf_history_count_stats_and_print, &ctx);

	/* Calculate total allocated mbufs */
	uint64_t total_allocated = stats[3] + stats[4] + stats[5] +
	stats[6] + stats[7] + stats[8];

	/* Print statistics summary */
	fprintf(f, "\n"
		"Populated:       %u\n"
		"Never allocated: %" PRIu64 "\n"
		"Free:            %" PRIu64 "\n"
		"Allocated:       %" PRIu64 "\n"
		"PMD owned Tx:    %" PRIu64 "\n"
		"PMD owned Rx:    %" PRIu64 "\n"
		"App owned alloc: %" PRIu64 "\n"
		"App owned Rx:    %" PRIu64 "\n"
		"App owned busy:  %" PRIu64 "\n"
		"Counted total:   %" PRIu64 "\n",
		mp->populated_size, stats[1], stats[2], total_allocated,
		stats[4], stats[6], stats[7], stats[5], stats[8], stats[0]);

	fprintf(f, "---\n");
}
#endif

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_mbuf_history_dump, 25.11)
#if RTE_MBUF_HISTORY_DEBUG
void rte_mbuf_history_dump(FILE *f)
{
	if (f == NULL) {
		RTE_LOG(ERR, MBUF, "Invalid file pointer\n");
		return;
	}

	fprintf(f, "=== MBUF History Statistics ===\n");
	fprintf(f, "Dumping complete mbuf history for all mempools...\n");

	/* Check if mbuf history is initialized */
	if (rte_mbuf_history_field_offset == -1) {
		fprintf(f, "WARNING: MBUF history not initialized. Call rte_mbuf_history_init() first.\n\n");
		return;
	}

	/* Use rte_mempool_walk to iterate over all mempools */
	rte_mempool_walk(mbuf_history_get_stat, f);
}

int rte_mbuf_history_init(void)
{
	if (rte_mbuf_history_field_offset != -1) {
		/* Already initialized */
		return 0;
	}

	rte_mbuf_history_field_offset = rte_mbuf_dynfield_register(&mbuf_dynfield_history);
	if (rte_mbuf_history_field_offset < 0) {
		RTE_LOG(ERR, MBUF, "Failed to register mbuf history dynamic field: %s\n",
			rte_strerror(rte_errno));
		return -1;
	}
	return 0;
}
#else
void rte_mbuf_history_dump(FILE *f)
{
	RTE_SET_USED(f);
	RTE_LOG(INFO, MBUF, "Mbuf history recorder is not supported\n");
}

int rte_mbuf_history_init(void)
{
	rte_errno = ENOTSUP;
	return -1;
}
#endif
RTE_EXPORT_SYMBOL(rte_mbuf_history_init);
RTE_EXPORT_SYMBOL(rte_mbuf_history_dump);
