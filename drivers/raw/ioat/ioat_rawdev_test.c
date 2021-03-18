/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <unistd.h>
#include <inttypes.h>
#include <rte_mbuf.h>
#include "rte_rawdev.h"
#include "rte_ioat_rawdev.h"
#include "ioat_private.h"

#define MAX_SUPPORTED_RAWDEVS 64
#define TEST_SKIPPED 77

int ioat_rawdev_test(uint16_t dev_id); /* pre-define to keep compiler happy */

static struct rte_mempool *pool;
static unsigned short expected_ring_size[MAX_SUPPORTED_RAWDEVS];

#define PRINT_ERR(...) print_err(__func__, __LINE__, __VA_ARGS__)

static inline int
__rte_format_printf(3, 4)
print_err(const char *func, int lineno, const char *format, ...)
{
	va_list ap;
	int ret;

	ret = fprintf(stderr, "In %s:%d - ", func, lineno);
	va_start(ap, format);
	ret += vfprintf(stderr, format, ap);
	va_end(ap);

	return ret;
}

static int
test_enqueue_copies(int dev_id)
{
	const unsigned int length = 1024;
	unsigned int i;

	do {
		struct rte_mbuf *src, *dst;
		char *src_data, *dst_data;
		struct rte_mbuf *completed[2] = {0};

		/* test doing a single copy */
		src = rte_pktmbuf_alloc(pool);
		dst = rte_pktmbuf_alloc(pool);
		src->data_len = src->pkt_len = length;
		dst->data_len = dst->pkt_len = length;
		src_data = rte_pktmbuf_mtod(src, char *);
		dst_data = rte_pktmbuf_mtod(dst, char *);

		for (i = 0; i < length; i++)
			src_data[i] = rand() & 0xFF;

		if (rte_ioat_enqueue_copy(dev_id,
				src->buf_iova + src->data_off,
				dst->buf_iova + dst->data_off,
				length,
				(uintptr_t)src,
				(uintptr_t)dst) != 1) {
			PRINT_ERR("Error with rte_ioat_enqueue_copy\n");
			return -1;
		}
		rte_ioat_perform_ops(dev_id);
		usleep(10);

		if (rte_ioat_completed_ops(dev_id, 1, (void *)&completed[0],
				(void *)&completed[1]) != 1) {
			PRINT_ERR("Error with rte_ioat_completed_ops\n");
			return -1;
		}
		if (completed[0] != src || completed[1] != dst) {
			PRINT_ERR("Error with completions: got (%p, %p), not (%p,%p)\n",
					completed[0], completed[1], src, dst);
			return -1;
		}

		for (i = 0; i < length; i++)
			if (dst_data[i] != src_data[i]) {
				PRINT_ERR("Data mismatch at char %u\n", i);
				return -1;
			}
		rte_pktmbuf_free(src);
		rte_pktmbuf_free(dst);
	} while (0);

	/* test doing multiple copies */
	do {
		struct rte_mbuf *srcs[32], *dsts[32];
		struct rte_mbuf *completed_src[64];
		struct rte_mbuf *completed_dst[64];
		unsigned int j;

		for (i = 0; i < RTE_DIM(srcs); i++) {
			char *src_data;

			srcs[i] = rte_pktmbuf_alloc(pool);
			dsts[i] = rte_pktmbuf_alloc(pool);
			srcs[i]->data_len = srcs[i]->pkt_len = length;
			dsts[i]->data_len = dsts[i]->pkt_len = length;
			src_data = rte_pktmbuf_mtod(srcs[i], char *);

			for (j = 0; j < length; j++)
				src_data[j] = rand() & 0xFF;

			if (rte_ioat_enqueue_copy(dev_id,
					srcs[i]->buf_iova + srcs[i]->data_off,
					dsts[i]->buf_iova + dsts[i]->data_off,
					length,
					(uintptr_t)srcs[i],
					(uintptr_t)dsts[i]) != 1) {
				PRINT_ERR("Error with rte_ioat_enqueue_copy for buffer %u\n",
						i);
				return -1;
			}
		}
		rte_ioat_perform_ops(dev_id);
		usleep(100);

		if (rte_ioat_completed_ops(dev_id, 64, (void *)completed_src,
				(void *)completed_dst) != RTE_DIM(srcs)) {
			PRINT_ERR("Error with rte_ioat_completed_ops\n");
			rte_rawdev_dump(dev_id, stdout);
			return -1;
		}
		for (i = 0; i < RTE_DIM(srcs); i++) {
			char *src_data, *dst_data;

			if (completed_src[i] != srcs[i]) {
				PRINT_ERR("Error with source pointer %u\n", i);
				return -1;
			}
			if (completed_dst[i] != dsts[i]) {
				PRINT_ERR("Error with dest pointer %u\n", i);
				return -1;
			}

			src_data = rte_pktmbuf_mtod(srcs[i], char *);
			dst_data = rte_pktmbuf_mtod(dsts[i], char *);
			for (j = 0; j < length; j++)
				if (src_data[j] != dst_data[j]) {
					PRINT_ERR("Error with copy of packet %u, byte %u\n",
							i, j);
					return -1;
				}
			rte_pktmbuf_free(srcs[i]);
			rte_pktmbuf_free(dsts[i]);
		}

	} while (0);

	return 0;
}

static int
test_enqueue_fill(int dev_id)
{
	const unsigned int length[] = {8, 64, 1024, 50, 100, 89};
	struct rte_mbuf *dst = rte_pktmbuf_alloc(pool);
	char *dst_data = rte_pktmbuf_mtod(dst, char *);
	struct rte_mbuf *completed[2] = {0};
	uint64_t pattern = 0xfedcba9876543210;
	unsigned int i, j;

	for (i = 0; i < RTE_DIM(length); i++) {
		/* reset dst_data */
		memset(dst_data, 0, length[i]);

		/* perform the fill operation */
		if (rte_ioat_enqueue_fill(dev_id, pattern,
				dst->buf_iova + dst->data_off, length[i],
				(uintptr_t)dst) != 1) {
			PRINT_ERR("Error with rte_ioat_enqueue_fill\n");
			return -1;
		}

		rte_ioat_perform_ops(dev_id);
		usleep(100);

		if (rte_ioat_completed_ops(dev_id, 1, (void *)&completed[0],
			(void *)&completed[1]) != 1) {
			PRINT_ERR("Error with completed ops\n");
			return -1;
		}
		/* check the result */
		for (j = 0; j < length[i]; j++) {
			char pat_byte = ((char *)&pattern)[j % 8];
			if (dst_data[j] != pat_byte) {
				PRINT_ERR("Error with fill operation (length = %u): got (%x), not (%x)\n",
						length[i], dst_data[j],
						pat_byte);
				return -1;
			}
		}
	}

	rte_pktmbuf_free(dst);
	return 0;
}

static int
test_burst_capacity(int dev_id, unsigned int ring_size)
{
	unsigned int i, j;
	unsigned int length = 1024;

	/* Test to make sure it does not enqueue if we cannot fit the entire burst */
	do {
#define BURST_SIZE			19
#define EXPECTED_REJECTS	5
		struct rte_mbuf *srcs[BURST_SIZE], *dsts[BURST_SIZE];
		struct rte_mbuf *completed_src[BURST_SIZE];
		struct rte_mbuf *completed_dst[BURST_SIZE];
		unsigned int cnt_success = 0;
		unsigned int cnt_rejected = 0;
		unsigned int valid_iters = (ring_size - 1)/BURST_SIZE;

		/* Enqueue burst until they won't fit + some extra iterations which should
		* be rejected
		*/
		for (i = 0; i < valid_iters + EXPECTED_REJECTS; i++) {
			if (rte_ioat_burst_capacity(dev_id) >= BURST_SIZE) {
				for (j = 0; j < BURST_SIZE; j++) {

					srcs[j] = rte_pktmbuf_alloc(pool);
					dsts[j] = rte_pktmbuf_alloc(pool);
					srcs[j]->data_len = srcs[j]->pkt_len = length;
					dsts[j]->data_len = dsts[j]->pkt_len = length;

					if (rte_ioat_enqueue_copy(dev_id,
							srcs[j]->buf_iova + srcs[j]->data_off,
							dsts[j]->buf_iova + dsts[j]->data_off,
							length,
							(uintptr_t)srcs[j],
							(uintptr_t)dsts[j]) != 1) {
						PRINT_ERR("Error with rte_ioat_enqueue_copy\n");
						return -1;
					}

					rte_pktmbuf_free(srcs[j]);
					rte_pktmbuf_free(dsts[j]);
					cnt_success++;
				}
			} else {
				cnt_rejected++;
			}
		}

		/* do cleanup before next tests */
		rte_ioat_perform_ops(dev_id);
		usleep(100);
		for (i = 0; i < valid_iters; i++) {
			if (rte_ioat_completed_ops(dev_id, BURST_SIZE, (void *)completed_src,
					(void *)completed_dst) != BURST_SIZE) {
				PRINT_ERR("error with completions\n");
				return -1;
			}
		}

		printf("successful_enqueues: %u  expected_successful: %u  rejected_iters: %u  expected_rejects: %u\n",
				cnt_success, valid_iters * BURST_SIZE, cnt_rejected,
				EXPECTED_REJECTS);

		if (!(cnt_success == (valid_iters * BURST_SIZE)) &&
				!(cnt_rejected == EXPECTED_REJECTS)) {
			PRINT_ERR("Burst Capacity test failed\n");
			return -1;
		}
	} while (0);

	/* Verify that space is taken and free'd as expected.
	 * Repeat the test to verify wrap-around handling is correct in
	 * rte_ioat_burst_capacity().
	 */
	for (i = 0; i < ring_size / 32; i++) {
		struct rte_mbuf *srcs[64], *dsts[64];
		struct rte_mbuf *completed_src[64];
		struct rte_mbuf *completed_dst[64];

		/* Make sure the ring is clean before we start */
		if (rte_ioat_burst_capacity(dev_id) != ring_size - 1) {
			PRINT_ERR("Error, ring should be empty\n");
			return -1;
		}

		/* Enqueue 64 mbufs & verify that space is taken */
		for (j = 0; j < 64; j++) {
			srcs[j] = rte_pktmbuf_alloc(pool);
			dsts[j] = rte_pktmbuf_alloc(pool);
			srcs[j]->data_len = srcs[j]->pkt_len = length;
			dsts[j]->data_len = dsts[j]->pkt_len = length;

			if (rte_ioat_enqueue_copy(dev_id,
					srcs[j]->buf_iova + srcs[j]->data_off,
					dsts[j]->buf_iova + dsts[j]->data_off,
					length,
					(uintptr_t)srcs[j],
					(uintptr_t)dsts[j]) != 1) {
				PRINT_ERR("Error with rte_ioat_enqueue_copy\n");
				return -1;
			}

			rte_pktmbuf_free(srcs[j]);
			rte_pktmbuf_free(dsts[j]);
		}

		if (rte_ioat_burst_capacity(dev_id) != (ring_size - 1) - 64) {
			PRINT_ERR("Error, space available not as expected\n");
			return -1;
		}

		/* Copy, gather completions, and make sure the space is free'd again */
		rte_ioat_perform_ops(dev_id);
		usleep(100);
		for (j = 0; j < 2; j++) {
			if (rte_ioat_completed_ops(dev_id, 32, (void *)completed_src,
					(void *)completed_dst) != 32) {
				PRINT_ERR("error with completions\n");
				return -1;	
			}
		}

		if (rte_ioat_burst_capacity(dev_id) != ring_size - 1) {
			PRINT_ERR("Error, space available not as expected\n");
			return -1;
		}

	}

	return 0;
}

int
ioat_rawdev_test(uint16_t dev_id)
{
#define IOAT_TEST_RINGSIZE 512
	struct rte_ioat_rawdev_config p = { .ring_size = -1 };
	struct rte_rawdev_info info = { .dev_private = &p };
	struct rte_rawdev_xstats_name *snames = NULL;
	uint64_t *stats = NULL;
	unsigned int *ids = NULL;
	unsigned int nb_xstats;
	unsigned int i;

	if (dev_id >= MAX_SUPPORTED_RAWDEVS) {
		printf("Skipping test. Cannot test rawdevs with id's greater than %d\n",
				MAX_SUPPORTED_RAWDEVS);
		return TEST_SKIPPED;
	}

	rte_rawdev_info_get(dev_id, &info, sizeof(p));
	if (p.ring_size != expected_ring_size[dev_id]) {
		PRINT_ERR("Error, initial ring size is not as expected (Actual: %d, Expected: %d)\n",
				(int)p.ring_size, expected_ring_size[dev_id]);
		return -1;
	}

	p.ring_size = IOAT_TEST_RINGSIZE;
	if (rte_rawdev_configure(dev_id, &info, sizeof(p)) != 0) {
		PRINT_ERR("Error with rte_rawdev_configure()\n");
		return -1;
	}
	rte_rawdev_info_get(dev_id, &info, sizeof(p));
	if (p.ring_size != IOAT_TEST_RINGSIZE) {
		PRINT_ERR("Error, ring size is not %d (%d)\n",
				IOAT_TEST_RINGSIZE, (int)p.ring_size);
		return -1;
	}
	expected_ring_size[dev_id] = p.ring_size;

	if (rte_rawdev_start(dev_id) != 0) {
		PRINT_ERR("Error with rte_rawdev_start()\n");
		return -1;
	}

	pool = rte_pktmbuf_pool_create("TEST_IOAT_POOL",
			256, /* n == num elements */
			32,  /* cache size */
			0,   /* priv size */
			2048, /* data room size */
			info.socket_id);
	if (pool == NULL) {
		PRINT_ERR("Error with mempool creation\n");
		return -1;
	}

	/* allocate memory for xstats names and values */
	nb_xstats = rte_rawdev_xstats_names_get(dev_id, NULL, 0);

	snames = malloc(sizeof(*snames) * nb_xstats);
	if (snames == NULL) {
		PRINT_ERR("Error allocating xstat names memory\n");
		goto err;
	}
	rte_rawdev_xstats_names_get(dev_id, snames, nb_xstats);

	ids = malloc(sizeof(*ids) * nb_xstats);
	if (ids == NULL) {
		PRINT_ERR("Error allocating xstat ids memory\n");
		goto err;
	}
	for (i = 0; i < nb_xstats; i++)
		ids[i] = i;

	stats = malloc(sizeof(*stats) * nb_xstats);
	if (stats == NULL) {
		PRINT_ERR("Error allocating xstat memory\n");
		goto err;
	}

	/* run the test cases */
	printf("Running Copy Tests\n");
	for (i = 0; i < 100; i++) {
		unsigned int j;

		if (test_enqueue_copies(dev_id) != 0)
			goto err;

		rte_rawdev_xstats_get(dev_id, ids, stats, nb_xstats);
		for (j = 0; j < nb_xstats; j++)
			printf("%s: %"PRIu64"   ", snames[j].name, stats[j]);
		printf("\r");
	}
	printf("\n");

	/* test enqueue fill operation */
	printf("Running Fill Tests\n");
	for (i = 0; i < 100; i++) {
		unsigned int j;

		if (test_enqueue_fill(dev_id) != 0)
			goto err;

		rte_rawdev_xstats_get(dev_id, ids, stats, nb_xstats);
		for (j = 0; j < nb_xstats; j++)
			printf("%s: %"PRIu64"   ", snames[j].name, stats[j]);
		printf("\r");
	}
	printf("\n");

	printf("Running Burst Capacity Test\n");
	if (test_burst_capacity(dev_id, expected_ring_size[dev_id]) != 0)
		goto err;

	rte_rawdev_stop(dev_id);
	if (rte_rawdev_xstats_reset(dev_id, NULL, 0) != 0) {
		PRINT_ERR("Error resetting xstat values\n");
		goto err;
	}

	rte_mempool_free(pool);
	free(snames);
	free(stats);
	free(ids);
	return 0;

err:
	rte_rawdev_stop(dev_id);
	rte_rawdev_xstats_reset(dev_id, NULL, 0);
	rte_mempool_free(pool);
	free(snames);
	free(stats);
	free(ids);
	return -1;
}
