/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_time.h>
#include <rte_mbuf.h>
#include <rte_dmadev.h>
#include <rte_malloc.h>
#include <rte_lcore.h>

#include "main.h"

#define MAX_DMA_CPL_NB 255

#define TEST_WAIT_U_SECOND 10000

#define CSV_LINE_DMA_FMT "Scenario %u,%u,%s,%u,%u,%u,%" PRIu64 ",%.3lf,%.3lf\n"
#define CSV_LINE_CPU_FMT "Scenario %u,%u,NA,%u,%u,%u,%" PRIu64 ",%.3lf,%.3lf\n"

struct worker_info {
	bool ready_flag;
	bool start_flag;
	bool stop_flag;
	uint32_t total_cpl;
	uint32_t test_cpl;
};

struct lcore_params {
	uint8_t scenario_id;
	unsigned int lcore_id;
	char *dma_name;
	uint16_t worker_id;
	uint16_t dev_id;
	uint32_t nr_buf;
	uint16_t kick_batch;
	uint32_t buf_size;
	uint16_t test_secs;
	struct rte_mbuf **srcs;
	struct rte_mbuf **dsts;
	struct worker_info worker_info;
};

static struct rte_mempool *src_pool;
static struct rte_mempool *dst_pool;

static volatile struct lcore_params *worker_params[MAX_WORKER_NB];

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

static inline void
calc_result(uint32_t buf_size, uint32_t nr_buf, uint16_t nb_workers, uint16_t test_secs,
				uint32_t total_cnt, uint32_t *memory, uint32_t *ave_cycle,
				float *bandwidth, float *mops)
{
	*memory = (buf_size * (nr_buf / nb_workers) * 2) / (1024 * 1024);
	*ave_cycle = test_secs * rte_get_timer_hz() / total_cnt;
	*bandwidth = (buf_size * 8 * (rte_get_timer_hz() / (float)*ave_cycle)) / 1000000000;
	*mops = (float)rte_get_timer_hz() / *ave_cycle / 1000000;
}

static void
output_result(uint8_t scenario_id, uint32_t lcore_id, char *dma_name, uint64_t ave_cycle,
			uint32_t buf_size, uint32_t nr_buf, uint32_t memory,
			float bandwidth, float mops, bool is_dma)
{
	if (is_dma)
		printf("lcore %u, DMA %s:\n", lcore_id, dma_name);
	else
		printf("lcore %u\n", lcore_id);

	printf("average cycles/op: %" PRIu64 ", buffer size: %u, nr_buf: %u, memory: %uMB, frequency: %" PRIu64 ".\n",
			ave_cycle, buf_size, nr_buf, memory, rte_get_timer_hz());
	printf("Average bandwidth: %.3lfGbps, MOps: %.3lf\n", bandwidth, mops);

	if (is_dma)
		snprintf(output_str[lcore_id], MAX_OUTPUT_STR_LEN, CSV_LINE_DMA_FMT,
			scenario_id, lcore_id, dma_name, buf_size,
			nr_buf, memory, ave_cycle, bandwidth, mops);
	else
		snprintf(output_str[lcore_id], MAX_OUTPUT_STR_LEN, CSV_LINE_CPU_FMT,
			scenario_id, lcore_id, buf_size,
			nr_buf, memory, ave_cycle, bandwidth, mops);
}

static inline void
cache_flush_buf(__maybe_unused struct rte_mbuf **array,
		__maybe_unused uint32_t buf_size,
		__maybe_unused uint32_t nr_buf)
{
#ifdef RTE_ARCH_X86_64
	char *data;
	struct rte_mbuf **srcs = array;
	uint32_t i, offset;

	for (i = 0; i < nr_buf; i++) {
		data = rte_pktmbuf_mtod(srcs[i], char *);
		for (offset = 0; offset < buf_size; offset += 64)
			__builtin_ia32_clflush(data + offset);
	}
#endif
}

/* Configuration of device. */
static void
configure_dmadev_queue(uint32_t dev_id, uint32_t ring_size)
{
	uint16_t vchan = 0;
	struct rte_dma_info info;
	struct rte_dma_conf dev_config = { .nb_vchans = 1 };
	struct rte_dma_vchan_conf qconf = {
		.direction = RTE_DMA_DIR_MEM_TO_MEM,
		.nb_desc = ring_size
	};

	if (rte_dma_configure(dev_id, &dev_config) != 0)
		rte_exit(EXIT_FAILURE, "Error with dma configure.\n");

	if (rte_dma_vchan_setup(dev_id, vchan, &qconf) != 0)
		rte_exit(EXIT_FAILURE, "Error with queue configuration.\n");

	rte_dma_info_get(dev_id, &info);
	if (info.nb_vchans != 1)
		rte_exit(EXIT_FAILURE, "Error, no configured queues reported on device id. %u\n", dev_id);

	if (rte_dma_start(dev_id) != 0)
		rte_exit(EXIT_FAILURE, "Error with dma start.\n");
}

static int
config_dmadevs(struct test_configure *cfg)
{
	uint32_t ring_size = cfg->ring_size.cur;
	struct lcore_dma_map_t *ldm = &cfg->lcore_dma_map;
	uint32_t nb_workers = ldm->cnt;
	uint32_t i;
	int dev_id;
	uint16_t nb_dmadevs = 0;
	char *dma_name;

	for (i = 0; i < ldm->cnt; i++) {
		dma_name = ldm->dma_names[i];
		dev_id = rte_dma_get_dev_id_by_name(dma_name);
		if (dev_id == -1) {
			fprintf(stderr, "Error: Fail to find DMA %s.\n", dma_name);
			goto end;
		}

		ldm->dma_ids[i] = dev_id;
		configure_dmadev_queue(dev_id, ring_size);
		++nb_dmadevs;
	}

end:
	if (nb_dmadevs < nb_workers) {
		printf("Not enough dmadevs (%u) for all workers (%u).\n", nb_dmadevs, nb_workers);
		return -1;
	}

	printf("Number of used dmadevs: %u.\n", nb_dmadevs);

	return 0;
}

#define POLL_MAX 1000

static inline int
do_dma_mem_copy(void *p)
{
	uint16_t *para_idx = (uint16_t *)p;
	volatile struct lcore_params *para = worker_params[*para_idx];
	volatile struct worker_info *worker_info = &(para->worker_info);
	uint16_t dev_id = para->dev_id;
	uint32_t nr_buf = para->nr_buf;
	uint16_t kick_batch = para->kick_batch;
	uint32_t buf_size = para->buf_size;
	struct rte_mbuf **srcs = para->srcs;
	struct rte_mbuf **dsts = para->dsts;
	int64_t async_cnt = 0;
	int nr_cpl = 0;
	uint32_t i;
	uint32_t poll_cnt = 0;

	worker_info->stop_flag = false;
	worker_info->ready_flag = true;

	while (!worker_info->start_flag)
		;

	while (1) {
		for (i = 0; i < nr_buf; i++) {
			if (unlikely(rte_dma_copy(dev_id,
						0,
						rte_pktmbuf_iova(srcs[i]),
						rte_pktmbuf_iova(dsts[i]),
						buf_size,
						0) < 0)) {
				rte_dma_submit(dev_id, 0);
				while (rte_dma_burst_capacity(dev_id, 0) == 0) {
					nr_cpl = rte_dma_completed(dev_id, 0, MAX_DMA_CPL_NB,
								NULL, NULL);
					async_cnt -= nr_cpl;
					worker_info->total_cpl += nr_cpl;
				}
				if (rte_dma_copy(dev_id,
						0,
						rte_pktmbuf_iova(srcs[i]),
						rte_pktmbuf_iova(dsts[i]),
						buf_size,
						0) < 0) {
					printf("enqueue fail again at %u\n", i);
					printf("space:%d\n", rte_dma_burst_capacity(dev_id, 0));
					rte_exit(EXIT_FAILURE, "DMA enqueue failed\n");
				}
			}
			async_cnt++;

			if ((async_cnt % kick_batch) == 0) {
				rte_dma_submit(dev_id, 0);
				/* add a poll to avoid ring full */
				nr_cpl = rte_dma_completed(dev_id, 0, MAX_DMA_CPL_NB, NULL, NULL);
				async_cnt -= nr_cpl;
				worker_info->total_cpl += nr_cpl;
			}
		}

		if (worker_info->stop_flag)
			break;
	}

	rte_dma_submit(dev_id, 0);
	while ((async_cnt > 0) && (poll_cnt++ < POLL_MAX)) {
		nr_cpl = rte_dma_completed(dev_id, 0, MAX_DMA_CPL_NB, NULL, NULL);
		async_cnt -= nr_cpl;
	}

	return 0;
}

static inline int
do_cpu_mem_copy(void *p)
{
	uint16_t *para_idx = (uint16_t *)p;
	volatile struct lcore_params *para = worker_params[*para_idx];
	volatile struct worker_info *worker_info = &(para->worker_info);
	uint32_t nr_buf = para->nr_buf;
	uint32_t buf_size = para->buf_size;
	struct rte_mbuf **srcs = para->srcs;
	struct rte_mbuf **dsts = para->dsts;
	uint32_t i;

	worker_info->stop_flag = false;
	worker_info->ready_flag = true;

	while (!worker_info->start_flag)
		;

	while (1) {
		for (i = 0; i < nr_buf; i++) {
			/* copy buffer form src to dst */
			rte_memcpy((void *)(uintptr_t)rte_mbuf_data_iova(dsts[i]),
				(void *)(uintptr_t)rte_mbuf_data_iova(srcs[i]),
				(size_t)buf_size);
			worker_info->total_cpl++;
		}
		if (worker_info->stop_flag)
			break;
	}

	return 0;
}

static int
setup_memory_env(struct test_configure *cfg, struct rte_mbuf ***srcs,
			struct rte_mbuf ***dsts)
{
	unsigned int buf_size = cfg->buf_size.cur;
	unsigned int nr_sockets;
	uint32_t nr_buf = cfg->nr_buf;

	nr_sockets = rte_socket_count();
	if (cfg->src_numa_node >= nr_sockets ||
		cfg->dst_numa_node >= nr_sockets) {
		printf("Error: Source or destination numa exceeds the acture numa nodes.\n");
		return -1;
	}

	src_pool = rte_pktmbuf_pool_create("Benchmark_DMA_SRC",
			nr_buf, /* n == num elements */
			64,  /* cache size */
			0,   /* priv size */
			buf_size + RTE_PKTMBUF_HEADROOM,
			cfg->src_numa_node);
	if (src_pool == NULL) {
		PRINT_ERR("Error with source mempool creation.\n");
		return -1;
	}

	dst_pool = rte_pktmbuf_pool_create("Benchmark_DMA_DST",
			nr_buf, /* n == num elements */
			64,  /* cache size */
			0,   /* priv size */
			buf_size + RTE_PKTMBUF_HEADROOM,
			cfg->dst_numa_node);
	if (dst_pool == NULL) {
		PRINT_ERR("Error with destination mempool creation.\n");
		return -1;
	}

	*srcs = rte_malloc(NULL, nr_buf * sizeof(struct rte_mbuf *), 0);
	if (*srcs == NULL) {
		printf("Error: srcs malloc failed.\n");
		return -1;
	}

	*dsts = rte_malloc(NULL, nr_buf * sizeof(struct rte_mbuf *), 0);
	if (*dsts == NULL) {
		printf("Error: dsts malloc failed.\n");
		return -1;
	}

	if (rte_mempool_get_bulk(src_pool, (void **)*srcs, nr_buf) != 0) {
		printf("get src mbufs failed.\n");
		return -1;
	}
	if (rte_mempool_get_bulk(dst_pool, (void **)*dsts, nr_buf) != 0) {
		printf("get dst mbufs failed.\n");
		return -1;
	}

	return 0;
}

void
mem_copy_benchmark(struct test_configure *cfg, bool is_dma)
{
	uint16_t i;
	uint32_t offset;
	unsigned int lcore_id = 0;
	struct rte_mbuf **srcs = NULL, **dsts = NULL;
	struct lcore_dma_map_t *ldm = &cfg->lcore_dma_map;
	unsigned int buf_size = cfg->buf_size.cur;
	uint16_t kick_batch = cfg->kick_batch.cur;
	uint32_t nr_buf = cfg->nr_buf = (cfg->mem_size.cur * 1024 * 1024) / (cfg->buf_size.cur * 2);
	uint16_t nb_workers = ldm->cnt;
	uint16_t test_secs = cfg->test_secs;
	uint32_t memory;
	uint32_t avg_cycles = 0;
	float mops;
	float bandwidth;

	if (setup_memory_env(cfg, &srcs, &dsts) < 0)
		goto out;

	if (is_dma)
		if (config_dmadevs(cfg) < 0)
			goto out;

	if (cfg->cache_flush) {
		cache_flush_buf(srcs, buf_size, nr_buf);
		cache_flush_buf(dsts, buf_size, nr_buf);
		rte_mb();
	}

	printf("Start testing....\n");

	for (i = 0; i < nb_workers; i++) {
		lcore_id = ldm->lcores[i];
		offset = nr_buf / nb_workers * i;

		worker_params[i] = rte_malloc(NULL, sizeof(struct lcore_params), 0);
		if (!worker_params[i]) {
			printf("lcore parameters malloc failure for lcore %d\n", lcore_id);
			break;
		}
		if (is_dma) {
			worker_params[i]->dma_name = ldm->dma_names[i];
			worker_params[i]->dev_id = ldm->dma_ids[i];
			worker_params[i]->kick_batch = kick_batch;
		}
		worker_params[i]->worker_id = i;
		worker_params[i]->nr_buf = (uint32_t)(nr_buf / nb_workers);
		worker_params[i]->buf_size = buf_size;
		worker_params[i]->test_secs = test_secs;
		worker_params[i]->srcs = srcs + offset;
		worker_params[i]->dsts = dsts + offset;
		worker_params[i]->scenario_id = cfg->scenario_id;
		worker_params[i]->lcore_id = lcore_id;

		if (is_dma)
			rte_eal_remote_launch(do_dma_mem_copy, (void *)(&i), lcore_id);
		else
			rte_eal_remote_launch(do_cpu_mem_copy, (void *)(&i), lcore_id);
	}

	while (1) {
		bool ready = true;
		for (i = 0; i < nb_workers; i++) {
			if (worker_params[i]->worker_info.ready_flag == false) {
				ready = 0;
				break;
			}
		}
		if (ready)
			break;
	}

	for (i = 0; i < nb_workers; i++)
		worker_params[i]->worker_info.start_flag = true;

	usleep(TEST_WAIT_U_SECOND);
	for (i = 0; i < nb_workers; i++)
		worker_params[i]->worker_info.test_cpl = worker_params[i]->worker_info.total_cpl;

	usleep(test_secs * 1000 * 1000);
	for (i = 0; i < nb_workers; i++)
		worker_params[i]->worker_info.test_cpl = worker_params[i]->worker_info.total_cpl -
						worker_params[i]->worker_info.test_cpl;

	for (i = 0; i < nb_workers; i++)
		worker_params[i]->worker_info.stop_flag = true;

	rte_eal_mp_wait_lcore();

	for (i = 0; i < nb_workers; i++) {
		calc_result(buf_size, nr_buf, nb_workers, test_secs,
			worker_params[i]->worker_info.test_cpl,
			&memory, &avg_cycles, &bandwidth, &mops);
		output_result(cfg->scenario_id, worker_params[i]->lcore_id,
					worker_params[i]->dma_name, avg_cycles, buf_size,
					nr_buf / nb_workers, memory, bandwidth, mops, is_dma);
	}

out:
	/* free env */
	if (srcs)
		rte_pktmbuf_free_bulk(srcs, nr_buf);
	if (dsts)
		rte_pktmbuf_free_bulk(dsts, nr_buf);

	if (src_pool)
		rte_mempool_free(src_pool);
	if (dst_pool)
		rte_mempool_free(dst_pool);

	if (is_dma) {
		for (i = 0; i < nb_workers; i++) {
			printf("Stopping dmadev %d\n", ldm->dma_ids[i]);
			rte_dma_stop(ldm->dma_ids[i]);
		}
	}
}
