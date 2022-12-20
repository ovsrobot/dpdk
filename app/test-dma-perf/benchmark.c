/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include <inttypes.h>

#include <rte_time.h>
#include <rte_mbuf.h>
#include <rte_dmadev.h>
#include <rte_malloc.h>
#include <rte_lcore.h>

#include "main.h"
#include "benchmark.h"


#define MAX_DMA_CPL_NB 255

#define CSV_LINE_DMA_FMT "Scenario %u,%u,%u,%u,%u,%u,%" PRIu64 ",%.3lf,%" PRIu64 "\n"
#define CSV_LINE_CPU_FMT "Scenario %u,%u,NA,%u,%u,%u,%" PRIu64 ",%.3lf,%" PRIu64 "\n"

struct lcore_params {
	uint16_t dev_id;
	uint32_t nr_buf;
	uint16_t kick_batch;
	uint32_t buf_size;
	uint32_t repeat_times;
	uint16_t mpool_iter_step;
	struct rte_mbuf **srcs;
	struct rte_mbuf **dsts;
	uint8_t scenario_id;
};

struct buf_info {
	struct rte_mbuf **array;
	uint32_t nr_buf;
	uint32_t buf_size;
};

static struct rte_mempool *src_pool;
static struct rte_mempool *dst_pool;

uint16_t dmadev_ids[MAX_WORKER_NB];
uint32_t nb_dmadevs;

extern char output_str[MAX_WORKER_NB][MAX_OUTPUT_STR_LEN];

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
calc_result(struct lcore_params *p, uint64_t cp_cycle_sum, double time_sec,
			uint32_t repeat_times, uint32_t *memory, uint64_t *ave_cycle,
			float *bandwidth, uint64_t *ops)
{
	*memory = (p->buf_size * p->nr_buf * 2) / (1024 * 1024);
	*ave_cycle = cp_cycle_sum / (p->repeat_times * p->nr_buf);
	*bandwidth = p->buf_size * 8 * rte_get_timer_hz() / (*ave_cycle * 1000 * 1000 * 1000.0);
	*ops = (double)p->nr_buf * repeat_times / time_sec;
}

static void
output_result(uint8_t scenario_id, uint32_t lcore_id, uint16_t dev_id, uint64_t ave_cycle,
			uint32_t buf_size, uint32_t nr_buf, uint32_t memory,
			float bandwidth, uint64_t ops, bool is_dma)
{
	if (is_dma)
		printf("lcore %u, DMA %u:\n"
				"average cycles: %" PRIu64 ","
				" buffer size: %u, nr_buf: %u,"
				" memory: %uMB, frequency: %" PRIu64 ".\n",
				lcore_id,
				dev_id,
				ave_cycle,
				buf_size,
				nr_buf,
				memory,
				rte_get_timer_hz());
	else
		printf("lcore %u\n"
			"average cycles: %" PRIu64 ","
			" buffer size: %u, nr_buf: %u,"
			" memory: %uMB, frequency: %" PRIu64 ".\n",
			lcore_id,
			ave_cycle,
			buf_size,
			nr_buf,
			memory,
			rte_get_timer_hz());

	printf("Average bandwidth: %.3lfGbps, OPS: %" PRIu64 "\n", bandwidth, ops);

	if (is_dma)
		snprintf(output_str[lcore_id], MAX_OUTPUT_STR_LEN,
			CSV_LINE_DMA_FMT,
			scenario_id, lcore_id, dev_id, buf_size,
			nr_buf, memory, ave_cycle, bandwidth, ops);
	else
		snprintf(output_str[lcore_id], MAX_OUTPUT_STR_LEN,
			CSV_LINE_CPU_FMT,
			scenario_id, lcore_id, buf_size,
			nr_buf, memory, ave_cycle, bandwidth, ops);
}

static inline void
cache_flush_buf(void *arg)
{
	char *data;
	char *addr;
	struct buf_info *info = arg;
	struct rte_mbuf **srcs = info->array;
	uint32_t i, k;

	for (i = 0; i < info->nr_buf; i++) {
		data = rte_pktmbuf_mtod(srcs[i], char *);
		for (k = 0; k < info->buf_size / 64; k++) {
			addr = (k * 64 + data);
			__builtin_ia32_clflush(addr);
		}
	}
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
		rte_exit(EXIT_FAILURE, "Error with rte_dma_configure()\n");

	if (rte_dma_vchan_setup(dev_id, vchan, &qconf) != 0) {
		printf("Error with queue configuration\n");
		rte_panic();
	}

	rte_dma_info_get(dev_id, &info);
	if (info.nb_vchans != 1) {
		printf("Error, no configured queues reported on device id %u\n", dev_id);
		rte_panic();
	}
	if (rte_dma_start(dev_id) != 0)
		rte_exit(EXIT_FAILURE, "Error with rte_dma_start()\n");
}

static int
config_dmadevs(uint32_t nb_workers, uint32_t ring_size)
{
	int16_t dev_id = rte_dma_next_dev(0);
	uint32_t i;

	nb_dmadevs = 0;

	for (i = 0; i < nb_workers; i++) {
		if (dev_id == -1)
			goto end;

		dmadev_ids[i] = dev_id;
		configure_dmadev_queue(dmadev_ids[i], ring_size);
		dev_id = rte_dma_next_dev(dev_id + 1);
		++nb_dmadevs;
	}

end:
	if (nb_dmadevs < nb_workers) {
		printf("Not enough dmadevs (%u) for all workers (%u).\n", nb_dmadevs, nb_workers);
		return -1;
	}

	RTE_LOG(INFO, DMA, "Number of used dmadevs: %u.\n", nb_dmadevs);

	return 0;
}

static inline void
do_dma_mem_copy(uint16_t dev_id, uint32_t nr_buf, uint16_t kick_batch, uint32_t buf_size,
			uint16_t mpool_iter_step, struct rte_mbuf **srcs, struct rte_mbuf **dsts)
{
	int64_t async_cnt = 0;
	int nr_cpl = 0;
	uint32_t index;
	uint16_t offset;
	uint32_t i;

	for (offset = 0; offset < mpool_iter_step; offset++) {
		for (i = 0; index = i * mpool_iter_step + offset, index < nr_buf; i++) {
			if (unlikely(rte_dma_copy(dev_id,
						0,
						srcs[index]->buf_iova + srcs[index]->data_off,
						dsts[index]->buf_iova + dsts[index]->data_off,
						buf_size,
						0) < 0)) {
				rte_dma_submit(dev_id, 0);
				while (rte_dma_burst_capacity(dev_id, 0) == 0) {
					nr_cpl = rte_dma_completed(dev_id, 0, MAX_DMA_CPL_NB,
								NULL, NULL);
					async_cnt -= nr_cpl;
				}
				if (rte_dma_copy(dev_id,
						0,
						srcs[index]->buf_iova + srcs[index]->data_off,
						dsts[index]->buf_iova + dsts[index]->data_off,
						buf_size,
						0) < 0) {
					printf("enqueue fail again at %u\n", index);
					printf("space:%d\n", rte_dma_burst_capacity(dev_id, 0));
					rte_exit(EXIT_FAILURE, "DMA enqueue failed\n");
				}
			}
			async_cnt++;

			/**
			 * When '&' is used to wrap an index, mask must be a power of 2.
			 * That is, kick_batch must be 2^n.
			 */
			if (unlikely((async_cnt % kick_batch) == 0)) {
				rte_dma_submit(dev_id, 0);
				/* add a poll to avoid ring full */
				nr_cpl = rte_dma_completed(dev_id, 0, MAX_DMA_CPL_NB, NULL, NULL);
				async_cnt -= nr_cpl;
			}
		}

		rte_dma_submit(dev_id, 0);
		while (async_cnt > 0) {
			nr_cpl = rte_dma_completed(dev_id, 0, MAX_DMA_CPL_NB, NULL, NULL);
			async_cnt -= nr_cpl;
		}
	}
}

static int
dma_mem_copy(void *p)
{
	uint64_t ops;
	uint32_t memory;
	float bandwidth;
	double time_sec;
	uint32_t lcore_id = rte_lcore_id();
	struct lcore_params *params = (struct lcore_params *)p;
	uint32_t repeat_times = params->repeat_times;
	uint32_t buf_size = params->buf_size;
	uint16_t kick_batch = params->kick_batch;
	uint32_t lcore_nr_buf = params->nr_buf;
	uint16_t dev_id = params->dev_id;
	uint16_t mpool_iter_step = params->mpool_iter_step;
	struct rte_mbuf **srcs = params->srcs;
	struct rte_mbuf **dsts = params->dsts;
	uint64_t begin, end, total_cycles = 0, avg_cycles = 0;
	uint32_t r;

	begin = rte_rdtsc();

	for (r = 0; r < repeat_times; r++)
		do_dma_mem_copy(dev_id, lcore_nr_buf, kick_batch, buf_size,
			mpool_iter_step, srcs, dsts);

	end = rte_rdtsc();
	total_cycles = end - begin;
	time_sec = (double)total_cycles / rte_get_timer_hz();

	calc_result(params, total_cycles, time_sec, repeat_times, &memory,
			&avg_cycles, &bandwidth, &ops);
	output_result(params->scenario_id, lcore_id, dev_id, avg_cycles, buf_size, lcore_nr_buf,
			memory, bandwidth, ops, true);

	rte_free(p);

	return 0;
}

static int
cpu_mem_copy(void *p)
{
	uint32_t idx;
	uint32_t lcore_id;
	uint32_t memory;
	uint64_t ops;
	float bandwidth;
	double time_sec;
	struct lcore_params *params = (struct lcore_params *)p;
	uint32_t repeat_times = params->repeat_times;
	uint32_t buf_size = params->buf_size;
	uint32_t lcore_nr_buf = params->nr_buf;
	uint16_t mpool_iter_step = params->mpool_iter_step;
	struct rte_mbuf **srcs = params->srcs;
	struct rte_mbuf **dsts = params->dsts;
	uint64_t begin, end, total_cycles = 0, avg_cycles = 0;
	uint32_t k, j, offset;

	begin = rte_rdtsc();

	for (k = 0; k < repeat_times; k++) {
		/* copy buffer form src to dst */
		for (offset = 0; offset < mpool_iter_step; offset++) {
			for (j = 0; idx = j * mpool_iter_step + offset, idx < lcore_nr_buf; j++) {
				rte_memcpy((void *)(uintptr_t)rte_mbuf_data_iova(dsts[idx]),
					(void *)(uintptr_t)rte_mbuf_data_iova(srcs[idx]),
					(size_t)buf_size);
			}
		}
	}

	end = rte_rdtsc();
	total_cycles = end - begin;
	time_sec = (double)total_cycles / rte_get_timer_hz();

	lcore_id = rte_lcore_id();

	calc_result(params, total_cycles, time_sec, repeat_times, &memory,
			&avg_cycles, &bandwidth, &ops);
	output_result(params->scenario_id, lcore_id, 0, avg_cycles, buf_size, lcore_nr_buf,
			memory, bandwidth, ops, false);

	rte_free(p);

	return 0;
}

static int
setup_memory_env(struct test_configure *cfg, struct rte_mbuf ***srcs,
			struct rte_mbuf ***dsts)
{
	uint32_t i;
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

	*srcs = (struct rte_mbuf **)(malloc(nr_buf * sizeof(struct rte_mbuf *)));
	if (*srcs == NULL) {
		printf("Error: srcs malloc failed.\n");
		return -1;
	}

	*dsts = (struct rte_mbuf **)(malloc(nr_buf * sizeof(struct rte_mbuf *)));
	if (*dsts == NULL) {
		printf("Error: dsts malloc failed.\n");
		return -1;
	}

	for (i = 0; i < nr_buf; i++) {
		(*srcs)[i] = rte_pktmbuf_alloc(src_pool);
		(*dsts)[i] = rte_pktmbuf_alloc(dst_pool);
		if ((!(*srcs)[i]) || (!(*dsts)[i])) {
			printf("src: %p, dst: %p\n", (*srcs)[i], (*dsts)[i]);
			return -1;
		}

		(*srcs)[i]->data_len = (*srcs)[i]->pkt_len = buf_size;
		(*dsts)[i]->data_len = (*dsts)[i]->pkt_len = buf_size;
	}

	return 0;
}

void
dma_mem_copy_benchmark(struct test_configure *cfg)
{
	uint32_t i;
	uint32_t offset;
	unsigned int lcore_id  = 0;
	struct rte_mbuf **srcs = NULL, **dsts = NULL;
	unsigned int buf_size = cfg->buf_size.cur;
	uint16_t kick_batch = cfg->kick_batch.cur;
	uint16_t mpool_iter_step = cfg->mpool_iter_step;
	uint32_t nr_buf = cfg->nr_buf = (cfg->mem_size.cur * 1024 * 1024) / (cfg->buf_size.cur * 2);
	uint16_t nb_workers = cfg->nb_workers;
	uint32_t repeat_times = cfg->repeat_times;

	if (setup_memory_env(cfg, &srcs, &dsts) < 0)
		goto out;

	if (config_dmadevs(nb_workers, cfg->ring_size.cur) < 0)
		goto out;

	if (cfg->cache_flush) {
		struct buf_info info;

		info.array = srcs;
		info.buf_size = buf_size;
		info.nr_buf = nr_buf;
		cache_flush_buf(&info);

		info.array = dsts;
		cache_flush_buf(&info);
		__builtin_ia32_mfence();
	}

	printf("Start testing....\n");

	for (i = 0; i < nb_workers; i++) {
		lcore_id = rte_get_next_lcore(lcore_id, true, true);
		offset = nr_buf / nb_workers * i;

		struct lcore_params *p = rte_malloc(NULL, sizeof(*p), 0);
		if (!p) {
			printf("lcore parameters malloc failure for lcore %d\n", lcore_id);
			break;
		}
		*p = (struct lcore_params) {
			dmadev_ids[i],
			(uint32_t)(nr_buf/nb_workers),
			kick_batch,
			buf_size,
			repeat_times,
			mpool_iter_step,
			srcs + offset,
			dsts + offset,
			cfg->scenario_id
		};

		rte_eal_remote_launch((lcore_function_t *)dma_mem_copy, p, lcore_id);
	}

	rte_eal_mp_wait_lcore();

out:
	/* free env */
	if (srcs) {
		for (i = 0; i < nr_buf; i++)
			rte_pktmbuf_free(srcs[i]);
		free(srcs);
	}
	if (dsts) {
		for (i = 0; i < nr_buf; i++)
			rte_pktmbuf_free(dsts[i]);
		free(dsts);
	}

	if (src_pool)
		rte_mempool_free(src_pool);
	if (dst_pool)
		rte_mempool_free(dst_pool);

	for (i = 0; i < nb_dmadevs; i++) {
		printf("Stopping dmadev %d\n", dmadev_ids[i]);
		rte_dma_stop(dmadev_ids[i]);
	}
}

void
cpu_mem_copy_benchmark(struct test_configure *cfg)
{
	uint32_t i, offset;
	uint32_t repeat_times = cfg->repeat_times;
	uint32_t kick_batch = cfg->kick_batch.cur;
	uint32_t buf_size = cfg->buf_size.cur;
	uint32_t nr_buf = cfg->nr_buf = (cfg->mem_size.cur * 1024 * 1024) / (cfg->buf_size.cur * 2);
	uint16_t nb_workers = cfg->nb_workers;
	uint16_t mpool_iter_step = cfg->mpool_iter_step;
	struct rte_mbuf **srcs  = NULL, **dsts  = NULL;
	unsigned int lcore_id = 0;

	if (setup_memory_env(cfg, &srcs, &dsts) < 0)
		goto out;

	for (i = 0; i < nb_workers; i++) {
		lcore_id = rte_get_next_lcore(lcore_id, rte_lcore_count() > 1 ? 1 : 0, 1);
		offset = nr_buf / nb_workers * i;
		struct lcore_params *p = rte_malloc(NULL, sizeof(*p), 0);
		if (!p) {
			printf("lcore parameters malloc failure for lcore %d\n", lcore_id);
			break;
		}
		*p = (struct lcore_params) { 0, nr_buf/nb_workers, kick_batch,
						buf_size, repeat_times, mpool_iter_step,
						srcs + offset, dsts + offset, cfg->scenario_id };
		rte_eal_remote_launch((lcore_function_t *)cpu_mem_copy, p, lcore_id);
	}

	rte_eal_mp_wait_lcore();

out:
	/* free env */
	if (srcs) {
		for (i = 0; i < nr_buf; i++)
			rte_pktmbuf_free(srcs[i]);
		free(srcs);
	}
	if (dsts) {
		for (i = 0; i < nr_buf; i++)
			rte_pktmbuf_free(dsts[i]);
		free(dsts);
	}

	if (src_pool)
		rte_mempool_free(src_pool);
	if (dst_pool)
		rte_mempool_free(dst_pool);
}
