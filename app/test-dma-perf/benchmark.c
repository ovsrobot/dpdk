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
#include <rte_random.h>

#include "main.h"

#define MAX_DMA_CPL_NB 255

#define TEST_WAIT_U_SECOND 10000
#define POLL_MAX 1000

#define CSV_LINE_DMA_FMT "Scenario %u,%u,%s,%u,%u,%u,%u,%.2lf,%" PRIu64 ",%.3lf,%.3lf\n"
#define CSV_LINE_CPU_FMT "Scenario %u,%u,NA,NA,NA,%u,%u,%.2lf,%" PRIu64 ",%.3lf,%.3lf\n"

#define CSV_TOTAL_LINE_FMT "Scenario %u Summary, , , , , ,%u,%.2lf,%u,%.3lf,%.3lf\n"

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
	struct rte_dma_sge *src_sges;
	struct rte_dma_sge *dst_sges;
	uint8_t src_ptrs;
	uint8_t dst_ptrs;
	volatile struct worker_info worker_info;
};

static struct rte_mempool *src_pool;
static struct rte_mempool *dst_pool;

static struct lcore_params *lcores[MAX_WORKER_NB];

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
				uint32_t total_cnt, float *memory, uint32_t *ave_cycle,
				float *bandwidth, float *mops)
{
	float ops;

	*memory = (float)(buf_size * (nr_buf / nb_workers) * 2) / (1024 * 1024);
	*ave_cycle = test_secs * rte_get_timer_hz() / total_cnt;
	ops = (float)total_cnt / test_secs;
	*mops = ops / (1000 * 1000);
	*bandwidth = (ops * buf_size * 8) / (1000 * 1000 * 1000);
}

static void
output_result(struct test_configure *cfg, struct lcore_params *para,
			uint16_t kick_batch, uint64_t ave_cycle, uint32_t buf_size,
			uint32_t nr_buf, float memory, float bandwidth, float mops)
{
	uint16_t ring_size = cfg->ring_size.cur;
	uint8_t scenario_id = cfg->scenario_id;
	uint32_t lcore_id = para->lcore_id;
	char *dma_name = para->dma_name;

	if (cfg->is_dma) {
		printf("lcore %u, DMA %s, DMA Ring Size: %u, Kick Batch Size: %u", lcore_id,
		       dma_name, ring_size, kick_batch);
		if (cfg->is_sg)
			printf(" DMA src ptrs: %u, dst ptrs: %u",
			       para->src_ptrs, para->dst_ptrs);
		printf(".\n");
	} else {
		printf("lcore %u\n", lcore_id);
	}

	printf("Average Cycles/op: %" PRIu64 ", Buffer Size: %u B, Buffer Number: %u, Memory: %.2lf MB, Frequency: %.3lf Ghz.\n",
			ave_cycle, buf_size, nr_buf, memory, rte_get_timer_hz()/1000000000.0);
	printf("Average Bandwidth: %.3lf Gbps, MOps: %.3lf\n", bandwidth, mops);

	if (cfg->is_dma)
		snprintf(output_str[lcore_id], MAX_OUTPUT_STR_LEN, CSV_LINE_DMA_FMT,
			scenario_id, lcore_id, dma_name, ring_size, kick_batch, buf_size,
			nr_buf, memory, ave_cycle, bandwidth, mops);
	else
		snprintf(output_str[lcore_id], MAX_OUTPUT_STR_LEN, CSV_LINE_CPU_FMT,
			scenario_id, lcore_id, buf_size,
			nr_buf, memory, ave_cycle, bandwidth, mops);
}

static inline void
cache_flush_buf(__rte_unused struct rte_mbuf **array,
		__rte_unused uint32_t buf_size,
		__rte_unused uint32_t nr_buf)
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

static int
vchan_data_populate(uint32_t dev_id, struct rte_dma_vchan_conf *qconf,
		    struct test_configure *cfg)
{
	struct rte_dma_info info;

	qconf->direction = cfg->transfer_dir;

	rte_dma_info_get(dev_id, &info);
	if (!(RTE_BIT64(qconf->direction) & info.dev_capa))
		return -1;

	qconf->nb_desc = cfg->ring_size.cur;

	switch (qconf->direction) {
	case RTE_DMA_DIR_MEM_TO_DEV:
		qconf->dst_port.pcie.vfen = 1;
		qconf->dst_port.port_type = RTE_DMA_PORT_PCIE;
		qconf->dst_port.pcie.coreid = cfg->dcoreid;
		qconf->dst_port.pcie.vfid = cfg->vfid;
		qconf->dst_port.pcie.pfid = cfg->pfid;
		break;
	case RTE_DMA_DIR_DEV_TO_MEM:
		qconf->src_port.pcie.vfen = 1;
		qconf->src_port.port_type = RTE_DMA_PORT_PCIE;
		qconf->src_port.pcie.coreid = cfg->scoreid;
		qconf->src_port.pcie.vfid = cfg->vfid;
		qconf->src_port.pcie.pfid = cfg->pfid;
		break;
	case RTE_DMA_DIR_MEM_TO_MEM:
	case RTE_DMA_DIR_DEV_TO_DEV:
		break;
	}

	return 0;
}

/* Configuration of device. */
static void
configure_dmadev_queue(uint32_t dev_id, struct test_configure *cfg, uint8_t ptrs_max)
{
	uint16_t vchan = 0;
	struct rte_dma_info info;
	struct rte_dma_conf dev_config = { .nb_vchans = 1 };
	struct rte_dma_vchan_conf qconf = { 0 };

	if (vchan_data_populate(dev_id, &qconf, cfg) != 0)
		rte_exit(EXIT_FAILURE, "Error with vchan data populate.\n");

	if (rte_dma_configure(dev_id, &dev_config) != 0)
		rte_exit(EXIT_FAILURE, "Error with dma configure.\n");

	if (rte_dma_vchan_setup(dev_id, vchan, &qconf) != 0)
		rte_exit(EXIT_FAILURE, "Error with queue configuration.\n");

	if (rte_dma_info_get(dev_id, &info) != 0)
		rte_exit(EXIT_FAILURE, "Error with getting device info.\n");

	if (info.nb_vchans != 1)
		rte_exit(EXIT_FAILURE, "Error, no configured queues reported on device id. %u\n",
				dev_id);

	if (info.max_sges < ptrs_max)
		rte_exit(EXIT_FAILURE, "Error, DMA ptrs more than supported by device id %u.\n",
				dev_id);

	if (rte_dma_start(dev_id) != 0)
		rte_exit(EXIT_FAILURE, "Error with dma start.\n");
}

static int
config_dmadevs(struct test_configure *cfg)
{
	struct lcore_dma_map_t *ldm = &cfg->lcore_dma_map;
	uint32_t nb_workers = ldm->cnt;
	uint32_t i;
	int dev_id;
	uint16_t nb_dmadevs = 0;
	uint8_t ptrs_max = 0;
	char *dma_name;

	if (cfg->is_sg)
		ptrs_max = RTE_MAX(cfg->src_ptrs, cfg->dst_ptrs);

	for (i = 0; i < ldm->cnt; i++) {
		dma_name = ldm->dma_names[i];
		dev_id = rte_dma_get_dev_id_by_name(dma_name);
		if (dev_id < 0) {
			fprintf(stderr, "Error: Fail to find DMA %s.\n", dma_name);
			goto end;
		}

		ldm->dma_ids[i] = dev_id;
		configure_dmadev_queue(dev_id, cfg, ptrs_max);
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

static void
error_exit(int dev_id)
{
	rte_dma_stop(dev_id);
	rte_dma_close(dev_id);
	rte_exit(EXIT_FAILURE, "DMA error\n");
}

static inline void
do_dma_submit_and_poll(uint16_t dev_id, uint64_t *async_cnt,
			volatile struct worker_info *worker_info)
{
	int ret;
	uint16_t nr_cpl;

	ret = rte_dma_submit(dev_id, 0);
	if (ret < 0)
		error_exit(dev_id);

	nr_cpl = rte_dma_completed(dev_id, 0, MAX_DMA_CPL_NB, NULL, NULL);
	*async_cnt -= nr_cpl;
	worker_info->total_cpl += nr_cpl;
}

static inline int
do_dma_plain_mem_copy(void *p)
{
	struct lcore_params *para = (struct lcore_params *)p;
	volatile struct worker_info *worker_info = &(para->worker_info);
	const uint16_t dev_id = para->dev_id;
	const uint32_t nr_buf = para->nr_buf;
	const uint16_t kick_batch = para->kick_batch;
	const uint32_t buf_size = para->buf_size;
	struct rte_mbuf **srcs = para->srcs;
	struct rte_mbuf **dsts = para->dsts;
	uint16_t nr_cpl;
	uint64_t async_cnt = 0;
	uint32_t i;
	uint32_t poll_cnt = 0;
	int ret;

	worker_info->stop_flag = false;
	worker_info->ready_flag = true;

	while (!worker_info->start_flag)
		;

	while (1) {
		for (i = 0; i < nr_buf; i++) {
dma_copy:
			ret = rte_dma_copy(dev_id, 0, rte_mbuf_data_iova(srcs[i]),
				rte_mbuf_data_iova(dsts[i]), buf_size, 0);
			if (unlikely(ret < 0)) {
				if (ret == -ENOSPC) {
					do_dma_submit_and_poll(dev_id, &async_cnt, worker_info);
					goto dma_copy;
				} else
					error_exit(dev_id);
			}
			async_cnt++;

			if ((async_cnt % kick_batch) == 0)
				do_dma_submit_and_poll(dev_id, &async_cnt, worker_info);
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
do_dma_sg_mem_copy(void *p)
{
	struct lcore_params *para = (struct lcore_params *)p;
	volatile struct worker_info *worker_info = &(para->worker_info);
	struct rte_dma_sge *src_sges = para->src_sges;
	struct rte_dma_sge *dst_sges = para->dst_sges;
	const uint16_t kick_batch = para->kick_batch;
	const uint8_t src_ptrs = para->src_ptrs;
	const uint8_t dst_ptrs = para->dst_ptrs;
	const uint16_t dev_id = para->dev_id;
	uint32_t nr_buf = para->nr_buf;
	uint64_t async_cnt = 0;
	uint32_t poll_cnt = 0;
	uint16_t nr_cpl;
	uint32_t i, j;
	int ret;

	nr_buf /= RTE_MAX(src_ptrs, dst_ptrs);
	worker_info->stop_flag = false;
	worker_info->ready_flag = true;

	while (!worker_info->start_flag)
		;

	while (1) {
		j = 0;
		for (i = 0; i < nr_buf; i++) {
dma_copy:
			ret = rte_dma_copy_sg(dev_id, 0,
				&src_sges[i * src_ptrs], &dst_sges[j * dst_ptrs],
				src_ptrs, dst_ptrs, 0);
			if (unlikely(ret < 0)) {
				if (ret == -ENOSPC) {
					do_dma_submit_and_poll(dev_id, &async_cnt, worker_info);
					goto dma_copy;
				} else
					error_exit(dev_id);
			}
			async_cnt++;
			j++;

			if ((async_cnt % kick_batch) == 0)
				do_dma_submit_and_poll(dev_id, &async_cnt, worker_info);
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
	struct lcore_params *para = (struct lcore_params *)p;
	volatile struct worker_info *worker_info = &(para->worker_info);
	const uint32_t nr_buf = para->nr_buf;
	const uint32_t buf_size = para->buf_size;
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

static void
dummy_free_ext_buf(void *addr, void *opaque)
{
	RTE_SET_USED(addr);
	RTE_SET_USED(opaque);
}

static int
setup_memory_env(struct test_configure *cfg,
			 struct rte_mbuf ***srcs, struct rte_mbuf ***dsts,
			 struct rte_dma_sge **src_sges, struct rte_dma_sge **dst_sges)
{
	static struct rte_mbuf_ext_shared_info *ext_buf_info;
	unsigned int buf_size = cfg->buf_size.cur;
	unsigned int nr_sockets;
	uint32_t nr_buf = cfg->nr_buf;
	uint32_t i;

	nr_sockets = rte_socket_count();
	if (cfg->src_numa_node >= nr_sockets ||
		cfg->dst_numa_node >= nr_sockets) {
		printf("Error: Source or destination numa exceeds the acture numa nodes.\n");
		return -1;
	}

	src_pool = rte_pktmbuf_pool_create("Benchmark_DMA_SRC",
			nr_buf,
			0,
			0,
			buf_size + RTE_PKTMBUF_HEADROOM,
			cfg->src_numa_node);
	if (src_pool == NULL) {
		PRINT_ERR("Error with source mempool creation.\n");
		return -1;
	}

	dst_pool = rte_pktmbuf_pool_create("Benchmark_DMA_DST",
			nr_buf,
			0,
			0,
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

	if (rte_pktmbuf_alloc_bulk(src_pool, *srcs, nr_buf) != 0) {
		printf("alloc src mbufs failed.\n");
		return -1;
	}

	if (rte_pktmbuf_alloc_bulk(dst_pool, *dsts, nr_buf) != 0) {
		printf("alloc dst mbufs failed.\n");
		return -1;
	}

	for (i = 0; i < nr_buf; i++) {
		memset(rte_pktmbuf_mtod((*srcs)[i], void *), rte_rand(), buf_size);
		memset(rte_pktmbuf_mtod((*dsts)[i], void *), 0, buf_size);
	}

	if (cfg->transfer_dir == RTE_DMA_DIR_DEV_TO_MEM ||
	    cfg->transfer_dir == RTE_DMA_DIR_MEM_TO_DEV) {
		ext_buf_info = rte_malloc(NULL, sizeof(struct rte_mbuf_ext_shared_info), 0);
		if (ext_buf_info == NULL) {
			printf("Error: ext_buf_info malloc failed.\n");
			return -1;
		}
	}

	if (cfg->transfer_dir == RTE_DMA_DIR_DEV_TO_MEM) {
		ext_buf_info->free_cb = dummy_free_ext_buf;
		ext_buf_info->fcb_opaque = NULL;
		for (i = 0; i < nr_buf; i++) {
			/* Using mbuf structure to hold remote iova address. */
			rte_pktmbuf_attach_extbuf((*srcs)[i], (void *)cfg->raddr,
						  (rte_iova_t)cfg->raddr, 0, ext_buf_info);
			rte_mbuf_ext_refcnt_update(ext_buf_info, 1);
		}
	}

	if (cfg->transfer_dir == RTE_DMA_DIR_MEM_TO_DEV) {
		ext_buf_info->free_cb = dummy_free_ext_buf;
		ext_buf_info->fcb_opaque = NULL;
		for (i = 0; i < nr_buf; i++) {
			/* Using mbuf structure to hold remote iova address. */
			rte_pktmbuf_attach_extbuf((*dsts)[i], (void *)cfg->raddr,
						  (rte_iova_t)cfg->raddr, 0, ext_buf_info);
			rte_mbuf_ext_refcnt_update(ext_buf_info, 1);
		}
	}

	if (cfg->is_sg) {
		uint8_t src_ptrs = cfg->src_ptrs;
		uint8_t dst_ptrs = cfg->dst_ptrs;
		uint32_t sglen_src, sglen_dst;

		*src_sges = rte_zmalloc(NULL, nr_buf * sizeof(struct rte_dma_sge),
					RTE_CACHE_LINE_SIZE);
		if (*src_sges == NULL) {
			printf("Error: src_sges array malloc failed.\n");
			return -1;
		}

		*dst_sges = rte_zmalloc(NULL, nr_buf * sizeof(struct rte_dma_sge),
					RTE_CACHE_LINE_SIZE);
		if (*dst_sges == NULL) {
			printf("Error: dst_sges array malloc failed.\n");
			return -1;
		}

		sglen_src = buf_size / src_ptrs;
		sglen_dst = buf_size / dst_ptrs;

		for (i = 0; i < nr_buf; i++) {
			(*src_sges)[i].addr = rte_pktmbuf_iova((*srcs)[i]);
			(*src_sges)[i].length = sglen_src;
			if (!((i+1) % src_ptrs))
				(*src_sges)[i].length += (buf_size % src_ptrs);

			(*dst_sges)[i].addr = rte_pktmbuf_iova((*dsts)[i]);
			(*dst_sges)[i].length = sglen_dst;
			if (!((i+1) % dst_ptrs))
				(*dst_sges)[i].length += (buf_size % dst_ptrs);
		}
	}

	return 0;
}

int
mem_copy_benchmark(struct test_configure *cfg)
{
	uint32_t i, j;
	uint32_t offset;
	unsigned int lcore_id = 0;
	struct rte_mbuf **srcs = NULL, **dsts = NULL, **m = NULL;
	struct rte_dma_sge *src_sges = NULL, *dst_sges = NULL;
	struct lcore_dma_map_t *ldm = &cfg->lcore_dma_map;
	const uint32_t mcore_id = rte_get_main_lcore();
	unsigned int buf_size = cfg->buf_size.cur;
	uint16_t kick_batch = cfg->kick_batch.cur;
	uint16_t nb_workers = ldm->cnt;
	uint16_t test_secs = cfg->test_secs;
	float memory = 0;
	uint32_t avg_cycles = 0;
	uint32_t avg_cycles_total;
	float mops, mops_total;
	float bandwidth, bandwidth_total;
	uint32_t nr_sgsrc = 0, nr_sgdst = 0;
	uint32_t nr_buf;
	int ret = 0;

	/* Align number of buffers according to workers count */
	nr_buf = (cfg->mem_size.cur * 1024 * 1024) / (cfg->buf_size.cur * 2);
	nr_buf -= (nr_buf % nb_workers);
	if (cfg->is_sg) {
		nr_buf /= nb_workers;
		nr_buf -= nr_buf % (cfg->src_ptrs * cfg->dst_ptrs);
		nr_buf *= nb_workers;

		if (cfg->dst_ptrs > cfg->src_ptrs) {
			nr_sgsrc = (nr_buf / cfg->dst_ptrs * cfg->src_ptrs);
			nr_sgdst = nr_buf;
		} else {
			nr_sgsrc = nr_buf;
			nr_sgdst = (nr_buf / cfg->src_ptrs * cfg->dst_ptrs);
		}
	}

	cfg->nr_buf = nr_buf;
	if (setup_memory_env(cfg, &srcs, &dsts, &src_sges, &dst_sges) < 0)
		goto out;

	if (cfg->is_dma)
		if (config_dmadevs(cfg) < 0)
			goto out;

	if (cfg->cache_flush == 1) {
		cache_flush_buf(srcs, buf_size, nr_buf);
		cache_flush_buf(dsts, buf_size, nr_buf);
		rte_mb();
	}

	printf("Start testing....\n");

	for (i = 0; i < nb_workers; i++) {
		lcore_id = ldm->lcores[i];
		if (lcore_id == mcore_id) {
			printf("lcore parameters can not use main core id %d\n", mcore_id);
			goto out;
		}

		if (rte_eal_lcore_role(lcore_id) == ROLE_OFF) {
			printf("lcore parameters can not use offline core id %d\n", lcore_id);
			goto out;
		}

		offset = nr_buf / nb_workers * i;
		lcores[i] = rte_malloc(NULL, sizeof(struct lcore_params), 0);
		if (lcores[i] == NULL) {
			printf("lcore parameters malloc failure for lcore %d\n", lcore_id);
			break;
		}
		if (cfg->is_dma) {
			lcores[i]->dma_name = ldm->dma_names[i];
			lcores[i]->dev_id = ldm->dma_ids[i];
			lcores[i]->kick_batch = kick_batch;
		}
		lcores[i]->worker_id = i;
		lcores[i]->nr_buf = (uint32_t)(nr_buf / nb_workers);
		lcores[i]->buf_size = buf_size;
		lcores[i]->test_secs = test_secs;
		lcores[i]->srcs = srcs + offset;
		lcores[i]->dsts = dsts + offset;
		lcores[i]->scenario_id = cfg->scenario_id;
		lcores[i]->lcore_id = lcore_id;

		if (cfg->is_sg) {
			lcores[i]->src_ptrs = cfg->src_ptrs;
			lcores[i]->dst_ptrs = cfg->dst_ptrs;
			lcores[i]->src_sges = src_sges + (nr_sgsrc / nb_workers * i);
			lcores[i]->dst_sges = dst_sges + (nr_sgdst / nb_workers * i);
		}

		if (cfg->is_dma) {
			if (!cfg->is_sg)
				rte_eal_remote_launch(do_dma_plain_mem_copy, (void *)(lcores[i]),
					lcore_id);
			else
				rte_eal_remote_launch(do_dma_sg_mem_copy, (void *)(lcores[i]),
					lcore_id);
		} else {
			rte_eal_remote_launch(do_cpu_mem_copy, (void *)(lcores[i]), lcore_id);
		}
	}

	while (1) {
		bool ready = true;
		for (i = 0; i < nb_workers; i++) {
			if (lcores[i]->worker_info.ready_flag == false) {
				ready = 0;
				break;
			}
		}
		if (ready)
			break;
	}

	for (i = 0; i < nb_workers; i++)
		lcores[i]->worker_info.start_flag = true;

	usleep(TEST_WAIT_U_SECOND);
	for (i = 0; i < nb_workers; i++)
		lcores[i]->worker_info.test_cpl = lcores[i]->worker_info.total_cpl;

	usleep(test_secs * 1000 * 1000);
	for (i = 0; i < nb_workers; i++)
		lcores[i]->worker_info.test_cpl = lcores[i]->worker_info.total_cpl -
						lcores[i]->worker_info.test_cpl;

	for (i = 0; i < nb_workers; i++)
		lcores[i]->worker_info.stop_flag = true;

	rte_eal_mp_wait_lcore();

	if (!cfg->is_sg) {
		for (i = 0; i < (nr_buf / nb_workers) * nb_workers; i++) {
			if (memcmp(rte_pktmbuf_mtod(srcs[i], void *),
					rte_pktmbuf_mtod(dsts[i], void *),
					cfg->buf_size.cur) != 0) {
				printf("Copy validation fails for buffer number %d\n", i);
				ret = -1;
				goto out;
			}
		}
	} else {
		size_t src_remsz = buf_size % cfg->src_ptrs;
		size_t dst_remsz = buf_size % cfg->dst_ptrs;
		size_t src_sz = buf_size / cfg->src_ptrs;
		size_t dst_sz = buf_size / cfg->dst_ptrs;
		uint8_t src[buf_size], dst[buf_size];
		uint8_t *sbuf, *dbuf, *ptr;

		for (i = 0; i < (nr_buf / RTE_MAX(cfg->src_ptrs, cfg->dst_ptrs)); i++) {
			sbuf = src;
			dbuf = dst;
			ptr = NULL;

			for (j = 0; j < cfg->src_ptrs; j++) {
				ptr = rte_pktmbuf_mtod(srcs[i * cfg->src_ptrs + j], uint8_t *);
				memcpy(sbuf, ptr, src_sz);
				sbuf += src_sz;
			}

			if (src_remsz)
				memcpy(sbuf, ptr + src_sz, src_remsz);

			for (j = 0; j < cfg->dst_ptrs; j++) {
				ptr = rte_pktmbuf_mtod(dsts[i * cfg->dst_ptrs + j], uint8_t *);
				memcpy(dbuf, ptr, dst_sz);
				dbuf += dst_sz;
			}

			if (dst_remsz)
				memcpy(dbuf, ptr + dst_sz, dst_remsz);

			if (memcmp(src, dst, buf_size) != 0) {
				printf("SG Copy validation fails for buffer number %d\n",
					i * cfg->src_ptrs);
				ret = -1;
				goto out;
			}
		}
	}

	mops_total = 0;
	bandwidth_total = 0;
	avg_cycles_total = 0;
	for (i = 0; i < nb_workers; i++) {
		calc_result(buf_size, nr_buf, nb_workers, test_secs,
			lcores[i]->worker_info.test_cpl,
			&memory, &avg_cycles, &bandwidth, &mops);
		output_result(cfg, lcores[i], kick_batch, avg_cycles, buf_size,
			nr_buf / nb_workers, memory, bandwidth, mops);
		mops_total += mops;
		bandwidth_total += bandwidth;
		avg_cycles_total += avg_cycles;
	}
	printf("\nTotal Bandwidth: %.3lf Gbps, Total MOps: %.3lf\n", bandwidth_total, mops_total);
	snprintf(output_str[MAX_WORKER_NB], MAX_OUTPUT_STR_LEN, CSV_TOTAL_LINE_FMT,
			cfg->scenario_id, nr_buf, memory * nb_workers,
			avg_cycles_total / nb_workers, bandwidth_total, mops_total);

out:

	if (cfg->transfer_dir == RTE_DMA_DIR_DEV_TO_MEM)
		m = srcs;
	else if (cfg->transfer_dir == RTE_DMA_DIR_MEM_TO_DEV)
		m = dsts;

	if (m) {
		for (i = 0; i < nr_buf; i++)
			rte_pktmbuf_detach_extbuf(m[i]);

		if (m[0]->shinfo && rte_mbuf_ext_refcnt_read(m[0]->shinfo) == 0)
			rte_free(m[0]->shinfo);
	}

	/* free mbufs used in the test */
	if (srcs != NULL)
		rte_pktmbuf_free_bulk(srcs, nr_buf);
	if (dsts != NULL)
		rte_pktmbuf_free_bulk(dsts, nr_buf);

	/* free the points for the mbufs */
	rte_free(srcs);
	srcs = NULL;
	rte_free(dsts);
	dsts = NULL;

	rte_mempool_free(src_pool);
	src_pool = NULL;

	rte_mempool_free(dst_pool);
	dst_pool = NULL;

	/* free sges for mbufs */
	rte_free(src_sges);
	src_sges = NULL;

	rte_free(dst_sges);
	dst_sges = NULL;

	/* free the worker parameters */
	for (i = 0; i < nb_workers; i++) {
		rte_free(lcores[i]);
		lcores[i] = NULL;
	}

	if (cfg->is_dma) {
		for (i = 0; i < nb_workers; i++) {
			printf("Stopping dmadev %d\n", ldm->dma_ids[i]);
			rte_dma_stop(ldm->dma_ids[i]);
		}
	}

	return ret;
}
