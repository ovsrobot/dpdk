/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_mbuf.h>
#include <rte_bitmap.h>
#include <rte_reciprocal.h>

#include "rte_sched.h"
#include "rte_sched_common.h"
#include "rte_approx.h"

#ifdef __INTEL_COMPILER
#pragma warning(disable:2259) /* conversion may lose significant bits */
#endif

#ifdef RTE_SCHED_VECTOR
#include <rte_vect.h>

#ifdef RTE_ARCH_X86
#define SCHED_VECTOR_SSE4
#elif defined(RTE_MACHINE_CPUFLAG_NEON)
#define SCHED_VECTOR_NEON
#endif

#endif

#define RTE_SCHED_TB_RATE_CONFIG_ERR          (1e-7)
#define RTE_SCHED_WRR_SHIFT                   3
#define RTE_SCHED_MAX_QUEUES_PER_TC           RTE_SCHED_BE_QUEUES_PER_PIPE
#define RTE_SCHED_TRAFFIC_CLASS_BE            (RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE - 1)
#define RTE_SCHED_GRINDER_PCACHE_SIZE         (64 / RTE_SCHED_QUEUES_PER_PIPE)
#define RTE_SCHED_PIPE_INVALID                UINT32_MAX
#define RTE_SCHED_BMP_POS_INVALID             UINT32_MAX

/* Scaling for cycles_per_byte calculation
 * Chosen so that minimum rate is 480 bit/sec
 */
#define RTE_SCHED_TIME_SHIFT		      8

enum grinder_state {
	e_GRINDER_PREFETCH_PIPE = 0,
	e_GRINDER_PREFETCH_TC_QUEUE_ARRAYS,
	e_GRINDER_PREFETCH_MBUF,
	e_GRINDER_READ_MBUF
};

struct rte_sched_grinder {
	/* Pipe cache */
	uint16_t pcache_qmask[RTE_SCHED_GRINDER_PCACHE_SIZE];
	uint32_t pcache_qindex[RTE_SCHED_GRINDER_PCACHE_SIZE];
	uint32_t pcache_w;
	uint32_t pcache_r;

	/* Current pipe */
	uint32_t pindex;
	struct rte_sched_pipe *pipe;
	struct rte_sched_pipe_profile *pipe_params;
	struct rte_sched_subport *subport;

	/* Grinder state*/
	enum grinder_state state;
	uint32_t productive;

	/* TC cache */
	uint8_t tccache_qmask[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t tccache_qindex[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t tccache_w;
	uint32_t tccache_r;

	/* Current TC */
	uint32_t tc_index;
	uint32_t qpos;
	struct rte_sched_queue *queue[RTE_SCHED_MAX_QUEUES_PER_TC];
	struct rte_mbuf **qbase[RTE_SCHED_MAX_QUEUES_PER_TC];
	uint32_t qindex[RTE_SCHED_MAX_QUEUES_PER_TC];
	uint16_t qsize[RTE_SCHED_MAX_QUEUES_PER_TC];
	uint32_t qmask;
	struct rte_mbuf *pkt;

	/* WRR */
	uint16_t wrr_tokens[RTE_SCHED_BE_QUEUES_PER_PIPE];
	uint16_t wrr_mask[RTE_SCHED_BE_QUEUES_PER_PIPE];
	uint8_t wrr_cost[RTE_SCHED_BE_QUEUES_PER_PIPE];
};

struct rte_sched_subport {
	/* Token bucket (TB) */
	uint64_t tb_time; /* time of last update */
	uint32_t tb_period;
	uint32_t tb_credits_per_period;
	uint32_t tb_size;
	uint32_t tb_credits;

	/* Traffic classes (TCs) */
	uint64_t tc_time; /* time of next update */
	uint32_t tc_credits_per_period[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t tc_credits[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t tc_period;

	/* TC oversubscription */
	uint32_t tc_ov_wm;
	uint32_t tc_ov_wm_min;
	uint32_t tc_ov_wm_max;
	uint8_t tc_ov_period_id;
	uint8_t tc_ov;
	uint32_t tc_ov_n;
	double tc_ov_rate;

	/* Statistics */
	struct rte_sched_subport_stats stats;

	/* Subport Pipes*/
	uint32_t n_subport_pipes;

	uint16_t qsize[RTE_SCHED_QUEUES_PER_PIPE];
	uint32_t n_pipe_profiles;
	uint32_t n_max_pipe_profiles;
	uint32_t pipe_tc_be_rate_max;
#ifdef RTE_SCHED_RED
	struct rte_red_config red_config[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE][RTE_COLORS];
#endif

	/* Scheduling loop detection */
	uint32_t pipe_loop;
	uint32_t pipe_exhaustion;

	/* Bitmap */
	struct rte_bitmap *bmp;
	uint32_t grinder_base_bmp_pos[RTE_SCHED_PORT_N_GRINDERS] __rte_aligned_16;

	/* Grinders */
	struct rte_sched_grinder grinder[RTE_SCHED_PORT_N_GRINDERS];
	uint32_t busy_grinders;

	/* Queue base calculation */
	uint32_t qsize_add[RTE_SCHED_QUEUES_PER_PIPE];
	uint32_t qsize_sum;

	struct rte_sched_pipe *pipe;
	struct rte_sched_queue *queue;
	struct rte_sched_queue_extra *queue_extra;
	struct rte_sched_pipe_profile *pipe_profiles;
	uint8_t *bmp_array;
	struct rte_mbuf **queue_array;
	uint8_t memory[0] __rte_cache_aligned;
} __rte_cache_aligned;

struct rte_sched_pipe_profile {
	/* Token bucket (TB) */
	uint32_t tb_period;
	uint32_t tb_credits_per_period;
	uint32_t tb_size;

	/* Pipe traffic classes */
	uint32_t tc_period;
	uint32_t tc_credits_per_period[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint8_t tc_ov_weight;

	/* Pipe best-effort traffic class queues */
	uint8_t n_be_queues;

	uint8_t  wrr_cost[RTE_SCHED_BE_QUEUES_PER_PIPE];
};

struct rte_sched_pipe {
	/* Token bucket (TB) */
	uint64_t tb_time; /* time of last update */
	uint32_t tb_credits;

	/* Pipe profile and flags */
	uint32_t profile;

	/* Traffic classes (TCs) */
	uint64_t tc_time; /* time of next update */
	uint32_t tc_credits[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];

	uint8_t n_be_queues; /* Best effort traffic class queues */

	/* Weighted Round Robin (WRR) */
	uint8_t wrr_tokens[RTE_SCHED_BE_QUEUES_PER_PIPE];

	/* TC oversubscription */
	uint32_t tc_ov_credits;
	uint8_t tc_ov_period_id;
	uint8_t reserved[3];
} __rte_cache_aligned;

struct rte_sched_queue {
	uint16_t qw;
	uint16_t qr;
};

struct rte_sched_queue_extra {
	struct rte_sched_queue_stats stats;
#ifdef RTE_SCHED_RED
	struct rte_red red;
#endif
};

struct rte_sched_port {
	/* User parameters */
	uint32_t n_subports_per_port;
	uint32_t n_pipes_per_subport;
	uint32_t n_pipes_per_subport_log2;
	int socket;
	uint32_t rate;
	uint32_t mtu;
	uint32_t frame_overhead;
	uint16_t qsize[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t n_pipe_profiles;
	uint32_t pipe_tc3_rate_max;
#ifdef RTE_SCHED_RED
	struct rte_red_config red_config[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE][RTE_COLORS];
#endif

	/* Timing */
	uint64_t time_cpu_cycles;     /* Current CPU time measured in CPU cyles */
	uint64_t time_cpu_bytes;      /* Current CPU time measured in bytes */
	uint64_t time;                /* Current NIC TX time measured in bytes */
	struct rte_reciprocal inv_cycles_per_byte; /* CPU cycles per byte */

	/* Scheduling loop detection */
	uint32_t pipe_loop;
	uint32_t pipe_exhaustion;

	/* Bitmap */
	struct rte_bitmap *bmp;
	uint32_t grinder_base_bmp_pos[RTE_SCHED_PORT_N_GRINDERS] __rte_aligned_16;

	/* Grinders */
	struct rte_sched_grinder grinder[RTE_SCHED_PORT_N_GRINDERS];
	uint32_t busy_grinders;
	struct rte_mbuf **pkts_out;
	uint32_t n_pkts_out;
	uint32_t subport_id;

	uint32_t max_subport_pipes_log2;   /* Max number of subport pipes */

	/* Queue base calculation */
	uint32_t qsize_add[RTE_SCHED_QUEUES_PER_PIPE];
	uint32_t qsize_sum;

	/* Large data structures */
	struct rte_sched_subport *subport;
	struct rte_sched_pipe *pipe;
	struct rte_sched_queue *queue;
	struct rte_sched_queue_extra *queue_extra;
	struct rte_sched_pipe_profile *pipe_profiles;
	uint8_t *bmp_array;
	struct rte_mbuf **queue_array;
	struct rte_sched_subport *subports[0];
	uint8_t memory[0] __rte_cache_aligned;
} __rte_cache_aligned;

enum rte_sched_port_array {
	e_RTE_SCHED_PORT_ARRAY_SUBPORT = 0,
	e_RTE_SCHED_PORT_ARRAY_PIPE,
	e_RTE_SCHED_PORT_ARRAY_QUEUE,
	e_RTE_SCHED_PORT_ARRAY_QUEUE_EXTRA,
	e_RTE_SCHED_PORT_ARRAY_PIPE_PROFILES,
	e_RTE_SCHED_PORT_ARRAY_BMP_ARRAY,
	e_RTE_SCHED_PORT_ARRAY_QUEUE_ARRAY,
	e_RTE_SCHED_PORT_ARRAY_TOTAL,
};

enum rte_sched_subport_array {
	e_RTE_SCHED_SUBPORT_ARRAY_PIPE = 0,
	e_RTE_SCHED_SUBPORT_ARRAY_QUEUE,
	e_RTE_SCHED_SUBPORT_ARRAY_QUEUE_EXTRA,
	e_RTE_SCHED_SUBPORT_ARRAY_PIPE_PROFILES,
	e_RTE_SCHED_SUBPORT_ARRAY_BMP_ARRAY,
	e_RTE_SCHED_SUBPORT_ARRAY_QUEUE_ARRAY,
	e_RTE_SCHED_SUBPORT_ARRAY_TOTAL,
};

static inline uint32_t
rte_sched_subport_queues(struct rte_sched_subport *subport)
{
	return RTE_SCHED_QUEUES_PER_PIPE * subport->n_subport_pipes;
}

static inline struct rte_mbuf **
rte_sched_subport_qbase(struct rte_sched_subport *subport, uint32_t qindex)
{
	uint32_t pindex = qindex >> 4;
	uint32_t qpos = qindex & 0xF;

	return (subport->queue_array + pindex *
		subport->qsize_sum + subport->qsize_add[qpos]);
}

static inline uint16_t
rte_sched_subport_qsize(struct rte_sched_subport *subport, uint32_t qindex)
{
	uint32_t qpos = qindex & 0xF;
	return subport->qsize[qpos];
}

static inline uint32_t
rte_sched_port_queues(struct rte_sched_port *port)
{
	uint32_t n_queues = 0, i;

	for (i = 0; i < port->n_subports_per_port; i++)
		n_queues += rte_sched_subport_queues(port->subports[i]);

	return n_queues;
}

static int
pipe_profile_check(struct rte_sched_pipe_params *params,
	uint32_t rate, uint16_t *qsize)
{
	uint32_t i;

	/* Pipe parameters */
	if (params == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for parameter params \n", __func__);
		return -EINVAL;
	}

	/* TB rate: non-zero, not greater than port rate */
	if (params->tb_rate == 0 ||
		params->tb_rate > rate) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for tb rate \n", __func__);
		return -EINVAL;
	}

	/* TB size: non-zero */
	if (params->tb_size == 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for tb size \n", __func__);
		return -EINVAL;
	}

	/* TC rate: non-zero, less than pipe rate */
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASS_BE; i++) {
		if ((qsize[i] == 0 && params->tc_rate[i] != 0) ||
			(qsize[i] != 0 && (params->tc_rate[i] == 0 ||
			params->tc_rate[i] > params->tb_rate))) {
			RTE_LOG(ERR, SCHED,
				"%s: Incorrect value for qsize or tc_rate \n", __func__);
			return -EINVAL;
		}
	}

	if (params->tc_rate[RTE_SCHED_TRAFFIC_CLASS_BE] == 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for be traffic class rate \n", __func__);
		return -EINVAL;
	}

	/* TC period: non-zero */
	if (params->tc_period == 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for tc period \n", __func__);
		return -EINVAL;
	}

#ifdef RTE_SCHED_SUBPORT_TC_OV
	/* TC3 oversubscription weight: non-zero */
	if (params->tc_ov_weight == 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for tc ov weight \n", __func__);
		return -EINVAL;
	}
#endif

	/* Queue WRR weights: non-zero */
	for (i = 0; i < RTE_SCHED_BE_QUEUES_PER_PIPE; i++) {
		uint32_t qindex = RTE_SCHED_TRAFFIC_CLASS_BE + i;
		if ((qsize[qindex] != 0 && params->wrr_weights[i] == 0) ||
			(qsize[qindex] == 0 && params->wrr_weights[i] != 0)) {
			RTE_LOG(ERR, SCHED,
				"%s: Incorrect value for qsize or wrr weight \n", __func__);
			return -EINVAL;
		}
	}

	return 0;
}

static int
rte_sched_port_check_params(struct rte_sched_port_params *params)
{
	if (params == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for parameter params \n", __func__);
		return -EINVAL;
	}

	/* socket */
	if (params->socket < 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for socket id \n", __func__);
		return -EINVAL;
	}

	/* rate */
	if (params->rate == 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for rate \n", __func__);
		return -EINVAL;
	}

	/* mtu */
	if (params->mtu == 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for mtu \n", __func__);
		return -EINVAL;
	}

	/* n_subports_per_port: non-zero, limited to 16 bits, power of 2 */
	if (params->n_subports_per_port == 0 ||
	    !rte_is_power_of_2(params->n_subports_per_port)) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for number of subports \n", __func__);
		return -EINVAL;
	}

	return 0;
}

static uint32_t
rte_sched_subport_get_array_base(struct rte_sched_subport_params *params,
	enum rte_sched_subport_array array)
{
	uint32_t n_subport_pipes = params->n_subport_pipes;
	uint32_t n_subport_queues = RTE_SCHED_QUEUES_PER_PIPE * n_subport_pipes;

	uint32_t size_pipe = n_subport_pipes * sizeof(struct rte_sched_pipe);
	uint32_t size_queue = n_subport_queues * sizeof(struct rte_sched_queue);
	uint32_t size_queue_extra
		= n_subport_queues * sizeof(struct rte_sched_queue_extra);
	uint32_t size_pipe_profiles = params->n_max_pipe_profiles *
		sizeof(struct rte_sched_pipe_profile);
	uint32_t size_bmp_array =
		rte_bitmap_get_memory_footprint(n_subport_queues);
	uint32_t size_per_pipe_queue_array, size_queue_array;

	uint32_t base, i;

	size_per_pipe_queue_array = 0;
	for (i = 0; i < RTE_SCHED_QUEUES_PER_PIPE; i++) {
		size_per_pipe_queue_array += params->qsize[i] * sizeof(struct rte_mbuf *);
	}
	size_queue_array = n_subport_pipes * size_per_pipe_queue_array;

	base = 0;

	if (array == e_RTE_SCHED_SUBPORT_ARRAY_PIPE)
		return base;
	base += RTE_CACHE_LINE_ROUNDUP(size_pipe);

	if (array == e_RTE_SCHED_SUBPORT_ARRAY_QUEUE)
		return base;
	base += RTE_CACHE_LINE_ROUNDUP(size_queue);

	if (array == e_RTE_SCHED_SUBPORT_ARRAY_QUEUE_EXTRA)
		return base;
	base += RTE_CACHE_LINE_ROUNDUP(size_queue_extra);

	if (array == e_RTE_SCHED_SUBPORT_ARRAY_PIPE_PROFILES)
		return base;
	base += RTE_CACHE_LINE_ROUNDUP(size_pipe_profiles);

	if (array == e_RTE_SCHED_SUBPORT_ARRAY_BMP_ARRAY)
		return base;
	base += RTE_CACHE_LINE_ROUNDUP(size_bmp_array);

	if (array == e_RTE_SCHED_SUBPORT_ARRAY_QUEUE_ARRAY)
		return base;
	base += RTE_CACHE_LINE_ROUNDUP(size_queue_array);

	return base;
}

static void
rte_sched_pipe_wrr_queues_config(struct rte_sched_pipe_params *src,
	struct rte_sched_pipe_profile *dst)
{
	uint32_t wrr_cost[RTE_SCHED_BE_QUEUES_PER_PIPE];

	if (dst->n_be_queues == 1) {
		dst->wrr_cost[0] = (uint8_t) src->wrr_weights[0];

		return;
	}

	if (dst->n_be_queues == 2) {
		uint32_t lcd;
		wrr_cost[0] = src->wrr_weights[0];
		wrr_cost[1] = src->wrr_weights[1];

		lcd = rte_get_lcd(wrr_cost[0], wrr_cost[1]);

		wrr_cost[0] = lcd / wrr_cost[0];
		wrr_cost[1] = lcd / wrr_cost[1];

		dst->wrr_cost[0] = (uint8_t) wrr_cost[0];
		dst->wrr_cost[1] = (uint8_t) wrr_cost[1];

		return;
	}

	if (dst->n_be_queues == 4) {
		uint32_t lcd, lcd1, lcd2;

		wrr_cost[0] = src->wrr_weights[0];
		wrr_cost[1] = src->wrr_weights[1];
		wrr_cost[2] = src->wrr_weights[2];
		wrr_cost[3] = src->wrr_weights[3];

		lcd1 = rte_get_lcd(wrr_cost[0], wrr_cost[1]);
		lcd2 = rte_get_lcd(wrr_cost[2], wrr_cost[3]);
		lcd = rte_get_lcd(lcd1, lcd2);

		wrr_cost[0] = lcd / wrr_cost[0];
		wrr_cost[1] = lcd / wrr_cost[1];
		wrr_cost[2] = lcd / wrr_cost[2];
		wrr_cost[3] = lcd / wrr_cost[3];

		dst->wrr_cost[0] = (uint8_t) wrr_cost[0];
		dst->wrr_cost[1] = (uint8_t) wrr_cost[1];
		dst->wrr_cost[2] = (uint8_t) wrr_cost[2];
		dst->wrr_cost[3] = (uint8_t) wrr_cost[3];

		return;
	}

	if (dst->n_be_queues == 8) {
		uint32_t lcd1, lcd2, lcd3, lcd4, lcd5, lcd6, lcd7;

		wrr_cost[0] = src->wrr_weights[0];
		wrr_cost[1] = src->wrr_weights[1];
		wrr_cost[2] = src->wrr_weights[2];
		wrr_cost[3] = src->wrr_weights[3];
		wrr_cost[4] = src->wrr_weights[4];
		wrr_cost[5] = src->wrr_weights[5];
		wrr_cost[6] = src->wrr_weights[6];
		wrr_cost[7] = src->wrr_weights[7];

		lcd1 = rte_get_lcd(wrr_cost[0], wrr_cost[1]);
		lcd2 = rte_get_lcd(wrr_cost[2], wrr_cost[3]);
		lcd3 = rte_get_lcd(wrr_cost[4], wrr_cost[5]);
		lcd4 = rte_get_lcd(wrr_cost[6], wrr_cost[7]);

		lcd5 = rte_get_lcd(lcd1, lcd2);
		lcd6 = rte_get_lcd(lcd3, lcd4);

		lcd7 = rte_get_lcd(lcd5, lcd6);

		wrr_cost[0] = lcd7 / wrr_cost[0];
		wrr_cost[1] = lcd7 / wrr_cost[1];
		wrr_cost[2] = lcd7 / wrr_cost[2];
		wrr_cost[3] = lcd7 / wrr_cost[3];
		wrr_cost[4] = lcd7 / wrr_cost[4];
		wrr_cost[5] = lcd7 / wrr_cost[5];
		wrr_cost[6] = lcd7 / wrr_cost[6];
		wrr_cost[7] = lcd7 / wrr_cost[7];

		dst->wrr_cost[0] = (uint8_t) wrr_cost[0];
		dst->wrr_cost[1] = (uint8_t) wrr_cost[1];
		dst->wrr_cost[2] = (uint8_t) wrr_cost[2];
		dst->wrr_cost[3] = (uint8_t) wrr_cost[3];
		dst->wrr_cost[4] = (uint8_t) wrr_cost[4];
		dst->wrr_cost[5] = (uint8_t) wrr_cost[5];
		dst->wrr_cost[6] = (uint8_t) wrr_cost[6];
		dst->wrr_cost[7] = (uint8_t) wrr_cost[7];

		return;
	}
}

static void
rte_sched_subport_config_qsize(struct rte_sched_subport *subport)
{
	uint32_t i;

	subport->qsize_add[0] = 0;

	for (i = 1; i < RTE_SCHED_QUEUES_PER_PIPE; i++)
		subport->qsize_add[i] =
			subport->qsize_add[i-1] + subport->qsize[i-1];

	subport->qsize_sum = subport->qsize_add[15] + subport->qsize[15];
}

static void
rte_sched_port_log_pipe_profile(struct rte_sched_subport *subport, uint32_t i)
{
	struct rte_sched_pipe_profile *p = subport->pipe_profiles + i;

	RTE_LOG(DEBUG, SCHED, "Low level config for pipe profile %u:\n"
		"    Token bucket: period = %u, credits per period = %u, size = %u\n"
		"    Traffic classes: period = %u, credits per period = [%u, %u, %u, %u, %u, %u, %u, %u, %u]\n"
		"    Traffic class BE oversubscription: weight = %hhu\n"
		"    WRR cost: [%hhu, %hhu, %hhu, %hhu, %hhu, %hhu, %hhu, %hhu]\n",
		i,

		/* Token bucket */
		p->tb_period,
		p->tb_credits_per_period,
		p->tb_size,

		/* Traffic classes */
		p->tc_period,
		p->tc_credits_per_period[0],
		p->tc_credits_per_period[1],
		p->tc_credits_per_period[2],
		p->tc_credits_per_period[3],
		p->tc_credits_per_period[4],
		p->tc_credits_per_period[5],
		p->tc_credits_per_period[6],
		p->tc_credits_per_period[7],
		p->tc_credits_per_period[8],

		/* Traffic class 3 oversubscription */
		p->tc_ov_weight,

		/* WRR */
		p->wrr_cost[0], p->wrr_cost[1], p->wrr_cost[2], p->wrr_cost[3],
		p->wrr_cost[4], p->wrr_cost[5], p->wrr_cost[6], p->wrr_cost[7]);
}

static inline uint64_t
rte_sched_time_ms_to_bytes(uint32_t time_ms, uint32_t rate)
{
	uint64_t time = time_ms;

	time = (time * rate) / 1000;

	return time;
}

static void
rte_sched_pipe_profile_convert(struct rte_sched_subport *subport,
	struct rte_sched_pipe_params *src,
	struct rte_sched_pipe_profile *dst,
	uint32_t rate)
{
	uint32_t i;

	/* Token Bucket */
	if (src->tb_rate == rate) {
		dst->tb_credits_per_period = 1;
		dst->tb_period = 1;
	} else {
		double tb_rate = (double) src->tb_rate
				/ (double) rate;
		double d = RTE_SCHED_TB_RATE_CONFIG_ERR;

		rte_approx(tb_rate, d,
			&dst->tb_credits_per_period, &dst->tb_period);
	}

	dst->tb_size = src->tb_size;

	/* Traffic Classes */
	dst->tc_period = rte_sched_time_ms_to_bytes(src->tc_period,
						rate);

	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		if (subport->qsize[i])
			dst->tc_credits_per_period[i]
				= rte_sched_time_ms_to_bytes(src->tc_period,
					src->tc_rate[i]);

#ifdef RTE_SCHED_SUBPORT_TC_OV
	dst->tc_ov_weight = src->tc_ov_weight;
#endif

	/* WRR queues */
	for (i = 0; i < RTE_SCHED_BE_QUEUES_PER_PIPE; i++)
		if (subport->qsize[RTE_SCHED_TRAFFIC_CLASS_BE + i])
			dst->n_be_queues++;

	rte_sched_pipe_wrr_queues_config(src, dst);
}

static void
rte_sched_subport_config_pipe_profile_table(struct rte_sched_subport *subport,
	struct rte_sched_subport_params *params, uint32_t rate)
{
	uint32_t i;

	for (i = 0; i < subport->n_pipe_profiles; i++) {
		struct rte_sched_pipe_params *src = params->pipe_profiles + i;
		struct rte_sched_pipe_profile *dst = subport->pipe_profiles + i;

		rte_sched_pipe_profile_convert(subport, src, dst, rate);
		rte_sched_port_log_pipe_profile(subport, i);
	}

	subport->pipe_tc_be_rate_max = 0;
	for (i = 0; i < subport->n_pipe_profiles; i++) {
		struct rte_sched_pipe_params *src = params->pipe_profiles + i;
		uint32_t pipe_tc_be_rate = src->tc_rate[RTE_SCHED_TRAFFIC_CLASS_BE];

		if (subport->pipe_tc_be_rate_max < pipe_tc_be_rate)
			subport->pipe_tc_be_rate_max = pipe_tc_be_rate;
	}
}

static int
rte_sched_subport_check_params(struct rte_sched_subport_params *params,
	uint32_t rate)
{
	uint32_t i, j;

	/* Check user parameters */
	if (params == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for parameter params \n", __func__);
		return -EINVAL;
	}

	if (params->tb_rate == 0 || params->tb_rate > rate) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for tb rate \n", __func__);
		return -EINVAL;
	}

	if (params->tb_size == 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for tb size \n", __func__);
		return -EINVAL;
	}

	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		if (params->tc_rate[i] > params->tb_rate) {
			RTE_LOG(ERR, SCHED,
				"%s: Incorrect value for tc rate \n", __func__);
			return -EINVAL;
		}

	if (params->tc_period == 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for tc period \n", __func__);
		return -EINVAL;
	}

	/* n_subport_pipes: non-zero, power of 2 */
	if (params->n_subport_pipes == 0 ||
	    !rte_is_power_of_2(params->n_subport_pipes)) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for pipes number \n", __func__);
		return -EINVAL;
	}

	/* qsize: power of 2, if non-zero
	 * no bigger than 32K (due to 16-bit read/write pointers)
	 */
	for (i = 0, j = 0; i < RTE_SCHED_QUEUES_PER_PIPE; i++) {
		uint32_t tc_rate = params->tc_rate[j];
		uint16_t qsize = params->qsize[i];

		if (((qsize == 0) &&
			((tc_rate != 0) && (j != RTE_SCHED_TRAFFIC_CLASS_BE))) ||
			((qsize != 0) &&
			((tc_rate == 0) || !rte_is_power_of_2(qsize)))) {
			RTE_LOG(ERR, SCHED,
				"%s: Incorrect value for tc rate \n", __func__);
			return -EINVAL;
		}
		if (j < RTE_SCHED_TRAFFIC_CLASS_BE)
			j++;
	}

	/* WRR queues : 1, 4, 8 */
	uint32_t wrr_queues = 0;
	for (i = 0; i < RTE_SCHED_BE_QUEUES_PER_PIPE; i++) {
		if (params->qsize[RTE_SCHED_TRAFFIC_CLASS_BE + i])
			wrr_queues++;
	}
	if (params->tc_rate[RTE_SCHED_TRAFFIC_CLASS_BE] &&
		(wrr_queues != 1 && wrr_queues != 2 &&
		wrr_queues != 4 && wrr_queues != 8)) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for wrr weights \n", __func__);
		return -EINVAL;
	}

	/* pipe_profiles and n_pipe_profiles */
	if (params->pipe_profiles == NULL ||
	    params->n_pipe_profiles == 0 ||
		 params->n_pipe_profiles > params->n_max_pipe_profiles) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for number of pipe profiles \n", __func__);
		return -EINVAL;
	}

	for (i = 0; i < params->n_pipe_profiles; i++) {
		struct rte_sched_pipe_params *p = params->pipe_profiles + i;
		int status;

		status = pipe_profile_check(p, rate, &params->qsize[0]);
		if (status != 0) {
			RTE_LOG(ERR, SCHED,
				"%s: Pipe profile check failed(%d) \n", __func__, status);
			return -EINVAL;
		}
	}

	return 0;
}

static uint32_t
rte_sched_subport_get_memory_footprint(struct rte_sched_port *port,
	uint32_t subport_id, struct rte_sched_subport_params *params)
{
	uint32_t size0, size1;
	int status;

	if (port == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for parameter port \n", __func__);
		return 0;
	}

	if (subport_id >= port->n_subports_per_port) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for subport id \n", __func__);
		return 0;
	}

	status = rte_sched_subport_check_params(params, port->rate);
	if (status != 0) {
		RTE_LOG(NOTICE, SCHED,
			"Port scheduler params check failed (%d)\n", status);

		return 0;
	}

	size0 = sizeof(struct rte_sched_subport);
	size1 = rte_sched_subport_get_array_base(params,
			e_RTE_SCHED_SUBPORT_ARRAY_TOTAL);

	return size0 + size1;
}

uint32_t
rte_sched_port_get_memory_footprint(struct rte_sched_port_params *port_params,
	struct rte_sched_subport_params *subport_params)
{
	uint32_t size0 = 0, size1 = 0, i;
	int status;

	status = rte_sched_port_check_params(port_params);
	if (status != 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Port scheduler port params check failed (%d)\n",
			__func__, status);

		return 0;
	}

	status = rte_sched_subport_check_params(subport_params,
				port_params->rate);
	if (status != 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Port scheduler subport params check failed (%d)\n",
			__func__, status);

		return 0;
	}

	size0 = sizeof(struct rte_sched_port);

	for (i = 0; i < port_params->n_subports_per_port; i++) {
		struct rte_sched_subport_params *sp = &subport_params[i];
		size1 += rte_sched_subport_get_array_base(sp,
			e_RTE_SCHED_SUBPORT_ARRAY_TOTAL);
	}

	return size0 + size1;
}

struct rte_sched_port *
rte_sched_port_config(struct rte_sched_port_params *params)
{
	struct rte_sched_port *port = NULL;
	uint32_t size0, size1;
	uint32_t cycles_per_byte;
	int status;

	status = rte_sched_port_check_params(params);
	if (status != 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Port scheduler params check failed (%d)\n",
			__func__, status);
		return NULL;
	}

	size0 = sizeof(struct rte_sched_port);
	size1 = params->n_subports_per_port * sizeof(struct rte_sched_subport *);

	/* Allocate memory to store the data structures */
	port = rte_zmalloc_socket("qos_params", size0 + size1,
		RTE_CACHE_LINE_SIZE, params->socket);
	if (port == NULL)
		return NULL;

	/* User parameters */
	port->n_subports_per_port = params->n_subports_per_port;
	port->socket = params->socket;
	port->rate = params->rate;
	port->mtu = params->mtu + params->frame_overhead;
	port->frame_overhead = params->frame_overhead;

	/* Timing */
	port->time_cpu_cycles = rte_get_tsc_cycles();
	port->time_cpu_bytes = 0;
	port->time = 0;

	cycles_per_byte = (rte_get_tsc_hz() << RTE_SCHED_TIME_SHIFT)
		/ params->rate;
	port->inv_cycles_per_byte = rte_reciprocal_value(cycles_per_byte);

	port->pkts_out = NULL;
	port->n_pkts_out = 0;
	port->subport_id = 0;

	port->max_subport_pipes_log2 = 0;

	return port;
}

static inline void
rte_sched_subport_free(struct rte_sched_subport *subport)
{
	uint32_t n_subport_queues;
	uint32_t qindex;

	if (subport == NULL)
		return;

	n_subport_queues = rte_sched_subport_queues(subport);

	/* Free enqueued mbufs */
	for (qindex = 0; qindex < n_subport_queues; qindex++) {
		struct rte_mbuf **mbufs =
			rte_sched_subport_qbase(subport, qindex);
		uint16_t qsize = rte_sched_subport_qsize(subport, qindex);
		if (qsize != 0) {
			struct rte_sched_queue *queue = subport->queue + qindex;
			uint16_t qr = queue->qr & (qsize - 1);
			uint16_t qw = queue->qw & (qsize - 1);

			for (; qr != qw; qr = (qr + 1) & (qsize - 1))
				rte_pktmbuf_free(mbufs[qr]);
		}
	}

	rte_bitmap_free(subport->bmp);
}

void
rte_sched_port_free(struct rte_sched_port *port)
{
	uint32_t i;

	/* Check user parameters */
	if (port == NULL)
		return;

	for (i = 0; i < port->n_subports_per_port; i++)
		rte_sched_subport_free(port->subports[i]);

	rte_free(port);
}

static void
rte_sched_port_log_subport_config(struct rte_sched_port *port, uint32_t i)
{
	struct rte_sched_subport *s = port->subports[i];

	RTE_LOG(DEBUG, SCHED, "Low level config for subport %u:\n"
		"    Token bucket: period = %u, credits per period = %u, size = %u\n"
		"    Traffic classes: period = %u, credits per period = [%u, %u, %u, %u, %u, %u, %u, %u, %u]\n"
		"    Traffic class BE oversubscription: wm min = %u, wm max = %u\n",
		i,

		/* Token bucket */
		s->tb_period,
		s->tb_credits_per_period,
		s->tb_size,

		/* Traffic classes */
		s->tc_period,
		s->tc_credits_per_period[0],
		s->tc_credits_per_period[1],
		s->tc_credits_per_period[2],
		s->tc_credits_per_period[3],
		s->tc_credits_per_period[4],
		s->tc_credits_per_period[5],
		s->tc_credits_per_period[6],
		s->tc_credits_per_period[7],
		s->tc_credits_per_period[8],

		/* Traffic class BE oversubscription */
		s->tc_ov_wm_min,
		s->tc_ov_wm_max);
}

int
rte_sched_subport_config(struct rte_sched_port *port,
	uint32_t subport_id,
	struct rte_sched_subport_params *params)
{
	struct rte_sched_subport *s = NULL;
	uint32_t mem_size, bmp_mem_size, n_subport_queues, n_subport_pipes_log2, i;

	/* Check user parameters. Determine the amount of memory to allocate */
	mem_size = rte_sched_subport_get_memory_footprint(port,
		subport_id, params);
	if (mem_size == 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Fail to determine the memory to allocate \n", __func__);
		return -EINVAL;
	}

	/* Allocate memory to store the data structures */
	s = rte_zmalloc_socket("subport_params", mem_size, RTE_CACHE_LINE_SIZE,
		port->socket);
	if (s == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Memory allocation fails \n", __func__);
		return -ENOMEM;
	}

	/* Token Bucket (TB) */
	if (params->tb_rate == port->rate) {
		s->tb_credits_per_period = 1;
		s->tb_period = 1;
	} else {
		double tb_rate = ((double) params->tb_rate) / ((double) port->rate);
		double d = RTE_SCHED_TB_RATE_CONFIG_ERR;

		rte_approx(tb_rate, d, &s->tb_credits_per_period, &s->tb_period);
	}

	s->tb_size = params->tb_size;
	s->tb_time = port->time;
	s->tb_credits = s->tb_size / 2;

	/* Traffic Classes (TCs) */
	s->tc_period = rte_sched_time_ms_to_bytes(params->tc_period, port->rate);
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		if (params->qsize[i])
			s->tc_credits_per_period[i]
				= rte_sched_time_ms_to_bytes(params->tc_period,
					params->tc_rate[i]);
	}
	s->tc_time = port->time + s->tc_period;
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		if (params->qsize[i])
			s->tc_credits[i] = s->tc_credits_per_period[i];

	/* compile time checks */
	RTE_BUILD_BUG_ON(RTE_SCHED_PORT_N_GRINDERS == 0);
	RTE_BUILD_BUG_ON(RTE_SCHED_PORT_N_GRINDERS &
		(RTE_SCHED_PORT_N_GRINDERS - 1));

	/* User parameters */
	s->n_subport_pipes = params->n_subport_pipes;
	n_subport_pipes_log2 = __builtin_ctz(params->n_subport_pipes);
	memcpy(s->qsize, params->qsize, sizeof(params->qsize));
	s->n_pipe_profiles = params->n_pipe_profiles;
	s->n_max_pipe_profiles = params->n_max_pipe_profiles;

#ifdef RTE_SCHED_RED
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		uint32_t j;

		for (j = 0; j < RTE_COLORS; j++) {
			/* if min/max are both zero, then RED is disabled */
			if ((params->red_params[i][j].min_th |
			     params->red_params[i][j].max_th) == 0) {
				continue;
			}

			if (rte_red_config_init(&s->red_config[i][j],
				params->red_params[i][j].wq_log2,
				params->red_params[i][j].min_th,
				params->red_params[i][j].max_th,
				params->red_params[i][j].maxp_inv) != 0) {
				rte_free(s);
				return -3;
			}
		}
	}
#endif

	/* Scheduling loop detection */
	s->pipe_loop = RTE_SCHED_PIPE_INVALID;
	s->pipe_exhaustion = 0;

	/* Grinders */
	s->busy_grinders = 0;

	/* Queue base calculation */
	rte_sched_subport_config_qsize(s);

	/* Large data structures */
	s->pipe = (struct rte_sched_pipe *)
		(s->memory + rte_sched_subport_get_array_base(params,
						e_RTE_SCHED_SUBPORT_ARRAY_PIPE));
	s->queue = (struct rte_sched_queue *)
		(s->memory + rte_sched_subport_get_array_base(params,
						e_RTE_SCHED_SUBPORT_ARRAY_QUEUE));
	s->queue_extra = (struct rte_sched_queue_extra *)
		(s->memory + rte_sched_subport_get_array_base(params,
						e_RTE_SCHED_SUBPORT_ARRAY_QUEUE_EXTRA));
	s->pipe_profiles = (struct rte_sched_pipe_profile *)
		(s->memory + rte_sched_subport_get_array_base(params,
						e_RTE_SCHED_SUBPORT_ARRAY_PIPE_PROFILES));
	s->bmp_array =  s->memory + rte_sched_subport_get_array_base(params,
						e_RTE_SCHED_SUBPORT_ARRAY_BMP_ARRAY);
	s->queue_array = (struct rte_mbuf **)
		(s->memory + rte_sched_subport_get_array_base(params,
						e_RTE_SCHED_SUBPORT_ARRAY_QUEUE_ARRAY));

	/* Pipe profile table */
	rte_sched_subport_config_pipe_profile_table(s, params, port->rate);

	/* Bitmap */
	n_subport_queues = rte_sched_subport_queues(s);
	bmp_mem_size = rte_bitmap_get_memory_footprint(n_subport_queues);
	s->bmp = rte_bitmap_init(n_subport_queues, s->bmp_array,
				bmp_mem_size);
	if (s->bmp == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Subport bitmap init error \n", __func__);

		rte_free(port);
		return -EINVAL;
	}

	for (i = 0; i < RTE_SCHED_PORT_N_GRINDERS; i++)
		s->grinder_base_bmp_pos[i] = RTE_SCHED_PIPE_INVALID;

	/* Port */
	port->subports[subport_id] = s;

	if (n_subport_pipes_log2 > port->max_subport_pipes_log2)
		port->max_subport_pipes_log2 = n_subport_pipes_log2;

#ifdef RTE_SCHED_SUBPORT_TC_OV
	/* TC oversubscription */
	s->tc_ov_wm_min = port->mtu;
	s->tc_ov_wm_max = rte_sched_time_ms_to_bytes(params->tc_period,
						     s->pipe_tc_be_rate_max);
	s->tc_ov_wm = s->tc_ov_wm_max;
	s->tc_ov_period_id = 0;
	s->tc_ov = 0;
	s->tc_ov_n = 0;
	s->tc_ov_rate = 0;
#endif

	rte_sched_port_log_subport_config(port, subport_id);

	return 0;
}

int
rte_sched_pipe_config(struct rte_sched_port *port,
	uint32_t subport_id,
	uint32_t pipe_id,
	int32_t pipe_profile)
{
	struct rte_sched_subport *s;
	struct rte_sched_pipe *p;
	struct rte_sched_pipe_profile *params;
	uint32_t deactivate, profile, i;

	/* Check user parameters */
	profile = (uint32_t) pipe_profile;
	deactivate = (pipe_profile < 0);

	if (port == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for parameter port \n", __func__);
		return -EINVAL;
	}

	if (subport_id >= port->n_subports_per_port) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for subport id \n", __func__);
		return -EINVAL;
	}

	if (pipe_id >= port->subports[subport_id]->n_subport_pipes) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for pipe id \n", __func__);
		return -EINVAL;
	}

	if (!deactivate &&
		profile >= port->subports[subport_id]->n_pipe_profiles) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for pipe profile \n", __func__);
		return -EINVAL;
	}

	/* Check that subport configuration is valid */
	s = port->subports[subport_id];
	p = s->pipe + pipe_id;

	/* Handle the case when pipe already has a valid configuration */
	if (p->tb_time) {
		params = s->pipe_profiles + p->profile;

#ifdef RTE_SCHED_SUBPORT_TC_OV
		double subport_tc_be_rate =
			(double) s->tc_credits_per_period[
					RTE_SCHED_TRAFFIC_CLASS_BE]
			/ (double) s->tc_period;
		double pipe_tc_be_rate =
			(double) params->tc_credits_per_period[
					RTE_SCHED_TRAFFIC_CLASS_BE]
			/ (double) params->tc_period;
		uint32_t tc_be_ov = s->tc_ov;

		/* Unplug pipe from its subport */
		s->tc_ov_n -= params->tc_ov_weight;
		s->tc_ov_rate -= pipe_tc_be_rate;
		s->tc_ov = s->tc_ov_rate > subport_tc_be_rate;

		if (s->tc_ov != tc_be_ov) {
			RTE_LOG(DEBUG, SCHED,
				"Subport %u Best effort TC oversubscription is OFF (%.4lf >= %.4lf)\n",
				subport_id, subport_tc_be_rate, s->tc_ov_rate);
		}
#endif

		/* Reset the pipe */
		memset(p, 0, sizeof(struct rte_sched_pipe));
	}

	if (deactivate)
		return 0;

	/* Apply the new pipe configuration */
	p->profile = profile;
	params = s->pipe_profiles + p->profile;

	/* Token Bucket (TB) */
	p->tb_time = port->time;
	p->tb_credits = params->tb_size / 2;

	/* Traffic Classes (TCs) */
	p->n_be_queues = params->n_be_queues;
	p->tc_time = port->time + params->tc_period;
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		if (s->qsize[i])
			p->tc_credits[i] = params->tc_credits_per_period[i];

#ifdef RTE_SCHED_SUBPORT_TC_OV
	{
		/* Subport TC3 oversubscription */
		double subport_tc_be_rate =
			(double) s->tc_credits_per_period[
					RTE_SCHED_TRAFFIC_CLASS_BE]
			/ (double) s->tc_period;
		double pipe_tc_be_rate =
			(double) params->tc_credits_per_period[
					RTE_SCHED_TRAFFIC_CLASS_BE]
			/ (double) params->tc_period;
		uint32_t tc_be_ov = s->tc_ov;

		s->tc_ov_n += params->tc_ov_weight;
		s->tc_ov_rate += pipe_tc_be_rate;
		s->tc_ov = s->tc_ov_rate > subport_tc_be_rate;

		if (s->tc_ov != tc_be_ov) {
			RTE_LOG(DEBUG, SCHED,
				"Subport %u Best effort TC oversubscription is ON (%.4lf < %.4lf)\n",
				subport_id, subport_tc_be_rate, s->tc_ov_rate);
		}
		p->tc_ov_period_id = s->tc_ov_period_id;
		p->tc_ov_credits = s->tc_ov_wm;
	}
#endif

	return 0;
}

int __rte_experimental
rte_sched_port_pipe_profile_add(struct rte_sched_port *port,
	uint32_t subport_id,
	struct rte_sched_pipe_params *params,
	uint32_t *pipe_profile_id)
{
	struct rte_sched_pipe_profile *pp;
	struct rte_sched_subport *s;
	uint32_t i;
	int status;

	/* Port */
	if (port == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for parameter port \n", __func__);
		return -EINVAL;
	}

	/* Subport id not exceeds the max limit */
	if (subport_id > port->n_subports_per_port) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for subport id \n", __func__);
		return -EINVAL;
	}

	s = port->subports[subport_id];

	/* Pipe profiles not exceeds the max limit */
	if (s->n_pipe_profiles >= s->n_max_pipe_profiles) {
		RTE_LOG(ERR, SCHED,
			"%s: Number of pipe profiles exceeds the max limit \n", __func__);
		return -EINVAL;
	}

	/* Pipe params */
	status = pipe_profile_check(params, port->rate, &s->qsize[0]);
	if (status != 0) {
		RTE_LOG(ERR, SCHED,
			"%s: Pipe profile check failed(%d) \n", __func__, status);
		return -EINVAL;
	}

	pp = &s->pipe_profiles[s->n_pipe_profiles];
	rte_sched_pipe_profile_convert(s, params, pp, port->rate);

	/* Pipe profile not exists */
	for (i = 0; i < s->n_pipe_profiles; i++)
		if (memcmp(s->pipe_profiles + i, pp, sizeof(*pp)) == 0) {
			RTE_LOG(ERR, SCHED,
				"%s: Pipe profile doesn't exist \n", __func__);
			return -EINVAL;
		}

	/* Pipe profile commit */
	*pipe_profile_id = s->n_pipe_profiles;
	s->n_pipe_profiles++;

	if (s->pipe_tc_be_rate_max < params->tc_rate[RTE_SCHED_TRAFFIC_CLASS_BE])
		s->pipe_tc_be_rate_max = params->tc_rate[RTE_SCHED_TRAFFIC_CLASS_BE];

	rte_sched_port_log_pipe_profile(s, *pipe_profile_id);

	return 0;
}

static inline uint32_t
rte_sched_port_qindex(struct rte_sched_port *port,
	struct rte_sched_subport *s,
	uint32_t subport,
	uint32_t pipe,
	uint32_t queue)
{
	return ((subport & (port->n_subports_per_port - 1)) <<
			(port->max_subport_pipes_log2 + 4)) |
			((pipe & (s->n_subport_pipes - 1)) << 4) |
			(queue & (RTE_SCHED_QUEUES_PER_PIPE - 1));
}

void
rte_sched_port_pkt_write(struct rte_sched_port *port,
			 struct rte_mbuf *pkt,
			 uint32_t subport, uint32_t pipe,
			 uint32_t traffic_class,
			 uint32_t queue, enum rte_color color)
{
	struct rte_sched_subport *s = port->subports[subport];
	uint32_t qindex = rte_sched_port_qindex(port, s, subport, pipe, queue);
	rte_mbuf_sched_set(pkt, qindex, traffic_class, (uint8_t)color);
}

void
rte_sched_port_pkt_read_tree_path(struct rte_sched_port *port,
				  const struct rte_mbuf *pkt,
				  uint32_t *subport, uint32_t *pipe,
				  uint32_t *traffic_class, uint32_t *queue)
{
	struct rte_sched_subport *s;
	uint32_t qindex = rte_mbuf_sched_queue_get(pkt);
	uint32_t tc_id = rte_mbuf_sched_traffic_class_get(pkt);

	*subport = (qindex >> (port->max_subport_pipes_log2 + 4)) &
		(port->n_subports_per_port - 1);

	s = port->subports[*subport];
	*pipe = (qindex >> 4) & (s->n_subport_pipes - 1);
	*traffic_class = tc_id;
	*queue = qindex & (RTE_SCHED_QUEUES_PER_PIPE - 1);
}

enum rte_color
rte_sched_port_pkt_read_color(const struct rte_mbuf *pkt)
{
	return (enum rte_color)rte_mbuf_sched_color_get(pkt);
}

int
rte_sched_subport_read_stats(struct rte_sched_port *port,
			     uint32_t subport_id,
			     struct rte_sched_subport_stats *stats,
			     uint32_t *tc_ov)
{
	struct rte_sched_subport *s;

	/* Check user parameters */
	if (port == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for parameter port \n", __func__);
		return -EINVAL;
	}

	if (subport_id >= port->n_subports_per_port) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for subport id \n", __func__);
		return -EINVAL;
	}

	if (stats == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for parameter stats \n", __func__);
		return -EINVAL;
	}

	if (tc_ov == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for tc_ov \n", __func__);
		return -EINVAL;
	}

	s = port->subports[subport_id];

	/* Copy subport stats and clear */
	memcpy(stats, &s->stats, sizeof(struct rte_sched_subport_stats));
	memset(&s->stats, 0, sizeof(struct rte_sched_subport_stats));

	/* Subport TC oversubscription status */
	*tc_ov = s->tc_ov;

	return 0;
}

int
rte_sched_queue_read_stats(struct rte_sched_port *port,
	uint32_t queue_id,
	struct rte_sched_queue_stats *stats,
	uint16_t *qlen)
{
	uint32_t subport_id, qindex;
	struct rte_sched_subport *s;
	struct rte_sched_queue *q;
	struct rte_sched_queue_extra *qe;

	/* Check user parameters */
	if (port == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for parameter port \n", __func__);
		return -EINVAL;
	}

	if (queue_id >= rte_sched_port_queues(port)) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for queue id \n", __func__);
		return -EINVAL;
	}

	if (stats == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for parameter stats \n", __func__);
		return -EINVAL;
	}

	if (qlen == NULL) {
		RTE_LOG(ERR, SCHED,
			"%s: Incorrect value for parameter qlen \n", __func__);
		return -EINVAL;
	}

	subport_id = (queue_id >> (port->max_subport_pipes_log2 + 4)) &
					(port->n_subports_per_port - 1);
	s = port->subports[subport_id];
	qindex = ((1 << (port->max_subport_pipes_log2 + 4)) - 1) & queue_id;
	q = s->queue + qindex;
	qe = s->queue_extra + qindex;

	/* Copy queue stats and clear */
	memcpy(stats, &qe->stats, sizeof(struct rte_sched_queue_stats));
	memset(&qe->stats, 0, sizeof(struct rte_sched_queue_stats));

	/* Queue length */
	*qlen = q->qw - q->qr;

	return 0;
}

#ifdef RTE_SCHED_DEBUG

static inline int
rte_sched_port_queue_is_empty(struct rte_sched_subport *subport,
	uint32_t qindex)
{
	struct rte_sched_queue *queue = subport->queue + qindex;

	return queue->qr == queue->qw;
}

#endif /* RTE_SCHED_DEBUG */

#ifdef RTE_SCHED_COLLECT_STATS

static inline void
rte_sched_port_update_subport_stats(struct rte_sched_subport *s,
	struct rte_mbuf *pkt)
{
	uint32_t tc_index = rte_mbuf_sched_traffic_class_get(pkt);
	uint32_t pkt_len = pkt->pkt_len;

	s->stats.n_pkts_tc[tc_index] += 1;
	s->stats.n_bytes_tc[tc_index] += pkt_len;
}

#ifdef RTE_SCHED_RED
static inline void
rte_sched_port_update_subport_stats_on_drop(struct rte_sched_subport *subport,
						struct rte_mbuf *pkt,
						uint32_t red)
#else
static inline void
rte_sched_port_update_subport_stats_on_drop(struct rte_sched_subport *subport,
						struct rte_mbuf *pkt,
						__rte_unused uint32_t red)
#endif
{
	uint32_t tc_index = rte_mbuf_sched_traffic_class_get(pkt);
	uint32_t pkt_len = pkt->pkt_len;

	subport->stats.n_pkts_tc_dropped[tc_index] += 1;
	subport->stats.n_bytes_tc_dropped[tc_index] += pkt_len;
#ifdef RTE_SCHED_RED
	subport->stats.n_pkts_red_dropped[tc_index] += red;
#endif
}

static inline void
rte_sched_port_update_queue_stats(struct rte_sched_subport *subport,
	uint32_t qindex, struct rte_mbuf *pkt)
{
	struct rte_sched_queue_extra *qe = subport->queue_extra + qindex;
	uint32_t pkt_len = pkt->pkt_len;

	qe->stats.n_pkts += 1;
	qe->stats.n_bytes += pkt_len;
}

#ifdef RTE_SCHED_RED
static inline void
rte_sched_port_update_queue_stats_on_drop(struct rte_sched_subport *subport,
						uint32_t qindex,
						struct rte_mbuf *pkt,
						int32_t red)
#else
static inline void
rte_sched_port_update_queue_stats_on_drop(struct rte_sched_subport *subport,
						uint32_t qindex,
						struct rte_mbuf *pkt,
						__rte_unused uint32_t red)
#endif
{
	struct rte_sched_queue_extra *qe = subport->queue_extra + qindex;
	uint32_t pkt_len = pkt->pkt_len;

	qe->stats.n_pkts_dropped += 1;
	qe->stats.n_bytes_dropped += pkt_len;
#ifdef RTE_SCHED_RED
	qe->stats.n_pkts_red_dropped += red;
#endif
}

#endif /* RTE_SCHED_COLLECT_STATS */

#ifdef RTE_SCHED_RED

static inline int
rte_sched_port_red_drop(struct rte_sched_subport *subport,
	struct rte_mbuf *pkt,
	uint32_t qindex,
	uint16_t qlen,
	uint64_t time)
{
	struct rte_sched_queue_extra *qe;
	struct rte_red_config *red_cfg;
	struct rte_red *red;
	uint32_t tc_index;
	enum rte_color color;

	tc_index = rte_mbuf_sched_traffic_class_get(pkt);
	color = rte_sched_port_pkt_read_color(pkt);
	red_cfg = &subport->red_config[tc_index][color];

	if ((red_cfg->min_th | red_cfg->max_th) == 0)
		return 0;

	qe = subport->queue_extra + qindex;
	red = &qe->red;

	return rte_red_enqueue(red_cfg, red, qlen, time);
}

static inline void
rte_sched_port_set_queue_empty_timestamp(struct rte_sched_port *port,
	struct rte_sched_subport *subport, uint32_t qindex)
{
	struct rte_sched_queue_extra *qe = subport->queue_extra + qindex;
	struct rte_red *red = &qe->red;

	rte_red_mark_queue_empty(red, port->time);
}

#else

static inline int rte_sched_port_red_drop(
	struct rte_sched_subport *subport __rte_unused,
	struct rte_mbuf *pkt __rte_unused,
	uint32_t qindex __rte_unused,
	uint16_t qlen __rte_unused,
	uint64_t time __rte_unused)
{
	return 0;
}

static inline void
rte_sched_port_set_queue_empty_timestamp(struct rte_sched_port *port __rte_unused,
	struct rte_sched_subport *subport __rte_unused,
	uint32_t qindex __rte_unused)
{
	return;
}
#endif /* RTE_SCHED_RED */

#ifdef RTE_SCHED_DEBUG

static inline void
debug_check_queue_slab(struct rte_sched_subport *subport, uint32_t bmp_pos,
		       uint64_t bmp_slab)
{
	uint64_t mask;
	uint32_t i, panic;

	if (bmp_slab == 0)
		rte_panic("Empty slab at position %u\n", bmp_pos);

	panic = 0;
	for (i = 0, mask = 1; i < 64; i++, mask <<= 1) {
		if (mask & bmp_slab) {
			if (rte_sched_port_queue_is_empty(subport, bmp_pos + i)) {
				printf("Queue %u (slab offset %u) is empty\n", bmp_pos + i, i);
				panic = 1;
			}
		}
	}

	if (panic)
		rte_panic("Empty queues in slab 0x%" PRIx64 "starting at position %u\n",
			bmp_slab, bmp_pos);
}

#endif /* RTE_SCHED_DEBUG */

static inline struct rte_sched_subport *
rte_sched_port_get_subport(struct rte_sched_port *port,
	struct rte_mbuf *pkt)
{
	uint32_t qindex = rte_mbuf_sched_queue_get(pkt);
	uint32_t subport_id = (qindex >> (port->max_subport_pipes_log2 + 4)) &
		(port->n_subports_per_port - 1);

	return port->subports[subport_id];
}

static inline uint32_t
rte_sched_port_enqueue_qptrs_prefetch0(struct rte_sched_subport *subport,
	struct rte_mbuf *pkt, uint32_t bitwidth)
{
	struct rte_sched_queue *q;
#ifdef RTE_SCHED_COLLECT_STATS
	struct rte_sched_queue_extra *qe;
#endif
	uint32_t qindex = rte_mbuf_sched_queue_get(pkt);
	uint32_t queue_id = ((1 << (bitwidth + 4)) - 1) & qindex;

	q = subport->queue + queue_id;
	rte_prefetch0(q);
#ifdef RTE_SCHED_COLLECT_STATS
	qe = subport->queue_extra + queue_id;
	rte_prefetch0(qe);
#endif

	return queue_id;
}

static inline void
rte_sched_port_enqueue_qwa_prefetch0(struct rte_sched_subport *subport,
				     uint32_t qindex, struct rte_mbuf **qbase)
{
	struct rte_sched_queue *q;
	struct rte_mbuf **q_qw;
	uint16_t qsize;

	q = subport->queue + qindex;
	qsize = rte_sched_subport_qsize(subport, qindex);
	q_qw = qbase + (q->qw & (qsize - 1));

	rte_prefetch0(q_qw);
	rte_bitmap_prefetch0(subport->bmp, qindex);
}

static inline int
rte_sched_port_enqueue_qwa(struct rte_sched_subport *subport, uint32_t qindex,
		struct rte_mbuf **qbase, struct rte_mbuf *pkt, uint64_t time)
{
	struct rte_sched_queue *q = subport->queue + qindex;
	uint16_t qsize = rte_sched_subport_qsize(subport, qindex);
	uint16_t qlen = q->qw - q->qr;

	/* Drop the packet (and update drop stats) when queue is full */
	if (unlikely(rte_sched_port_red_drop(subport, pkt, qindex, qlen, time)
		|| (qlen >= qsize))) {
		rte_pktmbuf_free(pkt);
#ifdef RTE_SCHED_COLLECT_STATS
		rte_sched_port_update_subport_stats_on_drop(subport, pkt,
			qlen < qsize);
		rte_sched_port_update_queue_stats_on_drop(subport, qindex, pkt,
			qlen < qsize);
#endif
		return 0;
	}

	/* Enqueue packet */
	qbase[q->qw & (qsize - 1)] = pkt;
	q->qw++;

	/* Activate queue in the subport bitmap */
	rte_bitmap_set(subport->bmp, qindex);

	/* Statistics */
#ifdef RTE_SCHED_COLLECT_STATS
	rte_sched_port_update_subport_stats(subport, pkt);
	rte_sched_port_update_queue_stats(subport, qindex, pkt);
#endif

	return 1;
}


/*
 * The enqueue function implements a 4-level pipeline with each stage
 * processing two different packets. The purpose of using a pipeline
 * is to hide the latency of prefetching the data structures. The
 * naming convention is presented in the diagram below:
 *
 *   p00  _______   p10  _______   p20  _______   p30  _______
 * ----->|       |----->|       |----->|       |----->|       |----->
 *       |   0   |      |   1   |      |   2   |      |   3   |
 * ----->|_______|----->|_______|----->|_______|----->|_______|----->
 *   p01            p11            p21            p31
 *
 */
int
rte_sched_port_enqueue(struct rte_sched_port *port, struct rte_mbuf **pkts,
		       uint32_t n_pkts)
{
	struct rte_mbuf *pkt00, *pkt01, *pkt10, *pkt11, *pkt20, *pkt21,
		*pkt30, *pkt31, *pkt_last;
	struct rte_mbuf **q00_base, **q01_base, **q10_base, **q11_base,
		**q20_base, **q21_base, **q30_base, **q31_base, **q_last_base;
	struct rte_sched_subport *subport00, *subport01, *subport10, *subport11,
		*subport20, *subport21, *subport30, *subport31, *subport_last;
	uint32_t q00, q01, q10, q11, q20, q21, q30, q31, q_last;
	uint32_t r00, r01, r10, r11, r20, r21, r30, r31, r_last;
	uint32_t result, bitwidth, i;

	result = 0;
	bitwidth = port->max_subport_pipes_log2;

	/*
	 * Less then 6 input packets available, which is not enough to
	 * feed the pipeline
	 */
	if (unlikely(n_pkts < 6)) {
		struct rte_sched_subport *subports[5];
		struct rte_mbuf **q_base[5];
		uint32_t q[5];

		/* Prefetch the mbuf structure of each packet */
		for (i = 0; i < n_pkts; i++)
			rte_prefetch0(pkts[i]);

		/* Prefetch the subport structure for each packet */
		for (i = 0; i < n_pkts; i++)
			subports[i] =
				rte_sched_port_get_subport(port, pkts[i]);

		/* Prefetch the queue structure for each queue */
		for (i = 0; i < n_pkts; i++)
			q[i] = rte_sched_port_enqueue_qptrs_prefetch0(subports[i],
					pkts[i], bitwidth);

		/* Prefetch the write pointer location of each queue */
		for (i = 0; i < n_pkts; i++) {
			q_base[i] = rte_sched_subport_qbase(subports[i], q[i]);
			rte_sched_port_enqueue_qwa_prefetch0(subports[i], q[i],
							     q_base[i]);
		}

		/* Write each packet to its queue */
		for (i = 0; i < n_pkts; i++)
			result += rte_sched_port_enqueue_qwa(subports[i], q[i],
					q_base[i], pkts[i], port->time);

		return result;
	}

	/* Feed the first 3 stages of the pipeline (6 packets needed) */
	pkt20 = pkts[0];
	pkt21 = pkts[1];
	rte_prefetch0(pkt20);
	rte_prefetch0(pkt21);

	pkt10 = pkts[2];
	pkt11 = pkts[3];
	rte_prefetch0(pkt10);
	rte_prefetch0(pkt11);

	subport20 = rte_sched_port_get_subport(port, pkt20);
	subport21 = rte_sched_port_get_subport(port, pkt21);
	q20 = rte_sched_port_enqueue_qptrs_prefetch0(subport20, pkt20, bitwidth);
	q21 = rte_sched_port_enqueue_qptrs_prefetch0(subport21, pkt21, bitwidth);

	pkt00 = pkts[4];
	pkt01 = pkts[5];
	rte_prefetch0(pkt00);
	rte_prefetch0(pkt01);

	subport10 = rte_sched_port_get_subport(port, pkt10);
	subport11 = rte_sched_port_get_subport(port, pkt11);
	q10 = rte_sched_port_enqueue_qptrs_prefetch0(subport10, pkt10, bitwidth);
	q11 = rte_sched_port_enqueue_qptrs_prefetch0(subport11, pkt11, bitwidth);

	q20_base = rte_sched_subport_qbase(subport20, q20);
	q21_base = rte_sched_subport_qbase(subport21, q21);
	rte_sched_port_enqueue_qwa_prefetch0(subport20, q20, q20_base);
	rte_sched_port_enqueue_qwa_prefetch0(subport21, q21, q21_base);

	/* Run the pipeline */
	for (i = 6; i < (n_pkts & (~1)); i += 2) {
		/* Propagate stage inputs */
		pkt30 = pkt20;
		pkt31 = pkt21;
		pkt20 = pkt10;
		pkt21 = pkt11;
		pkt10 = pkt00;
		pkt11 = pkt01;
		q30 = q20;
		q31 = q21;
		q20 = q10;
		q21 = q11;
		subport30 = subport20;
		subport31 = subport21;
		subport20 = subport10;
		subport21 = subport11;
		q30_base = q20_base;
		q31_base = q21_base;

		/* Stage 0: Get packets in */
		pkt00 = pkts[i];
		pkt01 = pkts[i + 1];
		rte_prefetch0(pkt00);
		rte_prefetch0(pkt01);

		/* Stage 1: Prefetch subport and queue structure storing queue
		 *  pointers
		 */
		subport10 = rte_sched_port_get_subport(port, pkt10);
		subport11 = rte_sched_port_get_subport(port, pkt11);
		q10 = rte_sched_port_enqueue_qptrs_prefetch0(subport10, pkt10, bitwidth);
		q11 = rte_sched_port_enqueue_qptrs_prefetch0(subport11, pkt11, bitwidth);

		/* Stage 2: Prefetch queue write location */
		q20_base = rte_sched_subport_qbase(subport20, q20);
		q21_base = rte_sched_subport_qbase(subport21, q21);
		rte_sched_port_enqueue_qwa_prefetch0(subport20, q20, q20_base);
		rte_sched_port_enqueue_qwa_prefetch0(subport21, q21, q21_base);

		/* Stage 3: Write packet to queue and activate queue */
		r30 = rte_sched_port_enqueue_qwa(subport30, q30, q30_base,
			pkt30, port->time);
		r31 = rte_sched_port_enqueue_qwa(subport31, q31, q31_base,
			pkt31, port->time);
		result += r30 + r31;
	}

	/*
	 * Drain the pipeline (exactly 6 packets).
	 * Handle the last packet in the case
	 * of an odd number of input packets.
	 */
	pkt_last = pkts[n_pkts - 1];
	rte_prefetch0(pkt_last);

	subport00 = rte_sched_port_get_subport(port, pkt00);
	subport01 = rte_sched_port_get_subport(port, pkt01);
	q00 = rte_sched_port_enqueue_qptrs_prefetch0(subport00, pkt00, bitwidth);
	q01 = rte_sched_port_enqueue_qptrs_prefetch0(subport01, pkt01, bitwidth);

	q10_base = rte_sched_subport_qbase(subport10, q10);
	q11_base = rte_sched_subport_qbase(subport11, q11);
	rte_sched_port_enqueue_qwa_prefetch0(subport10, q10, q10_base);
	rte_sched_port_enqueue_qwa_prefetch0(subport11, q11, q11_base);

	r20 = rte_sched_port_enqueue_qwa(subport20, q20, q20_base, pkt20,
		port->time);
	r21 = rte_sched_port_enqueue_qwa(subport21, q21, q21_base, pkt21,
		port->time);
	result += r20 + r21;

	subport_last = rte_sched_port_get_subport(port, pkt_last);
	q_last = rte_sched_port_enqueue_qptrs_prefetch0(subport_last,
				pkt_last, bitwidth);

	q00_base = rte_sched_subport_qbase(subport00, q00);
	q01_base = rte_sched_subport_qbase(subport01, q01);
	rte_sched_port_enqueue_qwa_prefetch0(subport00, q00, q00_base);
	rte_sched_port_enqueue_qwa_prefetch0(subport01, q01, q01_base);

	r10 = rte_sched_port_enqueue_qwa(subport10, q10, q10_base, pkt10,
		port->time);
	r11 = rte_sched_port_enqueue_qwa(subport11, q11, q11_base, pkt11,
		port->time);
	result += r10 + r11;

	q_last_base = rte_sched_subport_qbase(subport_last, q_last);
	rte_sched_port_enqueue_qwa_prefetch0(subport_last, q_last, q_last_base);

	r00 = rte_sched_port_enqueue_qwa(subport00, q00, q00_base, pkt00,
		port->time);
	r01 = rte_sched_port_enqueue_qwa(subport01, q01, q01_base, pkt01,
		port->time);
	result += r00 + r01;

	if (n_pkts & 1) {
		r_last = rte_sched_port_enqueue_qwa(subport_last, q_last,
				q_last_base, pkt_last, port->time);
		result += r_last;
	}

	return result;
}

#ifndef RTE_SCHED_SUBPORT_TC_OV

static inline void
grinder_credits_update(struct rte_sched_port *port,
	struct rte_sched_subport *subport, uint32_t pos)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	struct rte_sched_pipe *pipe = grinder->pipe;
	struct rte_sched_pipe_profile *params = grinder->pipe_params;
	uint64_t n_periods;
	uint32_t i;

	/* Subport TB */
	n_periods = (port->time - subport->tb_time) / subport->tb_period;
	subport->tb_credits += n_periods * subport->tb_credits_per_period;
	subport->tb_credits = rte_sched_min_val_2_u32(subport->tb_credits, subport->tb_size);
	subport->tb_time += n_periods * subport->tb_period;

	/* Pipe TB */
	n_periods = (port->time - pipe->tb_time) / params->tb_period;
	pipe->tb_credits += n_periods * params->tb_credits_per_period;
	pipe->tb_credits = rte_sched_min_val_2_u32(pipe->tb_credits, params->tb_size);
	pipe->tb_time += n_periods * params->tb_period;

	/* Subport TCs */
	if (unlikely(port->time >= subport->tc_time)) {
		for (i = 0; i <= RTE_SCHED_TRAFFIC_CLASS_BE; i++)
			subport->tc_credits[i] = subport->tc_credits_per_period[i];

		subport->tc_time = port->time + subport->tc_period;
	}

	/* Pipe TCs */
	if (unlikely(port->time >= pipe->tc_time)) {
		for (i = 0; i <= RTE_SCHED_TRAFFIC_CLASS_BE; i++)
			pipe->tc_credits[i] = params->tc_credits_per_period[i];

		pipe->tc_time = port->time + params->tc_period;
	}
}

#else

static inline uint32_t
grinder_tc_ov_credits_update(struct rte_sched_port *port,
	struct rte_sched_subport *subport, uint32_t pos)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	struct rte_sched_pipe *pipe = grinder->pipe;
	uint32_t tc_ov_consumption[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t tc_consumption = 0, tc_ov_consumption_max;
	uint32_t tc_ov_wm = subport->tc_ov_wm;
	uint32_t i;

	if (subport->tc_ov == 0)
		return subport->tc_ov_wm_max;

	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASS_BE; i++) {
		tc_ov_consumption[i] =
			subport->tc_credits_per_period[i] - subport->tc_credits[i];
		tc_consumption += tc_ov_consumption[i];
	}

	tc_ov_consumption[RTE_SCHED_TRAFFIC_CLASS_BE] =
		subport->tc_credits_per_period[RTE_SCHED_TRAFFIC_CLASS_BE] -
		subport->tc_credits[RTE_SCHED_TRAFFIC_CLASS_BE];

	tc_ov_consumption_max =
		subport->tc_credits_per_period[RTE_SCHED_TRAFFIC_CLASS_BE] - tc_consumption;

	if (tc_ov_consumption[RTE_SCHED_TRAFFIC_CLASS_BE] >
		(tc_ov_consumption_max - port->mtu)) {
		tc_ov_wm  -= tc_ov_wm >> 7;
		if (tc_ov_wm < subport->tc_ov_wm_min)
			tc_ov_wm = subport->tc_ov_wm_min;

		return tc_ov_wm;
	}

	tc_ov_wm += (tc_ov_wm >> 7) + 1;
	if (tc_ov_wm > subport->tc_ov_wm_max)
		tc_ov_wm = subport->tc_ov_wm_max;

	return tc_ov_wm;
}

static inline void
grinder_credits_update(struct rte_sched_port *port,
	struct rte_sched_subport *subport, uint32_t pos)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	struct rte_sched_pipe *pipe = grinder->pipe;
	struct rte_sched_pipe_profile *params = grinder->pipe_params;
	uint64_t n_periods;
	uint32_t i;

	/* Subport TB */
	n_periods = (port->time - subport->tb_time) / subport->tb_period;
	subport->tb_credits += n_periods * subport->tb_credits_per_period;
	subport->tb_credits = rte_sched_min_val_2_u32(subport->tb_credits, subport->tb_size);
	subport->tb_time += n_periods * subport->tb_period;

	/* Pipe TB */
	n_periods = (port->time - pipe->tb_time) / params->tb_period;
	pipe->tb_credits += n_periods * params->tb_credits_per_period;
	pipe->tb_credits = rte_sched_min_val_2_u32(pipe->tb_credits, params->tb_size);
	pipe->tb_time += n_periods * params->tb_period;

	/* Subport TCs */
	if (unlikely(port->time >= subport->tc_time)) {
		subport->tc_ov_wm = grinder_tc_ov_credits_update(port, subport, pos);

		for (i = 0; i <= RTE_SCHED_TRAFFIC_CLASS_BE; i++)
			subport->tc_credits[i] = subport->tc_credits_per_period[i];

		subport->tc_time = port->time + subport->tc_period;
		subport->tc_ov_period_id++;
	}

	/* Pipe TCs */
	if (unlikely(port->time >= pipe->tc_time)) {
		for (i = 0; i <= RTE_SCHED_TRAFFIC_CLASS_BE; i++)
			pipe->tc_credits[i] = params->tc_credits_per_period[i];

		pipe->tc_time = port->time + params->tc_period;
	}

	/* Pipe TCs - Oversubscription */
	if (unlikely(pipe->tc_ov_period_id != subport->tc_ov_period_id)) {
		pipe->tc_ov_credits = subport->tc_ov_wm * params->tc_ov_weight;

		pipe->tc_ov_period_id = subport->tc_ov_period_id;
	}
}

#endif /* RTE_SCHED_TS_CREDITS_UPDATE, RTE_SCHED_SUBPORT_TC_OV */


#ifndef RTE_SCHED_SUBPORT_TC_OV

static inline int
grinder_credits_check(struct rte_sched_subport *subport,
	uint32_t pos, uint32_t frame_overhead)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	struct rte_sched_pipe *pipe = grinder->pipe;
	struct rte_mbuf *pkt = grinder->pkt;
	uint32_t tc_index = grinder->tc_index;
	uint32_t pkt_len = pkt->pkt_len + frame_overhead;
	uint32_t subport_tb_credits = subport->tb_credits;
	uint32_t subport_tc_credits = subport->tc_credits[tc_index];
	uint32_t pipe_tb_credits = pipe->tb_credits;
	uint32_t pipe_tc_credits = pipe->tc_credits[tc_index];
	int enough_credits;

	/* Check queue credits */
	enough_credits = (pkt_len <= subport_tb_credits) &&
		(pkt_len <= subport_tc_credits) &&
		(pkt_len <= pipe_tb_credits) &&
		(pkt_len <= pipe_tc_credits);

	if (!enough_credits)
		return 0;

	/* Update subport credits */
	subport->tb_credits -= pkt_len;
	subport->tc_credits[tc_index] -= pkt_len;
	pipe->tb_credits -= pkt_len;
	pipe->tc_credits[tc_index] -= pkt_len;

	return 1;
}

#else

static inline int
grinder_credits_check(struct rte_sched_subport *subport,
	uint32_t pos, uint32_t frame_overhead)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	struct rte_sched_pipe *pipe = grinder->pipe;
	struct rte_mbuf *pkt = grinder->pkt;
	uint32_t tc_index = grinder->tc_index;
	uint32_t pkt_len = pkt->pkt_len + frame_overhead;
	uint32_t subport_tb_credits = subport->tb_credits;
	uint32_t subport_tc_credits = subport->tc_credits[tc_index];
	uint32_t pipe_tb_credits = pipe->tb_credits;
	uint32_t pipe_tc_credits = pipe->tc_credits[tc_index];
	uint32_t pipe_tc_ov_mask1[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t pipe_tc_ov_mask2[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE] = {0};
	uint32_t pipe_tc_ov_credits, i;
	int enough_credits;

	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		pipe_tc_ov_mask1[i] = UINT32_MAX;

	pipe_tc_ov_mask1[RTE_SCHED_TRAFFIC_CLASS_BE] = pipe->tc_ov_credits;
	pipe_tc_ov_mask2[RTE_SCHED_TRAFFIC_CLASS_BE] = UINT32_MAX;
	pipe_tc_ov_credits = pipe_tc_ov_mask1[tc_index];

	/* Check pipe and subport credits */
	enough_credits = (pkt_len <= subport_tb_credits) &&
		(pkt_len <= subport_tc_credits) &&
		(pkt_len <= pipe_tb_credits) &&
		(pkt_len <= pipe_tc_credits) &&
		(pkt_len <= pipe_tc_ov_credits);

	if (!enough_credits)
		return 0;

	/* Update pipe and subport credits */
	subport->tb_credits -= pkt_len;
	subport->tc_credits[tc_index] -= pkt_len;
	pipe->tb_credits -= pkt_len;
	pipe->tc_credits[tc_index] -= pkt_len;
	pipe->tc_ov_credits -= pipe_tc_ov_mask2[tc_index] & pkt_len;

	return 1;
}

#endif /* RTE_SCHED_SUBPORT_TC_OV */

static inline int
grinder_schedule(struct rte_sched_port *port,
	struct rte_sched_subport *subport, uint32_t pos)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	struct rte_mbuf *pkt = grinder->pkt;
	struct rte_sched_queue *queue;
	uint32_t frame_overhead = port->frame_overhead;
	uint32_t qpos, pkt_len;
	int be_tc_active;

	if (!grinder_credits_check(subport, pos, frame_overhead))
		return 0;

	pkt_len = pkt->pkt_len + frame_overhead;
	qpos = grinder->qpos;
	queue = grinder->queue[qpos];

	/* Advance port time */
	port->time += pkt_len;

	/* Send packet */
	port->pkts_out[port->n_pkts_out++] = pkt;
	queue->qr++;

	be_tc_active = (grinder->tc_index == RTE_SCHED_TRAFFIC_CLASS_BE);
	grinder->wrr_tokens[qpos] +=
		pkt_len * grinder->wrr_cost[qpos] * be_tc_active;

	if (queue->qr == queue->qw) {
		uint32_t qindex = grinder->qindex[qpos];

		rte_bitmap_clear(subport->bmp, qindex);
		grinder->qmask &= ~(1 << qpos);
		if (be_tc_active)
			grinder->wrr_mask[qpos] = 0;

		rte_sched_port_set_queue_empty_timestamp(port, subport, qindex);
	}

	/* Reset pipe loop detection */
	subport->pipe_loop = RTE_SCHED_PIPE_INVALID;
	grinder->productive = 1;

	return 1;
}

#ifdef SCHED_VECTOR_SSE4

static inline int
grinder_pipe_exists(struct rte_sched_subport *subport, uint32_t base_pipe)
{
	__m128i index = _mm_set1_epi32(base_pipe);
	__m128i pipes =
		_mm_load_si128((__m128i *)subport->grinder_base_bmp_pos);
	__m128i res = _mm_cmpeq_epi32(pipes, index);

	pipes = _mm_load_si128((__m128i *)(subport->grinder_base_bmp_pos + 4));
	pipes = _mm_cmpeq_epi32(pipes, index);
	res = _mm_or_si128(res, pipes);

	if (_mm_testz_si128(res, res))
		return 0;

	return 1;
}

#elif defined(SCHED_VECTOR_NEON)

static inline int
grinder_pipe_exists(struct rte_sched_subport *subport, uint32_t base_pipe)
{
	uint32x4_t index, pipes;
	uint32_t *pos = (uint32_t *)subport->grinder_base_bmp_pos;

	index = vmovq_n_u32(base_pipe);
	pipes = vld1q_u32(pos);
	if (!vminvq_u32(veorq_u32(pipes, index)))
		return 1;

	pipes = vld1q_u32(pos + 4);
	if (!vminvq_u32(veorq_u32(pipes, index)))
		return 1;

	return 0;
}

#else

static inline int
grinder_pipe_exists(struct rte_sched_subport *subport, uint32_t base_pipe)
{
	uint32_t i;

	for (i = 0; i < RTE_SCHED_PORT_N_GRINDERS; i++) {
		if (subport->grinder_base_bmp_pos[i] == base_pipe)
			return 1;
	}

	return 0;
}

#endif /* RTE_SCHED_OPTIMIZATIONS */

static inline void
grinder_pcache_populate(struct rte_sched_subport *subport, uint32_t pos,
	uint32_t bmp_pos, uint64_t bmp_slab)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	uint16_t w[4];

	grinder->pcache_w = 0;
	grinder->pcache_r = 0;

	w[0] = (uint16_t) bmp_slab;
	w[1] = (uint16_t) (bmp_slab >> 16);
	w[2] = (uint16_t) (bmp_slab >> 32);
	w[3] = (uint16_t) (bmp_slab >> 48);

	grinder->pcache_qmask[grinder->pcache_w] = w[0];
	grinder->pcache_qindex[grinder->pcache_w] = bmp_pos;
	grinder->pcache_w += (w[0] != 0);

	grinder->pcache_qmask[grinder->pcache_w] = w[1];
	grinder->pcache_qindex[grinder->pcache_w] = bmp_pos + 16;
	grinder->pcache_w += (w[1] != 0);

	grinder->pcache_qmask[grinder->pcache_w] = w[2];
	grinder->pcache_qindex[grinder->pcache_w] = bmp_pos + 32;
	grinder->pcache_w += (w[2] != 0);

	grinder->pcache_qmask[grinder->pcache_w] = w[3];
	grinder->pcache_qindex[grinder->pcache_w] = bmp_pos + 48;
	grinder->pcache_w += (w[3] != 0);
}

static inline void
grinder_tccache_populate(struct rte_sched_subport *subport, uint32_t pos,
	uint32_t qindex, uint16_t qmask)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	uint8_t b, i;

	grinder->tccache_w = 0;
	grinder->tccache_r = 0;

	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASS_BE; i++) {
		b = (uint8_t) ((qmask >> i) & 0x1);
		grinder->tccache_qmask[grinder->tccache_w] = b;
		grinder->tccache_qindex[grinder->tccache_w] = qindex + i;
		grinder->tccache_w += (b != 0);
	}

	b = (uint8_t) (qmask >> (RTE_SCHED_TRAFFIC_CLASS_BE));
	grinder->tccache_qmask[grinder->tccache_w] = b;
	grinder->tccache_qindex[grinder->tccache_w] = qindex +
		RTE_SCHED_TRAFFIC_CLASS_BE;
	grinder->tccache_w += (b != 0);
}

static inline int
grinder_next_tc(struct rte_sched_subport *subport, uint32_t pos)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	struct rte_sched_pipe *pipe = grinder->pipe;
	struct rte_mbuf **qbase;
	uint32_t qindex, qpos = 0;
	uint16_t qsize;

	if (grinder->tccache_r == grinder->tccache_w)
		return 0;

	qindex = grinder->tccache_qindex[grinder->tccache_r];
	grinder->tc_index = qindex & 0xf;
	qbase = rte_sched_subport_qbase(subport, qindex);

	if (grinder->tc_index < RTE_SCHED_TRAFFIC_CLASS_BE) {
		qsize = rte_sched_subport_qsize(subport, qindex);

		grinder->queue[qpos] = subport->queue + qindex;
		grinder->qbase[qpos] = qbase;
		grinder->qindex[qpos] = qindex;
		grinder->qsize[qpos] = qsize;
		grinder->qmask = grinder->tccache_qmask[grinder->tccache_r];
		grinder->tccache_r++;

		return 1;
	}

	for ( ; qpos < pipe->n_be_queues; qpos++) {
		qsize = rte_sched_subport_qsize(subport, qindex + qpos);
		grinder->queue[qpos] = subport->queue + qindex + qpos;
		grinder->qbase[qpos] = qbase + qpos * qsize;
		grinder->qindex[qpos] = qindex + qpos;
		grinder->qsize[qpos] = qsize;
	}
	grinder->tc_index = RTE_SCHED_TRAFFIC_CLASS_BE;
	grinder->qmask = grinder->tccache_qmask[grinder->tccache_r];
	grinder->tccache_r++;

	return 1;
}

static inline int
grinder_next_pipe(struct rte_sched_subport *subport, uint32_t pos)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	uint32_t pipe_qindex;
	uint16_t pipe_qmask;

	if (grinder->pcache_r < grinder->pcache_w) {
		pipe_qmask = grinder->pcache_qmask[grinder->pcache_r];
		pipe_qindex = grinder->pcache_qindex[grinder->pcache_r];
		grinder->pcache_r++;
	} else {
		uint64_t bmp_slab = 0;
		uint32_t bmp_pos = 0;

		/* Get another non-empty pipe group */
		if (unlikely(rte_bitmap_scan(subport->bmp, &bmp_pos, &bmp_slab)
			<= 0))
			return 0;

#ifdef RTE_SCHED_DEBUG
		debug_check_queue_slab(subport, bmp_pos, bmp_slab);
#endif

		/* Return if pipe group already in one of the other grinders */
		subport->grinder_base_bmp_pos[pos] = RTE_SCHED_BMP_POS_INVALID;
		if (unlikely(grinder_pipe_exists(subport, bmp_pos)))
			return 0;

		subport->grinder_base_bmp_pos[pos] = bmp_pos;

		/* Install new pipe group into grinder's pipe cache */
		grinder_pcache_populate(subport, pos, bmp_pos, bmp_slab);

		pipe_qmask = grinder->pcache_qmask[0];
		pipe_qindex = grinder->pcache_qindex[0];
		grinder->pcache_r = 1;
	}

	/* Install new pipe in the grinder */
	grinder->pindex = pipe_qindex >> 4;
	grinder->subport = subport;
	grinder->pipe = subport->pipe + grinder->pindex;
	grinder->pipe_params = NULL; /* to be set after the pipe structure is prefetched */
	grinder->productive = 0;

	grinder_tccache_populate(subport, pos, pipe_qindex, pipe_qmask);
	grinder_next_tc(subport, pos);

	/* Check for pipe exhaustion */
	if (grinder->pindex == subport->pipe_loop) {
		subport->pipe_exhaustion = 1;
		subport->pipe_loop = RTE_SCHED_PIPE_INVALID;
	}

	return 1;
}


static inline void
grinder_wrr_load(struct rte_sched_subport *subport, uint32_t pos)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	struct rte_sched_pipe *pipe = grinder->pipe;
	struct rte_sched_pipe_profile *pipe_params = grinder->pipe_params;
	uint32_t qmask = grinder->qmask;
	uint32_t qindex = grinder->qindex[0];
	uint32_t i;

	for (i = 0; i < pipe->n_be_queues; i++) {
		grinder->wrr_tokens[i] =
			((uint16_t) pipe->wrr_tokens[qindex + i]) << RTE_SCHED_WRR_SHIFT;
		grinder->wrr_mask[i] = ((qmask >> i) & 0x1) * 0xFFFF;
		grinder->wrr_cost[i] = pipe_params->wrr_cost[qindex + i];
	}
}

static inline void
grinder_wrr_store(struct rte_sched_subport *subport, uint32_t pos)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	struct rte_sched_pipe *pipe = grinder->pipe;
	uint32_t i;

	for (i = 0; i < pipe->n_be_queues; i++)
		pipe->wrr_tokens[i] =
			(grinder->wrr_tokens[i] & grinder->wrr_mask[i]) >>
				RTE_SCHED_WRR_SHIFT;
}

static inline void
grinder_wrr(struct rte_sched_subport *subport, uint32_t pos)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	struct rte_sched_pipe *pipe = grinder->pipe;
	uint32_t n_be_queues = pipe->n_be_queues;
	uint16_t wrr_tokens_min;

	if (n_be_queues == 1) {
		grinder->wrr_tokens[0] |= ~grinder->wrr_mask[0];
		grinder->qpos = 0;
		wrr_tokens_min = grinder->wrr_tokens[0];
		grinder->wrr_tokens[0] -= wrr_tokens_min;
		return;
	}

	if (n_be_queues == 2) {
		grinder->wrr_tokens[0] |= ~grinder->wrr_mask[0];
		grinder->wrr_tokens[1] |= ~grinder->wrr_mask[1];

		grinder->qpos = rte_min_pos_2_u16(grinder->wrr_tokens);
		wrr_tokens_min = grinder->wrr_tokens[grinder->qpos];

		grinder->wrr_tokens[0] -= wrr_tokens_min;
		grinder->wrr_tokens[1] -= wrr_tokens_min;
		return;
	}

	if (n_be_queues == 4) {
		grinder->wrr_tokens[0] |= ~grinder->wrr_mask[0];
		grinder->wrr_tokens[1] |= ~grinder->wrr_mask[1];
		grinder->wrr_tokens[2] |= ~grinder->wrr_mask[2];
		grinder->wrr_tokens[3] |= ~grinder->wrr_mask[3];

		grinder->qpos = rte_min_pos_4_u16(grinder->wrr_tokens);
		wrr_tokens_min = grinder->wrr_tokens[grinder->qpos];

		grinder->wrr_tokens[0] -= wrr_tokens_min;
		grinder->wrr_tokens[1] -= wrr_tokens_min;
		grinder->wrr_tokens[2] -= wrr_tokens_min;
		grinder->wrr_tokens[3] -= wrr_tokens_min;
		return;
	}

	grinder->wrr_tokens[0] |= ~grinder->wrr_mask[0];
	grinder->wrr_tokens[1] |= ~grinder->wrr_mask[1];
	grinder->wrr_tokens[2] |= ~grinder->wrr_mask[2];
	grinder->wrr_tokens[3] |= ~grinder->wrr_mask[3];
	grinder->wrr_tokens[4] |= ~grinder->wrr_mask[4];
	grinder->wrr_tokens[5] |= ~grinder->wrr_mask[5];
	grinder->wrr_tokens[6] |= ~grinder->wrr_mask[6];
	grinder->wrr_tokens[7] |= ~grinder->wrr_mask[7];

	grinder->qpos = rte_min_pos_8_u16(grinder->wrr_tokens);
	wrr_tokens_min = grinder->wrr_tokens[grinder->qpos];

	grinder->wrr_tokens[0] -= wrr_tokens_min;
	grinder->wrr_tokens[1] -= wrr_tokens_min;
	grinder->wrr_tokens[2] -= wrr_tokens_min;
	grinder->wrr_tokens[3] -= wrr_tokens_min;
	grinder->wrr_tokens[4] -= wrr_tokens_min;
	grinder->wrr_tokens[5] -= wrr_tokens_min;
	grinder->wrr_tokens[6] -= wrr_tokens_min;
	grinder->wrr_tokens[7] -= wrr_tokens_min;
}


#define grinder_evict(subport, pos)

static inline void
grinder_prefetch_pipe(struct rte_sched_subport *subport, uint32_t pos)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;

	rte_prefetch0(grinder->pipe);
	rte_prefetch0(grinder->queue[0]);
}

static inline void
grinder_prefetch_tc_queue_arrays(struct rte_sched_subport *subport, uint32_t pos)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	struct rte_sched_pipe *pipe = grinder->pipe;
	struct rte_sched_queue *queue;
	uint32_t i;
	uint16_t qsize, qr[RTE_SCHED_MAX_QUEUES_PER_TC];

	grinder->qpos = 0;
	if (grinder->tc_index < RTE_SCHED_TRAFFIC_CLASS_BE) {
		queue = grinder->queue[0];
		qsize = grinder->qsize[0];
		qr[0] = queue->qr & (qsize - 1);

		rte_prefetch0(grinder->qbase[0] + qr[0]);
		return;
	}

	for (i = 0; i < pipe->n_be_queues; i++) {
		queue = grinder->queue[i];
		qsize = grinder->qsize[i];
		qr[i] = queue->qr & (qsize - 1);

		rte_prefetch0(grinder->qbase[i] + qr[i]);
	}

	grinder_wrr_load(subport, pos);
	grinder_wrr(subport, pos);
}

static inline void
grinder_prefetch_mbuf(struct rte_sched_subport *subport, uint32_t pos)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;
	struct rte_mbuf **qbase;
	uint32_t qpos = grinder->qpos;
	uint16_t qsize, qr;

	qbase = grinder->qbase[qpos];
	qsize = grinder->qsize[qpos];
	qr = grinder->queue[qpos]->qr & (qsize - 1);

	grinder->pkt = qbase[qr];
	rte_prefetch0(grinder->pkt);

	if (unlikely((qr & 0x7) == 7)) {
		uint16_t qr_next = (grinder->queue[qpos]->qr + 1) & (qsize - 1);

		rte_prefetch0(qbase + qr_next);
	}
}

static inline uint32_t
grinder_handle(struct rte_sched_port *port,
	struct rte_sched_subport *subport, uint32_t pos)
{
	struct rte_sched_grinder *grinder = subport->grinder + pos;

	switch (grinder->state) {
	case e_GRINDER_PREFETCH_PIPE:
	{
		if (grinder_next_pipe(subport, pos)) {
			grinder_prefetch_pipe(subport, pos);
			subport->busy_grinders++;

			grinder->state = e_GRINDER_PREFETCH_TC_QUEUE_ARRAYS;
			return 0;
		}

		return 0;
	}

	case e_GRINDER_PREFETCH_TC_QUEUE_ARRAYS:
	{
		struct rte_sched_pipe *pipe = grinder->pipe;

		grinder->pipe_params = subport->pipe_profiles + pipe->profile;
		grinder_prefetch_tc_queue_arrays(subport, pos);
		grinder_credits_update(port, subport, pos);

		grinder->state = e_GRINDER_PREFETCH_MBUF;
		return 0;
	}

	case e_GRINDER_PREFETCH_MBUF:
	{
		grinder_prefetch_mbuf(subport, pos);

		grinder->state = e_GRINDER_READ_MBUF;
		return 0;
	}

	case e_GRINDER_READ_MBUF:
	{
		uint32_t wrr_active, result = 0;

		result = grinder_schedule(port, subport, pos);
		wrr_active = (grinder->tc_index == RTE_SCHED_TRAFFIC_CLASS_BE);

		/* Look for next packet within the same TC */
		if (result && grinder->qmask) {
			if (wrr_active)
				grinder_wrr(subport, pos);

			grinder_prefetch_mbuf(subport, pos);

			return 1;
		}

		if (wrr_active)
			grinder_wrr_store(subport, pos);

		/* Look for another active TC within same pipe */
		if (grinder_next_tc(subport, pos)) {
			grinder_prefetch_tc_queue_arrays(subport, pos);

			grinder->state = e_GRINDER_PREFETCH_MBUF;
			return result;
		}

		if (grinder->productive == 0 &&
		    subport->pipe_loop == RTE_SCHED_PIPE_INVALID)
			subport->pipe_loop = grinder->pindex;

		grinder_evict(subport, pos);

		/* Look for another active pipe */
		if (grinder_next_pipe(subport, pos)) {
			grinder_prefetch_pipe(subport, pos);

			grinder->state = e_GRINDER_PREFETCH_TC_QUEUE_ARRAYS;
			return result;
		}

		/* No active pipe found */
		subport->busy_grinders--;

		grinder->state = e_GRINDER_PREFETCH_PIPE;
		return result;
	}

	default:
		rte_panic("Algorithmic error (invalid state)\n");
		return 0;
	}
}

static inline void
rte_sched_port_time_resync(struct rte_sched_port *port)
{
	uint64_t cycles = rte_get_tsc_cycles();
	uint64_t cycles_diff = cycles - port->time_cpu_cycles;
	uint64_t bytes_diff;
	uint32_t i;

	/* Compute elapsed time in bytes */
	bytes_diff = rte_reciprocal_divide(cycles_diff << RTE_SCHED_TIME_SHIFT,
					   port->inv_cycles_per_byte);

	/* Advance port time */
	port->time_cpu_cycles = cycles;
	port->time_cpu_bytes += bytes_diff;
	if (port->time < port->time_cpu_bytes)
		port->time = port->time_cpu_bytes;

	/* Reset pipe loop detection */
	for (i = 0; i < port->n_subports_per_port; i++)
		port->subports[i]->pipe_loop = RTE_SCHED_PIPE_INVALID;
}

static inline int
rte_sched_port_exceptions(struct rte_sched_subport *subport, int second_pass)
{
	int exceptions;

	/* Check if any exception flag is set */
	exceptions = (second_pass && subport->busy_grinders == 0) ||
		(subport->pipe_exhaustion == 1);

	/* Clear exception flags */
	subport->pipe_exhaustion = 0;

	return exceptions;
}

int
rte_sched_port_dequeue(struct rte_sched_port *port, struct rte_mbuf **pkts, uint32_t n_pkts)
{
	struct rte_sched_subport *subport;
	uint32_t subport_id = port->subport_id;
	uint32_t i, n_subports = 0, count;

	port->pkts_out = pkts;
	port->n_pkts_out = 0;

	rte_sched_port_time_resync(port);

	/* Take each queue in the grinder one step further */
	for (i = 0, count = 0; ; i++)  {
		subport = port->subports[subport_id];

		count += grinder_handle(port, subport, i &
				(RTE_SCHED_PORT_N_GRINDERS - 1));
		if (count == n_pkts) {
			subport_id++;

			if (subport_id == port->n_subports_per_port)
				subport_id = 0;

			port->subport_id = subport_id;
			break;
		}

		if (rte_sched_port_exceptions(subport, i >= RTE_SCHED_PORT_N_GRINDERS)) {
			i = 0;
			subport_id++;
			n_subports++;
		}

		if (subport_id == port->n_subports_per_port)
			subport_id = 0;

		if (n_subports == port->n_subports_per_port) {
			port->subport_id = subport_id;
			break;
		}
	}

	return count;
}
