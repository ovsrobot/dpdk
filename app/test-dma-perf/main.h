/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#ifndef _MAIN_H_
#define _MAIN_H_


#include <rte_common.h>
#include <rte_cycles.h>

#define MAX_WORKER_NB 128
#define MAX_OUTPUT_STR_LEN 512

#define RTE_LOGTYPE_DMA RTE_LOGTYPE_USER1

extern char output_str[MAX_WORKER_NB][MAX_OUTPUT_STR_LEN];

typedef enum {
	OP_NONE = 0,
	OP_ADD,
	OP_MUL
} alg_op_type;

struct test_configure_entry {
	uint32_t first;
	uint32_t last;
	uint32_t incr;
	alg_op_type op;
	uint32_t cur;
};

struct test_configure {
	uint8_t test_type;
	const char *test_type_str;
	uint16_t src_numa_node;
	uint16_t dst_numa_node;
	uint16_t opcode;
	bool is_dma;
	struct test_configure_entry mem_size;
	struct test_configure_entry buf_size;
	struct test_configure_entry ring_size;
	struct test_configure_entry kick_batch;
	uint32_t cache_flush;
	uint32_t nr_buf;
	uint32_t repeat_times;
	uint32_t nb_workers;
	uint16_t mpool_iter_step;
	const char *eal_args;
	uint8_t scenario_id;
};

#endif /* _MAIN_H_ */
