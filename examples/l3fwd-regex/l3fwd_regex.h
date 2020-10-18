/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef __L3FWD_REGEX_H__
#define __L3FWD_REGEX_H__

#define REGEX_NB_OPS (8192)

int
regex_dev_init(uint32_t dev_id, uint16_t nb_queue_pairs);

int
regex_lcore_init(uint32_t lcore_id, uint32_t dev_id, uint32_t qp_id);

uint32_t
regex_enqueue_burst_ops(int dev_id, uint32_t lcore_id, uint16_t qp_id,
		struct rte_mbuf **pkts_burst, uint16_t nb_pkts);
uint32_t
regex_dequeue_burst_ops(int dev_id, uint32_t lcore_id, uint16_t qp_id,
		struct rte_mbuf **pkts_burst, uint16_t nb_pkts);
int
regex_read_rule_db_file(char *filename);
void
regex_debug_enable(void);
void
regex_drop_on_match(void);

void
regex_stats_print(uint32_t lcore);
void
regex_dev_uninit(uint32_t dev_id);
void
regex_lcore_uninit(uint32_t lcore_id);
void
regex_mem_free(void);

#endif /* __L3FWD_REGEX_H__ */
