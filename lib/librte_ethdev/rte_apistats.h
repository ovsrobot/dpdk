/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 NTT TechnoCross Corporation
 */

#ifndef _RTE_APISTATS_H_
#define _RTE_APISTATS_H_

/**
 * @file
 * RTE apistats
 *
 * library to provide rte_rx_burst/tx_burst api stats.
 */


#ifdef __cplusplus
extern "C" {
#endif

#include <rte_compat.h>
#include <rte_lcore.h>

/**
 * A structure for rte_rx_burst/tx_burst api statistics.
 */
struct rte_apistats {
	int lcoreid_list[RTE_MAX_LCORE];        /**< In use lcoreid list */
	/**< Total rte_rx_burst call counts */
	uint64_t rx_burst_counts[RTE_MAX_LCORE];

	/**< Total rte_tx_burst call counts */
	uint64_t tx_burst_counts[RTE_MAX_LCORE];
};

extern struct rte_apistats *rte_apicounts;

/**
 *  Initialize rte_rx_burst/tx_burst call count area.
 *  @b EXPERIMENTAL: this API may change without prior notice.
 *
 *  @return
 *   -1     : On error
 *   -ENOMEM: On error
 *    0     : On success
 */
__rte_experimental
int rte_apistats_init(void);

/**
 *  Clean up and free memory.
 *  @b EXPERIMENTAL: this API may change without prior notice.
 *
 *  @return
 *   -1: On error
 *    0: On success
 */
__rte_experimental
int rte_apistats_uninit(void);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_APISTATS_H_ */
