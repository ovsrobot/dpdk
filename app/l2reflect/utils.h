/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Siemens AG
 */

#ifndef _L2REFLECT_UTILS_H_
#define _L2REFLECT_UTILS_H_

#define MAX_REPEAT_TIMES 30
#define CHECK_INTERVAL 2000

void assert_link_status(int port_id);

uint32_t
eth_dev_get_overhead_len(uint32_t max_rx_pktlen, uint16_t max_mtu);

int
config_port_max_pkt_len(struct rte_eth_conf *conf,
			struct rte_eth_dev_info *dev_info);

#endif /* _L2REFLECT_UTILS_H_ */
