/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Siemens AG
 */

#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_ethdev.h>

#include "utils.h"
#include "l2reflect.h"

void
assert_link_status(int port_id)
{
	struct rte_eth_link link;
	uint8_t rep_cnt = MAX_REPEAT_TIMES;
	int link_get_err = -EINVAL;

	memset(&link, 0, sizeof(link));
	do {
		link_get_err = rte_eth_link_get_nowait(port_id, &link);
		if (link_get_err == 0 && link.link_status == RTE_ETH_LINK_UP)
			break;
		rte_delay_ms(CHECK_INTERVAL);
		RTE_LOG(INFO, L2REFLECT, "Link not ready yet, try again...\n");
	} while (--rep_cnt && (l2reflect_state != S_LOCAL_TERM));

	if (link_get_err < 0)
		rte_exit(EXIT_FAILURE, "error: link get is failing: %s\n",
			 rte_strerror(-link_get_err));
	if (link.link_status == RTE_ETH_LINK_DOWN)
		rte_exit(EXIT_FAILURE, "error: link is still down\n");

	const char *linkspeed_str = rte_eth_link_speed_to_str(link.link_speed);
	RTE_LOG(INFO, L2REFLECT,
		"Link status on port %d: speed: %s, duplex: %s\n",
		port_id, linkspeed_str,
		link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX ? "full" : "half");
}

uint32_t
eth_dev_get_overhead_len(uint32_t max_rx_pktlen, uint16_t max_mtu)
{
	uint32_t overhead_len;
	if (max_mtu != UINT16_MAX && max_rx_pktlen > max_mtu)
		overhead_len = max_rx_pktlen - max_mtu;
	else
		overhead_len = RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;
	return overhead_len;
}

int
config_port_max_pkt_len(struct rte_eth_conf *conf,
						struct rte_eth_dev_info *dev_info)
{
	uint32_t overhead_len;
	if (l2reflect_pkt_bytes < RTE_ETHER_MIN_LEN ||
		l2reflect_pkt_bytes > MAX_JUMBO_PKT_LEN)
		return -1;
	overhead_len = eth_dev_get_overhead_len(dev_info->max_rx_pktlen,
		dev_info->max_mtu);
	conf->rxmode.mtu = MAX(l2reflect_pkt_bytes - overhead_len,
			       dev_info->min_mtu);
	if (conf->rxmode.mtu > RTE_ETHER_MTU)
		conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
	return 0;
}
