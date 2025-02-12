/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */

#ifndef _RNP_LINK_H_
#define _RNP_LINK_H_

#define RNP_DEVICE_LINK		(0x3000c)
#define RNP_DEVICE_LINK_EX	(0xa800 + 64 * 64 - 4)
#define RNP_LINK_NOCHANGED(lane_bit, change_lane) \
	(!((RTE_BIT32(lane_bit)) & (change_lane)))
#define RNP_LINK_DUPLEX_ATTR_EN		(0xA0000000)
#define RNP_SPEED_META_VALID(magic)	(!!(magic) == 0xA0000000)
#define RNP_LINK_STATE(n)		RTE_BIT32(n)
#define RNP_LINK_SPEED_CODE(sp, n) \
	(((sp) & RTE_GENMASK32((11) + ((4) * (n)), \
		(8) + ((4) * (n)))) >> (8 + 4 * (n)))
#define RNP_LINK_DUPLEX_STATE(sp, n)	((sp) & RTE_BIT32((24) + (n)))
#define RNP_ALARM_INTERVAL	(50000) /* unit us */
enum rnp_lane_speed {
	RNP_LANE_SPEED_10M = 0,
	RNP_LANE_SPEED_100M,
	RNP_LANE_SPEED_1G,
	RNP_LANE_SPEED_10G,
	RNP_LANE_SPEED_25G,
	RNP_LANE_SPEED_40G,
};

void rnp_link_event(struct rnp_eth_adapter *adapter,
		    struct rnp_mbx_fw_cmd_req *req);
int rnp_dev_link_update(struct rte_eth_dev *eth_dev,
			int wait_to_complete);
void rnp_run_link_poll_task(struct rnp_eth_port *port);
void rnp_cancel_link_poll_task(struct rnp_eth_port *port);

#endif /* _RNP_LINK_H_ */
