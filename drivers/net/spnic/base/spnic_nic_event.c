/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <ethdev_driver.h>

#include "spnic_compat.h"
#include "spnic_cmd.h"
#include "spnic_hwif.h"
#include "spnic_hwdev.h"
#include "spnic_mgmt.h"
#include "spnic_nic_cfg.h"
#include "spnic_hwdev.h"
#include "spnic_nic_event.h"

void get_port_info(struct spnic_hwdev *hwdev, u8 link_state,
		   struct rte_eth_link *link)
{
	uint32_t port_speed[LINK_SPEED_LEVELS] = {ETH_SPEED_NUM_10M,
					ETH_SPEED_NUM_100M, ETH_SPEED_NUM_1G,
					ETH_SPEED_NUM_10G, ETH_SPEED_NUM_25G,
					ETH_SPEED_NUM_40G, ETH_SPEED_NUM_100G};
	struct nic_port_info port_info = {0};
	int err;

	if (!link_state) {
		link->link_status = ETH_LINK_DOWN;
		link->link_speed = ETH_SPEED_NUM_NONE;
		link->link_duplex = ETH_LINK_HALF_DUPLEX;
		link->link_autoneg = ETH_LINK_FIXED;
	} else {
		link->link_status = ETH_LINK_UP;

		err = spnic_get_port_info(hwdev, &port_info);
		if (err) {
			link->link_speed = ETH_SPEED_NUM_NONE;
			link->link_duplex = ETH_LINK_FULL_DUPLEX;
			link->link_autoneg = ETH_LINK_FIXED;
		} else {
			link->link_speed = port_speed[port_info.speed %
						LINK_SPEED_LEVELS];
			link->link_duplex = port_info.duplex;
			link->link_autoneg = port_info.autoneg_state;
		}
	}
}

static void spnic_link_event_stats(void *dev, u8 link)
{
	struct spnic_hwdev *hwdev = dev;
	struct link_event_stats *stats = &hwdev->hw_stats.link_event_stats;

	if (link)
		__atomic_fetch_add(&stats->link_up_stats, 1, __ATOMIC_RELAXED);
	else
		__atomic_fetch_add(&stats->link_down_stats, 1, __ATOMIC_RELAXED);
}

static void link_status_event_handler(void *hwdev, void *buf_in,
				      __rte_unused u16 in_size,
				      __rte_unused void *buf_out,
				      __rte_unused u16 *out_size)
{
	struct spnic_cmd_link_state *link_status = NULL;
	struct rte_eth_link link;
	struct spnic_hwdev *dev = hwdev;
	int err;

	link_status = buf_in;
	PMD_DRV_LOG(INFO, "Link status report received, func_id: %d, status: %d(%s)",
		    spnic_global_func_id(hwdev), link_status->state,
		    link_status->state ? "UP" : "DOWN");

	spnic_link_event_stats(hwdev, link_status->state);

	/* Link event reported only after set vport enable */
	get_port_info(dev, link_status->state, &link);
	err = rte_eth_linkstatus_set((struct rte_eth_dev *)(dev->eth_dev),
				     &link);
	if (!err)
		rte_eth_dev_callback_process(dev->eth_dev,
					      RTE_ETH_EVENT_INTR_LSC, NULL);
}

struct nic_event_handler {
	u16 cmd;
	void (*handler)(void *hwdev, void *buf_in, u16 in_size,
			void *buf_out, u16 *out_size);
};

struct nic_event_handler nic_cmd_handler[] = {
};

static void nic_event_handler(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
			      void *buf_out, u16 *out_size)
{
	u32 i, size = ARRAY_LEN(nic_cmd_handler);

	if (!hwdev)
		return;

	*out_size = 0;

	for (i = 0; i < size; i++) {
		if (cmd == nic_cmd_handler[i].cmd) {
			nic_cmd_handler[i].handler(hwdev, buf_in, in_size,
						   buf_out, out_size);
			break;
		}
	}

	if (i == size)
		PMD_DRV_LOG(WARNING,
			    "Unsupported nic event cmd(%d) to process", cmd);
}

/*
 * VF handler mbox msg from ppf/pf
 * VF link change event
 * VF fault report event
 */
int spnic_vf_event_handler(void *hwdev, __rte_unused void *pri_handle,
			   u16 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size)
{
	nic_event_handler(hwdev, cmd, buf_in, in_size, buf_out, out_size);
	return 0;
}

/*  NIC event of PF/PPF handler reported by mgmt cpu */
void spnic_pf_event_handler(void *hwdev, __rte_unused void *pri_handle,
			    u16 cmd, void *buf_in, u16 in_size,
			    void *buf_out, u16 *out_size)
{
	nic_event_handler(hwdev, cmd, buf_in, in_size, buf_out, out_size);
}

static struct nic_event_handler mag_cmd_handler[] = {
	{
		.cmd = MAG_CMD_GET_LINK_STATUS,
		.handler = link_status_event_handler,
	},
};

static int spnic_mag_event_handler(void *hwdev, u16 cmd, void *buf_in,
				   u16 in_size, void *buf_out,
				   u16 *out_size)
{
	u32 size = ARRAY_LEN(mag_cmd_handler);
	u32 i;

	if (!hwdev)
		return -EINVAL;

	*out_size = 0;
	for (i = 0; i < size; i++) {
		if (cmd == mag_cmd_handler[i].cmd) {
			mag_cmd_handler[i].handler(hwdev, buf_in, in_size,
						   buf_out, out_size);
			break;
		}
	}

	/* can't find this event cmd */
	if (i == size)
		PMD_DRV_LOG(ERR, "Unsupported mag event, cmd: %u\n", cmd);

	return 0;
}

int spnic_vf_mag_event_handler(void *hwdev, void *pri_handle, u16 cmd,
			       void *buf_in, u16 in_size, void *buf_out,
			       u16 *out_size)
{
	return spnic_mag_event_handler(hwdev, cmd, buf_in, in_size, buf_out,
				       out_size);
}

/* pf/ppf handler mgmt cpu report hilink event*/
void spnic_pf_mag_event_handler(void *hwdev, void *pri_handle, u16 cmd,
				void *buf_in, u16 in_size, void *buf_out,
				u16 *out_size)
{
	spnic_mag_event_handler(hwdev, cmd, buf_in, in_size, buf_out, out_size);
}

u8 spnic_nic_sw_aeqe_handler(__rte_unused void *hwdev, u8 event, u8 *data)
{
	PMD_DRV_LOG(ERR,
		    "Received nic ucode aeq event type: 0x%x, data: %"PRIu64"",
		    event, *((u64 *)data));

	return 0;
}
