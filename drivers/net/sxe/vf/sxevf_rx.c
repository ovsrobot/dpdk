/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV

#include <rte_common.h>
#include <ethdev_driver.h>

#include "sxe_logs.h"
#include "sxe_errno.h"
#include "sxevf.h"
#include "sxevf_msg.h"
#include "sxevf_rx.h"
#include "sxe_rx_common.h"
#include "sxevf_queue.h"
#include "sxevf_rx.h"
#include "sxe_ethdev.h"

#define SXEVF_RX_HDR_SIZE  256

static void sxevf_rss_bit_num_configure(struct sxevf_hw *hw, u16 rx_queues_num)
{
	u32 psrtype;

	psrtype = (rx_queues_num >> 1) << SXEVF_PSRTYPE_RQPL_SHIFT;

	sxevf_rss_bit_num_set(hw, psrtype);
}

static void sxevf_rxmode_offload_configure(struct rte_eth_dev *eth_dev,
						u64 queue_offload, u32 buf_size)
{
	struct rte_eth_rxmode *rxmode = &eth_dev->data->dev_conf.rxmode;
	u32 frame_size = SXE_GET_FRAME_SIZE(eth_dev);

	if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_SCATTER ||
		((frame_size + 2 * SXEVF_VLAN_TAG_SIZE) > buf_size)) {
		if (!eth_dev->data->scattered_rx) {
			PMD_LOG_WARN(DRV, "rxmode offload:0x%" SXE_PRIX64 " max_rx_pkt_len:%u "
					"buf_size:%u enable rx scatter",
					rxmode->offloads,
					frame_size,
					buf_size);
		}
		eth_dev->data->scattered_rx = 1;
	}

	if (queue_offload & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
		rxmode->offloads |= RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
}

static s32 sxevf_rx_queue_configure(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	sxevf_rx_queue_s *rxq;
	struct rte_eth_rxmode *rxmode = &eth_dev->data->dev_conf.rxmode;
	s32 ret;
	u16 i;
	u32 len;
	u32 buf_size;

	rxmode->offloads &= ~RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		rxq = eth_dev->data->rx_queues[i];
		len = rxq->ring_depth * sizeof(sxevf_rx_data_desc_u);

		ret = sxevf_rx_queue_mbufs_alloc(rxq);
		if (ret) {
			LOG_ERROR_BDF("rx queue num:%u queue id:%u alloc "
					  "rx buffer fail.(err:%d)",
					  eth_dev->data->nb_rx_queues, i, ret);
			goto l_out;
		}

		buf_size = (u16)(rte_pktmbuf_data_room_size(rxq->mb_pool) -
			RTE_PKTMBUF_HEADROOM);

		sxevf_rx_ring_desc_configure(hw, len, rxq->base_addr, rxq->reg_idx);

		sxevf_rx_rcv_ctl_configure(hw, rxq->reg_idx, SXEVF_RX_HDR_SIZE,
					   buf_size, rxq->drop_en);

		sxevf_rxmode_offload_configure(eth_dev, rxq->offloads, buf_size);
	}

	sxevf_rss_bit_num_configure(hw, eth_dev->data->nb_rx_queues);

	sxevf_rx_function_set(eth_dev);

l_out:
	return ret;
}

s32 sxevf_rx_configure(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	u32 frame_size = SXE_GET_FRAME_SIZE(eth_dev);
	u32 mtu = frame_size - SXE_ETH_OVERHEAD;
	s32 ret;

	if (rte_is_power_of_2(eth_dev->data->nb_rx_queues) == 0) {
		ret = -SXEVF_ERR_PARAM;
		LOG_ERROR_BDF("invalid rx queue num:%u.",
			 eth_dev->data->nb_rx_queues);
		goto l_out;
	}

	if (eth_dev->data->nb_rx_queues > adapter->max_rx_queue) {
		ret = -SXEVF_ERR_PARAM;
		LOG_ERROR_BDF("invalid rx queue num:%u exceed max rx queue:%u ",
			eth_dev->data->nb_rx_queues,
			adapter->max_rx_queue);
		goto l_out;
	}

	ret = sxevf_rx_max_frame_set(hw, mtu);
	if (ret) {
		LOG_ERROR_BDF("max frame size:%u set fail.(err:%d)",
				  frame_size, ret);
		goto l_out;
	}

	ret = sxevf_rx_queue_configure(eth_dev);
	if (ret) {
		LOG_ERROR_BDF("rx queue num:%u configure fail.(err:%u)",
				  eth_dev->data->nb_rx_queues, ret);
	}

l_out:
	return ret;
}

void __rte_cold sxevf_rx_function_set(struct rte_eth_dev *dev)
{
	struct sxevf_adapter *adapter = dev->data->dev_private;

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	__sxe_rx_function_set(dev, adapter->rx_batch_alloc_allowed, &adapter->rx_vec_allowed);
#else
	__sxe_rx_function_set(dev, adapter->rx_batch_alloc_allowed, NULL);
#endif
}

s32 sxevf_rx_descriptor_status(void *rx_queue, u16 offset)
{
	return __sxe_rx_descriptor_status(rx_queue, offset);
}

u16 sxevf_pkts_recv(void *rx_queue, struct rte_mbuf **rx_pkts, u16 num_pkts)
{
	return __sxe_pkts_recv(rx_queue, rx_pkts, num_pkts);
}

const u32 *sxevf_dev_supported_ptypes_get(struct rte_eth_dev *dev, size_t *no_of_elements)
{
	return __sxe_dev_supported_ptypes_get(dev, no_of_elements);
}

#endif
