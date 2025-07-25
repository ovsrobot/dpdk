/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV

#include <rte_byteorder.h>
#include <rte_mbuf_core.h>
#include <rte_ethdev.h>
#include "sxevf_rx.h"
#include "sxevf_tx.h"
#include "sxe_logs.h"
#include "sxevf.h"
#include "sxe_queue_common.h"
#include "sxevf_hw.h"
#include "sxe_offload.h"
#include "sxe_ethdev.h"
#include "sxevf_queue.h"
#include "sxevf_msg.h"

s32 __rte_cold sxevf_rx_queue_mbufs_alloc(sxevf_rx_queue_s *rxq)
{
	s32 ret;

	ret = __sxe_rx_queue_mbufs_alloc((sxevf_rx_queue_s *)rxq);

	return ret;
}

s32 __rte_cold sxevf_rx_queue_setup(struct rte_eth_dev *dev,
			 u16 queue_idx, u16 desc_num,
			 unsigned int socket_id,
			 const struct rte_eth_rxconf *rx_conf,
			 struct rte_mempool *mp)
{
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw	 *hw = &adapter->hw;
	struct rx_setup rx_setup = {};
	s32 ret;

	PMD_INIT_FUNC_TRACE();

	rx_setup.desc_num = desc_num;
	rx_setup.queue_idx = queue_idx;
	rx_setup.socket_id = socket_id;
	rx_setup.mp = mp;
	rx_setup.dev = dev;
	rx_setup.reg_base_addr = hw->reg_base_addr;
	rx_setup.rx_conf = rx_conf;
	rx_setup.rx_batch_alloc_allowed = &adapter->rx_batch_alloc_allowed;

	ret = __sxe_rx_queue_setup(&rx_setup, true);
	if (ret)
		LOG_ERROR_BDF("rx queue setup fail.(err:%d)", ret);

	return ret;
}

s32 __rte_cold sxevf_tx_queue_setup(struct rte_eth_dev *dev,
				u16 tx_queue_id,
				u16 ring_depth,
				u32 socket_id,
				const struct rte_eth_txconf *tx_conf)
{
	s32 ret;
	struct sxevf_hw *hw = (&((struct sxevf_adapter *)(dev->data->dev_private))->hw);
	struct tx_setup tx_setup;

	tx_setup.dev = dev;
	tx_setup.desc_num = ring_depth;
	tx_setup.queue_idx = tx_queue_id;
	tx_setup.socket_id = socket_id;
	tx_setup.reg_base_addr = hw->reg_base_addr;
	tx_setup.tx_conf = tx_conf;

	ret = __sxe_tx_queue_setup(&tx_setup, true);
	if (ret)
		PMD_LOG_ERR(DRV, "rx queue setup fail.(err:%d)", ret);

	return ret;
}

void __rte_cold
sxevf_rx_queue_release(struct rte_eth_dev *dev, u16 queue_id)
{
	__sxe_rx_queue_free(dev->data->rx_queues[queue_id]);
}

void __rte_cold
sxevf_tx_queue_release(struct rte_eth_dev *dev, u16 queue_id)
{
	__sxe_tx_queue_free(dev->data->tx_queues[queue_id]);
}

void sxevf_rx_queue_info_get(struct rte_eth_dev *dev, u16 queue_id,
	struct rte_eth_rxq_info *qinfo)
{
	__sxe_rx_queue_info_get(dev, queue_id, qinfo);
}

void sxevf_tx_queue_info_get(struct rte_eth_dev *dev, u16 queue_id,
		struct rte_eth_txq_info *q_info)
{
	__sxe_tx_queue_info_get(dev, queue_id, q_info);
}

s32 sxevf_tx_done_cleanup(void *tx_queue, u32 free_cnt)
{
	s32 ret;

	/* Tx queue cleanup */
	ret = __sxe_tx_done_cleanup(tx_queue, free_cnt);
	if (ret)
		PMD_LOG_ERR(DRV, "tx cleanup fail.(err:%d)", ret);

	return ret;
}

s32 sxevf_rss_reta_update(struct rte_eth_dev *dev,
			struct rte_eth_rss_reta_entry64 *reta_conf,
			u16 reta_size)
{
	s32 ret = -ENOTSUP;

	PMD_INIT_FUNC_TRACE();

	RTE_SET_USED(reta_conf);
	RTE_SET_USED(reta_size);

	if (!dev->data->dev_started) {
		PMD_LOG_ERR(DRV,
			"port %d must be started before rss reta update",
			 dev->data->port_id);
		ret = -EIO;
		goto l_out;
	}

	PMD_LOG_ERR(DRV, "rss reta update is not supported on vf.(err:%d)", ret);

l_out:
	return ret;
}

s32 sxevf_rss_reta_query(struct rte_eth_dev *dev,
			 struct rte_eth_rss_reta_entry64 *reta_conf,
			 u16 reta_size)
{
	s32 ret = 0;

	RTE_SET_USED(dev);
	RTE_SET_USED(reta_conf);

	if (reta_size != 0) {
		ret = -EINVAL;
		PMD_LOG_ERR(DRV, "vf rss reta size:0, not support query.(err:%d)", ret);
	}

	return ret;
}

s32 sxevf_rss_hash_conf_get(struct rte_eth_dev *dev,
				struct rte_eth_rss_conf *rss_conf)
{
	s32 ret = 0;
	struct sxevf_adapter *adapter = dev->data->dev_private;

	ret = sxevf_rss_hash_config_get(adapter, rss_conf);
	if (ret) {
		LOG_ERROR_BDF("rss hash config get failed.(err:%d)", ret);
		goto l_out;
	}

l_out:
	return ret;
}

s32 sxevf_rss_hash_update(struct rte_eth_dev *dev,
			struct rte_eth_rss_conf *rss_conf)
{
	s32 ret = -ENOTSUP;

	RTE_SET_USED(dev);
	RTE_SET_USED(rss_conf);

	PMD_LOG_ERR(DRV, "rss hash update is not supported on vf.(err:%d)", ret);

	return ret;
}

void sxevf_secondary_proc_init(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	bool rx_vec_allowed = 0;

	__sxe_secondary_proc_init(eth_dev, adapter->rx_batch_alloc_allowed, &rx_vec_allowed);
}

void __rte_cold sxevf_txrx_queues_clear(struct rte_eth_dev *dev, bool rx_batch_alloc_allowed)
{
	__sxe_txrx_queues_clear(dev, rx_batch_alloc_allowed);
}

void sxevf_queues_free(struct rte_eth_dev *dev)
{
	__sxe_queues_free(dev);
}

#endif
