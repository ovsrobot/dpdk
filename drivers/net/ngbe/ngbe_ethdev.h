/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020 Beijing WangXun Technology Co., Ltd.
 * Copyright(c) 2010-2017 Intel Corporation
 */

#ifndef _NGBE_ETHDEV_H_
#define _NGBE_ETHDEV_H_

/* need update link, bit flag */
#define NGBE_FLAG_NEED_LINK_UPDATE (uint32_t)(1 << 0)
#define NGBE_FLAG_MAILBOX          (uint32_t)(1 << 1)
#define NGBE_FLAG_PHY_INTERRUPT    (uint32_t)(1 << 2)
#define NGBE_FLAG_MACSEC           (uint32_t)(1 << 3)
#define NGBE_FLAG_NEED_LINK_CONFIG (uint32_t)(1 << 4)

#define NGBE_HKEY_MAX_INDEX 10

#define NGBE_RSS_OFFLOAD_ALL ( \
	ETH_RSS_IPV4 | \
	ETH_RSS_NONFRAG_IPV4_TCP | \
	ETH_RSS_NONFRAG_IPV4_UDP | \
	ETH_RSS_IPV6 | \
	ETH_RSS_NONFRAG_IPV6_TCP | \
	ETH_RSS_NONFRAG_IPV6_UDP | \
	ETH_RSS_IPV6_EX | \
	ETH_RSS_IPV6_TCP_EX | \
	ETH_RSS_IPV6_UDP_EX)

#define NGBE_MISC_VEC_ID               RTE_INTR_VEC_ZERO_OFFSET

/* structure for interrupt relative data */
struct ngbe_interrupt {
	uint32_t flags;
	uint32_t mask_misc;
	uint32_t mask_misc_orig; /* save mask during delayed handler */
	uint64_t mask;
	uint64_t mask_orig; /* save mask during delayed handler */
};

/*
 * Structure to store private data for each driver instance (for each port).
 */
struct ngbe_adapter {
	struct ngbe_hw             hw;
	struct ngbe_interrupt      intr;
	bool rx_bulk_alloc_allowed;
};

#define NGBE_DEV_ADAPTER(dev) \
	((struct ngbe_adapter *)(dev)->data->dev_private)

#define NGBE_DEV_HW(dev) \
	(&((struct ngbe_adapter *)(dev)->data->dev_private)->hw)

#define NGBE_DEV_INTR(dev) \
	(&((struct ngbe_adapter *)(dev)->data->dev_private)->intr)

void ngbe_dev_rx_queue_release(void *rxq);

void ngbe_dev_tx_queue_release(void *txq);

int  ngbe_dev_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
		uint16_t nb_rx_desc, unsigned int socket_id,
		const struct rte_eth_rxconf *rx_conf,
		struct rte_mempool *mb_pool);

int  ngbe_dev_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
		uint16_t nb_tx_desc, unsigned int socket_id,
		const struct rte_eth_txconf *tx_conf);

int
ngbe_dev_link_update_share(struct rte_eth_dev *dev,
		int wait_to_complete);

#define NGBE_LINK_DOWN_CHECK_TIMEOUT 4000 /* ms */
#define NGBE_LINK_UP_CHECK_TIMEOUT   1000 /* ms */
#define NGBE_VMDQ_NUM_UC_MAC         4096 /* Maximum nb. of UC MAC addr. */

/*
 *  Default values for RX/TX configuration
 */
#define NGBE_DEFAULT_RX_FREE_THRESH  32
#define NGBE_DEFAULT_RX_PTHRESH      8
#define NGBE_DEFAULT_RX_HTHRESH      8
#define NGBE_DEFAULT_RX_WTHRESH      0

#define NGBE_DEFAULT_TX_FREE_THRESH  32
#define NGBE_DEFAULT_TX_PTHRESH      32
#define NGBE_DEFAULT_TX_HTHRESH      0
#define NGBE_DEFAULT_TX_WTHRESH      0

#endif /* _NGBE_ETHDEV_H_ */
