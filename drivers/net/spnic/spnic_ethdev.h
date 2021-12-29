/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_ETHDEV_H_
#define _SPNIC_ETHDEV_H_

#define SPNIC_COPY_MEMPOOL_DEPTH	128
#define SPNIC_COPY_MBUF_SIZE		4096
#define SPNIC_DEV_NAME_LEN		32

#define SPNIC_UINT32_BIT_SIZE		(CHAR_BIT * sizeof(uint32_t))
#define SPNIC_VFTA_SIZE			(4096 / SPNIC_UINT32_BIT_SIZE)
#define SPNIC_MAX_QUEUE_NUM		64

enum spnic_dev_status {
	SPNIC_DEV_INIT,
	SPNIC_DEV_CLOSE,
	SPNIC_DEV_START,
	SPNIC_DEV_INTR_EN
};

enum spnic_tx_cvlan_type {
	SPNIC_TX_TPID0,
};

enum nic_feature_cap {
	NIC_F_CSUM = BIT(0),
	NIC_F_SCTP_CRC = BIT(1),
	NIC_F_TSO = BIT(2),
	NIC_F_LRO = BIT(3),
	NIC_F_UFO = BIT(4),
	NIC_F_RSS = BIT(5),
	NIC_F_RX_VLAN_FILTER = BIT(6),
	NIC_F_RX_VLAN_STRIP = BIT(7),
	NIC_F_TX_VLAN_INSERT = BIT(8),
	NIC_F_VXLAN_OFFLOAD = BIT(9),
	NIC_F_IPSEC_OFFLOAD = BIT(10),
	NIC_F_FDIR = BIT(11),
	NIC_F_PROMISC = BIT(12),
	NIC_F_ALLMULTI = BIT(13),
};

#define DEFAULT_DRV_FEATURE		0x3FFF

struct spnic_nic_dev {
	struct spnic_hwdev *hwdev; /* Hardware device */

	struct spnic_txq **txqs;
	struct spnic_rxq **rxqs;
	struct rte_mempool *cpy_mpool;

	u16 num_sqs;
	u16 num_rqs;
	u16 max_sqs;
	u16 max_rqs;

	u16 rx_buff_len;
	u16 mtu_size;

	u16 rss_state;
	u8 num_rss;
	u8 rsvd0;

	u32 rx_mode;
	u8 rx_queue_list[SPNIC_MAX_QUEUE_NUM];
	rte_spinlock_t queue_list_lock;
	pthread_mutex_t rx_mode_mutex;

	u32 default_cos;
	u32 rx_csum_en;

	u8 rss_key[SPNIC_RSS_KEY_SIZE];

	u32 dev_status;

	bool pause_set;
	pthread_mutex_t pause_mutuex;

	struct rte_ether_addr default_addr;
	struct rte_ether_addr *mc_list;

	char dev_name[SPNIC_DEV_NAME_LEN];
	u64 feature_cap;
	u32 vfta[SPNIC_VFTA_SIZE]; /* VLAN bitmap */
};

#define SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev) \
	((struct spnic_nic_dev *)(dev)->data->dev_private)

#endif /* _SPNIC_ETHDEV_H_ */
