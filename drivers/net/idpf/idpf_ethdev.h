/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#ifndef _IDPF_ETHDEV_H_
#define _IDPF_ETHDEV_H_

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>
#include <rte_ethdev.h>
#include <rte_kvargs.h>
#include <ethdev_driver.h>

#include "base/iecm_osdep.h"
#include "base/iecm_type.h"
#include "base/iecm_devids.h"
#include "base/iecm_lan_txrx.h"
#include "base/iecm_lan_pf_regs.h"
#include "base/virtchnl.h"
#include "base/virtchnl2.h"

#define IDPF_INVALID_VPORT_IDX	0xffff
#define IDPF_TXQ_PER_GRP	1
#define IDPF_TX_COMPLQ_PER_GRP	1
#define IDPF_RXQ_PER_GRP	1
#define IDPF_RX_BUFQ_PER_GRP	2

#define IDPF_CTLQ_ID		-1
#define IDPF_CTLQ_LEN		64
#define IDPF_DFLT_MBX_BUF_SIZE	4096

#define IDPF_DFLT_Q_VEC_NUM	1
#define IDPF_DFLT_INTERVAL	16

#define IDPF_MAX_NUM_QUEUES	256
#define IDPF_MIN_BUF_SIZE	1024
#define IDPF_MAX_FRAME_SIZE	9728

#define IDPF_NUM_MACADDR_MAX	64

#define IDPF_MAX_PKT_TYPE	1024

#define IDPF_VLAN_TAG_SIZE	4
#define IDPF_ETH_OVERHEAD \
	(RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + IDPF_VLAN_TAG_SIZE * 2)

#define IDPF_RSS_OFFLOAD_ALL ( \
	RTE_ETH_RSS_IPV4		| \
	RTE_ETH_RSS_FRAG_IPV4		| \
	RTE_ETH_RSS_NONFRAG_IPV4_TCP	| \
	RTE_ETH_RSS_NONFRAG_IPV4_UDP	| \
	RTE_ETH_RSS_NONFRAG_IPV4_SCTP	| \
	RTE_ETH_RSS_NONFRAG_IPV4_OTHER	| \
	RTE_ETH_RSS_IPV6		| \
	RTE_ETH_RSS_FRAG_IPV6		| \
	RTE_ETH_RSS_NONFRAG_IPV6_TCP	| \
	RTE_ETH_RSS_NONFRAG_IPV6_UDP	| \
	RTE_ETH_RSS_NONFRAG_IPV6_SCTP	| \
	RTE_ETH_RSS_NONFRAG_IPV6_OTHER)

#ifndef ETH_ADDR_LEN
#define ETH_ADDR_LEN		6
#endif

/* Message type read in virtual channel from PF */
enum idpf_vc_result {
	IDPF_MSG_ERR = -1, /* Meet error when accessing admin queue */
	IDPF_MSG_NON,      /* Read nothing from admin queue */
	IDPF_MSG_SYS,      /* Read system msg from admin queue */
	IDPF_MSG_CMD,      /* Read async command result */
};

struct idpf_chunks_info {
	uint32_t tx_start_qid;
	uint32_t rx_start_qid;
	/* Valid only if split queue model */
	uint32_t tx_compl_start_qid;
	uint32_t rx_buf_start_qid;

	uint64_t tx_qtail_start;
	uint32_t tx_qtail_spacing;
	uint64_t rx_qtail_start;
	uint32_t rx_qtail_spacing;
	uint64_t tx_compl_qtail_start;
	uint32_t tx_compl_qtail_spacing;
	uint64_t rx_buf_qtail_start;
	uint32_t rx_buf_qtail_spacing;
};

struct idpf_vport {
	struct idpf_adapter *adapter; /* Backreference to associated adapter */
	uint16_t vport_id;
	uint32_t txq_model;
	uint32_t rxq_model;
	uint16_t num_tx_q;
	/* valid only if txq_model is split Q */
	uint16_t num_tx_complq;
	uint16_t num_rx_q;
	/* valid only if rxq_model is split Q */
	uint16_t num_rx_bufq;

	uint16_t max_mtu;
	uint8_t default_mac_addr[VIRTCHNL_ETH_LENGTH_OF_ADDRESS];

	enum virtchnl_rss_algorithm rss_algorithm;
	uint16_t rss_key_size;
	uint16_t rss_lut_size;

	uint16_t sw_idx; /* SW idx */

	struct rte_eth_dev_data *dev_data; /* Pointer to the device data */
	uint16_t max_pkt_len; /* Maximum packet length */

	/* RSS info */
	uint32_t *rss_lut;
	uint8_t *rss_key;
	uint64_t rss_hf;

	/* Chunk info */
	struct idpf_chunks_info chunks_info;

	/* Event from ipf */
	bool link_up;
	uint32_t link_speed;

	bool stopped;
	struct virtchnl2_vport_stats eth_stats_offset;
};

struct idpf_adapter {
	struct iecm_hw hw;

	struct virtchnl_version_info virtchnl_version;
	struct virtchnl2_get_capabilities *caps;

	volatile enum virtchnl_ops pend_cmd; /* pending command not finished */
	uint32_t cmd_retval; /* return value of the cmd response from ipf */
	uint8_t *mbx_resp; /* buffer to store the mailbox response from ipf */

	uint32_t txq_model;
	uint32_t rxq_model;

	/* Vport info */
	uint8_t **vport_req_info;
	uint8_t **vport_recv_info;
	struct idpf_vport **vports;
	uint16_t max_vport_nb;
	uint16_t cur_vport_nb;
	uint16_t next_vport_idx;

	/* Max config queue number per VC message */
	uint32_t max_rxq_per_msg;
	uint32_t max_txq_per_msg;

	uint32_t ptype_tbl[IDPF_MAX_PKT_TYPE] __rte_cache_min_aligned;

	bool initialized;
	bool stopped;
};

extern struct idpf_adapter *adapter;

#define IDPF_DEV_TO_PCI(eth_dev)		\
	RTE_DEV_TO_PCI((eth_dev)->device)

/* structure used for sending and checking response of virtchnl ops */
struct idpf_cmd_info {
	uint32_t ops;
	uint8_t *in_args;       /* buffer for sending */
	uint32_t in_args_size;  /* buffer size for sending */
	uint8_t *out_buffer;    /* buffer for response */
	uint32_t out_size;      /* buffer size for response */
};

/* notify current command done. Only call in case execute
 * _atomic_set_cmd successfully.
 */
static inline void
_notify_cmd(struct idpf_adapter *adapter, int msg_ret)
{
	adapter->cmd_retval = msg_ret;
	rte_wmb();
	adapter->pend_cmd = VIRTCHNL_OP_UNKNOWN;
}

/* clear current command. Only call in case execute
 * _atomic_set_cmd successfully.
 */
static inline void
_clear_cmd(struct idpf_adapter *adapter)
{
	rte_wmb();
	adapter->pend_cmd = VIRTCHNL_OP_UNKNOWN;
	adapter->cmd_retval = VIRTCHNL_STATUS_SUCCESS;
}

/* Check there is pending cmd in execution. If none, set new command. */
static inline int
_atomic_set_cmd(struct idpf_adapter *adapter, enum virtchnl_ops ops)
{
	int ret = rte_atomic32_cmpset(&adapter->pend_cmd, VIRTCHNL_OP_UNKNOWN, ops);

	if (!ret)
		PMD_DRV_LOG(ERR, "There is incomplete cmd %d", adapter->pend_cmd);

	return !ret;
}

int idpf_dev_link_update(struct rte_eth_dev *dev,
			 __rte_unused int wait_to_complete);
void idpf_handle_virtchnl_msg(struct rte_eth_dev *dev);
int idpf_check_api_version(struct idpf_adapter *adapter);
int idpf_get_caps(struct idpf_adapter *adapter);
int idpf_create_vport(__rte_unused struct rte_eth_dev *dev);
int idpf_destroy_vport(struct idpf_vport *vport);
int idpf_set_rss_key(struct idpf_vport *vport);
int idpf_set_rss_lut(struct idpf_vport *vport);
int idpf_set_rss_hash(struct idpf_vport *vport);
int idpf_config_rxqs(struct idpf_vport *vport);
int idpf_config_rxq(struct idpf_vport *vport, uint16_t rxq_id);
int idpf_config_txqs(struct idpf_vport *vport);
int idpf_config_txq(struct idpf_vport *vport, uint16_t txq_id);
int idpf_switch_queue(struct idpf_vport *vport, uint16_t qid,
		      bool rx, bool on);
int idpf_ena_dis_queues(struct idpf_vport *vport, bool enable);
int idpf_ena_dis_vport(struct idpf_vport *vport, bool enable);
int idpf_query_stats(struct idpf_vport *vport,
			struct virtchnl2_vport_stats **pstats);

#endif /* _IDPF_ETHDEV_H_ */

