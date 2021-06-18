/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */
#ifndef __CNXK_ETHDEV_H__
#define __CNXK_ETHDEV_H__

#include <math.h>
#include <stdint.h>

#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <rte_kvargs.h>

#include "roc_api.h"

#define CNXK_ETH_DEV_PMD_VERSION "1.0"

/* VLAN tag inserted by NIX_TX_VTAG_ACTION.
 * In Tx space is always reserved for this in FRS.
 */
#define CNXK_NIX_MAX_VTAG_INS	   2
#define CNXK_NIX_MAX_VTAG_ACT_SIZE (4 * CNXK_NIX_MAX_VTAG_INS)

/* ETH_HLEN+ETH_FCS+2*VLAN_HLEN */
#define CNXK_NIX_L2_OVERHEAD (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + 8)

#define CNXK_NIX_RX_MIN_DESC	    16
#define CNXK_NIX_RX_MIN_DESC_ALIGN  16
#define CNXK_NIX_RX_NB_SEG_MAX	    6
#define CNXK_NIX_RX_DEFAULT_RING_SZ 4096
/* Max supported SQB count */
#define CNXK_NIX_TX_MAX_SQB 512

/* If PTP is enabled additional SEND MEM DESC is required which
 * takes 2 words, hence max 7 iova address are possible
 */
#if defined(RTE_LIBRTE_IEEE1588)
#define CNXK_NIX_TX_NB_SEG_MAX 7
#else
#define CNXK_NIX_TX_NB_SEG_MAX 9
#endif

#define CNXK_NIX_RSS_L3_L4_SRC_DST                                             \
	(ETH_RSS_L3_SRC_ONLY | ETH_RSS_L3_DST_ONLY | ETH_RSS_L4_SRC_ONLY |     \
	 ETH_RSS_L4_DST_ONLY)

#define CNXK_NIX_RSS_OFFLOAD                                                   \
	(ETH_RSS_PORT | ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP |               \
	 ETH_RSS_SCTP | ETH_RSS_TUNNEL | ETH_RSS_L2_PAYLOAD |                  \
	 CNXK_NIX_RSS_L3_L4_SRC_DST | ETH_RSS_LEVEL_MASK | ETH_RSS_C_VLAN)

#define CNXK_NIX_TX_OFFLOAD_CAPA                                               \
	(DEV_TX_OFFLOAD_MBUF_FAST_FREE | DEV_TX_OFFLOAD_MT_LOCKFREE |          \
	 DEV_TX_OFFLOAD_VLAN_INSERT | DEV_TX_OFFLOAD_QINQ_INSERT |             \
	 DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM | DEV_TX_OFFLOAD_OUTER_UDP_CKSUM |    \
	 DEV_TX_OFFLOAD_TCP_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM |                 \
	 DEV_TX_OFFLOAD_SCTP_CKSUM | DEV_TX_OFFLOAD_TCP_TSO |                  \
	 DEV_TX_OFFLOAD_VXLAN_TNL_TSO | DEV_TX_OFFLOAD_GENEVE_TNL_TSO |        \
	 DEV_TX_OFFLOAD_GRE_TNL_TSO | DEV_TX_OFFLOAD_MULTI_SEGS |              \
	 DEV_TX_OFFLOAD_IPV4_CKSUM)

#define CNXK_NIX_RX_OFFLOAD_CAPA                                               \
	(DEV_RX_OFFLOAD_CHECKSUM | DEV_RX_OFFLOAD_SCTP_CKSUM |                 \
	 DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM | DEV_RX_OFFLOAD_SCATTER |            \
	 DEV_RX_OFFLOAD_JUMBO_FRAME | DEV_RX_OFFLOAD_OUTER_UDP_CKSUM |         \
	 DEV_RX_OFFLOAD_RSS_HASH)

struct cnxk_eth_dev {
	/* ROC NIX */
	struct roc_nix nix;

	/* Max macfilter entries */
	uint8_t max_mac_entries;

	uint16_t flags;
	bool scalar_ena;

	/* Pointer back to rte */
	struct rte_eth_dev *eth_dev;

	/* HW capabilities / Limitations */
	union {
		struct {
			uint64_t cq_min_4k : 1;
		};
		uint64_t hwcap;
	};

	/* Rx and Tx offload capabilities */
	uint64_t rx_offload_capa;
	uint64_t tx_offload_capa;
	uint32_t speed_capa;

	/* Default mac address */
	uint8_t mac_addr[RTE_ETHER_ADDR_LEN];
};

static inline struct cnxk_eth_dev *
cnxk_eth_pmd_priv(struct rte_eth_dev *eth_dev)
{
	return eth_dev->data->dev_private;
}

/* Common ethdev ops */
extern struct eth_dev_ops cnxk_eth_dev_ops;

/* Ops */
int cnxk_nix_probe(struct rte_pci_driver *pci_drv,
		   struct rte_pci_device *pci_dev);
int cnxk_nix_remove(struct rte_pci_device *pci_dev);
int cnxk_nix_info_get(struct rte_eth_dev *eth_dev,
		      struct rte_eth_dev_info *dev_info);

/* Devargs */
int cnxk_ethdev_parse_devargs(struct rte_devargs *devargs,
			      struct cnxk_eth_dev *dev);

#endif /* __CNXK_ETHDEV_H__ */
