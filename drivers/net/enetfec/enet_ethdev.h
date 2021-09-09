/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021 NXP
 */

#ifndef __ENETFEC_ETHDEV_H__
#define __ENETFEC_ETHDEV_H__

#include <compat.h>
#include <rte_ethdev.h>

/* Common log type name prefix */
#define ENETFEC_LOGTYPE_PREFIX	"pmd.net.enetfec."

/*
 * ENETFEC with AVB IP can support maximum 3 rx and tx queues.
 */
#define ENETFEC_MAX_Q		3

#define BD_LEN			49152
#define ENETFEC_TX_FR_SIZE	2048
#define MAX_TX_BD_RING_SIZE	512	/* It should be power of 2 */
#define MAX_RX_BD_RING_SIZE	512

/* full duplex or half duplex */
#define HALF_DUPLEX             0x00
#define FULL_DUPLEX             0x01
#define UNKNOWN_DUPLEX          0xff

#define PKT_MAX_BUF_SIZE        1984
#define OPT_FRAME_SIZE		(PKT_MAX_BUF_SIZE << 16)
#define ETH_ALEN		RTE_ETHER_ADDR_LEN
#define ETH_HLEN		RTE_ETHER_HDR_LEN
#define VLAN_HLEN		4

struct bufdesc {
	uint16_t		bd_datlen;  /* buffer data length */
	uint16_t		bd_sc;	    /* buffer control & status */
	uint32_t		bd_bufaddr; /* buffer address */
};

struct bufdesc_ex {
	struct			bufdesc desc;
	uint32_t		bd_esc;
	uint32_t		bd_prot;
	uint32_t		bd_bdu;
	uint32_t		ts;
	uint16_t		res0[4];
};

struct bufdesc_prop {
	int			queue_id;
	/* Addresses of Tx and Rx buffers */
	struct bufdesc		*base;
	struct bufdesc		*last;
	struct bufdesc		*cur;
	void __iomem		*active_reg_desc;
	uint64_t		descr_baseaddr_p;
	unsigned short		ring_size;
	unsigned char		d_size;
	unsigned char		d_size_log2;
};

struct enetfec_priv_tx_q {
	struct bufdesc_prop	bd;
	struct rte_mbuf		*tx_mbuf[MAX_TX_BD_RING_SIZE];
	struct bufdesc		*dirty_tx;
	struct rte_mempool	*pool;
	struct enetfec_private	*fep;
};

struct enetfec_priv_rx_q {
	struct bufdesc_prop	bd;
	struct rte_mbuf		*rx_mbuf[MAX_RX_BD_RING_SIZE];
	struct rte_mempool	*pool;
	struct enetfec_private	*fep;
};

/* Buffer descriptors of FEC are used to track the ring buffers. Buffer
 * descriptor base is x_bd_base. Currently available buffer are x_cur
 * and x_cur. where x is rx or tx. Current buffer is tracked by dirty_tx
 * that is sent by the controller.
 * The tx_cur and dirty_tx are same in completely full and empty
 * conditions. Actual condition is determined by empty & ready bits.
 */
struct enetfec_private {
	struct rte_eth_dev	*dev;
	struct rte_eth_stats	stats;
	struct rte_mempool	*pool;
	uint16_t		max_rx_queues;
	uint16_t		max_tx_queues;
	unsigned int		total_tx_ring_size;
	unsigned int		total_rx_ring_size;
	bool			bufdesc_ex;
	unsigned int		tx_align;
	unsigned int		rx_align;
	int			full_duplex;
	unsigned int		phy_speed;
	u_int32_t		quirks;
	int			flag_csum;
	int			flag_pause;
	int			flag_wol;
	bool			rgmii_txc_delay;
	bool			rgmii_rxc_delay;
	int			link;
	void			*hw_baseaddr_v;
	uint64_t		hw_baseaddr_p;
	void			*bd_addr_v;
	uint64_t		bd_addr_p;
	uint64_t		bd_addr_p_r[ENETFEC_MAX_Q];
	uint64_t		bd_addr_p_t[ENETFEC_MAX_Q];
	void			*dma_baseaddr_r[ENETFEC_MAX_Q];
	void			*dma_baseaddr_t[ENETFEC_MAX_Q];
	uint64_t		cbus_size;
	unsigned int		reg_size;
	unsigned int		bd_size;
	int			hw_ts_rx_en;
	int			hw_ts_tx_en;
	struct enetfec_priv_rx_q *rx_queues[ENETFEC_MAX_Q];
	struct enetfec_priv_tx_q *tx_queues[ENETFEC_MAX_Q];
};

#define writel(v, p) ({*(volatile unsigned int *)(p) = (v); })
#define readl(p) rte_read32(p)

static inline struct
bufdesc *enet_get_nextdesc(struct bufdesc *bdp, struct bufdesc_prop *bd)
{
	return (bdp >= bd->last) ? bd->base
			: (struct bufdesc *)(((uint64_t)bdp) + bd->d_size);
}

static inline struct
bufdesc *enet_get_prevdesc(struct bufdesc *bdp, struct bufdesc_prop *bd)
{
	return (bdp <= bd->base) ? bd->last
			: (struct bufdesc *)(((uint64_t)bdp) - bd->d_size);
}

static inline int
enet_get_bd_index(struct bufdesc *bdp, struct bufdesc_prop *bd)
{
	return ((const char *)bdp - (const char *)bd->base) >> bd->d_size_log2;
}

static inline int
fls64(unsigned long word)
{
	return (64 - __builtin_clzl(word)) - 1;
}

uint16_t enetfec_recv_pkts(void *rxq1, __rte_unused struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);
uint16_t enetfec_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts);
struct bufdesc *enet_get_nextdesc(struct bufdesc *bdp,
		struct bufdesc_prop *bd);
int enet_new_rxbdp(struct enetfec_private *fep, struct bufdesc *bdp,
		struct rte_mbuf *mbuf);
void enetfec_enable(void *base);
void enetfec_disable(void *base);

#endif /*__ENETFEC_ETHDEV_H__*/
