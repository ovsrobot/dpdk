/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 Qualcomm Technologies, Inc.
 */

#ifndef _STMMAC_H_
#define _STMMAC_H_

#include <stdint.h>

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "stmmac_regs.h"

#define STMMAC_MAX_Q			1

#define STMMAC_DEFAULT_RING_SIZE	256
#define STMMAC_MAX_RING_SIZE		1024	/* Linux DMA_MAX_RX/TX_SIZE */

/*
 * Descriptor overlay: raw 32-bit words, interpreted through the bit macros
 * in stmmac_regs.h, as the kernel driver does for the GMAC4 normal descriptor.
 */
struct stmmac_desc {
	uint32_t des[4];
};

struct stmmac_tx_queue {
	struct stmmac_desc	*tx_ring;
	uint64_t		tx_ring_iova;
	struct rte_mbuf		**sw_ring;
	uint16_t		nb_desc;
	uint16_t		tx_tail;	/* next slot to fill */
	uint16_t		tx_free;	/* next slot to reclaim */
	uint16_t		queue_id;
	uint16_t		port_id;
	void			*chan_base;	/* mac_base + DMA chan(0) offset */
	const struct rte_memzone *mz;
	uint64_t		tx_packets;
	uint64_t		tx_bytes;
	uint64_t		tx_errors;	/* TDES3 ES seen on reclaim */
	uint64_t		tx_ring_full;	/* burst stopped: no free slot */
};

struct stmmac_rx_queue {
	struct stmmac_desc	*rx_ring;
	uint64_t		rx_ring_iova;
	struct rte_mbuf		**sw_ring;
	uint16_t		nb_desc;
	uint16_t		rx_tail;	/* next slot to check */
	uint16_t		rx_refill;	/* next slot to refill */
	uint16_t		queue_id;
	uint16_t		port_id;
	struct rte_mempool	*mb_pool;
	void			*chan_base;	/* mac_base + DMA chan(0) offset */
	const struct rte_memzone *mz;
	uint64_t		rx_packets;
	uint64_t		rx_bytes;
	uint64_t		rx_errors;
	uint64_t		rx_nombuf;
};

struct stmmac_priv {
	void			*mac_base;	/* resource[0]: MAC/MTL/DMA block */
	void			*rgmii_base;	/* resource[1]: RGMII IO macro (NULL if absent) */
	struct stmmac_chan_addrs chan_addrs;

	struct stmmac_tx_queue	*txq[STMMAC_MAX_Q];
	struct stmmac_rx_queue	*rxq[STMMAC_MAX_Q];

	struct rte_ether_addr	mac_addr;

	uint16_t		mdio_addr;	/* PHY MDIO address, from devarg */
	int			has_emac_ge_3;	/* DMA/MTL channel stride override */

	int			link_up;
	uint32_t		link_speed;

	struct rte_eth_stats	stats;
};

/* stmmac_rxtx.c */
uint16_t stmmac_rx_pkt_burst_nc(void *rxq, struct rte_mbuf **rx_pkts,
				uint16_t nb_pkts);
uint16_t stmmac_tx_pkt_burst_nc(void *txq, struct rte_mbuf **tx_pkts,
				uint16_t nb_pkts);

uint16_t stmmac_mdio_read(void *mac_base, uint16_t mdio_addr,
			  uint16_t phyreg);
void stmmac_mdio_write(void *mac_base, uint16_t mdio_addr,
		       uint16_t phyreg, uint16_t phydata);

#endif /* _STMMAC_H_ */
