/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021 NXP
 */

#ifndef __ENETFEC_ETHDEV_H__
#define __ENETFEC_ETHDEV_H__

#include <rte_ethdev.h>

/* full duplex */
#define FULL_DUPLEX             0x00

#define PKT_MAX_BUF_SIZE        1984
#define OPT_FRAME_SIZE         (PKT_MAX_BUF_SIZE << 16)

/*
 * ENETFEC can support 1 rx and tx queue..
 */

#define ENETFEC_MAX_Q		1

#define writel(v, p) ({*(volatile unsigned int *)(p) = (v); })
#define readl(p) rte_read32(p)

struct enetfec_private {
	struct rte_eth_dev	*dev;
	struct rte_eth_stats	stats;
	struct rte_mempool	*pool;
	uint16_t		max_rx_queues;
	uint16_t		max_tx_queues;
	unsigned int		total_tx_ring_size;
	unsigned int		total_rx_ring_size;
	bool			bufdesc_ex;
	int			full_duplex;
	uint32_t		quirks;
	uint32_t		enetfec_e_cntl;
	int			flag_csum;
	int			flag_pause;
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
	struct enetfec_priv_rx_q *rx_queues[ENETFEC_MAX_Q];
	struct enetfec_priv_tx_q *tx_queues[ENETFEC_MAX_Q];
};

#endif /*__ENETFEC_ETHDEV_H__*/
