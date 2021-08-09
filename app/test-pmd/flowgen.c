/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2014-2020 Mellanox Technologies, Ltd
 */

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_flow.h>

#include "testpmd.h"

/*
 * Hardcoded range for flow generation.
 *
 * Total number of flows =
 *     cfg_n_ip_src * cfg_n_ip_dst * cfg_n_udp_src * cfg_n_udp_dst
 */
static uint32_t cfg_n_ip_src = 100;
static uint32_t cfg_n_ip_dst = 100;
static uint32_t cfg_n_udp_src = 10;
static uint32_t cfg_n_udp_dst = 10;

/* Base ip and port for flow generation. */
static uint32_t cfg_ip_src_base = RTE_IPV4(10, 254, 0, 0);
static uint32_t cfg_ip_dst_base = RTE_IPV4(10, 253, 0, 0);
static uint16_t cfg_udp_src_base = 1000;
static uint16_t cfg_udp_dst_base = 1001;
static struct rte_ether_addr cfg_ether_src =
	{{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x00 }};
static struct rte_ether_addr cfg_ether_dst =
	{{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x01 }};

RTE_DEFINE_PER_LCORE(uint32_t, _next_ip_src);
RTE_DEFINE_PER_LCORE(uint32_t, _next_ip_dst);
RTE_DEFINE_PER_LCORE(uint32_t, _next_udp_src);
RTE_DEFINE_PER_LCORE(uint32_t, _next_udp_dst);

#define IP_DEFTTL  64   /* from RFC 1340. */

/* Use this type to inform GCC that ip_sum violates aliasing rules. */
typedef unaligned_uint16_t alias_int16_t __attribute__((__may_alias__));

/*
 * Multi-flow generation mode.
 *
 * We originate a bunch of flows (varying destination IP addresses), and
 * terminate receive traffic.  Received traffic is simply discarded, but we
 * still do so in order to maintain traffic statistics.
 */
static void
pkt_burst_flow_gen(struct fwd_stream *fs)
{
	uint32_t pkt_size = tx_pkt_length - 4; /* Adjust FCS */
	struct rte_mbuf  *pkts_burst[MAX_PKT_BURST];
	struct rte_mempool *mbp;
	struct rte_mbuf  *pkt = NULL;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_udp_hdr *udp_hdr;
	uint16_t vlan_tci, vlan_tci_outer;
	uint64_t ol_flags = 0;
	uint16_t nb_rx;
	uint16_t nb_tx;
	uint16_t nb_pkt;
	uint16_t nb_clones = nb_pkt_flowgen_clones;
	uint16_t i;
	uint32_t retry;
	uint64_t tx_offloads;
	uint64_t start_tsc = 0;
	uint32_t next_ip_src = RTE_PER_LCORE(_next_ip_src);
	uint32_t next_ip_dst = RTE_PER_LCORE(_next_ip_dst);
	uint32_t next_udp_src = RTE_PER_LCORE(_next_udp_src);
	uint32_t next_udp_dst = RTE_PER_LCORE(_next_udp_dst);

	get_start_cycles(&start_tsc);

	/* Receive a burst of packets and discard them. */
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue, pkts_burst,
				 nb_pkt_per_burst);
	inc_rx_burst_stats(fs, nb_rx);
	fs->rx_packets += nb_rx;
	for (i = 0; i < nb_rx; i++)
		rte_pktmbuf_free(pkts_burst[i]);

	mbp = current_fwd_lcore()->mbp;
	vlan_tci = ports[fs->tx_port].tx_vlan_id;
	vlan_tci_outer = ports[fs->tx_port].tx_vlan_id_outer;

	tx_offloads = ports[fs->tx_port].dev_conf.txmode.offloads;
	if (tx_offloads	& DEV_TX_OFFLOAD_VLAN_INSERT)
		ol_flags |= PKT_TX_VLAN_PKT;
	if (tx_offloads & DEV_TX_OFFLOAD_QINQ_INSERT)
		ol_flags |= PKT_TX_QINQ_PKT;
	if (tx_offloads	& DEV_TX_OFFLOAD_MACSEC_INSERT)
		ol_flags |= PKT_TX_MACSEC;

	for (nb_pkt = 0; nb_pkt < nb_pkt_per_burst; nb_pkt++) {
		if (!nb_pkt || !nb_clones) {
			nb_clones = nb_pkt_flowgen_clones;
			/* Logic limitation */
			if (nb_clones > nb_pkt_per_burst)
				nb_clones = nb_pkt_per_burst;

			pkt = rte_mbuf_raw_alloc(mbp);
			if (!pkt)
				break;

			pkt->data_len = pkt_size;
			pkt->next = NULL;

			/* Initialize Ethernet header. */
			eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
			rte_ether_addr_copy(&cfg_ether_dst, &eth_hdr->d_addr);
			rte_ether_addr_copy(&cfg_ether_src, &eth_hdr->s_addr);
			eth_hdr->ether_type =
				rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

			/* Initialize IP header. */
			ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
			memset(ip_hdr, 0, sizeof(*ip_hdr));
			ip_hdr->version_ihl	= RTE_IPV4_VHL_DEF;
			ip_hdr->type_of_service	= 0;
			ip_hdr->fragment_offset	= 0;
			ip_hdr->time_to_live	= IP_DEFTTL;
			ip_hdr->next_proto_id	= IPPROTO_UDP;
			ip_hdr->packet_id	= 0;
			ip_hdr->src_addr	=
				rte_cpu_to_be_32(cfg_ip_src_base
						+ next_ip_src);
			ip_hdr->dst_addr	=
				rte_cpu_to_be_32(cfg_ip_dst_base
						+ next_ip_dst);
			ip_hdr->total_length	=
				RTE_CPU_TO_BE_16(pkt_size
						- sizeof(*eth_hdr));
			rte_ipv4_cksum(ip_hdr);

			/* Initialize UDP header. */
			udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
			udp_hdr->src_port	=
				rte_cpu_to_be_16(cfg_udp_src_base
						+ next_udp_src);
			udp_hdr->dst_port	=
				rte_cpu_to_be_16(cfg_udp_dst_base
						+ next_udp_dst);
			udp_hdr->dgram_len	=
				RTE_CPU_TO_BE_16(pkt_size
						- sizeof(*eth_hdr)
						- sizeof(*ip_hdr));
			udp_hdr->dgram_cksum	= 0; /* No UDP checksum. */
			pkt->nb_segs		= 1;
			pkt->pkt_len		= pkt_size;
			pkt->ol_flags		&= EXT_ATTACHED_MBUF;
			pkt->ol_flags		|= ol_flags;
			pkt->vlan_tci		= vlan_tci;
			pkt->vlan_tci_outer	= vlan_tci_outer;
			pkt->l2_len		= sizeof(struct rte_ether_hdr);
			pkt->l3_len		= sizeof(struct rte_ipv4_hdr);
		} else {
			nb_clones--;
			rte_mbuf_refcnt_update(pkt, 1);
		}
		pkts_burst[nb_pkt] = pkt;

		if (++next_udp_dst < cfg_n_udp_dst)
			continue;
		next_udp_dst = 0;
		if (++next_udp_src < cfg_n_udp_src)
			continue;
		next_udp_src = 0;
		if (++next_ip_dst < cfg_n_ip_dst)
			continue;
		next_ip_dst = 0;
		if (++next_ip_src < cfg_n_ip_src)
			continue;
		next_ip_src = 0;
	}

	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_pkt);
	/*
	 * Retry if necessary
	 */
	if (unlikely(nb_tx < nb_pkt) && fs->retry_enabled) {
		retry = 0;
		while (nb_tx < nb_pkt && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
					&pkts_burst[nb_tx], nb_pkt - nb_tx);
		}
	}

	inc_tx_burst_stats(fs, nb_tx);
	fs->tx_packets += nb_tx;
	/* Catch up flow idx by actual sent. */
	for (i = 0; i < nb_tx; ++i) {
		RTE_PER_LCORE(_next_udp_dst) = RTE_PER_LCORE(_next_udp_dst) + 1;
		if (RTE_PER_LCORE(_next_udp_dst) < cfg_n_udp_dst)
			continue;
		RTE_PER_LCORE(_next_udp_dst) = 0;
		RTE_PER_LCORE(_next_udp_src) = RTE_PER_LCORE(_next_udp_src) + 1;
		if (RTE_PER_LCORE(_next_udp_src) < cfg_n_udp_src)
			continue;
		RTE_PER_LCORE(_next_udp_src) = 0;
		RTE_PER_LCORE(_next_ip_dst) = RTE_PER_LCORE(_next_ip_dst) + 1;
		if (RTE_PER_LCORE(_next_ip_dst) < cfg_n_ip_dst)
			continue;
		RTE_PER_LCORE(_next_ip_dst) = 0;
		RTE_PER_LCORE(_next_ip_src) = RTE_PER_LCORE(_next_ip_src) + 1;
		if (RTE_PER_LCORE(_next_ip_src) < cfg_n_ip_src)
			continue;
		RTE_PER_LCORE(_next_ip_src) = 0;
	}

	if (unlikely(nb_tx < nb_pkt)) {
		fs->fwd_dropped += nb_pkt - nb_tx;
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_pkt);
	}

	get_end_cycles(fs, start_tsc);
}

struct fwd_engine flow_gen_engine = {
	.fwd_mode_name  = "flowgen",
	.port_fwd_begin = NULL,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_flow_gen,
};
