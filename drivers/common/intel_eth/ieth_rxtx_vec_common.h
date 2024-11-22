/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Intel Corporation
 */

#ifndef IETH_RXTX_VEC_COMMON_H_
#define IETH_RXTX_VEC_COMMON_H_

#include <stdint.h>
#include <unistd.h>
#include <rte_mbuf.h>
#include "ieth_rxtx.h"

#define IETH_RX_BURST 32

static inline uint16_t
ieth_rx_reassemble_packets(struct rte_mbuf **rx_bufs,
			  uint16_t nb_bufs, uint8_t *split_flags,
			  struct rte_mbuf **pkt_first_seg,
			  struct rte_mbuf **pkt_last_seg,
			  const uint8_t crc_len)
{
	struct rte_mbuf *pkts[IETH_RX_BURST] = {0}; /*finished pkts*/
	struct rte_mbuf *start = *pkt_first_seg;
	struct rte_mbuf *end = *pkt_last_seg;
	unsigned int pkt_idx, buf_idx;

	for (buf_idx = 0, pkt_idx = 0; buf_idx < nb_bufs; buf_idx++) {
		if (end) {
			/* processing a split packet */
			end->next = rx_bufs[buf_idx];
			rx_bufs[buf_idx]->data_len += crc_len;

			start->nb_segs++;
			start->pkt_len += rx_bufs[buf_idx]->data_len;
			end = end->next;

			if (!split_flags[buf_idx]) {
				/* it's the last packet of the set */
				start->hash = end->hash;
				start->vlan_tci = end->vlan_tci;
				start->ol_flags = end->ol_flags;
				/* we need to strip crc for the whole packet */
				start->pkt_len -= crc_len;
				if (end->data_len > crc_len)
					end->data_len -= crc_len;
				else {
					/* free up last mbuf */
					struct rte_mbuf *secondlast = start;

					start->nb_segs--;
					while (secondlast->next != end)
						secondlast = secondlast->next;
					secondlast->data_len -= (crc_len - end->data_len);
					secondlast->next = NULL;
					rte_pktmbuf_free_seg(end);
				}
				pkts[pkt_idx++] = start;
				start = NULL;
				end = NULL;
			}
		} else{
			/* not processing a split packet */
			if (!split_flags[buf_idx]) {
				/* not a split packet, save and skip */
				pkts[pkt_idx++] = rx_bufs[buf_idx];
				continue;
			}
			start = rx_bufs[buf_idx];
			end = start;
			rx_bufs[buf_idx]->data_len += crc_len;
			rx_bufs[buf_idx]->pkt_len += crc_len;
		}
	}

	/* save the partial packet for next time */
	*pkt_first_seg = start;
	*pkt_last_seg = end;
	memcpy(rx_bufs, pkts, pkt_idx * (sizeof(*pkts)));
	return pkt_idx;
}

static __rte_always_inline void
ieth_tx_backlog_entry(struct ieth_tx_entry *txep, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	for (uint16_t i = 0; i < (int)nb_pkts; ++i)
		txep[i].mbuf = tx_pkts[i];
}
#endif /* IETH_RXTX_VEC_COMMON_H_ */
