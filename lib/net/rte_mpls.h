/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016 6WIND S.A.
 */

#ifndef _RTE_MPLS_H_
#define _RTE_MPLS_H_

/**
 * @file
 *
 * MPLS-related defines
 */

#include <stdint.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * MPLS header.
 */
__extension__
struct rte_mpls_hdr {
	rte_be16_t tag_msb; /**< Label(msb). */
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint8_t tag_lsb:4;  /**< Label(lsb). */
	uint8_t tc:3;       /**< Traffic class. */
	uint8_t bs:1;       /**< Bottom of stack. */
#else
	uint8_t bs:1;       /**< Bottom of stack. */
	uint8_t tc:3;       /**< Traffic class. */
	uint8_t tag_lsb:4;  /**< label(lsb) */
#endif
	uint8_t  ttl;       /**< Time to live. */
} __rte_packed;

#define RTE_MPLS_HLEN 4 /**< Length of MPLS header. */

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Insert MPLS header into the packet.
 * If it's first MPLS header to be inserted in the packet,
 *  - Updates the ether type.
 *  - Sets the MPLS bottom-of-stack bit to 1.
 *
 * @param m
 *   The pointer to the mbuf.
 * @param mp
 *   The pointer to the MPLS header.
 * @return
 *   0 on success, -1 on error
 */
__rte_experimental
static inline int
rte_mpls_push_over_l2(struct rte_mbuf **m, const struct rte_mpls_hdr *mp)
{
	struct rte_ether_hdr *oh, *nh;
	struct rte_mpls_hdr *mph;

	/* Can't insert header if mbuf is shared */
	if (!RTE_MBUF_DIRECT(*m) || rte_mbuf_refcnt_read(*m) > 1)
		return -EINVAL;

	/* Can't insert header if ethernet frame doesn't exist */
	if (rte_pktmbuf_data_len(*m) < RTE_ETHER_HDR_LEN)
		return -EINVAL;

	oh = rte_pktmbuf_mtod(*m, struct rte_ether_hdr *);
	nh = (struct rte_ether_hdr *)(void *)
		rte_pktmbuf_prepend(*m, sizeof(struct rte_mpls_hdr));
	if (nh == NULL)
		return -ENOSPC;

	memmove(nh, oh, RTE_ETHER_HDR_LEN);

	/* Copy the MPLS header after ethernet frame */
	mph = rte_pktmbuf_mtod_offset(*m, struct rte_mpls_hdr*,
			sizeof(struct rte_ether_hdr));
	memcpy(mph, mp, RTE_MPLS_HLEN);

	mph->tag_msb = rte_cpu_to_be_16(mp->tag_msb);

	/* If first MPLS header, update ether type and bottom-of-stack bit */
	if (nh->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_MPLS)) {
		nh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_MPLS);
		mph->bs = 1;
	} else {
		mph->bs = 0;
	}

	return 0;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Strips MPLS from the packet. Doesn't update the ether type
 *
 * @param m
 *   The pointer to the mbuf.
 * @return
 *   0 on success, -1 on error
 */
__rte_experimental
static inline int
rte_mpls_strip_over_l2(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	struct rte_mpls_hdr *mph;
	bool mpls_exist = true;

	if (eh->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_MPLS))
		return -1;

	/* Stripping all MPLS header */
	while (mpls_exist) {
		mph = rte_pktmbuf_mtod_offset(m, struct rte_mpls_hdr*,
		sizeof(struct rte_ether_hdr));
		if (mph->bs & 1)
			mpls_exist = false;
		memmove(rte_pktmbuf_adj(m, sizeof(struct rte_mpls_hdr)),
		eh, sizeof(struct rte_ether_hdr));
		eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	}

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* RTE_MPLS_H_ */
