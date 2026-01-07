/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 1982, 1986, 1990, 1993
 *      The Regents of the University of California.
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright(c) 2014 6WIND S.A.
 * All rights reserved.
 */

#ifndef _RTE_CKSUM_H_
#define _RTE_CKSUM_H_

/**
 * @file
 *
 * Protocol independent checksum utilities.
 */

#include <stdint.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @internal Calculate a sum of all words in the buffer.
 * Helper routine for the rte_raw_cksum().
 *
 * @param buf
 *   Pointer to the buffer.
 * @param len
 *   Length of the buffer.
 * @param sum
 *   Initial value of the sum.
 * @return
 *   sum += Sum of all words in the buffer.
 */
__rte_no_ubsan_alignment
static inline uint32_t
__rte_raw_cksum(const void *buf, size_t len, uint32_t sum)
{
	/* Process in 64 byte blocks (32 x uint16_t). */
	/* Always process as uint16_t chunks to preserve overflow/carry. */
	const void *end = RTE_PTR_ADD(buf, RTE_ALIGN_FLOOR(len, 64));
	while (buf != end) {
		const unaligned_uint16_t *p16 = (const unaligned_uint16_t *)buf;
		sum += (uint32_t)p16[0] + p16[1] + p16[2] + p16[3] +
			 p16[4] + p16[5] + p16[6] + p16[7] +
			 p16[8] + p16[9] + p16[10] + p16[11] +
			 p16[12] + p16[13] + p16[14] + p16[15] +
			 p16[16] + p16[17] + p16[18] + p16[19] +
			 p16[20] + p16[21] + p16[22] + p16[23] +
			 p16[24] + p16[25] + p16[26] + p16[27] +
			 p16[28] + p16[29] + p16[30] + p16[31];
		buf = RTE_PTR_ADD(buf, 64);
	}

	if (len & 32) {
		const unaligned_uint16_t *p16 = (const unaligned_uint16_t *)buf;
		sum += (uint32_t)p16[0] + p16[1] + p16[2] + p16[3] +
			 p16[4] + p16[5] + p16[6] + p16[7] +
			 p16[8] + p16[9] + p16[10] + p16[11] +
			 p16[12] + p16[13] + p16[14] + p16[15];
		buf = RTE_PTR_ADD(buf, 32);
	}

	if (len & 16) {
		const unaligned_uint16_t *p16 = (const unaligned_uint16_t *)buf;
		sum += (uint32_t)p16[0] + p16[1] + p16[2] + p16[3] +
			 p16[4] + p16[5] + p16[6] + p16[7];
		buf = RTE_PTR_ADD(buf, 16);
	}

	if (len & 8) {
		const unaligned_uint16_t *p16 = (const unaligned_uint16_t *)buf;
		sum += (uint32_t)p16[0] + p16[1] + p16[2] + p16[3];
		buf = RTE_PTR_ADD(buf, 8);
	}

	if (len & 4) {
		const unaligned_uint16_t *p16 = (const unaligned_uint16_t *)buf;
		sum += (uint32_t)p16[0] + p16[1];
		buf = RTE_PTR_ADD(buf, 4);
	}

	if (len & 2) {
		const unaligned_uint16_t *p16 = (const unaligned_uint16_t *)buf;
		sum += *p16;
		buf = RTE_PTR_ADD(buf, 2);
	}

	/* If length is odd use memcpy for byte order independence */
	if (len & 1) {
		uint16_t left = 0;
		memcpy(&left, buf, 1);
		sum += left;
	}

	return sum;
}

/**
 * @internal Reduce a sum to the non-complemented checksum.
 * Helper routine for the rte_raw_cksum().
 *
 * @param sum
 *   Value of the sum.
 * @return
 *   The non-complemented checksum.
 */
static inline uint16_t
__rte_raw_cksum_reduce(uint32_t sum)
{
	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	return (uint16_t)sum;
}

/**
 * Process the non-complemented checksum of a buffer.
 *
 * @param buf
 *   Pointer to the buffer.
 * @param len
 *   Length of the buffer.
 * @return
 *   The non-complemented checksum.
 */
static inline uint16_t
rte_raw_cksum(const void *buf, size_t len)
{
	uint32_t sum;

	sum = __rte_raw_cksum(buf, len, 0);
	return __rte_raw_cksum_reduce(sum);
}

/**
 * Compute the raw (non complemented) checksum of a packet.
 *
 * @param m
 *   The pointer to the mbuf.
 * @param off
 *   The offset in bytes to start the checksum.
 * @param len
 *   The length in bytes of the data to checksum.
 * @param cksum
 *   A pointer to the checksum, filled on success.
 * @return
 *   0 on success, -1 on error (bad length or offset).
 */
static inline int
rte_raw_cksum_mbuf(const struct rte_mbuf *m, uint32_t off, uint32_t len,
	uint16_t *cksum)
{
	const struct rte_mbuf *seg;
	const char *buf;
	uint32_t sum, tmp;
	uint32_t seglen, done;

	/* easy case: all data in the first segment */
	if (off + len <= rte_pktmbuf_data_len(m)) {
		*cksum = rte_raw_cksum(rte_pktmbuf_mtod_offset(m,
				const char *, off), len);
		return 0;
	}

	if (unlikely(off + len > rte_pktmbuf_pkt_len(m)))
		return -1; /* invalid params, return a dummy value */

	/* else browse the segment to find offset */
	seglen = 0;
	for (seg = m; seg != NULL; seg = seg->next) {
		seglen = rte_pktmbuf_data_len(seg);
		if (off < seglen)
			break;
		off -= seglen;
	}
	RTE_ASSERT(seg != NULL);
	if (seg == NULL)
		return -1;
	seglen -= off;
	buf = rte_pktmbuf_mtod_offset(seg, const char *, off);
	if (seglen >= len) {
		/* all in one segment */
		*cksum = rte_raw_cksum(buf, len);
		return 0;
	}

	/* hard case: process checksum of several segments */
	sum = 0;
	done = 0;
	for (;;) {
		tmp = __rte_raw_cksum(buf, seglen, 0);
		if (done & 1)
			tmp = rte_bswap16((uint16_t)tmp);
		sum += tmp;
		done += seglen;
		if (done == len)
			break;
		seg = seg->next;
		buf = rte_pktmbuf_mtod(seg, const char *);
		seglen = rte_pktmbuf_data_len(seg);
		if (seglen > len - done)
			seglen = len - done;
	}

	*cksum = __rte_raw_cksum_reduce(sum);
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_CKSUM_H_ */
