/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#ifndef _RTE_IPSEC_GROUP_H_
#define _RTE_IPSEC_GROUP_H_

/**
 * @file rte_ipsec_group.h
 *
 * RTE IPsec support.
 * It is not recommended to include this file directly,
 * include <rte_ipsec.h> instead.
 * Contains helper functions to process completed crypto-ops
 * and group related packets by sessions they belong to.
 */


#ifdef __cplusplus
extern "C" {
#endif

/**
 * Used to group mbufs by some id.
 * See below for particular usage.
 */
struct rte_ipsec_group {
	union {
		uint64_t val;
		void *ptr;
	} id; /**< grouped by value */
	struct rte_mbuf **m;  /**< start of the group */
	uint32_t cnt;         /**< number of entries in the group */
	int32_t rc;           /**< status code associated with the group */
};

/**
 * Take crypto-op as an input and extract pointer to related ipsec session.
 * @param cop
 *   The address of an input *rte_crypto_op* structure.
 * @return
 *   The pointer to the related *rte_ipsec_session* structure.
 */
struct rte_ipsec_session *
rte_ipsec_ses_from_crypto(const struct rte_crypto_op *cop);

/**
 * Take as input completed crypto ops, extract related mbufs
 * and group them by rte_ipsec_session they belong to.
 * For mbuf which crypto-op wasn't completed successfully
 * RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED will be raised in ol_flags.
 * Note that mbufs with undetermined SA (session-less) are not freed
 * by the function, but are placed beyond mbufs for the last valid group.
 * It is a user responsibility to handle them further.
 * @param cop
 *   The address of an array of *num* pointers to the input *rte_crypto_op*
 *   structures.
 * @param mb
 *   The address of an array of *num* pointers to output *rte_mbuf* structures.
 * @param grp
 *   The address of an array of *num* to output *rte_ipsec_group* structures.
 * @param num
 *   The maximum number of crypto-ops to process.
 * @return
 *   Number of filled elements in *grp* array.
 */
uint16_t
rte_ipsec_pkt_crypto_group(const struct rte_crypto_op *cop[],
	struct rte_mbuf *mb[], struct rte_ipsec_group grp[], uint16_t num);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_IPSEC_GROUP_H_ */
