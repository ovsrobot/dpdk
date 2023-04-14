/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell.
 */

#ifndef RTE_PDCP_H
#define RTE_PDCP_H

/**
 * @file rte_pdcp.h
 *
 * RTE PDCP support.
 *
 * librte_pdcp provides a framework for PDCP protocol processing.
 */

#include <rte_compat.h>
#include <rte_common.h>
#include <rte_mempool.h>
#include <rte_security.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * PDCP entity.
 */
struct rte_pdcp_entity {
	/**
	 * PDCP entities may hold packets for purposes of in-order delivery (in
	 * case of receiving PDCP entity) and re-transmission (in case of
	 * transmitting PDCP entity).
	 *
	 * For receiving PDCP entity, it may hold packets when in-order
	 * delivery is enabled. The packets would be cached until either a
	 * packet that completes the sequence arrives or when t-Reordering timer
	 * expires.
	 *
	 * When post-processing of PDCP packet which completes a sequence is
	 * done, the API may return more packets than enqueued. Application is
	 * expected to provide *rte_pdcp_pkt_post_process()* with *out_mb*
	 * which can hold maximum number of packets which may be returned.
	 */
	uint32_t max_pkt_cache;
	/** User area for saving application data. */
	uint64_t user_area[2];
} __rte_cache_aligned;

/**
 * PDCP entity configuration to be used for establishing an entity.
 */
/* Structure rte_pdcp_entity_conf 8< */
struct rte_pdcp_entity_conf {
	/** PDCP transform for the entity. */
	struct rte_security_pdcp_xform pdcp_xfrm;
	/** Crypto transform applicable for the entity. */
	struct rte_crypto_sym_xform *crypto_xfrm;
	/** Mempool for crypto symmetric session. */
	struct rte_mempool *sess_mpool;
	/** Crypto op pool.*/
	struct rte_mempool *cop_pool;
	/**
	 * 32 bit count value (HFN + SN) to be used for the first packet.
	 * pdcp_xfrm.hfn would be ignored as the HFN would be derived from this value.
	 */
	uint32_t count;
	/** Indicate whether the PDCP entity belongs to Side Link Radio Bearer. */
	bool is_slrb;
	/** Enable security offload on the device specified. */
	bool en_sec_offload;
	/** Device on which security/crypto session need to be created. */
	uint8_t dev_id;
	/** Reverse direction during IV generation. Can be used to simulate UE crypto processing.*/
	bool reverse_iv_direction;
};
/* >8 End of structure rte_pdcp_entity_conf. */

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * 5.1.1 PDCP entity establishment
 *
 * Establish PDCP entity based on provided input configuration.
 *
 * @param conf
 *   Parameters to be used for initializing PDCP entity object.
 * @return
 *   - Valid handle if success
 *   - NULL in case of failure. rte_errno will be set to error code
 */
__rte_experimental
struct rte_pdcp_entity *
rte_pdcp_entity_establish(const struct rte_pdcp_entity_conf *conf);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * 5.1.3 PDCP entity release
 *
 * Release PDCP entity.
 *
 * For UL/transmitting PDCP entity, all stored PDCP SDUs would be dropped.
 * For DL/receiving PDCP entity, the stored PDCP SDUs would be returned in
 * *out_mb* buffer. The buffer should be large enough to hold all cached
 * packets in the entity.
 *
 * @param pdcp_entity
 *   Pointer to the PDCP entity to be released.
 * @param[out] out_mb
 *   The address of an array that can hold up to *rte_pdcp_entity.max_pkt_cache*
 *   pointers to *rte_mbuf* structures.
 * @return
 *   -  0: Success and no cached packets to return
 *   - >0: Success and the number of packets returned in out_mb
 *   - <0: Error code in case of failures
 */
__rte_experimental
int
rte_pdcp_entity_release(struct rte_pdcp_entity *pdcp_entity,
			struct rte_mbuf *out_mb[]);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * 5.1.4 PDCP entity suspend
 *
 * Suspend PDCP entity.
 *
 * For DL/receiving PDCP entity, the stored PDCP SDUs would be returned in
 * *out_mb* buffer. The buffer should be large enough to hold all cached
 * packets in the entity.
 *
 * For UL/transmitting PDCP entity, *out_mb* buffer would be unused.
 *
 * @param pdcp_entity
 *   Pointer to the PDCP entity to be suspended.
 * @param[out] out_mb
 *   The address of an array that can hold up to *rte_pdcp_entity.max_pkt_cache*
 *   pointers to *rte_mbuf* structures.
 * @return
 *   -  0: Success and no cached packets to return
 *   - >0: Success and the number of packets returned in out_mb
 *   - <0: Error code in case of failures
 */
__rte_experimental
int
rte_pdcp_entity_suspend(struct rte_pdcp_entity *pdcp_entity,
			struct rte_mbuf *out_mb[]);

#ifdef __cplusplus
}
#endif

#endif /* RTE_PDCP_H */
