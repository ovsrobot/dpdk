/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 Stephen Hemminger <stephen@networkplumber.org>
 */

#ifndef RTE_MIRROR_H_
#define RTE_MIRROR_H_

#include <stdint.h>

#include <rte_compat.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * Ethdev port mirroring
 *
 * This interface provides the ability to duplicate packets to another port.
 */

/* Definitions for ethdev analyzer direction */
#define RTE_ETH_MIRROR_DIRECTION_INGRESS 1
#define RTE_ETH_MIRROR_DIRECTION_EGRESS 2

/**
 * @warning
 * @b EXPERIMENTAL: this structure may change without prior notice.
 *
 * This dynamic field is added to mbuf's when they are copied to
 * the port mirror.
 */
typedef struct rte_mbuf_origin {
	uint32_t original_len;	/**< Packet length before copy */
	uint16_t port_id;	/**< Port where packet originated */
	uint16_t queue_id;      /**< Queue used for Tx or Rx */
} rte_mbuf_origin_t;

/**
 * @warning
 * @b EXPERIMENTAL: this structure may change without prior notice.
 *
 * Structure used to configure ethdev Switched Port Analyzer (MIRROR)
 */
struct rte_eth_mirror_conf {
	struct rte_mempool *mp;	/**< Memory pool for copies, If NULL then cloned. */
	uint32_t snaplen;	/**< Upper limit on number of bytes to copy */
	uint32_t flags;		/**< bitmask of RTE_ETH_MIRROR_XXX_FLAG's */
	uint16_t target;	/**< Destination port */
	uint8_t direction;	/**< bitmask of RTE_ETH_MIRROR_DIRECTION_XXX */
};

#define RTE_ETH_MIRROR_TIMESTAMP_FLAG 1	/**< insert timestamp into mirrored packet */
#define RTE_ETH_MIRROR_ORIGIN_FLAG 2	/**< insert rte_mbuf_origin into mirrored packet */
#define RTE_ETH_MIRROR_INDIRECT_FLAG 4  /**< use rte_mbuf_attach rather than copy */

#define RTE_ETH_MIRROR_FLAG_MASK 7

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Create a Switched Port Analyzer (MIRROR) instance.
 *
 * @param port_id
 *   The port identifier of the source Ethernet device.
 * @param conf
 *   Settings for this MIRROR instance..
 * @return
 *   Negative errno value on error, 0 on success.
 */
__rte_experimental
int
rte_eth_add_mirror(uint16_t port_id, const struct rte_eth_mirror_conf *conf);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Break port mirrorning.
 * After this call no more packets will be sent the target port.
 *
 * @param port_id
 *   The port identifier of the source Ethernet device.
 * @param target_id
 *   The identifier of the destination port.
 * @return
 *   Negative errno value on error, 0 on success.
 */
__rte_experimental
int rte_eth_remove_mirror(uint16_t port_id, uint16_t target_id);

#ifdef __cplusplus
}
#endif

#endif /* RTE_MIRROR_H_ */
