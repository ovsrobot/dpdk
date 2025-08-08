/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 Stephen Hemminger <stephen@networkplumber.org>
 */

#ifndef RTE_MIRROR_H_
#define RTE_MIRROR_H_

/**
 * @file
 * Ethdev port mirroring
 *
 * This interface provides the ability to duplicate packets to another port.
 */

#include <stdint.h>

#include <rte_compat.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Definitions for ethdev mirror flags */
#define RTE_ETH_MIRROR_DIRECTION_INGRESS 1
#define RTE_ETH_MIRROR_DIRECTION_EGRESS 2
#define RTE_ETH_MIRROR_DIRECTION_MASK (RTE_ETH_MIRROR_DIRECTION_INGRESS | \
				       RTE_ETH_MIRROR_DIRECTION_EGRESS)

#define RTE_ETH_MIRROR_TIMESTAMP_FLAG 4	/**< insert timestamp into mirrored packet */
#define RTE_ETH_MIRROR_ORIGIN_FLAG    8	/**< insert rte_mbuf_origin into mirrored packet */

#define RTE_ETH_MIRROR_FLAG_MASK      (RTE_ETH_MIRROR_TIMESTAMP_FLAG | \
				       RTE_ETH_MIRROR_ORIGIN_FLAG)
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
struct rte_bpf_prm;
struct rte_eth_mirror_conf {
	struct rte_mempool *mp;	/**< Memory pool for copies, If NULL then cloned. */
	struct rte_bpf_prm *filter; /**< Optional packet filter */
	uint32_t snaplen;	/**< Upper limit on number of bytes to copy */
	uint32_t flags;		/**< bitmask of RTE_ETH_MIRROR_XXX_FLAG's */
	uint16_t target;	/**< Destination port */
};

/**
 * @warning
 * @b EXPERIMENTAL: this structure may change without prior notice.
 *
 * Structure returned by rte_mirror_stats.
 */
struct rte_eth_mirror_stats {
	uint64_t packets;	/**< Number of mirrored packets. */
	uint64_t filtered;	/**< Packets filtered by BPF program */
	uint64_t nombuf;	/**< Rx mbuf allocation failures. */
	uint64_t full;		/**< Target port transmit full. */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Create a port mirror instance.
 *
 * @param port_id
 *   The port identifier of the source Ethernet device.
 * @param conf
 *   Settings for this MIRROR instance.
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
 * Break port existing port mirroring.
 * After this call no more packets will be sent from origin port to the target port.
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

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Query statistics for a mirror.
 *
 * @param port_id
 *   The port identifier of the source Ethernet device.
 * @param target_id
 *   The identifier of the destination port.
 * @param stats
 *   A pointer to a structure of type *rte_eth_mirror_stats* to be filled.
 *
 * @return
 *   Negative errno value on error, 0 on success.
 */
__rte_experimental
int rte_eth_mirror_stats_get(uint16_t port_id, uint16_t target_id,
			     struct rte_eth_mirror_stats *stats);
/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Reset statistics for mirror.
 *
 * @param port_id
 *   The port identifier of the source Ethernet device.
 * @param target_id
 *   The identifier of the destination port.
 */
__rte_experimental
int rte_eth_mirror_stats_reset(uint16_t port_id, uint16_t target_id);

#ifdef __cplusplus
}
#endif

#endif /* RTE_MIRROR_H_ */
