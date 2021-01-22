/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2020
 */

/**
 * @file rte_pmd_txgbe.h
 * txgbe PMD specific functions.
 *
 **/

#ifndef _PMD_TXGBE_H_
#define _PMD_TXGBE_H_

#include <rte_compat.h>
#include <rte_ethdev.h>
#include <rte_ether.h>

/**
 * Set the VF MAC address.
 *
 * @param port
 *   The port identifier of the Ethernet device.
 * @param vf
 *   VF id.
 * @param mac_addr
 *   VF MAC address.
 * @return
 *   - (0) if successful.
 *   - (-ENODEV) if *port* invalid.
 *   - (-EINVAL) if *vf* or *mac_addr* is invalid.
 */
int rte_pmd_txgbe_set_vf_mac_addr(uint16_t port, uint16_t vf,
		struct rte_ether_addr *mac_addr);

/**
 * Enable/Disable vf vlan strip for all queues in a pool
 *
 * @param port
 *    The port identifier of the Ethernet device.
 * @param vf
 *    ID specifying VF.
 * @param on
 *    1 - Enable VF's vlan strip on RX queues.
 *    0 - Disable VF's vlan strip on RX queues.
 *
 * @return
 *   - (0) if successful.
 *   - (-ENOTSUP) if hardware doesn't support this feature.
 *   - (-ENODEV) if *port* invalid.
 *   - (-EINVAL) if bad parameter.
 */
int
rte_pmd_txgbe_set_vf_vlan_stripq(uint16_t port, uint16_t vf, uint8_t on);

/**
 * Enable/Disable hardware VF VLAN filtering by an Ethernet device of
 * received VLAN packets tagged with a given VLAN Tag Identifier.
 *
 * @param port
 *   The port identifier of the Ethernet device.
 * @param vlan
 *   The VLAN Tag Identifier whose filtering must be enabled or disabled.
 * @param vf_mask
 *    Bitmap listing which VFs participate in the VLAN filtering.
 * @param vlan_on
 *    1 - Enable VFs VLAN filtering.
 *    0 - Disable VFs VLAN filtering.
 * @return
 *   - (0) if successful.
 *   - (-ENOTSUP) if hardware doesn't support.
 *   - (-ENODEV) if *port_id* invalid.
 *   - (-EINVAL) if bad parameter.
 */
int
rte_pmd_txgbe_set_vf_vlan_filter(uint16_t port, uint16_t vlan,
				 uint64_t vf_mask, uint8_t vlan_on);

/**
 * Response sent back to txgbe driver from user app after callback
 */
enum rte_pmd_txgbe_mb_event_rsp {
	RTE_PMD_TXGBE_MB_EVENT_NOOP_ACK,  /**< skip mbox request and ACK */
	RTE_PMD_TXGBE_MB_EVENT_NOOP_NACK, /**< skip mbox request and NACK */
	RTE_PMD_TXGBE_MB_EVENT_PROCEED,  /**< proceed with mbox request  */
	RTE_PMD_TXGBE_MB_EVENT_MAX       /**< max value of this enum */
};

/**
 * Data sent to the user application when the callback is executed.
 */
struct rte_pmd_txgbe_mb_event_param {
	uint16_t vfid;     /**< Virtual Function number */
	uint16_t msg_type; /**< VF to PF message type, defined in txgbe_mbx.h */
	uint16_t retval;   /**< return value */
	void *msg;         /**< pointer to message */
};
#endif /* _PMD_TXGBE_H_ */
