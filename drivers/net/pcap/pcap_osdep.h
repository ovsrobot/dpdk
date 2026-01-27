/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Dmitry Kozlyuk
 */

#ifndef _RTE_PCAP_OSDEP_
#define _RTE_PCAP_OSDEP_

#include <rte_ether.h>
#include <rte_log.h>

#define PMD_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, ETH_PCAP, "%s(): ", __func__, __VA_ARGS__)
extern int eth_pcap_logtype;
#define RTE_LOGTYPE_ETH_PCAP eth_pcap_logtype

/**
 * Link information returned by osdep_iface_link_get().
 */
struct osdep_iface_link {
	uint32_t link_speed;    /**< Speed in Mbps, 0 if unknown */
	uint8_t link_status;    /**< 1 = up, 0 = down */
	uint8_t link_duplex;    /**< 1 = full, 0 = half */
	uint8_t link_autoneg;   /**< 1 = autoneg enabled, 0 = fixed */
};

int osdep_iface_index_get(const char *name);
int osdep_iface_mac_get(const char *name, struct rte_ether_addr *mac);

/**
 * Get link state and speed for a network interface.
 *
 * @param name
 *   Interface name (e.g., "eth0" on Linux, "{GUID}" on Windows).
 * @param link
 *   Pointer to structure to fill with link information.
 * @return
 *   0 on success, -1 on failure.
 */
int osdep_iface_link_get(const char *name, struct osdep_iface_link *link);

#endif
