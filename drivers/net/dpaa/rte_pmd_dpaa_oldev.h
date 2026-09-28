/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2026 NXP
 */

#ifndef _RTE_PMD_DPAA_OLDEV_H
#define _RTE_PMD_DPAA_OLDEV_H

/**
 * @file rte_pmd_dpaa_oldev.h
 *
 * NXP DPAA offline (O/H) port PMD-specific API.
 *
 * @warning
 * @b EXPERIMENTAL:
 * All functions in this file may be changed or removed without prior notice.
 *
 * These APIs configure the classification, local gateway (LGW) and related
 * uplink information for the DPAA offline port through the kernel control
 * device.
 */

#include <stdint.h>
#include <rte_common.h>
#include <rte_compat.h>

#define DPA_ISC_IPV4_ADDR_TYPE  0x04
#define DPA_ISC_IPV6_ADDR_TYPE  0x06
#define DPDK_OLDEV_MAX_NUM_PORTS 2

#define DPA_ISC_IPV4_SUBNET_TYPE  0x04
#define DPA_ISC_IPV6_SUBNET_TYPE  0x06
#define DPDK_OLDEV_MAX_NUM_SUBNETS 4

/* following macros used for flags field */
/* this macro should be set when addr pair consisting valid
 * inner IP address
 */
#define DPDK_CLASSIF_INNER_IP 0x1

/* this macro should be set when addr pair consisting static
 * IP address
 */
#define DPDK_CLASSIF_STATIC_IP 0x2

/* macro to indicate telecom application is listening on only
 * static IP address
 */
#define DPDK_TELECOM_LISTEN_ON_ONLY_STATICIP 0x4

/* macro to indicate that telecom application is listening on
 * both static and inner IP addresses
 */
#define DPDK_TELECOM_LISTEN_ON_BOTH_STATIC_INNER_IP 0x8

/* macro to indicate that telecom application is listening on
 * only inner IP address
 */
#define DPDK_TELECOM_LISTEN_ON_ONLY_INNERIP 0x10

/* Holds an IPv4 or IPv6 address; ip_addr[0] is used for IPv4, all four
 * words for IPv6. The addr_type field in dpa_ip_pair_s selects the version.
 */
struct dpa_ip_addr_s {
	uint32_t	ip_addr[4];
};

struct __rte_packed_begin dpa_ip_pair_s {
	struct dpa_ip_addr_s static_ip, inner_ip;
	uint8_t flags;
	uint8_t addr_type;
	uint8_t pad[2];
} __rte_packed_end;

struct __rte_packed_begin dpa_lgw_subnet_s {
	uint32_t subnet[4];
	uint8_t mask;
	uint8_t subnet_type;
	uint8_t pad[2];
} __rte_packed_end;

struct rte_pmd_dpaa_uplink_cls_info_s {
	struct dpa_ip_pair_s	addr_pair;
	/* DPDK app listens on these GTP ports */
	uint16_t	gtp_udp_port[DPDK_OLDEV_MAX_NUM_PORTS];
	uint8_t		gtp_proto_id; /* DPDK app listens on UDP protocol */
	uint8_t		num_ports;
	uint8_t		sec_enabled;
	uint8_t		pad;
};

struct __rte_packed_begin rte_pmd_dpaa_lgw_info_s {
	struct dpa_lgw_subnet_s subnets[DPDK_OLDEV_MAX_NUM_SUBNETS];
	uint8_t		num_subnets;
	uint8_t		pad[3];
} __rte_packed_end;

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Program the uplink classification information for the DPAA offline port.
 *
 * @param cls_info
 *   Pointer to the classification information to program. Must not be NULL.
 * @return
 *   0 on success, negative value otherwise.
 */
__rte_experimental
int rte_pmd_dpaa_ol_set_classif_info(struct rte_pmd_dpaa_uplink_cls_info_s *cls_info);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Reset the uplink classification information for the DPAA offline port.
 *
 * @return
 *   0 on success, negative value otherwise.
 */
__rte_experimental
int rte_pmd_dpaa_ol_reset_classif_info(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Program the local gateway (LGW) information for the DPAA offline port.
 *
 * @param lgw_info
 *   Pointer to the LGW information to program. Must not be NULL.
 * @return
 *   0 on success, negative value otherwise.
 */
__rte_experimental
int rte_pmd_dpaa_ol_set_lgw_info(struct rte_pmd_dpaa_lgw_info_s *lgw_info);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Reset the local gateway (LGW) information for the DPAA offline port.
 *
 * @return
 *   0 on success, negative value otherwise.
 */
__rte_experimental
int rte_pmd_dpaa_ol_reset_lgw_info(void);

#endif
