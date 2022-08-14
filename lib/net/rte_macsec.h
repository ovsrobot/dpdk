/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#ifndef _RTE_MACSEC_H_
#define _RTE_MACSEC_H_

/**
 * @file
 *
 * MACsec-related defines
 */

#include <rte_byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif


/* SecTAG length = macsec ether header without the optional SCI */
#define RTE_MACSEC_TAG_LEN 6
#define RTE_MACSEC_SCI_LEN 8

#define RTE_MACSEC_TCI_VERSION	0x80 /**< Version mask for MACsec. Should be 0. */
#define RTE_MACSEC_TCI_ES	0x40 /**< End station - SCI is not valid */
#define RTE_MACSEC_TCI_SC	0x20 /**< SCI present */
#define RTE_MACSEC_TCI_SCB	0x10 /**< Secure channel support EPON single copy broadcast */
#define RTE_MACSEC_TCI_E	0x08 /**< User data is encrypted */
#define RTE_MACSEC_TCI_C	0x04 /**< User data was changed (because of encryption) */
#define RTE_MACSEC_AN_MASK	0x03 /**< Association number mask in tci_an */
#define RTE_MACSEC_NUM_AN	4    /**< 2 bits for the association number */
#define RTE_MACSEC_SALT_LEN	12   /**< Salt length for MACsec SA */

/**
 * MACsec Header
 */
struct rte_macsec_hdr {
	/* SecTAG */
	uint8_t  tci_an;	/**< Tag control information and Association number of SC */
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	uint8_t short_length : 6; /**< Short Length */
	uint8_t unused : 2;
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint8_t unused : 2;
	uint8_t short_length : 6;
#endif
	rte_be32_t packet_number; /**< Packet number to support replay protection */
	uint8_t secure_channel_id[8]; /* optional */
} __rte_packed;

#ifdef __cplusplus
}
#endif

#endif /* RTE_MACSEC_H_ */
