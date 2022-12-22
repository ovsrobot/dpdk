/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#ifndef _RTE_PDCP_HDR_H_
#define _RTE_PDCP_HDR_H_

/**
 * @file
 *
 * PDCP-related defines
 *
 * Based on - ETSI TS 138 323 V17.1.0 (2022-08)
 * https://www.etsi.org/deliver/etsi_ts/138300_138399/138323/17.01.00_60/ts_138323v170100p.pdf
 */

#include <rte_byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 6.2.2.1 Data PDU for SRBs
 */
__extension__
struct rte_pdcp_cp_data_pdu_sn_12_hdr {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	uint8_t sn_11_8 : 4;	/**< Sequence number bits 8-11 */
	uint8_t r : 4;		/**< Reserved */
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint8_t r : 4;		/**< Reserved */
	uint8_t sn_11_8 : 4;	/**< Sequence number bits 8-11 */
#endif
	uint8_t sn_7_0;		/**< Sequence number bits 0-7 */
};

/**
 * 6.2.2.2 Data PDU for DRBs and MRBs with 12 bits PDCP SN
 */
__extension__
struct rte_pdcp_up_data_pdu_sn_12_hdr {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	uint8_t sn_11_8 : 4;	/**< Sequence number bits 8-11 */
	uint8_t r : 3;		/**< Reserved */
	uint8_t d_c : 1;	/**< D/C bit */
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint8_t d_c : 1;	/**< D/C bit */
	uint8_t r : 3;		/**< Reserved */
	uint8_t sn_11_8 : 4;	/**< Sequence number bits 8-11 */
#endif
	uint8_t sn_7_0;		/**< Sequence number bits 0-7 */
};

/**
 * 6.2.2.3 Data PDU for DRBs and MRBs with 18 bits PDCP SN
 */
__extension__
struct rte_pdcp_up_data_pdu_sn_18_hdr {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	uint8_t sn_17_16 : 2;	/**< Sequence number bits 16-17 */
	uint8_t r : 5;		/**< Reserved */
	uint8_t d_c : 1;	/**< D/C bit */
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint8_t d_c : 1;	/**< D/C bit */
	uint8_t r : 5;		/**< Reserved */
	uint8_t sn_17_16 : 2;	/**< Sequence number bits 16-17 */
#endif
	uint8_t sn_15_8;	/**< Sequence number bits 8-15 */
	uint8_t sn_7_0;		/**< Sequence number bits 0-7 */
};

/**
 * 6.2.3.1 Control PDU for PDCP status report
 */
__extension__
struct rte_pdcp_up_ctrl_pdu_hdr {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	uint8_t r : 4;		/**< Reserved */
	uint8_t pdu_type : 3;	/**< Control PDU type */
	uint8_t d_c : 1;	/**< D/C bit */
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint8_t d_c : 1;	/**< D/C bit */
	uint8_t pdu_type : 3;	/**< Control PDU type */
	uint8_t r : 4;		/**< Reserved */
#endif
};

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PDCP_HDR_H_ */
