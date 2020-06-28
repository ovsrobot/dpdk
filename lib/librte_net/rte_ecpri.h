/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#ifndef _RTE_ECPRI_H_
#define _RTE_ECPRI_H_

#include <stdint.h>
#include <rte_byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * eCPRI Protocol Revision 1.0, 1.1, 1.2, 2.0: 0001b
 * Other values are reserved for future
 */
#define RTE_ECPRI_REV_UPTO_20		1

/**
 * eCPRI message types in specifications
 * IWF* types will only be supported from rev.2
 */
#define RTE_ECPRI_MSG_TYPE_IQ_DATA	0
#define RTE_ECPRI_MSG_TYPE_BIT_SEQ	1
#define RTE_ECPRI_MSG_TYPE_RTC_CTRL	2
#define RTE_ECPRI_MSG_TYPE_GEN_DATA	3
#define RTE_ECPRI_MSG_TYPE_RM_ACC	4
#define RTE_ECPRI_MSG_TYPE_DLY_MSR	5
#define RTE_ECPRI_MSG_TYPE_RMT_RST	6
#define RTE_ECPRI_MSG_TYPE_EVT_IND	7
#define RTE_ECPRI_MSG_TYPE_IWF_UP	8
#define RTE_ECPRI_MSG_TYPE_IWF_OPT	9
#define RTE_ECPRI_MSG_TYPE_IWF_MAP	10
#define RTE_ECPRI_MSG_TYPE_IWF_DCTRL	11

/**
 * eCPRI Common Header
 */
RTE_STD_C11
struct rte_ecpri_common_hdr {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	uint32_t size:16;		/**< Payload Size */
	uint32_t type:8;		/**< Message Type */
	uint32_t c:1;			/**< Concatenation Indicator */
	uint32_t res:3;			/**< Reserved */
	uint32_t revision:4;		/**< Protocol Revision */
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint32_t revision:4;		/**< Protocol Revision */
	uint32_t res:3;			/**< Reserved */
	uint32_t c:1;			/**< Concatenation Indicator */
	uint32_t type:8;		/**< Message Type */
	uint32_t size:16;		/**< Payload Size */
#endif
} __rte_packed;

/**
 * eCPRI Message Header of Type #0: IQ Data
 */
struct rte_ecpri_msg_iq_data {
	rte_be16_t pc_id;		/**< Physical channel ID */
	rte_be16_t seq_id;		/**< Sequence ID */
};

/**
 * eCPRI Message Header of Type #1: Bit Sequence
 */
struct rte_ecpri_msg_bit_seq {
	rte_be16_t pc_id;		/**< Physical channel ID */
	rte_be16_t seq_id;		/**< Sequence ID */
};

/**
 * eCPRI Message Header of Type #2: Real-Time Control Data
 */
struct rte_ecpri_msg_rtc_ctrl {
	rte_be16_t rtc_id;		/**< Real-Time Control Data ID */
	rte_be16_t seq_id;		/**< Sequence ID */
};

/**
 * eCPRI Message Header of Type #3: Generic Data Transfer
 */
struct rte_ecpri_msg_gen_data {
	rte_be32_t pc_id;		/**< Physical channel ID */
	rte_be32_t seq_id;		/**< Sequence ID */
};

/**
 * eCPRI Message Header of Type #4: Remote Memory Access
 */
RTE_STD_C11
struct rte_ecpri_msg_rm_access {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	uint32_t ele_id:16;		/**< Element ID */
	uint32_t rr:4;			/**< Req/Resp */
	uint32_t rw:4;			/**< Read/Write */
	uint32_t rma_id:8;		/**< Remote Memory Access ID */
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint32_t rma_id:8;		/**< Remote Memory Access ID */
	uint32_t rw:4;			/**< Read/Write */
	uint32_t rr:4;			/**< Req/Resp */
	uint32_t ele_id:16;		/**< Element ID */
#endif
	rte_be16_t addr_m;		/**< 48-bits address (16 MSB) */
	rte_be32_t addr_l;		/**< 48-bits address (32 LSB) */
	rte_be16_t length;		/**< number of bytes */
} __rte_packed;

/**
 * eCPRI Message Header of Type #5: One-Way Delay Measurement
 */
struct rte_ecpri_msg_delay_measure {
	uint8_t msr_id;			/**< Measurement ID */
	uint8_t act_type;		/**< Action Type */
};

/**
 * eCPRI Message Header of Type #6: Remote Reset
 */
struct rte_ecpri_msg_remote_reset {
	uint8_t msr_id;			/**< Measurement ID */
	uint8_t act_type;		/**< Action Type */
};

/**
 * eCPRI Message Header of Type #7: Event Indication
 */
struct rte_ecpri_msg_event_ind {
	uint8_t evt_id;			/**< Event ID */
	uint8_t evt_type;		/**< Event Type */
	uint8_t seq;			/**< Sequence Number */
	uint8_t number;			/**< Number of Faults/Notif */
};

/**
 * eCPRI Message Header Format: Common Header + Message Types
 */
RTE_STD_C11
struct rte_ecpri_msg_hdr {
	struct rte_ecpri_common_hdr common;
	union {
		struct rte_ecpri_msg_iq_data type0;
		struct rte_ecpri_msg_bit_seq type1;
		struct rte_ecpri_msg_rtc_ctrl type2;
		struct rte_ecpri_msg_bit_seq type3;
		struct rte_ecpri_msg_rm_access type4;
		struct rte_ecpri_msg_delay_measure type5;
		struct rte_ecpri_msg_remote_reset type6;
		struct rte_ecpri_msg_event_ind type7;
		uint32_t dummy[3];
	};
};

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ECPRI_H_ */
