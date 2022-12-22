/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#ifndef _PDCP_ENTITY_H_
#define _PDCP_ENTITY_H_

#include <rte_common.h>
#include <rte_crypto_sym.h>
#include <rte_mempool.h>
#include <rte_pdcp.h>
#include <rte_security.h>

struct entity_priv;

#define PDCP_PDU_HDR_SIZE_SN_12 (RTE_ALIGN_MUL_CEIL(12, 8) / 8)
#define PDCP_PDU_HDR_SIZE_SN_18 (RTE_ALIGN_MUL_CEIL(18, 8) / 8)

#define PDCP_GET_SN_12_FROM_COUNT(c) ((c) & 0xfff)
#define PDCP_GET_SN_18_FROM_COUNT(c) ((c) & 0x3ffff)

#define PDCP_GET_HFN_SN_12_FROM_COUNT(c) (((c) >> 12) & 0xfffff)
#define PDCP_GET_HFN_SN_18_FROM_COUNT(c) (((c) >> 18) & 0x3fff)

#define PDCP_SET_COUNT_FROM_HFN_SN_12(h, s) ((((h) & 0xfffff) << 12) | ((s) & 0xfff))
#define PDCP_SET_COUNT_FROM_HFN_SN_18(h, s) ((((h) & 0x3fff) << 18) | ((s) & 0x3ffff))

#define PDCP_SN_12_WINDOW_SZ 0x800
#define PDCP_SN_18_WINDOW_SZ 0x20000

#define PDCP_SN_12_HFN_MAX ((1 << (32 - 12)) - 1)
#define PDCP_SN_12_HFN_MIN 0
#define PDCP_SN_18_HFN_MAX ((1 << (32 - 18)) - 1)
#define PDCP_SN_18_HFN_MIN 0

/* IV generation function based on the entity configuration */
typedef void (*iv_gen_t)(struct rte_crypto_op *cop, const struct entity_priv *en_priv,
			 uint32_t count);

enum pdcp_pdu_type {
	PDCP_PDU_TYPE_CTRL = 0,
	PDCP_PDU_TYPE_DATA = 1,
};

enum pdcp_up_ctrl_pdu_type {
	PDCP_UP_CTRL_PDU_TYPE_STATUS_REPORT,
	PDCP_UP_CTRL_PDU_TYPE_ROHC_FEEDBACK,
	PDCP_UP_CTRL_PDU_TYPE_EHC_FEEDBACK,
	PDCP_UP_CRTL_PDU_TYPE_UDC_FEEDBACK
};

struct entity_state {
	uint32_t rx_next;
	uint32_t tx_next;
	uint32_t rx_deliv;
	uint32_t rx_reord;
};

union auth_iv_partial {
	/* For AES-CMAC, there is no IV, but message gets prepended */
	struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
		uint64_t count : 32;
		uint64_t zero_38_39 : 2;
		uint64_t direction : 1;
		uint64_t bearer : 5;
		uint64_t zero_40_63 : 24;
#else
		uint64_t count : 32;
		uint64_t bearer : 5;
		uint64_t direction : 1;
		uint64_t zero_38_39 : 2;
		uint64_t zero_40_63 : 24;
#endif
	} aes_cmac;
	struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
		uint64_t count : 32;
		uint64_t zero_37_39 : 3;
		uint64_t bearer : 5;
		uint64_t zero_40_63 : 24;

		uint64_t rsvd_65_71 : 7;
		uint64_t direction_64 : 1;
		uint64_t rsvd_72_111 : 40;
		uint64_t rsvd_113_119 : 7;
		uint64_t direction_112 : 1;
		uint64_t rsvd_120_127 : 8;
#else
		uint64_t count : 32;
		uint64_t bearer : 5;
		uint64_t zero_37_39 : 3;
		uint64_t zero_40_63 : 24;

		uint64_t direction_64 : 1;
		uint64_t rsvd_65_71 : 7;
		uint64_t rsvd_72_111 : 40;
		uint64_t direction_112 : 1;
		uint64_t rsvd_113_119 : 7;
		uint64_t rsvd_120_127 : 8;
#endif
	} zs;
	uint64_t u64[2];
};

union cipher_iv_partial {
	struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
		uint64_t count : 32;
		uint64_t zero_38_39 : 2;
		uint64_t direction : 1;
		uint64_t bearer : 5;
		uint64_t zero_40_63 : 24;

		uint64_t zero_64_127;
#else
		uint64_t count : 32;
		uint64_t bearer : 5;
		uint64_t direction : 1;
		uint64_t zero_38_39 : 2;
		uint64_t zero_40_63 : 24;

		uint64_t zero_64_127;
#endif
	} aes_ctr;
	struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
		uint64_t count : 32;
		uint64_t zero_38_39 : 2;
		uint64_t direction : 1;
		uint64_t bearer : 5;
		uint64_t zero_40_63 : 24;

		uint64_t rsvd_64_127;
#else
		uint64_t count : 32;
		uint64_t bearer : 5;
		uint64_t direction : 1;
		uint64_t zero_38_39 : 2;
		uint64_t zero_40_63 : 24;

		uint64_t rsvd_64_127;
#endif
	} zs;
	uint64_t u64[2];
};

/*
 * Layout of PDCP entity: [rte_pdcp_entity] [entity_priv] [entity_dl/ul]
 */

struct entity_priv {
	/** Crypto sym session. */
	struct rte_cryptodev_sym_session *crypto_sess;
	/** Entity specific IV generation function. */
	iv_gen_t iv_gen;
	/** Pre-prepared auth IV. */
	union auth_iv_partial auth_iv_part;
	/** Pre-prepared cipher IV. */
	union cipher_iv_partial cipher_iv_part;
	/** Entity state variables. */
	struct entity_state state;
	/** Flags. */
	struct {
		/** PDCP PDU has 4 byte MAC-I. */
		uint64_t is_authenticated : 1;
		/** Cipher offset & length in bits. */
		uint64_t is_ciph_in_bits : 1;
		/** Auth offset & length in bits. */
		uint64_t is_auth_in_bits : 1;
		/** Is UL/transmitting PDCP entity */
		uint64_t is_ul_entity : 1;
	} flags;
	/** Crypto op pool. */
	struct rte_mempool *cop_pool;
	/** PDCP header size. */
	uint8_t hdr_sz;
	/** PDCP AAD size. For AES-CMAC, additional message is prepended for the operation. */
	uint8_t aad_sz;
	/** Device ID of the device to be used for offload. */
	uint8_t dev_id;
};

struct entity_priv_dl_part {
	/* TODO - when in-order-delivery is supported, post PDCP packets would need to cached. */
	uint8_t dummy;
};

struct entity_priv_ul_part {
	/*
	 * TODO - when re-establish is supported, both plain & post PDCP packets would need to be
	 * cached.
	 */
	uint8_t dummy;
};

static inline struct entity_priv *
entity_priv_get(const struct rte_pdcp_entity *entity) {
	return RTE_PTR_ADD(entity, sizeof(struct rte_pdcp_entity));
}

static inline struct entity_priv_dl_part *
entity_dl_part_get(const struct rte_pdcp_entity *entity) {
	return RTE_PTR_ADD(entity, sizeof(struct rte_pdcp_entity) + sizeof(struct entity_priv));
}

static inline struct entity_priv_ul_part *
entity_ul_part_get(const struct rte_pdcp_entity *entity) {
	return RTE_PTR_ADD(entity, sizeof(struct rte_pdcp_entity) + sizeof(struct entity_priv));
}

static inline int
pdcp_hdr_size_get(enum rte_security_pdcp_sn_size sn_size)
{
	return RTE_ALIGN_MUL_CEIL(sn_size, 8) / 8;
}

#endif /* _PDCP_ENTITY_H_ */
