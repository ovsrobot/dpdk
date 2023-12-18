/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright(c) 2023 Intel Corporation
 */

#ifndef ADF_TRANSPORT_ACCESS_MACROS_VQAT_H
#define ADF_TRANSPORT_ACCESS_MACROS_VQAT_H

#define ADF_RINGS_PER_INT_SRCSEL_VQAT 2
#define ADF_BANK_INT_SRC_SEL_MASK_VQAT 0x44UL
#define ADF_BANK_INT_FLAG_CLEAR_MASK_VQAT 0x3
#define ADF_RING_BUNDLE_SIZE_VQAT 0x2000
#define ADF_RING_CSR_ADDR_OFFSET_VQAT 0x0
#define ADF_RING_CSR_RING_CONFIG_VQAT ADF_VQAT_R0_CONFIG
#define ADF_RING_CSR_RING_LBASE_VQAT ADF_VQAT_R0_LBASE
#define ADF_RING_CSR_RING_UBASE_VQAT ADF_VQAT_R0_UBASE
#define ADF_RING_CSR_RP_IDX_TX 0
#define ADF_RING_CSR_RP_IDX_RX 1

#define BUILD_RING_BASE_ADDR_VQAT(addr, size) \
	((((addr) >> 6) & (0xFFFFFFFFFFFFFFFFULL << (size))) << 6)
#define READ_CSR_RING_HEAD_VQAT(csr_base_addr, bank, ring) \
	ADF_CSR_RD((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_VQAT, \
		(ADF_RING_BUNDLE_SIZE_VQAT * (bank)) + \
		ADF_RING_CSR_RING_HEAD + ((ring) << 2))
#define READ_CSR_RING_TAIL_VQAT(csr_base_addr, bank, ring) \
	ADF_CSR_RD((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_VQAT, \
		(ADF_RING_BUNDLE_SIZE_VQAT * (bank)) + \
		ADF_RING_CSR_RING_TAIL + ((ring) << 2))
#define READ_CSR_STAT_VQAT(csr_base_addr, bank) \
	ADF_CSR_RD((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_VQAT, \
		(ADF_RING_BUNDLE_SIZE_VQAT * (bank)) + \
		ADF_RING_CSR_STAT)
#define READ_CSR_UO_STAT_VQAT(csr_base_addr, bank) \
	ADF_CSR_RD((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_VQAT, \
		(ADF_RING_BUNDLE_SIZE_VQAT * (bank)) + \
		ADF_RING_CSR_UO_STAT)
#define READ_CSR_E_STAT_VQAT(csr_base_addr, bank) \
	ADF_CSR_RD((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_VQAT, \
		(ADF_RING_BUNDLE_SIZE_VQAT * (bank)) + \
		ADF_RING_CSR_E_STAT)
#define READ_CSR_NE_STAT_VQAT(csr_base_addr, bank) \
	ADF_CSR_RD((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_VQAT, \
		(ADF_RING_BUNDLE_SIZE_VQAT * (bank)) + \
		ADF_RING_CSR_NE_STAT)
#define READ_CSR_NF_STAT_VQAT(csr_base_addr, bank) \
	ADF_CSR_RD((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_VQAT, \
		(ADF_RING_BUNDLE_SIZE_VQAT * (bank)) + \
		ADF_RING_CSR_NF_STAT)
#define READ_CSR_F_STAT_VQAT(csr_base_addr, bank) \
	ADF_CSR_RD((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_VQAT, \
		(ADF_RING_BUNDLE_SIZE_VQAT * (bank)) + \
		ADF_RING_CSR_F_STAT)
#define READ_CSR_C_STAT_VQAT(csr_base_addr, bank) \
	ADF_CSR_RD((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_VQAT, \
		(ADF_RING_BUNDLE_SIZE_VQAT * (bank)) + \
		ADF_RING_CSR_C_STAT)
#define READ_CSR_RING_CONFIG_VQAT(csr_base_addr, bank, ring) \
	ADF_CSR_RD((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_VQAT, \
		(ADF_RING_BUNDLE_SIZE_VQAT * (bank)) + \
		ADF_RING_CSR_RING_CONFIG_VQAT + ((ring) << 2))
#define WRITE_CSR_RING_CONFIG_VQAT(csr_base_addr, bank, ring, value) \
	ADF_CSR_WR((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_VQAT, \
		(ADF_RING_BUNDLE_SIZE_VQAT * (bank)) + \
		ADF_RING_CSR_RING_CONFIG_VQAT + ((ring) << 2), (value))
#define WRITE_CSR_RING_BASE_VQAT(csr_base_addr, bank, ring, value)	\
do {									\
	void __iomem *_csr_base_addr = csr_base_addr;			\
	u32 _bank = bank;						\
	u32 _ring = ring;						\
	dma_addr_t _value = value;					\
	u32 l_base = 0, u_base = 0;					\
	l_base = (u32)((_value) & 0xFFFFFFFF);				\
	u_base = (u32)(((_value) & 0xFFFFFFFF00000000ULL) >> 32);	\
	ADF_CSR_WR((_csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_VQAT,	\
		(ADF_RING_BUNDLE_SIZE_VQAT * (_bank)) +			\
		ADF_RING_CSR_RING_LBASE_VQAT + ((_ring) << 2), l_base);	\
	ADF_CSR_WR((_csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_VQAT,	\
		(ADF_RING_BUNDLE_SIZE_VQAT * (_bank)) +			\
		ADF_RING_CSR_RING_UBASE_VQAT + ((_ring) << 2), u_base);	\
} while (0)

#endif
