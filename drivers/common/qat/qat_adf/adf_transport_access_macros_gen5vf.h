/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 * Copyright(c) 2023 Intel Corporation
 */

#ifndef ADF_TRANSPORT_ACCESS_MACROS_GEN5VF_H
#define ADF_TRANSPORT_ACCESS_MACROS_GEN5VF_H

#include "adf_transport_access_macros.h"
#include "adf_transport_access_macros_gen5.h"

#define ADF_RING_CSR_ADDR_OFFSET_GEN5VF 0x0

#define WRITE_CSR_RING_BASE_GEN5VF(csr_base_addr, bank, ring, value) \
do { \
	uint32_t l_base = 0, u_base = 0; \
	l_base = (uint32_t)(value & 0xFFFFFFFF); \
	u_base = (uint32_t)((value & 0xFFFFFFFF00000000ULL) >> 32); \
	ADF_CSR_WR(csr_base_addr + ADF_RING_CSR_ADDR_OFFSET_GEN5VF, \
		(ADF_RING_BUNDLE_SIZE_GEN5 * bank) + \
		ADF_RING_CSR_RING_LBASE_GEN5 + (ring << 2),	\
		l_base);	\
	ADF_CSR_WR(csr_base_addr + ADF_RING_CSR_ADDR_OFFSET_GEN5VF,	\
		 (ADF_RING_BUNDLE_SIZE_GEN5 * bank) + \
		ADF_RING_CSR_RING_UBASE_GEN5 + (ring << 2),		\
		u_base);	\
} while (0)

#define WRITE_CSR_RING_CONFIG_GEN5VF(csr_base_addr, bank, ring, value) \
	ADF_CSR_WR(csr_base_addr + ADF_RING_CSR_ADDR_OFFSET_GEN5VF,	\
		 (ADF_RING_BUNDLE_SIZE_GEN5 * bank) + \
		ADF_RING_CSR_RING_CONFIG_GEN5 + (ring << 2), value)

#define WRITE_CSR_RING_TAIL_GEN5VF(csr_base_addr, bank, ring, value) \
	ADF_CSR_WR((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_GEN5VF, \
		(ADF_RING_BUNDLE_SIZE_GEN5 * (bank)) + \
		ADF_RING_CSR_RING_TAIL + ((ring) << 2), (value))

#define WRITE_CSR_RING_HEAD_GEN5VF(csr_base_addr, bank, ring, value) \
	ADF_CSR_WR((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_GEN5VF, \
		(ADF_RING_BUNDLE_SIZE_GEN5 * (bank)) + \
		ADF_RING_CSR_RING_HEAD + ((ring) << 2), (value))

#define WRITE_CSR_RING_SRV_ARB_EN_GEN5VF(csr_base_addr, bank, value) \
	ADF_CSR_WR((csr_base_addr) + ADF_RING_CSR_ADDR_OFFSET_GEN5VF, \
		(ADF_RING_BUNDLE_SIZE_GEN5 * (bank)) + \
		ADF_RING_CSR_RING_SRV_ARB_EN, (value))

#endif
