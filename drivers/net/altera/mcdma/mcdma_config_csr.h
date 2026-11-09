/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2026 Altera Corporation
 */
#ifndef __MCDMA_CONFIG_CSR_H_
#define __MCDMA_CONFIG_CSR_H_

#include <rte_bitops.h>

typedef enum {
	MCDMA_QCSR_Q_CTRL			= 0x00U,
	/* QCSR_Reserved		= 0x04U, */
	MCDMA_QCSR_Q_START_ADDR_L		= 0x08U,
	MCDMA_QCSR_Q_START_ADDR_H		= 0x0CU,
	MCDMA_QCSR_Q_SIZE			= 0x10U,
	MCDMA_QCSR_Q_TAIL_POINTER		= 0x14U,
	MCDMA_QCSR_Q_HEAD_POINTER		= 0x18U,
	MCDMA_QCSR_Q_COMPLETED_POINTER		= 0x1CU,
	MCDMA_QCSR_Q_CONSUMED_HEAD_ADDR_L	= 0x20U,
	MCDMA_QCSR_Q_CONSUMED_HEAD_ADDR_H	= 0x24U,
	MCDMA_QCSR_Q_BATCH_DELAY		= 0x28U,
	MCDMA_QCSR_Q_DEBUG_STATUS_1		= 0x38U,
	MCDMA_QCSR_Q_DEBUG_STATUS_2		= 0x3CU,
	MCDMA_QCSR_Q_DATA_DRP_ERR_CTR		= 0x40U,
	MCDMA_QCSR_Q_PAYLOAD_COUNT		= 0x44U,
	MCDMA_QCSR_Q_RESET			= 0x48U,
	MCDMA_QCSR_Q_CPL_TIMEOUT		= 0x4CU,
	MCDMA_QCSR_Q_REG_MAX			= 0xFFFFFFFFU
} mcdma_qcsr_reg_offset_t;

#define MCDMA_QCSR_Q(reg)			MCDMA_QCSR_Q##_##reg
#define MCDMA_QCSR_Q_RESET_MASK			RTE_GENMASK32(0, 0)
#define MCDMA_QCSR_Q_RESET_SHIFT		0

/* Q_DATA_DRP_ERR_CTR: valid in bit 20, drop count in bits [15:0] */
#define MCDMA_QCSR_DRP_CTR_VALID		RTE_BIT32(20)
#define MCDMA_QCSR_DRP_CTR_CNT_MASK		RTE_GENMASK32(15, 0)
#define MCDMA_QCSR_DRP_CTR_CLR_MASK		(MCDMA_QCSR_DRP_CTR_VALID | \
						 MCDMA_QCSR_DRP_CTR_CNT_MASK)
/* Error sticky bit in head / completed pointer registers */
#define MCDMA_QCSR_PTR_ERR_MASK			RTE_BIT32(24)

typedef union {
	struct {
		/*
		 * Enable. Once it is enabled, the DMA starts fetching pending
		 * descriptors and executing them.
		 */
		uint32_t q_en : 1;
		uint32_t rsv : 7;       /* Reserved. */
		uint32_t q_wb_en : 1;   /* If set, upon completion, do a write back. */
		uint32_t q_intr_en : 1; /* If set, upon completion generate MSI-X interrupt. */
		uint32_t rsvd : 22;     /* Reserved. */
	} field;
	uint32_t val;
} mcdma_qcsr_q_ctrl_t;

/*
 * The following "read only" registers are available for all functions, not only PF0:
 * VER_NUM (offset 9'h070)
 * P0_<H2D, D2H>_TPTR_AVL (offset 9'h100, 110)
 * PF<0,1,2,3,4,5,6,7>_PARAM_2 (Offset 9'h084, 094, 0A4, 0B4, 0C4, 0D4, 0E4, 0F4)
 */
typedef enum {
	MCDMA_CSR_CTRL			= 0x000U,
	/* Reserved: 0x004          */
	MCDMA_CSR_WB_INTR_DELAY		= 0x008U,
	/* Reserved: 0x00C - 0x01F  */
	/* VF Weight registers */
	MCDMA_CSR_VF_WEIGHT_0		= 0x020U,
	MCDMA_CSR_VF_WEIGHT_1		= 0x024U,
	MCDMA_CSR_VF_WEIGHT_2		= 0x028U,
	MCDMA_CSR_VF_WEIGHT_3		= 0x02CU,
	/* Reserved: 0x030 - 0x06F  */

	/* Version / IP params */
	MCDMA_CSR_VER_NUM		= 0x070U,
	MCDMA_CSR_IP_PARAM_1		= 0x074U,

	/* PF IP PARAM */
	MCDMA_CSR_PF0_IP_PARAM_1	= 0x080U,
	MCDMA_CSR_PF0_IP_PARAM_2	= 0x084U,
	/* Reserved: 0x088 - 0x08F  */
	MCDMA_CSR_PF1_IP_PARAM_1	= 0x090U,
	MCDMA_CSR_PF1_IP_PARAM_2	= 0x094U,
	/* Reserved: 0x098 - 0x09F  */
	MCDMA_CSR_PF2_IP_PARAM_1	= 0x0A0U,
	MCDMA_CSR_PF2_IP_PARAM_2	= 0x0A4U,
	/* Reserved: 0x0A8 - 0x0AF  */
	MCDMA_CSR_PF3_IP_PARAM_1	= 0x0B0U,
	MCDMA_CSR_PF3_IP_PARAM_2	= 0x0B4U,
	/* Reserved: 0x0B8 - 0x0BF  */
	MCDMA_CSR_PF4_IP_PARAM_1	= 0x0C0U,
	MCDMA_CSR_PF4_IP_PARAM_2	= 0x0C4U,
	/* Reserved: 0x0C8 - 0x0CF  */
	MCDMA_CSR_PF5_IP_PARAM_1	= 0x0D0U,
	MCDMA_CSR_PF5_IP_PARAM_2	= 0x0D4U,
	/* Reserved: 0x0D8 - 0x0DF  */
	MCDMA_CSR_PF6_IP_PARAM_1	= 0x0E0U,
	MCDMA_CSR_PF6_IP_PARAM_2	= 0x0E4U,
	/* Reserved: 0x0E8 - 0x0EF  */
	MCDMA_CSR_PF7_IP_PARAM_1	= 0x0F0U,
	MCDMA_CSR_PF7_IP_PARAM_2	= 0x0F4U,
	/* Reserved: 0x0F8 - 0x0FF  */

	/* Port H2D tail pointers */
	MCDMA_CSR_P0_H2D_TPTR_AVL	= 0x100U,
	MCDMA_CSR_P1_H2D_TPTR_AVL	= 0x104U,
	MCDMA_CSR_P2_H2D_TPTR_AVL	= 0x108U,
	MCDMA_CSR_P3_H2D_TPTR_AVL	= 0x10CU,

	/* Port D2H tail pointers */
	MCDMA_CSR_P0_D2H_TPTR_AVL	= 0x110U,
	MCDMA_CSR_P1_D2H_TPTR_AVL	= 0x114U,
	MCDMA_CSR_P2_D2H_TPTR_AVL	= 0x118U,
	MCDMA_CSR_P3_D2H_TPTR_AVL	= 0x11CU,

	/* Misc */
	MCDMA_CSR_SW_RESET		= 0x120U,
	/* Reserved: 0x125 - 0x127  */
	MCDMA_CSR_MSIX_WB_FIFO_STS	= 0x128U,
	/* Reserved: 0x12C - 0x14F  */

	/* Debug bank 1 */
	MCDMA_CSR_DBG1_REG00		= 0x150U,
	MCDMA_CSR_DBG1_REG01		= 0x154U,
	MCDMA_CSR_DBG1_REG02		= 0x158U,
	MCDMA_CSR_DBG1_REG03		= 0x15CU,
	MCDMA_CSR_DBG1_REG04		= 0x160U,
	MCDMA_CSR_DBG1_REG05		= 0x164U,
	MCDMA_CSR_DBG1_REG06		= 0x168U,
	MCDMA_CSR_DBG1_REG07		= 0x16CU,
	MCDMA_CSR_DBG1_REG08		= 0x170U,
	MCDMA_CSR_DBG1_REG09		= 0x174U,
	MCDMA_CSR_DBG1_REG10		= 0x178U,
	MCDMA_CSR_DBG1_REG11		= 0x17CU,
	MCDMA_CSR_DBG1_REG12		= 0x180U,
	MCDMA_CSR_DBG1_REG13		= 0x184U,
	MCDMA_CSR_DBG1_REG14		= 0x188U,
	MCDMA_CSR_DBG1_REG15		= 0x18CU,

	/* Debug bank 2 */
	MCDMA_CSR_DBG2_REG00		= 0x190U,
	MCDMA_CSR_DBG2_REG01		= 0x194U,
	MCDMA_CSR_DBG2_REG02		= 0x198U,
	MCDMA_CSR_DBG2_REG03		= 0x19CU,
	MCDMA_CSR_DBG2_REG04		= 0x1A0U,
	MCDMA_CSR_DBG2_REG05		= 0x1A4U,
	MCDMA_CSR_DBG2_REG06		= 0x1A8U,
	MCDMA_CSR_DBG2_REG07		= 0x1ACU,
	MCDMA_CSR_DBG2_REG08		= 0x1B0U,
	MCDMA_CSR_DBG2_REG09		= 0x1B4U,
	MCDMA_CSR_DBG2_REG10		= 0x1B8U,
	MCDMA_CSR_DBG2_REG11		= 0x1BCU,
	MCDMA_CSR_DBG2_REG12		= 0x1C0U,
	MCDMA_CSR_DBG2_REG13		= 0x1C4U,
	MCDMA_CSR_DBG2_REG14		= 0x1C8U,
	MCDMA_CSR_DBG2_REG15		= 0x1CCU,

	MCDMA_CSR_OFFSET_MAX		= 0xFFFFFFFFU   /* force 32-bit backing */
} mcdma_csr_offset_t;

#define MCDMA_CSR_PF_PARAM_STEP		0x10
#define MCDMA_CSR_PF_PARAM2_OFFSET(pf) \
	(MCDMA_CSR_PF0_IP_PARAM_2 + ((pf) * MCDMA_CSR_PF_PARAM_STEP))

/* NUM_DMA_CHAN_PER_PF : bits [31:16] */
#define MCDMA_NUM_CHAN_PER_PF_SHIFT	16U
#define MCDMA_NUM_CHAN_PER_PF_MASK	(0xFFFFU << MCDMA_NUM_CHAN_PER_PF_SHIFT)

/* NUM_DMA_CHAN_PER_VF : bits [15:0] */
#define MCDMA_NUM_CHAN_PER_VF_SHIFT	0U
#define MCDMA_NUM_CHAN_PER_VF_MASK	RTE_GENMASK32(15, 0)

#define MCDMA_GET_NUM_CHAN_PER_PF(reg_val) \
	(((reg_val) & MCDMA_NUM_CHAN_PER_PF_MASK) >> MCDMA_NUM_CHAN_PER_PF_SHIFT)

#define MCDMA_GET_NUM_CHAN_PER_VF(reg_val) \
	(((reg_val) & MCDMA_NUM_CHAN_PER_VF_MASK) >> MCDMA_NUM_CHAN_PER_VF_SHIFT)

static inline uint32_t mcdma_reg_readl(volatile void *addr)
{
	return *(volatile uint32_t *)addr;
}

static inline void mcdma_reg_writel(volatile void *addr, uint32_t value)
{
	*(volatile uint32_t *)addr = value;
}

static inline void mcdma_reg_updatel(volatile void *base, uint32_t offset,
				     uint32_t value, uint32_t shift, uint32_t mask)
{
	volatile void *addr = (volatile uint8_t *)base + offset;
	uint32_t tmp;

	tmp = mcdma_reg_readl(addr);
	tmp = (tmp & ~mask) | ((value << shift) & mask);
	mcdma_reg_writel(addr, tmp);
}

#endif /* __MCDMA_CONFIG_CSR_H_ */
