/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_REG_H_
#define _SSSNIC_REG_H_

#include <rte_io.h>

/* registers of config */
#define SSSNIC_ATTR0_REG 0x0
#define SSSNIC_ATTR1_REG 0x4
#define SSSNIC_ATTR2_REG 0x8
#define SSSNIC_ATTR3_REG 0xC
#define SSSNIC_ATTR4_REG 0x10
#define SSSNIC_ATTR5_REG 0x14
#define SSSNIC_ATTR6_REG 0x18

#define SSSNIC_MSIX_CTRL_REG 0x58

#define SSSNIC_EVENTQ_CI_CTRL_REG 0x50
#define SSSNIC_EVENTQ_IDX_SEL_REG 0x210
#define SSSNIC_EVENTQ_CTRL0_REG 0x200
#define SSSNIC_EVENTQ_CTRL1_REG 0x204
#define SSSNIC_EVENTQ_CONS_IDX_REG 0x208
#define SSSNIC_EVENTQ_PROD_IDX_REG 0x20c
#define SSSNIC_EVENTQ_PAGE_ADDR_REG 0x240

#define SSSNIC_MBOX_SEND_DATA_BASE_REG 0x80
#define SSSNIC_MBOX_SEND_CTRL0_REG 0x100
#define SSSNIC_MBOX_SEND_CTRL1_REG 0x104
#define SSSNIC_MBOX_SEND_RESULT_ADDR_H_REG 0x108
#define SSSNIC_MBOX_SEND_RESULT_ADDR_L_REG 0x10c

/* registers of mgmt */
#define SSSNIC_AF_ELECTION_REG 0x6000
#define SSSNIC_MF_ELECTION_REG 0x6020

struct sssnic_attr0_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t func_idx : 12;
			uint32_t pf_idx : 5;
			uint32_t pci_idx : 3;
			uint32_t vf_off : 8; /* vf offset in pf */
			uint32_t func_type : 1;
			uint32_t resvd_0 : 4;
		};
	};
};

struct sssnic_attr1_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t af_idx : 6;
			uint32_t resvd_0 : 2;
			uint32_t num_aeq : 2;
			uint32_t resvd_1 : 20;
			uint32_t mgmt_init_status : 1;
			uint32_t pf_init_status : 1;
		};
	};
};

struct sssnic_attr2_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t num_ceq : 9;
			uint32_t num_dma_attr : 3;
			uint32_t resvd_0 : 4;
			uint32_t num_irq : 11;
			uint32_t resvd_1 : 5;
		};
	};
};

struct sssnic_attr3_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t global_vf_off1 : 12;
			uint32_t resvd_0 : 4;
			uint32_t global_vf_off : 12; /*global vf offset*/
			uint32_t resvd_1 : 4;
		};
	};
};

struct sssnic_attr4_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t db_ctrl : 1;
			uint32_t resvd_0 : 31;
		};
	};
};

struct sssnic_attr5_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t outbound_ctrl : 1;
			uint32_t resvd_0 : 31;
		};
	};
};

struct sssnic_attr6_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t pf_status : 16;
			uint32_t resvd_0 : 6;
			uint32_t msix_en : 1;
			uint32_t max_queues : 9;
		};
	};
};

struct sssnic_af_election_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t func_idx : 6;
			uint32_t resvd_0 : 26;
		};
	};
};

struct sssnic_mf_election_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t func_idx : 5;
			uint32_t resvd_0 : 27;
		};
	};
};

struct sssnic_msix_ctrl_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t resend_timer_clr : 1;
			uint32_t int_msk_set : 1;
			uint32_t int_msk_clr : 1;
			uint32_t auto_msk_set : 1;
			uint32_t auto_msk_clr : 1;
			uint32_t resvd_0 : 17;
			uint32_t msxi_idx : 10;
		};
	};
};

#define SSSNIC_REG_EVENTQ_INTR_MODE_0 0 /* armed mode */
#define SSSNIC_REG_EVENTQ_INTR_MODE_1 1 /* allway mode */
#define SSSNIC_REG_EVENTQ_DEF_DMA_ATTR 0
struct sssnic_eventq_ctrl0_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t intr_idx : 10;
			uint32_t resvd_0 : 2;
			uint32_t dma_attr : 6;
			uint32_t resvd_1 : 2;
			uint32_t pci_idx : 1;
			uint32_t resvd_2 : 8;
			uint32_t intr_mode : 1;
		};
	};
};

struct sssnic_eventq_ctrl1_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t depth : 21;
			uint32_t resvd_0 : 3;
			uint32_t entry_size : 2;
			uint32_t resvd_1 : 2;
			uint32_t page_size : 4;
		};
	};
};

struct sssnic_eventq_ci_ctrl_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t ci : 21;
			uint32_t informed : 1;
			uint32_t resvd_0 : 8;
			uint32_t qid : 2;
		};
	};
};

#define SSSNIC_REG_MBOX_TX_DONE 0 /* Mailbox transmission is done */
#define SSSNIC_REG_MBOX_TX_READY 1 /* Mailbox is ready to transmit */
struct sssnic_mbox_send_ctrl0_reg {
	union {
		uint32_t u32;
		struct {
			/* enable to inform source eventq if tx done */
			uint32_t src_eq_en : 1;
			/* mailbox tx result, see SSSNIC_REG_MBOX_TX_XX */
			uint32_t tx_status : 1;
			uint32_t resvd0 : 14;
			/* destination function where the mbox send to */
			uint32_t func : 13;
			uint32_t resvd1 : 3;
		};
	};
};

struct sssnic_mbox_send_ctrl1_reg {
	union {
		uint32_t u32;
		struct {
			uint32_t resvd0 : 10;
			/* Destination eventq in the mgmt cpu */
			uint32_t dst_eq : 2;
			/* eventq that will be informed if tx done */
			uint32_t src_eq : 2;
			uint32_t dma_attr : 6;
			/* mailbox message size include header and body
			 * must 4byte align and unit is 4byte
			 */
			uint32_t tx_size : 5;
			uint32_t ordering : 2;
			uint32_t resvd1 : 1;
			/*write result back to DMA address of sending result  */
			uint32_t wb : 1;
			uint32_t resvd2 : 3;
		};
	};
};

static inline uint32_t
sssnic_cfg_reg_read(struct sssnic_hw *hw, uint32_t reg)
{
	return rte_be_to_cpu_32(rte_read32(hw->cfg_base_addr + reg));
}

static inline void
sssnic_cfg_reg_write(struct sssnic_hw *hw, uint32_t reg, uint32_t val)
{
	rte_write32(rte_cpu_to_be_32(val), hw->cfg_base_addr + reg);
}

static inline uint32_t
sssnic_mgmt_reg_read(struct sssnic_hw *hw, uint32_t reg)
{
	return rte_be_to_cpu_32(rte_read32(hw->mgmt_base_addr + reg));
}

static inline void
sssnic_mgmt_reg_write(struct sssnic_hw *hw, uint32_t reg, uint32_t val)
{
	rte_write32(rte_cpu_to_be_32(val), hw->mgmt_base_addr + reg);
}

#endif /*_SSSNIC_REG_H_*/
