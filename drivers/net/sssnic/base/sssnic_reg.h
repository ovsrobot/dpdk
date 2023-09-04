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
