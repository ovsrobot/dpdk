/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_HWIF_H_
#define _SPNIC_HWIF_H_

#define SPNIC_WAIT_DOORBELL_AND_OUTBOUND_TIMEOUT	60000
#define SPNIC_PCIE_LINK_DOWN		0xFFFFFFFF

/* PCIe bar space */
#define SPNIC_VF_PCI_CFG_REG_BAR	0
#define SPNIC_PF_PCI_CFG_REG_BAR	1

#define SPNIC_PCI_INTR_REG_BAR		2
#define SPNIC_PCI_MGMT_REG_BAR		3 /* Only PF has mgmt bar */
#define SPNIC_PCI_DB_BAR		4

#define SPNIC_DB_DWQE_SIZE		0x00400000

/* Doorbell or direct wqe page size is 4K */
#define SPNIC_DB_PAGE_SIZE		0x00001000ULL
#define SPNIC_DWQE_OFFSET		0x00000800ULL

#define SPNIC_DB_MAX_AREAS	(SPNIC_DB_DWQE_SIZE / SPNIC_DB_PAGE_SIZE)

enum func_type {
	TYPE_PF,
	TYPE_VF,
	TYPE_PPF,
	TYPE_UNKNOWN
};

enum spnic_msix_state {
	SPNIC_MSIX_ENABLE,
	SPNIC_MSIX_DISABLE
};

struct spnic_free_db_area {
	u32 db_idx[SPNIC_DB_MAX_AREAS];

	u32 num_free;

	u32 alloc_pos;
	u32 return_pos;
	u32 db_max_areas;

	/* Spinlock for allocating doorbell area */
	rte_spinlock_t idx_lock;
};

struct spnic_func_attr {
	u16 func_global_idx;
	u8 port_to_port_idx;
	u8 pci_intf_idx;
	u8 vf_in_pf;
	enum func_type func_type;

	u8 mpf_idx;

	u8 ppf_idx;

	u16 num_irqs; /* Max: 2 ^ 15 */
	u8 num_aeqs; /* Max: 2 ^ 3 */
	u8 num_ceqs; /* Max: 2 ^ 7 */

	u8 num_dma_attr; /* Max: 2 ^ 6 */

	u16 global_vf_id_of_pf;
};

struct spnic_hwif {
	/* Configure virtual address, PF is bar1, VF is bar0/1 */
	u8 *cfg_regs_base;
	/* Interrupt configuration register address, PF is bar2, VF is bar2/3 */
	u8 *intr_regs_base;
	/* For PF bar3 virtual address, if function is VF should set NULL */
	u8 *mgmt_regs_base;
	u8 *db_base;
	u64 db_dwqe_len;
	struct spnic_free_db_area free_db_area;

	struct spnic_func_attr attr;

	void *pdev;
};

enum spnic_outbound_ctrl {
	ENABLE_OUTBOUND  = 0x0,
	DISABLE_OUTBOUND = 0x1
};

enum spnic_doorbell_ctrl {
	ENABLE_DOORBELL  = 0x0,
	DISABLE_DOORBELL = 0x1
};

enum spnic_pf_status {
	SPNIC_PF_STATUS_INIT = 0X0,
	SPNIC_PF_STATUS_ACTIVE_FLAG = 0x11,
	SPNIC_PF_STATUS_FLR_START_FLAG = 0x12,
	SPNIC_PF_STATUS_FLR_FINISH_FLAG = 0x13
};

#define SPNIC_HWIF_NUM_AEQS(hwif)		((hwif)->attr.num_aeqs)
#define SPNIC_HWIF_NUM_IRQS(hwif)		((hwif)->attr.num_irqs)
#define SPNIC_HWIF_GLOBAL_IDX(hwif)		((hwif)->attr.func_global_idx)
#define SPNIC_HWIF_GLOBAL_VF_OFFSET(hwif) ((hwif)->attr.global_vf_id_of_pf)
#define SPNIC_HWIF_PPF_IDX(hwif)		((hwif)->attr.ppf_idx)
#define SPNIC_PCI_INTF_IDX(hwif)		((hwif)->attr.pci_intf_idx)

#define SPNIC_FUNC_TYPE(dev)		((dev)->hwif->attr.func_type)
#define SPNIC_IS_PF(dev)		(SPNIC_FUNC_TYPE(dev) == TYPE_PF)
#define SPNIC_IS_VF(dev)		(SPNIC_FUNC_TYPE(dev) == TYPE_VF)
#define SPNIC_IS_PPF(dev)		(SPNIC_FUNC_TYPE(dev) == TYPE_PPF)

u32 spnic_hwif_read_reg(struct spnic_hwif *hwif, u32 reg);

void spnic_hwif_write_reg(struct spnic_hwif *hwif, u32 reg, u32 val);

void spnic_set_msix_state(struct spnic_hwdev *hwdev, u16 msix_idx,
			  enum spnic_msix_state flag);

void spnic_misx_intr_clear_resend_bit(struct spnic_hwdev *hwdev, u16 msix_idx,
				       u8 clear_resend_en);

u16 spnic_global_func_id(struct spnic_hwdev *hwdev);

u8 spnic_pf_id_of_vf(struct spnic_hwdev *hwdev);

u8 spnic_pcie_itf_id(struct spnic_hwdev *hwdev);

enum func_type spnic_func_type(struct spnic_hwdev *hwdev);

u16 spnic_glb_pf_vf_offset(struct spnic_hwdev *hwdev);

void spnic_set_pf_status(struct spnic_hwif *hwif,
			 enum spnic_pf_status status);

enum spnic_pf_status spnic_get_pf_status(struct spnic_hwif *hwif);

int spnic_alloc_db_addr(struct spnic_hwdev *hwdev, void **db_base, void **dwqe_base);

void spnic_free_db_addr(struct spnic_hwdev *hwdev, const void *db_base,
			__rte_unused void *dwqe_base);

void spnic_disable_doorbell(struct spnic_hwif *hwif);

void spnic_enable_doorbell(struct spnic_hwif *hwif);

int spnic_init_hwif(struct spnic_hwdev *hwdev);

void spnic_free_hwif(struct spnic_hwdev *hwdev);

#endif /* _SPNIC_HWIF_H_ */
