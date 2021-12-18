/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <rte_bus_pci.h>
#include "spnic_compat.h"
#include "spnic_csr.h"
#include "spnic_hwdev.h"
#include "spnic_hwif.h"

#define WAIT_HWIF_READY_TIMEOUT			10000

#define DB_IDX(db, db_base)	\
	((u32)(((ulong)(db) - (ulong)(db_base)) /	\
	SPNIC_DB_PAGE_SIZE))

#define SPNIC_AF0_FUNC_GLOBAL_IDX_SHIFT		0
#define SPNIC_AF0_P2P_IDX_SHIFT			12
#define SPNIC_AF0_PCI_INTF_IDX_SHIFT		17
#define SPNIC_AF0_VF_IN_PF_SHIFT		20
#define SPNIC_AF0_FUNC_TYPE_SHIFT		28

#define SPNIC_AF0_FUNC_GLOBAL_IDX_MASK		0xFFF
#define SPNIC_AF0_P2P_IDX_MASK			0x1F
#define SPNIC_AF0_PCI_INTF_IDX_MASK		0x7
#define SPNIC_AF0_VF_IN_PF_MASK			0xFF
#define SPNIC_AF0_FUNC_TYPE_MASK		0x1

#define SPNIC_AF0_GET(val, member)				\
	(((val) >> SPNIC_AF0_##member##_SHIFT) & SPNIC_AF0_##member##_MASK)

#define SPNIC_AF1_PPF_IDX_SHIFT			0
#define SPNIC_AF1_AEQS_PER_FUNC_SHIFT		8
#define SPNIC_AF1_MGMT_INIT_STATUS_SHIFT	30
#define SPNIC_AF1_PF_INIT_STATUS_SHIFT		31

#define SPNIC_AF1_PPF_IDX_MASK			0x3F
#define SPNIC_AF1_AEQS_PER_FUNC_MASK		0x3
#define SPNIC_AF1_MGMT_INIT_STATUS_MASK		0x1
#define SPNIC_AF1_PF_INIT_STATUS_MASK		0x1

#define SPNIC_AF1_GET(val, member)				\
	(((val) >> SPNIC_AF1_##member##_SHIFT) & SPNIC_AF1_##member##_MASK)

#define SPNIC_AF2_CEQS_PER_FUNC_SHIFT		0
#define SPNIC_AF2_DMA_ATTR_PER_FUNC_SHIFT	9
#define SPNIC_AF2_IRQS_PER_FUNC_SHIFT		16

#define SPNIC_AF2_CEQS_PER_FUNC_MASK		0x1FF
#define SPNIC_AF2_DMA_ATTR_PER_FUNC_MASK	0x7
#define SPNIC_AF2_IRQS_PER_FUNC_MASK		0x7FF

#define SPNIC_AF2_GET(val, member)				\
	(((val) >> SPNIC_AF2_##member##_SHIFT) & SPNIC_AF2_##member##_MASK)

#define SPNIC_AF3_GLOBAL_VF_ID_OF_NXT_PF_SHIFT	0
#define SPNIC_AF3_GLOBAL_VF_ID_OF_PF_SHIFT	16

#define SPNIC_AF3_GLOBAL_VF_ID_OF_NXT_PF_MASK	0xFFF
#define SPNIC_AF3_GLOBAL_VF_ID_OF_PF_MASK	0xFFF

#define SPNIC_AF3_GET(val, member)				\
	(((val) >> SPNIC_AF3_##member##_SHIFT) & SPNIC_AF3_##member##_MASK)

#define SPNIC_AF4_DOORBELL_CTRL_SHIFT		0
#define SPNIC_AF4_DOORBELL_CTRL_MASK		0x1

#define SPNIC_AF4_GET(val, member)				\
	(((val) >> SPNIC_AF4_##member##_SHIFT) & SPNIC_AF4_##member##_MASK)

#define SPNIC_AF4_SET(val, member)				\
	(((val) & SPNIC_AF4_##member##_MASK) << SPNIC_AF4_##member##_SHIFT)

#define SPNIC_AF4_CLEAR(val, member)				\
	((val) & (~(SPNIC_AF4_##member##_MASK <<		\
	SPNIC_AF4_##member##_SHIFT)))

#define SPNIC_AF5_OUTBOUND_CTRL_SHIFT		0
#define SPNIC_AF5_OUTBOUND_CTRL_MASK		0x1

#define SPNIC_AF5_GET(val, member)				\
	(((val) >> SPNIC_AF5_##member##_SHIFT) & SPNIC_AF5_##member##_MASK)

#define SPNIC_AF5_SET(val, member)				\
	(((val) & SPNIC_AF5_##member##_MASK) << SPNIC_AF5_##member##_SHIFT)

#define SPNIC_AF5_CLEAR(val, member)				\
	((val) & (~(SPNIC_AF5_##member##_MASK <<		\
	SPNIC_AF5_##member##_SHIFT)))

#define SPNIC_AF6_PF_STATUS_SHIFT		0
#define SPNIC_AF6_PF_STATUS_MASK		0xFFFF

#define SPNIC_AF6_SET(val, member)				\
	((((u32)(val)) & SPNIC_AF6_##member##_MASK) <<		\
	SPNIC_AF6_##member##_SHIFT)

#define SPNIC_AF6_GET(val, member)				\
	(((val) >> SPNIC_AF6_##member##_SHIFT) & SPNIC_AF6_##member##_MASK)

#define SPNIC_AF6_CLEAR(val, member)				\
	((val) & (~(SPNIC_AF6_##member##_MASK <<		\
	SPNIC_AF6_##member##_SHIFT)))

#define SPNIC_PPF_ELECTION_IDX_SHIFT		0

#define SPNIC_PPF_ELECTION_IDX_MASK		0x3F

#define SPNIC_PPF_ELECTION_SET(val, member)			\
	(((val) & SPNIC_PPF_ELECTION_##member##_MASK) <<	\
		SPNIC_PPF_ELECTION_##member##_SHIFT)

#define SPNIC_PPF_ELECTION_GET(val, member)			\
	(((val) >> SPNIC_PPF_ELECTION_##member##_SHIFT) &	\
		SPNIC_PPF_ELECTION_##member##_MASK)

#define SPNIC_PPF_ELECTION_CLEAR(val, member)			\
	((val) & (~(SPNIC_PPF_ELECTION_##member##_MASK	\
		<< SPNIC_PPF_ELECTION_##member##_SHIFT)))

#define SPNIC_MPF_ELECTION_IDX_SHIFT		0

#define SPNIC_MPF_ELECTION_IDX_MASK		0x1F

#define SPNIC_MPF_ELECTION_SET(val, member)			\
	(((val) & SPNIC_MPF_ELECTION_##member##_MASK) <<	\
		SPNIC_MPF_ELECTION_##member##_SHIFT)

#define SPNIC_MPF_ELECTION_GET(val, member)			\
	(((val) >> SPNIC_MPF_ELECTION_##member##_SHIFT) &	\
		SPNIC_MPF_ELECTION_##member##_MASK)

#define SPNIC_MPF_ELECTION_CLEAR(val, member)			\
	((val) & (~(SPNIC_MPF_ELECTION_##member##_MASK	\
		<< SPNIC_MPF_ELECTION_##member##_SHIFT)))

#define SPNIC_GET_REG_FLAG(reg)	((reg) & (~(SPNIC_REGS_FLAG_MAKS)))

#define SPNIC_GET_REG_ADDR(reg)	((reg) & (SPNIC_REGS_FLAG_MAKS))

#define SPNIC_IS_VF_DEV(pdev)	((pdev)->id.device_id == SPNIC_DEV_ID_VF)

u32 spnic_hwif_read_reg(struct spnic_hwif *hwif, u32 reg)
{
	if (SPNIC_GET_REG_FLAG(reg) == SPNIC_MGMT_REGS_FLAG)
		return be32_to_cpu(rte_read32(hwif->mgmt_regs_base +
				   SPNIC_GET_REG_ADDR(reg)));
	else
		return be32_to_cpu(rte_read32(hwif->cfg_regs_base +
				   SPNIC_GET_REG_ADDR(reg)));
}

void spnic_hwif_write_reg(struct spnic_hwif *hwif, u32 reg, u32 val)
{
	if (SPNIC_GET_REG_FLAG(reg) == SPNIC_MGMT_REGS_FLAG)
		rte_write32(cpu_to_be32(val),
		       hwif->mgmt_regs_base + SPNIC_GET_REG_ADDR(reg));
	else
		rte_write32(cpu_to_be32(val),
		       hwif->cfg_regs_base + SPNIC_GET_REG_ADDR(reg));
}

/**
 * Judge whether HW initialization ok
 *
 * @param[in] hwdev
 *   The pointer to the private hardware device object
 *
 * @retval zero: Success
 * @retval negative: Failure
 */
static int hwif_ready(struct spnic_hwdev *hwdev)
{
	u32 addr, attr1;

	addr   = SPNIC_CSR_FUNC_ATTR1_ADDR;
	attr1  = spnic_hwif_read_reg(hwdev->hwif, addr);
	if (attr1 == SPNIC_PCIE_LINK_DOWN)
		return -EBUSY;

	if (!SPNIC_AF1_GET(attr1, MGMT_INIT_STATUS))
		return -EBUSY;

	return 0;
}

static int wait_hwif_ready(struct spnic_hwdev *hwdev)
{
	ulong timeout = 0;

	do {
		if (!hwif_ready(hwdev))
			return 0;

		rte_delay_ms(1);
		timeout++;
	} while (timeout <= WAIT_HWIF_READY_TIMEOUT);

	PMD_DRV_LOG(ERR, "Hwif is not ready");
	return -EBUSY;
}

/**
 * Set the attributes as members in hwif
 *
 * @param[in] hwif
 *   The hardware interface of a pci function device
 * @param[in] attr0
 *   The first attribute that was read from the hw
 * @param[in] attr1
 *   The second attribute that was read from the hw
 * @param[in] attr2
 *   The third attribute that was read from the hw
 * @param[in] attr3
 *   The fourth attribute that was read from the hw
 */
static void set_hwif_attr(struct spnic_hwif *hwif, u32 attr0, u32 attr1,
			  u32 attr2, u32 attr3)
{
	hwif->attr.func_global_idx = SPNIC_AF0_GET(attr0, FUNC_GLOBAL_IDX);
	hwif->attr.port_to_port_idx = SPNIC_AF0_GET(attr0, P2P_IDX);
	hwif->attr.pci_intf_idx = SPNIC_AF0_GET(attr0, PCI_INTF_IDX);
	hwif->attr.vf_in_pf = SPNIC_AF0_GET(attr0, VF_IN_PF);
	hwif->attr.func_type = SPNIC_AF0_GET(attr0, FUNC_TYPE);

	hwif->attr.ppf_idx = SPNIC_AF1_GET(attr1, PPF_IDX);
	hwif->attr.num_aeqs = BIT(SPNIC_AF1_GET(attr1, AEQS_PER_FUNC));

	hwif->attr.num_ceqs = (u8)SPNIC_AF2_GET(attr2, CEQS_PER_FUNC);
	hwif->attr.num_irqs = SPNIC_AF2_GET(attr2, IRQS_PER_FUNC);
	hwif->attr.num_dma_attr = BIT(SPNIC_AF2_GET(attr2, DMA_ATTR_PER_FUNC));

	hwif->attr.global_vf_id_of_pf = SPNIC_AF3_GET(attr3,
						      GLOBAL_VF_ID_OF_PF);
}

/**
 * Read and set the attributes as members in hwif
 *
 * @param[in] hwif
 *   The hardware interface of a pci function device
 */
static void get_hwif_attr(struct spnic_hwif *hwif)
{
	u32 addr, attr0, attr1, attr2, attr3;

	addr   = SPNIC_CSR_FUNC_ATTR0_ADDR;
	attr0  = spnic_hwif_read_reg(hwif, addr);

	addr   = SPNIC_CSR_FUNC_ATTR1_ADDR;
	attr1  = spnic_hwif_read_reg(hwif, addr);

	addr   = SPNIC_CSR_FUNC_ATTR2_ADDR;
	attr2  = spnic_hwif_read_reg(hwif, addr);

	addr   = SPNIC_CSR_FUNC_ATTR3_ADDR;
	attr3  = spnic_hwif_read_reg(hwif, addr);

	set_hwif_attr(hwif, attr0, attr1, attr2, attr3);
}

void spnic_set_pf_status(struct spnic_hwif *hwif, enum spnic_pf_status status)
{
	u32 attr6 = SPNIC_AF6_SET(status, PF_STATUS);
	u32 addr  = SPNIC_CSR_FUNC_ATTR6_ADDR;

	if (hwif->attr.func_type == TYPE_VF)
		return;

	spnic_hwif_write_reg(hwif, addr, attr6);
}

enum spnic_pf_status spnic_get_pf_status(struct spnic_hwif *hwif)
{
	u32 attr6 = spnic_hwif_read_reg(hwif, SPNIC_CSR_FUNC_ATTR6_ADDR);

	return SPNIC_AF6_GET(attr6, PF_STATUS);
}

static enum spnic_doorbell_ctrl
spnic_get_doorbell_ctrl_status(struct spnic_hwif *hwif)
{
	u32 attr4 = spnic_hwif_read_reg(hwif, SPNIC_CSR_FUNC_ATTR4_ADDR);

	return SPNIC_AF4_GET(attr4, DOORBELL_CTRL);
}

static enum spnic_outbound_ctrl
spnic_get_outbound_ctrl_status(struct spnic_hwif *hwif)
{
	u32 attr5 = spnic_hwif_read_reg(hwif, SPNIC_CSR_FUNC_ATTR5_ADDR);

	return SPNIC_AF5_GET(attr5, OUTBOUND_CTRL);
}

void spnic_enable_doorbell(struct spnic_hwif *hwif)
{
	u32 addr, attr4;

	addr = SPNIC_CSR_FUNC_ATTR4_ADDR;
	attr4 = spnic_hwif_read_reg(hwif, addr);

	attr4 = SPNIC_AF4_CLEAR(attr4, DOORBELL_CTRL);
	attr4 |= SPNIC_AF4_SET(ENABLE_DOORBELL, DOORBELL_CTRL);

	spnic_hwif_write_reg(hwif, addr, attr4);
}

void spnic_disable_doorbell(struct spnic_hwif *hwif)
{
	u32 addr, attr4;

	addr = SPNIC_CSR_FUNC_ATTR4_ADDR;
	attr4 = spnic_hwif_read_reg(hwif, addr);

	attr4 = SPNIC_AF4_CLEAR(attr4, DOORBELL_CTRL);
	attr4 |= SPNIC_AF4_SET(DISABLE_DOORBELL, DOORBELL_CTRL);

	spnic_hwif_write_reg(hwif, addr, attr4);
}

/**
 * Try to set hwif as ppf and set the type of hwif in this case
 *
 * @param[in] hwif
 *   The hardware interface of a pci function device
 */
static void set_ppf(struct spnic_hwif *hwif)
{
	struct spnic_func_attr *attr = &hwif->attr;
	u32 addr, val, ppf_election;

	addr  = SPNIC_CSR_PPF_ELECTION_ADDR;

	val = spnic_hwif_read_reg(hwif, addr);
	val = SPNIC_PPF_ELECTION_CLEAR(val, IDX);

	ppf_election =  SPNIC_PPF_ELECTION_SET(attr->func_global_idx, IDX);
	val |= ppf_election;

	spnic_hwif_write_reg(hwif, addr, val);

	/* Check PPF */
	val = spnic_hwif_read_reg(hwif, addr);

	attr->ppf_idx = SPNIC_PPF_ELECTION_GET(val, IDX);
	if (attr->ppf_idx == attr->func_global_idx)
		attr->func_type = TYPE_PPF;
}

/**
 * Get the mpf index from the hwif
 *
 * @param[in] hwif
 *   The hardware interface of a pci function device
 */
static void get_mpf(struct spnic_hwif *hwif)
{
	struct spnic_func_attr *attr = &hwif->attr;
	u32 mpf_election, addr;

	addr = SPNIC_CSR_GLOBAL_MPF_ELECTION_ADDR;

	mpf_election = spnic_hwif_read_reg(hwif, addr);
	attr->mpf_idx = SPNIC_MPF_ELECTION_GET(mpf_election, IDX);
}

/**
 * Try to set hwif as mpf and set the mpf idx in hwif
 *
 * @param[in] hwif
 *   The hardware interface of a pci function device
 */
static void set_mpf(struct spnic_hwif *hwif)
{
	struct spnic_func_attr *attr = &hwif->attr;
	u32 addr, val, mpf_election;

	addr  = SPNIC_CSR_GLOBAL_MPF_ELECTION_ADDR;

	val = spnic_hwif_read_reg(hwif, addr);

	val = SPNIC_MPF_ELECTION_CLEAR(val, IDX);
	mpf_election = SPNIC_MPF_ELECTION_SET(attr->func_global_idx, IDX);

	val |= mpf_election;
	spnic_hwif_write_reg(hwif, addr, val);
}

static void init_db_area_idx(struct spnic_free_db_area *free_db_area,
			     u64 db_dwqe_len)
{
	u32 i, db_max_areas;

	db_max_areas = (db_dwqe_len > SPNIC_DB_DWQE_SIZE) ?
		       SPNIC_DB_MAX_AREAS :
		       (u32)(db_dwqe_len / SPNIC_DB_PAGE_SIZE);

	for (i = 0; i < db_max_areas; i++)
		free_db_area->db_idx[i] = i;

	free_db_area->num_free = db_max_areas;
	free_db_area->db_max_areas = db_max_areas;

	rte_spinlock_init(&free_db_area->idx_lock);
}

static int get_db_idx(struct spnic_hwif *hwif, u32 *idx)
{
	struct spnic_free_db_area *free_db_area = &hwif->free_db_area;
	u32 pos;
	u32 pg_idx;

	rte_spinlock_lock(&free_db_area->idx_lock);

	do {
		if (free_db_area->num_free == 0) {
			rte_spinlock_unlock(&free_db_area->idx_lock);
			return -ENOMEM;
		}

		free_db_area->num_free--;

		pos = free_db_area->alloc_pos++;
		/* Doorbell max areas should be 2^n */
		pos &= free_db_area->db_max_areas - 1;

		pg_idx = free_db_area->db_idx[pos];

		free_db_area->db_idx[pos] = 0xFFFFFFFF;
	} while (pg_idx >= free_db_area->db_max_areas);

	rte_spinlock_unlock(&free_db_area->idx_lock);

	*idx = pg_idx;

	return 0;
}

static void free_db_idx(struct spnic_hwif *hwif, u32 idx)
{
	struct spnic_free_db_area *free_db_area = &hwif->free_db_area;
	u32 pos;

	if (idx >= free_db_area->db_max_areas)
		return;

	rte_spinlock_lock(&free_db_area->idx_lock);

	pos = free_db_area->return_pos++;
	pos &= free_db_area->db_max_areas - 1;

	free_db_area->db_idx[pos] = idx;

	free_db_area->num_free++;

	rte_spinlock_unlock(&free_db_area->idx_lock);
}

void spnic_free_db_addr(void *hwdev, const void *db_base,
			 __rte_unused void *dwqe_base)
{
	struct spnic_hwif *hwif = NULL;
	u32 idx;

	if (!hwdev || !db_base)
		return;

	hwif = ((struct spnic_hwdev *)hwdev)->hwif;
	idx = DB_IDX(db_base, hwif->db_base);

	free_db_idx(hwif, idx);
}

int spnic_alloc_db_addr(void *hwdev, void **db_base, void **dwqe_base)
{
	struct spnic_hwif *hwif = NULL;
	u32 idx;
	int err;

	if (!hwdev || !db_base)
		return -EINVAL;

	hwif = ((struct spnic_hwdev *)hwdev)->hwif;

	err = get_db_idx(hwif, &idx);
	if (err)
		return -EFAULT;

	*db_base = hwif->db_base + idx * SPNIC_DB_PAGE_SIZE;

	if (!dwqe_base)
		return 0;

	*dwqe_base = (u8 *)*db_base + SPNIC_DWQE_OFFSET;

	return 0;
}

/**
 * Set msix state
 *
 * @param[in] hwdev
 *   The pointer to the private hardware device object
 * @param[in] msix_idx
 *   MSIX index
 * @param[in] flag
 *   MSIX state flag, 0-enable, 1-disable
 */
void spnic_set_msix_state(void *hwdev, u16 msix_idx, enum spnic_msix_state flag)
{
	struct spnic_hwif *hwif = NULL;
	u32 mask_bits;
	u32 addr;
	u8 int_msk = 1;

	if (!hwdev)
		return;

	hwif = ((struct spnic_hwdev *)hwdev)->hwif;

	if (flag)
		mask_bits = SPNIC_MSI_CLR_INDIR_SET(int_msk, INT_MSK_SET);
	else
		mask_bits = SPNIC_MSI_CLR_INDIR_SET(int_msk, INT_MSK_CLR);
	mask_bits = mask_bits |
		    SPNIC_MSI_CLR_INDIR_SET(msix_idx, SIMPLE_INDIR_IDX);

	addr = SPNIC_CSR_FUNC_MSI_CLR_WR_ADDR;
	spnic_hwif_write_reg(hwif, addr, mask_bits);
}

static void disable_all_msix(struct spnic_hwdev *hwdev)
{
	u16 num_irqs = hwdev->hwif->attr.num_irqs;
	u16 i;

	for (i = 0; i < num_irqs; i++)
		spnic_set_msix_state(hwdev, i, SPNIC_MSIX_DISABLE);
}

void spnic_misx_intr_clear_resend_bit(void *hwdev, u16 msix_idx,
					      u8 clear_resend_en)
{
	struct spnic_hwif *hwif = NULL;
	u32 msix_ctrl = 0, addr;

	if (!hwdev)
		return;

	hwif = ((struct spnic_hwdev *)hwdev)->hwif;

	msix_ctrl = SPNIC_MSI_CLR_INDIR_SET(msix_idx, SIMPLE_INDIR_IDX) |
		    SPNIC_MSI_CLR_INDIR_SET(clear_resend_en, RESEND_TIMER_CLR);

	addr = SPNIC_CSR_FUNC_MSI_CLR_WR_ADDR;
	spnic_hwif_write_reg(hwif, addr, msix_ctrl);
}
#ifdef SPNIC_RELEASE
static int wait_until_doorbell_flush_states(struct spnic_hwif *hwif,
					    enum spnic_doorbell_ctrl states)
{
	enum spnic_doorbell_ctrl db_ctrl;
	u32 cnt = 0;

	if (!hwif)
		return -EINVAL;

	while (cnt < SPNIC_WAIT_DOORBELL_AND_OUTBOUND_TIMEOUT) {
		db_ctrl = spnic_get_doorbell_ctrl_status(hwif);
		if (db_ctrl == states)
			return 0;

		rte_delay_ms(1);
		cnt++;
	}

	return -EFAULT;
}
#endif

static int wait_until_doorbell_and_outbound_enabled(struct spnic_hwif *hwif)
{
	enum spnic_doorbell_ctrl db_ctrl;
	enum spnic_outbound_ctrl outbound_ctrl;
	u32 cnt = 0;

	while (cnt < SPNIC_WAIT_DOORBELL_AND_OUTBOUND_TIMEOUT) {
		db_ctrl = spnic_get_doorbell_ctrl_status(hwif);
		outbound_ctrl = spnic_get_outbound_ctrl_status(hwif);
		if (outbound_ctrl == ENABLE_OUTBOUND &&
		    db_ctrl == ENABLE_DOORBELL)
			return 0;

		rte_delay_ms(1);
		cnt++;
	}

	return -EFAULT;
}

static void spnic_get_bar_addr(struct spnic_hwdev *hwdev)
{
	struct rte_pci_device *pci_dev = hwdev->pci_dev;
	struct spnic_hwif *hwif = hwdev->hwif;
	void *cfg_regs_base = NULL;
	void *mgmt_reg_base = NULL;
	void *intr_reg_base = NULL;
	void *db_base = NULL;
	int cfg_bar;

	cfg_bar = SPNIC_IS_VF_DEV(pci_dev) ?
			SPNIC_VF_PCI_CFG_REG_BAR : SPNIC_PF_PCI_CFG_REG_BAR;

	cfg_regs_base = pci_dev->mem_resource[cfg_bar].addr;
	intr_reg_base = pci_dev->mem_resource[SPNIC_PCI_INTR_REG_BAR].addr;
	if (!SPNIC_IS_VF_DEV(pci_dev)) {
		mgmt_reg_base =
			pci_dev->mem_resource[SPNIC_PCI_MGMT_REG_BAR].addr;
	}
	db_base = pci_dev->mem_resource[SPNIC_PCI_DB_BAR].addr;

	/* If function is VF, mgmt_regs_base will be NULL */
	if (!mgmt_reg_base)
		hwif->cfg_regs_base = (u8 *)cfg_regs_base +
				      SPNIC_VF_CFG_REG_OFFSET;
	else
		hwif->cfg_regs_base = cfg_regs_base;
	hwif->intr_regs_base = intr_reg_base;
	hwif->mgmt_regs_base = mgmt_reg_base;
	hwif->db_base = db_base;
	hwif->db_dwqe_len = pci_dev->mem_resource[SPNIC_PCI_DB_BAR].len;
}

/**
 * Initialize the hw interface
 *
 * @param[in] hwdev
 *   The pointer to the private hardware device object
 *
 * @retval zero : Success
 * @retval non-zero : Failure.
 */
int spnic_init_hwif(void *dev)
{
	struct spnic_hwdev *hwdev = NULL;
	struct spnic_hwif *hwif;
	int err;

	hwif = rte_zmalloc("spnic_hwif", sizeof(struct spnic_hwif),
			   RTE_CACHE_LINE_SIZE);
	if (!hwif)
		return -ENOMEM;

	hwdev = (struct spnic_hwdev *)dev;
	hwdev->hwif = hwif;

	spnic_get_bar_addr(hwdev);

	init_db_area_idx(&hwif->free_db_area, hwif->db_dwqe_len);

	err = wait_hwif_ready(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Chip status is not ready");
		goto hwif_ready_err;
	}

	get_hwif_attr(hwif);

	err = wait_until_doorbell_and_outbound_enabled(hwif);
	if (err) {
		PMD_DRV_LOG(ERR, "Hw doorbell/outbound is disabled");
		goto hwif_ready_err;
	}

	if (!SPNIC_IS_VF(hwdev)) {
		set_ppf(hwif);

		if (SPNIC_IS_PPF(hwdev))
			set_mpf(hwif);

		get_mpf(hwif);
	}

	disable_all_msix(hwdev);
	/* Disable mgmt cpu reporting any event */
	spnic_set_pf_status(hwdev->hwif, SPNIC_PF_STATUS_INIT);

	PMD_DRV_LOG(INFO, "global_func_idx: %d, func_type: %d, host_id: %d, ppf: %d, mpf: %d",
		    hwif->attr.func_global_idx, hwif->attr.func_type,
		    hwif->attr.pci_intf_idx, hwif->attr.ppf_idx,
		    hwif->attr.mpf_idx);

	return 0;

hwif_ready_err:
	rte_free(hwdev->hwif);
	hwdev->hwif = NULL;

	return err;
}

/**
 * Free the hw interface
 *
 * @param[in] dev
 *   The pointer to the private hardware device object
 */
void spnic_free_hwif(void *dev)
{
	struct spnic_hwdev *hwdev = (struct spnic_hwdev *)dev;

	rte_free(hwdev->hwif);
}

u16 spnic_global_func_id(void *hwdev)
{
	struct spnic_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct spnic_hwdev *)hwdev)->hwif;

	return hwif->attr.func_global_idx;
}

u8 spnic_pf_id_of_vf(void *hwdev)
{
	struct spnic_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct spnic_hwdev *)hwdev)->hwif;

	return hwif->attr.port_to_port_idx;
}

u8 spnic_pcie_itf_id(void *hwdev)
{
	struct spnic_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct spnic_hwdev *)hwdev)->hwif;

	return hwif->attr.pci_intf_idx;
}

enum func_type spnic_func_type(void *hwdev)
{
	struct spnic_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct spnic_hwdev *)hwdev)->hwif;

	return hwif->attr.func_type;
}

u16 spnic_glb_pf_vf_offset(void *hwdev)
{
	struct spnic_hwif *hwif = NULL;

	if (!hwdev)
		return 0;

	hwif = ((struct spnic_hwdev *)hwdev)->hwif;

	return hwif->attr.global_vf_id_of_pf;
}
