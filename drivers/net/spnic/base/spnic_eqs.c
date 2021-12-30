/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <ethdev_driver.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include "spnic_compat.h"
#include "spnic_hwdev.h"
#include "spnic_hwif.h"
#include "spnic_csr.h"
#include "spnic_eqs.h"
#include "spnic_mgmt.h"
#include "spnic_mbox.h"
#include "spnic_nic_event.h"

#define AEQ_CTRL_0_INTR_IDX_SHIFT		0
#define AEQ_CTRL_0_DMA_ATTR_SHIFT		12
#define AEQ_CTRL_0_PCI_INTF_IDX_SHIFT		20
#define AEQ_CTRL_0_INTR_MODE_SHIFT		31

#define AEQ_CTRL_0_INTR_IDX_MASK		0x3FFU
#define AEQ_CTRL_0_DMA_ATTR_MASK		0x3FU
#define AEQ_CTRL_0_PCI_INTF_IDX_MASK		0x7U
#define AEQ_CTRL_0_INTR_MODE_MASK		0x1U

#define AEQ_CTRL_0_SET(val, member)		\
				(((val) & AEQ_CTRL_0_##member##_MASK) << \
				AEQ_CTRL_0_##member##_SHIFT)

#define AEQ_CTRL_0_CLEAR(val, member)		\
				((val) & (~(AEQ_CTRL_0_##member##_MASK \
					<< AEQ_CTRL_0_##member##_SHIFT)))

#define AEQ_CTRL_1_LEN_SHIFT			0
#define AEQ_CTRL_1_ELEM_SIZE_SHIFT		24
#define AEQ_CTRL_1_PAGE_SIZE_SHIFT		28

#define AEQ_CTRL_1_LEN_MASK			0x1FFFFFU
#define AEQ_CTRL_1_ELEM_SIZE_MASK		0x3U
#define AEQ_CTRL_1_PAGE_SIZE_MASK		0xFU

#define AEQ_CTRL_1_SET(val, member)		\
				(((val) & AEQ_CTRL_1_##member##_MASK) << \
				AEQ_CTRL_1_##member##_SHIFT)

#define AEQ_CTRL_1_CLEAR(val, member)		\
				((val) & (~(AEQ_CTRL_1_##member##_MASK \
					<< AEQ_CTRL_1_##member##_SHIFT)))

#define SPNIC_EQ_PROD_IDX_MASK			0xFFFFF
#define SPNIC_TASK_PROCESS_EQE_LIMIT		1024
#define SPNIC_EQ_UPDATE_CI_STEP                 64

#define EQ_ELEM_DESC_TYPE_SHIFT			0
#define EQ_ELEM_DESC_SRC_SHIFT			7
#define EQ_ELEM_DESC_SIZE_SHIFT			8
#define EQ_ELEM_DESC_WRAPPED_SHIFT		31

#define EQ_ELEM_DESC_TYPE_MASK			0x7FU
#define EQ_ELEM_DESC_SRC_MASK			0x1U
#define EQ_ELEM_DESC_SIZE_MASK			0xFFU
#define EQ_ELEM_DESC_WRAPPED_MASK		0x1U

#define EQ_ELEM_DESC_GET(val, member)		\
				(((val) >> EQ_ELEM_DESC_##member##_SHIFT) & \
				EQ_ELEM_DESC_##member##_MASK)

#define EQ_CI_SIMPLE_INDIR_CI_SHIFT		0
#define EQ_CI_SIMPLE_INDIR_ARMED_SHIFT		21
#define EQ_CI_SIMPLE_INDIR_AEQ_IDX_SHIFT	30

#define EQ_CI_SIMPLE_INDIR_CI_MASK		0x1FFFFFU
#define EQ_CI_SIMPLE_INDIR_ARMED_MASK		0x1U
#define EQ_CI_SIMPLE_INDIR_AEQ_IDX_MASK		0x3U

#define EQ_CI_SIMPLE_INDIR_SET(val, member)		\
			(((val) & EQ_CI_SIMPLE_INDIR_##member##_MASK) << \
			EQ_CI_SIMPLE_INDIR_##member##_SHIFT)

#define EQ_CI_SIMPLE_INDIR_CLEAR(val, member)		\
				((val) & (~(EQ_CI_SIMPLE_INDIR_##member##_MASK \
				<< EQ_CI_SIMPLE_INDIR_##member##_SHIFT)))

#define EQ_WRAPPED(eq)		((u32)(eq)->wrapped << EQ_VALID_SHIFT)

#define EQ_CONS_IDX(eq)		((eq)->cons_idx | \
				((u32)(eq)->wrapped << EQ_WRAPPED_SHIFT))
#define GET_EQ_NUM_PAGES(eq, size)	\
		((u16)(RTE_ALIGN((u32)((eq)->eq_len * (eq)->elem_size), \
		(size)) / (size)))

#define GET_EQ_NUM_ELEMS(eq, pg_size)	((pg_size) / (u32)(eq)->elem_size)

#define GET_EQ_ELEMENT(eq, idx)		\
		(((u8 *)(eq)->virt_addr[(idx) / (eq)->num_elem_in_pg]) + \
		(u32)(((idx) & ((eq)->num_elem_in_pg - 1)) * (eq)->elem_size))

#define GET_AEQ_ELEM(eq, idx)		((struct spnic_aeq_elem *)\
					GET_EQ_ELEMENT((eq), (idx)))

#define GET_CURR_AEQ_ELEM(eq)		GET_AEQ_ELEM((eq), (eq)->cons_idx)

#define PAGE_IN_4K(page_size)		((page_size) >> 12)
#define EQ_SET_HW_PAGE_SIZE_VAL(eq)	\
		((u32)ilog2(PAGE_IN_4K((eq)->page_size)))

#define ELEMENT_SIZE_IN_32B(eq)		(((eq)->elem_size) >> 5)
#define EQ_SET_HW_ELEM_SIZE_VAL(eq)	((u32)ilog2(ELEMENT_SIZE_IN_32B(eq)))

#define AEQ_DMA_ATTR_DEFAULT			0

#define EQ_MSIX_RESEND_TIMER_CLEAR		1

#define EQ_WRAPPED_SHIFT			20

#define	EQ_VALID_SHIFT				31

#define aeq_to_aeqs(eq) \
		container_of((eq) - (eq)->q_id, struct spnic_aeqs, aeq[0])

#define AEQ_MSIX_ENTRY_IDX_0			0

/**
 * Write the cons idx to hw
 *
 * @param[in] eq
 *   The event queue to update the cons idx
 * @param[in] arm_state
 *   Indicate whether report interrupts when generate eq element
 */
static void set_eq_cons_idx(struct spnic_eq *eq, u32 arm_state)
{
	u32 eq_wrap_ci, val;
	u32 addr = SPNIC_CSR_AEQ_CI_SIMPLE_INDIR_ADDR;

	eq_wrap_ci = EQ_CONS_IDX(eq);

	/* dpdk pmd driver only aeq0 use int_arm mode */
	if (eq->q_id != 0)
		val = EQ_CI_SIMPLE_INDIR_SET(SPNIC_EQ_NOT_ARMED, ARMED);
	else
		val = EQ_CI_SIMPLE_INDIR_SET(arm_state, ARMED);

	val = val | EQ_CI_SIMPLE_INDIR_SET(eq_wrap_ci, CI) |
	      EQ_CI_SIMPLE_INDIR_SET(eq->q_id, AEQ_IDX);

	spnic_hwif_write_reg(eq->hwdev->hwif, addr, val);
}

/**
 * Set aeq's ctrls registers
 *
 * @param[in] eq
 *   The event queue for setting
 */
static void set_aeq_ctrls(struct spnic_eq *eq)
{
	struct spnic_hwif *hwif = eq->hwdev->hwif;
	struct irq_info *eq_irq = &eq->eq_irq;
	u32 addr, val, ctrl0, ctrl1, page_size_val, elem_size;
	u32 pci_intf_idx = SPNIC_PCI_INTF_IDX(hwif);

	/* Set ctrl0 */
	addr = SPNIC_CSR_AEQ_CTRL_0_ADDR;

	val = spnic_hwif_read_reg(hwif, addr);

	val = AEQ_CTRL_0_CLEAR(val, INTR_IDX) &
	      AEQ_CTRL_0_CLEAR(val, DMA_ATTR) &
	      AEQ_CTRL_0_CLEAR(val, PCI_INTF_IDX) &
	      AEQ_CTRL_0_CLEAR(val, INTR_MODE);

	ctrl0 = AEQ_CTRL_0_SET(eq_irq->msix_entry_idx, INTR_IDX) |
		AEQ_CTRL_0_SET(AEQ_DMA_ATTR_DEFAULT, DMA_ATTR) |
		AEQ_CTRL_0_SET(pci_intf_idx, PCI_INTF_IDX) |
		AEQ_CTRL_0_SET(SPNIC_INTR_MODE_ARMED, INTR_MODE);

	val |= ctrl0;

	spnic_hwif_write_reg(hwif, addr, val);

	/* Set ctrl1 */
	addr = SPNIC_CSR_AEQ_CTRL_1_ADDR;

	page_size_val = EQ_SET_HW_PAGE_SIZE_VAL(eq);
	elem_size = EQ_SET_HW_ELEM_SIZE_VAL(eq);

	ctrl1 = AEQ_CTRL_1_SET(eq->eq_len, LEN)	|
		AEQ_CTRL_1_SET(elem_size, ELEM_SIZE)	|
		AEQ_CTRL_1_SET(page_size_val, PAGE_SIZE);

	spnic_hwif_write_reg(hwif, addr, ctrl1);
}

/**
 * Initialize all the elements in the aeq
 *
 * @param[in] eq
 *   The event queue
 * @param[in] init_val
 *   Value to init
 */
static void aeq_elements_init(struct spnic_eq *eq, u32 init_val)
{
	struct spnic_aeq_elem *aeqe = NULL;
	u32 i;

	for (i = 0; i < eq->eq_len; i++) {
		aeqe = GET_AEQ_ELEM(eq, i);
		aeqe->desc = cpu_to_be32(init_val);
	}

	rte_wmb(); /* Write the init values */
}

/**
 * Allocate the pages for the queue
 *
 * @param[in] eq
 *   The event queue
 *
 * @retval zero : Success
 * @retval negative : Failure.
 */
static int alloc_eq_pages(struct spnic_eq *eq)
{
	struct spnic_hwif *hwif = eq->hwdev->hwif;
	u64 dma_addr_size, virt_addr_size, eq_mz_size;
	u32 reg, init_val;
	u16 pg_num, i;
	int err;

	dma_addr_size = eq->num_pages * sizeof(*eq->dma_addr);
	virt_addr_size = eq->num_pages * sizeof(*eq->virt_addr);
	eq_mz_size = eq->num_pages * sizeof(*eq->eq_mz);

	eq->dma_addr = rte_zmalloc("eq_dma", dma_addr_size,
				   SPNIC_MEM_ALLOC_ALIGN_MIN);
	if (!eq->dma_addr)
		return -ENOMEM;

	eq->virt_addr = rte_zmalloc("eq_va", virt_addr_size,
				    SPNIC_MEM_ALLOC_ALIGN_MIN);
	if (!eq->virt_addr) {
		err = -ENOMEM;
		goto virt_addr_alloc_err;
	}

	eq->eq_mz = rte_zmalloc("eq_mz", eq_mz_size, SPNIC_MEM_ALLOC_ALIGN_MIN);
	if (!eq->eq_mz) {
		err = -ENOMEM;
		goto eq_mz_alloc_err;
	}

	for (pg_num = 0; pg_num < eq->num_pages; pg_num++) {
		eq->eq_mz[pg_num] = rte_eth_dma_zone_reserve(eq->hwdev->eth_dev,
					"eq_mz", eq->q_id, eq->page_size,
					eq->page_size, SOCKET_ID_ANY);
		if (!eq->eq_mz[pg_num]) {
			err = -ENOMEM;
			goto dma_alloc_err;
		}

		eq->dma_addr[pg_num] = eq->eq_mz[pg_num]->iova;
		eq->virt_addr[pg_num] = eq->eq_mz[pg_num]->addr;

		reg = SPNIC_AEQ_HI_PHYS_ADDR_REG(pg_num);
		spnic_hwif_write_reg(hwif, reg,
				     upper_32_bits(eq->dma_addr[pg_num]));

		reg = SPNIC_AEQ_LO_PHYS_ADDR_REG(pg_num);
		spnic_hwif_write_reg(hwif, reg,
				     lower_32_bits(eq->dma_addr[pg_num]));
	}

	eq->num_elem_in_pg = GET_EQ_NUM_ELEMS(eq, eq->page_size);
	if (eq->num_elem_in_pg & (eq->num_elem_in_pg - 1)) {
		PMD_DRV_LOG(ERR, "Number element in eq page != power of 2");
		err = -EINVAL;
		goto dma_alloc_err;
	}
	init_val = EQ_WRAPPED(eq);

	aeq_elements_init(eq, init_val);

	return 0;

dma_alloc_err:
	for (i = 0; i < pg_num; i++)
		rte_memzone_free(eq->eq_mz[i]);

eq_mz_alloc_err:
	rte_free(eq->virt_addr);

virt_addr_alloc_err:
	rte_free(eq->dma_addr);

	return err;
}

/**
 * Free the pages of the queue
 *
 * @param[in] eq
 *   The event queue
 */
static void free_eq_pages(struct spnic_eq *eq)
{
	u16 pg_num;

	for (pg_num = 0; pg_num < eq->num_pages; pg_num++)
		rte_memzone_free(eq->eq_mz[pg_num]);

	rte_free(eq->eq_mz);
	rte_free(eq->virt_addr);
	rte_free(eq->dma_addr);
}

static inline u32 get_page_size(struct spnic_eq *eq)
{
	u32 total_size;
	u16 count, n = 0;

	total_size = RTE_ALIGN((eq->eq_len * eq->elem_size),
			       SPNIC_MIN_EQ_PAGE_SIZE);
	if (total_size <= (SPNIC_EQ_MAX_PAGES * SPNIC_MIN_EQ_PAGE_SIZE))
		return SPNIC_MIN_EQ_PAGE_SIZE;

	count = (u16)(RTE_ALIGN((total_size / SPNIC_EQ_MAX_PAGES),
		      SPNIC_MIN_EQ_PAGE_SIZE) / SPNIC_MIN_EQ_PAGE_SIZE);
	if (!(count & (count - 1)))
		return SPNIC_MIN_EQ_PAGE_SIZE * count;

	while (count) {
		count >>= 1;
		n++;
	}

	return ((u32)SPNIC_MIN_EQ_PAGE_SIZE) << n;
}

/**
 * Initialize aeq
 *
 * @param[in] eq
 *   The event queue
 * @param[in] hwdev
 *   The pointer to the private hardware device object
 * @param[in] q_id
 *   Queue id number
 * @param[in] q_len
 *   The number of EQ elements
 *
 * @retval zero : Success
 * @retval non-zero : Failure.
 */
static int init_aeq(struct spnic_eq *eq, struct spnic_hwdev *hwdev,
		    u16 q_id, u32 q_len)
{
	int err = 0;

	eq->hwdev = hwdev;
	eq->q_id = q_id;
	eq->eq_len = q_len;

	/* Indirect access should set q_id first */
	spnic_hwif_write_reg(hwdev->hwif, SPNIC_AEQ_INDIR_IDX_ADDR, eq->q_id);
	rte_wmb(); /* write index before config */

	/* Clear eq_len to force eqe drop in hardware */
	spnic_hwif_write_reg(eq->hwdev->hwif, SPNIC_CSR_AEQ_CTRL_1_ADDR, 0);
	rte_wmb();
	/* Init aeq pi to 0 before allocating aeq pages */
	spnic_hwif_write_reg(eq->hwdev->hwif, SPNIC_CSR_AEQ_PROD_IDX_ADDR, 0);

	eq->cons_idx = 0;
	eq->wrapped = 0;

	eq->elem_size = SPNIC_AEQE_SIZE;
	eq->page_size = get_page_size(eq);
	eq->orig_page_size = eq->page_size;
	eq->num_pages = GET_EQ_NUM_PAGES(eq, eq->page_size);
	if (eq->num_pages > SPNIC_EQ_MAX_PAGES) {
		PMD_DRV_LOG(ERR, "Too many pages: %d for aeq", eq->num_pages);
		return -EINVAL;
	}

	err = alloc_eq_pages(eq);
	if (err) {
		PMD_DRV_LOG(ERR, "Allocate pages for eq failed");
		return err;
	}

	/* Pmd driver uses AEQ_MSIX_ENTRY_IDX_0 */
	eq->eq_irq.msix_entry_idx = AEQ_MSIX_ENTRY_IDX_0;
	set_aeq_ctrls(eq);

	set_eq_cons_idx(eq, SPNIC_EQ_ARMED);

	if (eq->q_id == 0)
		spnic_set_msix_state(hwdev, 0, SPNIC_MSIX_ENABLE);

	eq->poll_retry_nr = SPNIC_RETRY_NUM;

	return 0;
}

/**
 * Remove aeq
 *
 * @param[in] eq
 *   The event queue
 */
static void remove_aeq(struct spnic_eq *eq)
{
	struct irq_info *entry = &eq->eq_irq;

	if (eq->q_id == 0)
		spnic_set_msix_state(eq->hwdev, entry->msix_entry_idx,
				     SPNIC_MSIX_DISABLE);

	/* Indirect access should set q_id first */
	spnic_hwif_write_reg(eq->hwdev->hwif, SPNIC_AEQ_INDIR_IDX_ADDR,
			     eq->q_id);

	rte_wmb(); /* Write index before config */

	/* Clear eq_len to avoid hw access host memory */
	spnic_hwif_write_reg(eq->hwdev->hwif, SPNIC_CSR_AEQ_CTRL_1_ADDR, 0);

	/* Update cons_idx to avoid invalid interrupt */
	eq->cons_idx = spnic_hwif_read_reg(eq->hwdev->hwif,
					   SPNIC_CSR_AEQ_PROD_IDX_ADDR);
	set_eq_cons_idx(eq, SPNIC_EQ_NOT_ARMED);

	free_eq_pages(eq);
}

/**
 * Init all aeqs
 *
 * @param[in] hwdev
 *   The pointer to the private hardware device object
 *
 * @retval zero : Success
 * @retval non-zero : Failure.
 */
int spnic_aeqs_init(struct spnic_hwdev *hwdev)
{
	struct spnic_aeqs *aeqs = NULL;
	u16 num_aeqs;
	int err;
	u16 i, q_id;

	if (!hwdev)
		return -EINVAL;

	num_aeqs = SPNIC_HWIF_NUM_AEQS(hwdev->hwif);
	if (num_aeqs > SPNIC_MAX_AEQS) {
		PMD_DRV_LOG(INFO, "Adjust aeq num to %d", SPNIC_MAX_AEQS);
		num_aeqs = SPNIC_MAX_AEQS;
	} else if (num_aeqs < SPNIC_MIN_AEQS) {
		PMD_DRV_LOG(ERR, "PMD needs %d AEQs, Chip has %d",
			    SPNIC_MIN_AEQS, num_aeqs);
		return -EINVAL;
	}

	aeqs = rte_zmalloc("spnic_aeqs", sizeof(*aeqs),
			   SPNIC_MEM_ALLOC_ALIGN_MIN);
	if (!aeqs)
		return -ENOMEM;

	hwdev->aeqs = aeqs;
	aeqs->hwdev = hwdev;
	aeqs->num_aeqs = num_aeqs;

	for (q_id = 0; q_id < num_aeqs; q_id++) {
		err = init_aeq(&aeqs->aeq[q_id], hwdev, q_id,
			       SPNIC_DEFAULT_AEQ_LEN);
		if (err) {
			PMD_DRV_LOG(ERR, "Init aeq %d failed", q_id);
			goto init_aeq_err;
		}
	}

	return 0;

init_aeq_err:
	for (i = 0; i < q_id; i++)
		remove_aeq(&aeqs->aeq[i]);

	rte_free(aeqs);
	return err;
}

/**
 * Free all aeqs
 *
 * @param[in] hwdev
 *   The pointer to the private hardware device object
 */
void spnic_aeqs_free(struct spnic_hwdev *hwdev)
{
	struct spnic_aeqs *aeqs = hwdev->aeqs;
	u16 q_id;

	for (q_id = 0; q_id < aeqs->num_aeqs; q_id++)
		remove_aeq(&aeqs->aeq[q_id]);

	rte_free(aeqs);
}

void spnic_dump_aeq_info(struct spnic_hwdev *hwdev)
{
	struct spnic_aeq_elem *aeqe_pos = NULL;
	struct spnic_eq *eq = NULL;
	u32 addr, ci, pi, ctrl0, idx;
	int q_id;

	for (q_id = 0; q_id < hwdev->aeqs->num_aeqs; q_id++) {
		eq = &hwdev->aeqs->aeq[q_id];
		/* Indirect access should set q_id first */
		spnic_hwif_write_reg(eq->hwdev->hwif, SPNIC_AEQ_INDIR_IDX_ADDR,
				     eq->q_id);
		rte_wmb(); /* Write index before config */

		addr = SPNIC_CSR_AEQ_CTRL_0_ADDR;

		ctrl0 = spnic_hwif_read_reg(hwdev->hwif, addr);

		idx = spnic_hwif_read_reg(hwdev->hwif,
					  SPNIC_AEQ_INDIR_IDX_ADDR);

		addr = SPNIC_CSR_AEQ_CONS_IDX_ADDR;
		ci = spnic_hwif_read_reg(hwdev->hwif, addr);
		addr = SPNIC_CSR_AEQ_PROD_IDX_ADDR;
		pi = spnic_hwif_read_reg(hwdev->hwif, addr);
		aeqe_pos = GET_CURR_AEQ_ELEM(eq);
		PMD_DRV_LOG(ERR, "Aeq id: %d, idx: %u, ctrl0: 0x%08x, wrap: %d,"
			    " pi: 0x%x, ci: 0x%08x,  desc: 0x%x", q_id, idx,
			    ctrl0, eq->wrapped, pi, ci,
			    be32_to_cpu(aeqe_pos->desc));
	}
}

static int aeq_elem_handler(struct spnic_eq *eq, u32 aeqe_desc,
			    struct spnic_aeq_elem *aeqe_pos, void *param)
{
	enum spnic_aeq_type event;
	u8 data[SPNIC_AEQE_DATA_SIZE];
	u8 size;

	event = EQ_ELEM_DESC_GET(aeqe_desc, TYPE);
	if (EQ_ELEM_DESC_GET(aeqe_desc, SRC)) {
		/* SW event uses only the first 8B */
		memcpy(data, aeqe_pos->aeqe_data, SPNIC_AEQE_DATA_SIZE);
		spnic_be32_to_cpu(data, SPNIC_AEQE_DATA_SIZE);
		/* Just support SPNIC_STATELESS_EVENT */
		return spnic_nic_sw_aeqe_handler(eq->hwdev, event, data);
	}

	memcpy(data, aeqe_pos->aeqe_data, SPNIC_AEQE_DATA_SIZE);
	spnic_be32_to_cpu(data, SPNIC_AEQE_DATA_SIZE);
	size = EQ_ELEM_DESC_GET(aeqe_desc, SIZE);

	if (event == SPNIC_MSG_FROM_MGMT_CPU) {
		return spnic_mgmt_msg_aeqe_handler(eq->hwdev, data, size,
						   param);
	} else if (event == SPNIC_MBX_FROM_FUNC) {
		return spnic_mbox_func_aeqe_handler(eq->hwdev, data, size,
						    param);
	} else {
		PMD_DRV_LOG(ERR, "AEQ hw event not support %d", event);
		return -EINVAL;
	}
}

/**
 * Poll one or continue aeqe, and call dedicated process
 *
 * @param[in] eq
 *   The event queue
 * @param[in] timeout
 *   0   - Poll all aeqe in eq, used in interrupt mode,
 *   > 0 - Poll aeq until get aeqe with 'last' field set to 1,
 *         used in polling mode.
 * @param[in] param
 *   Customized parameter
 *
 * @retval zero : Success
 * @retval -EIO : Poll timeout
 * @retval -ENODEV : Swe not support
 */
int spnic_aeq_poll_msg(struct spnic_eq *eq, u32 timeout, void *param)
{
	struct spnic_aeq_elem *aeqe_pos = NULL;
	u32 aeqe_desc = 0;
	u32 eqe_cnt = 0;
	int err = -EFAULT;
	int done = SPNIC_MSG_HANDLER_RES;
	unsigned long end;
	u16 i;

	for (i = 0; ((timeout == 0) && (i < eq->eq_len)) ||
	     ((timeout > 0) && (done != 0) && (i < eq->eq_len)); i++) {
		err = -EIO;
		end = jiffies + msecs_to_jiffies(timeout);
		do {
			aeqe_pos = GET_CURR_AEQ_ELEM(eq);
			rte_rmb();

			/* Data in HW is in Big endian Format */
			aeqe_desc = be32_to_cpu(aeqe_pos->desc);

			/*
			 * HW updates wrapped bit,
			 * when it adds eq element event
			 */
			if (EQ_ELEM_DESC_GET(aeqe_desc, WRAPPED)
				!= eq->wrapped) {
				err = 0;
				break;
			}

			if (timeout != 0)
				usleep(1000);
		} while (time_before(jiffies, end));

		if (err != 0) /* Poll time out */
			break;

		done = aeq_elem_handler(eq, aeqe_desc, aeqe_pos, param);

		eq->cons_idx++;
		if (eq->cons_idx == eq->eq_len) {
			eq->cons_idx = 0;
			eq->wrapped = !eq->wrapped;
		}

		if (++eqe_cnt >= SPNIC_EQ_UPDATE_CI_STEP) {
			eqe_cnt = 0;
			set_eq_cons_idx(eq, SPNIC_EQ_NOT_ARMED);
		}
	}

	set_eq_cons_idx(eq, SPNIC_EQ_ARMED);

	return err;
}
