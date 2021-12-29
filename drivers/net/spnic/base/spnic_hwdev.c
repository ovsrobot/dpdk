/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include "spnic_compat.h"
#include "spnic_csr.h"
#include "spnic_eqs.h"
#include "spnic_mgmt.h"
#include "spnic_cmd.h"
#include "spnic_mbox.h"
#include "spnic_wq.h"
#include "spnic_cmdq.h"
#include "spnic_hw_cfg.h"
#include "spnic_hwdev.h"
#include "spnic_hwif.h"
#include "spnic_hw_comm.h"

enum spnic_pcie_nosnoop {
	SPNIC_PCIE_SNOOP = 0,
	SPNIC_PCIE_NO_SNOOP = 1
};

enum spnic_pcie_tph {
	SPNIC_PCIE_TPH_DISABLE = 0,
	SPNIC_PCIE_TPH_ENABLE = 1
};

#define SPNIC_DMA_ATTR_INDIR_IDX_SHIFT				0

#define SPNIC_DMA_ATTR_INDIR_IDX_MASK				0x3FF

#define SPNIC_DMA_ATTR_INDIR_IDX_SET(val, member)			\
		(((u32)(val) & SPNIC_DMA_ATTR_INDIR_##member##_MASK) << \
			SPNIC_DMA_ATTR_INDIR_##member##_SHIFT)

#define SPNIC_DMA_ATTR_INDIR_IDX_CLEAR(val, member)		\
		((val) & (~(SPNIC_DMA_ATTR_INDIR_##member##_MASK	\
			<< SPNIC_DMA_ATTR_INDIR_##member##_SHIFT)))

#define SPNIC_DMA_ATTR_ENTRY_ST_SHIFT				0
#define SPNIC_DMA_ATTR_ENTRY_AT_SHIFT				8
#define SPNIC_DMA_ATTR_ENTRY_PH_SHIFT				10
#define SPNIC_DMA_ATTR_ENTRY_NO_SNOOPING_SHIFT			12
#define SPNIC_DMA_ATTR_ENTRY_TPH_EN_SHIFT			13

#define SPNIC_DMA_ATTR_ENTRY_ST_MASK				0xFF
#define SPNIC_DMA_ATTR_ENTRY_AT_MASK				0x3
#define SPNIC_DMA_ATTR_ENTRY_PH_MASK				0x3
#define SPNIC_DMA_ATTR_ENTRY_NO_SNOOPING_MASK			0x1
#define SPNIC_DMA_ATTR_ENTRY_TPH_EN_MASK			0x1

#define SPNIC_DMA_ATTR_ENTRY_SET(val, member)			\
		(((u32)(val) & SPNIC_DMA_ATTR_ENTRY_##member##_MASK) << \
			SPNIC_DMA_ATTR_ENTRY_##member##_SHIFT)

#define SPNIC_DMA_ATTR_ENTRY_CLEAR(val, member)		\
		((val) & (~(SPNIC_DMA_ATTR_ENTRY_##member##_MASK	\
			<< SPNIC_DMA_ATTR_ENTRY_##member##_SHIFT)))

#define SPNIC_PCIE_ST_DISABLE			0
#define SPNIC_PCIE_AT_DISABLE			0
#define SPNIC_PCIE_PH_DISABLE			0

#define PCIE_MSIX_ATTR_ENTRY			0

#define SPNIC_CHIP_PRESENT			1
#define SPNIC_CHIP_ABSENT			0

#define SPNIC_DEAULT_EQ_MSIX_PENDING_LIMIT	0
#define SPNIC_DEAULT_EQ_MSIX_COALESC_TIMER_CFG	0xFF
#define SPNIC_DEAULT_EQ_MSIX_RESEND_TIMER_CFG	7

typedef void (*mgmt_event_cb)(struct spnic_hwdev *hwdev, void *buf_in, u16 in_size,
			      void *buf_out, u16 *out_size);

struct mgmt_event_handle {
	u16 cmd;
	mgmt_event_cb proc;
};

int spnic_vf_handle_pf_comm_mbox(void *handle, __rte_unused void *pri_handle,
			   __rte_unused u16 cmd, __rte_unused void *buf_in,
			   __rte_unused u16 in_size, __rte_unused void *buf_out,
			   __rte_unused u16 *out_size)
{
	struct spnic_hwdev *hwdev = handle;

	if (!hwdev)
		return -EINVAL;

	PMD_DRV_LOG(WARNING, "Unsupported pf mbox event %d to process", cmd);

	return 0;
}

static void fault_event_handler(__rte_unused struct spnic_hwdev *hwdev,
				__rte_unused void *buf_in,
				__rte_unused u16 in_size,
				__rte_unused void *buf_out,
				__rte_unused u16 *out_size)
{
	PMD_DRV_LOG(WARNING, "Unsupported fault event handler");
}

static void ffm_event_msg_handler(__rte_unused struct spnic_hwdev *hwdev,
				  void *buf_in, u16 in_size,
				  __rte_unused void *buf_out, u16 *out_size)
{
	struct ffm_intr_info *intr = NULL;

	if (in_size != sizeof(*intr)) {
		PMD_DRV_LOG(ERR, "Invalid fault event report, length: %d, should be %d",
			    in_size, (int)(sizeof(*intr)));
		return;
	}

	intr = buf_in;

	PMD_DRV_LOG(ERR, "node_id: 0x%x, err_type: 0x%x, err_level: %d, "
		    "err_csr_addr: 0x%08x, err_csr_value: 0x%08x",
		    intr->node_id, intr->err_type, intr->err_level,
		    intr->err_csr_addr, intr->err_csr_value);

	*out_size = sizeof(*intr);
}

const struct mgmt_event_handle mgmt_event_proc[] = {
	{
		.cmd	= MGMT_CMD_FAULT_REPORT,
		.proc	= fault_event_handler,
	},

	{
		.cmd	= MGMT_CMD_FFM_SET,
		.proc	= ffm_event_msg_handler,
	},
};

void spnic_pf_handle_mgmt_comm_event(void *handle, __rte_unused void *pri_handle,
			       u16 cmd, void *buf_in, u16 in_size,
			       void *buf_out, u16 *out_size)
{
	struct spnic_hwdev *hwdev = handle;
	u32 i, event_num = RTE_DIM(mgmt_event_proc);

	if (!hwdev)
		return;

	for (i = 0; i < event_num; i++) {
		if (cmd == mgmt_event_proc[i].cmd) {
			if (mgmt_event_proc[i].proc)
				mgmt_event_proc[i].proc(handle, buf_in, in_size,
							buf_out, out_size);

			return;
		}
	}

	PMD_DRV_LOG(WARNING, "Unsupported mgmt cpu event %d to process", cmd);
}

/**
 * Initialize the default dma attributes
 *
 * @param[in] hwdev
 *   The pointer to the private hardware device object
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int dma_attr_table_init(struct spnic_hwdev *hwdev)
{
	u32 addr, val, dst_attr;

	/* Use indirect access should set entry_idx first */
	addr = SPNIC_CSR_DMA_ATTR_INDIR_IDX_ADDR;
	val = spnic_hwif_read_reg(hwdev->hwif, addr);
	val = SPNIC_DMA_ATTR_INDIR_IDX_CLEAR(val, IDX);

	val |= SPNIC_DMA_ATTR_INDIR_IDX_SET(PCIE_MSIX_ATTR_ENTRY, IDX);

	spnic_hwif_write_reg(hwdev->hwif, addr, val);

	rte_wmb(); /* Write index before config */

	addr = SPNIC_CSR_DMA_ATTR_TBL_ADDR;
	val = spnic_hwif_read_reg(hwdev->hwif, addr);

	dst_attr = SPNIC_DMA_ATTR_ENTRY_SET(SPNIC_PCIE_ST_DISABLE, ST)	|
		SPNIC_DMA_ATTR_ENTRY_SET(SPNIC_PCIE_AT_DISABLE, AT)	|
		SPNIC_DMA_ATTR_ENTRY_SET(SPNIC_PCIE_PH_DISABLE, PH)	|
		SPNIC_DMA_ATTR_ENTRY_SET(SPNIC_PCIE_SNOOP, NO_SNOOPING)	|
		SPNIC_DMA_ATTR_ENTRY_SET(SPNIC_PCIE_TPH_DISABLE, TPH_EN);

	if (val == dst_attr)
		return 0;

	return spnic_set_dma_attr_tbl(hwdev, PCIE_MSIX_ATTR_ENTRY,
				      SPNIC_PCIE_ST_DISABLE,
				      SPNIC_PCIE_AT_DISABLE,
				      SPNIC_PCIE_PH_DISABLE,
				      SPNIC_PCIE_SNOOP,
				      SPNIC_PCIE_TPH_DISABLE);
}

static int init_aeqs_msix_attr(struct spnic_hwdev *hwdev)
{
	struct spnic_aeqs *aeqs = hwdev->aeqs;
	struct interrupt_info info = {0};
	struct spnic_eq *eq = NULL;
	u16 q_id;
	int err;

	info.lli_set = 0;
	info.interrupt_coalesc_set = 1;
	info.pending_limt = SPNIC_DEAULT_EQ_MSIX_PENDING_LIMIT;
	info.coalesc_timer_cfg = SPNIC_DEAULT_EQ_MSIX_COALESC_TIMER_CFG;
	info.resend_timer_cfg = SPNIC_DEAULT_EQ_MSIX_RESEND_TIMER_CFG;

	for (q_id = 0; q_id < aeqs->num_aeqs; q_id++) {
		eq = &aeqs->aeq[q_id];
		info.msix_index = eq->eq_irq.msix_entry_idx;
		err = spnic_set_interrupt_cfg(hwdev, info);
		if (err) {
			PMD_DRV_LOG(ERR, "Set msix attr for aeq %d failed",
				q_id);
			return -EFAULT;
		}
	}

	return 0;
}

static int spnic_comm_pf_to_mgmt_init(struct spnic_hwdev *hwdev)
{
	int err;

	/* VF does not support send msg to mgmt directly */
	if (spnic_func_type(hwdev) == TYPE_VF)
		return 0;

	err = spnic_pf_to_mgmt_init(hwdev);
	if (err)
		return err;

	return 0;
}

static void spnic_comm_pf_to_mgmt_free(struct spnic_hwdev *hwdev)
{
	/* VF does not support send msg to mgmt directly */
	if (spnic_func_type(hwdev) == TYPE_VF)
		return;

	spnic_pf_to_mgmt_free(hwdev);
}

static int spnic_comm_cmdqs_init(struct spnic_hwdev *hwdev)
{
	int err;

	err = spnic_cmdqs_init(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init cmd queues failed");
		return err;
	}

	err = spnic_set_cmdq_depth(hwdev, SPNIC_CMDQ_DEPTH);
	if (err) {
		PMD_DRV_LOG(ERR, "Set cmdq depth failed");
		goto set_cmdq_depth_err;
	}

	return 0;

set_cmdq_depth_err:
	spnic_cmdqs_free(hwdev);

	return err;
}

static void spnic_comm_cmdqs_free(struct spnic_hwdev *hwdev)
{
	spnic_cmdqs_free(hwdev);
}

static void spnic_sync_mgmt_func_state(struct spnic_hwdev *hwdev)
{
	spnic_set_pf_status(hwdev->hwif, SPNIC_PF_STATUS_ACTIVE_FLAG);
}

static int __get_func_misc_info(struct spnic_hwdev *hwdev)
{
	int err;

	err = spnic_get_board_info(hwdev, &hwdev->board_info);
	if (err) {
		/* For the PF/VF of secondary host, return error */
		if (spnic_pcie_itf_id(hwdev))
			return err;

		memset(&hwdev->board_info, 0xff,
		       sizeof(struct spnic_board_info));
	}

	err = spnic_get_mgmt_version(hwdev, hwdev->mgmt_ver,
			SPNIC_MGMT_VERSION_MAX_LEN);
	if (err) {
		PMD_DRV_LOG(ERR, "Get mgmt cpu version failed");
		return err;
	}

	return 0;
}

static int init_mgmt_channel(struct spnic_hwdev *hwdev)
{
	int err;

	err = spnic_aeqs_init(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init async event queues failed");
		return err;
	}

	err = spnic_comm_pf_to_mgmt_init(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init mgmt channel failed");
		goto msg_init_err;
	}

	err = spnic_func_to_func_init(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init mailbox channel failed");
		goto func_to_func_init_err;
	}

	return 0;

func_to_func_init_err:
	spnic_comm_pf_to_mgmt_free(hwdev);

msg_init_err:
	spnic_aeqs_free(hwdev);

	return err;
}

static void free_mgmt_channel(struct spnic_hwdev *hwdev)
{
	spnic_func_to_func_free(hwdev);
	spnic_comm_pf_to_mgmt_free(hwdev);
	spnic_aeqs_free(hwdev);
}

static int init_cmdqs_channel(struct spnic_hwdev *hwdev)
{
	int err;

	err = dma_attr_table_init(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init dma attr table failed");
		goto dma_attr_init_err;
	}

	err = init_aeqs_msix_attr(hwdev);
	if (err)
		goto init_aeqs_msix_err;

	/* Set default wq page_size */
	hwdev->wq_page_size = SPNIC_DEFAULT_WQ_PAGE_SIZE;
	err = spnic_set_wq_page_size(hwdev, spnic_global_func_id(hwdev),
				      hwdev->wq_page_size);
	if (err) {
		PMD_DRV_LOG(ERR, "Set wq page size failed");
		goto init_wq_pg_size_err;
	}

	err = spnic_comm_cmdqs_init(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init cmd queues failed");
		goto cmdq_init_err;
	}

	return 0;

cmdq_init_err:
	if (SPNIC_FUNC_TYPE(hwdev) != TYPE_VF)
		spnic_set_wq_page_size(hwdev, spnic_global_func_id(hwdev),
					SPNIC_HW_WQ_PAGE_SIZE);
init_wq_pg_size_err:
init_aeqs_msix_err:
dma_attr_init_err:

	return err;
}

static int spnic_init_comm_ch(struct spnic_hwdev *hwdev)
{
	int err;

	err = init_mgmt_channel(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init mgmt channel failed");
		return err;
	}

	err = __get_func_misc_info(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Get function msic information failed");
		goto get_func_info_err;
	}

	err = spnic_func_reset(hwdev, SPNIC_NIC_RES | SPNIC_COMM_RES);
	if (err) {
		PMD_DRV_LOG(ERR, "Reset function failed");
		goto func_reset_err;
	}

	err = init_cmdqs_channel(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init cmdq channel failed");
		goto init_cmdqs_channel_err;
	}

	spnic_sync_mgmt_func_state(hwdev);

	return 0;

init_cmdqs_channel_err:
func_reset_err:
get_func_info_err:
	free_mgmt_channel(hwdev);

	return err;
}

static void spnic_uninit_comm_ch(struct spnic_hwdev *hwdev)
{
	spnic_set_pf_status(hwdev->hwif, SPNIC_PF_STATUS_INIT);

	spnic_comm_cmdqs_free(hwdev);

	if (SPNIC_FUNC_TYPE(hwdev) != TYPE_VF)
		spnic_set_wq_page_size(hwdev, spnic_global_func_id(hwdev),
					SPNIC_HW_WQ_PAGE_SIZE);

	free_mgmt_channel(hwdev);
}

int spnic_init_hwdev(struct spnic_hwdev *hwdev)
{
	int err;

	hwdev->chip_fault_stats = rte_zmalloc("chip_fault_stats",
					      SPNIC_CHIP_FAULT_SIZE,
					      RTE_CACHE_LINE_SIZE);
	if (!hwdev->chip_fault_stats) {
		PMD_DRV_LOG(ERR, "Alloc memory for chip_fault_stats failed");
		return -ENOMEM;
	}

	err = spnic_init_hwif(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Initialize hwif failed");
		goto init_hwif_err;
	}

	err = spnic_init_comm_ch(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init communication channel failed");
		goto init_comm_ch_err;
	}

	err = spnic_init_capability(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init capability failed");
		goto init_cap_err;
	}

	err = spnic_set_comm_features(hwdev, hwdev->features,
				       MAX_FEATURE_QWORD);
	if (err) {
		PMD_DRV_LOG(ERR, "Failed to set comm features\n");
		goto set_feature_err;
	}

	return 0;

set_feature_err:
	spnic_free_capability(hwdev);

init_cap_err:
	spnic_uninit_comm_ch(hwdev);

init_comm_ch_err:
	spnic_free_hwif(hwdev);

init_hwif_err:
	rte_free(hwdev->chip_fault_stats);

	return -EFAULT;
}

void spnic_free_hwdev(struct spnic_hwdev *hwdev)
{
	spnic_free_capability(hwdev);

	spnic_uninit_comm_ch(hwdev);

	spnic_free_hwif(hwdev);

	rte_free(hwdev->chip_fault_stats);
}
