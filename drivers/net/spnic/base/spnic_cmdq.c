/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <rte_mbuf.h>

#include "spnic_compat.h"
#include "spnic_hwdev.h"
#include "spnic_hwif.h"
#include "spnic_wq.h"
#include "spnic_cmd.h"
#include "spnic_mgmt.h"
#include "spnic_cmdq.h"

#define CMDQ_CTXT_CURR_WQE_PAGE_PFN_SHIFT		0
#define CMDQ_CTXT_EQ_ID_SHIFT				53
#define CMDQ_CTXT_CEQ_ARM_SHIFT				61
#define CMDQ_CTXT_CEQ_EN_SHIFT				62
#define CMDQ_CTXT_HW_BUSY_BIT_SHIFT			63

#define CMDQ_CTXT_CURR_WQE_PAGE_PFN_MASK		0xFFFFFFFFFFFFF
#define CMDQ_CTXT_EQ_ID_MASK				0xFF
#define CMDQ_CTXT_CEQ_ARM_MASK				0x1
#define CMDQ_CTXT_CEQ_EN_MASK				0x1
#define CMDQ_CTXT_HW_BUSY_BIT_MASK			0x1

#define CMDQ_CTXT_PAGE_INFO_SET(val, member)		\
	(((u64)(val) & CMDQ_CTXT_##member##_MASK) << CMDQ_CTXT_##member##_SHIFT)

#define CMDQ_CTXT_WQ_BLOCK_PFN_SHIFT			0
#define CMDQ_CTXT_CI_SHIFT				52

#define CMDQ_CTXT_WQ_BLOCK_PFN_MASK			0xFFFFFFFFFFFFF
#define CMDQ_CTXT_CI_MASK				0xFFF

#define CMDQ_CTXT_BLOCK_INFO_SET(val, member)		\
	(((u64)(val) & CMDQ_CTXT_##member##_MASK) << CMDQ_CTXT_##member##_SHIFT)

#define WAIT_CMDQ_ENABLE_TIMEOUT	300

static int init_cmdq(struct spnic_cmdq *cmdq, struct spnic_hwdev *hwdev,
		     struct spnic_wq *wq, enum spnic_cmdq_type q_type)
{
	void *db_base = NULL;
	int err = 0;
	size_t errcode_size;
	size_t cmd_infos_size;

	cmdq->wq = wq;
	cmdq->cmdq_type = q_type;
	cmdq->wrapped = 1;

	rte_spinlock_init(&cmdq->cmdq_lock);

	errcode_size = wq->q_depth * sizeof(*cmdq->errcode);
	cmdq->errcode = rte_zmalloc(NULL, errcode_size, 0);
	if (!cmdq->errcode) {
		PMD_DRV_LOG(ERR, "Allocate errcode for cmdq failed");
		return -ENOMEM;
	}

	cmd_infos_size = wq->q_depth * sizeof(*cmdq->cmd_infos);
	cmdq->cmd_infos = rte_zmalloc(NULL, cmd_infos_size, 0);
	if (!cmdq->cmd_infos) {
		PMD_DRV_LOG(ERR, "Allocate cmd info for cmdq failed");
		err = -ENOMEM;
		goto cmd_infos_err;
	}

	err = spnic_alloc_db_addr(hwdev, &db_base, NULL);
	if (err)
		goto alloc_db_err;

	cmdq->db_base = (u8 *)db_base;

	return 0;

alloc_db_err:
	rte_free(cmdq->cmd_infos);

cmd_infos_err:
	rte_free(cmdq->errcode);

	return err;
}

static void free_cmdq(struct spnic_hwdev *hwdev, struct spnic_cmdq *cmdq)
{
	spnic_free_db_addr(hwdev, cmdq->db_base, NULL);
	rte_free(cmdq->cmd_infos);
	rte_free(cmdq->errcode);
}

static int spnic_set_cmdq_ctxts(struct spnic_hwdev *hwdev)
{
	struct spnic_cmdqs *cmdqs = hwdev->cmdqs;
	struct spnic_cmd_cmdq_ctxt cmdq_ctxt;
	enum spnic_cmdq_type cmdq_type;
	u16 out_size = sizeof(cmdq_ctxt);
	int err;

	cmdq_type = SPNIC_CMDQ_SYNC;
	for (; cmdq_type < SPNIC_MAX_CMDQ_TYPES; cmdq_type++) {
		memset(&cmdq_ctxt, 0, sizeof(cmdq_ctxt));
		memcpy(&cmdq_ctxt.ctxt_info, &cmdqs->cmdq[cmdq_type].cmdq_ctxt,
			sizeof(cmdq_ctxt.ctxt_info));
		cmdq_ctxt.func_idx = spnic_global_func_id(hwdev);
		cmdq_ctxt.cmdq_id = cmdq_type;

		err = spnic_msg_to_mgmt_sync(hwdev, SPNIC_MOD_COMM,
					     MGMT_CMD_SET_CMDQ_CTXT,
					     &cmdq_ctxt, sizeof(cmdq_ctxt),
					     &cmdq_ctxt, &out_size, 0);
		if (err || !out_size || cmdq_ctxt.status) {
			PMD_DRV_LOG(ERR, "Set cmdq ctxt failed, err: %d, status: 0x%x, out_size: 0x%x",
				    err, cmdq_ctxt.status, out_size);
			return -EFAULT;
		}
	}

	cmdqs->status |= SPNIC_CMDQ_ENABLE;

	return 0;
}

int spnic_reinit_cmdq_ctxts(struct spnic_hwdev *hwdev)
{
	return spnic_set_cmdq_ctxts(hwdev);
}

int spnic_cmdqs_init(struct spnic_hwdev *hwdev)
{
	struct spnic_cmdqs *cmdqs = NULL;
	enum spnic_cmdq_type type, cmdq_type;
	char cmdq_pool_name[RTE_MEMPOOL_NAMESIZE];
	int err;

	cmdqs = rte_zmalloc(NULL, sizeof(*cmdqs), 0);
	if (!cmdqs)
		return -ENOMEM;

	hwdev->cmdqs = cmdqs;
	cmdqs->hwdev = hwdev;

	memset(cmdq_pool_name, 0, RTE_MEMPOOL_NAMESIZE);
	snprintf(cmdq_pool_name, sizeof(cmdq_pool_name), "spnic_cmdq_%u",
		 hwdev->port_id);

	cmdqs->cmd_buf_pool = rte_pktmbuf_pool_create(cmdq_pool_name,
				SPNIC_CMDQ_DEPTH * SPNIC_MAX_CMDQ_TYPES,
				0, 0, SPNIC_CMDQ_BUF_SIZE, rte_socket_id());
	if (!cmdqs->cmd_buf_pool) {
		PMD_DRV_LOG(ERR, "Create cmdq buffer pool failed");
		err = -ENOMEM;
		goto pool_create_err;
	}

	cmdq_type = SPNIC_CMDQ_SYNC;
	for (; cmdq_type < SPNIC_MAX_CMDQ_TYPES; cmdq_type++) {
		err = init_cmdq(&cmdqs->cmdq[cmdq_type], hwdev,
				&cmdqs->saved_wqs[cmdq_type], cmdq_type);
		if (err) {
			PMD_DRV_LOG(ERR, "Initialize cmdq failed");
			goto init_cmdq_err;
		}
	}

	err = spnic_set_cmdq_ctxts(hwdev);
	if (err)
		goto init_cmdq_err;

	return 0;

init_cmdq_err:
	type = SPNIC_CMDQ_SYNC;
	for (; type < cmdq_type; type++)
		free_cmdq(hwdev, &cmdqs->cmdq[type]);

	rte_mempool_free(cmdqs->cmd_buf_pool);

pool_create_err:
	rte_free(cmdqs);

	return err;
}

void spnic_cmdqs_free(struct spnic_hwdev *hwdev)
{
	struct spnic_cmdqs *cmdqs = hwdev->cmdqs;
	enum spnic_cmdq_type cmdq_type = SPNIC_CMDQ_SYNC;

	cmdqs->status &= ~SPNIC_CMDQ_ENABLE;

	for (; cmdq_type < SPNIC_MAX_CMDQ_TYPES; cmdq_type++)
		free_cmdq(cmdqs->hwdev, &cmdqs->cmdq[cmdq_type]);

	rte_mempool_free(cmdqs->cmd_buf_pool);

	rte_free(cmdqs->saved_wqs);

	rte_free(cmdqs);
}
