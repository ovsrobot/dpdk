/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2020 Intel Corporation
 */

#include "dlb2_user.h"

#include "dlb2_hw_types.h"
#include "dlb2_mbox.h"
#include "dlb2_osdep.h"
#include "dlb2_osdep_bitmap.h"
#include "dlb2_osdep_types.h"
#include "dlb2_regs.h"
#include "dlb2_resource.h"

#include "../../dlb2_priv.h"
#include "../../dlb2_inline_fns.h"

#define DLB2_DOM_LIST_HEAD(head, type) \
	DLB2_LIST_HEAD((head), type, domain_list)

#define DLB2_FUNC_LIST_HEAD(head, type) \
	DLB2_LIST_HEAD((head), type, func_list)

#define DLB2_DOM_LIST_FOR(head, ptr, iter) \
	DLB2_LIST_FOR_EACH(head, ptr, domain_list, iter)

#define DLB2_FUNC_LIST_FOR(head, ptr, iter) \
	DLB2_LIST_FOR_EACH(head, ptr, func_list, iter)

#define DLB2_DOM_LIST_FOR_SAFE(head, ptr, ptr_tmp, it, it_tmp) \
	DLB2_LIST_FOR_EACH_SAFE((head), ptr, ptr_tmp, domain_list, it, it_tmp)

#define DLB2_FUNC_LIST_FOR_SAFE(head, ptr, ptr_tmp, it, it_tmp) \
	DLB2_LIST_FOR_EACH_SAFE((head), ptr, ptr_tmp, func_list, it, it_tmp)

void dlb2_hw_enable_sparse_dir_cq_mode(struct dlb2_hw *hw)
{
	union dlb2_chp_cfg_chp_csr_ctrl r0;

	r0.val = DLB2_CSR_RD(hw, DLB2_CHP_CFG_CHP_CSR_CTRL);

	r0.field.cfg_64bytes_qe_dir_cq_mode = 1;

	DLB2_CSR_WR(hw, DLB2_CHP_CFG_CHP_CSR_CTRL, r0.val);
}

void dlb2_hw_enable_sparse_ldb_cq_mode(struct dlb2_hw *hw)
{
	union dlb2_chp_cfg_chp_csr_ctrl r0;

	r0.val = DLB2_CSR_RD(hw, DLB2_CHP_CFG_CHP_CSR_CTRL);

	r0.field.cfg_64bytes_qe_ldb_cq_mode = 1;

	DLB2_CSR_WR(hw, DLB2_CHP_CFG_CHP_CSR_CTRL, r0.val);
}

/*
 * The PF driver cannot assume that a register write will affect subsequent HCW
 * writes. To ensure a write completes, the driver must read back a CSR. This
 * function only need be called for configuration that can occur after the
 * domain has started; prior to starting, applications can't send HCWs.
 */
static inline void dlb2_flush_csr(struct dlb2_hw *hw)
{
	DLB2_CSR_RD(hw, DLB2_SYS_TOTAL_VAS);
}

int dlb2_get_group_sequence_numbers(struct dlb2_hw *hw, unsigned int group_id)
{
	if (group_id >= DLB2_MAX_NUM_SEQUENCE_NUMBER_GROUPS)
		return -EINVAL;

	return hw->rsrcs.sn_groups[group_id].sequence_numbers_per_queue;
}

int dlb2_get_group_sequence_number_occupancy(struct dlb2_hw *hw,
					     unsigned int group_id)
{
	if (group_id >= DLB2_MAX_NUM_SEQUENCE_NUMBER_GROUPS)
		return -EINVAL;

	return dlb2_sn_group_used_slots(&hw->rsrcs.sn_groups[group_id]);
}

static void dlb2_log_set_group_sequence_numbers(struct dlb2_hw *hw,
						unsigned int group_id,
						unsigned long val)
{
	DLB2_HW_DBG(hw, "DLB2 set group sequence numbers:\n");
	DLB2_HW_DBG(hw, "\tGroup ID: %u\n", group_id);
	DLB2_HW_DBG(hw, "\tValue:    %lu\n", val);
}

int dlb2_set_group_sequence_numbers(struct dlb2_hw *hw,
				    unsigned int group_id,
				    unsigned long val)
{
	u32 valid_allocations[] = {64, 128, 256, 512, 1024};
	union dlb2_ro_pipe_grp_sn_mode r0 = { {0} };
	struct dlb2_sn_group *group;
	int mode;

	if (group_id >= DLB2_MAX_NUM_SEQUENCE_NUMBER_GROUPS)
		return -EINVAL;

	group = &hw->rsrcs.sn_groups[group_id];

	/*
	 * Once the first load-balanced queue using an SN group is configured,
	 * the group cannot be changed.
	 */
	if (group->slot_use_bitmap != 0)
		return -EPERM;

	for (mode = 0; mode < DLB2_MAX_NUM_SEQUENCE_NUMBER_MODES; mode++)
		if (val == valid_allocations[mode])
			break;

	if (mode == DLB2_MAX_NUM_SEQUENCE_NUMBER_MODES)
		return -EINVAL;

	group->mode = mode;
	group->sequence_numbers_per_queue = val;

	r0.field.sn_mode_0 = hw->rsrcs.sn_groups[0].mode;
	r0.field.sn_mode_1 = hw->rsrcs.sn_groups[1].mode;

	DLB2_CSR_WR(hw, DLB2_RO_PIPE_GRP_SN_MODE, r0.val);

	dlb2_log_set_group_sequence_numbers(hw, group_id, val);

	return 0;
}

static struct dlb2_dir_pq_pair *
dlb2_get_domain_used_dir_pq(struct dlb2_hw *hw,
			    u32 id,
			    bool vdev_req,
			    struct dlb2_hw_domain *domain)
{
	struct dlb2_list_entry *iter;
	struct dlb2_dir_pq_pair *port;
	RTE_SET_USED(iter);

	if (id >= DLB2_MAX_NUM_DIR_PORTS(hw->ver))
		return NULL;

	DLB2_DOM_LIST_FOR(domain->used_dir_pq_pairs, port, iter)
		if ((!vdev_req && port->id.phys_id == id) ||
		    (vdev_req && port->id.virt_id == id))
			return port;

	return NULL;
}

static struct dlb2_ldb_queue *
dlb2_get_domain_ldb_queue(u32 id,
			  bool vdev_req,
			  struct dlb2_hw_domain *domain)
{
	struct dlb2_list_entry *iter;
	struct dlb2_ldb_queue *queue;
	RTE_SET_USED(iter);

	if (id >= DLB2_MAX_NUM_LDB_QUEUES)
		return NULL;

	DLB2_DOM_LIST_FOR(domain->used_ldb_queues, queue, iter)
		if ((!vdev_req && queue->id.phys_id == id) ||
		    (vdev_req && queue->id.virt_id == id))
			return queue;

	return NULL;
}

static void dlb2_log_get_dir_queue_depth(struct dlb2_hw *hw,
					 u32 domain_id,
					 u32 queue_id,
					 bool vdev_req,
					 unsigned int vf_id)
{
	DLB2_HW_DBG(hw, "DLB get directed queue depth:\n");
	if (vdev_req)
		DLB2_HW_DBG(hw, "(Request from VF %d)\n", vf_id);
	DLB2_HW_DBG(hw, "\tDomain ID: %d\n", domain_id);
	DLB2_HW_DBG(hw, "\tQueue ID: %d\n", queue_id);
}

int dlb2_hw_get_dir_queue_depth(struct dlb2_hw *hw,
				u32 domain_id,
				struct dlb2_get_dir_queue_depth_args *args,
				struct dlb2_cmd_response *resp,
				bool vdev_req,
				unsigned int vdev_id)
{
	struct dlb2_dir_pq_pair *queue;
	struct dlb2_hw_domain *domain;
	int id;

	id = domain_id;

	dlb2_log_get_dir_queue_depth(hw, domain_id, args->queue_id,
				     vdev_req, vdev_id);

	domain = dlb2_get_domain_from_id(hw, id, vdev_req, vdev_id);
	if (domain == NULL) {
		resp->status = DLB2_ST_INVALID_DOMAIN_ID;
		return -EINVAL;
	}

	id = args->queue_id;

	queue = dlb2_get_domain_used_dir_pq(hw, id, vdev_req, domain);
	if (queue == NULL) {
		resp->status = DLB2_ST_INVALID_QID;
		return -EINVAL;
	}

	resp->id = dlb2_dir_queue_depth(hw, queue);

	return 0;
}

static void dlb2_log_get_ldb_queue_depth(struct dlb2_hw *hw,
					 u32 domain_id,
					 u32 queue_id,
					 bool vdev_req,
					 unsigned int vf_id)
{
	DLB2_HW_DBG(hw, "DLB get load-balanced queue depth:\n");
	if (vdev_req)
		DLB2_HW_DBG(hw, "(Request from VF %d)\n", vf_id);
	DLB2_HW_DBG(hw, "\tDomain ID: %d\n", domain_id);
	DLB2_HW_DBG(hw, "\tQueue ID: %d\n", queue_id);
}

int dlb2_hw_get_ldb_queue_depth(struct dlb2_hw *hw,
				u32 domain_id,
				struct dlb2_get_ldb_queue_depth_args *args,
				struct dlb2_cmd_response *resp,
				bool vdev_req,
				unsigned int vdev_id)
{
	struct dlb2_hw_domain *domain;
	struct dlb2_ldb_queue *queue;

	dlb2_log_get_ldb_queue_depth(hw, domain_id, args->queue_id,
				     vdev_req, vdev_id);

	domain = dlb2_get_domain_from_id(hw, domain_id, vdev_req, vdev_id);
	if (domain == NULL) {
		resp->status = DLB2_ST_INVALID_DOMAIN_ID;
		return -EINVAL;
	}

	queue = dlb2_get_domain_ldb_queue(args->queue_id, vdev_req, domain);
	if (queue == NULL) {
		resp->status = DLB2_ST_INVALID_QID;
		return -EINVAL;
	}

	resp->id = dlb2_ldb_queue_depth(hw, queue);

	return 0;
}
