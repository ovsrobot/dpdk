/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2017 Intel Corporation
 */
#include <rte_tm_driver.h>

#include "base/ice_sched.h"
#include "ice_dcf_ethdev.h"

static int ice_dcf_hierarchy_commit(struct rte_eth_dev *dev,
				 __rte_unused int clear_on_fail,
				 __rte_unused struct rte_tm_error *error);
static int ice_dcf_node_add(struct rte_eth_dev *dev, uint32_t node_id,
	      uint32_t parent_node_id, uint32_t priority,
	      uint32_t weight, uint32_t level_id,
	      struct rte_tm_node_params *params,
	      struct rte_tm_error *error);
static int ice_dcf_node_delete(struct rte_eth_dev *dev, uint32_t node_id,
			    struct rte_tm_error *error);
static int ice_dcf_shaper_profile_add(struct rte_eth_dev *dev,
			uint32_t shaper_profile_id,
			struct rte_tm_shaper_params *profile,
			struct rte_tm_error *error);
static int ice_dcf_shaper_profile_del(struct rte_eth_dev *dev,
				   uint32_t shaper_profile_id,
				   struct rte_tm_error *error);

const struct rte_tm_ops ice_dcf_tm_ops = {
	.shaper_profile_add = ice_dcf_shaper_profile_add,
	.shaper_profile_delete = ice_dcf_shaper_profile_del,
	.hierarchy_commit = ice_dcf_hierarchy_commit,
	.node_add = ice_dcf_node_add,
	.node_delete = ice_dcf_node_delete,
};

void
ice_dcf_tm_conf_init(struct rte_eth_dev *dev)
{
	struct ice_dcf_adapter *adapter = dev->data->dev_private;
	struct ice_dcf_hw *hw = &adapter->real_hw;

	/* initialize shaper profile list */
	TAILQ_INIT(&hw->tm_conf.shaper_profile_list);

	/* initialize node configuration */
	hw->tm_conf.root = NULL;
	TAILQ_INIT(&hw->tm_conf.tc_list);
	TAILQ_INIT(&hw->tm_conf.vsi_list);
	hw->tm_conf.nb_tc_node = 0;
	hw->tm_conf.nb_vsi_node = 0;
	hw->tm_conf.committed = false;
}

static inline struct ice_dcf_tm_node *
dcf_tm_node_search(struct rte_eth_dev *dev,
		    uint32_t node_id, enum ice_dcf_tm_node_type *node_type)
{
	struct ice_dcf_adapter *adapter = dev->data->dev_private;
	struct ice_dcf_hw *hw = &adapter->real_hw;
	struct ice_dcf_tm_node_list *vsi_list = &hw->tm_conf.vsi_list;
	struct ice_dcf_tm_node_list *tc_list = &hw->tm_conf.tc_list;
	struct ice_dcf_tm_node *tm_node;

	if (hw->tm_conf.root && hw->tm_conf.root->id == node_id) {
		*node_type = ICE_DCF_TM_NODE_TYPE_PORT;
		return hw->tm_conf.root;
	}

	TAILQ_FOREACH(tm_node, tc_list, node) {
		if (tm_node->id == node_id) {
			*node_type = ICE_DCF_TM_NODE_TYPE_TC;
			return tm_node;
		}
	}

	TAILQ_FOREACH(tm_node, vsi_list, node) {
		if (tm_node->id == node_id) {
			*node_type = ICE_DCF_TM_NODE_TYPE_VSI;
			return tm_node;
		}
	}

	return NULL;
}

static inline struct ice_dcf_tm_shaper_profile *
dcf_shaper_profile_search(struct rte_eth_dev *dev,
			   uint32_t shaper_profile_id)
{
	struct ice_dcf_adapter *adapter = dev->data->dev_private;
	struct ice_dcf_hw *hw = &adapter->real_hw;
	struct ice_dcf_shaper_profile_list *shaper_profile_list =
		&hw->tm_conf.shaper_profile_list;
	struct ice_dcf_tm_shaper_profile *shaper_profile;

	TAILQ_FOREACH(shaper_profile, shaper_profile_list, node) {
		if (shaper_profile_id == shaper_profile->shaper_profile_id)
			return shaper_profile;
	}

	return NULL;
}

static int
dcf_node_param_check(struct ice_dcf_hw *hw, uint32_t node_id,
		      uint32_t priority, uint32_t weight,
		      struct rte_tm_node_params *params,
		      struct rte_tm_error *error)
{
	/* checked all the unsupported parameter */
	if (node_id == RTE_TM_NODE_ID_NULL) {
		error->type = RTE_TM_ERROR_TYPE_NODE_ID;
		error->message = "invalid node id";
		return -EINVAL;
	}

	if (priority) {
		error->type = RTE_TM_ERROR_TYPE_NODE_PRIORITY;
		error->message = "priority should be 0";
		return -EINVAL;
	}

	if (weight != 1) {
		error->type = RTE_TM_ERROR_TYPE_NODE_WEIGHT;
		error->message = "weight must be 1";
		return -EINVAL;
	}

	/* not support shared shaper */
	if (params->shared_shaper_id) {
		error->type = RTE_TM_ERROR_TYPE_NODE_PARAMS_SHARED_SHAPER_ID;
		error->message = "shared shaper not supported";
		return -EINVAL;
	}
	if (params->n_shared_shapers) {
		error->type = RTE_TM_ERROR_TYPE_NODE_PARAMS_N_SHARED_SHAPERS;
		error->message = "shared shaper not supported";
		return -EINVAL;
	}

	/* for non-leaf node */
	if (node_id >= 8 * hw->num_vfs) {
		if (params->nonleaf.wfq_weight_mode) {
			error->type =
				RTE_TM_ERROR_TYPE_NODE_PARAMS_WFQ_WEIGHT_MODE;
			error->message = "WFQ not supported";
			return -EINVAL;
		}
		if (params->nonleaf.n_sp_priorities != 1) {
			error->type =
				RTE_TM_ERROR_TYPE_NODE_PARAMS_N_SP_PRIORITIES;
			error->message = "SP priority not supported";
			return -EINVAL;
		} else if (params->nonleaf.wfq_weight_mode &&
			   !(*params->nonleaf.wfq_weight_mode)) {
			error->type =
				RTE_TM_ERROR_TYPE_NODE_PARAMS_WFQ_WEIGHT_MODE;
			error->message = "WFP should be byte mode";
			return -EINVAL;
		}

		return 0;
	}

	/* for leaf node */
	if (params->leaf.cman) {
		error->type = RTE_TM_ERROR_TYPE_NODE_PARAMS_CMAN;
		error->message = "Congestion management not supported";
		return -EINVAL;
	}
	if (params->leaf.wred.wred_profile_id !=
	    RTE_TM_WRED_PROFILE_ID_NONE) {
		error->type =
			RTE_TM_ERROR_TYPE_NODE_PARAMS_WRED_PROFILE_ID;
		error->message = "WRED not supported";
		return -EINVAL;
	}
	if (params->leaf.wred.shared_wred_context_id) {
		error->type =
			RTE_TM_ERROR_TYPE_NODE_PARAMS_SHARED_WRED_CONTEXT_ID;
		error->message = "WRED not supported";
		return -EINVAL;
	}
	if (params->leaf.wred.n_shared_wred_contexts) {
		error->type =
			RTE_TM_ERROR_TYPE_NODE_PARAMS_N_SHARED_WRED_CONTEXTS;
		error->message = "WRED not supported";
		return -EINVAL;
	}

	return 0;
}

static int
ice_dcf_node_add(struct rte_eth_dev *dev, uint32_t node_id,
	      uint32_t parent_node_id, uint32_t priority,
	      uint32_t weight, uint32_t level_id,
	      struct rte_tm_node_params *params,
	      struct rte_tm_error *error)
{
	enum ice_dcf_tm_node_type parent_node_type = ICE_DCF_TM_NODE_TYPE_MAX;
	enum ice_dcf_tm_node_type node_type = ICE_DCF_TM_NODE_TYPE_MAX;
	struct ice_dcf_tm_shaper_profile *shaper_profile = NULL;
	struct ice_dcf_adapter *adapter = dev->data->dev_private;
	struct ice_dcf_hw *hw = &adapter->real_hw;
	struct ice_dcf_tm_node *parent_node;
	struct ice_dcf_tm_node *tm_node;
	uint16_t tc_nb = 1;
	int i, ret;

	if (!params || !error)
		return -EINVAL;

	/* if already committed */
	if (hw->tm_conf.committed) {
		error->type = RTE_TM_ERROR_TYPE_UNSPECIFIED;
		error->message = "already committed";
		return -EINVAL;
	}

	ret = dcf_node_param_check(hw, node_id, priority, weight,
				   params, error);
	if (ret)
		return ret;

	for (i = 1; i < ICE_MAX_TRAFFIC_CLASS; i++) {
		if (hw->ets_config->tc_valid_bits & (1 << i))
			tc_nb++;
	}

	/* check if the node is already existed */
	if (dcf_tm_node_search(dev, node_id, &node_type)) {
		error->type = RTE_TM_ERROR_TYPE_NODE_ID;
		error->message = "node id already used";
		return -EINVAL;
	}

	/* check the shaper profile id */
	if (params->shaper_profile_id != RTE_TM_SHAPER_PROFILE_ID_NONE) {
		shaper_profile = dcf_shaper_profile_search(dev,
			params->shaper_profile_id);
		if (!shaper_profile) {
			error->type =
				RTE_TM_ERROR_TYPE_NODE_PARAMS_SHAPER_PROFILE_ID;
			error->message = "shaper profile not exist";
			return -EINVAL;
		}
	}

	/* add root node if not have a parent */
	if (parent_node_id == RTE_TM_NODE_ID_NULL) {
		/* check level */
		if (level_id != ICE_DCF_TM_NODE_TYPE_PORT) {
			error->type = RTE_TM_ERROR_TYPE_NODE_PARAMS;
			error->message = "Wrong level";
			return -EINVAL;
		}

		/* obviously no more than one root */
		if (hw->tm_conf.root) {
			error->type = RTE_TM_ERROR_TYPE_NODE_PARENT_NODE_ID;
			error->message = "already have a root";
			return -EINVAL;
		}

		/* add the root node */
		tm_node = rte_zmalloc("ice_dcf_tm_node",
				      sizeof(struct ice_dcf_tm_node),
				      0);
		if (!tm_node)
			return -ENOMEM;
		tm_node->id = node_id;
		tm_node->parent = NULL;
		tm_node->reference_count = 0;
		rte_memcpy(&tm_node->params, params,
				 sizeof(struct rte_tm_node_params));
		hw->tm_conf.root = tm_node;

		return 0;
	}

	/* TC or vsi node */
	/* check the parent node */
	parent_node = dcf_tm_node_search(dev, parent_node_id,
					  &parent_node_type);
	if (!parent_node) {
		error->type = RTE_TM_ERROR_TYPE_NODE_PARENT_NODE_ID;
		error->message = "parent not exist";
		return -EINVAL;
	}
	if (parent_node_type != ICE_DCF_TM_NODE_TYPE_PORT &&
	    parent_node_type != ICE_DCF_TM_NODE_TYPE_TC) {
		error->type = RTE_TM_ERROR_TYPE_NODE_PARENT_NODE_ID;
		error->message = "parent is not port or TC";
		return -EINVAL;
	}
	/* check level */
	if (level_id != RTE_TM_NODE_LEVEL_ID_ANY &&
	    level_id != parent_node_type + 1) {
		error->type = RTE_TM_ERROR_TYPE_NODE_PARAMS;
		error->message = "Wrong level";
		return -EINVAL;
	}

	/* check the TC node number */
	if (parent_node_type == ICE_DCF_TM_NODE_TYPE_PORT) {
		/* check the TC number */
		if (hw->tm_conf.nb_tc_node >= tc_nb) {
			error->type = RTE_TM_ERROR_TYPE_NODE_ID;
			error->message = "too many TCs";
			return -EINVAL;
		}
	} else {
		/* check the vsi node number */
		if (parent_node->reference_count >= hw->num_vfs) {
			error->type = RTE_TM_ERROR_TYPE_NODE_ID;
			error->message = "too many VSI for one TC";
			return -EINVAL;
		}
		/* check the vsi node id */
		if (node_id > tc_nb * hw->num_vfs) {
			error->type = RTE_TM_ERROR_TYPE_NODE_ID;
			error->message = "too large VSI id";
			return -EINVAL;
		}
	}

	/* add the TC or vsi node */
	tm_node = rte_zmalloc("ice_dcf_tm_node",
			      sizeof(struct ice_dcf_tm_node),
			      0);
	if (!tm_node)
		return -ENOMEM;
	tm_node->id = node_id;
	tm_node->priority = priority;
	tm_node->weight = weight;
	tm_node->shaper_profile = shaper_profile;
	tm_node->reference_count = 0;
	tm_node->parent = parent_node;
	rte_memcpy(&tm_node->params, params,
			 sizeof(struct rte_tm_node_params));
	if (parent_node_type == ICE_DCF_TM_NODE_TYPE_PORT) {
		TAILQ_INSERT_TAIL(&hw->tm_conf.tc_list,
				  tm_node, node);
		tm_node->tc = hw->tm_conf.nb_tc_node;
		hw->tm_conf.nb_tc_node++;
	} else {
		TAILQ_INSERT_TAIL(&hw->tm_conf.vsi_list,
				  tm_node, node);
		tm_node->tc = parent_node->tc;
		hw->tm_conf.nb_vsi_node++;
	}
	tm_node->parent->reference_count++;

	/* increase the reference counter of the shaper profile */
	if (shaper_profile)
		shaper_profile->reference_count++;

	return 0;
}

static int
ice_dcf_node_delete(struct rte_eth_dev *dev, uint32_t node_id,
		 struct rte_tm_error *error)
{
	enum ice_dcf_tm_node_type node_type = ICE_DCF_TM_NODE_TYPE_MAX;
	struct ice_dcf_adapter *adapter = dev->data->dev_private;
	struct ice_dcf_hw *hw = &adapter->real_hw;
	struct ice_dcf_tm_node *tm_node;

	if (!error)
		return -EINVAL;

	/* if already committed */
	if (hw->tm_conf.committed) {
		error->type = RTE_TM_ERROR_TYPE_UNSPECIFIED;
		error->message = "already committed";
		return -EINVAL;
	}

	if (node_id == RTE_TM_NODE_ID_NULL) {
		error->type = RTE_TM_ERROR_TYPE_NODE_ID;
		error->message = "invalid node id";
		return -EINVAL;
	}

	/* check if the node id exists */
	tm_node = dcf_tm_node_search(dev, node_id, &node_type);
	if (!tm_node) {
		error->type = RTE_TM_ERROR_TYPE_NODE_ID;
		error->message = "no such node";
		return -EINVAL;
	}

	/* the node should have no child */
	if (tm_node->reference_count) {
		error->type = RTE_TM_ERROR_TYPE_NODE_ID;
		error->message =
			"cannot delete a node which has children";
		return -EINVAL;
	}

	/* root node */
	if (node_type == ICE_DCF_TM_NODE_TYPE_PORT) {
		if (tm_node->shaper_profile)
			tm_node->shaper_profile->reference_count--;
		rte_free(tm_node);
		hw->tm_conf.root = NULL;
		return 0;
	}

	/* TC or VSI node */
	if (tm_node->shaper_profile)
		tm_node->shaper_profile->reference_count--;
	tm_node->parent->reference_count--;
	if (node_type == ICE_DCF_TM_NODE_TYPE_TC) {
		TAILQ_REMOVE(&hw->tm_conf.tc_list, tm_node, node);
		hw->tm_conf.nb_tc_node--;
	} else {
		TAILQ_REMOVE(&hw->tm_conf.vsi_list, tm_node, node);
		hw->tm_conf.nb_vsi_node--;
	}
	rte_free(tm_node);

	return 0;
}

static int
dcf_shaper_profile_param_check(struct rte_tm_shaper_params *profile,
				struct rte_tm_error *error)
{
	/* min bucket size not supported */
	if (profile->committed.size) {
		error->type = RTE_TM_ERROR_TYPE_SHAPER_PROFILE_COMMITTED_SIZE;
		error->message = "committed bucket size not supported";
		return -EINVAL;
	}
	/* max bucket size not supported */
	if (profile->peak.size) {
		error->type = RTE_TM_ERROR_TYPE_SHAPER_PROFILE_PEAK_SIZE;
		error->message = "peak bucket size not supported";
		return -EINVAL;
	}
	/* length adjustment not supported */
	if (profile->pkt_length_adjust) {
		error->type = RTE_TM_ERROR_TYPE_SHAPER_PROFILE_PKT_ADJUST_LEN;
		error->message = "packet length adjustment not supported";
		return -EINVAL;
	}

	return 0;
}

static int
ice_dcf_shaper_profile_add(struct rte_eth_dev *dev,
			uint32_t shaper_profile_id,
			struct rte_tm_shaper_params *profile,
			struct rte_tm_error *error)
{
	struct ice_dcf_adapter *adapter = dev->data->dev_private;
	struct ice_dcf_hw *hw = &adapter->real_hw;
	struct ice_dcf_tm_shaper_profile *shaper_profile;
	int ret;

	if (!profile || !error)
		return -EINVAL;

	ret = dcf_shaper_profile_param_check(profile, error);
	if (ret)
		return ret;

	shaper_profile = dcf_shaper_profile_search(dev, shaper_profile_id);

	if (shaper_profile) {
		error->type = RTE_TM_ERROR_TYPE_SHAPER_PROFILE_ID;
		error->message = "profile ID exist";
		return -EINVAL;
	}

	shaper_profile = rte_zmalloc("ice_dcf_tm_shaper_profile",
				     sizeof(struct ice_dcf_tm_shaper_profile),
				     0);
	if (!shaper_profile)
		return -ENOMEM;
	shaper_profile->shaper_profile_id = shaper_profile_id;
	rte_memcpy(&shaper_profile->profile, profile,
			 sizeof(struct rte_tm_shaper_params));
	TAILQ_INSERT_TAIL(&hw->tm_conf.shaper_profile_list,
			  shaper_profile, node);

	return 0;
}

static int
ice_dcf_shaper_profile_del(struct rte_eth_dev *dev,
			uint32_t shaper_profile_id,
			struct rte_tm_error *error)
{
	struct ice_dcf_adapter *adapter = dev->data->dev_private;
	struct ice_dcf_hw *hw = &adapter->real_hw;
	struct ice_dcf_tm_shaper_profile *shaper_profile;

	if (!error)
		return -EINVAL;

	shaper_profile = dcf_shaper_profile_search(dev, shaper_profile_id);

	if (!shaper_profile) {
		error->type = RTE_TM_ERROR_TYPE_SHAPER_PROFILE_ID;
		error->message = "profile ID not exist";
		return -EINVAL;
	}

	/* don't delete a profile if it's used by one or several nodes */
	if (shaper_profile->reference_count) {
		error->type = RTE_TM_ERROR_TYPE_SHAPER_PROFILE;
		error->message = "profile in use";
		return -EINVAL;
	}

	TAILQ_REMOVE(&hw->tm_conf.shaper_profile_list, shaper_profile, node);
	rte_free(shaper_profile);

	return 0;
}

static int
ice_dcf_set_vf_bw(struct ice_dcf_hw *hw,
			struct virtchnl_dcf_vf_bw_cfg_list *vf_bw,
			uint16_t len)
{
	struct dcf_virtchnl_cmd args;
	int err;

	memset(&args, 0, sizeof(args));
	args.v_op = VIRTCHNL_OP_DCF_CONFIG_VF_TC;
	args.req_msg = (uint8_t *)vf_bw;
	args.req_msglen  = len;
	err = ice_dcf_execute_virtchnl_cmd(hw, &args);
	if (err)
		PMD_DRV_LOG(ERR, "fail to execute command %s",
			    "VIRTCHNL_OP_DCF_CONFIG_VF_TC");
	return err;
}

static int ice_dcf_hierarchy_commit(struct rte_eth_dev *dev,
				 __rte_unused int clear_on_fail,
				 __rte_unused struct rte_tm_error *error)
{
	struct ice_dcf_adapter *adapter = dev->data->dev_private;
	struct ice_dcf_hw *hw = &adapter->real_hw;
	struct virtchnl_dcf_vf_bw_cfg_list *vf_bw;
	struct ice_dcf_tm_node_list *vsi_list = &hw->tm_conf.vsi_list;
	struct rte_tm_shaper_params *profile;
	struct ice_dcf_tm_node *tm_node;
	uint32_t port_bw, cir_total;
	uint16_t size, vf_id;
	int ret;
	int num_elem = 0;

	size = sizeof(*vf_bw) +
		sizeof(vf_bw->cfg[0]) * (hw->tm_conf.nb_tc_node - 1);
	vf_bw = rte_zmalloc("vf_bw", size, 0);
	if (!vf_bw)
		return ICE_ERR_NO_MEMORY;

	/* port bandwidth (Kbps) */
	port_bw = hw->link_speed * 1000;
	cir_total = 0;

	for (vf_id = 0; vf_id < hw->num_vfs; vf_id++) {
		num_elem = 0;
		vf_bw->vf_id = vf_id;
		TAILQ_FOREACH(tm_node, vsi_list, node) {
			/* scan the nodes belong to one VSI */
			if (tm_node->id - hw->num_vfs * tm_node->tc != vf_id)
				continue;
			vf_bw->cfg[num_elem].tc_id = tm_node->tc;
			vf_bw->cfg[num_elem].type = VIRTCHNL_BW_SHAPER;
			if (tm_node->shaper_profile) {
				/* Transfer from Byte per seconds to Kbps */
				profile = &tm_node->shaper_profile->profile;
				vf_bw->cfg[num_elem].shaper.peak =
				profile->peak.rate / 1000 * BITS_PER_BYTE;
				vf_bw->cfg[num_elem].shaper.committed =
				profile->committed.rate / 1000 * BITS_PER_BYTE;
			}
			cir_total += vf_bw->cfg[num_elem].shaper.committed;
			num_elem++;
		}

		/* check if total CIR is larger than port bandwidth */
		if (cir_total > port_bw) {
			PMD_DRV_LOG(ERR, "Total CIR of all VFs is larger than port bandwidth");
			return ICE_ERR_PARAM;
		}
		vf_bw->num_elem = num_elem;
		ret = ice_dcf_set_vf_bw(hw, vf_bw, size);
		if (ret)
			return ret;
	}

	hw->tm_conf.committed = true;
	return ICE_SUCCESS;
}
