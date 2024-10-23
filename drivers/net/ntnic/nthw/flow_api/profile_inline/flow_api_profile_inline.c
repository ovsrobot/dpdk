/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "flow_api_profile_inline.h"
#include "ntnic_mod_reg.h"

struct flow_handle *flow_create_profile_inline(struct flow_eth_dev *dev,
	const struct rte_flow_attr *attr,
	uint16_t forced_vlan_vid,
	uint16_t caller_id,
	const struct rte_flow_item elem[],
	const struct rte_flow_action action[],
	struct rte_flow_error *error)
{
	return NULL;
}

int flow_destroy_locked_profile_inline(struct flow_eth_dev *dev,
	struct flow_handle *fh,
	struct rte_flow_error *error)
{
	assert(dev);
	assert(fh);

	int err = 0;

	flow_nic_set_error(ERR_SUCCESS, error);

	return err;
}

int flow_destroy_profile_inline(struct flow_eth_dev *dev, struct flow_handle *flow,
	struct rte_flow_error *error)
{
	int err = 0;

	flow_nic_set_error(ERR_SUCCESS, error);

	if (flow) {
		/* Delete this flow */
		pthread_mutex_lock(&dev->ndev->mtx);
		err = flow_destroy_locked_profile_inline(dev, flow, error);
		pthread_mutex_unlock(&dev->ndev->mtx);
	}

	return err;
}

static const struct profile_inline_ops ops = {
	/*
	 * Flow functionality
	 */
	.flow_destroy_locked_profile_inline = flow_destroy_locked_profile_inline,
	.flow_create_profile_inline = flow_create_profile_inline,
	.flow_destroy_profile_inline = flow_destroy_profile_inline,
};

void profile_inline_init(void)
{
	register_profile_inline_ops(&ops);
}
