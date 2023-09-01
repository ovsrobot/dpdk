/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _FLOW_API_PROFILE_INLINE_H_
#define _FLOW_API_PROFILE_INLINE_H_

#include "stream_binary_flow_api.h"
#include "flow_api.h"

/*
 * Management
 */

int done_flow_management_of_ndev_profile_inline(struct flow_nic_dev *ndev);

int initialize_flow_management_of_ndev_profile_inline(struct flow_nic_dev *ndev);

/*
 * Flow functionality
 */

int flow_destroy_locked_profile_inline(struct flow_eth_dev *dev,
				       struct flow_handle *flow,
				       struct flow_error *error);

int flow_validate_profile_inline(struct flow_eth_dev *dev,
				 const struct flow_elem elem[],
				 const struct flow_action action[],
				 struct flow_error *error);

struct flow_handle *flow_create_profile_inline(struct flow_eth_dev *dev,
	const struct flow_attr *attr,
	const struct flow_elem elem[], const struct flow_action action[],
	struct flow_error *error);

int flow_destroy_profile_inline(struct flow_eth_dev *dev,
				struct flow_handle *flow,
				struct flow_error *error);

int flow_flush_profile_inline(struct flow_eth_dev *dev,
			      struct flow_error *error);

int flow_query_profile_inline(struct flow_eth_dev *dev,
			      struct flow_handle *flow,
			      const struct flow_action *action, void **data,
			      uint32_t *length, struct flow_error *error);

/*
 * Stats
 */

int flow_get_flm_stats_profile_inline(struct flow_nic_dev *ndev, uint64_t *data,
				      uint64_t size);

#endif /* _FLOW_API_PROFILE_INLINE_H_ */
