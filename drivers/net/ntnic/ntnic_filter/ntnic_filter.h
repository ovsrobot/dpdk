/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTNIC_FILTER_H__
#define __NTNIC_FILTER_H__

struct rte_flow *
client_flow_create(struct flow_eth_dev *flw_dev, enum fpga_info_profile profile,
		   struct cnv_attr_s *attribute, struct cnv_match_s *match,
		   struct cnv_action_s *action, uint32_t flow_stat_id,
		   struct rte_flow_error *error);

#endif /* __NTNIC_FILTER_H__ */
