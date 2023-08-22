/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_FILTER_HPP__
#define __FLOW_FILTER_HPP__
#undef USE_OPAE

#include "nthw_fpga_model.h"
#include "flow_api.h"

int flow_filter_init(nt_fpga_t *p_fpga, struct flow_nic_dev **p_flow_device,
		   int adapter_no);
int flow_filter_done(struct flow_nic_dev *dev);

#endif /* __FLOW_FILTER_HPP__ */
