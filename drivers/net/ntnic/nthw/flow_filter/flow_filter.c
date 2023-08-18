/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "nthw_drv.h"
#include "flow_filter.h"
#include "flow_api_backend.h"
#include "flow_backend.h"
#include "flow_api_nic_setup.h"

int flow_filter_init(nt_fpga_t *p_fpga, struct flow_nic_dev **p_flow_device,
		   int adapter_no)
{
	void *be_dev = NULL;
	struct flow_nic_dev *flow_nic;

	NT_LOG(DBG, FILTER, "Initializing flow filter api\n");
	const struct flow_api_backend_ops *iface =
		bin_flow_backend_init(p_fpga, &be_dev);

	flow_nic = flow_api_create((uint8_t)adapter_no, iface, be_dev);
	if (!flow_nic) {
		*p_flow_device = NULL;
		return -1;
	}
	*p_flow_device = flow_nic;
	return 0;
}

int flow_filter_done(struct flow_nic_dev *dev)
{
	void *be_dev = flow_api_get_be_dev(dev);

	int res = flow_api_done(dev);

	if (be_dev)
		bin_flow_backend_done(be_dev);
	return res;
}
