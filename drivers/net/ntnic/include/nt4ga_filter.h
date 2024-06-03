/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NT4GA_FILTER_H_
#define NT4GA_FILTER_H_

typedef struct nt4ga_filter_s {
	int n_intf_cnt;
	int n_queues_per_intf_cnt;

	struct flow_nic_dev *mp_flow_device;
} nt4ga_filter_t;

#endif	/* NT4GA_FILTER_H_ */
