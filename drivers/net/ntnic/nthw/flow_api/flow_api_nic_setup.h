/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_API_NIC_SETUP_H__
#define __FLOW_API_NIC_SETUP_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct flow_api_backend_ops; /* Operation list for common FPGA module API for backend */
struct flow_nic_dev; /* adapter device */

/*
 * Flow capable NIC backend - creating flow api instance for adapter nr (backend)
 */
struct flow_nic_dev *flow_api_create(uint8_t adapter_no,
				     const struct flow_api_backend_ops *be_if,
				     void *be_dev);
int flow_api_done(struct flow_nic_dev *dev);
void *flow_api_get_be_dev(struct flow_nic_dev *dev);

#ifdef __cplusplus
}
#endif

#endif /* __FLOW_API_NIC_SETUP_H__ */
