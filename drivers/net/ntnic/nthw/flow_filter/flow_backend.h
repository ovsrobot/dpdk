/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_BACKEND_H__
#define __FLOW_BACKEND_H__

#include <stdint.h> /* uint8_t */
#include "nthw_fpga_model.h"

const struct flow_api_backend_ops *bin_flow_backend_init(nt_fpga_t *p_fpga,
		void **be_dev);
void bin_flow_backend_done(void *be_dev);

#endif /* __FLOW_BACKEND_H__ */
