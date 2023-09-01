/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _TEMPMON_H
#define _TEMPMON_H

#include "nthw_fpga_model.h"
#include <stdlib.h>

#include "sensors.h"

struct nt_fpga_sensor_monitor *tempmon_new(void);
void tempmon_init(struct nt_fpga_sensor_monitor *t, nt_fpga_t *p_fpga);

#endif /* _TEMPMON_H */
