/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "tempmon.h"
#include "ntlog.h"
#include "nthw_register.h"

struct nt_fpga_sensor_monitor *tempmon_new(void)
{
	struct nt_fpga_sensor_monitor *temp =
		malloc(sizeof(struct nt_fpga_sensor_monitor));
	if (temp == NULL)
		NT_LOG(ERR, ETHDEV, "%s: monitor is NULL\n", __func__);
	return temp;
}

void tempmon_init(struct nt_fpga_sensor_monitor *t, nt_fpga_t *p_fpga)
{
	if (t == NULL || p_fpga == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: bad argument(s)\n", __func__);
		return;
	}
	/* fetch initialized module */
	t->fpga = p_fpga;
	t->mod = nthw_get_module(t->fpga, MOD_TEMPMON, 0);
	if (t->mod == NULL)
		NT_LOG(ERR, ETHDEV, "module is NULL\n");
	/* fetch register */
	t->reg = module_get_register(t->mod, TEMPMON_STAT);
	if (t->reg == NULL)
		NT_LOG(ERR, ETHDEV, "register is NULL\n");
	/* fetch fields */
	t->fields = malloc(sizeof(nt_field_t *));
	if (t->fields == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: field is NULL", __func__);
		return;
	}
	t->fields[0] = register_get_field(t->reg, TEMPMON_STAT_TEMP);
	if (t->fields[0] == NULL)
		NT_LOG(ERR, ETHDEV, "field is NULL\n");
}
