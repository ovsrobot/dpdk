/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "nt_util.h"
#include "ntlog.h"
#include "i2c_nim.h"
#include "nt4ga_adapter.h"

#include <string.h>
#include "ntnic_mod_reg.h"
#include "nim_defines.h"

static int nt4ga_agx_link_100g_ports_init(struct adapter_info_s *p_adapter_info,
	nthw_fpga_t *fpga);

/*
 * Init AGX 100G link ops variables
 */
static struct link_ops_s link_agx_100g_ops = {
	.link_init = nt4ga_agx_link_100g_ports_init,
};

void link_agx_100g_init(void)
{
	register_agx_100g_link_ops(&link_agx_100g_ops);
}

/*
 * Link state machine
 */
static void *_common_ptp_nim_state_machine(void *data)
{
	adapter_info_t *drv = (adapter_info_t *)data;
	fpga_info_t *fpga_info = &drv->fpga_info;
	nt4ga_link_t *link_info = &drv->nt4ga_link;
	nthw_fpga_t *fpga = fpga_info->mp_fpga;
	const int adapter_no = drv->adapter_no;
	const int nb_ports = fpga_info->n_phy_ports;
	uint32_t last_lpbk_mode[NUM_ADAPTER_PORTS_MAX];
	/* link_state_t new_link_state; */

	link_state_t *link_state = link_info->link_state;

	if (!fpga) {
		NT_LOG(ERR, NTNIC, "%s: fpga is NULL", drv->mp_adapter_id_str);
		goto NT4GA_LINK_100G_MON_EXIT;
	}

	assert(adapter_no >= 0 && adapter_no < NUM_ADAPTER_MAX);

	monitor_task_is_running[adapter_no] = 1;
	memset(last_lpbk_mode, 0, sizeof(last_lpbk_mode));

	/* Initialize link state */
	for (int i = 0; i < nb_ports; i++) {
		link_state[i].link_disabled = true;
		link_state[i].nim_present = false;
		link_state[i].lh_nim_absent = true;
		link_state[i].link_up = false;
		link_state[i].link_state = NT_LINK_STATE_UNKNOWN;
		link_state[i].link_state_latched = NT_LINK_STATE_UNKNOWN;
	}

	if (monitor_task_is_running[adapter_no])
		NT_LOG(DBG, NTNIC, "%s: link state machine running...", drv->mp_adapter_id_str);

	while (monitor_task_is_running[adapter_no]) {
		int i;

		for (i = 0; i < nb_ports; i++) {
			const bool is_port_disabled = link_info->port_action[i].port_disable;
			const bool was_port_disabled = link_state[i].link_disabled;
			const bool disable_port = is_port_disabled && !was_port_disabled;
			const bool enable_port = !is_port_disabled && was_port_disabled;

			if (!monitor_task_is_running[adapter_no])
				break;

			/*
			 * Has the administrative port state changed?
			 */
			assert(!(disable_port && enable_port));

			if (enable_port) {
				link_state[i].link_disabled = false;
				NT_LOG(DBG, NTNIC, "%s: Port %i is enabled",
					drv->mp_port_id_str[i], i);
			}

			if (is_port_disabled)
				continue;

			link_state[i].link_disabled = is_port_disabled;

			if (!link_state[i].nim_present) {
				if (!link_state[i].lh_nim_absent) {
					NT_LOG(INF, NTNIC, "%s: NIM module removed",
						drv->mp_port_id_str[i]);
					link_state[i].link_up = false;
					link_state[i].lh_nim_absent = true;

				} else {
					NT_LOG(DBG, NTNIC, "%s: No NIM module, skip",
						drv->mp_port_id_str[i]);
				}

				continue;
			}
		}

		if (monitor_task_is_running[adapter_no])
			nt_os_wait_usec(5 * 100000U);	/*  5 x 0.1s = 0.5s */
	}

NT4GA_LINK_100G_MON_EXIT:
	NT_LOG(DBG, NTNIC, "%s: Stopped NT4GA 100 Gbps link monitoring thread.",
		drv->mp_adapter_id_str);
	return NULL;
}

static uint32_t nt4ga_agx_link_100g_mon(void *data)
{
	(void)_common_ptp_nim_state_machine(data);

	return 0;
}

/*
 * Initialize all ports
 * The driver calls this function during initialization (of the driver).
 */
int nt4ga_agx_link_100g_ports_init(struct adapter_info_s *p_adapter_info, nthw_fpga_t *fpga)
{
	(void)fpga;
	const int adapter_no = p_adapter_info->adapter_no;
	int res = 0;

	NT_LOG(DBG, NTNIC, "%s: Initializing ports", p_adapter_info->mp_adapter_id_str);

	/*
	 * Create state-machine thread
	 */
	if (res == 0) {
		if (!monitor_task_is_running[adapter_no]) {
			res = rte_thread_create(&monitor_tasks[adapter_no], NULL,
					nt4ga_agx_link_100g_mon, p_adapter_info);
		}
	}

	return res;
}
