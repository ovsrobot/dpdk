/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <rte_thread.h>

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_fpga.h"
#include "nthw_register.h"
#include "nt4ga_adapter.h"
#include "nt4ga_pci_ta_tg.h"
#include "ntnic_mod_reg.h"

#include "flow_filter.h"

static int nt4ga_adapter_init(struct adapter_info_s *p_adapter_info);
static int nt4ga_adapter_deinit(struct adapter_info_s *p_adapter_info);

static int nt4ga_adapter_show_info(struct adapter_info_s *p_adapter_info, FILE *pfh);

/*
 * Global variables shared by NT adapter types
 */
rte_thread_t monitor_tasks[NUM_ADAPTER_MAX];
volatile int monitor_task_is_running[NUM_ADAPTER_MAX];

/*
 * Signal-handler to stop all monitor threads
 */
static void stop_monitor_tasks(int signum)
{
	const size_t N = ARRAY_SIZE(monitor_task_is_running);
	size_t i;

	/* Stop all monitor tasks */
	for (i = 0; i < N; i++) {
		const int is_running = monitor_task_is_running[i];
		monitor_task_is_running[i] = 0;

		if (signum == -1 && is_running != 0) {
			rte_thread_join(monitor_tasks[i], NULL);
			memset(&monitor_tasks[i], 0, sizeof(monitor_tasks[0]));
		}
	}
}

static int nt4ga_adapter_show_info(struct adapter_info_s *p_adapter_info, FILE *pfh)
{
	const char *const p_dev_name = p_adapter_info->p_dev_name;
	const char *const p_adapter_id_str = p_adapter_info->mp_adapter_id_str;
	fpga_info_t *p_fpga_info = &p_adapter_info->fpga_info;
	hw_info_t *p_hw_info = &p_adapter_info->hw_info;
	mcu_info_t *mcu_info = &p_adapter_info->fpga_info.mcu_info;
	char a_pci_ident_str[32];
	const struct nt4ga_stat_ops *nt4ga_stat_ops = get_nt4ga_stat_ops();

	if (nt4ga_stat_ops != NULL)
		nt4ga_stat_ops->nt4ga_stat_dump(p_adapter_info, pfh);

	snprintf(a_pci_ident_str, sizeof(a_pci_ident_str), "" PCIIDENT_PRINT_STR "",
		PCIIDENT_TO_DOMAIN(p_fpga_info->pciident),
		PCIIDENT_TO_BUSNR(p_fpga_info->pciident),
		PCIIDENT_TO_DEVNR(p_fpga_info->pciident),
		PCIIDENT_TO_FUNCNR(p_fpga_info->pciident));

	fprintf(pfh, "%s: DeviceName: %s\n", p_adapter_id_str, (p_dev_name ? p_dev_name : "NA"));
	fprintf(pfh, "%s: PCI Details:\n", p_adapter_id_str);
	fprintf(pfh, "%s: %s: %08X: %04X:%04X %04X:%04X\n", p_adapter_id_str, a_pci_ident_str,
		p_fpga_info->pciident, p_hw_info->pci_vendor_id, p_hw_info->pci_device_id,
		p_hw_info->pci_sub_vendor_id, p_hw_info->pci_sub_device_id);
	fprintf(pfh, "%s: FPGA Details:\n", p_adapter_id_str);
	fprintf(pfh, "%s: %03d-%04d-%02d-%02d [%016" PRIX64 "] (%08X)\n", p_adapter_id_str,
		p_fpga_info->n_fpga_type_id, p_fpga_info->n_fpga_prod_id,
		p_fpga_info->n_fpga_ver_id, p_fpga_info->n_fpga_rev_id, p_fpga_info->n_fpga_ident,
		p_fpga_info->n_fpga_build_time);
	fprintf(pfh, "%s: FpgaDebugMode=0x%x\n", p_adapter_id_str, p_fpga_info->n_fpga_debug_mode);
	fprintf(pfh, "%s: Nims=%d PhyPorts=%d PhyQuads=%d RxPorts=%d TxPorts=%d\n",
		p_adapter_id_str, p_fpga_info->n_nims, p_fpga_info->n_phy_ports,
		p_fpga_info->n_phy_quads, p_fpga_info->n_rx_ports, p_fpga_info->n_tx_ports);
	fprintf(pfh, "%s: Hw=0x%02X_rev%d: %s\n", p_adapter_id_str, p_hw_info->hw_platform_id,
		p_fpga_info->nthw_hw_info.hw_id, p_fpga_info->nthw_hw_info.hw_plat_id_str);
	fprintf(pfh, "%s: MCU Details:\n", p_adapter_id_str);
	fprintf(pfh, "%s: HasMcu=%d McuType=%d McuDramSize=%d\n", p_adapter_id_str,
		mcu_info->mb_has_mcu, mcu_info->mn_mcu_type, mcu_info->mn_mcu_dram_size);

	if (nt4ga_stat_ops != NULL)
		nt4ga_stat_ops->nt4ga_stat_dump(p_adapter_info, pfh);

	return 0;
}

/*
 * SPI for sensors reading
 */
nthw_spis_t *new_sensors_t_spi(struct nthw_fpga_s *p_fpga)
{
	nthw_spis_t *sensors_t_spi = nthw_spis_new();

	/* init SPI for sensor initialization process */
	if (sensors_t_spi == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: SPI allocation error\n", __func__);
		return NULL;
	}

	if (nthw_spis_init(sensors_t_spi, p_fpga, 0)) {
		NT_LOG(ERR, ETHDEV, "%s: SPI initialization error\n", __func__);
		nthw_spis_delete(sensors_t_spi);
		return NULL;
	}

	return sensors_t_spi;
}

static int nt4ga_adapter_init(struct adapter_info_s *p_adapter_info)
{
	const struct flow_filter_ops *flow_filter_ops = get_flow_filter_ops();

	if (flow_filter_ops == NULL)
		NT_LOG(ERR, ETHDEV, "%s: flow_filter module uninitialized\n", __func__);

	char *const p_dev_name = malloc(24);
	char *const p_adapter_id_str = malloc(24);
	fpga_info_t *fpga_info = &p_adapter_info->fpga_info;
	hw_info_t *p_hw_info = &p_adapter_info->hw_info;

	/*
	 * IMPORTANT: Most variables cannot be determined before nthw fpga model is instantiated
	 * (nthw_fpga_init())
	 */
	bool b_has_mcu = false;
	int n_phy_ports = -1;
	int n_nim_ports = -1;
	int res = -1;
	nthw_fpga_t *p_fpga = NULL;

	(void)b_has_mcu;/* currently UNUSED - prevent warning */
	(void)n_nim_ports;	/* currently UNUSED - prevent warning */

	p_hw_info->n_nthw_adapter_id = nthw_platform_get_nthw_adapter_id(p_hw_info->pci_device_id);

	fpga_info->n_nthw_adapter_id = p_hw_info->n_nthw_adapter_id;
	/* ref: DN-0060 section 9 */
	p_hw_info->hw_product_type = p_hw_info->pci_device_id & 0x000f;
	/* ref: DN-0060 section 9 */
	p_hw_info->hw_platform_id = (p_hw_info->pci_device_id >> 4) & 0x00ff;
	/* ref: DN-0060 section 9 */
	p_hw_info->hw_reserved1 = (p_hw_info->pci_device_id >> 12) & 0x000f;

	/* mp_dev_name */
	p_adapter_info->p_dev_name = p_dev_name;

	if (p_dev_name) {
		snprintf(p_dev_name, 24, "" PCIIDENT_PRINT_STR "",
			PCIIDENT_TO_DOMAIN(p_adapter_info->fpga_info.pciident),
			PCIIDENT_TO_BUSNR(p_adapter_info->fpga_info.pciident),
			PCIIDENT_TO_DEVNR(p_adapter_info->fpga_info.pciident),
			PCIIDENT_TO_FUNCNR(p_adapter_info->fpga_info.pciident));
		NT_LOG(DBG, ETHDEV, "%s: (0x%08X)\n", p_dev_name,
			p_adapter_info->fpga_info.pciident);
	}

	/* mp_adapter_id_str */
	p_adapter_info->mp_adapter_id_str = p_adapter_id_str;

	p_adapter_info->fpga_info.mp_adapter_id_str = p_adapter_id_str;

	if (p_adapter_id_str) {
		snprintf(p_adapter_id_str, 24, "PCI:" PCIIDENT_PRINT_STR "",
			PCIIDENT_TO_DOMAIN(p_adapter_info->fpga_info.pciident),
			PCIIDENT_TO_BUSNR(p_adapter_info->fpga_info.pciident),
			PCIIDENT_TO_DEVNR(p_adapter_info->fpga_info.pciident),
			PCIIDENT_TO_FUNCNR(p_adapter_info->fpga_info.pciident));
		NT_LOG(DBG, ETHDEV, "%s: %s\n", p_adapter_id_str, p_dev_name);
	}

	{
		int i;

		for (i = 0; i < (int)ARRAY_SIZE(p_adapter_info->mp_port_id_str); i++) {
			char *p = malloc(32);

			if (p) {
				snprintf(p, 32, "%s:intf_%d",
					(p_adapter_id_str ? p_adapter_id_str : "NA"), i);
			}

			p_adapter_info->mp_port_id_str[i] = p;
		}
	}

	res = nthw_fpga_init(&p_adapter_info->fpga_info);

	if (res) {
		NT_LOG(ERR, ETHDEV, "%s: %s: FPGA=%04d res=x%08X [%s:%u]\n", p_adapter_id_str,
			p_dev_name, fpga_info->n_fpga_prod_id, res, __func__, __LINE__);
		return res;
	}

	assert(fpga_info);
	p_fpga = fpga_info->mp_fpga;
	assert(p_fpga);
	n_phy_ports = fpga_info->n_phy_ports;
	assert(n_phy_ports >= 1);
	n_nim_ports = fpga_info->n_nims;
	assert(n_nim_ports >= 1);
	b_has_mcu = fpga_info->mcu_info.mb_has_mcu;

	/* NOTE: RX and TX queues for VFs shall be considered too */
	int max_rx_queues = nthw_fpga_get_product_param(p_fpga, NT_DBS_RX_QUEUES, -1);
	int max_tx_queues = nthw_fpga_get_product_param(p_fpga, NT_DBS_TX_QUEUES, -1);

	if (max_rx_queues < 0 || max_tx_queues < 0 ||
		n_phy_ports * p_adapter_info->n_rx_host_buffers > max_rx_queues ||
		n_phy_ports * p_adapter_info->n_tx_host_buffers > max_tx_queues) {
		NT_LOG(ERR, ETHDEV,
			"%s: Too many queues requested: phy_ports=%d, rxqs=%d, txqs=%d, rx_queues_avail=%d, tx_queues_avail=%d\n",
			p_adapter_info->mp_adapter_id_str, n_phy_ports,
			p_adapter_info->n_rx_host_buffers, p_adapter_info->n_tx_host_buffers,
			max_rx_queues, max_tx_queues);
		nthw_fpga_shutdown(&p_adapter_info->fpga_info);
		return -1;
	}

	/* Nt4ga Init Filter */
	nt4ga_filter_t *p_filter = &p_adapter_info->nt4ga_filter;

	if (flow_filter_ops != NULL) {
		res = flow_filter_ops->flow_filter_init(p_fpga, &p_filter->mp_flow_device,
				p_adapter_info->adapter_no);

		if (res != 0) {
			NT_LOG(ERR, ETHDEV, "%s: Cannot initialize filter\n", p_adapter_id_str);
			return res;
		}
	}

	/*
	 * HIF/PCI TA/TG
	 */
	{
		res = nt4ga_pci_ta_tg_init(p_adapter_info);

		if (res == 0) {
			nt4ga_pci_ta_tg_measure_throughput_main(p_adapter_info, 0, 0, TG_PKT_SIZE,
				TG_NUM_PACKETS, TG_DELAY);

		} else {
			NT_LOG(WRN, ETHDEV, "%s: PCI TA/TG is not available - skipping\n",
				p_adapter_id_str);
		}
	}

	{
		int i;
		const struct link_ops_s *link_ops = NULL;
		assert(fpga_info->n_fpga_prod_id > 0);

		for (i = 0; i < NUM_ADAPTER_PORTS_MAX; i++) {
			/* Disable all ports. Must be enabled later */
			p_adapter_info->nt4ga_link.port_action[i].port_disable = true;
		}

		switch (fpga_info->n_fpga_prod_id) {
		/* NT200A01: 2x100G (Xilinx) */
		case 9563:	/* NT200A02 (Cap) */
			link_ops = get_100g_link_ops();

			if (link_ops == NULL) {
				NT_LOG(ERR, ETHDEV,
					"%s: NT200A02 100G link module uninitialized\n", __func__);
				res = -1;
				break;
			}

			res = link_ops->link_init(p_adapter_info, p_fpga);
			break;

		/* NT200A0x: 2x10G/2x25G (Xilinx) */
		case 9530:	/* NT200A02 (NFV) */
		case 9544:	/* NT200A02 (NFV Lenovo) */
			link_ops = get_25g_link_ops();

			if (link_ops == NULL) {
				NT_LOG(ERR, ETHDEV, "%s: NT200A02 25G link module uninitialized\n",
					__func__);
				res = -1;
				break;
			}

			res = link_ops->link_init(p_adapter_info, p_fpga);
			break;

		/* NT50b0x: 2x10G/2x25G (Xilinx) */
		case 9542:	/* NT50B01 (NFV) */
		case 9547:	/* NT50B01 (NFV Lenovo) */
			link_ops = get_25g_link_ops();

			if (link_ops == NULL) {
				NT_LOG(ERR, ETHDEV, "%s: NT50B01 25G link module uninitialized\n",
					__func__);
				res = -1;
				break;
			}

			res = link_ops->link_init(p_adapter_info, p_fpga);
			break;

		case 9569:	/* NT400D11 (Intel Agilex FPGA) */
			link_ops = get_agx_100g_link_ops();

			if (link_ops == NULL) {
				NT_LOG(ERR, ETHDEV,
					"%s: NT400D11 100G link module uninitialized\n", __func__);
				res = -1;
				break;
			}

			res = link_ops->link_init(p_adapter_info, p_fpga);
			break;

		case 9572:
			/* NT200A0x: 8x10G (Xilinx) */
			link_ops = get_8x10g_link_ops();

			if (link_ops == NULL) {
				NT_LOG(ERR, ETHDEV,
					"%s: NT200A0x 8x10G link module uninitialized\n", __func__);
				res = -1;
				break;
			}

			res = link_ops->link_init(p_adapter_info, p_fpga);
			break;

		default:
			NT_LOG(ERR, ETHDEV, "%s: Unsupported FPGA product: %04d\n", __func__,
				fpga_info->n_fpga_prod_id);
			res = -1;
			break;
		}

		if (res) {
			NT_LOG(ERR, ETHDEV, "%s: %s: %s: %u: FPGA=%04d res=x%08X\n",
				p_adapter_id_str, p_dev_name, __func__, __LINE__,
				fpga_info->n_fpga_prod_id, res);
			return res;
		}
	}

	/*
	 * HostBuffer Systems
	 */
	p_adapter_info->n_rx_host_buffers = 0;
	p_adapter_info->n_tx_host_buffers = 0;

	p_adapter_info->fpga_info.mp_nthw_epp = NULL;

	if (nthw_epp_present(p_adapter_info->fpga_info.mp_fpga, 0)) {
		p_adapter_info->fpga_info.mp_nthw_epp = nthw_epp_new();

		if (p_adapter_info->fpga_info.mp_nthw_epp == NULL) {
			NT_LOG(ERR, ETHDEV, "%s: Cannot create EPP\n", p_adapter_id_str);
			return -1;
		}

		res = nthw_epp_init(p_adapter_info->fpga_info.mp_nthw_epp,
				p_adapter_info->fpga_info.mp_fpga, 0);

		if (res != 0) {
			NT_LOG(ERR, ETHDEV, "%s: Cannot initialize EPP\n", p_adapter_id_str);
			return res;

		} else {
			NT_LOG(DBG, ETHDEV, "%s: Initialized EPP\n", p_adapter_id_str);
		}

		res = nthw_epp_setup(p_adapter_info->fpga_info.mp_nthw_epp);

		if (res != 0) {
			NT_LOG(ERR, ETHDEV, "%s: Cannot setup EPP\n", p_adapter_id_str);
			return res;
		}
	}

	const struct nt4ga_stat_ops *nt4ga_stat_ops = get_nt4ga_stat_ops();

	if (nt4ga_stat_ops != NULL) {
		/* Nt4ga Stat init/setup */
		res = nt4ga_stat_ops->nt4ga_stat_init(p_adapter_info);

		if (res != 0) {
			NT_LOG(ERR, ETHDEV, "%s: Cannot initialize the statistics module\n",
				p_adapter_id_str);
			return res;
		}

		res = nt4ga_stat_ops->nt4ga_stat_setup(p_adapter_info);

		if (res != 0) {
			NT_LOG(ERR, ETHDEV, "%s: Cannot setup the statistics module\n",
				p_adapter_id_str);
			return res;
		}
	}

	/*
	 * MCU testing
	 */

	return 0;
}

static int nt4ga_adapter_deinit(struct adapter_info_s *p_adapter_info)
{
	const struct sensor_ops *sensor_ops = get_sensor_ops();
	fpga_info_t *fpga_info = &p_adapter_info->fpga_info;
	int i;
	int res;
	struct nt_sensor_group *cur_adapter_sensor = NULL;
	struct nt_sensor_group *next_adapter_sensor = NULL;
	struct nim_sensor_group *cur_nim_sensor = NULL;
	struct nim_sensor_group *next_nim_sensor = NULL;

	stop_monitor_tasks(-1);

	const struct nt4ga_stat_ops *nt4ga_stat_ops = get_nt4ga_stat_ops();

	if (nt4ga_stat_ops != NULL)
		nt4ga_stat_ops->nt4ga_stat_stop(p_adapter_info);

	nthw_fpga_shutdown(&p_adapter_info->fpga_info);

	/* Rac rab reset flip flop */
	res = nthw_rac_rab_reset(fpga_info->mp_nthw_rac);

	/* Free adapter port ident strings */
	for (i = 0; i < fpga_info->n_phy_ports; i++) {
		if (p_adapter_info->mp_port_id_str[i]) {
			free(p_adapter_info->mp_port_id_str[i]);
			p_adapter_info->mp_port_id_str[i] = NULL;
		}
	}

	/* Free adapter ident string */
	if (p_adapter_info->mp_adapter_id_str) {
		free(p_adapter_info->mp_adapter_id_str);
		p_adapter_info->mp_adapter_id_str = NULL;
	}

	/* Free devname ident string */
	if (p_adapter_info->p_dev_name) {
		free(p_adapter_info->p_dev_name);
		p_adapter_info->p_dev_name = NULL;
	}

	/* Free adapter sensors */
	if (p_adapter_info->adapter_sensors != NULL) {
		do {
			cur_adapter_sensor = p_adapter_info->adapter_sensors;
			next_adapter_sensor = p_adapter_info->adapter_sensors->next;
			p_adapter_info->adapter_sensors = next_adapter_sensor;

			if (sensor_ops != NULL)
				sensor_ops->sensor_deinit(cur_adapter_sensor);
		} while (next_adapter_sensor != NULL);
	}

	/* Free NIM sensors */
	for (i = 0; i < fpga_info->n_phy_ports; i++) {
		if (p_adapter_info->nim_sensors[i] != NULL) {
			do {
				cur_nim_sensor = p_adapter_info->nim_sensors[i];
				next_nim_sensor = p_adapter_info->nim_sensors[i]->next;
				p_adapter_info->nim_sensors[i] = next_nim_sensor;
				free(cur_nim_sensor->sensor);
				free(cur_nim_sensor);
			} while (next_nim_sensor != NULL);
		}
	}

	return res;
}

static const struct adapter_ops ops = {
	.init = nt4ga_adapter_init,
	.deinit = nt4ga_adapter_deinit,

	.show_info = nt4ga_adapter_show_info,
};

static void __attribute__((constructor(65535))) adapter_init(void)
{
	register_adapter_ops(&ops);
}
