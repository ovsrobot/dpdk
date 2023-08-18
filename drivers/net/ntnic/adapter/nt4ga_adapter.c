/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_fpga.h"
#include "nt4ga_adapter.h"
#include "nt4ga_pci_ta_tg.h"
#include "nt4ga_link_100g.h"

#include "flow_filter.h"

/* Sensors includes */
#include "board_sensors.h"
#include "avr_sensors.h"

/*
 * Global variables shared by NT adapter types
 */
pthread_t monitor_tasks[NUM_ADAPTER_MAX];
volatile int monitor_task_is_running[NUM_ADAPTER_MAX];

/*
 * Signal-handler to stop all monitor threads
 */
static void stop_monitor_tasks(int signum)
{
	const size_t n = ARRAY_SIZE(monitor_task_is_running);
	size_t i;

	/* Stop all monitor tasks */
	for (i = 0; i < n; i++) {
		const int is_running = monitor_task_is_running[i];

		monitor_task_is_running[i] = 0;
		if (signum == -1 && is_running != 0) {
			void *ret_val = NULL;

			pthread_join(monitor_tasks[i], &ret_val);
			memset(&monitor_tasks[i], 0, sizeof(monitor_tasks[0]));
		}
	}
}

int nt4ga_adapter_show_info(struct adapter_info_s *p_adapter_info, FILE *pfh)
{
	const char *const p_dev_name = p_adapter_info->p_dev_name;
	const char *const p_adapter_id_str = p_adapter_info->mp_adapter_id_str;
	fpga_info_t *p_fpga_info = &p_adapter_info->fpga_info;
	hw_info_t *p_hw_info = &p_adapter_info->hw_info;
	char a_pci_ident_str[32];

	snprintf(a_pci_ident_str, sizeof(a_pci_ident_str), "" PCIIDENT_PRINT_STR "",
		PCIIDENT_TO_DOMAIN(p_fpga_info->pciident),
		PCIIDENT_TO_BUSNR(p_fpga_info->pciident),
		PCIIDENT_TO_DEVNR(p_fpga_info->pciident),
		PCIIDENT_TO_FUNCNR(p_fpga_info->pciident));

	fprintf(pfh, "%s: DeviceName: %s\n", p_adapter_id_str,
		(p_dev_name ? p_dev_name : "NA"));
	fprintf(pfh, "%s: PCI Details:\n", p_adapter_id_str);
	fprintf(pfh, "%s: %s: %08X: %04X:%04X %04X:%04X\n", p_adapter_id_str,
		a_pci_ident_str, p_fpga_info->pciident, p_hw_info->pci_vendor_id,
		p_hw_info->pci_device_id, p_hw_info->pci_sub_vendor_id,
		p_hw_info->pci_sub_device_id);
	fprintf(pfh, "%s: FPGA Details:\n", p_adapter_id_str);
	fprintf(pfh, "%s: %03d-%04d-%02d-%02d [%016" PRIX64 "] (%08X)\n",
		p_adapter_id_str, p_fpga_info->n_fpga_type_id, p_fpga_info->n_fpga_prod_id,
		p_fpga_info->n_fpga_ver_id, p_fpga_info->n_fpga_rev_id,
		p_fpga_info->n_fpga_ident, p_fpga_info->n_fpga_build_time);
	fprintf(pfh, "%s: FpgaDebugMode=0x%x\n", p_adapter_id_str,
		p_fpga_info->n_fpga_debug_mode);
	fprintf(pfh,
		"%s: Nims=%d PhyPorts=%d PhyQuads=%d RxPorts=%d TxPorts=%d\n",
		p_adapter_id_str, p_fpga_info->n_nims, p_fpga_info->n_phy_ports,
		p_fpga_info->n_phy_quads, p_fpga_info->n_rx_ports, p_fpga_info->n_tx_ports);
	fprintf(pfh, "%s: Hw=0x%02X_rev%d: %s\n", p_adapter_id_str,
		p_hw_info->hw_platform_id, p_fpga_info->nthw_hw_info.hw_id,
		p_fpga_info->nthw_hw_info.hw_plat_id_str);

	nt4ga_stat_dump(p_adapter_info, pfh);

	return 0;
}

/*
 * SPI for sensors initialization
 */
static nthw_spi_v3_t *new_sensors_s_spi(struct nt_fpga_s *p_fpga)
{
	nthw_spi_v3_t *sensors_s_spi = nthw_spi_v3_new();

	if (sensors_s_spi == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: SPI allocation error\n", __func__);
		return NULL;
	}

	if (nthw_spi_v3_init(sensors_s_spi, p_fpga, 0)) {
		NT_LOG(ERR, ETHDEV, "%s: SPI initialization error\n", __func__);
		nthw_spi_v3_delete(sensors_s_spi);
		return NULL;
	}

	return sensors_s_spi;
}

/*
 * SPI for sensors reading
 */
nthw_spis_t *new_sensors_t_spi(struct nt_fpga_s *p_fpga)
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

static void adapter_sensor_setup(hw_info_t *p_hw_info, struct adapter_info_s *adapter)
{
	struct nt_fpga_s *p_fpga = adapter->fpga_info.mp_fpga;
	struct nt_sensor_group *sensors_list_ptr = NULL;
	nthw_spi_v3_t *sensors_s_spi = new_sensors_s_spi(p_fpga);

	adapter->adapter_sensors_cnt = 0;

	/* FPGA */
	adapter->adapter_sensors = fpga_temperature_sensor_init(p_hw_info->n_nthw_adapter_id,
								NT_SENSOR_FPGA_TEMP, p_fpga);
	sensors_list_ptr = adapter->adapter_sensors;
	adapter->adapter_sensors_cnt++;

	/* AVR */
	if (sensors_s_spi) {
		if (nt_avr_sensor_mon_ctrl(sensors_s_spi,
					   SENSOR_MON_CTRL_REM_ALL_SENSORS) != 0) {
			/* stop sensor monitoring */
			NT_LOG(ERR, ETHDEV,
			       "Failed to stop AVR sensors monitoring\n");
		} else {
			NT_LOG(DBG, ETHDEV, "AVR sensors init started\n");

			sensors_list_ptr->next = avr_sensor_init(sensors_s_spi,
								 p_hw_info->n_nthw_adapter_id,
								 "FAN0",
								 NT_SENSOR_SOURCE_ADAPTER,
								 NT_SENSOR_TYPE_FAN,
								 NT_SENSOR_NT200E3_FAN_SPEED,
								 SENSOR_MON_FAN, 0,
								 SENSOR_MON_BIG_ENDIAN,
								 SENSOR_MON_UNSIGNED,
								 &fan, 0xFFFF);
			sensors_list_ptr = sensors_list_ptr->next;
			adapter->adapter_sensors_cnt++;

			sensors_list_ptr->next = avr_sensor_init(sensors_s_spi,
								 p_hw_info->n_nthw_adapter_id,
								 "PSU0",
								 NT_SENSOR_SOURCE_ADAPTER,
								 NT_SENSOR_TYPE_TEMPERATURE,
								 NT_SENSOR_NT200E3_PSU0_TEMP,
								 SENSOR_MON_PSU_EXAR_7724_0, 0x15,
								 SENSOR_MON_LITTLE_ENDIAN,
								 SENSOR_MON_UNSIGNED,
								 &exar7724_tj, 0xFFFF);
			sensors_list_ptr = sensors_list_ptr->next;
			adapter->adapter_sensors_cnt++;

			sensors_list_ptr->next = avr_sensor_init(sensors_s_spi,
								 p_hw_info->n_nthw_adapter_id,
								 "PSU1",
								 NT_SENSOR_SOURCE_ADAPTER,
								 NT_SENSOR_TYPE_TEMPERATURE,
								 NT_SENSOR_NT200A02_PSU1_TEMP,
								 SENSOR_MON_MP2886A, 0x8d,
								 SENSOR_MON_BIG_ENDIAN,
								 SENSOR_MON_UNSIGNED,
								 &mp2886a_tj, 0xFFFF);
			sensors_list_ptr = sensors_list_ptr->next;
			adapter->adapter_sensors_cnt++;

			sensors_list_ptr->next = avr_sensor_init(sensors_s_spi,
								 p_hw_info->n_nthw_adapter_id,
								 "PCB",
								 NT_SENSOR_SOURCE_ADAPTER,
								 NT_SENSOR_TYPE_TEMPERATURE,
								 NT_SENSOR_NT200E3_PCB_TEMP,
								 SENSOR_MON_DS1775, 0,
								 SENSOR_MON_LITTLE_ENDIAN,
								 SENSOR_MON_SIGNED,
								 &ds1775_t, 0xFFFF);
			sensors_list_ptr = sensors_list_ptr->next;
			adapter->adapter_sensors_cnt++;

			NT_LOG(DBG, ETHDEV, "AVR sensors init finished\n");

			if (nt_avr_sensor_mon_ctrl(sensors_s_spi,
						   SENSOR_MON_CTRL_RUN) != 0) {
				/* start sensor monitoring */
				NT_LOG(ERR, ETHDEV,
				       "Failed to start AVR sensors monitoring\n");
			} else {
				NT_LOG(DBG, ETHDEV,
				       "AVR sensors monitoring starteed\n");
			}
		}

		nthw_spi_v3_delete(sensors_s_spi);
	}
}

int nt4ga_adapter_init(struct adapter_info_s *p_adapter_info)
{
	char *const p_dev_name = malloc(24);
	char *const p_adapter_id_str = malloc(24);
	fpga_info_t *fpga_info = &p_adapter_info->fpga_info;
	hw_info_t *p_hw_info = &p_adapter_info->hw_info;

	/*
	 * IMPORTANT: Most variables cannot be determined before fpga model is instantiated
	 * (nthw_fpga_init())
	 */
	int n_phy_ports = -1;
	int n_nim_ports = -1;
	int res = -1;
	nt_fpga_t *p_fpga = NULL;

	(void)n_nim_ports; /* currently UNUSED - prevent warning */

	p_hw_info->n_nthw_adapter_id =
		nthw_platform_get_nthw_adapter_id(p_hw_info->pci_device_id);

	fpga_info->n_nthw_adapter_id = p_hw_info->n_nthw_adapter_id;
	p_hw_info->hw_product_type = p_hw_info->pci_device_id &
				   0x000f; /* ref: DN-0060 section 9 */
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

		for (i = 0; i < (int)ARRAY_SIZE(p_adapter_info->mp_port_id_str);
				i++) {
			char *p = malloc(32);

			if (p) {
				snprintf(p, 32, "%s:intf_%d",
					 (p_adapter_id_str ? p_adapter_id_str : "NA"),
					 i);
				NT_LOG(DBG, ETHDEV, "%s\n", p);
			}
			p_adapter_info->mp_port_id_str[i] = p;
		}
	}

	res = nthw_fpga_init(&p_adapter_info->fpga_info);
	if (res) {
		NT_LOG(ERR, ETHDEV, "%s: %s: FPGA=%04d res=x%08X [%s:%u]\n",
		       p_adapter_id_str, p_dev_name, fpga_info->n_fpga_prod_id, res,
		       __func__, __LINE__);
		return res;
	}

	assert(fpga_info);
	p_fpga = fpga_info->mp_fpga;
	assert(p_fpga);
	n_phy_ports = fpga_info->n_phy_ports;
	assert(n_phy_ports >= 1);
	n_nim_ports = fpga_info->n_nims;
	assert(n_nim_ports >= 1);

	/* Nt4ga Init Filter */
	nt4ga_filter_t *p_filter = &p_adapter_info->nt4ga_filter;

	res = flow_filter_init(p_fpga, &p_filter->mp_flow_device,
			     p_adapter_info->adapter_no);
	if (res != 0) {
		NT_LOG(ERR, ETHDEV, "%s: Cannot initialize filter\n",
		       p_adapter_id_str);
		return res;
	}

	/*
	 * HIF/PCI TA/TG
	 */
	{
		res = nt4ga_pci_ta_tg_init(p_adapter_info);
		if (res == 0) {
			nt4ga_pci_ta_tg_measure_throughput_main(p_adapter_info,
								0, 0,
								TG_PKT_SIZE,
								TG_NUM_PACKETS,
								TG_DELAY);
		} else {
			NT_LOG(WRN, ETHDEV,
			       "%s: PCI TA/TG is not available - skipping\n",
			       p_adapter_id_str);
		}
	}

	adapter_sensor_setup(p_hw_info, p_adapter_info);

	{
		int i;

		assert(fpga_info->n_fpga_prod_id > 0);
		for (i = 0; i < NUM_ADAPTER_PORTS_MAX; i++) {
			/* Disable all ports. Must be enabled later */
			p_adapter_info->nt4ga_link.port_action[i].port_disable =
				true;
		}
		switch (fpga_info->n_fpga_prod_id) {
		/* NT200A02: 2x100G */
		case 9563: /* NT200A02 */
			res = nt4ga_link_100g_ports_init(p_adapter_info, p_fpga);
			break;
		default:
			NT_LOG(ERR, ETHDEV,
			       "%s: Unsupported FPGA product: %04d\n", __func__,
			       fpga_info->n_fpga_prod_id);
			res = -1;
			break;
		}

		if (res) {
			NT_LOG(ERR, ETHDEV,
			       "%s: %s: %s: %u: FPGA=%04d res=x%08X\n",
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
			NT_LOG(ERR, ETHDEV, "%s: Cannot create EPP\n",
			       p_adapter_id_str);
			return -1;
		}

		res = nthw_epp_init(p_adapter_info->fpga_info.mp_nthw_epp,
				    p_adapter_info->fpga_info.mp_fpga, 0);
		if (res != 0) {
			NT_LOG(ERR, ETHDEV, "%s: Cannot initialize EPP\n",
			       p_adapter_id_str);
			return res;
		}
		NT_LOG(DBG, ETHDEV, "%s: Initialized EPP\n",
		       p_adapter_id_str);

		res = nthw_epp_setup(p_adapter_info->fpga_info.mp_nthw_epp);
		if (res != 0) {
			NT_LOG(ERR, ETHDEV, "%s: Cannot setup EPP\n",
			       p_adapter_id_str);
			return res;
		}
	}

	/* Nt4ga Stat init/setup */
	res = nt4ga_stat_init(p_adapter_info);
	if (res != 0) {
		NT_LOG(ERR, ETHDEV,
		       "%s: Cannot initialize the statistics module\n",
		       p_adapter_id_str);
		return res;
	}
	res = nt4ga_stat_setup(p_adapter_info);
	if (res != 0) {
		NT_LOG(ERR, ETHDEV, "%s: Cannot setup the statistics module\n",
		       p_adapter_id_str);
		return res;
	}

	return 0;
}

int nt4ga_adapter_deinit(struct adapter_info_s *p_adapter_info)
{
	fpga_info_t *fpga_info = &p_adapter_info->fpga_info;
	int i;
	int res;
	struct nt_sensor_group *cur_adapter_sensor = NULL;
	struct nt_sensor_group *next_adapter_sensor = NULL;
	struct nim_sensor_group *cur_nim_sensor = NULL;
	struct nim_sensor_group *next_nim_sensor = NULL;

	stop_monitor_tasks(-1);

	nt4ga_stat_stop(p_adapter_info);

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
			next_adapter_sensor =
				p_adapter_info->adapter_sensors->next;
			p_adapter_info->adapter_sensors = next_adapter_sensor;

			sensor_deinit(cur_adapter_sensor);
		} while (next_adapter_sensor != NULL);
	}

	/* Free NIM sensors */
	for (i = 0; i < fpga_info->n_phy_ports; i++) {
		if (p_adapter_info->nim_sensors[i] != NULL) {
			do {
				cur_nim_sensor = p_adapter_info->nim_sensors[i];
				next_nim_sensor =
					p_adapter_info->nim_sensors[i]->next;
				p_adapter_info->nim_sensors[i] = next_nim_sensor;
				free(cur_nim_sensor->sensor);
				free(cur_nim_sensor);
			} while (next_nim_sensor != NULL);
		}
	}

	return res;
}
