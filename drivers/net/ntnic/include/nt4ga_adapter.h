/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NT4GA_ADAPTER_H_
#define _NT4GA_ADAPTER_H_

#include "common_adapter_defs.h"

struct adapter_info_s;

/*
 * DN-0060 section 9
 */
typedef struct hw_info_s {
	/* pciids */
	uint16_t pci_vendor_id;
	uint16_t pci_device_id;
	uint16_t pci_sub_vendor_id;
	uint16_t pci_sub_device_id;
	uint16_t pci_class_id;

	/* Derived from pciid */
	nthw_adapter_id_t n_nthw_adapter_id;
	int hw_platform_id;
	int hw_product_type;
	int hw_reserved1;
} hw_info_t;

/*
 * Services provided by the adapter module
 */
#include "nt4ga_pci_ta_tg.h"
#include "nt4ga_filter.h"
#include "ntnic_stat.h"
#include "nt4ga_tfg.h"
#include "nt4ga_link.h"

#include "nthw_spi_v3.h"
#include "ntnic_nim.h"

#include "ntnic_sensor.h"

typedef struct adapter_info_s {
	struct nt4ga_pci_ta_tg_s nt4ga_pci_ta_tg;
	struct nt4ga_stat_s nt4ga_stat;
	struct nt4ga_filter_s nt4ga_filter;
	struct nt4ga_tfg_s nt4ga_tfg;
	struct nt4ga_link_s nt4ga_link;

	struct nthw_mcu *mp_nthw_mcu;

	struct hw_info_s hw_info;
	struct fpga_info_s fpga_info;

	uint16_t adapter_sensors_cnt;
	uint16_t nim_sensors_cnt[NUM_ADAPTER_PORTS_MAX];
	struct nt_sensor_group *adapter_sensors;
	struct nim_sensor_group *nim_sensors[NUM_ADAPTER_PORTS_MAX];

	char *mp_port_id_str[NUM_ADAPTER_PORTS_MAX];
	char *mp_adapter_id_str;
	char *p_dev_name;
	volatile bool *pb_shutdown;

	int adapter_no;
	int n_rx_host_buffers;
	int n_tx_host_buffers;
} adapter_info_t;

/*
 * Monitor task operations.  This structure defines the management hooks for
 * Napatech network devices.  The following hooks can be defined; unless noted
 * otherwise, they are optional and can be filled with a null pointer.
 *
 * int (*mto_open)(int adapter, int port);
 *     The function to call when a network device transitions to the up state,
 *     e.g., `ip link set <interface> up`.
 *
 * int (*mto_stop)(int adapter, int port);
 *     The function to call when a network device transitions to the down state,
 *     e.g., `ip link set <interface> down`.
 */
struct monitor_task_ops {
	int (*mto_open)(int adapter, int port);
	int (*mto_stop)(int adapter, int port);
};

#include <pthread.h>
#include <signal.h>

/* The file nt4ga_adapter.c defines the next four variables. */
extern pthread_t monitor_tasks[NUM_ADAPTER_MAX];
extern volatile int monitor_task_is_running[NUM_ADAPTER_MAX];

/*
 * Function that sets up signal handler(s) that stop the monitoring tasks.
 */
int set_up_signal_handlers_to_stop_monitoring_tasks(void);

/* SPI for sensors reading */
nthw_spis_t *new_sensors_t_spi(struct nthw_fpga_s *p_fpga);

#endif	/* _NT4GA_ADAPTER_H_ */
