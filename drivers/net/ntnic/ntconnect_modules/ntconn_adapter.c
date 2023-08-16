/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntnic_ethdev.h"
#include "ntconnect.h"
#include "ntconnect_api_adapter.h"
#include "ntos_system.h"
#include "ntconn_modules.h"
#include "ntconn_mod_helper.h"
#include "nt_util.h"
#include "ntlog.h"

#define NTCONN_ADAP_VERSION_MAJOR 0U
#define NTCONN_ADAP_VERSION_MINOR 1U

#define this_module_name "adapter"

#define MAX_ADAPTERS 2

static struct adap_hdl_s {
	struct drv_s *drv;
} adap_hdl[MAX_ADAPTERS];

static int func_adapter_get_interfaces(void *hdl, int client_id,
				       struct ntconn_header_s *hdr, char **data,
				       int *len);
static int func_adapter_get_info(void *hdl, int client_id,
				 struct ntconn_header_s *hdr, char **data,
				 int *len);
static int func_adapter_get_sensors(void *hdl, int client_id _unused,
				    struct ntconn_header_s *hdr _unused,
				    char **data, int *len);
static struct func_s funcs_get_level1[] = {
	{ "interfaces", NULL, func_adapter_get_interfaces },
	{ "info", NULL, func_adapter_get_info },
	{ "sensors", NULL, func_adapter_get_sensors },
	{ NULL, NULL, NULL },
};

static int func_adapter_set_interface(void *hdl, int client_id,
				      struct ntconn_header_s *hdr, char **data,
				      int *len);
static int func_adapter_set_adapter(void *hdl, int client_id,
				    struct ntconn_header_s *hdr, char **data,
				    int *len);
static struct func_s funcs_set_level1[] = {
	{ "interface", NULL, func_adapter_set_interface },
	{ "adapter", NULL, func_adapter_set_adapter },
	{ NULL, NULL, NULL },
};

/*
 * Entry level
 */
static struct func_s adapter_entry_funcs[] = {
	{ "get", funcs_get_level1, NULL },
	{ "set", funcs_set_level1, NULL },
	{ NULL, NULL, NULL },
};

static int read_link_speed(enum nt_link_speed_e link_speed)
{
	switch (link_speed) {
	case NT_LINK_SPEED_10M:
		return PORT_LINK_SPEED_10M;
	case NT_LINK_SPEED_100M:
		return PORT_LINK_SPEED_100M;
	case NT_LINK_SPEED_1G:
		return PORT_LINK_SPEED_1G;
	case NT_LINK_SPEED_10G:
		return PORT_LINK_SPEED_10G;
	case NT_LINK_SPEED_25G:
		return PORT_LINK_SPEED_25G;
	case NT_LINK_SPEED_40G:
		return PORT_LINK_SPEED_40G;
	case NT_LINK_SPEED_50G:
		return PORT_LINK_SPEED_50G;
	case NT_LINK_SPEED_100G:
		return PORT_LINK_SPEED_100G;
	default:
		break;
	}
	return PORT_LINK_SPEED_UNKNOWN;
}

static nt_link_speed_t convert_link_speed(char *speed_str)
{
	if (strcmp(speed_str, "10M") == 0)
		return NT_LINK_SPEED_10M;
	else if (strcmp(speed_str, "100M") == 0)
		return NT_LINK_SPEED_100M;
	else if (strcmp(speed_str, "1G") == 0)
		return NT_LINK_SPEED_1G;
	else if (strcmp(speed_str, "10G") == 0)
		return NT_LINK_SPEED_10G;
	else if (strcmp(speed_str, "25G") == 0)
		return NT_LINK_SPEED_25G;
	else if (strcmp(speed_str, "40G") == 0)
		return NT_LINK_SPEED_40G;
	else if (strcmp(speed_str, "50G") == 0)
		return NT_LINK_SPEED_50G;
	else if (strcmp(speed_str, "100G") == 0)
		return NT_LINK_SPEED_100G;
	else
		return NT_LINK_SPEED_UNKNOWN;
}

static int func_adapter_get_interfaces(void *hdl, int client_id _unused,
				       struct ntconn_header_s *hdr _unused,
				       char **data, int *len)
{
	struct ntc_interfaces_s *ifs;
	struct adap_hdl_s *adap = (struct adap_hdl_s *)hdl;
	fpga_info_t *fpga_info = &adap->drv->ntdrv.adapter_info.fpga_info;
	int lag_active;
	int final_list = adap->drv->probe_finished;
	/* keep final_list set before nb_ports are called */
	rte_compiler_barrier();
	int nb_ports = rte_eth_dev_count_avail();

	/* Get the "internals" structure of phy port 0 to find out if we're running LAG */
	char phy0_name[128];

	rte_eth_dev_get_name_by_port(0, phy0_name);
	struct rte_eth_dev *phy0_eth_dev = rte_eth_dev_get_by_name(phy0_name);

	if (phy0_eth_dev == NULL || phy0_eth_dev->data == NULL ||
			phy0_eth_dev->data->dev_private == NULL) {
		return ntconn_error(data, len, this_module_name,
				    NTCONN_ERR_CODE_INTERNAL_ERROR);
	}
	struct pmd_internals *phy0_internals =
		(struct pmd_internals *)phy0_eth_dev->data->dev_private;
	lag_active = (phy0_internals->lag_config == NULL) ? 0 : 1;
	if (lag_active) {
		/*
		 * Phy ports are link aggregated. I.e. number of ports is actually
		 * one bigger than what rte_eth_dev_count_avail() returned
		 */
		nb_ports++;

		/*
		 * Sanity check:
		 * For now we know about LAG with 2 ports only.
		 * If in the future we get HW with more ports, make assert to alert
		 * the developers that something needs to be looked at...
		 */
		assert(fpga_info->n_phy_ports == 2);
	}

	*len = sizeof(struct ntc_interfaces_s) +
	       sizeof(struct ntc_interface_s) * nb_ports;
	ifs = malloc(*len);
	if (!ifs) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "memory allocation failed");
		return REQUEST_ERR;
	}
	*data = (char *)ifs;

	ifs->nb_ports = nb_ports;
	ifs->final_list = final_list;

	int i;

	/* First set the "port type" of the physical ports */
	if (lag_active) {
		if (phy0_internals->lag_config->mode == BONDING_MODE_8023AD) {
			/* Active/active LAG */
			for (i = 0; i < fpga_info->n_phy_ports; i++) {
				ifs->intf[i].type =
					PORT_TYPE_PHY_LAG_ACTIVE_AVTIVE;
			}
		} else if (phy0_internals->lag_config->mode ==
				BONDING_MODE_ACTIVE_BACKUP) {
			/* Active/backup LAG */
			ifs->intf[phy0_internals->lag_config->primary_port]
			.type = PORT_TYPE_PHY_LAG_PRIMARY;
			ifs->intf[phy0_internals->lag_config->backup_port].type =
				PORT_TYPE_PHY_LAG_BACKUP;
		} else {
			/* Unknown LAG mode */
			assert(0);
		}
	} else {
		/* Normal phy ports (not link aggregated) */
		for (i = 0; i < fpga_info->n_phy_ports; i++)
			ifs->intf[i].type = PORT_TYPE_PHY_NORMAL;
	}

	/* Then set the remaining port values for the physical ports. */
	for (i = 0; i < fpga_info->n_phy_ports; i++) {
		char name[128];

		if (i > 0 && lag_active) {
			/*
			 * Secondary link aggregated port. Just display the "internals" values
			 * from port 0
			 */
			rte_eth_dev_get_name_by_port(0, name);
		} else {
			rte_eth_dev_get_name_by_port(i, name);
		}
		struct rte_eth_dev *eth_dev = rte_eth_dev_get_by_name(name);

		struct pmd_internals *internals =
			(struct pmd_internals *)eth_dev->data->dev_private;
		struct adapter_info_s *p_adapter_info =
				&adap->drv->ntdrv.adapter_info;

		ifs->intf[i].port_id = i;
		ifs->intf[i].pci_id.domain = internals->pci_dev->addr.domain;
		ifs->intf[i].pci_id.bus = internals->pci_dev->addr.bus;
		ifs->intf[i].pci_id.devid = internals->pci_dev->addr.devid;
		ifs->intf[i].pci_id.function =
			internals->pci_dev->addr.function;
		ifs->intf[i].pci_id.pad = 0;

		const bool port_link_status =
			nt4ga_port_get_link_status(p_adapter_info, i);
		ifs->intf[i].link = port_link_status ? PORT_LINK_UP :
				    PORT_LINK_DOWN;

		const nt_link_speed_t port_link_speed =
			nt4ga_port_get_link_speed(p_adapter_info, i);
		ifs->intf[i].port_speed = read_link_speed(port_link_speed);

		const bool port_adm_state =
			nt4ga_port_get_adm_state(p_adapter_info, i);
		if (!port_adm_state) {
			ifs->intf[i].port_state = PORT_STATE_DISABLED;
		} else {
			const bool port_nim_present =
				nt4ga_port_get_nim_present(p_adapter_info, i);
			if (port_nim_present) {
				ifs->intf[i].port_state =
					PORT_STATE_NIM_PRESENT;
			} else {
				ifs->intf[i].port_state = PORT_STATE_NIM_ABSENT;
			}
		}

		/* MTU */
		if (i > 0 && lag_active) {
			/* Secondary link aggregated port. Display same MTU value as port 0 */
			rte_eth_dev_get_mtu(0, &ifs->intf[i].mtu);
		} else {
			rte_eth_dev_get_mtu(i, &ifs->intf[i].mtu);
		}

		/* MAC */
		const uint64_t mac =
			fpga_info->nthw_hw_info.vpd_info.mn_mac_addr_value + i;
		ifs->intf[i].mac.addr_b[0] = (mac >> 40) & 0xFFu;
		ifs->intf[i].mac.addr_b[1] = (mac >> 32) & 0xFFu;
		ifs->intf[i].mac.addr_b[2] = (mac >> 24) & 0xFFu;
		ifs->intf[i].mac.addr_b[3] = (mac >> 16) & 0xFFu;
		ifs->intf[i].mac.addr_b[4] = (mac >> 8) & 0xFFu;
		ifs->intf[i].mac.addr_b[5] = (mac >> 0) & 0xFFu;

		if (i > 0 && lag_active) {
			/* Secondary link aggregated port. Queues not applicable */
			ifs->intf[i].num_queues = 0;
		} else {
			/* attached hw queues to this interface */
			unsigned int input_num = internals->nb_rx_queues;
			/*
			 * These are the "input" queues, meaning these go to host and is attached
			 * to receiving from a port
			 */
			for (unsigned int ii = 0; ii < input_num; ii++) {
				ifs->intf[i].queue[ii].idx =
					internals->rxq_scg[ii].queue.hw_id;
				ifs->intf[i].queue[ii].dir = QUEUE_INPUT;
			}

			/*
			 * These are the "output" queues, meaning these go to a virtual port queue
			 * which typically is used by vDPA
			 */
			for (unsigned int ii = 0; ii < internals->vpq_nb_vq;
					ii++) {
				ifs->intf[i].queue[ii + input_num].idx =
					internals->vpq[ii].hw_id;
				ifs->intf[i].queue[ii + input_num].dir =
					QUEUE_OUTPUT;
			}

			ifs->intf[i].num_queues =
				input_num + internals->vpq_nb_vq;
		}

		/* NIM information */
		nim_i2c_ctx_t nim_ctx =
			nt4ga_port_get_nim_capabilities(p_adapter_info, i);

		strlcpy((char *)&ifs->intf[i].nim_data.vendor_name,
			nim_ctx.vendor_name,
			sizeof(ifs->intf[i].nim_data.vendor_name));
		strlcpy((char *)&ifs->intf[i].nim_data.prod_no, nim_ctx.prod_no,
			sizeof(ifs->intf[i].nim_data.prod_no));
		strlcpy((char *)&ifs->intf[i].nim_data.serial_no,
			nim_ctx.serial_no,
			sizeof(ifs->intf[i].nim_data.serial_no));
		strlcpy((char *)&ifs->intf[i].nim_data.date, nim_ctx.date,
			sizeof(ifs->intf[i].nim_data.date));
		strlcpy((char *)&ifs->intf[i].nim_data.rev, nim_ctx.rev,
			sizeof(ifs->intf[i].nim_data.rev));

		if (nim_ctx.len_info[0] >= 0xFFFF)
			ifs->intf[i].nim_data.link_length.sm = 0xFFFF;
		else
			ifs->intf[i].nim_data.link_length.sm =
				nim_ctx.len_info[0];

		ifs->intf[i].nim_data.link_length.ebw = nim_ctx.len_info[1];
		ifs->intf[i].nim_data.link_length.mm50 = nim_ctx.len_info[2];
		ifs->intf[i].nim_data.link_length.mm62 = nim_ctx.len_info[3];
		ifs->intf[i].nim_data.link_length.copper = nim_ctx.len_info[4];

		ifs->intf[i].nim_data.pwr_level_req = nim_ctx.pwr_level_req;
		ifs->intf[i].nim_data.pwr_level_cur = nim_ctx.pwr_level_cur;
		ifs->intf[i].nim_data.nim_id = nim_ctx.nim_id;
		ifs->intf[i].nim_data.port_type = nim_ctx.port_type;
	}

	/* And finally handle the virtual ports. */
	int rte_eth_dev_virt_port_offset = lag_active ? 1 :
					   fpga_info->n_phy_ports;
	for (; i < nb_ports; i++, rte_eth_dev_virt_port_offset++) {
		/* Continue counting from the "i" value reached in the previous for loop */
		char name[128];

		rte_eth_dev_get_name_by_port(rte_eth_dev_virt_port_offset,
					     name);
		struct rte_eth_dev *eth_dev = rte_eth_dev_get_by_name(name);

		struct pmd_internals *internals =
			(struct pmd_internals *)eth_dev->data->dev_private;

		ifs->intf[i].port_id = i;
		ifs->intf[i].type = PORT_TYPE_VIRT;
		ifs->intf[i].pci_id.domain = internals->pci_dev->addr.domain;
		ifs->intf[i].pci_id.bus = internals->pci_dev->addr.bus;
		ifs->intf[i].pci_id.devid = internals->pci_dev->addr.devid;
		ifs->intf[i].pci_id.function =
			internals->pci_dev->addr.function;
		ifs->intf[i].pci_id.pad = 0;

		ifs->intf[i].port_speed = PORT_LINK_SPEED_NONE_REPORTED;
		switch (internals->vport_comm) {
		case VIRT_PORT_NEGOTIATED_NONE:
			ifs->intf[i].port_state = PORT_STATE_VIRTUAL_UNATTACHED;
			ifs->intf[i].link = PORT_LINK_DOWN;
			break;
		case VIRT_PORT_NEGOTIATED_SPLIT:
			ifs->intf[i].port_state = PORT_STATE_VIRTUAL_SPLIT;
			ifs->intf[i].link = PORT_LINK_UP;
			break;
		case VIRT_PORT_NEGOTIATED_PACKED:
			ifs->intf[i].port_state = PORT_STATE_VIRTUAL_PACKED;
			ifs->intf[i].link = PORT_LINK_UP;
			break;
		case VIRT_PORT_USE_RELAY:
			ifs->intf[i].port_state = PORT_STATE_VIRTUAL_RELAY;
			ifs->intf[i].link = PORT_LINK_UP;
			break;
		}

		/* MTU */
		rte_eth_dev_get_mtu(rte_eth_dev_virt_port_offset,
				    &ifs->intf[i].mtu);

		/* MAC */
		for (int ii = 0; ii < 6; ii++) {
			ifs->intf[i].mac.addr_b[ii] =
				internals->eth_addrs[0].addr_bytes[ii];
		}

		/* attached hw queues to this interface */
		unsigned int input_num = internals->nb_rx_queues;

		/*
		 * These are the "input" queues, meaning these go to host and is attached to
		 * receiving from a port
		 */
		for (unsigned int ii = 0; ii < input_num; ii++) {
			ifs->intf[i].queue[ii].idx =
				internals->rxq_scg[ii].queue.hw_id;
			ifs->intf[i].queue[ii].dir = QUEUE_INPUT;
		}

		/*
		 * These are the "output" queues, meaning these go to a virtual port queue
		 * which typically is used by vDPA
		 */
		unsigned int numq =
			((internals->vpq_nb_vq + input_num) > MAX_RSS_QUEUES) ?
			MAX_RSS_QUEUES - input_num :
			internals->vpq_nb_vq;
		for (unsigned int ii = 0; ii < numq; ii++) {
			ifs->intf[i].queue[ii + input_num].idx =
				internals->vpq[ii].hw_id;
			ifs->intf[i].queue[ii + input_num].dir = QUEUE_OUTPUT;
		}
		ifs->intf[i].num_queues = input_num + numq;
	}
	return REQUEST_OK;
}

static int func_adapter_get_info(void *hdl, int client_id _unused,
				 struct ntconn_header_s *hdr _unused,
				 char **data, int *len)
{
	struct adap_hdl_s *adap = (struct adap_hdl_s *)hdl;
	fpga_info_t *fpga_info = &adap->drv->ntdrv.adapter_info.fpga_info;

	*len = sizeof(struct ntc_adap_get_info_s);
	*data = malloc(*len);
	if (!*data) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "memory allocation failed");
		return REQUEST_ERR;
	}

	snprintf(*data, 31, "%03d-%04d-%02d-%02d", fpga_info->n_fpga_type_id,
		 fpga_info->n_fpga_prod_id, fpga_info->n_fpga_ver_id,
		 fpga_info->n_fpga_rev_id);

	return REQUEST_OK;
}

static int func_adapter_get_sensors(void *hdl, int client_id _unused,
				    struct ntconn_header_s *hdr _unused,
				    char **data, int *len)
{
	struct adapter_info_s *adapter =
		&(((struct adap_hdl_s *)hdl)->drv->ntdrv.adapter_info);
	struct sensor *sensor_ptr = NULL;
	uint16_t sensors_num = 0;
	uint8_t *sensors = NULL;
	struct ntc_sensors_s sensors_info = {
		.adapter_sensors_cnt = adapter->adapter_sensors_cnt,
		.ports_cnt = adapter->fpga_info.n_phy_ports
	};
	memcpy(sensors_info.adapter_name, adapter->p_dev_name, 24);

	/* Set a sum of sensor`s counters */
	sensors_num = adapter->adapter_sensors_cnt;
	for (int i = 0; i < adapter->fpga_info.n_phy_ports; i++) {
		sensors_num += adapter->nim_sensors_cnt[i];
		sensors_info.nim_sensors_cnt[i] = adapter->nim_sensors_cnt[i];
	}

	*len = sizeof(struct ntc_sensors_s) +
	       sensors_num * sizeof(struct sensor);

	/* Allocate memory for sensors array */
	sensors = malloc(*len);
	if (!sensors) {
		NT_LOG(ERR, NTCONNECT, "memory allocation failed");
		*len = 0;
		return REQUEST_ERR;
	}
	memcpy(sensors, &sensors_info, sizeof(struct ntc_sensors_s));
	sensor_ptr = (struct sensor *)(sensors + sizeof(struct ntc_sensors_s));

	/* Fetch adapter sensors */
	for (struct nt_sensor_group *ptr = adapter->adapter_sensors;
			ptr != NULL; ptr = ptr->next) {
		sensor_ptr->current_value = ptr->sensor->info.value;
		sensor_ptr->min_value = ptr->sensor->info.value_lowest;
		sensor_ptr->max_value = ptr->sensor->info.value_highest;
		sensor_ptr->sign = ptr->sensor->si;
		sensor_ptr->type = ptr->sensor->info.type;
		memcpy(sensor_ptr->name, ptr->sensor->info.name, 50);
		sensor_ptr++;
	}

	/* Fetch NIM sensors */
	for (int i = 0; i < adapter->fpga_info.n_phy_ports; i++) {
		for (struct nim_sensor_group *ptr = adapter->nim_sensors[i];
				ptr != NULL; ptr = ptr->next) {
			sensor_ptr->current_value = ptr->sensor->info.value;
			sensor_ptr->min_value = ptr->sensor->info.value_lowest;
			sensor_ptr->max_value = ptr->sensor->info.value_highest;
			sensor_ptr->sign = ptr->sensor->si;
			sensor_ptr->type = ptr->sensor->info.type;

			memcpy(sensor_ptr->name, ptr->sensor->info.name,
			       (strlen(ptr->sensor->info.name) >= 50) ?
			       50 :
			       strlen(ptr->sensor->info.name));
			sensor_ptr++;
		}
	}

	/* Send response */
	 *data = (char *)sensors;

	return REQUEST_OK;
}

static int set_port_enable(struct adap_hdl_s *adap, int port_nr)
{
	adapter_info_t *p_adapter_info = &adap->drv->ntdrv.adapter_info;

	nt4ga_port_set_adm_state(p_adapter_info, port_nr, true);

	return REQUEST_OK;
}

static int set_port_disable(struct adap_hdl_s *adap, int port_nr)
{
	adapter_info_t *p_adapter_info = &adap->drv->ntdrv.adapter_info;

	nt4ga_port_set_adm_state(p_adapter_info, port_nr, false);

	return REQUEST_OK;
}

static int set_link_up(struct adap_hdl_s *adap, int portid)
{
	struct adapter_info_s *p_adapter_info = &adap->drv->ntdrv.adapter_info;

	const bool link_status =
		nt4ga_port_get_link_status(p_adapter_info, portid);

	if (!link_status) {
		nt4ga_port_set_link_status(p_adapter_info, portid, true);
		NT_LOG(DBG, NTCONNECT, "Port %i: Link set to be up\n", portid);
	} else {
		NT_LOG(DBG, NTCONNECT,
		       "Port %i: Link is already set to be up\n", portid);
	}

	return REQUEST_OK;
}

static int set_link_down(struct adap_hdl_s *adap, int portid)
{
	struct adapter_info_s *p_adapter_info = &adap->drv->ntdrv.adapter_info;

	const bool link_status =
		nt4ga_port_get_link_status(p_adapter_info, portid);

	if (!link_status) {
		NT_LOG(DBG, NTCONNECT,
		       "Port %i: Link is already set to be down\n", portid);
	} else {
		nt4ga_port_set_link_status(p_adapter_info, portid, false);
		NT_LOG(DBG, NTCONNECT, "Port %i: Link set to be down\n",
		       portid);
	}

	return REQUEST_OK;
}

static int set_link_speed(struct adap_hdl_s *adap, int portid, char *speed_str,
			  char **data, int *len)
{
	struct adapter_info_s *p_adapter_info = &adap->drv->ntdrv.adapter_info;

	const bool port_adm_state =
		nt4ga_port_get_adm_state(p_adapter_info, portid);
	if (!port_adm_state) {
		const nt_link_speed_t speed = convert_link_speed(speed_str);

		if (speed != NT_LINK_SPEED_UNKNOWN) {
			nt4ga_port_set_link_speed(p_adapter_info, portid, speed);
			NT_LOG(DBG, NTCONNECT, "Port %i: set link speed - %s\n",
			       portid, speed_str);
		} else {
			return ntconn_error(data, len, this_module_name,
					    NTCONN_ERR_CODE_MISSING_INVALID_PARAM);
		}
	} else {
		NT_LOG(DBG, NTCONNECT,
		       "Port %i: fail to set link speed, port is enabled\n",
		       portid);
		return ntconn_reply_status(data, len,
					   NTCONN_ADAPTER_ERR_WRONG_LINK_STATE);
	}

	return REQUEST_OK;
}

static int set_loopback_mode(struct adap_hdl_s *adap, int portid, int mode)
{
	struct adapter_info_s *p_adapter_info = &adap->drv->ntdrv.adapter_info;

	NT_LOG(DBG, NTCONNECT, "Port %i: set loopback mode %i\n", portid, mode);
	nt4ga_port_set_loopback_mode(p_adapter_info, portid, mode);
	return REQUEST_OK;
}

static int set_tx_power(struct adap_hdl_s *adap, int portid, bool disable,
			char **data, int *len)
{
	struct adapter_info_s *p_adapter_info = &adap->drv->ntdrv.adapter_info;

	NT_LOG(DBG, NTCONNECT, "Port %i: set tx_power %i\n", portid, disable);
	if (nt4ga_port_tx_power(p_adapter_info, portid, disable)) {
		NT_LOG(DBG, NTCONNECT,
		       "Port %i: ERROR while changing tx_power\n", portid);
		return ntconn_reply_status(data, len,
					   NTCONN_ADAPTER_ERR_TX_POWER_FAIL);
	}
	return REQUEST_OK;
}

static int func_adapter_set_interface(void *hdl, int client_id _unused,
				      struct ntconn_header_s *hdr _unused,
				      char **data, int *len)
{
	struct adap_hdl_s *adap = (struct adap_hdl_s *)hdl;
	char *saveptr;
	int port_nr;
	int length;
	char *tok;

	*len = 0;

	/*
	 * This will receive the request strings starting with "adapter;set,interface,...."
	 * so in the situation of a request like: "adapter,set,interface,port0,link_speed=10G"
	 * the remainder of the command "port0,link_speed=10G" will be pointed to by *data,
	 * zero-terminated on entry
	 */

	if (!(data && *data))
		return ntconn_error(data, len, this_module_name,
				    NTCONN_ERR_CODE_INVALID_REQUEST);

	/* OK to modify *data */
	tok = strtok_r(*data, ",", &saveptr);
	if (!tok)
		return ntconn_error(data, len, this_module_name,
				    NTCONN_ERR_CODE_MISSING_INVALID_PARAM);

	length = strlen(tok);

	if (!(length > 4 && memcmp(tok, "port", 4) == 0))
		return ntconn_error(data, len, this_module_name,
				    NTCONN_ERR_CODE_MISSING_INVALID_PARAM);

	port_nr = atoi(tok + 4);

	/* Only set on phy ports */
	if (port_nr < adap->drv->ntdrv.adapter_info.fpga_info.n_phy_ports)
		return ntconn_error(data, len, this_module_name,
				    NTCONN_ERR_CODE_MISSING_INVALID_PARAM);

	tok = strtok_r(NULL, "=,", &saveptr);
	if (!tok)
		return ntconn_error(data, len, this_module_name,
			NTCONN_ERR_CODE_MISSING_INVALID_PARAM);
	if (strcmp(tok, "link_speed") == 0) {
		tok = strtok_r(NULL, ",", &saveptr);
		if (!tok)
			return ntconn_error(data, len, this_module_name,
				NTCONN_ERR_CODE_MISSING_INVALID_PARAM);
		return set_link_speed(adap, port_nr, tok, data, len);
	} else if (strcmp(tok, "enable") == 0) {
		return set_port_enable(adap, port_nr);
	} else if (strcmp(tok, "disable") == 0) {
		return set_port_disable(adap, port_nr);
	} else if (strcmp(tok, "link_state") == 0) {
		tok = strtok_r(NULL, ",", &saveptr);
		if (!tok)
			return ntconn_error(data, len, this_module_name,
				NTCONN_ERR_CODE_MISSING_INVALID_PARAM);
		if (strcmp(tok, "up") == 0)
			return set_link_up(adap, port_nr);
		else if (strcmp(tok, "down") == 0)
			return set_link_down(adap, port_nr);
	} else if (strcmp(tok, "host_loopback") == 0) {
		tok = strtok_r(NULL, ",", &saveptr);
		if (!tok)
			return ntconn_error(data, len, this_module_name,
				NTCONN_ERR_CODE_MISSING_INVALID_PARAM);
		if (strcmp(tok, "on") == 0)
			return set_loopback_mode(adap, port_nr,
				NT_LINK_LOOPBACK_HOST);
		else if (strcmp(tok, "off") == 0)
			return set_loopback_mode(adap, port_nr,
				NT_LINK_LOOPBACK_OFF);
	} else if (strcmp(tok, "line_loopback") == 0) {
		tok = strtok_r(NULL, ",", &saveptr);
		if (!tok)
			return ntconn_error(data, len, this_module_name,
				NTCONN_ERR_CODE_MISSING_INVALID_PARAM);
		if (strcmp(tok, "on") == 0)
			return set_loopback_mode(adap, port_nr,
				NT_LINK_LOOPBACK_LINE);
		else if (strcmp(tok, "off") == 0)
			return set_loopback_mode(adap, port_nr,
				NT_LINK_LOOPBACK_OFF);
	} else if (strcmp(tok, "tx_power") == 0) {
		tok = strtok_r(NULL, ",", &saveptr);
		if (!tok)
			return ntconn_error(data, len, this_module_name,
				NTCONN_ERR_CODE_MISSING_INVALID_PARAM);
		if (strcmp(tok, "on") == 0)
			return set_tx_power(adap, port_nr, false, data, len);
		else if (strcmp(tok, "off") == 0)
			return set_tx_power(adap, port_nr, true, data, len);
	}

	/* Should return 0 on success */
	return ntconn_error(data, len, this_module_name,
			    NTCONN_ERR_CODE_MISSING_INVALID_PARAM);
}

static int func_adapter_set_adapter(void *hdl _unused, int client_id _unused,
				    struct ntconn_header_s *hdr _unused,
				    char **data, int *len)
{
	if (data && *data) {
		NT_LOG(DBG, NTCONNECT,
		       "Set adapter: Command: %s\n", *data);
	}

	*len = 0;

	/* Should return 0 on success */
	return ntconn_error(data, len, this_module_name,
			    NTCONN_ERR_CODE_NOT_YET_IMPLEMENTED);
}

static int adap_request(void *hdl, int client_id _unused,
			struct ntconn_header_s *hdr, char *function,
			char **data, int *len)
{
	return execute_function(this_module_name, hdl, client_id, hdr, function,
				adapter_entry_funcs, data, len, 0);
}

static void adap_free_data(void *hdl _unused, char *data)
{
	free(data);
}

static void adap_client_cleanup(void *hdl _unused, int client_id _unused)
{
	/* Nothing to do */
}

static const ntconnapi_t ntconn_adap_op = { this_module_name,
					    NTCONN_ADAP_VERSION_MAJOR,
					    NTCONN_ADAP_VERSION_MINOR,
					    adap_request,
					    adap_free_data,
					    adap_client_cleanup
					  };

int ntconn_adap_register(struct drv_s *drv)
{
	int i;

	for (i = 0; i < MAX_ADAPTERS; i++) {
		if (adap_hdl[i].drv == NULL)
			break;
	}
	if (i == MAX_ADAPTERS) {
		NT_LOG(ERR, NTCONNECT,
		       "Cannot register more adapters into NtConnect framework");
		return -1;
	}

	adap_hdl[i].drv = drv;
	return register_ntconn_mod(&drv->p_dev->addr, (void *)&adap_hdl[i],
				   &ntconn_adap_op);
}
