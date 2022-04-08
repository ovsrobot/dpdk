/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Cavium, Inc
 */

#include <rte_ethdev.h>
#include <rte_common.h>
#include "sff_telemetry.h"

static void
sff_port_module_eeprom_display(uint16_t port_id, sff_item *items)
{
	struct rte_eth_dev_module_info minfo;
	struct rte_dev_eeprom_info einfo;
	int ret;

	ret = rte_eth_dev_get_module_info(port_id, &minfo);
	if (ret != 0) {
		switch (ret) {
		case -ENODEV:
			fprintf(stderr, "port index %d invalid\n", port_id);
			break;
		case -ENOTSUP:
			fprintf(stderr, "operation not supported by device\n");
			break;
		case -EIO:
			fprintf(stderr, "device is removed\n");
			break;
		default:
			fprintf(stderr, "Unable to get module EEPROM: %d\n",
				ret);
			break;
		}
		return;
	}

	einfo.offset = 0;
	einfo.length = minfo.eeprom_len;
	einfo.data = calloc(1, minfo.eeprom_len);
	if (!einfo.data) {
		fprintf(stderr,
			"Allocation of port %u eeprom data failed\n",
			port_id);
		return;
	}

	ret = rte_eth_dev_get_module_eeprom(port_id, &einfo);
	if (ret != 0) {
		switch (ret) {
		case -ENODEV:
			fprintf(stderr, "port index %d invalid\n", port_id);
			break;
		case -ENOTSUP:
			fprintf(stderr, "operation not supported by device\n");
			break;
		case -EIO:
			fprintf(stderr, "device is removed\n");
			break;
		default:
			fprintf(stderr, "Unable to get module EEPROM: %d\n",
				ret);
			break;
		}
		free(einfo.data);
		return;
	}

	switch (minfo.type) {
	case RTE_ETH_MODULE_SFF_8079:
		sff_8079_show_all(einfo.data, items);
		break;
	case RTE_ETH_MODULE_SFF_8472:
		sff_8079_show_all(einfo.data, items);
		sff_8472_show_all(einfo.data, items);
		break;
	case RTE_ETH_MODULE_SFF_8436:
	case RTE_ETH_MODULE_SFF_8636:
		sff_8636_show_all(einfo.data, einfo.length, items);
		break;
	default:
		break;
	}
	printf("Finish -- Port: %d MODULE EEPROM length: %d bytes\n", port_id, einfo.length);
	free(einfo.data);
}

void
add_item_string(sff_item *items, const char *name_str, const char *value_str)
{
	/* append different values for same keys */
	if (sff_item_count > 0 &&
	    (strcmp(items[sff_item_count - 1].name, name_str) == 0)) {
		strcat(items[sff_item_count - 1].value, "; ");
		strcat(items[sff_item_count - 1].value, value_str);
		return;
	}

	sprintf(items[sff_item_count].name, "%s", name_str);
	sprintf(items[sff_item_count].value, "%s", value_str);
	sff_item_count++;
}

static int
sff_module_tel_handle_info(const char *cmd __rte_unused, const char *params,
			struct rte_tel_data *d)
{
	/* handle module info */
	char *end_param;
	int port_id, i;
	sff_item *items;
	sff_item_count = 0;

	if (params == NULL || strlen(params) == 0 || !isdigit(*params))
		return -1;

	port_id = strtoul(params, &end_param, 0);
	if (*end_param != '\0')
		RTE_ETHDEV_LOG(NOTICE,
			"Extra parameters passed to ethdev telemetry command, ignoring");

	items = (sff_item *)malloc(SFF_ITEM_SIZE * SFF_ITEM_MAX_COUNT);
	if (items == NULL) {
		printf("Error allocating memory of items\n");
		free(items);
		return -1;
	}

	sff_port_module_eeprom_display(port_id, items);

	rte_tel_data_start_dict(d);
	for (i = 0; i < sff_item_count; i++)
		rte_tel_data_add_dict_string(d, items[i].name, items[i].value);

	free(items);
	return 0;
}

RTE_INIT(sff_module_info_init_telemetry)
{
	rte_telemetry_register_cmd(
		"/sff_module/info", sff_module_tel_handle_info,
		"Returns eeprom module info. Parameters: port_id");
}
