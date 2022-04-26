/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include <errno.h>

#include <rte_ethdev.h>
#include <rte_common.h>
#include "ethdev_sff_telemetry.h"

static uint16_t sff_item_count;

static void
sff_port_module_eeprom_display(uint16_t port_id, struct sff_item *items)
{
	struct rte_eth_dev_module_info minfo;
	struct rte_dev_eeprom_info einfo;
	int ret;

	ret = rte_eth_dev_get_module_info(port_id, &minfo);
	if (ret != 0) {
		switch (ret) {
		case -ENODEV:
			RTE_ETHDEV_LOG(ERR, "port index %d invalid\n", port_id);
			break;
		case -ENOTSUP:
			RTE_ETHDEV_LOG(ERR, "operation not supported by device\n");
			break;
		case -EIO:
			RTE_ETHDEV_LOG(ERR, "device is removed\n");
			break;
		default:
			RTE_ETHDEV_LOG(ERR, "Unable to get port %d EEPROM module info\n", ret);
			break;
		}
		return;
		}

	einfo.offset = 0;
	einfo.length = minfo.eeprom_len;
	einfo.data = calloc(1, minfo.eeprom_len);
	if (einfo.data == NULL) {
		RTE_ETHDEV_LOG(ERR, "Allocation of port %u eeprom data failed\n", port_id);
		return;
	}

	ret = rte_eth_dev_get_module_eeprom(port_id, &einfo);
	if (ret != 0) {
		switch (ret) {
		case -ENODEV:
			RTE_ETHDEV_LOG(ERR, "port index %d invalid\n", port_id);
			break;
		case -ENOTSUP:
			RTE_ETHDEV_LOG(ERR, "operation not supported by device\n");
			break;
		case -EIO:
			RTE_ETHDEV_LOG(ERR, "device is removed\n");
			break;
		default:
			RTE_ETHDEV_LOG(ERR, "Unable to get port %d module EEPROM\n", ret);
			break;
		}
		free(einfo.data);
		return;
	}

	switch (minfo.type) {
	/* parsing module EEPROM data base on different module type */
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
		RTE_ETHDEV_LOG(NOTICE, "Unsupported module type: %u\n", minfo.type);
		break;
	}

	free(einfo.data);
}

void
add_item_string(struct sff_item *items, const char *name_str, const char *value_str)
{
	/* append different values for same keys */
	if (sff_item_count > 0 &&
	    (strcmp(items[sff_item_count - 1].name, name_str) == 0)) {
		strlcat(items[sff_item_count - 1].value, "; ", SFF_ITEM_VALUE_SIZE);
		strlcat(items[sff_item_count - 1].value, value_str, SFF_ITEM_VALUE_SIZE);
		return;
	}

	snprintf(items[sff_item_count].name, SFF_ITEM_NAME_SIZE, "%s", name_str);
	snprintf(items[sff_item_count].value, SFF_ITEM_VALUE_SIZE, "%s", value_str);
	sff_item_count++;
}

int
eth_dev_handle_port_module_eeprom(const char *cmd __rte_unused, const char *params,
				  struct rte_tel_data *d)
{
	char *end_param;
	int port_id, i;
	struct sff_item *items;
	sff_item_count = 0;

	if (params == NULL || strlen(params) == 0 || !isdigit(*params))
		return -1;

	errno = 0;
	port_id = strtoul(params, &end_param, 0);

	if (errno != 0) {
		RTE_ETHDEV_LOG(ERR, "Invalid argument\n");
		return -1;
	}

	if (*end_param != '\0')
		RTE_ETHDEV_LOG(NOTICE,
			"Extra parameters passed to ethdev telemetry command, ignoring");

	items = calloc(1, sizeof(struct sff_item) * SFF_ITEM_MAX_COUNT);
	if (items == NULL) {
		RTE_ETHDEV_LOG(ERR, "Error allocating memory of items\n");
		return -1;
	}

	sff_port_module_eeprom_display(port_id, items);

	rte_tel_data_start_dict(d);
	for (i = 0; i < sff_item_count; i++)
		rte_tel_data_add_dict_string(d, items[i].name, items[i].value);

	free(items);
	return 0;
}
