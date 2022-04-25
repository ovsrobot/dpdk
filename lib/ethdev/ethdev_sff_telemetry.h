/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#ifndef _ETHDEV_SFF_TELEMETRY_H_
#define _ETHDEV_SFF_TELEMETRY_H_

#include <rte_telemetry.h>

#define ARRAY_SIZE(arr) RTE_DIM(arr)

#define SFF_ITEM_NAME_SIZE 64
#define SFF_ITEM_VALUE_SIZE 256
#define SFF_ITEM_MAX_COUNT 256
#define SFF_ITEM_VAL_COMPOSE_SIZE 64

struct sff_item {
	char name[SFF_ITEM_NAME_SIZE];    /* The item name. */
	char value[SFF_ITEM_VALUE_SIZE];  /* The item value. */
};

uint16_t sff_item_count;

/* SFF-8079 Optics diagnostics */
void sff_8079_show_all(const uint8_t *data, struct sff_item *items);

/* SFF-8472 Optics diagnostics */
void sff_8472_show_all(const uint8_t *data, struct sff_item *items);

/* SFF-8636 Optics diagnostics */
void sff_8636_show_all(const uint8_t *data, uint32_t eeprom_len, struct sff_item *items);

int eth_dev_handle_port_module_eeprom(const char *cmd __rte_unused,
				      const char *params,
				      struct rte_tel_data *d);

void add_item_string(struct sff_item *items, const char *name_str, const char *value_str);

#endif /* _ETHDEV_SFF_TELEMETRY_H_ */
