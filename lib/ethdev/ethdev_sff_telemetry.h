/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Cavium, Inc
 */

#ifndef ETHDEV_SFF_H_
#define ETHDEV_SFF_H_

#include <rte_ethdev.h>
#include <rte_telemetry.h>

#define ARRAY_SIZE(arr) RTE_DIM(arr)

#define SFF_ITEM_NAME_SIZE 64
#define SFF_ITEM_VALUE_SIZE 256
#define SFF_ITEM_MAX_COUNT 256
#define TMP_STRING_SIZE 64

typedef struct sff_module_info_item {
	char name[SFF_ITEM_NAME_SIZE];    /* The item name. */
	char value[SFF_ITEM_VALUE_SIZE];  /* The item value. */
} sff_item;

#define SFF_ITEM_SIZE sizeof(sff_item)

uint16_t sff_item_count;

/* SFF-8079 Optics diagnostics */
void sff_8079_show_all(const uint8_t *id, sff_item *items);

/* SFF-8472 Optics diagnostics */
void sff_8472_show_all(const uint8_t *id, sff_item *items);

/* SFF-8636 Optics diagnostics */
void sff_8636_show_all(const uint8_t *id, uint32_t eeprom_len, sff_item *items);

int eth_dev_handle_port_module_eeprom(const char *cmd __rte_unused,
				      const char *params,
				      struct rte_tel_data *d);

void add_item_string(sff_item *items, const char *name_str, const char *value_str);

#endif /* ETHDEV_SFF_H_ */
