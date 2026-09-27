/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#ifndef _ETHDEV_SFF_TELEMETRY_H_
#define _ETHDEV_SFF_TELEMETRY_H_

#include <rte_telemetry.h>

#define SFF_ITEM_VAL_COMPOSE_SIZE 64

/* Consumer of decoded module EEPROM fields */
struct sff_output {
	/* Called once per decoded field, name may repeat */
	void (*field_cb)(const char *name, const char *value, void *arg);
	void *arg;
};

/* SFF-8079 Optics diagnostics */
void sff_8079_show_all(const uint8_t *data, struct sff_output *d);

/* SFF-8472 Optics diagnostics */
void sff_8472_show_all(const uint8_t *data, struct sff_output *d);

/* SFF-8636 Optics diagnostics */
void sff_8636_show_all(const uint8_t *data, uint32_t eeprom_len, struct sff_output *d);

/*
 * Decode module EEPROM of the given type (RTE_ETH_MODULE_SFF_*).
 * Returns 0 on success, -EINVAL if the data is too short for the type,
 * -ENOTSUP if the type is unknown.
 */
int sff_decode_module_eeprom(uint32_t type, const uint8_t *data, uint32_t length,
			     struct sff_output *d);

int eth_dev_handle_port_module_eeprom(const char *cmd __rte_unused,
				      const char *params,
				      struct rte_tel_data *d);

void ssf_add_dict_string(struct sff_output *d, const char *name_str,
			 const char *value_str);

#endif /* _ETHDEV_SFF_TELEMETRY_H_ */
