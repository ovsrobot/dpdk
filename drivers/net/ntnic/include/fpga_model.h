/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef FPGA_MODEL_H_
#define FPGA_MODEL_H_

#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

enum nt_fpga_bus_type {
	BUS_TYPE_UNKNOWN =
		0, /* Unknown/uninitialized - keep this as the first enum element */
	BUS_TYPE_BAR,
	BUS_TYPE_PCI,
	BUS_TYPE_CCIP,
	BUS_TYPE_RAB0,
	BUS_TYPE_RAB1,
	BUS_TYPE_RAB2,
	BUS_TYPE_NMB,
	BUS_TYPE_NDM,
	BUS_TYPE_SPI0,
	BUS_TYPE_SPI = BUS_TYPE_SPI0,
};

typedef enum nt_fpga_bus_type nt_fpga_bus_type_t;

enum nt_fpga_register_type {
	REGISTER_TYPE_UNKNOWN =
		0, /* Unknown/uninitialized - keep this as the first enum element */
	REGISTER_TYPE_RW,
	REGISTER_TYPE_RO,
	REGISTER_TYPE_WO,
	REGISTER_TYPE_RC1,
	REGISTER_TYPE_MIXED,
};

typedef enum nt_fpga_register_type nt_fpga_register_type_t;

struct nt_fpga_field_init {
	int id;
	uint16_t bw;
	uint16_t low;
	uint64_t reset_val;
};

typedef struct nt_fpga_field_init nt_fpga_field_init_t;

struct nt_fpga_register_init {
	int id;
	uint32_t addr_rel;
	uint16_t bw;
	nt_fpga_register_type_t type;
	uint64_t reset_val;
	int nb_fields;
	struct nt_fpga_field_init *fields;
};

typedef struct nt_fpga_register_init nt_fpga_register_init_t;

struct nt_fpga_module_init {
	int id;
	int instance;
	int def_id;
	int major_version;
	int minor_version;
	nt_fpga_bus_type_t bus_id;
	uint32_t addr_base;
	int nb_registers;
	struct nt_fpga_register_init *registers;
};

typedef struct nt_fpga_module_init nt_fpga_module_init_t;

struct nt_fpga_prod_param {
	const int param_id;
	const int param_value;
};

typedef struct nt_fpga_prod_param nt_fpga_prod_param_t;

struct nt_fpga_prod_init {
	int fpga_item_id;
	int fpga_product_id;
	int fpga_version;
	int fpga_revision;
	int fpga_patch_no;
	int fpga_build_no;
	uint32_t fpga_build_time;
	int nb_prod_params;
	struct nt_fpga_prod_param *product_params;
	int nb_modules;
	struct nt_fpga_module_init *modules;
};

typedef struct nt_fpga_prod_init nt_fpga_prod_init_t;

#endif /* FPGA_MODEL_H_ */
