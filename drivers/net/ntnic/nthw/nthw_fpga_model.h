/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_FPGA_MODEL_H__
#define __NTHW_FPGA_MODEL_H__

#include <stdbool.h>
#include <stdio.h>
#include "fpga_model.h"

#ifndef FPGAID_TO_PRODUCTCODE
#define FPGAID_TO_PRODUCTTYPE(fpga_id) ((uint16_t)((fpga_id) >> 32) & 0xFF)
#define FPGAID_TO_PRODUCTCODE(fpga_id) ((uint16_t)((fpga_id) >> 16) & 0xFFFF)
#define FPGAID_TO_VERSIONCODE(fpga_id) ((uint16_t)((fpga_id) >> 8 & 0xFF))
#define FPGAID_TO_REVISIONCODE(fpga_id) ((uint16_t)((fpga_id) >> 0 & 0xFF))
#endif

#define VERSION_PACKED64(_major_, _minor_) \
	((((uint64_t)(_major_) & 0xFFFFFFFF) << 32) | ((_minor_) & 0xFFFFFFFF))

enum debug_mode { NO_DEBUG, ON_READ, ON_WRITE };

enum nthw_bus_type {
	NTHW_BUS_UNKNOWN,
	NTHW_BUS_BAR,
	NTHW_BUS_PCI,
	NTHW_BUS_NMB,
	NTHW_BUS_NDM,
	NTHW_BUS_RAB0,
	NTHW_BUS_RAB1,
	NTHW_BUS_RAB2
};

struct nt_fpga_s;

struct nt_param_s;

struct nt_module_s;

struct nt_register_s;

struct nt_field_s;

struct nt_fpga_mgr_s {
	int mn_fpgas;
	struct nt_fpga_prod_init **mpa_fpga_prod_init;
};

typedef struct nt_fpga_mgr_s nt_fpga_mgr_t;

struct nt_fpga_s {
	struct fpga_info_s *p_fpga_info;

	int m_item_id;
	int m_product_id;
	int m_fpga_version;
	int m_fpga_revision;
	int m_fpga_patch_no;
	int m_fpga_build_no;
	uint32_t m_fpga_build_time;

	int mn_params;
	struct nt_param_s **mpa_params;

	int mn_modules;
	struct nt_module_s **mpa_modules;

	nt_fpga_prod_init_t *mp_init;

	int m_debug_mode;
};

typedef struct nt_fpga_s nt_fpga_t;

struct nt_param_s {
	nt_fpga_t *mp_owner;

	int param_id;
	int param_value;

	nt_fpga_prod_param_t *mp_init;
};

typedef struct nt_param_s nt_param_t;

struct nt_module_s {
	nt_fpga_t *mp_owner;

	int m_mod_id;

	int m_instance;

	int m_mod_def_id;
	int m_major_version;
	int m_minor_version;

	int m_bus;
	uint32_t m_addr_base;

	int m_debug_mode;

	int mn_registers;
	struct nt_register_s **mpa_registers;

	nt_fpga_module_init_t *mp_init;
};

typedef struct nt_module_s nt_module_t;

struct nt_register_s {
	nt_module_t *mp_owner;

	uint32_t m_id;

	uint32_t mn_bit_width;
	uint32_t mn_addr_rel;
	uint32_t m_addr;
	uint32_t m_type;
	uint32_t m_len;

	int m_debug_mode;

	int mn_fields;
	struct nt_field_s **mpa_fields;

	uint32_t *mp_shadow;
	bool *mp_dirty;

	nt_fpga_register_init_t *mp_init;
};

typedef struct nt_register_s nt_register_t;

struct nt_field_s {
	nt_register_t *mp_owner;

	uint32_t m_id;

	uint32_t mn_bit_width;
	uint32_t mn_bit_pos_low;
	uint32_t m_reset_val;
	uint32_t m_first_word;
	uint32_t m_first_bit;
	uint32_t m_front_mask;
	uint32_t m_body_length;
	uint32_t mn_words;
	uint32_t m_tail_mask;

	int m_debug_mode;

	nt_fpga_field_init_t *mp_init;
};

typedef struct nt_field_s nt_field_t;

nt_fpga_mgr_t *fpga_mgr_new(void);
void fpga_mgr_init(nt_fpga_mgr_t *p);
void fpga_mgr_delete(nt_fpga_mgr_t *p);
nt_fpga_t *fpga_mgr_query_fpga(nt_fpga_mgr_t *p, uint64_t n_fpga_id,
			     struct fpga_info_s *p_fpga_info);

void fpga_mgr_log_dump(nt_fpga_mgr_t *p);
void fpga_mgr_show(nt_fpga_mgr_t *p, FILE *out, int detail_level);

nt_fpga_t *fpga_new(void);
void fpga_delete(nt_fpga_t *p);
void fpga_delete_all(nt_fpga_t *p);
void fpga_init(nt_fpga_t *p, nt_fpga_prod_init_t *fpga_prod_init,
	       struct fpga_info_s *p_fpga_info);

int fpga_get_product_param(const nt_fpga_t *p, const int n_param_id,
			 const int default_value);
int fpga_get_product_id(const nt_fpga_t *p);
int fpga_get_fpga_version(const nt_fpga_t *p);
int fpga_get_fpga_revision(const nt_fpga_t *p);
nt_module_t *fpga_query_module(const nt_fpga_t *p, int id, int instance);
nt_fpga_module_init_t *fpga_lookup_init(nt_fpga_t *p, int id, int instance);
bool fpga_query(nt_fpga_t *p, int id, int instance);
void fpga_set_debug_mode(nt_fpga_t *p, int n_debug_mode);

void fpga_log_info(const nt_fpga_t *p);
void fpga_dump(const nt_fpga_t *p);
void fpga_dump_params(const nt_fpga_t *p);
void fpga_dump_modules(const nt_fpga_t *p);

nt_param_t *param_new(void);
void param_delete(nt_param_t *p);
void param_init(nt_param_t *p, nt_fpga_t *p_fpga, nt_fpga_prod_param_t *p_init);

void param_dump(const nt_param_t *p);

nt_module_t *module_new(void);
void module_delete(nt_module_t *p);
void module_init(nt_module_t *p, nt_fpga_t *p_fpga,
		 nt_fpga_module_init_t *p_init);
void module_init2(nt_module_t *p, nt_fpga_t *p_fpga, int mod_id, int instance,
		  int debug_mode);

int module_get_major_version(const nt_module_t *p);
int module_get_minor_version(const nt_module_t *p);
uint64_t module_get_version_packed64(const nt_module_t *p);
bool module_is_version_newer(const nt_module_t *p, int major_version,
			   int minor_version);

int module_get_bus(const nt_module_t *p);
nt_register_t *module_get_register(nt_module_t *p, uint32_t id);
nt_register_t *module_query_register(nt_module_t *p, uint32_t id);
int module_get_debug_mode(const nt_module_t *p);
void module_set_debug_mode(nt_module_t *p, unsigned int debug_mode);
uint32_t module_get_addr_base(const nt_module_t *p);
void module_unsuppported(const nt_module_t *p);

void module_dump(const nt_module_t *p);
void module_dump_registers(const nt_module_t *p);

nt_register_t *register_new(void);
void register_delete(nt_register_t *p);
void register_init(nt_register_t *p, nt_module_t *p_module,
		   nt_fpga_register_init_t *p_init);

nt_field_t *register_get_field(const nt_register_t *p, uint32_t id);
nt_field_t *register_query_field(const nt_register_t *p, uint32_t id);

uint32_t register_get_address(const nt_register_t *p);
uint32_t register_get_addr_rel(const nt_register_t *p);
int register_get_bit_width(const nt_register_t *p);
int register_get_debug_mode(const nt_module_t *p);
void register_set_debug_mode(nt_register_t *p, unsigned int debug_mode);

void register_get_val(const nt_register_t *p, uint32_t *p_data, uint32_t len);
uint32_t register_get_val32(const nt_register_t *p);
uint32_t register_get_val_updated32(const nt_register_t *p);

void register_set_val(nt_register_t *p, const uint32_t *p_data, uint32_t len);
void register_set_val_flush(nt_register_t *p, const uint32_t *p_data,
			  uint32_t len);

void register_make_dirty(nt_register_t *p);
void register_update(const nt_register_t *p);
void register_reset(const nt_register_t *p);
void register_flush(const nt_register_t *p, uint32_t cnt);
void register_clr(nt_register_t *p);
void register_set(nt_register_t *p);

void register_do_read_trig_ts(const nt_register_t *p, uint64_t *tsc1,
			   uint64_t *tsc2);

void register_dump(const nt_register_t *p);
void register_dump_fields(const nt_register_t *p);

nt_field_t *field_new(void);
void field_delete(nt_field_t *p);
void field_init(nt_field_t *p, nt_register_t *p_reg,
		const nt_fpga_field_init_t *p_init);

int field_get_debug_mode(const nt_module_t *p);
void field_set_debug_mode(nt_field_t *p, unsigned int n_debug_mode);
int field_get_bit_width(const nt_field_t *p);
int field_get_bit_pos_low(const nt_field_t *p);
int field_get_bit_pos_high(const nt_field_t *p);
uint32_t field_get_mask(const nt_field_t *p);
void field_reset(const nt_field_t *p);
uint32_t field_get_reset_val(const nt_field_t *p);
void field_get_val(const nt_field_t *p, uint32_t *p_data, uint32_t len);
void field_set_val(const nt_field_t *p, const uint32_t *p_data, uint32_t len);
void field_set_val_flush(const nt_field_t *p, const uint32_t *p_data,
		       uint32_t len);
uint32_t field_get_val_mask(const nt_field_t *p);
uint32_t field_get_val32(const nt_field_t *p);
uint32_t field_get_updated(const nt_field_t *p);
void field_read_trig_with_tsc(const nt_field_t *p, uint64_t *tsc1, uint64_t *tsc2);
void field_update_register(const nt_field_t *p);
void field_flush_register(const nt_field_t *p);
void field_set_val32(const nt_field_t *p, uint32_t val);
void field_set_val_flush32(const nt_field_t *p, uint32_t val);
void field_clr_all(const nt_field_t *p);
void field_clr_flush(const nt_field_t *p);
void field_set_all(const nt_field_t *p);
void field_set_flush(const nt_field_t *p);

int field_wait_clr_all32(const nt_field_t *p, int n_poll_iterations,
		       int n_poll_interval);
int field_wait_set_all32(const nt_field_t *p, int n_poll_iterations,
		       int n_poll_interval);

int field_wait_clr_any32(const nt_field_t *p, int n_poll_iterations,
		       int n_poll_interval);
int field_wait_set_any32(const nt_field_t *p, int n_poll_iterations,
		       int n_poll_interval);

int field_wait_val_mask32(const nt_field_t *p, uint32_t n_wait_cond_value,
			uint32_t n_wait_cond_mask, int n_poll_iterations,
			int n_poll_interval);

void field_dump(const nt_field_t *p);
void field_dump_val(const nt_field_t *p);
void field_dump_init(const nt_fpga_field_init_t *p);

/*
 * nthw helpers
 */
nt_fpga_t *nthw_get_fpga(struct fpga_info_s *p_fpga_info, uint64_t n_fpga_ident);
nt_module_t *nthw_get_module(nt_fpga_t *p_fpga, int n_mod, int n_instance);
nt_register_t *nthw_get_register(nt_module_t *p_mod, int n_reg);
nt_field_t *nthw_get_field(nt_register_t *p_reg, int n_fld);

#endif /* __NTHW_FPGA_MODEL_H__ */
