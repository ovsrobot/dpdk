/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <time.h> /* ctime */

#include "nthw_drv.h" /* fpga_info_s */
#include "nthw_register.h"
#include "nthw_fpga_model.h"
#include "nthw_rac.h"
#include "ntlog.h"

#include "nthw_fpga_instances.h"
#include "nthw_fpga_modules_defs.h"

/* Generated code */
nt_fpga_prod_init_t *nthw_fpga_instances[] = { &nthw_fpga_9563_055_024_0000,
					       NULL
					     };

static const struct {
	const int a;
	const char *b;
} sa_nthw_fpga_mod_map[] = {
	{ MOD_CAT, "CAT" },
	{ MOD_CB, "CB" },
	{ MOD_CCIP, "CCIP" },
	{ MOD_CFP4_CTRL_GBOX, "CFP4_CTRL_GBOX" },
	{ MOD_COR, "COR" },
	{ MOD_CPY, "CPY" },
	{ MOD_CSU, "CSU" },
	{ MOD_DBS, "DBS" },
	{ MOD_DDP, "DDP" },
	{ MOD_EPP, "EPP" },
	{ MOD_EQM, "EQM" },
	{ MOD_FHM, "FHM" },
	{ MOD_FLM, "FLM" },
	{ MOD_GFG, "GFG" },
	{ MOD_GMF, "GMF" },
	{ MOD_GPIO_PHY, "GPIO_PHY" },
	{ MOD_GPIO_PHY_PORTS, "GPIO_PHY_PORTS" },
	{ MOD_GPIO_SFPP, "GPIO_SFPP" },
	{ MOD_HFU, "HFU" },
	{ MOD_HIF, "HIF" },
	{ MOD_HSH, "HSH" },
	{ MOD_HST, "HST" },
	{ MOD_ICORE_10G, "ICORE_10G" },
	{ MOD_IFR, "IFR" },
	{ MOD_IIC, "IIC" },
	{ MOD_INS, "INS" },
	{ MOD_IOA, "IOA" },
	{ MOD_IPF, "IPF" },
	{ MOD_KM, "KM" },
	{ MOD_LAO, "LAO" },
	{ MOD_MAC, "MAC" },
	{ MOD_MAC10, "MAC10" },
	{ MOD_MAC100, "MAC100" },
	{ MOD_MAC10G, "MAC10G" },
	{ MOD_MAC1G, "MAC1G" },
	{ MOD_MAC_PCS, "MAC_PCS" },
	{ MOD_MAC_PCS_XXV, "MAC_PCS_XXV" },
	{ MOD_MAC_RX, "MAC_RX" },
	{ MOD_MAC_TFG, "MAC_TFG" },
	{ MOD_MAC_TX, "MAC_TX" },
	{ MOD_MCU, "MCU" },
	{ MOD_MDG, "MDG" },
	{ MOD_MSK, "MSK" },
	{ MOD_NIF, "NIF" },
	{ MOD_PCIE3, "PCIE3" },
	{ MOD_PCI_RD_TG, "PCI_RD_TG" },
	{ MOD_PCI_TA, "PCI_TA" },
	{ MOD_PCI_WR_TG, "PCI_WR_TG" },
	{ MOD_PCM_NT100A01_01, "PCM_NT100A01_01" },
	{ MOD_PCM_NT50B01_01, "PCM_NT50B01_01" },
	{ MOD_PCS, "PCS" },
	{ MOD_PCS100, "PCS100" },
	{ MOD_PDB, "PDB" },
	{ MOD_PDI, "PDI" },
	{ MOD_PHY10G, "PHY10G" },
	{ MOD_PHY3S10G, "PHY3S10G" },
	{ MOD_PM, "PM" },
	{ MOD_PRM_NT100A01_01, "PRM_NT100A01_01" },
	{ MOD_PRM_NT50B01_01, "PRM_NT50B01_01" },
	{ MOD_PTP1588, "PTP1588" },
	{ MOD_QM, "QM" },
	{ MOD_QSL, "QSL" },
	{ MOD_QSPI, "QSPI" },
	{ MOD_R2DRP, "R2DRP" },
	{ MOD_RAC, "RAC" },
	{ MOD_RBH, "RBH" },
	{ MOD_RFD, "RFD" },
	{ MOD_RMC, "RMC" },
	{ MOD_RNTC, "RNTC" },
	{ MOD_ROA, "ROA" },
	{ MOD_RPL, "RPL" },
	{ MOD_RPP_LR, "RPP_LR" },
	{ MOD_RST7000, "RST7000" },
	{ MOD_RST7001, "RST7001" },
	{ MOD_RST9500, "RST9500" },
	{ MOD_RST9501, "RST9501" },
	{ MOD_RST9502, "RST9502" },
	{ MOD_RST9503, "RST9503" },
	{ MOD_RST9504, "RST9504" },
	{ MOD_RST9505, "RST9505" },
	{ MOD_RST9506, "RST9506" },
	{ MOD_RST9507, "RST9507" },
	{ MOD_RST9508, "RST9508" },
	{ MOD_RST9509, "RST9509" },
	{ MOD_RST9510, "RST9510" },
	{ MOD_RST9512, "RST9512" },
	{ MOD_RST9513, "RST9513" },
	{ MOD_RST9515, "RST9515" },
	{ MOD_RST9516, "RST9516" },
	{ MOD_RST9517, "RST9517" },
	{ MOD_RST9519, "RST9519" },
	{ MOD_RST9520, "RST9520" },
	{ MOD_RST9521, "RST9521" },
	{ MOD_RST9522, "RST9522" },
	{ MOD_RST9523, "RST9523" },
	{ MOD_RST9524, "RST9524" },
	{ MOD_RST9525, "RST9525" },
	{ MOD_RST9526, "RST9526" },
	{ MOD_RST9527, "RST9527" },
	{ MOD_RST9528, "RST9528" },
	{ MOD_RST9529, "RST9529" },
	{ MOD_RST9530, "RST9530" },
	{ MOD_RST9531, "RST9531" },
	{ MOD_RST9532, "RST9532" },
	{ MOD_RST9533, "RST9533" },
	{ MOD_RST9534, "RST9534" },
	{ MOD_RST9535, "RST9535" },
	{ MOD_RST9536, "RST9536" },
	{ MOD_RST9537, "RST9537" },
	{ MOD_RST9538, "RST9538" },
	{ MOD_RST9539, "RST9539" },
	{ MOD_RST9540, "RST9540" },
	{ MOD_RST9541, "RST9541" },
	{ MOD_RST9542, "RST9542" },
	{ MOD_RST9543, "RST9543" },
	{ MOD_RST9544, "RST9544" },
	{ MOD_RST9545, "RST9545" },
	{ MOD_RST9546, "RST9546" },
	{ MOD_RST9547, "RST9547" },
	{ MOD_RST9548, "RST9548" },
	{ MOD_RST9549, "RST9549" },
	{ MOD_RST9553, "RST9553" },
	{ MOD_RST9555, "RST9555" },
	{ MOD_RST9559, "RST9559" },
	{ MOD_RST9563, "RST9563" },
	{ MOD_RTD, "RTD" },
	{ MOD_RTD_HMP, "RTD_HMP" },
	{ MOD_RTX, "RTX" },
	{ MOD_SDC, "SDC" },
	{ MOD_SLC, "SLC" },
	{ MOD_SLC_LR, "SLC_LR" },
	{ MOD_SMM, "SMM" },
	{ MOD_SMM_RX, "SMM_RX" },
	{ MOD_SMM_TX, "SMM_TX" },
	{ MOD_SPIM, "SPIM" },
	{ MOD_SPIS, "SPIS" },
	{ MOD_STA, "STA" },
	{ MOD_TBH, "TBH" },
	{ MOD_TEMPMON, "TEMPMON" },
	{ MOD_TINT, "TINT" },
	{ MOD_TMC, "TMC" },
	{ MOD_TSM, "TSM" },
	{ MOD_TX_CPY, "TX_CPY" },
	{ MOD_TX_CSI, "TX_CSI" },
	{ MOD_TX_CSO, "TX_CSO" },
	{ MOD_TX_INS, "TX_INS" },
	{ MOD_TX_RPL, "TX_RPL" },
	{ 0L, NULL },
};

/* NOTE: this needs to be (manually) synced with enum */
static const char *const a_bus_type[] = {
	"ERR", /* BUS_TYPE_UNKNOWN, */
	"BAR", /* BUS_TYPE_BAR, */
	"PCI", /* BUS_TYPE_PCI, */
	"CCIP", /* BUS_TYPE_CCIP, */
	"RAB0", /* BUS_TYPE_RAB0, */
	"RAB1", /* BUS_TYPE_RAB1, */
	"RAB2", /* BUS_TYPE_RAB2, */
	"NMB", /* BUS_TYPE_NMB, */
	"NDM", /* BUS_TYPE_NDM, */
};

static const char *get_bus_name(int n_bus_type_id)
{
	if (n_bus_type_id >= 1 && n_bus_type_id <= (int)ARRAY_SIZE(a_bus_type))
		return a_bus_type[n_bus_type_id];

	else
		return "ERR";
}

/*
 * Module name lookup by id from array
 * Uses naive linear search as performance is not an issue here...
 */
static const char *nthw_fpga_mod_id_to_str(uint64_t n_fpga_mod_id)
{
	int i;

	for (i = 0; i <= (int)ARRAY_SIZE(sa_nthw_fpga_mod_map); i++) {
		if ((uint64_t)sa_nthw_fpga_mod_map[i].a == n_fpga_mod_id)
			break;
	}
	return (sa_nthw_fpga_mod_map[i].b ? sa_nthw_fpga_mod_map[i].b :
		"unknown");
}

/*
 * Force C linkage for xxx_addr_bases and xxx_module_versions
 */
static int read_data(struct fpga_info_s *p_fpga_info, int n_bus_type_id, uint32_t addr,
		    uint32_t len, uint32_t *p_data)
{
	int rc = -1;

	assert(p_fpga_info);
	assert(p_data);

	switch (n_bus_type_id) {
	case BUS_TYPE_BAR:
	case BUS_TYPE_PCI:
		assert(len == 1);
		nthw_rac_reg_read32(p_fpga_info, addr, p_data);
		rc = 0;
		break;
	case BUS_TYPE_RAB0:
		assert(p_fpga_info->mp_nthw_rac);
		rc = nthw_rac_rab_read32(p_fpga_info->mp_nthw_rac, addr, 0, len,
					p_data);
		break;
	case BUS_TYPE_RAB1:
		assert(p_fpga_info->mp_nthw_rac);
		rc = nthw_rac_rab_read32(p_fpga_info->mp_nthw_rac, addr, 1, len,
					p_data);
		break;
	case BUS_TYPE_RAB2:
		assert(p_fpga_info->mp_nthw_rac);
		rc = nthw_rac_rab_read32(p_fpga_info->mp_nthw_rac, addr, 2, len,
					p_data);
		break;
	default:
		assert(false);
		return -1;
	}

	return rc;
}

static int read_data_tsc(struct fpga_info_s *p_fpga_info, int n_bus_type_id,
		       uint32_t addr, uint32_t len, uint32_t *p_data,
		       uint64_t *p_tsc1, uint64_t *p_tsc2)
{
	int rc = -1;

	(void)p_tsc1;
	(void)p_tsc2;

	rc = read_data(p_fpga_info, n_bus_type_id, addr, len, p_data);

	return rc;
}

static int write_data(struct fpga_info_s *p_fpga_info, int n_bus_type_id,
		     uint32_t addr, uint32_t len, const uint32_t *p_data)
{
	int rc = -1;

	assert(p_fpga_info);
	assert(p_data);

	switch (n_bus_type_id) {
	case BUS_TYPE_BAR:
	case BUS_TYPE_PCI:
		assert(len == 1);
		nthw_rac_reg_write32(p_fpga_info, addr, *p_data);
		rc = 0;
		break;
	case BUS_TYPE_RAB0:
		assert(p_fpga_info->mp_nthw_rac);
		rc = nthw_rac_rab_write32(p_fpga_info->mp_nthw_rac, addr, 0, len,
					 p_data);
		break;
	case BUS_TYPE_RAB1:
		assert(p_fpga_info->mp_nthw_rac);
		rc = nthw_rac_rab_write32(p_fpga_info->mp_nthw_rac, addr, 1, len,
					 p_data);
		break;
	case BUS_TYPE_RAB2:
		assert(p_fpga_info->mp_nthw_rac);
		rc = nthw_rac_rab_write32(p_fpga_info->mp_nthw_rac, addr, 2, len,
					 p_data);
		break;
	default:
		assert(false);
		return -1;
	}

	return rc;
}

/*
 * FpgaMgr
 */
nt_fpga_mgr_t *fpga_mgr_new(void)
{
	nt_fpga_mgr_t *p = malloc(sizeof(nt_fpga_mgr_t));
	return p;
}

void fpga_mgr_delete(nt_fpga_mgr_t *p)
{
	memset(p, 0, sizeof(nt_fpga_mgr_t));
	free(p);
}

void fpga_mgr_init(nt_fpga_mgr_t *p)
{
	size_t i;

	/* Count fpga instance in array */
	p->mpa_fpga_prod_init = nthw_fpga_instances;
	for (i = 0; i < ARRAY_SIZE(nthw_fpga_instances); i++) {
		if (p->mpa_fpga_prod_init[i] == NULL)
			break;
	}
	p->mn_fpgas = (int)i;
}

nt_fpga_t *fpga_mgr_query_fpga(nt_fpga_mgr_t *p, uint64_t n_fpga_id,
			     struct fpga_info_s *p_fpga_info)
{
	int i;

	const int n_fpga_prod = FPGAID_TO_PRODUCTCODE(n_fpga_id);
	const int n_fpga_ver = FPGAID_TO_VERSIONCODE(n_fpga_id);
	const int n_fpga_rev = FPGAID_TO_REVISIONCODE(n_fpga_id);

	for (i = 0; i < p->mn_fpgas; i++) {
		nt_fpga_prod_init_t *p_init = p->mpa_fpga_prod_init[i];

		if (p_init->fpga_product_id == n_fpga_prod &&
				p_init->fpga_version == n_fpga_ver &&
				p_init->fpga_revision == n_fpga_rev) {
			{
				nt_fpga_t *p_fpga = fpga_new();

				fpga_init(p_fpga, p_init, p_fpga_info);
				return p_fpga;
			}
		}
	}

	NT_LOG(ERR, NTHW,
	       "FPGA Id 0x%" PRIX64 ": %04d: %d.%d: no match found\n", n_fpga_id,
	       n_fpga_prod, n_fpga_ver, n_fpga_rev);

	return NULL;
}

void fpga_mgr_show(nt_fpga_mgr_t *p, FILE *fh_out, int detail_level)
{
	int i;

	fprintf(fh_out, "\n"); /* start of records */
	for (i = 0; i < p->mn_fpgas; i++) {
		nt_fpga_prod_init_t *p_init = p->mpa_fpga_prod_init[i];

		if (detail_level == 0) {
			fprintf(fh_out, "%04d-%02d-%02d\n",
				p_init->fpga_product_id, p_init->fpga_version,
				p_init->fpga_revision);
		} else {
			time_t fpga_build_time = p_init->fpga_build_time;

			fprintf(fh_out, "%04d-%02d-%02d: 0x%08lX: %s\n",
				p_init->fpga_product_id, p_init->fpga_version,
				p_init->fpga_revision, fpga_build_time,
				(fpga_build_time ? ctime(&fpga_build_time) :
				 "NA\n"));
		}
	}
	fprintf(fh_out, "\n"); /* end of records */
	fflush(fh_out);
}

void fpga_mgr_log_dump(nt_fpga_mgr_t *p)
{
	int i;

	NT_LOG(DBG, NTHW, "%s: fpgas=%d\n", __func__, p->mn_fpgas);
	for (i = 0; i < p->mn_fpgas; i++) {
		nt_fpga_prod_init_t *p_init _unused = p->mpa_fpga_prod_init[i];
		NT_LOG(DBG, NTHW, "%s: fpga=%d/%d: %04d-%02d-%02d\n", __func__,
		       i, p->mn_fpgas, p_init->fpga_product_id, p_init->fpga_version,
		       p_init->fpga_revision);
	}
}

/*
 * Fpga
 */
nt_fpga_t *fpga_new(void)
{
	nt_fpga_t *p = malloc(sizeof(nt_fpga_t));

	if (p)
		memset(p, 0, sizeof(nt_fpga_t));
	return p;
}

void fpga_delete(nt_fpga_t *p)
{
	memset(p, 0, sizeof(nt_fpga_t));
	free(p);
}

void fpga_delete_all(nt_fpga_t *p)
{
	int i;

	for (i = 0; i < p->mn_modules; i++) {
		nt_module_t *p_mod = p->mpa_modules[i];

		if (p_mod)
			module_delete(p_mod);
	}

	fpga_delete(p);
}

void fpga_init(nt_fpga_t *p, nt_fpga_prod_init_t *fpga_prod_init,
	       struct fpga_info_s *p_fpga_info)
{
	int i;

	p->p_fpga_info = p_fpga_info;
	p->mp_init = fpga_prod_init;

	p->m_item_id = fpga_prod_init->fpga_item_id;
	p->m_product_id = fpga_prod_init->fpga_product_id;
	p->m_fpga_version = fpga_prod_init->fpga_version;
	p->m_fpga_revision = fpga_prod_init->fpga_revision;
	p->m_fpga_patch_no = fpga_prod_init->fpga_patch_no;
	p->m_fpga_build_no = fpga_prod_init->fpga_build_no;
	p->m_fpga_build_time = fpga_prod_init->fpga_build_time;

	p->mn_params = fpga_prod_init->nb_prod_params;

	if (p->mn_params) {
		p->mpa_params = malloc(p->mn_params * sizeof(nt_param_t *));
		if (p->mpa_params) {
			memset(p->mpa_params, 0,
			       (p->mn_params * sizeof(nt_param_t *)));
			for (i = 0; i < p->mn_params; i++) {
				nt_param_t *p_param = param_new();

				param_init(p_param, p,
					   &fpga_prod_init->product_params[i]);
				p->mpa_params[i] = p_param;
			}
		}
	}

	p->mn_modules = fpga_prod_init->nb_modules;

	if (p->mn_modules) {
		p->mpa_modules =
			malloc(fpga_prod_init->nb_modules * sizeof(nt_module_t *));
		if (p->mpa_modules) {
			memset(p->mpa_modules, 0,
			       (p->mn_modules * sizeof(nt_module_t *)));
			for (i = 0; i < p->mn_modules; i++) {
				nt_module_t *p_mod = module_new();

				module_init(p_mod, p, &fpga_prod_init->modules[i]);
				p->mpa_modules[i] = p_mod;
			}
		}
	}
}

void fpga_set_debug_mode(nt_fpga_t *p, int n_debug_mode)
{
	int i;

	p->m_debug_mode = n_debug_mode;

	for (i = 0; i < p->mn_modules; i++) {
		nt_module_t *p_mod = p->mpa_modules[i];

		if (p_mod)
			module_set_debug_mode(p_mod, n_debug_mode);
	}
}

nt_module_t *fpga_query_module(const nt_fpga_t *p, int id, int instance)
{
	int i;

	for (i = 0; i < p->mn_modules; i++) {
		nt_module_t *p_mod = p->mpa_modules[i];

		if (p_mod->m_mod_id == id && p_mod->m_instance == instance)
			return p_mod;
	}
	return NULL;
}

bool fpga_query(nt_fpga_t *p, int id, int instance)
{
	return (fpga_query_module(p, id, instance) != NULL);
}

nt_fpga_module_init_t *fpga_lookup_init(nt_fpga_t *p, int id, int instance)
{
	int i;

	for (i = 0; i < p->mp_init->nb_modules; i++) {
		nt_fpga_module_init_t *p_mod_init = &p->mp_init->modules[i];

		if (p_mod_init->id == id && p_mod_init->instance == instance)
			return p_mod_init;
	}
	return NULL;
}

int fpga_get_product_param(const nt_fpga_t *p, const int n_param_id,
			 const int n_default_value)
{
	int i;

	for (i = 0; i < p->mn_params; i++) {
		nt_param_t *p_param = p->mpa_params[i];

		if (p_param->param_id == n_param_id)
			return p_param->param_value;
	}

	return n_default_value;
}

int fpga_get_product_id(const nt_fpga_t *p)
{
	return p->m_product_id;
}

int fpga_get_fpga_version(const nt_fpga_t *p)
{
	return p->m_fpga_version;
}

int fpga_get_fpga_revision(const nt_fpga_t *p)
{
	return p->m_fpga_revision;
}

void fpga_log_info(const nt_fpga_t *p _unused)
{
	NT_LOG(INF, NTHW, "FPGA: %d-%d-%d-%d-%d-%d (%08X)\n", p->m_item_id,
	       p->m_product_id, p->m_fpga_version, p->m_fpga_revision,
	       p->m_fpga_patch_no, p->m_fpga_build_no, p->m_fpga_build_time);
}

void fpga_dump(const nt_fpga_t *p)
{
	NT_LOG(DBG, NTHW, "%s: id=%d ver=%d.%d params=%d modules=%d\n",
	       __func__, p->m_product_id, p->m_fpga_version, p->m_fpga_revision,
	       p->mn_params, p->mn_modules);
	fpga_dump_params(p);
	fpga_dump_modules(p);
}

void fpga_dump_params(const nt_fpga_t *p)
{
	int i;

	NT_LOG(DBG, NTHW, "%s: params=%d\n", __func__, p->mn_params);

	for (i = 0; i < p->mn_params; i++) {
		nt_param_t *p_par = p->mpa_params[i];

		param_dump(p_par);
	}
}

void fpga_dump_modules(const nt_fpga_t *p)
{
	int i;

	NT_LOG(DBG, NTHW, "%s: modules=%d\n", __func__, p->mn_modules);

	for (i = 0; i < p->mn_modules; i++) {
		nt_module_t *p_mod = p->mpa_modules[i];

		module_dump(p_mod);
	}
}

/*
 * Param
 */
nt_param_t *param_new(void)
{
	nt_param_t *p = malloc(sizeof(nt_param_t));
	return p;
}

void param_delete(nt_param_t *p)
{
	if (p) {
		memset(p, 0, sizeof(nt_param_t));
		free(p);
	}
}

void param_init(nt_param_t *p, nt_fpga_t *p_fpga, nt_fpga_prod_param_t *p_init)
{
	p->mp_owner = p_fpga;
	p->mp_init = p_init;

	p->param_id = p_init->param_id;
	p->param_value = p_init->param_value;
}

void param_dump(const nt_param_t *p _unused)
{
	NT_LOG(DBG, NTHW, "%s: id=%d value=%d\n", __func__, p->param_id,
	       p->param_value);
}

/*
 * Module
 */
nt_module_t *module_new(void)
{
	nt_module_t *p = malloc(sizeof(nt_module_t));
	return p;
}

void module_delete(nt_module_t *p)
{
	int i;

	for (i = 0; i < p->mn_registers; i++) {
		nt_register_t *p_reg = p->mpa_registers[i];

		if (p_reg)
			register_delete(p_reg);
	}
	memset(p, 0, sizeof(nt_module_t));
	free(p);
}

void module_init(nt_module_t *p, nt_fpga_t *p_fpga, nt_fpga_module_init_t *p_init)
{
	int i;

	p->mp_owner = p_fpga;
	p->mp_init = p_init;

	p->m_mod_id = p_init->id;
	p->m_instance = p_init->instance;

	/* Copy debug mode from owner */
	if (p->mp_owner)
		p->m_debug_mode = p->mp_owner->m_debug_mode;

	else
		p->m_debug_mode = 0;

	p->m_mod_def_id = p_init->def_id;
	p->m_major_version = p_init->major_version;
	p->m_minor_version = p_init->minor_version;
	p->m_bus = p_init->bus_id;
	p->m_addr_base = p_init->addr_base;

	p->mn_registers = p_init->nb_registers;
	if (p->mn_registers) {
		p->mpa_registers =
			malloc(p->mn_registers * sizeof(nt_register_t *));
		if (p->mpa_registers) {
			memset(p->mpa_registers, 0,
			       (p->mn_registers * sizeof(nt_register_t *)));
			for (i = 0; i < p->mn_registers; i++) {
				nt_register_t *p_reg = register_new();

				register_init(p_reg, p, &p_init->registers[i]);
				p->mpa_registers[i] = p_reg;
			}
		}
	}
}

void module_init2(nt_module_t *p, nt_fpga_t *p_fpga, int mod_id, int instance,
		  int debug_mode)
{
	nt_fpga_module_init_t *p_init = NULL;

	p_init = fpga_lookup_init(p_fpga, mod_id, instance);
	module_init(p, p_fpga, p_init);

	/* set debug mode after regulat init... */
	p->m_debug_mode = debug_mode;
}

void module_dump(const nt_module_t *p)
{
	NT_LOG(DBG, NTHW,
	       "%s: id=%d inst=%d def=%d ver=%d.%d busid=%d base=0x%X regs=%d\n",
	       __func__, p->m_mod_id, p->m_instance, p->m_mod_def_id,
	       p->m_major_version, p->m_minor_version, p->m_bus, p->m_addr_base,
	       p->mn_registers);
	module_dump_registers(p);
}

void module_dump_registers(const nt_module_t *p)
{
	int i;

	NT_LOG(DBG, NTHW, "%s: regs=%d\n", __func__, p->mn_registers);

	for (i = 0; i < p->mn_registers; i++) {
		nt_register_t *p_reg = p->mpa_registers[i];

		register_dump(p_reg);
	}
}

int module_get_major_version(const nt_module_t *p)
{
	return p->m_major_version;
}

int module_get_minor_version(const nt_module_t *p)
{
	return p->m_minor_version;
}

uint64_t module_get_version_packed64(const nt_module_t *p)
{
	return (((uint64_t)p->m_major_version & 0xFFFFFFFF) << 32) |
	       (p->m_minor_version & 0xFFFFFFFF);
}

bool module_is_version_newer(const nt_module_t *p, int major_version,
			   int minor_version)
{
	if (major_version == p->m_major_version)
		return p->m_minor_version >= minor_version;
	return p->m_major_version >= major_version;
}

static nt_register_t *module_lookup_register(nt_module_t *p, uint32_t id)
{
	int i;
	nt_register_t *p_register = NULL;

	for (i = 0; i < p->mn_registers; i++) {
		if (p->mpa_registers[i]->m_id == id) {
			p_register = p->mpa_registers[i];
			break;
		}
	}
	return p_register;
}

nt_register_t *module_get_register(nt_module_t *p, uint32_t id)
{
	nt_register_t *p_register;

	if (p == NULL) {
		NT_LOG(ERR, NTHW, "Illegal module context for register %d\n",
		       id);
		return NULL;
	}

	p_register = module_lookup_register(p, id);
	if (!p_register) {
		NT_LOG(ERR, NTHW, "Register %d not found in module: %s (%d)\n",
		       id, nthw_fpga_mod_id_to_str(p->m_mod_id), p->m_mod_id);
	}
	return p_register;
}

nt_register_t *module_query_register(nt_module_t *p, uint32_t id)
{
	return module_lookup_register(p, id);
}

int module_get_debug_mode(const nt_module_t *p)
{
	return p->m_debug_mode;
}

void module_set_debug_mode(nt_module_t *p, unsigned int n_debug_mode)
{
	int i;
	nt_register_t *p_register = NULL;

	p->m_debug_mode = n_debug_mode;

	for (i = 0; i < p->mn_registers; i++) {
		p_register = p->mpa_registers[i];
		if (p_register)
			register_set_debug_mode(p_register, n_debug_mode);
	}
}

int module_get_bus(const nt_module_t *p)
{
	return p->m_bus;
}

uint32_t module_get_addr_base(const nt_module_t *p)
{
	return p->m_addr_base;
}

void module_unsuppported(const nt_module_t *p)
{
	NT_LOG(ERR, NTHW, "Module %d not supported", p->mp_init->id);
}

/*
 * Register
 */
nt_register_t *register_new(void)
{
	nt_register_t *p = malloc(sizeof(nt_register_t));
	return p;
}

void register_delete(nt_register_t *p)
{
	int i;

	for (i = 0; i < p->mn_fields; i++) {
		nt_field_t *p_field = p->mpa_fields[i];

		if (p_field)
			field_delete(p_field);
	}

	if (p->mp_shadow)
		free(p->mp_shadow);

	if (p->mp_dirty)
		free(p->mp_dirty);

	memset(p, 0, sizeof(nt_register_t));
	free(p);
}

void register_init(nt_register_t *p, nt_module_t *p_module,
		   nt_fpga_register_init_t *p_init)
{
	int i;

	p->mp_owner = p_module;

	p->m_id = p_init->id;
	p->mn_bit_width = p_init->bw;
	p->mn_addr_rel = p_init->addr_rel;
	p->m_addr = p_module->m_addr_base + p_init->addr_rel;
	p->m_type = p_init->type;
	p->m_len =
		((p_init->bw != (uint16_t)-1) ?
		 ((p_init->bw + 31) >> 5) :
		 1); /* Old P200 registers have no bw at register level - default to BW=-1 */
	p->m_debug_mode = p_module->m_debug_mode;

	p->mn_fields = p_init->nb_fields;
	if (p->mn_fields) {
		p->mpa_fields = malloc(p->mn_fields * sizeof(nt_field_t *));

		if (p->mpa_fields) {
			memset(p->mpa_fields, 0,
			       (p->mn_fields * sizeof(nt_field_t *)));
			for (i = 0; i < p->mn_fields; i++) {
				nt_field_t *p_field = field_new();

				field_init(p_field, p, &p_init->fields[i]);
				p->mpa_fields[i] = p_field;
			}

			p->mp_shadow = malloc(p->m_len * sizeof(uint32_t));
			if (p->mp_shadow) {
				memset(p->mp_shadow, 0x00,
				       (p->m_len * sizeof(uint32_t)));
			}

			p->mp_dirty = malloc(p->m_len * sizeof(bool));
			if (p->mp_dirty) {
				memset(p->mp_dirty, 0x00,
				       (p->m_len * sizeof(bool)));
			}
		}
	}
}

void register_dump(const nt_register_t *p)
{
	NT_LOG(DBG, NTHW,
	       "%s(id=%d type=%d addr=0x%08X addrrel=0x%08X len=%d bw=%d\n",
	       __func__, p->m_id, p->m_type, p->m_addr, p->mn_addr_rel, p->m_len,
	       p->mn_bit_width);
	register_dump_fields(p);
}

void register_dump_fields(const nt_register_t *p)
{
	int i;

	NT_LOG(DBG, NTHW, "%s(addr=0x%08X fields=%d\n", __func__, p->m_addr,
	       p->mn_fields);
	for (i = 0; i < p->mn_fields; i++)
		field_dump(p->mpa_fields[i]);
	NT_LOG(DBG, NTHW, "\n");
}

uint32_t register_get_address(const nt_register_t *p)
{
	return p->m_addr;
}

void register_reset(const nt_register_t *p)
{
	int i;
	nt_field_t *p_field = NULL;

	for (i = 0; i < p->mn_fields; i++) {
		p_field = p->mpa_fields[i];
		if (p_field)
			field_reset(p_field);
	}
}

static nt_field_t *register_lookup_field(const nt_register_t *p, uint32_t id)
{
	int i;
	nt_field_t *p_field = NULL;

	if (!p)
		return NULL;

	for (i = 0; i < p->mn_fields; i++) {
		if (p->mpa_fields[i]->m_id == id) {
			p_field = p->mpa_fields[i];
			break;
		}
	}
	return p_field;
}

nt_field_t *register_get_field(const nt_register_t *p, uint32_t id)
{
	nt_field_t *p_field;

	if (p == NULL) {
		NT_LOG(ERR, NTHW, "Illegal register context for field %d\n",
		       id);
		return NULL;
	}

	p_field = register_lookup_field(p, id);
	if (!p_field) {
		NT_LOG(ERR, NTHW, "Field %d not found in module: %s (%d)\n", id,
		       nthw_fpga_mod_id_to_str(p->mp_owner->m_mod_id),
		       p->mp_owner->m_mod_id);
	}
	return p_field;
}

nt_field_t *register_query_field(const nt_register_t *p, uint32_t id)
{
	return register_lookup_field(p, id);
}

int register_get_bit_width(const nt_register_t *p)
{
	return p->mn_bit_width;
}

uint32_t register_get_addr_rel(const nt_register_t *p)
{
	return p->mn_addr_rel;
}

int register_get_debug_mode(const nt_module_t *p)
{
	return p->m_debug_mode;
}

/*
 * NOTE: do not set debug on fields - as register operation dumps typically are enough
 */
void register_set_debug_mode(nt_register_t *p, unsigned int n_debug_mode)
{
	int i;
	nt_field_t *p_field = NULL;

	p->m_debug_mode = n_debug_mode;

	for (i = 0; i < p->mn_fields; i++) {
		p_field = p->mpa_fields[i];
		if (p_field)
			field_set_debug_mode(p_field, n_debug_mode);
	}
}

static int register_read_data(const nt_register_t *p)
{
	int rc = -1;

	const int n_bus_type_id = module_get_bus(p->mp_owner);
	const uint32_t addr = p->m_addr;
	const uint32_t len = p->m_len;
	uint32_t *const p_data = p->mp_shadow;

	struct fpga_info_s *p_fpga_info = NULL;

	if (p && p->mp_owner && p->mp_owner->mp_owner)
		p_fpga_info = p->mp_owner->mp_owner->p_fpga_info;
	assert(p_fpga_info);
	assert(p_data);

	rc = read_data(p_fpga_info, n_bus_type_id, addr, len, p_data);
	return rc;
}

static int register_read_data_tsc(const nt_register_t *p, uint64_t *p_tsc1,
				uint64_t *p_tsc2)
{
	int rc = -1;

	const int n_bus_type_id = module_get_bus(p->mp_owner);
	const uint32_t addr = p->m_addr;
	const uint32_t len = p->m_len;
	uint32_t *const p_data = p->mp_shadow;

	struct fpga_info_s *p_fpga_info = NULL;

	if (p && p->mp_owner && p->mp_owner->mp_owner)
		p_fpga_info = p->mp_owner->mp_owner->p_fpga_info;

	rc = read_data_tsc(p_fpga_info, n_bus_type_id, addr, len, p_data, p_tsc1, p_tsc2);

	return rc;
}

static int register_write_data(const nt_register_t *p, uint32_t cnt)
{
	int rc = -1;

	const int n_bus_type_id = module_get_bus(p->mp_owner);
	const uint32_t addr = p->m_addr;
	const uint32_t len = p->m_len;
	uint32_t *const p_data = p->mp_shadow;

	struct fpga_info_s *p_fpga_info = NULL;

	if (p && p->mp_owner && p->mp_owner->mp_owner)
		p_fpga_info = p->mp_owner->mp_owner->p_fpga_info;
	assert(p_fpga_info);
	assert(p_data);

	rc = write_data(p_fpga_info, n_bus_type_id, addr, (len * cnt), p_data);

	return rc;
}

void register_get_val(const nt_register_t *p, uint32_t *p_data, uint32_t len)
{
	uint32_t i;

	if (len == (uint32_t)-1 || len > p->m_len)
		len = p->m_len;

	assert(len <= p->m_len);
	assert(p_data);

	for (i = 0; i < len; i++)
		p_data[i] = p->mp_shadow[i];
}

uint32_t register_get_val32(const nt_register_t *p)
{
	uint32_t val = 0;

	register_get_val(p, &val, 1);
	return val;
}

void register_update(const nt_register_t *p)
{
	if (p && p->m_type != REGISTER_TYPE_WO) {
		const char *const p_dev_name _unused = "NA";
		const int n_bus_type_id = module_get_bus(p->mp_owner);

		const char *const p_bus_name _unused = get_bus_name(n_bus_type_id);
		const uint32_t addr _unused = p->m_addr;
		const uint32_t len = p->m_len;
		uint32_t *const p_data = p->mp_shadow;

		register_read_data(p);
		if (p->m_debug_mode & ON_READ) {
			uint32_t i = len;

			uint32_t *ptr _unused = p_data;
			NT_LOG(DBG, NTHW,
			       "Register::read(Dev: %s, Bus: %s, Addr: 0x%08X, _cnt: %d, Data:",
			       p_dev_name, p_bus_name, addr, len);
			while (i--)
				NT_LOG(DBG, NTHW, " 0x%08X ", *ptr++);
			NT_LOG(DBG, NTHW, ")\n");
		}
	}
}

uint32_t register_get_val_updated32(const nt_register_t *p)
{
	uint32_t val = 0;

	register_update(p);
	register_get_val(p, &val, 1);
	return val;
}

void register_make_dirty(nt_register_t *p)
{
	uint32_t i;

	for (i = 0; i < p->m_len; i++)
		p->mp_dirty[i] = true;
}

void register_set_val(nt_register_t *p, const uint32_t *p_data, uint32_t len)
{
	assert(len <= p->m_len);
	assert(p_data);

	if (len == (uint32_t)-1 || len > p->m_len)
		len = p->m_len;

	if (p->mp_shadow != p_data)
		memcpy(p->mp_shadow, p_data, (len * sizeof(uint32_t)));
}

void register_set_val_flush(nt_register_t *p, const uint32_t *p_data, uint32_t len)
{
	register_set_val(p, p_data, len);
	register_flush(p, 1);
}

void register_flush(const nt_register_t *p, uint32_t cnt)
{
	int rc;

	if (p->m_type != REGISTER_TYPE_RO) {
		const char *const p_dev_name = "NA";
		const int n_bus_type_id = module_get_bus(p->mp_owner);
		const char *p_bus_name = get_bus_name(n_bus_type_id);
		const uint32_t addr = p->m_addr;
		const uint32_t len = p->m_len;
		uint32_t *const p_data = p->mp_shadow;
		uint32_t i;

		assert(len * cnt <= 256);

		if (p->m_debug_mode & ON_WRITE) {
			uint32_t i = len * cnt;
			uint32_t *ptr = p_data;
			char *tmp_string =
				ntlog_helper_str_alloc("Register::write");
			ntlog_helper_str_add(tmp_string,
					     "(Dev: %s, Bus: %s, Addr: 0x%08X, _cnt: %d, Data:",
					     p_dev_name, p_bus_name, addr, i);
			while (i--) {
				ntlog_helper_str_add(tmp_string, " 0x%08X",
						     *ptr++);
			}
			ntlog_helper_str_add(tmp_string, ")\n");
			NT_LOG(DBG, NTHW, "%s", tmp_string);
			ntlog_helper_str_free(tmp_string);
		}

		rc = register_write_data(p, cnt);

		if (rc)
			NT_LOG(ERR, NTHW, "Register write error %d\n", rc);

		for (i = 0; i < cnt; i++)
			p->mp_dirty[i] = false;
	}
}

void register_do_read_trig_ts(const nt_register_t *p, uint64_t *tsc1,
			   uint64_t *tsc2)
{
	register_read_data_tsc(p, tsc1, tsc2);
}

void register_clr(nt_register_t *p)
{
	memset(p->mp_shadow, 0, p->m_len * sizeof(uint32_t));
	register_make_dirty(p);
}

void register_set(nt_register_t *p)
{
	memset(p->mp_shadow, 0xff, p->m_len * sizeof(uint32_t));
	register_make_dirty(p);
}

/*
 * Field
 */
nt_field_t *field_new(void)
{
	nt_field_t *p = malloc(sizeof(nt_field_t));
	return p;
}

void field_delete(nt_field_t *p)
{
	memset(p, 0, sizeof(nt_field_t));
	free(p);
}

void field_init(nt_field_t *p, nt_register_t *p_reg,
		const nt_fpga_field_init_t *p_init)
{
	p->mp_owner = p_reg;

	p->m_debug_mode = p_reg->m_debug_mode;

	p->m_id = p_init->id;
	p->mn_bit_width = p_init->bw;
	p->mn_bit_pos_low = p_init->low;
	p->m_reset_val = (uint32_t)p_init->reset_val;
	p->m_first_word = p_init->low / 32;
	p->m_first_bit = p_init->low % 32;
	p->m_front_mask = 0;
	p->m_body_length = 0;
	p->mn_words = (p_init->bw + 0x1f) / 0x20;
	p->m_tail_mask = 0;

	{
		int bits_remaining = p_init->bw;
		int front_mask_length = 32 - p->m_first_bit;

		if (front_mask_length > bits_remaining)
			front_mask_length = bits_remaining;
		bits_remaining -= front_mask_length;

		p->m_front_mask = (uint32_t)(((1ULL << front_mask_length) - 1)
					   << p->m_first_bit);

		p->m_body_length = bits_remaining / 32;
		bits_remaining -= p->m_body_length * 32;
		p->m_tail_mask = (1 << bits_remaining) - 1;

		if (p->m_debug_mode >= 0x100) {
			NT_LOG(DBG, NTHW,
			       "%s: fldid=%08d: [%08d:%08d] %08d/%08d: (%08d,%08d) (0x%08X,%08d,0x%08X)\n",
			       __func__, p_init->id, p_init->low,
			       (p_init->low + p_init->bw), p_init->bw,
			       ((p_init->bw + 31) / 32), p->m_first_word,
			       p->m_first_bit, p->m_front_mask, p->m_body_length,
			       p->m_tail_mask);
		}
	}
}

int field_get_debug_mode(const nt_module_t *p)
{
	return p->m_debug_mode;
}

void field_set_debug_mode(nt_field_t *p, unsigned int n_debug_mode)
{
	p->m_debug_mode = n_debug_mode;
}

int field_get_bit_width(const nt_field_t *p)
{
	return p->mn_bit_width;
}

int field_get_bit_pos_low(const nt_field_t *p)
{
	return p->mn_bit_pos_low;
}

int field_get_bit_pos_high(const nt_field_t *p)
{
	return p->mn_bit_pos_low + p->mn_bit_width - 1;
}

uint32_t field_get_mask(const nt_field_t *p)
{
	return p->m_front_mask;
}

void field_reset(const nt_field_t *p)
{
	field_set_val32(p, (uint32_t)p->m_reset_val);
}

uint32_t field_get_val_mask(const nt_field_t *p)
{
	return (p->m_front_mask >> p->mn_bit_pos_low);
}

uint32_t field_get_reset_val(const nt_field_t *p)
{
	return (uint32_t)p->m_reset_val;
}

void field_get_val(const nt_field_t *p, uint32_t *p_data, uint32_t len)
{
	uint32_t i;
	uint32_t data_index = 0;
	uint32_t shadow_index = p->m_first_word;

	union {
		uint32_t w32[2];
		uint64_t w64;
	} buf;

	(void)len;
	assert(len == p->mn_words);

	/* handle front */
	buf.w32[0] = p->mp_owner->mp_shadow[shadow_index++] & p->m_front_mask;

	/* handle body */
	for (i = 0; i < p->m_body_length; i++) {
		buf.w32[1] = p->mp_owner->mp_shadow[shadow_index++];
		buf.w64 = buf.w64 >> (p->m_first_bit);
		assert(data_index < len);
		p_data[data_index++] = buf.w32[0];
		buf.w64 = buf.w64 >> (32 - p->m_first_bit);
	}

	/* handle tail */
	if (p->m_tail_mask)
		buf.w32[1] = p->mp_owner->mp_shadow[shadow_index++] & p->m_tail_mask;

	else
		buf.w32[1] = 0;
	buf.w64 = buf.w64 >> (p->m_first_bit);
	p_data[data_index++] = buf.w32[0];
	if (data_index < p->mn_words)
		p_data[data_index++] = buf.w32[1];
}

void field_set_val(const nt_field_t *p, const uint32_t *p_data, uint32_t len)
{
	uint32_t i;
	uint32_t data_index = 0;
	uint32_t shadow_index = p->m_first_word;

	union {
		uint32_t w32[2];
		uint64_t w64;
	} buf;

	(void)len;
	assert(len == p->mn_words);

	/* handle front */
	buf.w32[0] = 0;
	buf.w32[1] = p_data[data_index++];
	buf.w64 = buf.w64 >> (32 - p->m_first_bit);
	p->mp_owner->mp_shadow[shadow_index] =
		(p->mp_owner->mp_shadow[shadow_index] & ~p->m_front_mask) |
		(buf.w32[0] & p->m_front_mask);
	shadow_index++;

	/* handle body */
	for (i = 0; i < p->m_body_length; i++) {
		buf.w64 = buf.w64 >> (p->m_first_bit);
		assert(data_index < len);
		buf.w32[1] = p_data[data_index++];
		buf.w64 = buf.w64 >> (32 - p->m_first_bit);
		p->mp_owner->mp_shadow[shadow_index++] = buf.w32[0];
	}

	/* handle tail */
	if (p->m_tail_mask) {
		buf.w64 = buf.w64 >> (p->m_first_bit);
		if (data_index < len)
			buf.w32[1] = p_data[data_index];
		buf.w64 = buf.w64 >> (32 - p->m_first_bit);
		p->mp_owner->mp_shadow[shadow_index] =
			(p->mp_owner->mp_shadow[shadow_index] & ~p->m_tail_mask) |
			(buf.w32[0] & p->m_tail_mask);
	}

	register_make_dirty(p->mp_owner);
}

void field_set_val_flush(const nt_field_t *p, const uint32_t *p_data, uint32_t len)
{
	field_set_val(p, p_data, len);
	field_flush_register(p);
}

uint32_t field_get_val32(const nt_field_t *p)
{
	uint32_t val;

	field_get_val(p, &val, 1);
	return val;
}

uint32_t field_get_updated(const nt_field_t *p)
{
	uint32_t val;

	register_update(p->mp_owner);
	field_get_val(p, &val, 1);

	return val;
}

void field_read_trig_with_tsc(const nt_field_t *p, uint64_t *tsc1, uint64_t *tsc2)
{
	register_do_read_trig_ts(p->mp_owner, tsc1, tsc2);
}

void field_update_register(const nt_field_t *p)
{
	register_update(p->mp_owner);
}

void field_flush_register(const nt_field_t *p)
{
	register_flush(p->mp_owner, 1);
}

void field_set_val32(const nt_field_t *p, uint32_t val)
{
	field_set_val(p, &val, 1);
}

void field_set_val_flush32(const nt_field_t *p, uint32_t val)
{
	field_set_val(p, &val, 1);
	register_flush(p->mp_owner, 1);
}

void field_clr_all(const nt_field_t *p)
{
	assert(p->m_body_length == 0);
	field_set_val32(p, 0);
}

void field_clr_flush(const nt_field_t *p)
{
	field_clr_all(p);
	register_flush(p->mp_owner, 1);
}

void field_set_all(const nt_field_t *p)
{
	assert(p->m_body_length == 0);
	field_set_val32(p, ~0);
}

void field_set_flush(const nt_field_t *p)
{
	field_set_all(p);
	register_flush(p->mp_owner, 1);
}

enum field_match {
	FIELD_MATCH_CLR_ALL,
	FIELD_MATCH_SET_ALL,
	FIELD_MATCH_CLR_ANY,
	FIELD_MATCH_SET_ANY,
};

static int field_wait_cond32(const nt_field_t *p, enum field_match e_match,
			    int n_poll_iterations, int n_poll_interval)
{
	const uint32_t n_mask = (1 << p->mn_bit_width) - 1;

	if (n_poll_iterations == -1)
		n_poll_iterations = 10000;
	if (n_poll_interval == -1)
		n_poll_interval = 100; /* usec */

	if (p->m_debug_mode) {
		const char *const p_cond_name _unused =
			((e_match == FIELD_MATCH_SET_ALL) ?
			 "SetAll" :
			 ((e_match == FIELD_MATCH_CLR_ALL) ?
			  "ClrAll" :
			  ((e_match == FIELD_MATCH_CLR_ANY) ?
			   "ClrAny" :
			   "SetAny")));
		const char *const p_dev_name _unused = "NA";
		const char *const p_bus_name _unused =
			get_bus_name(module_get_bus(p->mp_owner->mp_owner));
		uint32_t n_reg_addr _unused = register_get_address(p->mp_owner);

		uint32_t n_reg_mask _unused =
			(((1 << p->mn_bit_width) - 1) << p->mn_bit_pos_low);

		NT_LOG(DBG, NTHW,
		       "Register::Field::wait%s32(Dev: %s, Bus: %s, Addr: 0x%08X, Mask: 0x%08X, Iterations: %d, Interval: %d)\n",
		       p_cond_name, p_dev_name, p_bus_name, n_reg_addr, n_reg_mask,
		       n_poll_iterations, n_poll_interval);
	}

	while (true) {
		uint32_t val = field_get_updated(p);

		if (e_match == FIELD_MATCH_SET_ANY && val != 0) {
			return 0;
		} else if (e_match == FIELD_MATCH_SET_ALL && val == n_mask) {
			return 0;
		} else if (e_match == FIELD_MATCH_CLR_ALL && val == 0) {
			return 0;
		} else if (e_match == FIELD_MATCH_CLR_ANY) {
			uint32_t mask = field_get_mask(p);

			if (val != mask)
				return 0;
		}

		n_poll_iterations--;
		if (n_poll_iterations <= 0)
			return -1;
		NT_OS_WAIT_USEC(n_poll_interval);
	}
	return 0;
}

int field_wait_set_all32(const nt_field_t *p, int n_poll_iterations,
		       int n_poll_interval)
{
	return field_wait_cond32(p, FIELD_MATCH_SET_ALL, n_poll_iterations,
				n_poll_interval);
}

int field_wait_clr_all32(const nt_field_t *p, int n_poll_iterations,
		       int n_poll_interval)
{
	return field_wait_cond32(p, FIELD_MATCH_CLR_ALL, n_poll_iterations,
				n_poll_interval);
}

int field_wait_set_any32(const nt_field_t *p, int n_poll_iterations,
		       int n_poll_interval)
{
	return field_wait_cond32(p, FIELD_MATCH_SET_ANY, n_poll_iterations,
				n_poll_interval);
}

int field_wait_clr_any32(const nt_field_t *p, int n_poll_iterations,
		       int n_poll_interval)
{
	return field_wait_cond32(p, FIELD_MATCH_CLR_ANY, n_poll_iterations,
				n_poll_interval);
}

int field_wait_val_mask32(const nt_field_t *p, uint32_t n_wait_cond_value,
			uint32_t n_wait_cond_mask, int n_poll_iterations,
			int n_poll_interval)
{
	if (n_poll_iterations == -1)
		n_poll_iterations = 10000;
	if (n_poll_interval == -1)
		n_poll_interval = 100;

	while (true) {
		uint32_t val = field_get_updated(p);

		if (val == (n_wait_cond_value & n_wait_cond_mask))
			break;
		n_poll_iterations--;
		if (n_poll_iterations <= 0)
			return -1;
		NT_OS_WAIT_USEC(n_poll_interval);
	}
	return 0;
}

void field_dump(const nt_field_t *p _unused)
{
	NT_LOG(DBG, NTHW, "%s: %02d: %02d %02d %02d: %02d: %X\n", __func__,
	       p->m_id, p->mn_bit_pos_low, (p->mn_bit_pos_low + p->mn_bit_width),
	       p->mn_bit_width, p->mn_words, p->m_reset_val);
}

void field_dump_val(const nt_field_t *p)
{
	int i;
	uint32_t buf[32];

	field_get_val(p, buf, p->mn_words);
	NT_LOG(DBG, NTHW, " @%d:", p->m_first_bit + p->m_first_word * 32);
	NT_LOG(DBG, NTHW, "%X", buf[p->mn_words - 1]);
	for (i = p->mn_words - 1; i > 0; i--)
		NT_LOG(DBG, NTHW, "%08X", buf[i - 1]);
	NT_LOG(DBG, NTHW, "\n");
}

void field_dump_init(const nt_fpga_field_init_t *p _unused)
{
	NT_LOG(DBG, NTHW, "%s: %02d: %02d %02d %02d: 0x%" PRIX64 "\n", __func__,
	       p->id, p->low, p->low + p->bw, p->bw, p->reset_val);
}

/*
 * nthw fpga model helpers
 */

nt_fpga_t *nthw_get_fpga(struct fpga_info_s *p_fpga_info, uint64_t n_fpga_ident)
{
	nt_fpga_mgr_t *p_fpga_mgr = NULL;
	nt_fpga_t *p_fpga = NULL;
	int n_fpga_type_id, n_fpga_prod_id, n_fpga_ver_id, n_fpga_rev_id;
	char s_fpga_prod_ver_rev_str[32];

	p_fpga_mgr = fpga_mgr_new();
	fpga_mgr_init(p_fpga_mgr);
	p_fpga = fpga_mgr_query_fpga(p_fpga_mgr, n_fpga_ident, p_fpga_info);

	n_fpga_type_id = FPGAID_TO_PRODUCTTYPE(n_fpga_ident);
	n_fpga_prod_id = FPGAID_TO_PRODUCTCODE(n_fpga_ident);
	n_fpga_ver_id = FPGAID_TO_VERSIONCODE(n_fpga_ident);
	n_fpga_rev_id = FPGAID_TO_REVISIONCODE(n_fpga_ident);

	snprintf(s_fpga_prod_ver_rev_str, sizeof(s_fpga_prod_ver_rev_str),
		 "%04d-%04d-%02d-%02d", n_fpga_type_id, n_fpga_prod_id, n_fpga_ver_id,
		 n_fpga_rev_id);

	if (p_fpga == NULL) {
		NT_LOG(ERR, NTHW, "%s: no match for FPGA: %s\n", __func__,
		       s_fpga_prod_ver_rev_str);
		/* do not return here... */
	}

	if (p_fpga_mgr) {
		fpga_mgr_delete(p_fpga_mgr);
		p_fpga_mgr = NULL;
	}

	return p_fpga;
}

nt_module_t *nthw_get_module(nt_fpga_t *p_fpga, int n_mod, int n_instance)
{
	nt_module_t *p_mod = fpga_query_module(p_fpga, n_mod, n_instance);
	return p_mod;
}

nt_register_t *nthw_get_register(nt_module_t *p_mod, int n_reg)
{
	nt_register_t *p_reg = module_get_register(p_mod, n_reg);
	return p_reg;
}

nt_field_t *nthw_get_field(nt_register_t *p_reg, int n_fld)
{
	nt_field_t *p_fld = register_get_field(p_reg, n_fld);
	return p_fld;
}
