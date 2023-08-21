/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_gpio_phy.h"

nthw_gpio_phy_t *nthw_gpio_phy_new(void)
{
	nthw_gpio_phy_t *p = malloc(sizeof(nthw_gpio_phy_t));

	if (p)
		memset(p, 0, sizeof(nthw_gpio_phy_t));
	return p;
}

void nthw_gpio_phy_delete(nthw_gpio_phy_t *p)
{
	if (p) {
		memset(p, 0, sizeof(nthw_gpio_phy_t));
		free(p);
	}
}

int nthw_gpio_phy_init(nthw_gpio_phy_t *p, nt_fpga_t *p_fpga, int n_instance)
{
	nt_module_t *p_mod = fpga_query_module(p_fpga, MOD_GPIO_PHY, n_instance);

	if (p == NULL)
		return (p_mod == NULL ? -1 : 0);

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: GPIO_PHY %d: no such instance\n",
		       p_fpga->p_fpga_info->mp_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mn_instance = n_instance;
	p->mp_mod_gpio_phy = p_mod;

	/* Registers */
	p->mp_reg_config = module_get_register(p->mp_mod_gpio_phy, GPIO_PHY_CFG);
	p->mp_reg_gpio = module_get_register(p->mp_mod_gpio_phy, GPIO_PHY_GPIO);

	/* PORT-0, config fields */
	p->mpa_fields[0].cfg_fld_lp_mode =
		register_get_field(p->mp_reg_config, GPIO_PHY_CFG_PORT0_LPMODE);
	p->mpa_fields[0].cfg_int =
		register_get_field(p->mp_reg_config, GPIO_PHY_CFG_PORT0_INT_B);
	p->mpa_fields[0].cfg_reset =
		register_get_field(p->mp_reg_config, GPIO_PHY_CFG_PORT0_RESET_B);
	p->mpa_fields[0].cfg_mod_prs =
		register_get_field(p->mp_reg_config, GPIO_PHY_CFG_PORT0_MODPRS_B);

	/* PORT-0, Non-mandatory fields (queryField) */
	p->mpa_fields[0].cfg_pll_int =
		register_query_field(p->mp_reg_config, GPIO_PHY_CFG_PORT0_PLL_INTR);
	p->mpa_fields[0].cfg_port_rxlos =
		register_query_field(p->mp_reg_config, GPIO_PHY_CFG_E_PORT0_RXLOS);

	/* PORT-1, config fields */
	p->mpa_fields[1].cfg_fld_lp_mode =
		register_get_field(p->mp_reg_config, GPIO_PHY_CFG_PORT1_LPMODE);
	p->mpa_fields[1].cfg_int =
		register_get_field(p->mp_reg_config, GPIO_PHY_CFG_PORT1_INT_B);
	p->mpa_fields[1].cfg_reset =
		register_get_field(p->mp_reg_config, GPIO_PHY_CFG_PORT1_RESET_B);
	p->mpa_fields[1].cfg_mod_prs =
		register_get_field(p->mp_reg_config, GPIO_PHY_CFG_PORT1_MODPRS_B);

	/* PORT-1, Non-mandatory fields (queryField) */
	p->mpa_fields[1].cfg_pll_int =
		register_query_field(p->mp_reg_config, GPIO_PHY_CFG_PORT1_PLL_INTR);
	p->mpa_fields[1].cfg_port_rxlos =
		register_query_field(p->mp_reg_config, GPIO_PHY_CFG_E_PORT1_RXLOS);

	/* PORT-0, gpio fields */
	p->mpa_fields[0].gpio_fld_lp_mode =
		register_get_field(p->mp_reg_gpio, GPIO_PHY_GPIO_PORT0_LPMODE);
	p->mpa_fields[0].gpio_int =
		register_get_field(p->mp_reg_gpio, GPIO_PHY_GPIO_PORT0_INT_B);
	p->mpa_fields[0].gpio_reset =
		register_get_field(p->mp_reg_gpio, GPIO_PHY_GPIO_PORT0_RESET_B);
	p->mpa_fields[0].gpio_mod_prs =
		register_get_field(p->mp_reg_gpio, GPIO_PHY_GPIO_PORT0_MODPRS_B);

	/* PORT-0, Non-mandatory fields (queryField) */
	p->mpa_fields[0].gpio_pll_int =
		register_query_field(p->mp_reg_gpio, GPIO_PHY_GPIO_PORT0_PLL_INTR);
	p->mpa_fields[0].gpio_port_rxlos =
		register_query_field(p->mp_reg_gpio, GPIO_PHY_GPIO_E_PORT0_RXLOS);

	/* PORT-1, gpio fields */
	p->mpa_fields[1].gpio_fld_lp_mode =
		register_get_field(p->mp_reg_gpio, GPIO_PHY_GPIO_PORT1_LPMODE);
	p->mpa_fields[1].gpio_int =
		register_get_field(p->mp_reg_gpio, GPIO_PHY_GPIO_PORT1_INT_B);
	p->mpa_fields[1].gpio_reset =
		register_get_field(p->mp_reg_gpio, GPIO_PHY_GPIO_PORT1_RESET_B);
	p->mpa_fields[1].gpio_mod_prs =
		register_get_field(p->mp_reg_gpio, GPIO_PHY_GPIO_PORT1_MODPRS_B);

	/* PORT-1, Non-mandatory fields (queryField) */
	p->mpa_fields[1].gpio_pll_int =
		register_query_field(p->mp_reg_gpio, GPIO_PHY_GPIO_PORT1_PLL_INTR);
	p->mpa_fields[1].gpio_port_rxlos =
		register_query_field(p->mp_reg_gpio, GPIO_PHY_GPIO_E_PORT1_RXLOS);

	register_update(p->mp_reg_config);

	return 0;
}

bool nthw_gpio_phy_is_low_power_enabled(nthw_gpio_phy_t *p, uint8_t if_no)
{
	if (if_no >= ARRAY_SIZE(p->mpa_fields)) {
		assert(false);
		return false;
	}

	if (field_get_updated(p->mpa_fields[if_no].gpio_fld_lp_mode))
		return true;

	else
		return false;
}

bool nthw_gpio_phy_is_interrupt_set(nthw_gpio_phy_t *p, uint8_t if_no)
{
	if (if_no >= ARRAY_SIZE(p->mpa_fields)) {
		assert(false);
		return false;
	}

	/* NOTE: This is a negated GPIO PIN "INT_B" */
	if (field_get_updated(p->mpa_fields[if_no].gpio_int))
		return false;

	else
		return true;
}

bool nthw_gpio_phy_is_reset(nthw_gpio_phy_t *p, uint8_t if_no)
{
	if (if_no >= ARRAY_SIZE(p->mpa_fields)) {
		assert(false);
		return false;
	}

	/* NOTE: This is a negated GPIO PIN "RESET_B" */
	if (field_get_updated(p->mpa_fields[if_no].gpio_reset))
		return false;

	else
		return true;
}

bool nthw_gpio_phy_is_module_present(nthw_gpio_phy_t *p, uint8_t if_no)
{
	if (if_no >= ARRAY_SIZE(p->mpa_fields)) {
		assert(false);
		return false;
	}

	/* NOTE: This is a negated GPIO PIN "MODPRS_B" */
	return field_get_updated(p->mpa_fields[if_no].gpio_mod_prs) == 0U ? true :
	       false;
}

bool nthw_gpio_phy_is_pll_interrupt_set(nthw_gpio_phy_t *p, uint8_t if_no)
{
	if (if_no >= ARRAY_SIZE(p->mpa_fields)) {
		assert(false);
		return false;
	}

	/* NOTE: This is a normal GPIO PIN "PLL_INTR" */
	if (p->mpa_fields[if_no].gpio_pll_int) {
		if (field_get_updated(p->mpa_fields[if_no].gpio_pll_int))
			return true;

		else
			return false;
	} else {
		/* this HW doesn't support "PLL_INTR" (INTR from SyncE jitter attenuater) */
		return false;
	}
}

bool nthw_gpio_phy_is_port_rxlos(nthw_gpio_phy_t *p, uint8_t if_no)
{
	if (if_no >= ARRAY_SIZE(p->mpa_fields)) {
		assert(false);
		return false;
	}

	if (p->mpa_fields[if_no].gpio_port_rxlos) {
		if (field_get_updated(p->mpa_fields[if_no].gpio_port_rxlos))
			return true;
		else
			return false;
	} else {
		return false;
	}
}

void nthw_gpio_phy_set_low_power(nthw_gpio_phy_t *p, uint8_t if_no, bool enable)
{
	if (if_no >= ARRAY_SIZE(p->mpa_fields)) {
		assert(false);
		return;
	}

	if (enable)
		field_set_flush(p->mpa_fields[if_no].gpio_fld_lp_mode);

	else
		field_clr_flush(p->mpa_fields[if_no].gpio_fld_lp_mode);
	field_clr_flush(p->mpa_fields[if_no].cfg_fld_lp_mode); /* enable output */
}

void nthw_gpio_phy_set_reset(nthw_gpio_phy_t *p, uint8_t if_no, bool enable)
{
	if (if_no >= ARRAY_SIZE(p->mpa_fields)) {
		assert(false);
		return;
	}

	if (enable)
		field_clr_flush(p->mpa_fields[if_no].gpio_reset);

	else
		field_set_flush(p->mpa_fields[if_no].gpio_reset);
	field_clr_flush(p->mpa_fields[if_no].cfg_reset); /* enable output */
}

void nthw_gpio_phy_set_port_rxlos(nthw_gpio_phy_t *p, uint8_t if_no, bool enable)
{
	if (if_no >= ARRAY_SIZE(p->mpa_fields)) {
		assert(false);
		return;
	}

	if (p->mpa_fields[if_no].gpio_port_rxlos) {
		if (enable)
			field_set_flush(p->mpa_fields[if_no].gpio_port_rxlos);

		else
			field_clr_flush(p->mpa_fields[if_no].gpio_port_rxlos);
	}
}

void nthw_gpio_phy_set_cfg_default_values(nthw_gpio_phy_t *p, uint8_t if_no)
{
	if (if_no >= ARRAY_SIZE(p->mpa_fields)) {
		assert(false);
		return;
	}

	field_set_flush(p->mpa_fields[if_no].cfg_fld_lp_mode); /* enable input */
	field_set_flush(p->mpa_fields[if_no].cfg_int); /* enable input */
	field_set_flush(p->mpa_fields[if_no].cfg_reset); /* enable input */
	field_set_flush(p->mpa_fields[if_no].cfg_mod_prs); /* enable input */
	if (p->mpa_fields[if_no].cfg_port_rxlos)
		field_clr_flush(p->mpa_fields[if_no].cfg_port_rxlos); /* enable output */
}
