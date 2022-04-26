/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 *
 * Implements SFF-8024 Rev 4.0 of pluggable I/O configuration and some
 * common utilities for SFF-8436/8636 and SFF-8472/8079
 *
 */

#include <stdio.h>
#include <math.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include "sff_common.h"
#include "ethdev_sff_telemetry.h"


double convert_mw_to_dbm(double mw)
{
	return (10. * log10(mw / 1000.)) + 30.;
}

void sff_show_value_with_unit(const uint8_t *data, unsigned int reg,
			      const char *name, unsigned int mult,
			      const char *unit, struct sff_item *items)
{
	unsigned int val = data[reg];
	char val_string[SFF_ITEM_VAL_COMPOSE_SIZE];

	snprintf(val_string, sizeof(val_string), "%u%s", val * mult, unit);
	add_item_string(items, name, val_string);
}

void sff_show_ascii(const uint8_t *data, unsigned int first_reg,
		    unsigned int last_reg, const char *name, struct sff_item *items)
{
	unsigned int reg, val;
	char tmp[3];
	char val_string[SFF_ITEM_VAL_COMPOSE_SIZE];

	memset(val_string, 0, sizeof(val_string));

	while (first_reg <= last_reg && data[last_reg] == ' ')
		last_reg--;
	for (reg = first_reg; reg <= last_reg; reg++) {
		val = data[reg];
		if ((val >= 32) && (val <= 126)) {
			snprintf(tmp, sizeof(tmp), "%c", val);
			strlcat(val_string, tmp, sizeof(val_string));
		} else {
			strlcat(val_string, "_", sizeof(val_string));
		}
	}
	add_item_string(items, name, val_string);
}

void sff_8024_show_oui(const uint8_t *data, int id_offset, struct sff_item *items)
{
	char val_string[SFF_ITEM_VAL_COMPOSE_SIZE];

	snprintf(val_string, sizeof(val_string), "%02x:%02x:%02x",
		data[id_offset], data[(id_offset) + 1], data[(id_offset) + 2]);
	add_item_string(items, "Vendor OUI", val_string);
}

void sff_8024_show_identifier(const uint8_t *data, int id_offset, struct sff_item *items)
{
	char val_string[SFF_ITEM_VAL_COMPOSE_SIZE];

	snprintf(val_string, sizeof(val_string), "0x%02x", data[id_offset]);

	switch (data[id_offset]) {
	case SFF_8024_ID_UNKNOWN:
		strlcat(val_string, " (no module present, unknown, or unspecified)",
			sizeof(val_string));
		break;
	case SFF_8024_ID_GBIC:
		strlcat(val_string, " (GBIC)", sizeof(val_string));
		break;
	case SFF_8024_ID_SOLDERED_MODULE:
		strlcat(val_string, " (module soldered to motherboard)", sizeof(val_string));
		break;
	case SFF_8024_ID_SFP:
		strlcat(val_string, " (SFP)", sizeof(val_string));
		break;
	case SFF_8024_ID_300_PIN_XBI:
		strlcat(val_string, " (300 pin XBI)", sizeof(val_string));
		break;
	case SFF_8024_ID_XENPAK:
		strlcat(val_string, " (XENPAK)", sizeof(val_string));
		break;
	case SFF_8024_ID_XFP:
		strlcat(val_string, " (XFP)", sizeof(val_string));
		break;
	case SFF_8024_ID_XFF:
		strlcat(val_string, " (XFF)", sizeof(val_string));
		break;
	case SFF_8024_ID_XFP_E:
		strlcat(val_string, " (XFP-E)", sizeof(val_string));
		break;
	case SFF_8024_ID_XPAK:
		strlcat(val_string, " (XPAK)", sizeof(val_string));
		break;
	case SFF_8024_ID_X2:
		strlcat(val_string, " (X2)", sizeof(val_string));
		break;
	case SFF_8024_ID_DWDM_SFP:
		strlcat(val_string, " (DWDM-SFP)", sizeof(val_string));
		break;
	case SFF_8024_ID_QSFP:
		strlcat(val_string, " (QSFP)", sizeof(val_string));
		break;
	case SFF_8024_ID_QSFP_PLUS:
		strlcat(val_string, " (QSFP+)", sizeof(val_string));
		break;
	case SFF_8024_ID_CXP:
		strlcat(val_string, " (CXP)", sizeof(val_string));
		break;
	case SFF_8024_ID_HD4X:
		strlcat(val_string, " (Shielded Mini Multilane HD 4X)", sizeof(val_string));
		break;
	case SFF_8024_ID_HD8X:
		strlcat(val_string, " (Shielded Mini Multilane HD 8X)", sizeof(val_string));
		break;
	case SFF_8024_ID_QSFP28:
		strlcat(val_string, " (QSFP28)", sizeof(val_string));
		break;
	case SFF_8024_ID_CXP2:
		strlcat(val_string, " (CXP2/CXP28)", sizeof(val_string));
		break;
	case SFF_8024_ID_CDFP:
		strlcat(val_string, " (CDFP Style 1/Style 2)", sizeof(val_string));
		break;
	case SFF_8024_ID_HD4X_FANOUT:
		strlcat(val_string, " (Shielded Mini Multilane HD 4X Fanout Cable)",
			sizeof(val_string));
		break;
	case SFF_8024_ID_HD8X_FANOUT:
		strlcat(val_string, " (Shielded Mini Multilane HD 8X Fanout Cable)",
			sizeof(val_string));
		break;
	case SFF_8024_ID_CDFP_S3:
		strlcat(val_string, " (CDFP Style 3)", sizeof(val_string));
		break;
	case SFF_8024_ID_MICRO_QSFP:
		strlcat(val_string, " (microQSFP)", sizeof(val_string));
		break;
	default:
		strlcat(val_string, " (reserved or unknown)", sizeof(val_string));
		break;
	}
	add_item_string(items, "Identifier", val_string);
}

void sff_8024_show_connector(const uint8_t *data, int ctor_offset, struct sff_item *items)
{
	char val_string[SFF_ITEM_VAL_COMPOSE_SIZE];

	snprintf(val_string, sizeof(val_string), "0x%02x", data[ctor_offset]);

	switch (data[ctor_offset]) {
	case  SFF_8024_CTOR_UNKNOWN:
		strlcat(val_string, " (unknown or unspecified)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_SC:
		strlcat(val_string, " (SC)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_FC_STYLE_1:
		strlcat(val_string, " (Fibre Channel Style 1 copper)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_FC_STYLE_2:
		strlcat(val_string, " (Fibre Channel Style 2 copper)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_BNC_TNC:
		strlcat(val_string, " (BNC/TNC)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_FC_COAX:
		strlcat(val_string, " (Fibre Channel coaxial headers)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_FIBER_JACK:
		strlcat(val_string, " (FibreJack)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_LC:
		strlcat(val_string, " (LC)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_MT_RJ:
		strlcat(val_string, " (MT-RJ)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_MU:
		strlcat(val_string, " (MU)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_SG:
		strlcat(val_string, " (SG)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_OPT_PT:
		strlcat(val_string, " (Optical pigtail)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_MPO:
		strlcat(val_string, " (MPO Parallel Optic)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_MPO_2:
		strlcat(val_string, " (MPO Parallel Optic - 2x16)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_HSDC_II:
		strlcat(val_string, " (HSSDC II)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_COPPER_PT:
		strlcat(val_string, " (Copper pigtail)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_RJ45:
		strlcat(val_string, " (RJ45)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_NO_SEPARABLE:
		strlcat(val_string, " (No separable connector)", sizeof(val_string));
		break;
	case SFF_8024_CTOR_MXC_2x16:
		strlcat(val_string, " (MXC 2x16)", sizeof(val_string));
		break;
	default:
		strlcat(val_string, " (reserved or unknown)", sizeof(val_string));
		break;
	}
	add_item_string(items, "Connector", val_string);
}

void sff_8024_show_encoding(const uint8_t *data, int encoding_offset,
			    int sff_type, struct sff_item *items)
{
	char val_string[SFF_ITEM_VAL_COMPOSE_SIZE];

	snprintf(val_string, sizeof(val_string), "0x%02x", data[encoding_offset]);

	switch (data[encoding_offset]) {
	case SFF_8024_ENCODING_UNSPEC:
		strlcat(val_string, " (unspecified)", sizeof(val_string));
		break;
	case SFF_8024_ENCODING_8B10B:
		strlcat(val_string, " (8B/10B)", sizeof(val_string));
		break;
	case SFF_8024_ENCODING_4B5B:
		strlcat(val_string, " (4B/5B)", sizeof(val_string));
		break;
	case SFF_8024_ENCODING_NRZ:
		strlcat(val_string, " (NRZ)", sizeof(val_string));
		break;
	case SFF_8024_ENCODING_4h:
		if (sff_type == RTE_ETH_MODULE_SFF_8472)
			strlcat(val_string, " (Manchester)", sizeof(val_string));
		else if (sff_type == RTE_ETH_MODULE_SFF_8636)
			strlcat(val_string, " (SONET Scrambled)", sizeof(val_string));
		break;
	case SFF_8024_ENCODING_5h:
		if (sff_type == RTE_ETH_MODULE_SFF_8472)
			strlcat(val_string, " (SONET Scrambled)", sizeof(val_string));
		else if (sff_type == RTE_ETH_MODULE_SFF_8636)
			strlcat(val_string, " (64B/66B)", sizeof(val_string));
		break;
	case SFF_8024_ENCODING_6h:
		if (sff_type == RTE_ETH_MODULE_SFF_8472)
			strlcat(val_string, " (64B/66B)", sizeof(val_string));
		else if (sff_type == RTE_ETH_MODULE_SFF_8636)
			strlcat(val_string, " (Manchester)", sizeof(val_string));
		break;
	case SFF_8024_ENCODING_256B:
		strlcat(val_string,
		       " ((256B/257B (transcoded FEC-enabled data))", sizeof(val_string));
		break;
	case SFF_8024_ENCODING_PAM4:
		strlcat(val_string, " (PAM4)", sizeof(val_string));
		break;
	default:
		strlcat(val_string, " (reserved or unknown)", sizeof(val_string));
		break;
	}
	add_item_string(items, "Encoding", val_string);
}

void sff_show_thresholds(struct sff_diags sd, struct sff_item *items)
{
	char val_string[SFF_ITEM_VAL_COMPOSE_SIZE];

	SPRINT_BIAS(val_string, sd.bias_cur[HALRM]);
	add_item_string(items, "Laser bias current high alarm threshold", val_string);
	SPRINT_BIAS(val_string, sd.bias_cur[LALRM]);
	add_item_string(items, "Laser bias current low alarm threshold", val_string);
	SPRINT_BIAS(val_string, sd.bias_cur[HWARN]);
	add_item_string(items, "Laser bias current high warning threshold", val_string);
	SPRINT_BIAS(val_string, sd.bias_cur[LWARN]);
	add_item_string(items, "Laser bias current low warning threshold", val_string);

	SPRINT_xX_PWR(val_string, sd.tx_power[HALRM]);
	add_item_string(items, "Laser output power high alarm threshold", val_string);
	SPRINT_xX_PWR(val_string, sd.tx_power[LALRM]);
	add_item_string(items, "Laser output power low alarm threshold", val_string);
	SPRINT_xX_PWR(val_string, sd.tx_power[HWARN]);
	add_item_string(items, "Laser output power high warning threshold", val_string);
	SPRINT_xX_PWR(val_string, sd.tx_power[LWARN]);
	add_item_string(items, "Laser output power low warning threshold", val_string);

	SPRINT_TEMP(val_string, sd.sfp_temp[HALRM]);
	add_item_string(items, "Module temperature high alarm threshold", val_string);
	SPRINT_TEMP(val_string, sd.sfp_temp[LALRM]);
	add_item_string(items, "Module temperature low alarm threshold", val_string);
	SPRINT_TEMP(val_string, sd.sfp_temp[HWARN]);
	add_item_string(items, "Module temperature high warning threshold", val_string);
	SPRINT_TEMP(val_string, sd.sfp_temp[LWARN]);
	add_item_string(items, "Module temperature low warning threshold", val_string);

	SPRINT_VCC(val_string, sd.sfp_voltage[HALRM]);
	add_item_string(items, "Module voltage high alarm threshold", val_string);
	SPRINT_VCC(val_string, sd.sfp_voltage[LALRM]);
	add_item_string(items, "Module voltage low alarm threshold", val_string);
	SPRINT_VCC(val_string, sd.sfp_voltage[HWARN]);
	add_item_string(items, "Module voltage high warning threshold", val_string);
	SPRINT_VCC(val_string, sd.sfp_voltage[LWARN]);
	add_item_string(items, "Module voltage low alarm threshold", val_string);

	SPRINT_xX_PWR(val_string, sd.rx_power[HALRM]);
	add_item_string(items, "Laser rx power high alarm threshold", val_string);
	SPRINT_xX_PWR(val_string, sd.rx_power[LALRM]);
	add_item_string(items, "Laser rx power low alarm threshold", val_string);
	SPRINT_xX_PWR(val_string, sd.rx_power[HWARN]);
	add_item_string(items, "Laser rx power high warning threshold", val_string);
	SPRINT_xX_PWR(val_string, sd.rx_power[LWARN]);
	add_item_string(items, "Laser rx power low warning threshold", val_string);
}
