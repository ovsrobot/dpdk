/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2022 Intel Corporation
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

void sff_show_value_with_unit(const uint8_t *id, unsigned int reg,
			      const char *name, unsigned int mult,
			      const char *unit, sff_item *items)
{
	unsigned int val = id[reg];
	char val_string[TMP_STRING_SIZE];

	printf("%-41s : %u%s\n", name, val * mult, unit);
	sprintf(val_string, "%u%s", val * mult, unit);
	add_item_string(items, name, val_string);
}

void sff_show_ascii(const uint8_t *id, unsigned int first_reg,
		    unsigned int last_reg, const char *name, sff_item *items)
{
	unsigned int reg, val;
	char tmp[3];
	char val_string[TMP_STRING_SIZE];

	memset(val_string, 0, sizeof(val_string));

	printf("%-41s : ", name);
	while (first_reg <= last_reg && id[last_reg] == ' ')
		last_reg--;
	for (reg = first_reg; reg <= last_reg; reg++) {
		val = id[reg];
		putchar(((val >= 32) && (val <= 126)) ? val : '_');
		if ((val >= 32) && (val <= 126)) {
			sprintf(tmp, "%c", val);
			strcat(val_string, tmp);
		} else {
			strcat(val_string, "_");
		}
	}
	printf("\n");
	add_item_string(items, name, val_string);
}

void sff_8024_show_oui(const uint8_t *id, int id_offset, sff_item *items)
{
	char val_string[TMP_STRING_SIZE];

	printf("%-41s : %02x:%02x:%02x\n", "Vendor OUI",
		      id[id_offset], id[(id_offset) + 1],
		      id[(id_offset) + 2]);
	sprintf(val_string, "%02x:%02x:%02x",
		id[id_offset], id[(id_offset) + 1], id[(id_offset) + 2]);
	add_item_string(items, "Vendor OUI", val_string);
}

void sff_8024_show_identifier(const uint8_t *id, int id_offset, sff_item *items)
{
	char val_string[TMP_STRING_SIZE];

	printf("%-41s : 0x%02x", "Identifier", id[id_offset]);
	sprintf(val_string, "0x%02x", id[id_offset]);

	switch (id[id_offset]) {
	case SFF_8024_ID_UNKNOWN:
		printf(" (no module present, unknown, or unspecified)\n");
		strcat(val_string, " (no module present, unknown, or unspecified)");
		break;
	case SFF_8024_ID_GBIC:
		printf(" (GBIC)\n");
		strcat(val_string, " (GBIC)");
		break;
	case SFF_8024_ID_SOLDERED_MODULE:
		printf(" (module soldered to motherboard)\n");
		strcat(val_string, " (module soldered to motherboard)");
		break;
	case SFF_8024_ID_SFP:
		printf(" (SFP)\n");
		strcat(val_string, " (SFP)");
		break;
	case SFF_8024_ID_300_PIN_XBI:
		printf(" (300 pin XBI)\n");
		strcat(val_string, " (300 pin XBI)");
		break;
	case SFF_8024_ID_XENPAK:
		printf(" (XENPAK)\n");
		strcat(val_string, " (XENPAK)");
		break;
	case SFF_8024_ID_XFP:
		printf(" (XFP)\n");
		strcat(val_string, " (XFP)");
		break;
	case SFF_8024_ID_XFF:
		printf(" (XFF)\n");
		strcat(val_string, " (XFF)");
		break;
	case SFF_8024_ID_XFP_E:
		printf(" (XFP-E)\n");
		strcat(val_string, " (XFP-E)");
		break;
	case SFF_8024_ID_XPAK:
		printf(" (XPAK)\n");
		strcat(val_string, " (XPAK)");
		break;
	case SFF_8024_ID_X2:
		printf(" (X2)\n");
		strcat(val_string, " (X2)");
		break;
	case SFF_8024_ID_DWDM_SFP:
		printf(" (DWDM-SFP)\n");
		strcat(val_string, " (DWDM-SFP)");
		break;
	case SFF_8024_ID_QSFP:
		printf(" (QSFP)\n");
		strcat(val_string, " (QSFP)");
		break;
	case SFF_8024_ID_QSFP_PLUS:
		printf(" (QSFP+)\n");
		strcat(val_string, " (QSFP+)");
		break;
	case SFF_8024_ID_CXP:
		printf(" (CXP)\n");
		strcat(val_string, " (CXP)");
		break;
	case SFF_8024_ID_HD4X:
		printf(" (Shielded Mini Multilane HD 4X)\n");
		strcat(val_string, " (Shielded Mini Multilane HD 4X)");
		break;
	case SFF_8024_ID_HD8X:
		printf(" (Shielded Mini Multilane HD 8X)\n");
		strcat(val_string, " (Shielded Mini Multilane HD 8X)");
		break;
	case SFF_8024_ID_QSFP28:
		printf(" (QSFP28)\n");
		strcat(val_string, " (QSFP28)");
		break;
	case SFF_8024_ID_CXP2:
		printf(" (CXP2/CXP28)\n");
		strcat(val_string, " (CXP2/CXP28)");
		break;
	case SFF_8024_ID_CDFP:
		printf(" (CDFP Style 1/Style 2)\n");
		strcat(val_string, " (CDFP Style 1/Style 2)");
		break;
	case SFF_8024_ID_HD4X_FANOUT:
		printf(" (Shielded Mini Multilane HD 4X Fanout Cable)\n");
		strcat(val_string, " (Shielded Mini Multilane HD 4X Fanout Cable)");
		break;
	case SFF_8024_ID_HD8X_FANOUT:
		printf(" (Shielded Mini Multilane HD 8X Fanout Cable)\n");
		strcat(val_string, " (Shielded Mini Multilane HD 8X Fanout Cable)");
		break;
	case SFF_8024_ID_CDFP_S3:
		printf(" (CDFP Style 3)\n");
		strcat(val_string, " (CDFP Style 3)");
		break;
	case SFF_8024_ID_MICRO_QSFP:
		printf(" (microQSFP)\n");
		strcat(val_string, " (microQSFP)");
		break;
	default:
		printf(" (reserved or unknown)\n");
		strcat(val_string, " (reserved or unknown)");
		break;
	}
	add_item_string(items, "Identifier", val_string);
}

void sff_8024_show_connector(const uint8_t *id, int ctor_offset, sff_item *items)
{
	char val_string[TMP_STRING_SIZE];

	printf("%-41s : 0x%02x", "Connector", id[ctor_offset]);
	sprintf(val_string, "0x%02x", id[ctor_offset]);

	switch (id[ctor_offset]) {
	case  SFF_8024_CTOR_UNKNOWN:
		printf(" (unknown or unspecified)\n");
		strcat(val_string, " (unknown or unspecified)");
		break;
	case SFF_8024_CTOR_SC:
		printf(" (SC)\n");
		strcat(val_string, " (SC)");
		break;
	case SFF_8024_CTOR_FC_STYLE_1:
		printf(" (Fibre Channel Style 1 copper)\n");
		strcat(val_string, " (Fibre Channel Style 1 copper)");
		break;
	case SFF_8024_CTOR_FC_STYLE_2:
		printf(" (Fibre Channel Style 2 copper)\n");
		strcat(val_string, " (Fibre Channel Style 2 copper)");
		break;
	case SFF_8024_CTOR_BNC_TNC:
		printf(" (BNC/TNC)\n");
		strcat(val_string, " (BNC/TNC)");
		break;
	case SFF_8024_CTOR_FC_COAX:
		printf(" (Fibre Channel coaxial headers)\n");
		strcat(val_string, " (Fibre Channel coaxial headers)");
		break;
	case SFF_8024_CTOR_FIBER_JACK:
		printf(" (FibreJack)\n");
		strcat(val_string, " (FibreJack)");
		break;
	case SFF_8024_CTOR_LC:
		printf(" (LC)\n");
		strcat(val_string, " (LC)");
		break;
	case SFF_8024_CTOR_MT_RJ:
		printf(" (MT-RJ)\n");
		strcat(val_string, " (MT-RJ)");
		break;
	case SFF_8024_CTOR_MU:
		printf(" (MU)\n");
		strcat(val_string, " (MU)");
		break;
	case SFF_8024_CTOR_SG:
		printf(" (SG)\n");
		strcat(val_string, " (SG)");
		break;
	case SFF_8024_CTOR_OPT_PT:
		printf(" (Optical pigtail)\n");
		strcat(val_string, " (Optical pigtail)");
		break;
	case SFF_8024_CTOR_MPO:
		printf(" (MPO Parallel Optic)\n");
		strcat(val_string, " (MPO Parallel Optic)");
		break;
	case SFF_8024_CTOR_MPO_2:
		printf(" (MPO Parallel Optic - 2x16)\n");
		strcat(val_string, " (MPO Parallel Optic - 2x16)");
		break;
	case SFF_8024_CTOR_HSDC_II:
		printf(" (HSSDC II)\n");
		strcat(val_string, " (HSSDC II)");
		break;
	case SFF_8024_CTOR_COPPER_PT:
		printf(" (Copper pigtail)\n");
		strcat(val_string, " (Copper pigtail)");
		break;
	case SFF_8024_CTOR_RJ45:
		printf(" (RJ45)\n");
		strcat(val_string, " (RJ45)");
		break;
	case SFF_8024_CTOR_NO_SEPARABLE:
		printf(" (No separable connector)\n");
		strcat(val_string, " (No separable connector)");
		break;
	case SFF_8024_CTOR_MXC_2x16:
		printf(" (MXC 2x16)\n");
		strcat(val_string, " (MXC 2x16)");
		break;
	default:
		printf(" (reserved or unknown)\n");
		strcat(val_string, " (reserved or unknown)");
		break;
	}
	add_item_string(items, "Connector", val_string);
}

void sff_8024_show_encoding(const uint8_t *id, int encoding_offset,
			    int sff_type, sff_item *items)
{
	char val_string[TMP_STRING_SIZE];

	printf("%-41s : 0x%02x", "Encoding", id[encoding_offset]);
	sprintf(val_string, "0x%02x", id[encoding_offset]);

	switch (id[encoding_offset]) {
	case SFF_8024_ENCODING_UNSPEC:
		printf(" (unspecified)\n");
		strcat(val_string, " (unspecified)");
		break;
	case SFF_8024_ENCODING_8B10B:
		printf(" (8B/10B)\n");
		strcat(val_string, " (8B/10B)");
		break;
	case SFF_8024_ENCODING_4B5B:
		printf(" (4B/5B)\n");
		strcat(val_string, " (4B/5B)");
		break;
	case SFF_8024_ENCODING_NRZ:
		printf(" (NRZ)\n");
		strcat(val_string, " (NRZ)");
		break;
	case SFF_8024_ENCODING_4h:
		if (sff_type == RTE_ETH_MODULE_SFF_8472) {
			printf(" (Manchester)\n");
			strcat(val_string, " (Manchester)");
		} else if (sff_type == RTE_ETH_MODULE_SFF_8636) {
			printf(" (SONET Scrambled)\n");
			strcat(val_string, " (SONET Scrambled)");
		}
		break;
	case SFF_8024_ENCODING_5h:
		if (sff_type == RTE_ETH_MODULE_SFF_8472) {
			printf(" (SONET Scrambled)\n");
			strcat(val_string, " (SONET Scrambled)");
		} else if (sff_type == RTE_ETH_MODULE_SFF_8636) {
			printf(" (64B/66B)\n");
			strcat(val_string, " (64B/66B)");
		}
		break;
	case SFF_8024_ENCODING_6h:
		if (sff_type == RTE_ETH_MODULE_SFF_8472) {
			printf(" (64B/66B)\n");
			strcat(val_string, " (64B/66B)");
		} else if (sff_type == RTE_ETH_MODULE_SFF_8636) {
			printf(" (Manchester)\n");
			strcat(val_string, " (Manchester)");
		}
		break;
	case SFF_8024_ENCODING_256B:
		printf(" ((256B/257B (transcoded FEC-enabled data))\n");
		strcat(val_string,
		       " ((256B/257B (transcoded FEC-enabled data))");
		break;
	case SFF_8024_ENCODING_PAM4:
		printf(" (PAM4)\n");
		strcat(val_string, " (PAM4)");
		break;
	default:
		printf(" (reserved or unknown)\n");
		strcat(val_string, " (reserved or unknown)");
		break;
	}
	add_item_string(items, "Encoding", val_string);
}

void sff_show_thresholds(struct sff_diags sd, sff_item *items)
{
	char val_string[TMP_STRING_SIZE];

	PRINT_BIAS("Laser bias current high alarm threshold", sd.bias_cur[HALRM]);
	SPRINT_BIAS(val_string, sd.bias_cur[HALRM]);
	add_item_string(items, "Laser bias current high alarm threshold", val_string);
	PRINT_BIAS("Laser bias current low alarm threshold", sd.bias_cur[LALRM]);
	SPRINT_BIAS(val_string, sd.bias_cur[LALRM]);
	add_item_string(items, "Laser bias current low alarm threshold", val_string);
	PRINT_BIAS("Laser bias current high warning threshold", sd.bias_cur[HWARN]);
	SPRINT_BIAS(val_string, sd.bias_cur[HWARN]);
	add_item_string(items, "Laser bias current high warning threshold", val_string);
	PRINT_BIAS("Laser bias current low warning threshold", sd.bias_cur[LWARN]);
	SPRINT_BIAS(val_string, sd.bias_cur[LWARN]);
	add_item_string(items, "Laser bias current low warning threshold", val_string);

	PRINT_xX_PWR("Laser output power high alarm threshold", sd.tx_power[HALRM]);
	SPRINT_xX_PWR(val_string, sd.tx_power[HALRM]);
	add_item_string(items, "Laser output power high alarm threshold", val_string);
	PRINT_xX_PWR("Laser output power low alarm threshold", sd.tx_power[LALRM]);
	SPRINT_xX_PWR(val_string, sd.tx_power[LALRM]);
	add_item_string(items, "Laser output power low alarm threshold", val_string);
	PRINT_xX_PWR("Laser output power high warning threshold", sd.tx_power[HWARN]);
	SPRINT_xX_PWR(val_string, sd.tx_power[HWARN]);
	add_item_string(items, "Laser output power high warning threshold", val_string);
	PRINT_xX_PWR("Laser output power low warning threshold", sd.tx_power[LWARN]);
	SPRINT_xX_PWR(val_string, sd.tx_power[LWARN]);
	add_item_string(items, "Laser output power low warning threshold", val_string);

	PRINT_TEMP("Module temperature high alarm threshold", sd.sfp_temp[HALRM]);
	SPRINT_TEMP(val_string, sd.sfp_temp[HALRM]);
	add_item_string(items, "Module temperature high alarm threshold", val_string);
	PRINT_TEMP("Module temperature low alarm threshold", sd.sfp_temp[LALRM]);
	SPRINT_TEMP(val_string, sd.sfp_temp[LALRM]);
	add_item_string(items, "Module temperature low alarm threshold", val_string);
	PRINT_TEMP("Module temperature high warning threshold", sd.sfp_temp[HWARN]);
	SPRINT_TEMP(val_string, sd.sfp_temp[HWARN]);
	add_item_string(items, "Module temperature high warning threshold", val_string);
	PRINT_TEMP("Module temperature low warning threshold", sd.sfp_temp[LWARN]);
	SPRINT_TEMP(val_string, sd.sfp_temp[LWARN]);
	add_item_string(items, "Module temperature low warning threshold", val_string);

	PRINT_VCC("Module voltage high alarm threshold", sd.sfp_voltage[HALRM]);
	SPRINT_VCC(val_string, sd.sfp_voltage[HALRM]);
	add_item_string(items, "Module voltage high alarm threshold", val_string);
	PRINT_VCC("Module voltage low alarm threshold", sd.sfp_voltage[LALRM]);
	SPRINT_VCC(val_string, sd.sfp_voltage[LALRM]);
	add_item_string(items, "Module voltage low alarm threshold", val_string);
	PRINT_VCC("Module voltage high warning threshold", sd.sfp_voltage[HWARN]);
	SPRINT_VCC(val_string, sd.sfp_voltage[HWARN]);
	add_item_string(items, "Module voltage high warning threshold", val_string);
	PRINT_VCC("Module voltage low warning threshold", sd.sfp_voltage[LWARN]);
	SPRINT_VCC(val_string, sd.sfp_voltage[LWARN]);
	add_item_string(items, "Module voltage low alarm threshold", val_string);

	PRINT_xX_PWR("Laser rx power high alarm threshold", sd.rx_power[HALRM]);
	SPRINT_xX_PWR(val_string, sd.rx_power[HALRM]);
	add_item_string(items, "Laser rx power high alarm threshold", val_string);
	PRINT_xX_PWR("Laser rx power low alarm threshold", sd.rx_power[LALRM]);
	SPRINT_xX_PWR(val_string, sd.rx_power[LALRM]);
	add_item_string(items, "Laser rx power low alarm threshold", val_string);
	PRINT_xX_PWR("Laser rx power high warning threshold", sd.rx_power[HWARN]);
	SPRINT_xX_PWR(val_string, sd.rx_power[HWARN]);
	add_item_string(items, "Laser rx power high warning threshold", val_string);
	PRINT_xX_PWR("Laser rx power low warning threshold", sd.rx_power[LWARN]);
	SPRINT_xX_PWR(val_string, sd.rx_power[LWARN]);
	add_item_string(items, "Laser rx power low warning threshold", val_string);
}
