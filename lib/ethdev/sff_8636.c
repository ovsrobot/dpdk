/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2022 Intel Corporation
 *
 * Implements SFF-8636 based QSFP+/QSFP28 Diagnostics Memory map.
 *
 */

#include <stdio.h>
#include <math.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include "sff_common.h"
#include "sff_8636.h"
#include "ethdev_sff_telemetry.h"

#define MAX_DESC_SIZE	42

static struct sff_8636_aw_flags {
	const char *str;        /* Human-readable string, null at the end */
	int offset;             /* A2-relative address offset */
	uint8_t value;             /* Alarm is on if (offset & value) != 0. */
} sff_8636_aw_flags[] = {
	{ "Laser bias current high alarm   (Chan 1)",
		SFF_8636_TX_BIAS_12_AW_OFFSET, (SFF_8636_TX_BIAS_1_HALARM) },
	{ "Laser bias current low alarm    (Chan 1)",
		SFF_8636_TX_BIAS_12_AW_OFFSET, (SFF_8636_TX_BIAS_1_LALARM) },
	{ "Laser bias current high warning (Chan 1)",
		SFF_8636_TX_BIAS_12_AW_OFFSET, (SFF_8636_TX_BIAS_1_HWARN) },
	{ "Laser bias current low warning  (Chan 1)",
		SFF_8636_TX_BIAS_12_AW_OFFSET, (SFF_8636_TX_BIAS_1_LWARN) },

	{ "Laser bias current high alarm   (Chan 2)",
		SFF_8636_TX_BIAS_12_AW_OFFSET, (SFF_8636_TX_BIAS_2_HALARM) },
	{ "Laser bias current low alarm    (Chan 2)",
		SFF_8636_TX_BIAS_12_AW_OFFSET, (SFF_8636_TX_BIAS_2_LALARM) },
	{ "Laser bias current high warning (Chan 2)",
		SFF_8636_TX_BIAS_12_AW_OFFSET, (SFF_8636_TX_BIAS_2_HWARN) },
	{ "Laser bias current low warning  (Chan 2)",
		SFF_8636_TX_BIAS_12_AW_OFFSET, (SFF_8636_TX_BIAS_2_LWARN) },

	{ "Laser bias current high alarm   (Chan 3)",
		SFF_8636_TX_BIAS_34_AW_OFFSET, (SFF_8636_TX_BIAS_3_HALARM) },
	{ "Laser bias current low alarm    (Chan 3)",
		SFF_8636_TX_BIAS_34_AW_OFFSET, (SFF_8636_TX_BIAS_3_LALARM) },
	{ "Laser bias current high warning (Chan 3)",
		SFF_8636_TX_BIAS_34_AW_OFFSET, (SFF_8636_TX_BIAS_3_HWARN) },
	{ "Laser bias current low warning  (Chan 3)",
		SFF_8636_TX_BIAS_34_AW_OFFSET, (SFF_8636_TX_BIAS_3_LWARN) },

	{ "Laser bias current high alarm   (Chan 4)",
		SFF_8636_TX_BIAS_34_AW_OFFSET, (SFF_8636_TX_BIAS_4_HALARM) },
	{ "Laser bias current low alarm    (Chan 4)",
		SFF_8636_TX_BIAS_34_AW_OFFSET, (SFF_8636_TX_BIAS_4_LALARM) },
	{ "Laser bias current high warning (Chan 4)",
		SFF_8636_TX_BIAS_34_AW_OFFSET, (SFF_8636_TX_BIAS_4_HWARN) },
	{ "Laser bias current low warning  (Chan 4)",
		SFF_8636_TX_BIAS_34_AW_OFFSET, (SFF_8636_TX_BIAS_4_LWARN) },

	{ "Module temperature high alarm",
		SFF_8636_TEMP_AW_OFFSET, (SFF_8636_TEMP_HALARM_STATUS) },
	{ "Module temperature low alarm",
		SFF_8636_TEMP_AW_OFFSET, (SFF_8636_TEMP_LALARM_STATUS) },
	{ "Module temperature high warning",
		SFF_8636_TEMP_AW_OFFSET, (SFF_8636_TEMP_HWARN_STATUS) },
	{ "Module temperature low warning",
		SFF_8636_TEMP_AW_OFFSET, (SFF_8636_TEMP_LWARN_STATUS) },

	{ "Module voltage high alarm",
		SFF_8636_VCC_AW_OFFSET, (SFF_8636_VCC_HALARM_STATUS) },
	{ "Module voltage low alarm",
		SFF_8636_VCC_AW_OFFSET, (SFF_8636_VCC_LALARM_STATUS) },
	{ "Module voltage high warning",
		SFF_8636_VCC_AW_OFFSET, (SFF_8636_VCC_HWARN_STATUS) },
	{ "Module voltage low warning",
		SFF_8636_VCC_AW_OFFSET, (SFF_8636_VCC_LWARN_STATUS) },

	{ "Laser tx power high alarm   (Channel 1)",
		SFF_8636_TX_PWR_12_AW_OFFSET, (SFF_8636_TX_PWR_1_HALARM) },
	{ "Laser tx power low alarm    (Channel 1)",
		SFF_8636_TX_PWR_12_AW_OFFSET, (SFF_8636_TX_PWR_1_LALARM) },
	{ "Laser tx power high warning (Channel 1)",
		SFF_8636_TX_PWR_12_AW_OFFSET, (SFF_8636_TX_PWR_1_HWARN) },
	{ "Laser tx power low warning  (Channel 1)",
		SFF_8636_TX_PWR_12_AW_OFFSET, (SFF_8636_TX_PWR_1_LWARN) },

	{ "Laser tx power high alarm   (Channel 2)",
		SFF_8636_TX_PWR_12_AW_OFFSET, (SFF_8636_TX_PWR_2_HALARM) },
	{ "Laser tx power low alarm    (Channel 2)",
		SFF_8636_TX_PWR_12_AW_OFFSET, (SFF_8636_TX_PWR_2_LALARM) },
	{ "Laser tx power high warning (Channel 2)",
		SFF_8636_TX_PWR_12_AW_OFFSET, (SFF_8636_TX_PWR_2_HWARN) },
	{ "Laser tx power low warning  (Channel 2)",
		SFF_8636_TX_PWR_12_AW_OFFSET, (SFF_8636_TX_PWR_2_LWARN) },

	{ "Laser tx power high alarm   (Channel 3)",
		SFF_8636_TX_PWR_34_AW_OFFSET, (SFF_8636_TX_PWR_3_HALARM) },
	{ "Laser tx power low alarm    (Channel 3)",
		SFF_8636_TX_PWR_34_AW_OFFSET, (SFF_8636_TX_PWR_3_LALARM) },
	{ "Laser tx power high warning (Channel 3)",
		SFF_8636_TX_PWR_34_AW_OFFSET, (SFF_8636_TX_PWR_3_HWARN) },
	{ "Laser tx power low warning  (Channel 3)",
		SFF_8636_TX_PWR_34_AW_OFFSET, (SFF_8636_TX_PWR_3_LWARN) },

	{ "Laser tx power high alarm   (Channel 4)",
		SFF_8636_TX_PWR_34_AW_OFFSET, (SFF_8636_TX_PWR_4_HALARM) },
	{ "Laser tx power low alarm    (Channel 4)",
		SFF_8636_TX_PWR_34_AW_OFFSET, (SFF_8636_TX_PWR_4_LALARM) },
	{ "Laser tx power high warning (Channel 4)",
		SFF_8636_TX_PWR_34_AW_OFFSET, (SFF_8636_TX_PWR_4_HWARN) },
	{ "Laser tx power low warning  (Channel 4)",
		SFF_8636_TX_PWR_34_AW_OFFSET, (SFF_8636_TX_PWR_4_LWARN) },

	{ "Laser rx power high alarm   (Channel 1)",
		SFF_8636_RX_PWR_12_AW_OFFSET, (SFF_8636_RX_PWR_1_HALARM) },
	{ "Laser rx power low alarm    (Channel 1)",
		SFF_8636_RX_PWR_12_AW_OFFSET, (SFF_8636_RX_PWR_1_LALARM) },
	{ "Laser rx power high warning (Channel 1)",
		SFF_8636_RX_PWR_12_AW_OFFSET, (SFF_8636_RX_PWR_1_HWARN) },
	{ "Laser rx power low warning  (Channel 1)",
		SFF_8636_RX_PWR_12_AW_OFFSET, (SFF_8636_RX_PWR_1_LWARN) },

	{ "Laser rx power high alarm   (Channel 2)",
		SFF_8636_RX_PWR_12_AW_OFFSET, (SFF_8636_RX_PWR_2_HALARM) },
	{ "Laser rx power low alarm    (Channel 2)",
		SFF_8636_RX_PWR_12_AW_OFFSET, (SFF_8636_RX_PWR_2_LALARM) },
	{ "Laser rx power high warning (Channel 2)",
		SFF_8636_RX_PWR_12_AW_OFFSET, (SFF_8636_RX_PWR_2_HWARN) },
	{ "Laser rx power low warning  (Channel 2)",
		SFF_8636_RX_PWR_12_AW_OFFSET, (SFF_8636_RX_PWR_2_LWARN) },

	{ "Laser rx power high alarm   (Channel 3)",
		SFF_8636_RX_PWR_34_AW_OFFSET, (SFF_8636_RX_PWR_3_HALARM) },
	{ "Laser rx power low alarm    (Channel 3)",
		SFF_8636_RX_PWR_34_AW_OFFSET, (SFF_8636_RX_PWR_3_LALARM) },
	{ "Laser rx power high warning (Channel 3)",
		SFF_8636_RX_PWR_34_AW_OFFSET, (SFF_8636_RX_PWR_3_HWARN) },
	{ "Laser rx power low warning  (Channel 3)",
		SFF_8636_RX_PWR_34_AW_OFFSET, (SFF_8636_RX_PWR_3_LWARN) },

	{ "Laser rx power high alarm   (Channel 4)",
		SFF_8636_RX_PWR_34_AW_OFFSET, (SFF_8636_RX_PWR_4_HALARM) },
	{ "Laser rx power low alarm    (Channel 4)",
		SFF_8636_RX_PWR_34_AW_OFFSET, (SFF_8636_RX_PWR_4_LALARM) },
	{ "Laser rx power high warning (Channel 4)",
		SFF_8636_RX_PWR_34_AW_OFFSET, (SFF_8636_RX_PWR_4_HWARN) },
	{ "Laser rx power low warning  (Channel 4)",
		SFF_8636_RX_PWR_34_AW_OFFSET, (SFF_8636_RX_PWR_4_LWARN) },

	{ NULL, 0, 0 },
};

static void sff_8636_show_identifier(const uint8_t *id, sff_item *items)
{
	sff_8024_show_identifier(id, SFF_8636_ID_OFFSET, items);
}

static void sff_8636_show_ext_identifier(const uint8_t *id, sff_item *items)
{
	char val_string[TMP_STRING_SIZE];
	printf("%-41s : 0x%02x\n", "Extended identifier",
			id[SFF_8636_EXT_ID_OFFSET]);
	sprintf(val_string, "0x%02x", id[SFF_8636_EXT_ID_OFFSET]);
	add_item_string(items, "Extended identifier", val_string);

	static const char *pfx =
		"Extended identifier description           :";

	switch (id[SFF_8636_EXT_ID_OFFSET] & SFF_8636_EXT_ID_PWR_CLASS_MASK) {
	case SFF_8636_EXT_ID_PWR_CLASS_1:
		printf("%s 1.5W max. Power consumption\n", pfx);
		add_item_string(items, "Extended identifier description",
				"1.5W max. Power consumption");
		break;
	case SFF_8636_EXT_ID_PWR_CLASS_2:
		printf("%s 2.0W max. Power consumption\n", pfx);
		add_item_string(items, "Extended identifier description",
				"2.0W max. Power consumption");
		break;
	case SFF_8636_EXT_ID_PWR_CLASS_3:
		printf("%s 2.5W max. Power consumption\n", pfx);
		add_item_string(items, "Extended identifier description",
				"2.5W max. Power consumption");
		break;
	case SFF_8636_EXT_ID_PWR_CLASS_4:
		printf("%s 3.5W max. Power consumption\n", pfx);
		add_item_string(items, "Extended identifier description",
				"3.5W max. Power consumption");
		break;
	}

	if (id[SFF_8636_EXT_ID_OFFSET] & SFF_8636_EXT_ID_CDR_TX_MASK) {
		printf("%s CDR present in TX,", pfx);
		add_item_string(items, "Extended identifier description",
				"CDR present in TX");
	} else {
		printf("%s No CDR in TX,", pfx);
		add_item_string(items, "Extended identifier description",
				"No CDR in TX");
	}

	if (id[SFF_8636_EXT_ID_OFFSET] & SFF_8636_EXT_ID_CDR_RX_MASK) {
		printf(" CDR present in RX\n");
		add_item_string(items, "Extended identifier description",
				"CDR present in RX");
	} else {
		printf(" No CDR in RX\n");
		add_item_string(items, "Extended identifier description",
				"No CDR in RX");
	}

	switch (id[SFF_8636_EXT_ID_OFFSET] & SFF_8636_EXT_ID_EPWR_CLASS_MASK) {
	case SFF_8636_EXT_ID_PWR_CLASS_LEGACY:
		printf("%s", pfx);
		sprintf(val_string, "%s", "");
		break;
	case SFF_8636_EXT_ID_PWR_CLASS_5:
		printf("%s 4.0W max. Power consumption,", pfx);
		sprintf(val_string, "%s", "4.0W max. Power consumption, ");
		break;
	case SFF_8636_EXT_ID_PWR_CLASS_6:
		printf("%s 4.5W max. Power consumption, ", pfx);
		sprintf(val_string, "%s", "4.5W max. Power consumption, ");
		break;
	case SFF_8636_EXT_ID_PWR_CLASS_7:
		printf("%s 5.0W max. Power consumption, ", pfx);
		sprintf(val_string, "%s", "5.0W max. Power consumption, ");
		break;
	}
	if (id[SFF_8636_PWR_MODE_OFFSET] & SFF_8636_HIGH_PWR_ENABLE) {
		printf(" High Power Class (> 3.5 W) enabled\n");
		strcat(val_string, "High Power Class (> 3.5 W) enabled");
	} else {
		printf(" High Power Class (> 3.5 W) not enabled\n");
		strcat(val_string, "High Power Class (> 3.5 W) not enabled");
	}
	add_item_string(items, "Extended identifier description", val_string);
}

static void sff_8636_show_connector(const uint8_t *id, sff_item *items)
{
	sff_8024_show_connector(id, SFF_8636_CTOR_OFFSET, items);
}

static void sff_8636_show_transceiver(const uint8_t *id, sff_item *items)
{
	static const char *pfx =
		"Transceiver type                          :";
	static const char *name_string = "Transceiver type";
	char val_string[TMP_STRING_SIZE];

	printf("%-41s : 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
	       "Transceiver codes",
	       id[SFF_8636_ETHERNET_COMP_OFFSET],
	       id[SFF_8636_SONET_COMP_OFFSET],
	       id[SFF_8636_SAS_COMP_OFFSET],
	       id[SFF_8636_GIGE_COMP_OFFSET],
	       id[SFF_8636_FC_LEN_OFFSET],
	       id[SFF_8636_FC_TECH_OFFSET],
	       id[SFF_8636_FC_TRANS_MEDIA_OFFSET],
	       id[SFF_8636_FC_SPEED_OFFSET]);
	sprintf(val_string, "0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x",
		id[SFF_8636_ETHERNET_COMP_OFFSET],
		id[SFF_8636_SONET_COMP_OFFSET],
		id[SFF_8636_SAS_COMP_OFFSET],
		id[SFF_8636_GIGE_COMP_OFFSET],
		id[SFF_8636_FC_LEN_OFFSET],
		id[SFF_8636_FC_TECH_OFFSET],
		id[SFF_8636_FC_TRANS_MEDIA_OFFSET],
		id[SFF_8636_FC_SPEED_OFFSET]);
	add_item_string(items, "Transceiver codes", val_string);

	/* 10G/40G Ethernet Compliance Codes */
	if (id[SFF_8636_ETHERNET_COMP_OFFSET] & SFF_8636_ETHERNET_10G_LRM) {
		printf("%s 10G Ethernet: 10G Base-LRM\n", pfx);
		add_item_string(items, name_string,
				"10G Ethernet: 10G Base-LRM");
	}
	if (id[SFF_8636_ETHERNET_COMP_OFFSET] & SFF_8636_ETHERNET_10G_LR) {
		printf("%s 10G Ethernet: 10G Base-LR\n", pfx);
		add_item_string(items, name_string,
				"10G Ethernet: 10G Base-LR");
	}
	if (id[SFF_8636_ETHERNET_COMP_OFFSET] & SFF_8636_ETHERNET_10G_SR) {
		printf("%s 10G Ethernet: 10G Base-SR\n", pfx);
		add_item_string(items, name_string,
				"10G Ethernet: 10G Base-SR");
	}
	if (id[SFF_8636_ETHERNET_COMP_OFFSET] & SFF_8636_ETHERNET_40G_CR4) {
		printf("%s 40G Ethernet: 40G Base-CR4\n", pfx);
		add_item_string(items, name_string,
				"40G Ethernet: 40G Base-CR4");
	}
	if (id[SFF_8636_ETHERNET_COMP_OFFSET] & SFF_8636_ETHERNET_40G_SR4) {
		printf("%s 40G Ethernet: 40G Base-SR4\n", pfx);
		add_item_string(items, name_string,
				"40G Ethernet: 40G Base-SR4");
	}
	if (id[SFF_8636_ETHERNET_COMP_OFFSET] & SFF_8636_ETHERNET_40G_LR4) {
		printf("%s 40G Ethernet: 40G Base-LR4\n", pfx);
		add_item_string(items, name_string,
				"40G Ethernet: 40G Base-LR4");
	}
	if (id[SFF_8636_ETHERNET_COMP_OFFSET] & SFF_8636_ETHERNET_40G_ACTIVE) {
		printf("%s 40G Ethernet: 40G Active Cable (XLPPI)\n", pfx);
		add_item_string(items, name_string,
				"40G Ethernet: 40G Active Cable (XLPPI)");
	}
	/* Extended Specification Compliance Codes from SFF-8024 */
	if (id[SFF_8636_ETHERNET_COMP_OFFSET] & SFF_8636_ETHERNET_RSRVD) {
		switch (id[SFF_8636_OPTION_1_OFFSET]) {
		case SFF_8636_ETHERNET_UNSPECIFIED:
			printf("%s (reserved or unknown)\n", pfx);
			add_item_string(items, name_string,
					"(reserved or unknown)");
			break;
		case SFF_8636_ETHERNET_100G_AOC:
			printf("%s 100G Ethernet: 100G AOC or 25GAUI C2M AOC with worst BER of 5x10^(-5)\n",
					pfx);
			add_item_string(items, name_string,
				"100G Ethernet: 100G AOC or 25GAUI C2M AOC with worst BER of 5x10^(-5)");
			break;
		case SFF_8636_ETHERNET_100G_SR4:
			printf("%s 100G Ethernet: 100G Base-SR4 or 25GBase-SR\n",
					pfx);
			add_item_string(items, name_string,
					"100G Ethernet: 100G Base-SR4 or 25GBase-SR");
			break;
		case SFF_8636_ETHERNET_100G_LR4:
			printf("%s 100G Ethernet: 100G Base-LR4\n", pfx);
			add_item_string(items, name_string,
					"100G Ethernet: 100G Base-LR4");
			break;
		case SFF_8636_ETHERNET_100G_ER4:
			printf("%s 100G Ethernet: 100G Base-ER4\n", pfx);
			add_item_string(items, name_string,
					"100G Ethernet: 100G Base-ER4");
			break;
		case SFF_8636_ETHERNET_100G_SR10:
			printf("%s 100G Ethernet: 100G Base-SR10\n", pfx);
			add_item_string(items, name_string,
					"100G Ethernet: 100G Base-SR10");
			break;
		case SFF_8636_ETHERNET_100G_CWDM4_FEC:
			printf("%s 100G Ethernet: 100G CWDM4 MSA with FEC\n", pfx);
			add_item_string(items, name_string,
					"100G Ethernet: 100G CWDM4 MSA with FEC");
			break;
		case SFF_8636_ETHERNET_100G_PSM4:
			printf("%s 100G Ethernet: 100G PSM4 Parallel SMF\n", pfx);
			add_item_string(items, name_string,
					"100G Ethernet: 100G PSM4 Parallel SMF");
			break;
		case SFF_8636_ETHERNET_100G_ACC:
			printf("%s 100G Ethernet: 100G ACC or 25GAUI C2M ACC with worst BER of 5x10^(-5)\n",
				pfx);
			add_item_string(items, name_string,
				"100G Ethernet: 100G ACC or 25GAUI C2M ACC with worst BER of 5x10^(-5)");
			break;
		case SFF_8636_ETHERNET_100G_CWDM4_NO_FEC:
			printf("%s 100G Ethernet: 100G CWDM4 MSA without FEC\n", pfx);
			add_item_string(items, name_string,
				"100G Ethernet: 100G CWDM4 MSA without FEC");
			break;
		case SFF_8636_ETHERNET_100G_RSVD1:
			printf("%s (reserved or unknown)\n", pfx);
			add_item_string(items, name_string,
					"(reserved or unknown)");
			break;
		case SFF_8636_ETHERNET_100G_CR4:
			printf("%s 100G Ethernet: 100G Base-CR4 or 25G Base-CR CA-L\n",
				pfx);
			add_item_string(items, name_string,
					"100G Ethernet: 100G Base-CR4 or 25G Base-CR CA-L");
			break;
		case SFF_8636_ETHERNET_25G_CR_CA_S:
			printf("%s 25G Ethernet: 25G Base-CR CA-S\n", pfx);
			add_item_string(items, name_string,
					"25G Ethernet: 25G Base-CR CA-S");
			break;
		case SFF_8636_ETHERNET_25G_CR_CA_N:
			printf("%s 25G Ethernet: 25G Base-CR CA-N\n", pfx);
			add_item_string(items, name_string,
					"25G Ethernet: 25G Base-CR CA-N");
			break;
		case SFF_8636_ETHERNET_40G_ER4:
			printf("%s 40G Ethernet: 40G Base-ER4\n", pfx);
			add_item_string(items, name_string,
					"40G Ethernet: 40G Base-ER4");
			break;
		case SFF_8636_ETHERNET_4X10_SR:
			printf("%s 4x10G Ethernet: 10G Base-SR\n", pfx);
			add_item_string(items, name_string,
					"4x10G Ethernet: 10G Base-SR");
			break;
		case SFF_8636_ETHERNET_40G_PSM4:
			printf("%s 40G Ethernet: 40G PSM4 Parallel SMF\n", pfx);
			add_item_string(items, name_string,
					"40G Ethernet: 40G PSM4 Parallel SMF");
			break;
		case SFF_8636_ETHERNET_G959_P1I1_2D1:
			printf("%s Ethernet: G959.1 profile P1I1-2D1 (10709 MBd, 2km, 1310nm SM)\n",
					pfx);
			add_item_string(items, name_string,
				"Ethernet: G959.1 profile P1I1-2D1 (10709 MBd, 2km, 1310nm SM)");
			break;
		case SFF_8636_ETHERNET_G959_P1S1_2D2:
			printf("%s Ethernet: G959.1 profile P1S1-2D2 (10709 MBd, 40km, 1550nm SM)\n",
					pfx);
			add_item_string(items, name_string,
				"Ethernet: G959.1 profile P1S1-2D2 (10709 MBd, 40km, 1550nm SM)");
			break;
		case SFF_8636_ETHERNET_G959_P1L1_2D2:
			printf("%s Ethernet: G959.1 profile P1L1-2D2 (10709 MBd, 80km, 1550nm SM)\n",
					pfx);
			add_item_string(items, name_string,
				"Ethernet: G959.1 profile P1L1-2D2 (10709 MBd, 80km, 1550nm SM)");
			break;
		case SFF_8636_ETHERNET_10GT_SFI:
			printf("%s 10G Ethernet: 10G Base-T with SFI electrical interface\n",
					pfx);
			add_item_string(items, name_string,
				"10G Ethernet: 10G Base-T with SFI electrical interface");
			break;
		case SFF_8636_ETHERNET_100G_CLR4:
			printf("%s 100G Ethernet: 100G CLR4\n", pfx);
			add_item_string(items, name_string,
					"100G Ethernet: 100G CLR4");
			break;
		case SFF_8636_ETHERNET_100G_AOC2:
			printf("%s 100G Ethernet: 100G AOC or 25GAUI C2M AOC with worst BER of 10^(-12)\n",
					pfx);
			add_item_string(items, name_string,
				"100G Ethernet: 100G AOC or 25GAUI C2M AOC with worst BER of 10^(-12)");
			break;
		case SFF_8636_ETHERNET_100G_ACC2:
			printf("%s 100G Ethernet: 100G ACC or 25GAUI C2M ACC with worst BER of 10^(-12)\n",
					pfx);
			add_item_string(items, name_string,
				"100G Ethernet: 100G ACC or 25GAUI C2M ACC with worst BER of 10^(-12)");
			break;
		default:
			printf("%s (reserved or unknown)\n", pfx);
			add_item_string(items, name_string,
					"(reserved or unknown)");
			break;
		}
	}

	/* SONET Compliance Codes */
	if (id[SFF_8636_SONET_COMP_OFFSET] & SFF_8636_SONET_40G_OTN) {
		printf("%s 40G OTN (OTU3B/OTU3C)\n", pfx);
		add_item_string(items, name_string, "40G OTN (OTU3B/OTU3C)");
	}
	if (id[SFF_8636_SONET_COMP_OFFSET] & SFF_8636_SONET_OC48_LR) {
		printf("%s SONET: OC-48, long reach\n", pfx);
		add_item_string(items, name_string, "SONET: OC-48, long reach");
	}
	if (id[SFF_8636_SONET_COMP_OFFSET] & SFF_8636_SONET_OC48_IR) {
		printf("%s SONET: OC-48, intermediate reach\n", pfx);
		add_item_string(items, name_string, "SONET: OC-48, intermediate reach");
	}
	if (id[SFF_8636_SONET_COMP_OFFSET] & SFF_8636_SONET_OC48_SR) {
		printf("%s SONET: OC-48, short reach\n", pfx);
		add_item_string(items, name_string, "SONET: OC-48, short reach");
	}

	/* SAS/SATA Compliance Codes */
	if (id[SFF_8636_SAS_COMP_OFFSET] & SFF_8636_SAS_6G) {
		printf("%s SAS 6.0G\n", pfx);
		add_item_string(items, name_string, "SAS 6.0G");
	}
	if (id[SFF_8636_SAS_COMP_OFFSET] & SFF_8636_SAS_3G) {
		printf("%s SAS 3.0G\n", pfx);
		add_item_string(items, name_string, "SAS 3.0G");
	}

	/* Ethernet Compliance Codes */
	if (id[SFF_8636_GIGE_COMP_OFFSET] & SFF_8636_GIGE_1000_BASE_T) {
		printf("%s Ethernet: 1000BASE-T\n", pfx);
		add_item_string(items, name_string, "Ethernet: 1000BASE-T");
	}
	if (id[SFF_8636_GIGE_COMP_OFFSET] & SFF_8636_GIGE_1000_BASE_CX) {
		printf("%s Ethernet: 1000BASE-CX\n", pfx);
		add_item_string(items, name_string, "Ethernet: 1000BASE-CX");
	}
	if (id[SFF_8636_GIGE_COMP_OFFSET] & SFF_8636_GIGE_1000_BASE_LX) {
		printf("%s Ethernet: 1000BASE-LX\n", pfx);
		add_item_string(items, name_string, "Ethernet: 1000BASE-LX");
	}
	if (id[SFF_8636_GIGE_COMP_OFFSET] & SFF_8636_GIGE_1000_BASE_SX) {
		printf("%s Ethernet: 1000BASE-SX\n", pfx);
		add_item_string(items, name_string, "Ethernet: 1000BASE-SX");
	}

	/* Fibre Channel link length */
	if (id[SFF_8636_FC_LEN_OFFSET] & SFF_8636_FC_LEN_VERY_LONG) {
		printf("%s FC: very long distance (V)\n", pfx);
		add_item_string(items, name_string, "FC: very long distance (V)");
	}
	if (id[SFF_8636_FC_LEN_OFFSET] & SFF_8636_FC_LEN_SHORT) {
		printf("%s FC: short distance (S)\n", pfx);
		add_item_string(items, name_string, "FC: short distance (S)");
	}
	if (id[SFF_8636_FC_LEN_OFFSET] & SFF_8636_FC_LEN_INT) {
		printf("%s FC: intermediate distance (I)\n", pfx);
		add_item_string(items, name_string, "FC: intermediate distance (I)");
	}
	if (id[SFF_8636_FC_LEN_OFFSET] & SFF_8636_FC_LEN_LONG) {
		printf("%s FC: long distance (L)\n", pfx);
		add_item_string(items, name_string, "FC: long distance (L)");
	}
	if (id[SFF_8636_FC_LEN_OFFSET] & SFF_8636_FC_LEN_MED) {
		printf("%s FC: medium distance (M)\n", pfx);
		add_item_string(items, name_string, "FC: medium distance (M)");
	}

	/* Fibre Channel transmitter technology */
	if (id[SFF_8636_FC_LEN_OFFSET] & SFF_8636_FC_TECH_LONG_LC) {
		printf("%s FC: Longwave laser (LC)\n", pfx);
		add_item_string(items, name_string, "FC: Longwave laser (LC)");
	}
	if (id[SFF_8636_FC_LEN_OFFSET] & SFF_8636_FC_TECH_ELEC_INTER) {
		printf("%s FC: Electrical inter-enclosure (EL)\n", pfx);
		add_item_string(items, name_string, "FC: Electrical inter-enclosure (EL)");
	}
	if (id[SFF_8636_FC_TECH_OFFSET] & SFF_8636_FC_TECH_ELEC_INTRA) {
		printf("%s FC: Electrical intra-enclosure (EL)\n", pfx);
		add_item_string(items, name_string, "FC: Electrical intra-enclosure (EL)");
	}
	if (id[SFF_8636_FC_TECH_OFFSET] & SFF_8636_FC_TECH_SHORT_WO_OFC) {
		printf("%s FC: Shortwave laser w/o OFC (SN)\n", pfx);
		add_item_string(items, name_string, "FC: Shortwave laser w/o OFC (SN)");
	}
	if (id[SFF_8636_FC_TECH_OFFSET] & SFF_8636_FC_TECH_SHORT_W_OFC) {
		printf("%s FC: Shortwave laser with OFC (SL)\n", pfx);
		add_item_string(items, name_string, "FC: Shortwave laser with OFC (SL)");
	}
	if (id[SFF_8636_FC_TECH_OFFSET] & SFF_8636_FC_TECH_LONG_LL) {
		printf("%s FC: Longwave laser (LL)\n", pfx);
		add_item_string(items, name_string, "FC: Longwave laser (LL)");
	}

	/* Fibre Channel transmission media */
	if (id[SFF_8636_FC_TRANS_MEDIA_OFFSET] & SFF_8636_FC_TRANS_MEDIA_TW) {
		printf("%s FC: Twin Axial Pair (TW)\n", pfx);
		add_item_string(items, name_string, "FC: Twin Axial Pair (TW)");
	}
	if (id[SFF_8636_FC_TRANS_MEDIA_OFFSET] & SFF_8636_FC_TRANS_MEDIA_TP) {
		printf("%s FC: Twisted Pair (TP)\n", pfx);
		add_item_string(items, name_string, "FC: Twisted Pair (TP)");
	}
	if (id[SFF_8636_FC_TRANS_MEDIA_OFFSET] & SFF_8636_FC_TRANS_MEDIA_MI) {
		printf("%s FC: Miniature Coax (MI)\n", pfx);
		add_item_string(items, name_string, "FC: Miniature Coax (MI)");
	}
	if (id[SFF_8636_FC_TRANS_MEDIA_OFFSET] & SFF_8636_FC_TRANS_MEDIA_TV) {
		printf("%s FC: Video Coax (TV)\n", pfx);
		add_item_string(items, name_string, "FC: Video Coax (TV)");
	}
	if (id[SFF_8636_FC_TRANS_MEDIA_OFFSET] & SFF_8636_FC_TRANS_MEDIA_M6) {
		printf("%s FC: Multimode, 62.5m (M6)\n", pfx);
		add_item_string(items, name_string, "FC: Multimode, 62.5m (M6)");
	}
	if (id[SFF_8636_FC_TRANS_MEDIA_OFFSET] & SFF_8636_FC_TRANS_MEDIA_M5) {
		printf("%s FC: Multimode, 50m (M5)\n", pfx);
		add_item_string(items, name_string, "FC: Multimode, 50m (M5)");
	}
	if (id[SFF_8636_FC_TRANS_MEDIA_OFFSET] & SFF_8636_FC_TRANS_MEDIA_OM3) {
		printf("%s FC: Multimode, 50um (OM3)\n", pfx);
		add_item_string(items, name_string, "FC: Multimode, 50um (OM3)");
	}
	if (id[SFF_8636_FC_TRANS_MEDIA_OFFSET] & SFF_8636_FC_TRANS_MEDIA_SM) {
		printf("%s FC: Single Mode (SM)\n", pfx);
		add_item_string(items, name_string, "FC: Single Mode (SM)");
	}

	/* Fibre Channel speed */
	if (id[SFF_8636_FC_SPEED_OFFSET] & SFF_8636_FC_SPEED_1200_MBPS) {
		printf("%s FC: 1200 MBytes/sec\n", pfx);
		add_item_string(items, name_string, "FC: 1200 MBytes/sec");
	}
	if (id[SFF_8636_FC_SPEED_OFFSET] & SFF_8636_FC_SPEED_800_MBPS) {
		printf("%s FC: 800 MBytes/sec\n", pfx);
		add_item_string(items, name_string, "FC: 800 MBytes/sec");
	}
	if (id[SFF_8636_FC_SPEED_OFFSET] & SFF_8636_FC_SPEED_1600_MBPS) {
		printf("%s FC: 1600 MBytes/sec\n", pfx);
		add_item_string(items, name_string, "FC: 1600 MBytes/sec");
	}
	if (id[SFF_8636_FC_SPEED_OFFSET] & SFF_8636_FC_SPEED_400_MBPS) {
		printf("%s FC: 400 MBytes/sec\n", pfx);
		add_item_string(items, name_string, "FC: 400 MBytes/sec");
	}
	if (id[SFF_8636_FC_SPEED_OFFSET] & SFF_8636_FC_SPEED_200_MBPS) {
		printf("%s FC: 200 MBytes/sec\n", pfx);
		add_item_string(items, name_string, "FC: 200 MBytes/sec");
	}
	if (id[SFF_8636_FC_SPEED_OFFSET] & SFF_8636_FC_SPEED_100_MBPS) {
		printf("%s FC: 100 MBytes/sec\n", pfx);
		add_item_string(items, name_string, "FC: 100 MBytes/sec");
	}
}

static void sff_8636_show_encoding(const uint8_t *id, sff_item *items)
{
	sff_8024_show_encoding(id, SFF_8636_ENCODING_OFFSET,
			       RTE_ETH_MODULE_SFF_8636, items);
}

static void sff_8636_show_rate_identifier(const uint8_t *id, sff_item *items)
{
	char val_string[20];
	/* TODO: Need to fix rate select logic */
	printf("%-41s : 0x%02x\n", "Rate identifier",
			id[SFF_8636_EXT_RS_OFFSET]);
	sprintf(val_string, "0x%02x", id[SFF_8636_EXT_RS_OFFSET]);
	add_item_string(items, "Rate identifier", val_string);
}

static void sff_8636_show_oui(const uint8_t *id, sff_item *items)
{
	sff_8024_show_oui(id, SFF_8636_VENDOR_OUI_OFFSET, items);
}

static void sff_8636_show_wavelength_or_copper_compliance(const uint8_t *id, sff_item *items)
{
	char val_string[TMP_STRING_SIZE];
	printf("%-41s : 0x%02x", "Transmitter technology",
		(id[SFF_8636_DEVICE_TECH_OFFSET] & SFF_8636_TRANS_TECH_MASK));
	sprintf(val_string, "0x%02x",
		(id[SFF_8636_DEVICE_TECH_OFFSET] & SFF_8636_TRANS_TECH_MASK));

	switch (id[SFF_8636_DEVICE_TECH_OFFSET] & SFF_8636_TRANS_TECH_MASK) {
	case SFF_8636_TRANS_850_VCSEL:
		printf(" (850 nm VCSEL)\n");
		strcat(val_string, " (850 nm VCSEL)");
		break;
	case SFF_8636_TRANS_1310_VCSEL:
		printf(" (1310 nm VCSEL)\n");
		strcat(val_string, " (1310 nm VCSEL)");
		break;
	case SFF_8636_TRANS_1550_VCSEL:
		printf(" (1550 nm VCSEL)\n");
		strcat(val_string, " (1550 nm VCSEL)");
		break;
	case SFF_8636_TRANS_1310_FP:
		printf(" (1310 nm FP)\n");
		strcat(val_string, " (1310 nm FP)");
		break;
	case SFF_8636_TRANS_1310_DFB:
		printf(" (1310 nm DFB)\n");
		strcat(val_string, " (1310 nm DFB)");
		break;
	case SFF_8636_TRANS_1550_DFB:
		printf(" (1550 nm DFB)\n");
		strcat(val_string, " (1550 nm DFB)");
		break;
	case SFF_8636_TRANS_1310_EML:
		printf(" (1310 nm EML)\n");
		strcat(val_string, " (1310 nm EML)");
		break;
	case SFF_8636_TRANS_1550_EML:
		printf(" (1550 nm EML)\n");
		strcat(val_string, " (1550 nm EML)");
		break;
	case SFF_8636_TRANS_OTHERS:
		printf(" (Others/Undefined)\n");
		strcat(val_string, " (Others/Undefined)");
		break;
	case SFF_8636_TRANS_1490_DFB:
		printf(" (1490 nm DFB)\n");
		strcat(val_string, " (1490 nm DFB)");
		break;
	case SFF_8636_TRANS_COPPER_PAS_UNEQUAL:
		printf(" (Copper cable unequalized)\n");
		strcat(val_string, " (Copper cable unequalized)");
		break;
	case SFF_8636_TRANS_COPPER_PAS_EQUAL:
		printf(" (Copper cable passive equalized)\n");
		strcat(val_string, " (Copper cable passive equalized)");
		break;
	case SFF_8636_TRANS_COPPER_LNR_FAR_EQUAL:
		printf(" (Copper cable, near and far end limiting active equalizers)\n");
		strcat(val_string,
		       " (Copper cable, near and far end limiting active equalizers)");
		break;
	case SFF_8636_TRANS_COPPER_FAR_EQUAL:
		printf(" (Copper cable, far end limiting active equalizers)\n");
		strcat(val_string, " (Copper cable, far end limiting active equalizers)");
		break;
	case SFF_8636_TRANS_COPPER_NEAR_EQUAL:
		printf(" (Copper cable, near end limiting active equalizers)\n");
		strcat(val_string, " (Copper cable, near end limiting active equalizers)");
		break;
	case SFF_8636_TRANS_COPPER_LNR_EQUAL:
		printf(" (Copper cable, linear active equalizers)\n");
		strcat(val_string, " (Copper cable, linear active equalizers)");
		break;
	}
	add_item_string(items, "Transmitter technology", val_string);

	if ((id[SFF_8636_DEVICE_TECH_OFFSET] & SFF_8636_TRANS_TECH_MASK)
			>= SFF_8636_TRANS_COPPER_PAS_UNEQUAL) {
		printf("%-41s : %udb\n", "Attenuation at 2.5GHz",
			id[SFF_8636_WAVELEN_HIGH_BYTE_OFFSET]);
		sprintf(val_string, "%udb", id[SFF_8636_WAVELEN_HIGH_BYTE_OFFSET]);
		add_item_string(items, "Attenuation at 2.5GHz", val_string);

		printf("%-41s : %udb\n", "Attenuation at 5.0GHz",
			id[SFF_8636_WAVELEN_LOW_BYTE_OFFSET]);
		sprintf(val_string, "%udb", id[SFF_8636_WAVELEN_HIGH_BYTE_OFFSET]);
		add_item_string(items, "Attenuation at 5.0GHz", val_string);

		printf("%-41s : %udb\n", "Attenuation at 7.0GHz",
			id[SFF_8636_WAVE_TOL_HIGH_BYTE_OFFSET]);
		sprintf(val_string, "%udb", id[SFF_8636_WAVELEN_HIGH_BYTE_OFFSET]);
		add_item_string(items, "Attenuation at 7.0GHz", val_string);

		printf("%-41s : %udb\n", "Attenuation at 12.9GHz",
			id[SFF_8636_WAVE_TOL_LOW_BYTE_OFFSET]);
		sprintf(val_string, "%udb", id[SFF_8636_WAVELEN_HIGH_BYTE_OFFSET]);
		add_item_string(items, "Attenuation at 12.9GHz", val_string);
	} else {
		printf("%-41s : %.3lfnm\n", "Laser wavelength",
			(((id[SFF_8636_WAVELEN_HIGH_BYTE_OFFSET] << 8) |
			id[SFF_8636_WAVELEN_LOW_BYTE_OFFSET])*0.05));
		sprintf(val_string, "%.3lfnm",
			(((id[SFF_8636_WAVELEN_HIGH_BYTE_OFFSET] << 8) |
			id[SFF_8636_WAVELEN_LOW_BYTE_OFFSET])*0.05));
		add_item_string(items, "Laser wavelength", val_string);

		printf("%-41s : %.3lfnm\n", "Laser wavelength tolerance",
			(((id[SFF_8636_WAVE_TOL_HIGH_BYTE_OFFSET] << 8) |
			id[SFF_8636_WAVE_TOL_LOW_BYTE_OFFSET])*0.005));
		sprintf(val_string, "%.3lfnm",
			(((id[SFF_8636_WAVE_TOL_HIGH_BYTE_OFFSET] << 8) |
			id[SFF_8636_WAVE_TOL_LOW_BYTE_OFFSET])*0.005));
		add_item_string(items, "Laser wavelength tolerance", val_string);
	}
}

static void sff_8636_show_revision_compliance(const uint8_t *id, sff_item *items)
{
	static const char *pfx =
		"Revision Compliance                       :";

	switch (id[SFF_8636_REV_COMPLIANCE_OFFSET]) {
	case SFF_8636_REV_UNSPECIFIED:
		printf("%s Revision not specified\n", pfx);
		add_item_string(items, "Revision Compliance",
				"Revision not specified");
		break;
	case SFF_8636_REV_8436_48:
		printf("%s SFF-8436 Rev 4.8 or earlier\n", pfx);
		add_item_string(items, "Revision Compliance",
				"SFF-8436 Rev 4.8 or earlier");
		break;
	case SFF_8636_REV_8436_8636:
		printf("%s SFF-8436 Rev 4.8 or earlier\n", pfx);
		add_item_string(items, "Revision Compliance",
				"SFF-8436 Rev 4.8 or earlier");
		break;
	case SFF_8636_REV_8636_13:
		printf("%s SFF-8636 Rev 1.3 or earlier\n", pfx);
		add_item_string(items, "Revision Compliance",
				"SFF-8636 Rev 1.3 or earlier");
		break;
	case SFF_8636_REV_8636_14:
		printf("%s SFF-8636 Rev 1.4\n", pfx);
		add_item_string(items, "Revision Compliance",
				"SFF-8636 Rev 1.4");
		break;
	case SFF_8636_REV_8636_15:
		printf("%s SFF-8636 Rev 1.5\n", pfx);
		add_item_string(items, "Revision Compliance",
				"SFF-8636 Rev 1.5");
		break;
	case SFF_8636_REV_8636_20:
		printf("%s SFF-8636 Rev 2.0\n", pfx);
		add_item_string(items, "Revision Compliance",
				"SFF-8636 Rev 2.0");
		break;
	case SFF_8636_REV_8636_27:
		printf("%s SFF-8636 Rev 2.5/2.6/2.7\n", pfx);
		add_item_string(items, "Revision Compliance",
				"SFF-8636 Rev 2.5/2.6/2.7");
		break;
	default:
		printf("%s Unallocated\n", pfx);
		add_item_string(items, "Revision Compliance",
				"Unallocated");
		break;
	}
}

/*
 * 2-byte internal temperature conversions:
 * First byte is a signed 8-bit integer, which is the temp decimal part
 * Second byte are 1/256th of degree, which are added to the dec part.
 */
#define SFF_8636_OFFSET_TO_TEMP(offset) ((int16_t)OFFSET_TO_U16(offset))

static void sff_8636_dom_parse(const uint8_t *id, struct sff_diags *sd)
{
	int i = 0;

	/* Monitoring Thresholds for Alarms and Warnings */
	sd->sfp_voltage[MCURR] = OFFSET_TO_U16(SFF_8636_VCC_CURR);
	sd->sfp_voltage[HALRM] = OFFSET_TO_U16(SFF_8636_VCC_HALRM);
	sd->sfp_voltage[LALRM] = OFFSET_TO_U16(SFF_8636_VCC_LALRM);
	sd->sfp_voltage[HWARN] = OFFSET_TO_U16(SFF_8636_VCC_HWARN);
	sd->sfp_voltage[LWARN] = OFFSET_TO_U16(SFF_8636_VCC_LWARN);

	sd->sfp_temp[MCURR] = SFF_8636_OFFSET_TO_TEMP(SFF_8636_TEMP_CURR);
	sd->sfp_temp[HALRM] = SFF_8636_OFFSET_TO_TEMP(SFF_8636_TEMP_HALRM);
	sd->sfp_temp[LALRM] = SFF_8636_OFFSET_TO_TEMP(SFF_8636_TEMP_LALRM);
	sd->sfp_temp[HWARN] = SFF_8636_OFFSET_TO_TEMP(SFF_8636_TEMP_HWARN);
	sd->sfp_temp[LWARN] = SFF_8636_OFFSET_TO_TEMP(SFF_8636_TEMP_LWARN);

	sd->bias_cur[HALRM] = OFFSET_TO_U16(SFF_8636_TX_BIAS_HALRM);
	sd->bias_cur[LALRM] = OFFSET_TO_U16(SFF_8636_TX_BIAS_LALRM);
	sd->bias_cur[HWARN] = OFFSET_TO_U16(SFF_8636_TX_BIAS_HWARN);
	sd->bias_cur[LWARN] = OFFSET_TO_U16(SFF_8636_TX_BIAS_LWARN);

	sd->tx_power[HALRM] = OFFSET_TO_U16(SFF_8636_TX_PWR_HALRM);
	sd->tx_power[LALRM] = OFFSET_TO_U16(SFF_8636_TX_PWR_LALRM);
	sd->tx_power[HWARN] = OFFSET_TO_U16(SFF_8636_TX_PWR_HWARN);
	sd->tx_power[LWARN] = OFFSET_TO_U16(SFF_8636_TX_PWR_LWARN);

	sd->rx_power[HALRM] = OFFSET_TO_U16(SFF_8636_RX_PWR_HALRM);
	sd->rx_power[LALRM] = OFFSET_TO_U16(SFF_8636_RX_PWR_LALRM);
	sd->rx_power[HWARN] = OFFSET_TO_U16(SFF_8636_RX_PWR_HWARN);
	sd->rx_power[LWARN] = OFFSET_TO_U16(SFF_8636_RX_PWR_LWARN);


	/* Channel Specific Data */
	for (i = 0; i < MAX_CHANNEL_NUM; i++) {
		uint8_t rx_power_offset, tx_bias_offset;
		uint8_t tx_power_offset;

		switch (i) {
		case 0:
			rx_power_offset = SFF_8636_RX_PWR_1_OFFSET;
			tx_power_offset = SFF_8636_TX_PWR_1_OFFSET;
			tx_bias_offset = SFF_8636_TX_BIAS_1_OFFSET;
			break;
		case 1:
			rx_power_offset = SFF_8636_RX_PWR_2_OFFSET;
			tx_power_offset = SFF_8636_TX_PWR_2_OFFSET;
			tx_bias_offset = SFF_8636_TX_BIAS_2_OFFSET;
			break;
		case 2:
			rx_power_offset = SFF_8636_RX_PWR_3_OFFSET;
			tx_power_offset = SFF_8636_TX_PWR_3_OFFSET;
			tx_bias_offset = SFF_8636_TX_BIAS_3_OFFSET;
			break;
		case 3:
			rx_power_offset = SFF_8636_RX_PWR_4_OFFSET;
			tx_power_offset = SFF_8636_TX_PWR_4_OFFSET;
			tx_bias_offset = SFF_8636_TX_BIAS_4_OFFSET;
			break;
		}
		sd->scd[i].bias_cur = OFFSET_TO_U16(tx_bias_offset);
		sd->scd[i].rx_power = OFFSET_TO_U16(rx_power_offset);
		sd->scd[i].tx_power = OFFSET_TO_U16(tx_power_offset);
	}

}

static void sff_8636_show_dom(const uint8_t *id, uint32_t eeprom_len, sff_item *items)
{
	struct sff_diags sd = {0};
	const char *rx_power_string = NULL;
	char power_string[MAX_DESC_SIZE];
	char val_string[TMP_STRING_SIZE];
	int i;

	/*
	 * There is no clear identifier to signify the existence of
	 * optical diagnostics similar to SFF-8472. So checking existence
	 * of page 3, will provide the gurantee for existence of alarms
	 * and thresholds
	 * If pagging support exists, then supports_alarms is marked as 1
	 */

	if (eeprom_len == RTE_ETH_MODULE_SFF_8636_MAX_LEN) {
		if (!(id[SFF_8636_STATUS_2_OFFSET] &
					SFF_8636_STATUS_PAGE_3_PRESENT)) {
			sd.supports_alarms = 1;
		}
	}

	sd.rx_power_type = id[SFF_8636_DIAG_TYPE_OFFSET] &
						SFF_8636_RX_PWR_TYPE_MASK;
	sd.tx_power_type = id[SFF_8636_DIAG_TYPE_OFFSET] &
						SFF_8636_RX_PWR_TYPE_MASK;

	sff_8636_dom_parse(id, &sd);

	PRINT_TEMP("Module temperature", sd.sfp_temp[MCURR]);
	SPRINT_TEMP(val_string, sd.sfp_temp[MCURR]);
	add_item_string(items, "Module temperature", val_string);

	PRINT_VCC("Module voltage", sd.sfp_voltage[MCURR]);
	SPRINT_VCC(val_string, sd.sfp_voltage[MCURR]);
	add_item_string(items, "Module voltage", val_string);

	/*
	 * SFF-8636/8436 spec is not clear whether RX power/ TX bias
	 * current fields are supported or not. A valid temperature
	 * reading is used as existence for TX/RX power.
	 */
	if ((sd.sfp_temp[MCURR] == 0x0) ||
	    (sd.sfp_temp[MCURR] == (int16_t)0xFFFF))
		return;

	printf("%-41s : %s\n", "Alarm/warning flags implemented",
		(sd.supports_alarms ? "Yes" : "No"));
	add_item_string(items, "Alarm/warning flags implemented",
			(sd.supports_alarms ? "Yes" : "No"));

	for (i = 0; i < MAX_CHANNEL_NUM; i++) {
		snprintf(power_string, MAX_DESC_SIZE, "%s (Channel %d)",
					"Laser tx bias current", i+1);
		PRINT_BIAS(power_string, sd.scd[i].bias_cur);
		SPRINT_BIAS(val_string, sd.scd[i].bias_cur);
		add_item_string(items, power_string, val_string);
	}

	for (i = 0; i < MAX_CHANNEL_NUM; i++) {
		snprintf(power_string, MAX_DESC_SIZE, "%s (Channel %d)",
					"Transmit avg optical power", i+1);
		PRINT_xX_PWR(power_string, sd.scd[i].tx_power);
		SPRINT_xX_PWR(val_string, sd.scd[i].tx_power);
		add_item_string(items, power_string, val_string);
	}

	if (!sd.rx_power_type)
		rx_power_string = "Receiver signal OMA";
	else
		rx_power_string = "Rcvr signal avg optical power";

	for (i = 0; i < MAX_CHANNEL_NUM; i++) {
		snprintf(power_string, MAX_DESC_SIZE, "%s(Channel %d)",
					rx_power_string, i+1);
		PRINT_xX_PWR(power_string, sd.scd[i].rx_power);
		SPRINT_xX_PWR(val_string, sd.scd[i].rx_power);
		add_item_string(items, power_string, val_string);
	}

	if (sd.supports_alarms) {
		for (i = 0; sff_8636_aw_flags[i].str; ++i) {
			printf("%-41s : %s\n", sff_8636_aw_flags[i].str,
			       id[sff_8636_aw_flags[i].offset]
			       & sff_8636_aw_flags[i].value ? "On" : "Off");
			add_item_string(items, sff_8636_aw_flags[i].str,
					id[sff_8636_aw_flags[i].offset]
					& sff_8636_aw_flags[i].value ? "On" : "Off");
		}

		sff_show_thresholds(sd, items);
	}

}
void sff_8636_show_all(const uint8_t *id, uint32_t eeprom_len, sff_item *items)
{
	sff_8636_show_identifier(id, items);
	if ((id[SFF_8636_ID_OFFSET] == SFF_8024_ID_QSFP) ||
		(id[SFF_8636_ID_OFFSET] == SFF_8024_ID_QSFP_PLUS) ||
		(id[SFF_8636_ID_OFFSET] == SFF_8024_ID_QSFP28)) {
		sff_8636_show_ext_identifier(id, items);
		sff_8636_show_connector(id, items);
		sff_8636_show_transceiver(id, items);
		sff_8636_show_encoding(id, items);
		sff_show_value_with_unit(id, SFF_8636_BR_NOMINAL_OFFSET,
				"BR, Nominal", 100, "Mbps", items);
		sff_8636_show_rate_identifier(id, items);
		sff_show_value_with_unit(id, SFF_8636_SM_LEN_OFFSET,
			     "Length (SMF,km)", 1, "km", items);
		sff_show_value_with_unit(id, SFF_8636_OM3_LEN_OFFSET,
				"Length (OM3 50um)", 2, "m", items);
		sff_show_value_with_unit(id, SFF_8636_OM2_LEN_OFFSET,
				"Length (OM2 50um)", 1, "m", items);
		sff_show_value_with_unit(id, SFF_8636_OM1_LEN_OFFSET,
			     "Length (OM1 62.5um)", 1, "m", items);
		sff_show_value_with_unit(id, SFF_8636_CBL_LEN_OFFSET,
			     "Length (Copper or Active cable)", 1, "m", items);
		sff_8636_show_wavelength_or_copper_compliance(id, items);
		sff_show_ascii(id, SFF_8636_VENDOR_NAME_START_OFFSET,
			     SFF_8636_VENDOR_NAME_END_OFFSET, "Vendor name", items);
		sff_8636_show_oui(id, items);
		sff_show_ascii(id, SFF_8636_VENDOR_PN_START_OFFSET,
			     SFF_8636_VENDOR_PN_END_OFFSET, "Vendor PN", items);
		sff_show_ascii(id, SFF_8636_VENDOR_REV_START_OFFSET,
			     SFF_8636_VENDOR_REV_END_OFFSET, "Vendor rev", items);
		sff_show_ascii(id, SFF_8636_VENDOR_SN_START_OFFSET,
			     SFF_8636_VENDOR_SN_END_OFFSET, "Vendor SN", items);
		sff_show_ascii(id, SFF_8636_DATE_YEAR_OFFSET,
			     SFF_8636_DATE_VENDOR_LOT_OFFSET + 1, "Date code", items);
		sff_8636_show_revision_compliance(id, items);
		sff_8636_show_dom(id, eeprom_len, items);
	}
}
