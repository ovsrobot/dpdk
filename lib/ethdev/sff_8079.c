/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2022 Intel Corporation
 *
 * Implements SFF-8079 optics diagnostics.
 *
 */

#include <stdio.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include "sff_common.h"
#include "ethdev_sff_telemetry.h"

static void sff_8079_show_identifier(const uint8_t *id, sff_item *items)
{
	sff_8024_show_identifier(id, 0, items);
}

static void sff_8079_show_ext_identifier(const uint8_t *id, sff_item *items)
{
	char val_string[TMP_STRING_SIZE];

	printf("%-41s : 0x%02x", "Extended identifier", id[1]);
	sprintf(val_string, "0x%02x", id[1]);
	if (id[1] == 0x00) {
		printf(" (GBIC not specified / not MOD_DEF compliant)\n");
		strcat(val_string, " (GBIC not specified / not MOD_DEF compliant)");
	} else if (id[1] == 0x04) {
		printf(" (GBIC/SFP defined by 2-wire interface ID)\n");
		strcat(val_string, " (GBIC/SFP defined by 2-wire interface ID)");
	} else if (id[1] <= 0x07) {
		printf(" (GBIC compliant with MOD_DEF %u)\n", id[1]);
		char tmp[TMP_STRING_SIZE];
		sprintf(tmp, " (GBIC compliant with MOD_DEF %u)", id[1]);
		strcat(val_string, tmp);
	} else {
		printf(" (unknown)\n");
		strcat(val_string, " (unknown)");
	}
	add_item_string(items, "Extended identifier", val_string);
}

static void sff_8079_show_connector(const uint8_t *id, sff_item *items)
{
	sff_8024_show_connector(id, 2, items);
}

static void sff_8079_show_transceiver(const uint8_t *id, sff_item *items)
{
	static const char *pfx =
		"Transceiver type                          :";
	char val_string[TMP_STRING_SIZE];

	printf("%-41s : 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
		"Transceiver codes",
	       id[3], id[4], id[5], id[6],
	       id[7], id[8], id[9], id[10], id[36]);
	sprintf(val_string,
		"0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x",
		id[3], id[4], id[5], id[6], id[7], id[8], id[9], id[10], id[36]);
	add_item_string(items, "Transceiver codes", val_string);

	/* 10G Ethernet Compliance Codes */
	if (id[3] & (1 << 7)) {
		printf("%s 10G Ethernet: 10G Base-ER [SFF-8472 rev10.4 onwards]\n", pfx);
		add_item_string(items, "10G Ethernet transceiver type",
		"10G Ethernet: 10G Base-ER [SFF-8472 rev10.4 onwards]");
	}
	if (id[3] & (1 << 6)) {
		printf("%s 10G Ethernet: 10G Base-LRM\n", pfx);
		add_item_string(items, "Transceiver type",
		"10G Ethernet: 10G Base-LRM");
	}
	if (id[3] & (1 << 5)) {
		printf("%s 10G Ethernet: 10G Base-LR\n", pfx);
		add_item_string(items, "Transceiver type",
		"10G Ethernet: 10G Base-LR");
	}
	if (id[3] & (1 << 4)) {
		printf("%s 10G Ethernet: 10G Base-SR\n", pfx);
		add_item_string(items, "Transceiver type",
		"10G Ethernet: 10G Base-SR");
	}

	/* Infiniband Compliance Codes */
	if (id[3] & (1 << 3)) {
		printf("%s Infiniband: 1X SX\n", pfx);
		add_item_string(items, "Transceiver type",
		"Infiniband: 1X SX");
	}
	if (id[3] & (1 << 2)) {
		printf("%s Infiniband: 1X LX\n", pfx);
		add_item_string(items, "Transceiver type",
		"Infiniband: 1X LX");
	}
	if (id[3] & (1 << 1)) {
		printf("%s Infiniband: 1X Copper Active\n", pfx);
		add_item_string(items, "Transceiver type",
		"Infiniband: 1X Copper Active");
	}
	if (id[3] & (1 << 0)) {
		printf("%s Infiniband: 1X Copper Passive\n", pfx);
		add_item_string(items, "Transceiver type",
		"Infiniband: 1X Copper Passive");
	}

	/* ESCON Compliance Codes */
	if (id[4] & (1 << 7)) {
		printf("%s ESCON: ESCON MMF, 1310nm LED\n", pfx);
		add_item_string(items, "Transceiver type",
		"ESCON: ESCON MMF, 1310nm LED");
	}
	if (id[4] & (1 << 6)) {
		printf("%s ESCON: ESCON SMF, 1310nm Laser\n", pfx);
		add_item_string(items, "Transceiver type",
		"ESCON: ESCON SMF, 1310nm Laser");
	}

	/* SONET Compliance Codes */
	if (id[4] & (1 << 5)) {
		printf("%s SONET: OC-192, short reach\n", pfx);
		add_item_string(items, "Transceiver type",
		"SONET: OC-192, short reach");
	}
	if (id[4] & (1 << 4)) {
		printf("%s SONET: SONET reach specifier bit 1\n", pfx);
		add_item_string(items, "Transceiver type",
		"SONET: SONET reach specifier bit 1");
	}
	if (id[4] & (1 << 3)) {
		printf("%s SONET: SONET reach specifier bit 2\n", pfx);
		add_item_string(items, "Transceiver type",
		"SONET: SONET reach specifier bit 2");
	}
	if (id[4] & (1 << 2)) {
		printf("%s SONET: OC-48, long reach\n", pfx);
		add_item_string(items, "Transceiver type",
		"SONET: OC-48, long reach");
	}
	if (id[4] & (1 << 1)) {
		printf("%s SONET: OC-48, intermediate reach\n", pfx);
		add_item_string(items, "Transceiver type",
		"SONET: OC-48, intermediate reach");
	}
	if (id[4] & (1 << 0)) {
		printf("%s SONET: OC-48, short reach\n", pfx);
		add_item_string(items, "Transceiver type",
		"SONET: OC-48, short reach");
	}
	if (id[5] & (1 << 6)) {
		printf("%s SONET: OC-12, single mode, long reach\n", pfx);
		add_item_string(items, "Transceiver type",
		"SONET: OC-12, single mode, long reach");
	}
	if (id[5] & (1 << 5)) {
		printf("%s SONET: OC-12, single mode, inter. reach\n", pfx);
		add_item_string(items, "Transceiver type",
		"SONET: OC-12, single mode, inter. reach");
	}
	if (id[5] & (1 << 4)) {
		printf("%s SONET: OC-12, short reach\n", pfx);
		add_item_string(items, "Transceiver type",
		"SONET: OC-12, short reach");
	}
	if (id[5] & (1 << 2)) {
		printf("%s SONET: OC-3, single mode, long reach\n", pfx);
		add_item_string(items, "Transceiver type",
		"SONET: OC-3, single mode, long reach");
	}
	if (id[5] & (1 << 1)) {
		printf("%s SONET: OC-3, single mode, inter. reach\n", pfx);
		add_item_string(items, "Transceiver type",
		"SONET: OC-3, single mode, inter. reach");
	}
	if (id[5] & (1 << 0)) {
		printf("%s SONET: OC-3, short reach\n", pfx);
		add_item_string(items, "Transceiver type",
		"SONET: OC-3, short reach");
	}

	/* Ethernet Compliance Codes */
	if (id[6] & (1 << 7)) {
		printf("%s Ethernet: BASE-PX\n", pfx);
		add_item_string(items, "Transceiver type",
		"Ethernet: BASE-PX");
	}
	if (id[6] & (1 << 6)) {
		printf("%s Ethernet: BASE-BX10\n", pfx);
		add_item_string(items, "Transceiver type",
		"Ethernet: BASE-BX10");
	}
	if (id[6] & (1 << 5)) {
		printf("%s Ethernet: 100BASE-FX\n", pfx);
		add_item_string(items, "Transceiver type",
		"Ethernet: 100BASE-FX");
	}
	if (id[6] & (1 << 4)) {
		printf("%s Ethernet: 100BASE-LX/LX10\n", pfx);
		add_item_string(items, "Transceiver type",
		"Ethernet: 100BASE-LX/LX10");
	}
	if (id[6] & (1 << 3)) {
		printf("%s Ethernet: 1000BASE-T\n", pfx);
		add_item_string(items, "Transceiver type",
		"Ethernet: 1000BASE-T");
	}
	if (id[6] & (1 << 2)) {
		printf("%s Ethernet: 1000BASE-CX\n", pfx);
		add_item_string(items, "Transceiver type",
		"Ethernet: 1000BASE-CX");
	}
	if (id[6] & (1 << 1)) {
		printf("%s Ethernet: 1000BASE-LX\n", pfx);
		add_item_string(items, "Transceiver type",
		"Ethernet: 1000BASE-LX");
	}
	if (id[6] & (1 << 0)) {
		printf("%s Ethernet: 1000BASE-SX\n", pfx);
		add_item_string(items, "Transceiver type",
		"Ethernet: 1000BASE-SX");
	}

	/* Fibre Channel link length */
	if (id[7] & (1 << 7)) {
		printf("%s FC: very long distance (V)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: very long distance (V)");
	}
	if (id[7] & (1 << 6)) {
		printf("%s FC: short distance (S)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: short distance (S)");
	}
	if (id[7] & (1 << 5)) {
		printf("%s FC: intermediate distance (I)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: intermediate distance (I)");
	}
	if (id[7] & (1 << 4)) {
		printf("%s FC: long distance (L)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: long distance (L)");
	}
	if (id[7] & (1 << 3)) {
		printf("%s FC: medium distance (M)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: medium distance (M)");
	}

	/* Fibre Channel transmitter technology */
	if (id[7] & (1 << 2)) {
		printf("%s FC: Shortwave laser, linear Rx (SA)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Shortwave laser, linear Rx (SA)");
	}
	if (id[7] & (1 << 1)) {
		printf("%s FC: Longwave laser (LC)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Longwave laser (LC)");
	}
	if (id[7] & (1 << 0)) {
		printf("%s FC: Electrical inter-enclosure (EL)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Electrical inter-enclosure (EL)");
	}
	if (id[8] & (1 << 7)) {
		printf("%s FC: Electrical intra-enclosure (EL)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Electrical intra-enclosure (EL)");
	}
	if (id[8] & (1 << 6)) {
		printf("%s FC: Shortwave laser w/o OFC (SN)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Shortwave laser w/o OFC (SN)");
	}
	if (id[8] & (1 << 5)) {
		printf("%s FC: Shortwave laser with OFC (SL)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Shortwave laser with OFC (SL)");
	}
	if (id[8] & (1 << 4)) {
		printf("%s FC: Longwave laser (LL)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Longwave laser (LL)");
	}
	if (id[8] & (1 << 3)) {
		printf("%s Active Cable\n", pfx);
		add_item_string(items, "Transceiver type",
		"Active Cable");
	}
	if (id[8] & (1 << 2)) {
		printf("%s Passive Cable\n", pfx);
		add_item_string(items, "Transceiver type",
		"Passive Cable");
	}
	if (id[8] & (1 << 1)) {
		printf("%s FC: Copper FC-BaseT\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Copper FC-BaseT");
	}

	/* Fibre Channel transmission media */
	if (id[9] & (1 << 7)) {
		printf("%s FC: Twin Axial Pair (TW)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Twin Axial Pair (TW)");
	}
	if (id[9] & (1 << 6)) {
		printf("%s FC: Twisted Pair (TP)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Twisted Pair (TP)");
	}
	if (id[9] & (1 << 5)) {
		printf("%s FC: Miniature Coax (MI)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Miniature Coax (MI)");
	}
	if (id[9] & (1 << 4)) {
		printf("%s FC: Video Coax (TV)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Video Coax (TV)");
	}
	if (id[9] & (1 << 3)) {
		printf("%s FC: Multimode, 62.5um (M6)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Multimode, 62.5um (M6)");
	}
	if (id[9] & (1 << 2)) {
		printf("%s FC: Multimode, 50um (M5)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Multimode, 50um (M5)");
	}
	if (id[9] & (1 << 0)) {
		printf("%s FC: Single Mode (SM)\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: Single Mode (SM)");
	}

	/* Fibre Channel speed */
	if (id[10] & (1 << 7)) {
		printf("%s FC: 1200 MBytes/sec\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: 1200 MBytes/sec");
	}
	if (id[10] & (1 << 6)) {
		printf("%s FC: 800 MBytes/sec\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: 800 MBytes/sec");
	}
	if (id[10] & (1 << 4)) {
		printf("%s FC: 400 MBytes/sec\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: 400 MBytes/sec");
	}
	if (id[10] & (1 << 2)) {
		printf("%s FC: 200 MBytes/sec\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: 200 MBytes/sec");
	}
	if (id[10] & (1 << 0)) {
		printf("%s FC: 100 MBytes/sec\n", pfx);
		add_item_string(items, "Transceiver type",
		"FC: 100 MBytes/sec");
	}

	/* Extended Specification Compliance Codes from SFF-8024 */
	switch (id[36]) {
	case 0x1:
		printf("%s Extended: 100G AOC or 25GAUI C2M AOC with worst BER of 5x10^(-5)\n",
		       pfx);
		add_item_string(items, "Transceiver type",
		"Extended: 100G AOC or 25GAUI C2M AOC with worst BER of 5x10^(-5)");
		break;
	case 0x2:
		printf("%s Extended: 100G Base-SR4 or 25GBase-SR\n", pfx);
		add_item_string(items, "Transceiver type",
		"Extended: 100G Base-SR4 or 25GBase-SR");
		break;
	case 0x3:
		printf("%s Extended: 100G Base-LR4 or 25GBase-LR\n", pfx);
		add_item_string(items, "Transceiver type",
		"Extended: 100G Base-LR4 or 25GBase-LR");
		break;
	case 0x4:
		printf("%s Extended: 100G Base-ER4 or 25GBase-ER\n", pfx);
		add_item_string(items, "Transceiver type",
		"Extended: 100G Base-ER4 or 25GBase-ER");
		break;
	case 0x8:
		printf("%s Extended: 100G ACC or 25GAUI C2M ACC with worst BER of 5x10^(-5)\n",
		       pfx);
		add_item_string(items, "Transceiver type",
		"Extended: 100G ACC or 25GAUI C2M ACC with worst BER of 5x10^(-5)");
		break;
	case 0xb:
		printf("%s Extended: 100G Base-CR4 or 25G Base-CR CA-L\n", pfx);
		add_item_string(items, "Transceiver type",
		"Extended: 100G Base-CR4 or 25G Base-CR CA-L");
		break;
	case 0xc:
		printf("%s Extended: 25G Base-CR CA-S\n", pfx);
		add_item_string(items, "Transceiver type",
		"Extended: 25G Base-CR CA-S");
		break;
	case 0xd:
		printf("%s Extended: 25G Base-CR CA-N\n", pfx);
		add_item_string(items, "Transceiver type",
		"Extended: 25G Base-CR CA-N");
		break;
	case 0x16:
		printf("%s Extended: 10Gbase-T with SFI electrical interface\n", pfx);
		add_item_string(items, "Transceiver type",
		"Extended: 10Gbase-T with SFI electrical interface");
		break;
	case 0x18:
		printf("%s Extended: 100G AOC or 25GAUI C2M AOC with worst BER of 10^(-12)\n",
		       pfx);
		add_item_string(items, "Transceiver type",
		"Extended: 100G AOC or 25GAUI C2M AOC with worst BER of 10^(-12)");
		break;
	case 0x19:
		printf("%s Extended: 100G ACC or 25GAUI C2M ACC with worst BER of 10^(-12)\n",
		       pfx);
		add_item_string(items, "Transceiver type",
		"Extended: 100G ACC or 25GAUI C2M ACC with worst BER of 10^(-12)");
		break;
	case 0x1c:
		printf("%s Extended: 10Gbase-T Short Reach\n", pfx);
		add_item_string(items, "Transceiver type",
		"Extended: 10Gbase-T Short Reach");
		break;
	default:
		break;
	}
}

static void sff_8079_show_encoding(const uint8_t *id, sff_item *items)
{
	sff_8024_show_encoding(id, 11, RTE_ETH_MODULE_SFF_8472, items);
}

static void sff_8079_show_rate_identifier(const uint8_t *id, sff_item *items)
{
	char val_string[TMP_STRING_SIZE];

	printf("%-41s : 0x%02x", "Rate identifier", id[13]);
	sprintf(val_string, "0x%02x", id[13]);

	switch (id[13]) {
	case 0x00:
		printf(" (unspecified)\n");
		strcat(val_string, " (unspecified)");
		break;
	case 0x01:
		printf(" (4/2/1G Rate_Select & AS0/AS1)\n");
		strcat(val_string, " (4/2/1G Rate_Select & AS0/AS1)");
		break;
	case 0x02:
		printf(" (8/4/2G Rx Rate_Select only)\n");
		strcat(val_string, " (8/4/2G Rx Rate_Select only)");
		break;
	case 0x03:
		printf(" (8/4/2G Independent Rx & Tx Rate_Select)\n");
		strcat(val_string, " (8/4/2G Independent Rx & Tx Rate_Select)");
		break;
	case 0x04:
		printf(" (8/4/2G Tx Rate_Select only)\n");
		strcat(val_string, " (8/4/2G Tx Rate_Select only)");
		break;
	default:
		printf(" (reserved or unknown)\n");
		strcat(val_string, " (reserved or unknown)");
		break;
	}
	add_item_string(items, "Rate identifier", val_string);
}

static void sff_8079_show_oui(const uint8_t *id, sff_item *items)
{
	sff_8024_show_oui(id, 37, items);
}

static void
sff_8079_show_wavelength_or_copper_compliance(const uint8_t *id,
					      sff_item *items)
{
	char val_string[TMP_STRING_SIZE];

	if (id[8] & (1 << 2)) {
		printf("%-41s : 0x%02x", "Passive Cu cmplnce.", id[60]);
		sprintf(val_string, "0x%02x", id[60]);
		switch (id[60]) {
		case 0x00:
			printf(" (unspecified)");
			strcat(val_string, " (unspecified)");
			break;
		case 0x01:
			printf(" (SFF-8431 appendix E)");
			strcat(val_string, " (SFF-8431 appendix E)");
			break;
		default:
			printf(" (unknown)");
			strcat(val_string, " (unknown)");
			break;
		}
		printf(" [SFF-8472 rev10.4 only]\n");
		strcat(val_string, " [SFF-8472 rev10.4 only]");
		add_item_string(items, "Passive Cu cmplnce.", val_string);
	} else if (id[8] & (1 << 3)) {
		printf("%-41s : 0x%02x", "Active Cu cmplnce.", id[60]);
		sprintf(val_string, "0x%02x", id[60]);
		switch (id[60]) {
		case 0x00:
			printf(" (unspecified)");
			strcat(val_string, " (unspecified)");
			break;
		case 0x01:
			printf(" (SFF-8431 appendix E)");
			strcat(val_string, " (SFF-8431 appendix E)");
			break;
		case 0x04:
			printf(" (SFF-8431 limiting)");
			strcat(val_string, " (SFF-8431 limiting)");
			break;
		default:
			printf(" (unknown)");
			strcat(val_string, " (unknown)");
			break;
		}
		printf(" [SFF-8472 rev10.4 only]\n");
		strcat(val_string, " [SFF-8472 rev10.4 only]");
		add_item_string(items, "Active Cu cmplnce.", val_string);
	} else {
		printf("%-41s : %unm\n", "Laser wavelength",
		       (id[60] << 8) | id[61]);
		sprintf(val_string, "%unm", (id[60] << 8) | id[61]);
		add_item_string(items, "Laser wavelength", val_string);
	}
}

static void sff_8079_show_options(const uint8_t *id, sff_item *items)
{
	static const char *pfx =
		"Option                                    :";
	char val_string[TMP_STRING_SIZE];

	printf("%-41s : 0x%02x 0x%02x\n", "Option values", id[64], id[65]);
	sprintf(val_string, "0x%02x 0x%02x", id[64], id[65]);
	add_item_string(items, "Option values", val_string);

	if (id[65] & (1 << 1)) {
		printf("%s RX_LOS implemented\n", pfx);
		add_item_string(items, "Option",
				       "RX_LOS implemented");
	}
	if (id[65] & (1 << 2)) {
		printf("%s RX_LOS implemented, inverted\n", pfx);
		add_item_string(items, "Option",
				       "RX_LOS implemented, inverted");
	}
	if (id[65] & (1 << 3)) {
		printf("%s TX_FAULT implemented\n", pfx);
		add_item_string(items, "Option",
				       "TX_FAULT implemented");
	}
	if (id[65] & (1 << 4)) {
		printf("%s TX_DISABLE implemented\n", pfx);
		add_item_string(items, "Option",
				       "TX_DISABLE implemented");
	}
	if (id[65] & (1 << 5)) {
		printf("%s RATE_SELECT implemented\n", pfx);
		add_item_string(items, "Option",
				       "RATE_SELECT implemented");
	}
	if (id[65] & (1 << 6)) {
		printf("%s Tunable transmitter technology\n", pfx);
		add_item_string(items, "Option",
				       "Tunable transmitter technology");
	}
	if (id[65] & (1 << 7)) {
		printf("%s Receiver decision threshold implemented\n", pfx);
		add_item_string(items, "Option",
				       "Receiver decision threshold implemented");
	}
	if (id[64] & (1 << 0)) {
		printf("%s Linear receiver output implemented\n", pfx);
		add_item_string(items, "Option",
				       "Linear receiver output implemented");
	}
	if (id[64] & (1 << 1)) {
		printf("%s Power level 2 requirement\n", pfx);
		add_item_string(items, "Option",
				       "Power level 2 requirement");
	}
	if (id[64] & (1 << 2)) {
		printf("%s Cooled transceiver implemented\n", pfx);
		add_item_string(items, "Option",
				       "Cooled transceiver implemented");
	}
	if (id[64] & (1 << 3)) {
		printf("%s Retimer or CDR implemented\n", pfx);
		add_item_string(items, "Option",
				       "Retimer or CDR implemented");
	}
	if (id[64] & (1 << 4)) {
		printf("%s Paging implemented\n", pfx);
		add_item_string(items, "Option",
				       "Paging implemented");
	}
	if (id[64] & (1 << 5)) {
		printf("%s Power level 3 requirement\n", pfx);
		add_item_string(items, "Option",
				       "Power level 3 requirement");
	}
}

void sff_8079_show_all(const uint8_t *id, sff_item *items)
{
	sff_8079_show_identifier(id, items);
	if (((id[0] == 0x02) || (id[0] == 0x03)) && (id[1] == 0x04)) {
		unsigned int br_nom, br_min, br_max;
		char val_string[TMP_STRING_SIZE];

		if (id[12] == 0) {
			br_nom = br_min = br_max = 0;
		} else if (id[12] == 255) {
			br_nom = id[66] * 250;
			br_max = id[67];
			br_min = id[67];
		} else {
			br_nom = id[12] * 100;
			br_max = id[66];
			br_min = id[67];
		}
		sff_8079_show_ext_identifier(id, items);
		sff_8079_show_connector(id, items);
		sff_8079_show_transceiver(id, items);
		sff_8079_show_encoding(id, items);

		printf("%-41s : %u%s\n", "BR, Nominal", br_nom, "MBd");
		sprintf(val_string, "%uMBd", br_nom);
		add_item_string(items, "BR, Nominal", val_string);

		sff_8079_show_rate_identifier(id, items);
		sff_show_value_with_unit(id, 14,
					     "Length (SMF,km)", 1, "km", items);
		sff_show_value_with_unit(id, 15, "Length (SMF)", 100, "m", items);
		sff_show_value_with_unit(id, 16, "Length (50um)", 10, "m", items);
		sff_show_value_with_unit(id, 17,
					     "Length (62.5um)", 10, "m", items);
		sff_show_value_with_unit(id, 18, "Length (Copper)", 1, "m", items);
		sff_show_value_with_unit(id, 19, "Length (OM3)", 10, "m", items);
		sff_8079_show_wavelength_or_copper_compliance(id, items);
		sff_show_ascii(id, 20, 35, "Vendor name", items);
		sff_8079_show_oui(id, items);
		sff_show_ascii(id, 40, 55, "Vendor PN", items);
		sff_show_ascii(id, 56, 59, "Vendor rev", items);
		sff_8079_show_options(id, items);

		printf("%-41s : %u%s\n", "BR margin, max", br_max, "%");
		sprintf(val_string, "%u%%", br_max);
		add_item_string(items, "BR margin, max", val_string);
		printf("%-41s : %u%s\n", "BR margin, min", br_min, "%");
		sprintf(val_string, "%u%%", br_min);
		add_item_string(items, "BR margin, min", val_string);

		sff_show_ascii(id, 68, 83, "Vendor SN", items);
		sff_show_ascii(id, 84, 91, "Date code", items);
	}
}
