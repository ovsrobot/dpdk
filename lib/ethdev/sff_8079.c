/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
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

static void sff_8079_show_identifier(const uint8_t *data, struct sff_item *items)
{
	sff_8024_show_identifier(data, 0, items);
}

static void sff_8079_show_ext_identifier(const uint8_t *data, struct sff_item *items)
{
	char val_string[SFF_ITEM_VAL_COMPOSE_SIZE];

	snprintf(val_string, sizeof(val_string), "0x%02x", data[1]);
	if (data[1] == 0x00)
		strlcat(val_string, " (GBIC not specified / not MOD_DEF compliant)",
			sizeof(val_string));
	else if (data[1] == 0x04)
		strlcat(val_string, " (GBIC/SFP defined by 2-wire interface ID)",
			sizeof(val_string));
	else if (data[1] <= 0x07) {
		char tmp[SFF_ITEM_VAL_COMPOSE_SIZE];
		snprintf(tmp, sizeof(tmp), " (GBIC compliant with MOD_DEF %u)", data[1]);
		strlcat(val_string, tmp, sizeof(val_string));
	} else
		strlcat(val_string, " (unknown)", sizeof(val_string));
	add_item_string(items, "Extended identifier", val_string);
}

static void sff_8079_show_connector(const uint8_t *data, struct sff_item *items)
{
	sff_8024_show_connector(data, 2, items);
}

static void sff_8079_show_transceiver(const uint8_t *data, struct sff_item *items)
{
	static const char *name = "Transceiver type";
	char val_string[SFF_ITEM_VAL_COMPOSE_SIZE];

	snprintf(val_string, sizeof(val_string),
		"0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x",
		data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[36]);
	add_item_string(items, "Transceiver codes", val_string);

	/* 10G Ethernet Compliance Codes */
	if (data[3] & (1 << 7))
		add_item_string(items, "10G Ethernet transceiver type",
		"10G Ethernet: 10G Base-ER [SFF-8472 rev10.4 onwards]");
	if (data[3] & (1 << 6))
		add_item_string(items, name, "10G Ethernet: 10G Base-LRM");
	if (data[3] & (1 << 5))
		add_item_string(items, name, "10G Ethernet: 10G Base-LR");
	if (data[3] & (1 << 4))
		add_item_string(items, name, "10G Ethernet: 10G Base-SR");

	/* Infiniband Compliance Codes */
	if (data[3] & (1 << 3))
		add_item_string(items, name, "Infiniband: 1X SX");
	if (data[3] & (1 << 2))
		add_item_string(items, name, "Infiniband: 1X LX");
	if (data[3] & (1 << 1))
		add_item_string(items, name, "Infiniband: 1X Copper Active");
	if (data[3] & (1 << 0))
		add_item_string(items, name, "Infiniband: 1X Copper Passive");

	/* ESCON Compliance Codes */
	if (data[4] & (1 << 7))
		add_item_string(items, name, "ESCON: ESCON MMF, 1310nm LED");
	if (data[4] & (1 << 6))
		add_item_string(items, name, "ESCON: ESCON SMF, 1310nm Laser");

	/* SONET Compliance Codes */
	if (data[4] & (1 << 5))
		add_item_string(items, name, "SONET: OC-192, short reach");
	if (data[4] & (1 << 4))
		add_item_string(items, name, "SONET: SONET reach specifier bit 1");
	if (data[4] & (1 << 3))
		add_item_string(items, name, "SONET: SONET reach specifier bit 2");
	if (data[4] & (1 << 2))
		add_item_string(items, name, "SONET: OC-48, long reach");
	if (data[4] & (1 << 1))
		add_item_string(items, name, "SONET: OC-48, intermediate reach");
	if (data[4] & (1 << 0))
		add_item_string(items, name, "SONET: OC-48, short reach");
	if (data[5] & (1 << 6))
		add_item_string(items, name, "SONET: OC-12, single mode, long reach");
	if (data[5] & (1 << 5))
		add_item_string(items, name, "SONET: OC-12, single mode, inter. reach");
	if (data[5] & (1 << 4))
		add_item_string(items, name, "SONET: OC-12, short reach");
	if (data[5] & (1 << 2))
		add_item_string(items, name, "SONET: OC-3, single mode, long reach");
	if (data[5] & (1 << 1))
		add_item_string(items, name, "SONET: OC-3, single mode, inter. reach");
	if (data[5] & (1 << 0))
		add_item_string(items, name, "SONET: OC-3, short reach");

	/* Ethernet Compliance Codes */
	if (data[6] & (1 << 7))
		add_item_string(items, name, "Ethernet: BASE-PX");
	if (data[6] & (1 << 6))
		add_item_string(items, name, "Ethernet: BASE-BX10");
	if (data[6] & (1 << 5))
		add_item_string(items, name, "Ethernet: 100BASE-FX");
	if (data[6] & (1 << 4))
		add_item_string(items, name, "Ethernet: 100BASE-LX/LX10");
	if (data[6] & (1 << 3))
		add_item_string(items, name, "Ethernet: 1000BASE-T");
	if (data[6] & (1 << 2))
		add_item_string(items, name, "Ethernet: 1000BASE-CX");
	if (data[6] & (1 << 1))
		add_item_string(items, name, "Ethernet: 1000BASE-LX");
	if (data[6] & (1 << 0))
		add_item_string(items, name, "Ethernet: 1000BASE-SX");

	/* Fibre Channel link length */
	if (data[7] & (1 << 7))
		add_item_string(items, name, "FC: very long distance (V)");
	if (data[7] & (1 << 6))
		add_item_string(items, name, "FC: short distance (S)");
	if (data[7] & (1 << 5))
		add_item_string(items, name, "FC: intermediate distance (I)");
	if (data[7] & (1 << 4))
		add_item_string(items, name, "FC: long distance (L)");
	if (data[7] & (1 << 3))
		add_item_string(items, name, "FC: medium distance (M)");

	/* Fibre Channel transmitter technology */
	if (data[7] & (1 << 2))
		add_item_string(items, name, "FC: Shortwave laser, linear Rx (SA)");
	if (data[7] & (1 << 1))
		add_item_string(items, name, "FC: Longwave laser (LC)");
	if (data[7] & (1 << 0))
		add_item_string(items, name, "FC: Electrical inter-enclosure (EL)");
	if (data[8] & (1 << 7))
		add_item_string(items, name, "FC: Electrical intra-enclosure (EL)");
	if (data[8] & (1 << 6))
		add_item_string(items, name, "FC: Shortwave laser w/o OFC (SN)");
	if (data[8] & (1 << 5))
		add_item_string(items, name, "FC: Shortwave laser with OFC (SL)");
	if (data[8] & (1 << 4))
		add_item_string(items, name, "FC: Longwave laser (LL)");
	if (data[8] & (1 << 3))
		add_item_string(items, name, "Active Cable");
	if (data[8] & (1 << 2))
		add_item_string(items, name, "Passive Cable");
	if (data[8] & (1 << 1))
		add_item_string(items, name, "FC: Copper FC-BaseT");

	/* Fibre Channel transmission media */
	if (data[9] & (1 << 7))
		add_item_string(items, name, "FC: Twin Axial Pair (TW)");
	if (data[9] & (1 << 6))
		add_item_string(items, name, "FC: Twisted Pair (TP)");
	if (data[9] & (1 << 5))
		add_item_string(items, name, "FC: Miniature Coax (MI)");
	if (data[9] & (1 << 4))
		add_item_string(items, name, "FC: Video Coax (TV)");
	if (data[9] & (1 << 3))
		add_item_string(items, name, "FC: Multimode, 62.5um (M6)");
	if (data[9] & (1 << 2))
		add_item_string(items, name, "FC: Multimode, 50um (M5)");
	if (data[9] & (1 << 0))
		add_item_string(items, name, "FC: Single Mode (SM)");

	/* Fibre Channel speed */
	if (data[10] & (1 << 7))
		add_item_string(items, name, "FC: 1200 MBytes/sec");
	if (data[10] & (1 << 6))
		add_item_string(items, name, "FC: 800 MBytes/sec");
	if (data[10] & (1 << 4))
		add_item_string(items, name, "FC: 400 MBytes/sec");
	if (data[10] & (1 << 2))
		add_item_string(items, name, "FC: 200 MBytes/sec");
	if (data[10] & (1 << 0))
		add_item_string(items, name, "FC: 100 MBytes/sec");

	/* Extended Specification Compliance Codes from SFF-8024 */
	switch (data[36]) {
	case 0x1:
		add_item_string(items, name,
			"Extended: 100G AOC or 25GAUI C2M AOC with worst BER of 5x10^(-5)");
		break;
	case 0x2:
		add_item_string(items, name, "Extended: 100G Base-SR4 or 25GBase-SR");
		break;
	case 0x3:
		add_item_string(items, name, "Extended: 100G Base-LR4 or 25GBase-LR");
		break;
	case 0x4:
		add_item_string(items, name, "Extended: 100G Base-ER4 or 25GBase-ER");
		break;
	case 0x8:
		add_item_string(items, name,
			"Extended: 100G ACC or 25GAUI C2M ACC with worst BER of 5x10^(-5)");
		break;
	case 0xb:
		add_item_string(items, name, "Extended: 100G Base-CR4 or 25G Base-CR CA-L");
		break;
	case 0xc:
		add_item_string(items, name, "Extended: 25G Base-CR CA-S");
		break;
	case 0xd:
		add_item_string(items, name, "Extended: 25G Base-CR CA-N");
		break;
	case 0x16:
		add_item_string(items, name, "Extended: 10Gbase-T with SFI electrical interface");
		break;
	case 0x18:
		add_item_string(items, name,
			"Extended: 100G AOC or 25GAUI C2M AOC with worst BER of 10^(-12)");
		break;
	case 0x19:
		add_item_string(items, name,
			"Extended: 100G ACC or 25GAUI C2M ACC with worst BER of 10^(-12)");
		break;
	case 0x1c:
		add_item_string(items, name, "Extended: 10Gbase-T Short Reach");
		break;
	default:
		break;
	}
}

static void sff_8079_show_encoding(const uint8_t *data, struct sff_item *items)
{
	sff_8024_show_encoding(data, 11, RTE_ETH_MODULE_SFF_8472, items);
}

static void sff_8079_show_rate_identifier(const uint8_t *data, struct sff_item *items)
{
	char val_string[SFF_ITEM_VAL_COMPOSE_SIZE];

	snprintf(val_string, sizeof(val_string), "0x%02x", data[13]);

	switch (data[13]) {
	case 0x00:
		printf(" (unspecified)\n");
		strlcat(val_string, " (unspecified)", sizeof(val_string));
		break;
	case 0x01:
		strlcat(val_string, " (4/2/1G Rate_Select & AS0/AS1)", sizeof(val_string));
		break;
	case 0x02:
		strlcat(val_string, " (8/4/2G Rx Rate_Select only)", sizeof(val_string));
		break;
	case 0x03:
		strlcat(val_string, " (8/4/2G Independent Rx & Tx Rate_Select)",
			sizeof(val_string));
		break;
	case 0x04:
		strlcat(val_string, " (8/4/2G Tx Rate_Select only)", sizeof(val_string));
		break;
	default:
		strlcat(val_string, " (reserved or unknown)", sizeof(val_string));
		break;
	}
	add_item_string(items, "Rate identifier", val_string);
}

static void sff_8079_show_oui(const uint8_t *data, struct sff_item *items)
{
	sff_8024_show_oui(data, 37, items);
}

static void
sff_8079_show_wavelength_or_copper_compliance(const uint8_t *data,
					      struct sff_item *items)
{
	char val_string[SFF_ITEM_VAL_COMPOSE_SIZE];

	if (data[8] & (1 << 2)) {
		snprintf(val_string, sizeof(val_string), "0x%02x", data[60]);
		switch (data[60]) {
		case 0x00:
			strlcat(val_string, " (unspecified)", sizeof(val_string));
			break;
		case 0x01:
			strlcat(val_string, " (SFF-8431 appendix E)", sizeof(val_string));
			break;
		default:
			strlcat(val_string, " (unknown)", sizeof(val_string));
			break;
		}
		strlcat(val_string, " [SFF-8472 rev10.4 only]", sizeof(val_string));
		add_item_string(items, "Passive Cu cmplnce.", val_string);
	} else if (data[8] & (1 << 3)) {
		snprintf(val_string, sizeof(val_string), "0x%02x", data[60]);
		switch (data[60]) {
		case 0x00:
			strlcat(val_string, " (unspecified)", sizeof(val_string));
			break;
		case 0x01:
			strlcat(val_string, " (SFF-8431 appendix E)", sizeof(val_string));
			break;
		case 0x04:
			strlcat(val_string, " (SFF-8431 limiting)", sizeof(val_string));
			break;
		default:
			strlcat(val_string, " (unknown)", sizeof(val_string));
			break;
		}
		strlcat(val_string, " [SFF-8472 rev10.4 only]", sizeof(val_string));
		add_item_string(items, "Active Cu cmplnce.", val_string);
	} else {
		snprintf(val_string, sizeof(val_string), "%unm", (data[60] << 8) | data[61]);
		add_item_string(items, "Laser wavelength", val_string);
	}
}

static void sff_8079_show_options(const uint8_t *data, struct sff_item *items)
{
	static const char *name = "Option";
	char val_string[SFF_ITEM_VAL_COMPOSE_SIZE];

	snprintf(val_string, sizeof(val_string), "0x%02x 0x%02x", data[64], data[65]);
	add_item_string(items, "Option values", val_string);

	if (data[65] & (1 << 1))
		add_item_string(items, name, "RX_LOS implemented");
	if (data[65] & (1 << 2))
		add_item_string(items, name, "RX_LOS implemented, inverted");
	if (data[65] & (1 << 3))
		add_item_string(items, name, "TX_FAULT implemented");
	if (data[65] & (1 << 4))
		add_item_string(items, name, "TX_DISABLE implemented");
	if (data[65] & (1 << 5))
		add_item_string(items, name, "RATE_SELECT implemented");
	if (data[65] & (1 << 6))
		add_item_string(items, name, "Tunable transmitter technology");
	if (data[65] & (1 << 7))
		add_item_string(items, name, "Receiver decision threshold implemented");
	if (data[64] & (1 << 0))
		add_item_string(items, name, "Linear receiver output implemented");
	if (data[64] & (1 << 1))
		add_item_string(items, name, "Power level 2 requirement");
	if (data[64] & (1 << 2))
		add_item_string(items, name, "Cooled transceiver implemented");
	if (data[64] & (1 << 3))
		add_item_string(items, name, "Retimer or CDR implemented");
	if (data[64] & (1 << 4))
		add_item_string(items, name, "Paging implemented");
	if (data[64] & (1 << 5))
		add_item_string(items, name, "Power level 3 requirement");
}

void sff_8079_show_all(const uint8_t *data, struct sff_item *items)
{
	sff_8079_show_identifier(data, items);
	if (((data[0] == 0x02) || (data[0] == 0x03)) && (data[1] == 0x04)) {
		unsigned int br_nom, br_min, br_max;
		char val_string[SFF_ITEM_VAL_COMPOSE_SIZE];

		if (data[12] == 0) {
			br_nom = br_min = br_max = 0;
		} else if (data[12] == 255) {
			br_nom = data[66] * 250;
			br_max = data[67];
			br_min = data[67];
		} else {
			br_nom = data[12] * 100;
			br_max = data[66];
			br_min = data[67];
		}
		sff_8079_show_ext_identifier(data, items);
		sff_8079_show_connector(data, items);
		sff_8079_show_transceiver(data, items);
		sff_8079_show_encoding(data, items);

		snprintf(val_string, sizeof(val_string), "%uMBd", br_nom);
		add_item_string(items, "BR, Nominal", val_string);

		sff_8079_show_rate_identifier(data, items);
		sff_show_value_with_unit(data, 14,
					 "Length (SMF,km)", 1, "km", items);
		sff_show_value_with_unit(data, 15, "Length (SMF)", 100, "m", items);
		sff_show_value_with_unit(data, 16, "Length (50um)", 10, "m", items);
		sff_show_value_with_unit(data, 17,
					 "Length (62.5um)", 10, "m", items);
		sff_show_value_with_unit(data, 18, "Length (Copper)", 1, "m", items);
		sff_show_value_with_unit(data, 19, "Length (OM3)", 10, "m", items);
		sff_8079_show_wavelength_or_copper_compliance(data, items);
		sff_show_ascii(data, 20, 35, "Vendor name", items);
		sff_8079_show_oui(data, items);
		sff_show_ascii(data, 40, 55, "Vendor PN", items);
		sff_show_ascii(data, 56, 59, "Vendor rev", items);
		sff_8079_show_options(data, items);

		snprintf(val_string, sizeof(val_string), "%u%%", br_max);
		add_item_string(items, "BR margin, max", val_string);
		snprintf(val_string, sizeof(val_string), "%u%%", br_min);
		add_item_string(items, "BR margin, min", val_string);

		sff_show_ascii(data, 68, 83, "Vendor SN", items);
		sff_show_ascii(data, 84, 91, "Date code", items);
	}
}
