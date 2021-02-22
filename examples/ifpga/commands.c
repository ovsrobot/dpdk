/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2021 Intel Corporation.
 * All rights reserved.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline.h>

#include "commands.h"

static int parse_pciaddr(const char *bdf, opae_pci_device *id)
{
	size_t len = 0;
	unsigned int domain = 0;
	unsigned int bus = 0;
	unsigned int devid = 0;
	unsigned int function = 0;

	if (!bdf || !id)
		return -EINVAL;

	len = strlen(bdf);
	if ((len < 5) || (len > 12))
		return -EINVAL;

	len = sscanf(bdf, "%x:%x:%x.%d", &domain, &bus, &devid, &function);
	if (len == 4) {
		snprintf(id->bdf, sizeof(id->bdf), "%04x:%02x:%02x.%d",
			domain, bus, devid, function);
	} else {
		len = sscanf(bdf, "%x:%x.%d", &bus, &devid, &function);
		if (len == 3) {
			snprintf(id->bdf, sizeof(id->bdf), "%04x:%02x:%02x.%d",
				0, bus, devid, function);
		} else {
			return -EINVAL;
		}
	}
	return 0;
}

static void uuid_to_str(opae_uuid *id, uuid_str *str)
{
	uint8_t *b = NULL;
	char *p = NULL;
	int i, j;

	if (!id || !str)
		return;

	b = &id->b[15];
	p = str->s;
	for (i = 0; i < 4; i++, b--, p += 2)
		sprintf(p, "%02x", *b);
	sprintf(p++, "-");
	for (i = 0; i < 3; i++) {
		for (j = 0; j < 2; j++, b--, p += 2)
			sprintf(p, "%02x", *b);
		sprintf(p++, "-");
	}
	for (i = 0; i < 6; i++, b--, p += 2)
		sprintf(p, "%02x", *b);
}

/* *** GET API VERSION *** */
struct cmd_version_result {
	cmdline_fixed_string_t cmd;
};

static void cmd_version_parsed(__rte_unused void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	opae_api_version ver;
	opae_get_api_version(&ver);
	cmdline_printf(cl, "%d.%d.%d\n", ver.major, ver.minor, ver.micro);
}

cmdline_parse_token_string_t cmd_version_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_version_result, cmd, "get_api_version");

cmdline_parse_inst_t cmd_get_api_version = {
	.f = cmd_version_parsed,
	.data = NULL,
	.help_str = "get OPAE API version",
	.tokens = {
		(void *)&cmd_version_cmd,
		NULL,
	},
};

/* *** GET PROC TYPE *** */
struct cmd_proc_type_result {
	cmdline_fixed_string_t cmd;
};

static void cmd_proc_type_parsed(__rte_unused void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	int type = opae_get_proc_type();

	if (type == 0)
		cmdline_printf(cl, "Primary\n");
	else if (type == 1)
		cmdline_printf(cl, "Secondary\n");
	else
		cmdline_printf(cl, "Unknown\n");
}

cmdline_parse_token_string_t cmd_proc_type_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_proc_type_result, cmd, "get_proc_type");

cmdline_parse_inst_t cmd_get_proc_type = {
	.f = cmd_proc_type_parsed,
	.data = NULL,
	.help_str = "get DPDK process type",
	.tokens = {
		(void *)&cmd_proc_type_cmd,
		NULL,
	},
};

/* *** GET IMAGE INFO *** */
struct cmd_image_info_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t path;
};

static void cmd_image_info_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_image_info_result *res = parsed_result;
	opae_img_info info;

	if (opae_get_image_info(res->path, &info) == 0) {
		cmdline_printf(cl, "%-16s", "Type:");
		if (info.type == OPAE_IMG_TYPE_BBS)
			cmdline_printf(cl, "FPGA_BBS\n");
		else if (info.type == OPAE_IMG_TYPE_BMC)
			cmdline_printf(cl, "BMC\n");
		else if (info.type == OPAE_IMG_TYPE_GBS)
			cmdline_printf(cl, "FGPA_GBS\n");
		else
			cmdline_printf(cl, "Unknown\n");
		cmdline_printf(cl, "%-16s", "Action:");
		if (info.subtype == OPAE_IMG_SUBTYPE_UPDATE)
			cmdline_printf(cl, "UPDATE\n");
		else if (info.subtype == OPAE_IMG_SUBTYPE_CANCELLATION)
			cmdline_printf(cl, "CANCELLATION\n");
		else if (info.subtype == OPAE_IMG_SUBTYPE_ROOT_KEY_HASH_256)
			cmdline_printf(cl, "ROOT_HASH_256\n");
		else if (info.subtype == OPAE_IMG_SUBTYPE_ROOT_KEY_HASH_384)
			cmdline_printf(cl, "ROOT_HASH_384\n");
		else
			cmdline_printf(cl, "Unknown\n");
		cmdline_printf(cl, "%-16s%u\n", "Total length:",
			info.total_len);
		cmdline_printf(cl, "%-16s%u\n", "Payload offset:",
			info.payload_offset);
		cmdline_printf(cl, "%-16s%u\n", "Payload length:",
			info.payload_len);
	} else {
		cmdline_printf(cl, "Invalid image file\n");
	}
}

cmdline_parse_token_string_t cmd_image_info_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_image_info_result, cmd,
		"get_image_info");
cmdline_parse_token_string_t cmd_image_info_path =
	TOKEN_STRING_INITIALIZER(struct cmd_image_info_result, path, NULL);

cmdline_parse_inst_t cmd_get_image_info = {
	.f = cmd_image_info_parsed,
	.data = NULL,
	.help_str = "get information of image file",
	.tokens = {
		(void *)&cmd_image_info_cmd,
		(void *)&cmd_image_info_path,
		NULL,
	},
};

/* *** GET STATUS *** */
struct cmd_get_status_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
};

static void cmd_get_status_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_get_status_result *res = parsed_result;
	opae_pci_device id;
	uint32_t stat, prog;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (opae_load_rsu_status(&id, &stat, &prog) == 0) {
		cmdline_printf(cl, "%-10s", "Status:");
		if (stat == 0)
			cmdline_printf(cl, "IDLE\n");
		else if (stat == 1)
			cmdline_printf(cl, "PREPARE\n");
		else if (stat == 2)
			cmdline_printf(cl, "PROGRAM\n");
		else if (stat == 3)
			cmdline_printf(cl, "COPY\n");
		else if (stat == 4)
			cmdline_printf(cl, "REBOOT\n");
		else
			cmdline_printf(cl, "unknown\n");
		cmdline_printf(cl, "%-10s%u%%\n", "Progress:", prog);
	} else {
		cmdline_printf(cl, "Failed\n");
	}
}

cmdline_parse_token_string_t cmd_get_status_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_get_status_result, cmd, "get_status");
cmdline_parse_token_string_t cmd_get_status_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_get_status_result, bdf, NULL);

cmdline_parse_inst_t cmd_get_status = {
	.f = cmd_get_status_parsed,
	.data = NULL,
	.help_str = "get current status & progress of FPGA",
	.tokens = {
		(void *)&cmd_get_status_cmd,
		(void *)&cmd_get_status_bdf,
		NULL,
	},
};

/* *** GET PROPERTY *** */
struct cmd_property_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
	int32_t type;
};

static void cmd_property_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_property_result *res = parsed_result;
	opae_pci_device id;
	opae_fpga_property prop;
	uuid_str str;
	uint32_t port = 0;

	switch (res->type) {
	case 0:
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		cmdline_printf(cl, "%d is invalid type of property\n",
			res->type);
		return;
	}
	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (opae_get_property(&id, &prop, res->type) == 0) {
		if ((res->type == 0) || (res->type == 1)) {
			cmdline_printf(cl, "%s:\n", "PCI");
			cmdline_printf(cl, " %-16s : %s\n",
				"PCIe s:b:d.f", prop.pci.pci_addr);
			cmdline_printf(cl, " %-16s : %s\n",
				"kernel driver", prop.pci.drv_name);
		}
		if ((res->type == 0) || (res->type == 2)) {
			cmdline_printf(cl, "%s:\n", "FME");
			cmdline_printf(cl, " %-16s : %s\n",
				"platform", prop.fme.platform_name);
			cmdline_printf(cl, " %-16s : %s\n",
				"DCP version", prop.fme.dcp_version);
			cmdline_printf(cl, " %-16s : %s\n",
				"phase", prop.fme.release_name);
			cmdline_printf(cl, " %-16s : %s\n",
				"interface", prop.fme.interface_type);
			cmdline_printf(cl, " %-16s : %s\n",
				"build version", prop.fme.build_version);
			cmdline_printf(cl, " %-16s : %u\n",
				"ports num", prop.fme.num_ports);
			cmdline_printf(cl, " %-16s : %s\n",
				"boot page", prop.fme.boot_page ? "user" : "factory");
			uuid_to_str(&prop.fme.pr_id, &str);
			cmdline_printf(cl, " %-16s : %s\n", "pr interface id",
				str.s);
		}
		if ((res->type == 0) || (res->type == 4)) {
			for (port = 0; port < prop.fme.num_ports; port++) {
				cmdline_printf(cl, "%s%d:\n", "PORT", port);
				cmdline_printf(cl, " %-16s : %s\n",
					"access type",
					prop.port[port].type ? "VF" : "PF");
				uuid_to_str(&prop.port[port].afu_id, &str);
				cmdline_printf(cl, " %-16s : %s\n",
					"accelerator id", str.s);
			}
		}
		if ((res->type == 0) || (res->type == 8)) {
			cmdline_printf(cl, "%s:\n", "BMC");
			cmdline_printf(cl, " %-16s : %s\n",
				"MAX10 version", prop.bmc.bmc_version);
			cmdline_printf(cl, " %-16s : %s\n",
				"NIOS FW version", prop.bmc.fw_version);
		}
	} else {
		cmdline_printf(cl, "Failed\n");
	}
}

cmdline_parse_token_string_t cmd_property_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_property_result, cmd, "get_property");
cmdline_parse_token_string_t cmd_property_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_property_result, bdf, NULL);
cmdline_parse_token_num_t cmd_property_type =
	TOKEN_NUM_INITIALIZER(struct cmd_property_result, type, RTE_INT32);

cmdline_parse_inst_t cmd_get_property = {
	.f = cmd_property_parsed,
	.data = NULL,
	.help_str = "get property of FPGA",
	.tokens = {
		(void *)&cmd_property_cmd,
		(void *)&cmd_property_bdf,
		(void *)&cmd_property_type,
		NULL,
	},
};

/* *** GET PHY INFO *** */
struct cmd_phy_info_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
};

static void cmd_phy_info_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_phy_info_result *res = parsed_result;
	opae_pci_device id;
	opae_phy_info info;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (opae_get_phy_info(&id, &info) == 0) {
		cmdline_printf(cl, " %-16s : %u\n",
			"retimers num", info.num_retimers);
		cmdline_printf(cl, " %-16s : %uG\n",
			"link speed", info.link_speed);
		cmdline_printf(cl, " %-16s : %02xh\n",
			"link status", info.link_status);
	} else {
		cmdline_printf(cl, "Failed\n");
	}
}

cmdline_parse_token_string_t cmd_phy_info_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_phy_info_result, cmd, "get_phy_info");
cmdline_parse_token_string_t cmd_phy_info_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_phy_info_result, bdf, NULL);

cmdline_parse_inst_t cmd_phy_info = {
	.f = cmd_phy_info_parsed,
	.data = NULL,
	.help_str = "get information of PHY",
	.tokens = {
		(void *)&cmd_phy_info_cmd,
		(void *)&cmd_phy_info_bdf,
		NULL,
	},
};

/* *** GET PARENT *** */
struct cmd_parent_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
};

static void cmd_parent_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_parent_result *res = parsed_result;
	opae_pci_device id;
	opae_pci_device parent;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (opae_get_parent(&id, &parent) > 0)
		cmdline_printf(cl, "%s\n", parent.bdf);
	else
		cmdline_printf(cl, "Failed\n");
}

cmdline_parse_token_string_t cmd_parent_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_parent_result, cmd, "get_parent");
cmdline_parse_token_string_t cmd_parent_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_parent_result, bdf, NULL);

cmdline_parse_inst_t cmd_get_parent = {
	.f = cmd_parent_parsed,
	.data = NULL,
	.help_str = "get parent PCI device of FPGA",
	.tokens = {
		(void *)&cmd_parent_cmd,
		(void *)&cmd_parent_bdf,
		NULL,
	},
};

/* *** GET CHILD *** */
struct cmd_child_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
};

static void cmd_child_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_child_result *res = parsed_result;
	opae_pci_device id;
	pcidev_id child;
	int i, count = 0;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	count = opae_get_child(&id, NULL, 0);
	if (count > 0) {
		child = (pcidev_id)malloc(sizeof(opae_pci_device) * count);
		if (child) {
			opae_get_child(&id, child, count);
			for (i = 0; i < count; i++)
				cmdline_printf(cl, "%s\n", child[i].bdf);
			free(child);
		} else {
			cmdline_printf(cl, "No memory\n");
		}
	} else if (count == 0) {
		cmdline_printf(cl, "No child\n");
	} else {
		cmdline_printf(cl, "Failed\n");
	}
}

cmdline_parse_token_string_t cmd_child_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_child_result, cmd, "get_child");
cmdline_parse_token_string_t cmd_child_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_child_result, bdf, NULL);

cmdline_parse_inst_t cmd_get_child = {
	.f = cmd_child_parsed,
	.data = NULL,
	.help_str = "get child PCI device of FPGA",
	.tokens = {
		(void *)&cmd_child_cmd,
		(void *)&cmd_child_bdf,
		NULL,
	},
};

/* *** GET PF1 *** */
struct cmd_pf1_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
};

static void cmd_pf1_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_pf1_result *res = parsed_result;
	opae_pci_device id;
	pcidev_id peer;
	int i, count = 0;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	count = opae_get_pf1(&id, NULL, 0);
	if (count > 0) {
		peer = (pcidev_id)malloc(sizeof(opae_pci_device) * count);
		if (peer) {
			opae_get_pf1(&id, peer, count);
			for (i = 0; i < count; i++)
				cmdline_printf(cl, "%s\n", peer[i].bdf);
			free(peer);
		} else {
			cmdline_printf(cl, "No memory\n");
		}
	} else if (count == 0) {
		cmdline_printf(cl, "No PF1\n");
	} else {
		cmdline_printf(cl, "Failed\n");
	}
}

cmdline_parse_token_string_t cmd_pf1_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_pf1_result, cmd, "get_pf1");
cmdline_parse_token_string_t cmd_pf1_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_pf1_result, bdf, NULL);

cmdline_parse_inst_t cmd_get_pf1 = {
	.f = cmd_pf1_parsed,
	.data = NULL,
	.help_str = "get physical function 1 device of FPGA",
	.tokens = {
		(void *)&cmd_pf1_cmd,
		(void *)&cmd_pf1_bdf,
		NULL,
	},
};

/* *** SET LOG LEVEL *** */
struct cmd_log_level_result {
	cmdline_fixed_string_t cmd;
	int32_t level;
};

static void cmd_log_level_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_log_level_result *res = parsed_result;
	if (opae_set_log_level(res->level) == res->level)
		cmdline_printf(cl, "Successful\n");
	else
		cmdline_printf(cl, "Failed\n");
}

cmdline_parse_token_string_t cmd_log_level_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_log_level_result, cmd, "set_log_level");
cmdline_parse_token_num_t cmd_log_level_level =
	TOKEN_NUM_INITIALIZER(struct cmd_log_level_result, level, RTE_INT32);

cmdline_parse_inst_t cmd_set_log_level = {
	.f = cmd_log_level_parsed,
	.data = NULL,
	.help_str = "set logging level",
	.tokens = {
		(void *)&cmd_log_level_cmd,
		(void *)&cmd_log_level_level,
		NULL,
	},
};

/* *** SET LOG FILE *** */
struct cmd_log_file_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t path;
};

static void cmd_log_file_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_log_file_result *res = parsed_result;
	if (opae_set_log_file(res->path, 1) == 0)
		cmdline_printf(cl, "Successful\n");
	else
		cmdline_printf(cl, "Failed\n");
}

cmdline_parse_token_string_t cmd_log_file_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_log_file_result, cmd, "set_log_file");
cmdline_parse_token_string_t cmd_log_file_path =
	TOKEN_STRING_INITIALIZER(struct cmd_log_file_result, path, NULL);

cmdline_parse_inst_t cmd_set_log_file = {
	.f = cmd_log_file_parsed,
	.data = NULL,
	.help_str = "set logging file",
	.tokens = {
		(void *)&cmd_log_file_cmd,
		(void *)&cmd_log_file_path,
		NULL,
	},
};

/* *** SET STATUS *** */
struct cmd_set_status_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
	uint32_t stat;
	uint32_t prog;
};

static void cmd_set_status_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_set_status_result *res = parsed_result;
	opae_pci_device id;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}
	if ((res->stat > 4) || (res->prog > 100)) {
		cmdline_printf(cl, "%u,%u is invalid status\n", res->stat,
			res->prog);
		return;
	}

	if (opae_store_rsu_status(&id, res->stat, res->prog) == 0)
		cmdline_printf(cl, "Successful\n");
	else
		cmdline_printf(cl, "Failed\n");
}

cmdline_parse_token_string_t cmd_set_status_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_set_status_result, cmd, "set_status");
cmdline_parse_token_string_t cmd_set_status_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_set_status_result, bdf, NULL);
cmdline_parse_token_num_t cmd_set_status_stat =
	TOKEN_NUM_INITIALIZER(struct cmd_set_status_result, stat, RTE_UINT32);
cmdline_parse_token_num_t cmd_set_status_prog =
	TOKEN_NUM_INITIALIZER(struct cmd_set_status_result, prog, RTE_UINT32);

cmdline_parse_inst_t cmd_set_status = {
	.f = cmd_set_status_parsed,
	.data = NULL,
	.help_str = "set current status & progress of FPGA",
	.tokens = {
		(void *)&cmd_set_status_cmd,
		(void *)&cmd_set_status_bdf,
		(void *)&cmd_set_status_stat,
		(void *)&cmd_set_status_prog,
		NULL,
	},
};

/* *** ENUMERATE *** */
struct cmd_enumerate_result {
	cmdline_fixed_string_t cmd;
	uint32_t vid;
	uint32_t did;
};

static void cmd_enumerate_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_enumerate_result *res = parsed_result;
	opae_pci_id filter;
	opae_pci_device *id;
	int i, count = 0;

	filter.vendor_id = res->vid;
	filter.device_id = res->did;
	filter.class_id = BIT_SET_32;
	filter.subsystem_vendor_id = BIT_SET_16;
	filter.subsystem_device_id = BIT_SET_16;

	count = opae_enumerate(&filter, NULL, 0);
	if (count > 0) {
		id = (opae_pci_device *)malloc(sizeof(opae_pci_device) * count);
		if (id) {
			opae_enumerate(&filter, id, count);
			for (i = 0; i < count; i++)
				cmdline_printf(cl, "%s\n", id[i].bdf);
			free(id);
		} else {
			cmdline_printf(cl, "No memory\n");
		}
	} else if (count == 0) {
		cmdline_printf(cl, "Not found\n");
	} else {
		cmdline_printf(cl, "Failed\n");
	}
}

cmdline_parse_token_string_t cmd_enumerate_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_enumerate_result, cmd, "enumerate");
cmdline_parse_token_num_t cmd_enumerate_vid =
	TOKEN_NUM_INITIALIZER(struct cmd_enumerate_result, vid, RTE_UINT32);
cmdline_parse_token_num_t cmd_enumerate_did =
	TOKEN_NUM_INITIALIZER(struct cmd_enumerate_result, did, RTE_UINT32);

cmdline_parse_inst_t cmd_enumerate = {
	.f = cmd_enumerate_parsed,
	.data = NULL,
	.help_str = "enumerate specified FPGA",
	.tokens = {
		(void *)&cmd_enumerate_cmd,
		(void *)&cmd_enumerate_vid,
		(void *)&cmd_enumerate_did,
		NULL,
	},
};

/* *** BIND *** */
struct cmd_bind_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
	cmdline_fixed_string_t drv;
};

static void cmd_bind_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_bind_result *res = parsed_result;
	opae_pci_device id;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (opae_bind_driver(&id, res->drv) == 0)
		cmdline_printf(cl, "Successful\n");
	else
		cmdline_printf(cl, "Failed\n");
}

cmdline_parse_token_string_t cmd_bind_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_bind_result, cmd, "bind");
cmdline_parse_token_string_t cmd_bind_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_bind_result, bdf, NULL);
cmdline_parse_token_string_t cmd_bind_drv =
	TOKEN_STRING_INITIALIZER(struct cmd_bind_result, drv, NULL);

cmdline_parse_inst_t cmd_bind = {
	.f = cmd_bind_parsed,
	.data = NULL,
	.help_str = "bind FPGA with kernel driver",
	.tokens = {
		(void *)&cmd_bind_cmd,
		(void *)&cmd_bind_bdf,
		(void *)&cmd_bind_drv,
		NULL,
	},
};

/* *** UNBIND *** */
struct cmd_unbind_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
};

static void cmd_unbind_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_unbind_result *res = parsed_result;
	opae_pci_device id;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (opae_unbind_driver(&id) == 0)
		cmdline_printf(cl, "Successful\n");
	else
		cmdline_printf(cl, "Failed\n");
}

cmdline_parse_token_string_t cmd_unbind_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_bind_result, cmd, "unbind");
cmdline_parse_token_string_t cmd_unbind_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_bind_result, bdf, NULL);

cmdline_parse_inst_t cmd_unbind = {
	.f = cmd_unbind_parsed,
	.data = NULL,
	.help_str = "unbind FPGA from kernel driver",
	.tokens = {
		(void *)&cmd_unbind_cmd,
		(void *)&cmd_unbind_bdf,
		NULL,
	},
};

/* *** PROBE *** */
struct cmd_probe_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
};

static void cmd_probe_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_probe_result *res = parsed_result;
	opae_pci_device id;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (opae_probe_device(&id) == 0)
		cmdline_printf(cl, "Successful\n");
	else
		cmdline_printf(cl, "Failed\n");
}

cmdline_parse_token_string_t cmd_probe_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_probe_result, cmd, "probe");
cmdline_parse_token_string_t cmd_probe_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_probe_result, bdf, NULL);

cmdline_parse_inst_t cmd_probe = {
	.f = cmd_probe_parsed,
	.data = NULL,
	.help_str = "probe FPGA with IFPGA driver",
	.tokens = {
		(void *)&cmd_probe_cmd,
		(void *)&cmd_probe_bdf,
		NULL,
	},
};

/* *** REMOVE *** */
struct cmd_remove_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
};

static void cmd_remove_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_remove_result *res = parsed_result;
	opae_pci_device id;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (opae_remove_device(&id) == 0)
		cmdline_printf(cl, "Successful\n");
	else
		cmdline_printf(cl, "Failed\n");
}

cmdline_parse_token_string_t cmd_remove_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_remove_result, cmd, "remove");
cmdline_parse_token_string_t cmd_remove_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_remove_result, bdf, NULL);

cmdline_parse_inst_t cmd_remove = {
	.f = cmd_remove_parsed,
	.data = NULL,
	.help_str = "remove FPGA from IFPGA driver",
	.tokens = {
		(void *)&cmd_remove_cmd,
		(void *)&cmd_remove_bdf,
		NULL,
	},
};

/* *** FLASH *** */
struct cmd_flash_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
	cmdline_fixed_string_t path;
};

static void cmd_flash_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_flash_result *res = parsed_result;
	opae_pci_device id;
	uint64_t stat = 0;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (opae_update_flash(&id, res->path, &stat))
		cmdline_printf(cl, "Error: 0x%lx\n", (unsigned long)stat);
}

cmdline_parse_token_string_t cmd_flash_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_flash_result, cmd, "flash");
cmdline_parse_token_string_t cmd_flash_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_flash_result, bdf, NULL);
cmdline_parse_token_string_t cmd_flash_path =
	TOKEN_STRING_INITIALIZER(struct cmd_flash_result, path, NULL);

cmdline_parse_inst_t cmd_flash = {
	.f = cmd_flash_parsed,
	.data = NULL,
	.help_str = "update flash of FPGA",
	.tokens = {
		(void *)&cmd_flash_cmd,
		(void *)&cmd_flash_bdf,
		(void *)&cmd_flash_path,
		NULL,
	},
};

/* *** PR *** */
struct cmd_pr_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
	int32_t port;
	cmdline_fixed_string_t path;
};

static void cmd_pr_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_pr_result *res = parsed_result;
	opae_pci_device id;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (opae_partial_reconfigure(&id, res->port, res->path) == 0)
		cmdline_printf(cl, "Successful\n");
	else
		cmdline_printf(cl, "Failed\n");
}

cmdline_parse_token_string_t cmd_pr_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_pr_result, cmd, "pr");
cmdline_parse_token_string_t cmd_pr_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_pr_result, bdf, NULL);
cmdline_parse_token_num_t cmd_pr_port =
	TOKEN_NUM_INITIALIZER(struct cmd_pr_result, port, RTE_INT32);
cmdline_parse_token_string_t cmd_pr_path =
	TOKEN_STRING_INITIALIZER(struct cmd_pr_result, path, NULL);

cmdline_parse_inst_t cmd_pr = {
	.f = cmd_pr_parsed,
	.data = NULL,
	.help_str = "partial reconfigure FPGA",
	.tokens = {
		(void *)&cmd_pr_cmd,
		(void *)&cmd_pr_bdf,
		(void *)&cmd_pr_port,
		(void *)&cmd_pr_path,
		NULL,
	},
};

/* *** REBOOT *** */
struct cmd_reboot_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
	cmdline_fixed_string_t type;
	int32_t page;
};

static void cmd_reboot_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_reboot_result *res = parsed_result;
	opae_pci_device id;
	int type = 0;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (!strcmp(res->type, "fpga")) {
		type = 0;
	} else if (!strcmp(res->type, "bmc")) {
		type = 1;
	} else {
		cmdline_printf(cl, "%s is invalid reboot type\n", res->type);
		return;
	}

	if (opae_reboot_device(&id, type, res->page) == 0)
		cmdline_printf(cl, "Successful\n");
	else
		cmdline_printf(cl, "Failed\n");
}

cmdline_parse_token_string_t cmd_reboot_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_reboot_result, cmd, "reboot");
cmdline_parse_token_string_t cmd_reboot_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_reboot_result, bdf, NULL);
cmdline_parse_token_string_t cmd_reboot_type =
	TOKEN_STRING_INITIALIZER(struct cmd_reboot_result, type, NULL);
cmdline_parse_token_num_t cmd_reboot_page =
	TOKEN_NUM_INITIALIZER(struct cmd_reboot_result, page, RTE_INT32);

cmdline_parse_inst_t cmd_reboot = {
	.f = cmd_reboot_parsed,
	.data = NULL,
	.help_str = "reboot FPGA or MAX10",
	.tokens = {
		(void *)&cmd_reboot_cmd,
		(void *)&cmd_reboot_bdf,
		(void *)&cmd_reboot_type,
		(void *)&cmd_reboot_page,
		NULL,
	},
};

/* *** CANCEL *** */
struct cmd_cancel_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
};

static void cmd_cancel_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_cancel_result *res = parsed_result;
	opae_pci_device id;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (opae_cancel_flash_update(&id, 0) == 0)
		cmdline_printf(cl, "Successful\n");
	else
		cmdline_printf(cl, "Failed\n");
}

cmdline_parse_token_string_t cmd_cancel_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_cancel_result, cmd, "cancel");
cmdline_parse_token_string_t cmd_cancel_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_cancel_result, bdf, NULL);

cmdline_parse_inst_t cmd_cancel = {
	.f = cmd_cancel_parsed,
	.data = NULL,
	.help_str = "cancel flash update",
	.tokens = {
		(void *)&cmd_cancel_cmd,
		(void *)&cmd_cancel_bdf,
		NULL,
	},
};

/* *** PCI READ *** */
struct cmd_pci_read_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
	uint32_t offset;
};

static void cmd_pci_read_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_pci_read_result *res = parsed_result;
	opae_pci_device id;
	uint32_t offset = 0;
	uint32_t value = 0;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (res->offset & 0x3) {
		offset = res->offset & ~3;
		cmdline_printf(cl, "align offset to 0x%x\n", offset);
	} else {
		offset = res->offset;
	}

	if (opae_read_pci_cfg(&id, offset, &value) == 0)
		cmdline_printf(cl, "0x%08x\n", value);
	else
		cmdline_printf(cl, "Failed\n");
}

cmdline_parse_token_string_t cmd_pci_read_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_pci_read_result, cmd, "pci_read");
cmdline_parse_token_string_t cmd_pci_read_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_pci_read_result, bdf, NULL);
cmdline_parse_token_num_t cmd_pci_read_offset =
	TOKEN_NUM_INITIALIZER(struct cmd_pci_read_result, offset, RTE_UINT32);

cmdline_parse_inst_t cmd_pci_read = {
	.f = cmd_pci_read_parsed,
	.data = NULL,
	.help_str = "read PCI configuration space",
	.tokens = {
		(void *)&cmd_pci_read_cmd,
		(void *)&cmd_pci_read_bdf,
		(void *)&cmd_pci_read_offset,
		NULL,
	},
};

/* *** PCI WRITE *** */
struct cmd_pci_write_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t bdf;
	uint32_t offset;
	uint32_t value;
};

static void cmd_pci_write_parsed(void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_pci_write_result *res = parsed_result;
	opae_pci_device id;
	uint32_t offset = 0;

	if (parse_pciaddr(res->bdf, &id) < 0) {
		cmdline_printf(cl, "%s is invalid PCI address\n", res->bdf);
		return;
	}

	if (res->offset & 0x3) {
		offset = res->offset & ~3;
		cmdline_printf(cl, "align offset to 0x%x\n", offset);
	} else {
		offset = res->offset;
	}

	if (opae_write_pci_cfg(&id, offset, res->value) == 0)
		cmdline_printf(cl, "Successful\n");
	else
		cmdline_printf(cl, "Failed\n");
}

cmdline_parse_token_string_t cmd_pci_write_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_pci_write_result, cmd, "pci_write");
cmdline_parse_token_string_t cmd_pci_write_bdf =
	TOKEN_STRING_INITIALIZER(struct cmd_pci_write_result, bdf, NULL);
cmdline_parse_token_num_t cmd_pci_write_offset =
	TOKEN_NUM_INITIALIZER(struct cmd_pci_write_result, offset, RTE_UINT32);
cmdline_parse_token_num_t cmd_pci_write_value =
	TOKEN_NUM_INITIALIZER(struct cmd_pci_write_result, value, RTE_UINT32);

cmdline_parse_inst_t cmd_pci_write = {
	.f = cmd_pci_write_parsed,
	.data = NULL,
	.help_str = "write PCI configuration space",
	.tokens = {
		(void *)&cmd_pci_write_cmd,
		(void *)&cmd_pci_write_bdf,
		(void *)&cmd_pci_write_offset,
		(void *)&cmd_pci_write_value,
		NULL,
	},
};

/* *** QUIT *** */
struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void cmd_quit_parsed(__rte_unused void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	cmdline_quit(cl);
}

cmdline_parse_token_string_t cmd_quit_quit =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,
	.data = NULL,
	.help_str = "exit DPDK application",
	.tokens = {
		(void *)&cmd_quit_quit,
		NULL,
	},
};

/* *** HELP *** */
struct cmd_help_result {
	cmdline_fixed_string_t help;
};

static void cmd_help_parsed(__rte_unused void *parsed_result,
	struct cmdline *cl, __rte_unused void *data)
{
	cmdline_printf(cl,
		" get_api_version               \t\t"
			"get OPAE API version\n"
		" get_proc_type                 \t\t"
			"get DPDK process type\n"
		" get_image_info <FILE>         \t\t"
			"get information of image file\n"
		" get_status <BDF>              \t\t"
			"get current status & progress of FPGA\n"
		" get_property <BDF> <0|1|2|4|8>\t\t"
			"get property of FPGA\n"
		" get_phy_info <BDF>            \t\t"
			"get information of PHY\n"
		" get_parent <BDF>              \t\t"
			"get parent PCI device of FPGA\n"
		" get_child <BDF>               \t\t"
			"get child PCI device of FPGA\n"
		" get_pf1 <BDF>                 \t\t"
			"get physical function 1 device of FPGA\n"
		" set_log_level <0-4>           \t\t"
			"set logging level\n"
		" set_log_file <FILE>           \t\t"
			"set logging file\n"
		" set_status <BDF> <0-4> <0-100>\t\t"
			"set current status & progress of FPGA\n"
		" enumerate <VID> <DID>         \t\t"
			"enumerate specified FPGA\n"
		" bind <BDF> <DRIVER>           \t\t"
			"bind FPGA with kernel driver\n"
		" unbind <BDF>                  \t\t"
			"unbind FPGA from kernel driver\n"
		" probe <BDF>                   \t\t"
			"probe FPGA with IFPGA driver\n"
		" remove <BDF>                  \t\t"
			"remove FPGA from IFPGA driver\n"
		" flash <BDF> <FILE>            \t\t"
			"update flash of FPGA\n"
		" pr <BDF> <PORT> <FILE>        \t\t"
			"partial reconfigure FPGA\n"
		" reboot <BDF> <fpga|bmc> <0-1> \t\t"
			"reboot FPGA or MAX10\n"
		" cancel <BDF>                  \t\t"
			"cancel flash update\n"
		" pci_read <BDF> <0-1024>       \t\t"
			"read PCI configuration space\n"
		" pci_write <BDF> <0-1024> <NUM>\t\t"
			"write PCI configuration space\n"
		" quit                          \t\t"
			"exit DPDK application\n"
		" help                          \t\t"
			"show commands list\n");
}

cmdline_parse_token_string_t cmd_help_help =
	TOKEN_STRING_INITIALIZER(struct cmd_help_result, help, "help");

cmdline_parse_inst_t cmd_help = {
	.f = cmd_help_parsed,
	.data = NULL,
	.help_str = "show commands list",
	.tokens = {
		(void *)&cmd_help_help,
		NULL,
	},
};

/****** CONTEXT (list of commands) */
cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_get_image_info,
	(cmdline_parse_inst_t *)&cmd_get_api_version,
	(cmdline_parse_inst_t *)&cmd_get_proc_type,
	(cmdline_parse_inst_t *)&cmd_get_status,
	(cmdline_parse_inst_t *)&cmd_get_property,
	(cmdline_parse_inst_t *)&cmd_phy_info,
	(cmdline_parse_inst_t *)&cmd_get_parent,
	(cmdline_parse_inst_t *)&cmd_get_child,
	(cmdline_parse_inst_t *)&cmd_get_pf1,
	(cmdline_parse_inst_t *)&cmd_set_log_level,
	(cmdline_parse_inst_t *)&cmd_set_log_file,
	(cmdline_parse_inst_t *)&cmd_set_status,
	(cmdline_parse_inst_t *)&cmd_enumerate,
	(cmdline_parse_inst_t *)&cmd_bind,
	(cmdline_parse_inst_t *)&cmd_unbind,
	(cmdline_parse_inst_t *)&cmd_probe,
	(cmdline_parse_inst_t *)&cmd_remove,
	(cmdline_parse_inst_t *)&cmd_flash,
	(cmdline_parse_inst_t *)&cmd_pr,
	(cmdline_parse_inst_t *)&cmd_reboot,
	(cmdline_parse_inst_t *)&cmd_cancel,
	(cmdline_parse_inst_t *)&cmd_pci_read,
	(cmdline_parse_inst_t *)&cmd_pci_write,
	(cmdline_parse_inst_t *)&cmd_quit,
	(cmdline_parse_inst_t *)&cmd_help,
	NULL,
};
