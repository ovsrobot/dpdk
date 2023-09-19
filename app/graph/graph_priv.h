/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#ifndef APP_GRAPH_PRIV_H
#define APP_GRAPH_PRIV_H

#define MAX_GRAPH_USECASES 32

struct graph_help_cmd_tokens {
	cmdline_fixed_string_t help;
	cmdline_fixed_string_t graph;
};

struct graph_start_cmd_tokens {
	cmdline_fixed_string_t graph;
	cmdline_fixed_string_t start;
};

struct graph_stats_cmd_tokens {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t graph;
	cmdline_fixed_string_t stats;
};

struct graph_config_cmd_tokens {
	cmdline_fixed_string_t graph;
	cmdline_fixed_string_t usecase;
	cmdline_fixed_string_t bsz;
	cmdline_fixed_string_t tmo;
	cmdline_fixed_string_t coremask;
	cmdline_fixed_string_t model;
	cmdline_fixed_string_t model_name;
	uint16_t size;
	uint64_t ns;
	uint64_t mask;
};

enum graph_model {
	GRAPH_MODEL_RTC = 0x01,
	GRAPH_MODEL_MCD = 0x02,
};

struct usecases {
	char name[32];
	bool enabled;
};

struct usecase_params {
	uint64_t coremask;
	uint32_t bsz;
	uint32_t tmo;
};

struct graph_config {
	struct usecases usecases[MAX_GRAPH_USECASES];
	struct usecase_params params;
	enum graph_model model;
};

#endif
