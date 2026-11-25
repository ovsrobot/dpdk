/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Huawei Technologies Co., Ltd
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <rte_telemetry.h>
#include <rte_power_uncore.h>

#include "power_common.h"

static int
parse_uncore_param(const char *params, unsigned int *pkg, unsigned int *die)
{
	unsigned long pkg_id, die_id;
	char *end = NULL;

	if (params == NULL || params[0] == '\0' || !isdigit((unsigned char)params[0]))
		return -EINVAL;

	pkg_id = strtoul(params, &end, 0);
	if (end == NULL || *end != ',')
		return -EINVAL;
	die_id = strtoul(end + 1, &end, 0);
	if (*end != '\0')
		return -EINVAL;

	if (pkg_id > UINT_MAX || die_id > UINT_MAX)
		return -EINVAL;

	*pkg = (unsigned int)pkg_id;
	*die = (unsigned int)die_id;

	return 0;
}

static int
handle_power_uncore_curr_freq(const char *cmd __rte_unused, const char *params,
		struct rte_tel_data *d)
{
	unsigned int pkg, die;
	uint32_t curr_idx;
	int ret;

	if (rte_power_get_uncore_env() == RTE_UNCORE_PM_ENV_NOT_SET)
		return -EINVAL;

	ret = parse_uncore_param(params, &pkg, &die);
	if (ret != 0)
		return ret;

	if (pkg >= rte_power_uncore_get_num_pkgs())
		return -EINVAL;
	if (die >= rte_power_uncore_get_num_dies(pkg))
		return -EINVAL;

	curr_idx = rte_power_get_uncore_freq(pkg, die);
	if (curr_idx == (uint32_t)RTE_POWER_INVALID_FREQ_INDEX)
		return -EINVAL;

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_uint(d, "pkg", pkg);
	rte_tel_data_add_dict_uint(d, "die", die);
	rte_tel_data_add_dict_uint(d, "curr_freq_idx", curr_idx);
	return 0;
}

static int
handle_power_uncore_avail_freqs(const char *cmd __rte_unused, const char *params,
		struct rte_tel_data *d)
{
	unsigned int pkg, die;
	uint32_t *freqs;
	char key[12];
	int num_freqs;
	int ret;
	int i;

	if (rte_power_get_uncore_env() == RTE_UNCORE_PM_ENV_NOT_SET)
		return -EINVAL;

	ret = parse_uncore_param(params, &pkg, &die);
	if (ret != 0)
		return ret;

	if (pkg >= rte_power_uncore_get_num_pkgs())
		return -EINVAL;
	if (die >= rte_power_uncore_get_num_dies(pkg))
		return -EINVAL;

	num_freqs = rte_power_uncore_get_num_freqs(pkg, die);
	if (num_freqs <= 0)
		return -EINVAL;

	freqs = malloc(sizeof(uint32_t) * num_freqs);
	if (freqs == NULL)
		return -ENOMEM;

	if (rte_power_uncore_freqs(pkg, die, freqs, num_freqs) != num_freqs) {
		free(freqs);
		return -EINVAL;
	}

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_uint(d, "pkg", pkg);
	rte_tel_data_add_dict_uint(d, "die", die);
	rte_tel_data_add_dict_uint(d, "num_freqs", num_freqs);

	for (i = 0; i < num_freqs; i++) {
		snprintf(key, sizeof(key), "%d", i);
		rte_tel_data_add_dict_uint(d, key, freqs[i]);
	}

	free(freqs);
	return 0;
}

RTE_INIT(power_uncore_init_telemetry)
{
	rte_telemetry_register_cmd("/power/uncore/curr_freq", handle_power_uncore_curr_freq,
			"Returns the current frequency index of an uncore domain. "
			"Parameters: int pkg, int die");
	rte_telemetry_register_cmd("/power/uncore/avail_freqs", handle_power_uncore_avail_freqs,
			"Returns the available frequencies of an uncore domain. "
			"Parameters: int pkg, int die");
}
