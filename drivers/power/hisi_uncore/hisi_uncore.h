/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */
#ifndef HISI_UNCORE_H
#define HISI_UNCORE_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_stdatomic.h>

#define HISI_UNCORE_GOV_NAME_LEN	32
struct hisi_uncore_die_data {
	uint32_t die_id;
	uint32_t uid;
	uint32_t freqs[RTE_MAX_UNCORE_FREQS];
	uint32_t nb_freqs;
	uint32_t max_freq;
	uint32_t min_freq;
	uint32_t cur_freq_ori;
	uint32_t curr_idx;
	char governor_ori[HISI_UNCORE_GOV_NAME_LEN];
	FILE *f_set_freq;
};

struct hisi_uncore_pkg_data {
	uint32_t pkg_id;
	uint32_t die_num;
	struct hisi_uncore_die_data *die_data;
};

struct hisi_uncore_info {
	RTE_ATOMIC(uint32_t) ref;
	uint32_t pkg_num;
	struct hisi_uncore_pkg_data *pkg_data;
};

#endif
