/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Advanced Micro Devices, Inc.
 */

#include <errno.h>
#include <dirent.h>
#include <fnmatch.h>

#include <rte_memcpy.h>

#include "amd_uncore.h"
#include "power_common.h"
#include "e_smi/e_smi.h"

#define MAX_UNCORE_FREQS 8
#define MAX_NUMA_DIE 8

#define BUS_FREQ 1000

struct  __rte_cache_aligned uncore_power_info {
	unsigned int die;                  /* Core die id */
	unsigned int pkg;                  /* Package id */
	uint32_t freqs[MAX_UNCORE_FREQS];  /* Frequency array */
	uint32_t nb_freqs;                 /* Number of available freqs */
	uint32_t curr_idx;                 /* Freq index in freqs array */
	uint32_t max_freq;            /* System max uncore freq */
	uint32_t min_freq;            /* System min uncore freq */
};

static struct uncore_power_info uncore_info[RTE_MAX_NUMA_NODES][MAX_NUMA_DIE];
static int esmi_initialized;

static int
set_uncore_freq_internal(struct uncore_power_info *ui, uint32_t idx)
{
	int ret;

	if (idx >= MAX_UNCORE_FREQS || idx >= ui->nb_freqs) {
		POWER_LOG(DEBUG, "Invalid uncore frequency index %u, which "
				"should be less than %u", idx, ui->nb_freqs);
		return -1;
	}

	ret = esmi_apb_disable(ui->pkg, idx);
	if (ret != ESMI_SUCCESS) {
		POWER_LOG(ERR, "DF P-state '%u' set failed for pkg %02u",
				idx, ui->pkg);
		return -1;
	}

	POWER_DEBUG_LOG("DF P-state '%u' to be set for pkg %02u die %02u",
				idx, ui->pkg, ui->die);

	/* write the minimum value first if the target freq is less than current max */
	ui->curr_idx = idx;

	return 0;
}

/*
 * Fopen the sys file for the future setting of the uncore die frequency.
 */
static int
power_init_for_setting_uncore_freq(struct uncore_power_info *ui)
{
	/* open and read all uncore sys files */
	/* Base max */
	ui->max_freq = 1800000;
	ui->min_freq = 1200000;

	return 0;
}

/*
 * Get the available uncore frequencies of the specific die by reading the
 * sys file.
 */
static int
power_get_available_uncore_freqs(struct uncore_power_info *ui)
{
	int ret = -1;
	uint32_t i, num_uncore_freqs = 3;
	uint32_t fabric_freqs[] = {
	/* to be extended for probing support in future */
		1800,
		1444,
		1200
	};

	if (num_uncore_freqs >= MAX_UNCORE_FREQS) {
		POWER_LOG(ERR, "Too many available uncore frequencies: %d",
				num_uncore_freqs);
		goto out;
	}

	/* Generate the uncore freq bucket array. */
	for (i = 0; i < num_uncore_freqs; i++)
		ui->freqs[i] = fabric_freqs[i] * BUS_FREQ;

	ui->nb_freqs = num_uncore_freqs;

	ret = 0;

	POWER_DEBUG_LOG("%d frequency(s) of pkg %02u die %02u are available",
			num_uncore_freqs, ui->pkg, ui->die);

out:
	return ret;
}

static int
check_pkg_die_values(unsigned int pkg, unsigned int die)
{
	unsigned int max_pkgs, max_dies;
	max_pkgs = power_amd_uncore_get_num_pkgs();
	if (max_pkgs == 0)
		return -1;
	if (pkg >= max_pkgs) {
		POWER_LOG(DEBUG, "Package number %02u can not exceed %u",
				pkg, max_pkgs);
		return -1;
	}

	max_dies = power_amd_uncore_get_num_dies(pkg);
	if (max_dies == 0)
		return -1;
	if (die >= max_dies) {
		POWER_LOG(DEBUG, "Die number %02u can not exceed %u",
				die, max_dies);
		return -1;
	}

	return 0;
}

static void
power_amd_uncore_esmi_init(void)
{
	if (esmi_init() == ESMI_SUCCESS)
		esmi_initialized = 1;
}

int
power_amd_uncore_init(unsigned int pkg, unsigned int die)
{
	struct uncore_power_info *ui;
	int ret;

	if (!esmi_initialized) {
		ret = esmi_init();
		if (ret != ESMI_SUCCESS) {
			POWER_LOG(DEBUG, "ESMI Not initialized, drivers not found");
			return -1;
		}
	}

	ret = check_pkg_die_values(pkg, die);
	if (ret < 0)
		return -1;

	ui = &uncore_info[pkg][die];
	ui->die = die;
	ui->pkg = pkg;

	/* Init for setting uncore die frequency */
	if (power_init_for_setting_uncore_freq(ui) < 0) {
		POWER_LOG(DEBUG, "Cannot init for setting uncore frequency for "
				"pkg %02u die %02u", pkg, die);
		return -1;
	}

	/* Get the available frequencies */
	if (power_get_available_uncore_freqs(ui) < 0) {
		POWER_LOG(DEBUG, "Cannot get available uncore frequencies of "
				"pkg %02u die %02u", pkg, die);
		return -1;
	}

	return 0;
}

int
power_amd_uncore_exit(unsigned int pkg, unsigned int die)
{
	struct uncore_power_info *ui;

	int ret = check_pkg_die_values(pkg, die);
	if (ret < 0)
		return -1;

	ui = &uncore_info[pkg][die];
	ui->nb_freqs = 0;

	if (esmi_initialized) {
		esmi_exit();
		esmi_initialized = 0;
	}

	return 0;
}

uint32_t
power_get_amd_uncore_freq(unsigned int pkg, unsigned int die)
{
	int ret = check_pkg_die_values(pkg, die);
	if (ret < 0)
		return -1;

	return uncore_info[pkg][die].curr_idx;
}

int
power_set_amd_uncore_freq(unsigned int pkg, unsigned int die, uint32_t index)
{
	int ret = check_pkg_die_values(pkg, die);
	if (ret < 0)
		return -1;

	return set_uncore_freq_internal(&(uncore_info[pkg][die]), index);
}

int
power_amd_uncore_freq_max(unsigned int pkg, unsigned int die)
{
	int ret = check_pkg_die_values(pkg, die);
	if (ret < 0)
		return -1;

	return set_uncore_freq_internal(&(uncore_info[pkg][die]), 0);
}


int
power_amd_uncore_freq_min(unsigned int pkg, unsigned int die)
{
	int ret = check_pkg_die_values(pkg, die);
	if (ret < 0)
		return -1;

	struct uncore_power_info *ui = &uncore_info[pkg][die];

	return set_uncore_freq_internal(&(uncore_info[pkg][die]), ui->nb_freqs - 1);
}

int
power_amd_uncore_freqs(unsigned int pkg, unsigned int die, uint32_t *freqs, uint32_t num)
{
	struct uncore_power_info *ui;

	int ret = check_pkg_die_values(pkg, die);
	if (ret < 0)
		return -1;

	if (freqs == NULL) {
		POWER_LOG(ERR, "NULL buffer supplied");
		return 0;
	}

	ui = &uncore_info[pkg][die];
	if (num < ui->nb_freqs) {
		POWER_LOG(ERR, "Buffer size is not enough");
		return 0;
	}
	rte_memcpy(freqs, ui->freqs, ui->nb_freqs * sizeof(uint32_t));

	return ui->nb_freqs;
}

int
power_amd_uncore_get_num_freqs(unsigned int pkg, unsigned int die)
{
	int ret = check_pkg_die_values(pkg, die);
	if (ret < 0)
		return -1;

	return uncore_info[pkg][die].nb_freqs;
}

unsigned int
power_amd_uncore_get_num_pkgs(void)
{
	uint32_t num_pkgs = 0;
	int ret;

	if (esmi_initialized) {
		ret = esmi_number_of_sockets_get(&num_pkgs);
		if (ret != ESMI_SUCCESS) {
			POWER_LOG(ERR, "Failed to get number of sockets");
			num_pkgs = 0;
		}
	}
	return num_pkgs;
}

unsigned int
power_amd_uncore_get_num_dies(unsigned int pkg)
{
	if (pkg >= power_amd_uncore_get_num_pkgs()) {
		POWER_LOG(ERR, "Invalid package ID");
		return 0;
	}

	return 1;
}

static struct rte_power_uncore_ops amd_uncore_ops = {
	.name = "amd-hsmp",
	.cb = power_amd_uncore_esmi_init,
	.init = power_amd_uncore_init,
	.exit = power_amd_uncore_exit,
	.get_avail_freqs = power_amd_uncore_freqs,
	.get_num_pkgs = power_amd_uncore_get_num_pkgs,
	.get_num_dies = power_amd_uncore_get_num_dies,
	.get_num_freqs = power_amd_uncore_get_num_freqs,
	.get_freq = power_get_amd_uncore_freq,
	.set_freq = power_set_amd_uncore_freq,
	.freq_max = power_amd_uncore_freq_max,
	.freq_min = power_amd_uncore_freq_min,
};

RTE_POWER_REGISTER_UNCORE_OPS(amd_uncore_ops);
