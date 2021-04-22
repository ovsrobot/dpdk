/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Arm Limited
 */

#include <rte_memcpy.h>
#include <rte_memory.h>

#include "power_cppc_cpufreq.h"
#include "power_common.h"

#ifdef RTE_LIBRTE_POWER_DEBUG
#define POWER_DEBUG_TRACE(fmt, args...) do { \
		RTE_LOG(ERR, POWER, "%s: " fmt, __func__, ## args); \
} while (0)
#else
#define POWER_DEBUG_TRACE(fmt, args...)
#endif

#define FOPEN_OR_ERR_RET(f, retval) do { \
		if ((f) == NULL) { \
			RTE_LOG(ERR, POWER, "File not opened\n"); \
			return retval; \
		} \
} while (0)

#define FOPS_OR_NULL_GOTO(ret, label) do { \
		if ((ret) == NULL) { \
			RTE_LOG(ERR, POWER, "fgets returns nothing\n"); \
			goto label; \
		} \
} while (0)

#define FOPS_OR_ERR_GOTO(ret, label) do { \
		if ((ret) < 0) { \
			RTE_LOG(ERR, POWER, "File operations failed\n"); \
			goto label; \
		} \
} while (0)


/* macros used for rounding frequency to nearest 100000 */
#define FREQ_ROUNDING_DELTA 50000
#define ROUND_FREQ_TO_N_100000 100000

/* the unit of highest_perf and nominal_perf differs on different arm platforms.
 * For highest_perf, it maybe 300 or 3000000, both means 3.0GHz.
 */
#define UNIT_DIFF 10000

#define POWER_CONVERT_TO_DECIMAL 10

#define POWER_GOVERNOR_USERSPACE "userspace"
#define POWER_SYSFILE_GOVERNOR   \
		"/sys/devices/system/cpu/cpu%u/cpufreq/scaling_governor"
#define POWER_SYSFILE_SETSPEED   \
		"/sys/devices/system/cpu/cpu%u/cpufreq/scaling_setspeed"
#define POWER_SYSFILE_SCALING_MAX_FREQ \
		"/sys/devices/system/cpu/cpu%u/cpufreq/scaling_max_freq"
#define POWER_SYSFILE_SCALING_MIN_FREQ  \
		"/sys/devices/system/cpu/cpu%u/cpufreq/scaling_min_freq"
#define POWER_SYSFILE_HIGHEST_PERF \
		"/sys/devices/system/cpu/cpu%u/acpi_cppc/highest_perf"
#define POWER_SYSFILE_NOMINAL_PERF \
		"/sys/devices/system/cpu/cpu%u/acpi_cppc/nominal_perf"
#define POWER_SYSFILE_SYS_MAX \
		"/sys/devices/system/cpu/cpu%u/cpufreq/cpuinfo_max_freq"

#define POWER_CPPC_DRIVER "cppc-cpufreq"
#define BUS_FREQ     100000

enum power_state {
	POWER_IDLE = 0,
	POWER_ONGOING,
	POWER_USED,
	POWER_UNKNOWN
};

/**
 * Power info per lcore.
 */
struct cppc_power_info {
	unsigned int lcore_id;                   /**< Logical core id */
	uint32_t state;                      /**< Power in use state */
	FILE *f;                             /**< FD of scaling_setspeed */
	char governor_ori[32];               /**< Original governor name */
	uint32_t curr_idx;                   /**< Freq index in freqs array */
	uint32_t highest_perf;		     /**< system wide max freq */
	uint32_t nominal_perf;		     /**< system wide nominal freq */
	uint16_t turbo_available;            /**< Turbo Boost available */
	uint16_t turbo_enable;               /**< Turbo Boost enable/disable */
	uint32_t nb_freqs;                   /**< number of available freqs */
	uint32_t freqs[RTE_MAX_LCORE_FREQS]; /**< Frequency array */
} __rte_cache_aligned;

static struct cppc_power_info lcore_power_info[RTE_MAX_LCORE];

/**
 * It is to set specific freq for specific logical core, according to the index
 * of supported frequencies.
 */
static int
set_freq_internal(struct cppc_power_info *pi, uint32_t idx)
{
	if (idx >= RTE_MAX_LCORE_FREQS || idx >= pi->nb_freqs) {
		RTE_LOG(ERR, POWER, "Invalid frequency index %u, which "
				"should be less than %u\n", idx, pi->nb_freqs);
		return -1;
	}

	/* Check if it is the same as current */
	if (idx == pi->curr_idx)
		return 0;

	POWER_DEBUG_TRACE("Frequency[%u] %u to be set for lcore %u\n",
			idx, pi->freqs[idx], pi->lcore_id);
	if (fseek(pi->f, 0, SEEK_SET) < 0) {
		RTE_LOG(ERR, POWER, "Fail to set file position indicator to 0 "
				"for setting frequency for lcore %u\n", pi->lcore_id);
		return -1;
	}
	if (fprintf(pi->f, "%u", pi->freqs[idx]) < 0) {
		RTE_LOG(ERR, POWER, "Fail to write new frequency for "
				"lcore %u\n", pi->lcore_id);
		return -1;
	}
	fflush(pi->f);
	pi->curr_idx = idx;

	return 1;
}

/**
 * It is to check the current scaling governor by reading sys file, and then
 * set it into 'userspace' if it is not by writing the sys file. The original
 * governor will be saved for rolling back.
 */
static int
power_set_governor_userspace(struct cppc_power_info *pi)
{
	FILE *f;
	int ret = -1;
	char buf[BUFSIZ];
	char fullpath[PATH_MAX];
	char *s;
	int val;

	snprintf(fullpath, sizeof(fullpath), POWER_SYSFILE_GOVERNOR,
			pi->lcore_id);
	f = fopen(fullpath, "rw+");
	FOPEN_OR_ERR_RET(f, ret);

	s = fgets(buf, sizeof(buf), f);
	FOPS_OR_NULL_GOTO(s, out);
	/* Strip off terminating '\n' */
	strtok(buf, "\n");

	/* Check if current governor is userspace */
	if (strncmp(buf, POWER_GOVERNOR_USERSPACE,
			sizeof(POWER_GOVERNOR_USERSPACE)) == 0) {
		ret = 0;
		POWER_DEBUG_TRACE("Power management governor of lcore %u is "
				"already userspace\n", pi->lcore_id);
		goto out;
	}
	/* Save the original governor */
	strlcpy(pi->governor_ori, buf, sizeof(pi->governor_ori));

	/* Write 'userspace' to the governor */
	val = fseek(f, 0, SEEK_SET);
	FOPS_OR_ERR_GOTO(val, out);

	val = fputs(POWER_GOVERNOR_USERSPACE, f);
	FOPS_OR_ERR_GOTO(val, out);

	/* We need to flush to see if the fputs succeeds */
	val = fflush(f);
	FOPS_OR_ERR_GOTO(val, out);

	ret = 0;
	RTE_LOG(INFO, POWER, "Power management governor of lcore %u has been "
			"set to user space successfully\n", pi->lcore_id);
out:
	fclose(f);

	return ret;
}

static int
power_check_turbo(struct cppc_power_info *pi)
{
	FILE *f_nom, *f_max, *f_cmax;
	int ret = -1;
	char *p_nom, *p_max, *p_cmax;
	char buf_nom[BUFSIZ];
	char buf_max[BUFSIZ];
	char buf_cmax[BUFSIZ];
	char fullpath_nom[PATH_MAX];
	char fullpath_max[PATH_MAX];
	char fullpath_cmax[PATH_MAX];
	char *s_nom, *s_max, *s_cmax;
	uint32_t nominal_perf = 0, highest_perf = 0, cpuinfo_max_freq = 0;

	snprintf(fullpath_max, sizeof(fullpath_max),
			POWER_SYSFILE_HIGHEST_PERF,
			pi->lcore_id);
	snprintf(fullpath_nom, sizeof(fullpath_nom),
			POWER_SYSFILE_NOMINAL_PERF,
			pi->lcore_id);
	snprintf(fullpath_cmax, sizeof(fullpath_cmax),
			POWER_SYSFILE_SYS_MAX,
			pi->lcore_id);

	f_nom = fopen(fullpath_nom, "r");
	FOPEN_OR_ERR_RET(f_nom, ret);

	f_max = fopen(fullpath_max, "r");
	if (f_max == NULL)
		fclose(f_nom);
	FOPEN_OR_ERR_RET(f_max, ret);

	f_cmax = fopen(fullpath_cmax, "r");
	if (f_cmax == NULL) {
		fclose(f_max);
		fclose(f_nom);
	}
	FOPEN_OR_ERR_RET(f_cmax, ret);

	s_nom = fgets(buf_nom, sizeof(buf_nom), f_nom);
	FOPS_OR_NULL_GOTO(s_nom, out);

	s_max = fgets(buf_max, sizeof(buf_max), f_max);
	FOPS_OR_NULL_GOTO(s_max, out);

	s_cmax = fgets(buf_cmax, sizeof(buf_cmax), f_cmax);
	FOPS_OR_NULL_GOTO(s_cmax, out);

	/* Strip the line break if there is */
	p_nom = strchr(buf_nom, '\n');
	if (p_nom != NULL)
		*p_nom = 0;

	p_max = strchr(buf_max, '\n');
	if (p_max != NULL)
		*p_max = 0;

	p_cmax = strchr(buf_cmax, '\n');
	if (p_cmax != NULL)
		*p_cmax = 0;

	nominal_perf = strtoul(buf_nom, &p_nom, POWER_CONVERT_TO_DECIMAL);
	highest_perf = strtoul(buf_max, &p_max, POWER_CONVERT_TO_DECIMAL);
	cpuinfo_max_freq = strtoul(buf_cmax, &p_cmax, POWER_CONVERT_TO_DECIMAL);

	pi->highest_perf = highest_perf;
	pi->nominal_perf = nominal_perf;

	if ((highest_perf > nominal_perf) && ((cpuinfo_max_freq == highest_perf) ||
				cpuinfo_max_freq == highest_perf * UNIT_DIFF)) {
		pi->turbo_available = 1;
		pi->turbo_enable = 1;
		ret = 0;
		POWER_DEBUG_TRACE("Lcore %u can do Turbo Boost! highest perf %u, "
				"nominal perf %u\n",
				pi->lcore_id, highest_perf, nominal_perf);
	} else {
		pi->turbo_available = 0;
		pi->turbo_enable = 0;
		POWER_DEBUG_TRACE("Lcore %u Turbo not available! highest perf %u, "
				"nominal perf %u\n",
				pi->lcore_id, highest_perf, nominal_perf);
	}

out:
	fclose(f_nom);
	fclose(f_max);
	fclose(f_cmax);

	return ret;
}

/**
 * It is to get the available frequencies of the specific lcore by reading the
 * sys file.
 */
static int
power_get_available_freqs(struct cppc_power_info *pi)
{
	FILE *f_min, *f_max;
	int ret = -1;
	char *p_min, *p_max;
	char buf_min[BUFSIZ];
	char buf_max[BUFSIZ];
	char fullpath_min[PATH_MAX];
	char fullpath_max[PATH_MAX];
	char *s_min, *s_max;
	uint32_t scaling_min_freq = 0, scaling_max_freq = 0, nominal_perf = 0;
	uint32_t i, num_freqs = 0;

	snprintf(fullpath_max, sizeof(fullpath_max),
			POWER_SYSFILE_SCALING_MAX_FREQ,
			pi->lcore_id);
	snprintf(fullpath_min, sizeof(fullpath_min),
			POWER_SYSFILE_SCALING_MIN_FREQ,
			pi->lcore_id);

	f_min = fopen(fullpath_min, "r");
	FOPEN_OR_ERR_RET(f_min, ret);

	f_max = fopen(fullpath_max, "r");
	if (f_max == NULL)
		fclose(f_min);

	FOPEN_OR_ERR_RET(f_max, ret);

	s_min = fgets(buf_min, sizeof(buf_min), f_min);
	FOPS_OR_NULL_GOTO(s_min, out);

	s_max = fgets(buf_max, sizeof(buf_max), f_max);
	FOPS_OR_NULL_GOTO(s_max, out);


	/* Strip the line break if there is */
	p_min = strchr(buf_min, '\n');
	if (p_min != NULL)
		*p_min = 0;

	p_max = strchr(buf_max, '\n');
	if (p_max != NULL)
		*p_max = 0;

	scaling_min_freq = strtoul(buf_min, &p_min, POWER_CONVERT_TO_DECIMAL);
	scaling_max_freq = strtoul(buf_max, &p_max, POWER_CONVERT_TO_DECIMAL);

	power_check_turbo(pi);

	if (scaling_max_freq < scaling_min_freq)
		goto out;

	/* If turbo is available then there is one extra freq bucket
	 * to store the sys max freq which value is scaling_max_freq
	 */
	nominal_perf = (pi->nominal_perf < UNIT_DIFF) ?
			pi->nominal_perf * UNIT_DIFF : pi->nominal_perf;
	num_freqs = (nominal_perf - scaling_min_freq) / BUS_FREQ + 1 +
		pi->turbo_available;

	/* Generate the freq bucket array. */
	for (i = 0, pi->nb_freqs = 0; i < num_freqs; i++) {
		if ((i == 0) && pi->turbo_available)
			pi->freqs[pi->nb_freqs++] = scaling_max_freq;
		else
			pi->freqs[pi->nb_freqs++] =
			nominal_perf - (i - pi->turbo_available) * BUS_FREQ;
	}

	ret = 0;

	POWER_DEBUG_TRACE("%d frequency(s) of lcore %u are available\n",
			num_freqs, pi->lcore_id);

out:
	fclose(f_min);
	fclose(f_max);

	return ret;
}

/**
 * It is to fopen the sys file for the future setting the lcore frequency.
 */
static int
power_init_for_setting_freq(struct cppc_power_info *pi)
{
	FILE *f;
	char fullpath[PATH_MAX];
	char buf[BUFSIZ];
	uint32_t i, freq;
	char *s;

	snprintf(fullpath, sizeof(fullpath), POWER_SYSFILE_SETSPEED,
			pi->lcore_id);
	f = fopen(fullpath, "rw+");
	FOPEN_OR_ERR_RET(f, -1);

	s = fgets(buf, sizeof(buf), f);
	FOPS_OR_NULL_GOTO(s, out);

	freq = strtoul(buf, NULL, POWER_CONVERT_TO_DECIMAL);

	/* convert the frequency to nearest 100000 value
	 * Ex: if freq=1396789 then freq_conv=1400000
	 * Ex: if freq=800030 then freq_conv=800000
	 */
	unsigned int freq_conv = 0;
	freq_conv = (freq + FREQ_ROUNDING_DELTA)
				/ ROUND_FREQ_TO_N_100000;
	freq_conv = freq_conv * ROUND_FREQ_TO_N_100000;

	for (i = 0; i < pi->nb_freqs; i++) {
		if (freq_conv == pi->freqs[i]) {
			pi->curr_idx = i;
			pi->f = f;
			return 0;
		}
	}

out:
	fclose(f);

	return -1;
}

int
power_cppc_cpufreq_check_supported(void)
{
	return cpufreq_check_scaling_driver(POWER_CPPC_DRIVER);
}

int
power_cppc_cpufreq_init(unsigned int lcore_id)
{
	struct cppc_power_info *pi;
	uint32_t exp_state;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Lcore id %u can not exceeds %u\n",
				lcore_id, RTE_MAX_LCORE - 1U);
		return -1;
	}

	pi = &lcore_power_info[lcore_id];
	exp_state = POWER_IDLE;
	/* The power in use state works as a guard variable between
	 * the CPU frequency control initialization and exit process.
	 * The ACQUIRE memory ordering here pairs with the RELEASE
	 * ordering below as lock to make sure the frequency operations
	 * in the critical section are done under the correct state.
	 */
	if (!__atomic_compare_exchange_n(&(pi->state), &exp_state,
					POWER_ONGOING, 0,
					__ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		RTE_LOG(INFO, POWER, "Power management of lcore %u is "
				"in use\n", lcore_id);
		return -1;
	}

	pi->lcore_id = lcore_id;
	/* Check and set the governor */
	if (power_set_governor_userspace(pi) < 0) {
		RTE_LOG(ERR, POWER, "Cannot set governor of lcore %u to "
				"userspace\n", lcore_id);
		goto fail;
	}

	/* Get the available frequencies */
	if (power_get_available_freqs(pi) < 0) {
		RTE_LOG(ERR, POWER, "Cannot get available frequencies of "
				"lcore %u\n", lcore_id);
		goto fail;
	}

	/* Init for setting lcore frequency */
	if (power_init_for_setting_freq(pi) < 0) {
		RTE_LOG(ERR, POWER, "Cannot init for setting frequency for "
				"lcore %u\n", lcore_id);
		goto fail;
	}

	/* Set freq to max by default */
	if (power_cppc_cpufreq_freq_max(lcore_id) < 0) {
		RTE_LOG(ERR, POWER, "Cannot set frequency of lcore %u "
				"to max\n", lcore_id);
		goto fail;
	}

	RTE_LOG(INFO, POWER, "Initialized successfully for lcore %u "
			"power management\n", lcore_id);

	__atomic_store_n(&(pi->state), POWER_USED, __ATOMIC_RELEASE);

	return 0;

fail:
	__atomic_store_n(&(pi->state), POWER_UNKNOWN, __ATOMIC_RELEASE);
	return -1;
}

/**
 * It is to check the governor and then set the original governor back if
 * needed by writing the sys file.
 */
static int
power_set_governor_original(struct cppc_power_info *pi)
{
	FILE *f;
	int ret = -1;
	char buf[BUFSIZ];
	char fullpath[PATH_MAX];
	char *s;
	int val;

	snprintf(fullpath, sizeof(fullpath), POWER_SYSFILE_GOVERNOR,
			pi->lcore_id);
	f = fopen(fullpath, "rw+");
	FOPEN_OR_ERR_RET(f, ret);

	s = fgets(buf, sizeof(buf), f);
	FOPS_OR_NULL_GOTO(s, out);

	/* Check if the governor to be set is the same as current */
	if (strncmp(buf, pi->governor_ori, sizeof(pi->governor_ori)) == 0) {
		ret = 0;
		POWER_DEBUG_TRACE("Power management governor of lcore %u "
				"has already been set to %s\n",
				pi->lcore_id, pi->governor_ori);
		goto out;
	}

	/* Write back the original governor */
	val = fseek(f, 0, SEEK_SET);
	FOPS_OR_ERR_GOTO(val, out);

	val = fputs(pi->governor_ori, f);
	FOPS_OR_ERR_GOTO(val, out);

	ret = 0;
	RTE_LOG(INFO, POWER, "Power management governor of lcore %u "
			"has been set back to %s successfully\n",
			pi->lcore_id, pi->governor_ori);
out:
	fclose(f);

	return ret;
}

int
power_cppc_cpufreq_exit(unsigned int lcore_id)
{
	struct cppc_power_info *pi;
	uint32_t exp_state;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Lcore id %u can not exceeds %u\n",
				lcore_id, RTE_MAX_LCORE - 1U);
		return -1;
	}
	pi = &lcore_power_info[lcore_id];
	exp_state = POWER_USED;
	/* The power in use state works as a guard variable between
	 * the CPU frequency control initialization and exit process.
	 * The ACQUIRE memory ordering here pairs with the RELEASE
	 * ordering below as lock to make sure the frequency operations
	 * in the critical section are done under the correct state.
	 */
	if (!__atomic_compare_exchange_n(&(pi->state), &exp_state,
					POWER_ONGOING, 0,
					__ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		RTE_LOG(INFO, POWER, "Power management of lcore %u is "
				"not used\n", lcore_id);
		return -1;
	}

	/* Close FD of setting freq */
	fclose(pi->f);
	pi->f = NULL;

	/* Set the governor back to the original */
	if (power_set_governor_original(pi) < 0) {
		RTE_LOG(ERR, POWER, "Cannot set the governor of %u back "
				"to the original\n", lcore_id);
		goto fail;
	}

	RTE_LOG(INFO, POWER, "Power management of lcore %u has exited from "
			"'userspace' mode and been set back to the "
			"original\n", lcore_id);
	__atomic_store_n(&(pi->state), POWER_IDLE, __ATOMIC_RELEASE);

	return 0;

fail:
	__atomic_store_n(&(pi->state), POWER_UNKNOWN, __ATOMIC_RELEASE);

	return -1;
}

uint32_t
power_cppc_cpufreq_freqs(unsigned int lcore_id, uint32_t *freqs, uint32_t num)
{
	struct cppc_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return 0;
	}

	if (freqs == NULL) {
		RTE_LOG(ERR, POWER, "NULL buffer supplied\n");
		return 0;
	}

	pi = &lcore_power_info[lcore_id];
	if (num < pi->nb_freqs) {
		RTE_LOG(ERR, POWER, "Buffer size is not enough\n");
		return 0;
	}
	rte_memcpy(freqs, pi->freqs, pi->nb_freqs * sizeof(uint32_t));

	return pi->nb_freqs;
}

uint32_t
power_cppc_cpufreq_get_freq(unsigned int lcore_id)
{
	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return RTE_POWER_INVALID_FREQ_INDEX;
	}

	return lcore_power_info[lcore_id].curr_idx;
}

int
power_cppc_cpufreq_set_freq(unsigned int lcore_id, uint32_t index)
{
	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	return set_freq_internal(&(lcore_power_info[lcore_id]), index);
}

int
power_cppc_cpufreq_freq_down(unsigned int lcore_id)
{
	struct cppc_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];
	if (pi->curr_idx + 1 == pi->nb_freqs)
		return 0;

	/* Frequencies in the array are from high to low. */
	return set_freq_internal(pi, pi->curr_idx + 1);
}

int
power_cppc_cpufreq_freq_up(unsigned int lcore_id)
{
	struct cppc_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];
	if (pi->curr_idx == 0 || (pi->curr_idx == 1 &&
		pi->turbo_available && !pi->turbo_enable))
		return 0;

	/* Frequencies in the array are from high to low. */
	return set_freq_internal(pi, pi->curr_idx - 1);
}

int
power_cppc_cpufreq_freq_max(unsigned int lcore_id)
{
	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	/* Frequencies in the array are from high to low. */
	if (lcore_power_info[lcore_id].turbo_available) {
		if (lcore_power_info[lcore_id].turbo_enable)
			/* Set to Turbo */
			return set_freq_internal(
				&lcore_power_info[lcore_id], 0);
		else
			/* Set to max non-turbo */
			return set_freq_internal(
				&lcore_power_info[lcore_id], 1);
	} else
		return set_freq_internal(&lcore_power_info[lcore_id], 0);
}

int
power_cppc_cpufreq_freq_min(unsigned int lcore_id)
{
	struct cppc_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];

	/* Frequencies in the array are from high to low. */
	return set_freq_internal(pi, pi->nb_freqs - 1);
}

int
power_cppc_turbo_status(unsigned int lcore_id)
{
	struct cppc_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];

	return pi->turbo_enable;
}

int
power_cppc_enable_turbo(unsigned int lcore_id)
{
	struct cppc_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];

	if (pi->turbo_available)
		pi->turbo_enable = 1;
	else {
		pi->turbo_enable = 0;
		RTE_LOG(ERR, POWER,
			"Failed to enable turbo on lcore %u\n",
			lcore_id);
		return -1;
	}

	/* TODO: must set to max once enbling Turbo? Considering add condition:
	 * if ((pi->turbo_available) && (pi->curr_idx <= 1))
	 */
	/* Max may have changed, so call to max function */
	if (power_cppc_cpufreq_freq_max(lcore_id) < 0) {
		RTE_LOG(ERR, POWER,
			"Failed to set frequency of lcore %u to max\n",
			lcore_id);
		return -1;
	}

	return 0;
}

int
power_cppc_disable_turbo(unsigned int lcore_id)
{
	struct cppc_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];

	pi->turbo_enable = 0;

	if ((pi->turbo_available) && (pi->curr_idx <= 1)) {
		/* Try to set freq to max by default coming out of turbo */
		if (power_cppc_cpufreq_freq_max(lcore_id) < 0) {
			RTE_LOG(ERR, POWER,
				"Failed to set frequency of lcore %u to max\n",
				lcore_id);
			return -1;
		}
	}

	return 0;
}

int
power_cppc_get_capabilities(unsigned int lcore_id,
		struct rte_power_core_capabilities *caps)
{
	struct cppc_power_info *pi;

	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, POWER, "Invalid lcore ID\n");
		return -1;
	}
	if (caps == NULL) {
		RTE_LOG(ERR, POWER, "Invalid argument\n");
		return -1;
	}

	pi = &lcore_power_info[lcore_id];
	caps->capabilities = 0;
	caps->turbo = !!(pi->turbo_available);

	return 0;
}
