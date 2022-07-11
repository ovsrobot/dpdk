/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include <errno.h>

#include <rte_memcpy.h>

#include "rte_power_uncore.h"
#include "power_common.h"

#define BUS_FREQ     100000

#define POWER_GOVERNOR_PERF "performance"
#define POWER_UNCORE_SYSFILE_MAX_FREQ \
        "/sys/devices/system/cpu/intel_uncore_frequency/package_%02u_die_%02u/max_freq_khz"
#define POWER_UNCORE_SYSFILE_MIN_FREQ  \
        "/sys/devices/system/cpu/intel_uncore_frequency/package_%02u_die_%02u/min_freq_khz"
#define POWER_UNCORE_SYSFILE_BASE_MAX_FREQ \
        "/sys/devices/system/cpu/intel_uncore_frequency/package_%02u_die_%02u/initial_max_freq_khz"
#define POWER_UNCORE_SYSFILE_BASE_MIN_FREQ  \
        "/sys/devices/system/cpu/intel_uncore_frequency/package_%02u_die_%02u/initial_min_freq_khz"


struct uncore_power_info {
    unsigned int die;                    /**< Core die id */
    unsigned int pkg;                    /**< Package id */
    uint32_t freqs[RTE_MAX_UNCORE_FREQS];/**< Frequency array */  
    uint32_t nb_freqs;                   /**< Number of available freqs */
    FILE *f_cur_min;                     /**< FD of scaling_min */
    FILE *f_cur_max;                     /**< FD of scaling_max */
    FILE *f_base_min;                    /**< FD of initial min */
    FILE *f_base_max;                    /**< FD of initial max */
    int cur_idx;                         /**< Freq index in freqs array */
    uint32_t init_max_freq;              /**< Initial max frequency */
    uint32_t init_min_freq;              /**< Initial min frequency */
} __rte_cache_aligned;


static struct uncore_power_info uncore_info[RTE_MAX_NUMA_NODES][RTE_MAX_NUMA_DIE];

static int
set_uncore_freq_internal(struct uncore_power_info *ui, uint32_t idx)
{
    uint32_t target_uncore_freq, curr_max_freq;
    int ret;

    if (idx >= RTE_MAX_UNCORE_FREQS || idx >= ui->nb_freqs) {
        RTE_LOG(ERR, POWER, "Invalid uncore frequency index %u, which "
                "should be less than %u\n", idx, ui->nb_freqs);
        return -1;
    }

    target_uncore_freq = ui->freqs[idx];

    if (fprintf(ui->f_cur_min, "%u", target_uncore_freq) < 0) {
        RTE_LOG(ERR, POWER, "Fail to write new uncore frequency for "
                "pkg %02u die %02u\n", ui->pkg, ui->die);
        return -1;
    }

    if (fprintf(ui->f_cur_max, "%u", target_uncore_freq) < 0) {
        RTE_LOG(ERR, POWER, "Fail to write new uncore frequency for "
                "pkg %02u die %02u\n", ui->pkg, ui->die);
        return -1;
    }

    POWER_DEBUG_TRACE("Uncore requency '%u' to be set for pkg %02u die %02u\n",
                target_uncore_freq, ui->pkg, ui->die);
    
    open_core_sysfs_file(&ui->f_cur_max, "rw+", POWER_UNCORE_SYSFILE_MAX_FREQ,
            ui->pkg, ui->die);
    if (ui->f_cur_max == NULL) {
        RTE_LOG(DEBUG, POWER, "failed to open %s\n",
                POWER_UNCORE_SYSFILE_MAX_FREQ);
        return -1;
    }
    ret = read_core_sysfs_u32(ui->f_cur_max, &curr_max_freq);
        if (ret < 0) {
            RTE_LOG(DEBUG, POWER, "Failed to read %s\n",
                    POWER_UNCORE_SYSFILE_MAX_FREQ);
            fclose(ui->f_cur_max);
            return -1;
        }

    if (target_uncore_freq <= curr_max_freq){
        fflush(ui->f_cur_min);
        fflush(ui->f_cur_max);
    }
    else {
        fflush(ui->f_cur_max);
        fflush(ui->f_cur_min);
    }

    ui->cur_idx = idx;

    return 0;
}

/**
 * Fopen the sys file for the future setting of the uncore die frequency.
 */
static int
power_init_for_setting_uncore_freq(struct uncore_power_info *ui)
{
    FILE *f_base_min = NULL, *f_base_max = NULL, *f_min = NULL, *f_max = NULL;
    uint32_t base_min_freq, base_max_freq, min_freq, max_freq;
    int ret;

    /* open and read all uncore sys files */
    /* Base_max */
    open_core_sysfs_file(&f_base_max, "r", POWER_UNCORE_SYSFILE_BASE_MAX_FREQ,
            ui->pkg, ui->die);
    if (f_base_max == NULL) {
        RTE_LOG(DEBUG, POWER, "failed to open %s\n",
                POWER_UNCORE_SYSFILE_BASE_MAX_FREQ);
        goto err;
    }
    ret = read_core_sysfs_u32(f_base_max, &base_max_freq);
    if (ret < 0) {
        RTE_LOG(DEBUG, POWER, "Failed to read %s\n",
                POWER_UNCORE_SYSFILE_BASE_MAX_FREQ);
        goto err;
    }

    /* Base min */
    open_core_sysfs_file(&f_base_min, "r", POWER_UNCORE_SYSFILE_BASE_MIN_FREQ,
        ui->pkg, ui->die);
    if (f_base_min == NULL) {
        RTE_LOG(DEBUG, POWER, "failed to open %s\n",
                POWER_UNCORE_SYSFILE_BASE_MIN_FREQ);
        goto err;
    }
    if (f_base_min != NULL) {
        ret = read_core_sysfs_u32(f_base_min, &base_min_freq);
        if (ret < 0) {
            RTE_LOG(DEBUG, POWER, "Failed to read %s\n",
                    POWER_UNCORE_SYSFILE_BASE_MIN_FREQ);
            goto err;
        }
    }

    /* Curr min */
    open_core_sysfs_file(&f_min, "rw+", POWER_UNCORE_SYSFILE_MIN_FREQ,
            ui->pkg, ui->die);
    if (f_min == NULL) {
        RTE_LOG(DEBUG, POWER, "failed to open %s\n",
                POWER_UNCORE_SYSFILE_MIN_FREQ);
        goto err;
    }
    if (f_min != NULL) {
        ret = read_core_sysfs_u32(f_min, &min_freq);
        if (ret < 0) {
            RTE_LOG(DEBUG, POWER, "Failed to read %s\n",
                    POWER_UNCORE_SYSFILE_MIN_FREQ);
            goto err;
        }
    }

    /* Curr max */
    open_core_sysfs_file(&f_max, "rw+", POWER_UNCORE_SYSFILE_MAX_FREQ,
            ui->pkg, ui->die);
    if (f_max == NULL) {
        RTE_LOG(DEBUG, POWER, "failed to open %s\n",
                POWER_UNCORE_SYSFILE_MAX_FREQ);
        goto err;
    }
    if (f_max != NULL) {
        ret = read_core_sysfs_u32(f_max, &max_freq);
        if (ret < 0) {
            RTE_LOG(DEBUG, POWER, "Failed to read %s\n",
                    POWER_UNCORE_SYSFILE_MAX_FREQ);
            goto err;
        }
    }	

    /* assign file handles */
    ui->f_cur_min = f_min;
    ui->f_cur_max = f_max;
    ui->f_base_max = f_base_max;
    ui->f_base_min = f_base_min;
    ui->init_max_freq = base_max_freq;
    ui->init_min_freq = base_min_freq;

    return 0;

err:
    if (f_base_min != NULL)
        fclose(f_base_min);
    if (f_base_max != NULL)
        fclose(f_base_max);
    if (f_min != NULL)
        fclose(f_min);
    if (f_max != NULL)
        fclose(f_max);
    return -1;
}

/**
 * Get the available uncore frequencies of the specific die by reading the
 * sys file.
 */
static int
power_get_available_uncore_freqs(struct uncore_power_info *ui)
{
    int ret = -1;
    uint32_t i, num_uncore_freqs = 0;

    num_uncore_freqs = (ui->init_max_freq - ui->init_min_freq) / BUS_FREQ +1;
    if (num_uncore_freqs >= RTE_MAX_UNCORE_FREQS) {
        RTE_LOG(ERR, POWER, "Too many available uncore frequencies: %d\n",
                num_uncore_freqs);
        goto out;
    }

    /* Generate the uncore freq bucket array. */
    for (i = 0; i < num_uncore_freqs; i++) {
        ui->freqs[i] = ui->init_max_freq - (i) * BUS_FREQ;
    }

    ui->nb_freqs = num_uncore_freqs;

    ret = 0;

    POWER_DEBUG_TRACE("%d uncore frequency(s) of pkg %02u die %02u are available\n",
            num_uncore_freqs, ui->pkg, ui->die);

out:
    return ret;
}


int
rte_power_uncore_init(unsigned int pkg, unsigned int die)
{
    struct uncore_power_info *ui;

    /* Check if pkg and die values are viable */
    if (pkg >= RTE_MAX_NUMA_NODES) {
        RTE_LOG(DEBUG, POWER, "Package number %02u can not exceed %u\n",
                pkg, RTE_MAX_NUMA_NODES - 1U);
        return -1;
    }

    if (die >= RTE_MAX_NUMA_DIE) {
        RTE_LOG(DEBUG, POWER, "Die number %02u can not exceed %u\n",
                die, RTE_MAX_NUMA_DIE - 1U);
        return -1;
    }

    ui = &uncore_info[pkg][die];
    ui->die = die;
    ui->pkg = pkg;
    
    /* Init for setting unocre die frequency */
    if (power_init_for_setting_uncore_freq(ui) < 0) {
        RTE_LOG(DEBUG, POWER, "Cannot init for setting uncore frequency for "
                "pkg %02u die %02u\n", pkg, die);
        return -1;
    }

    /* Get the available frequencies */
    if (power_get_available_uncore_freqs(ui) < 0) {
        RTE_LOG(DEBUG, POWER, "Cannot get available uncore frequencies of "
                "pkg %02u die %02u\n", pkg, die);
        return -1;
    }

    return 0;
}

int
rte_power_uncore_exit(unsigned int pkg, unsigned int die)
{
    struct uncore_power_info *ui;

    if (pkg >= RTE_MAX_NUMA_NODES) {
        RTE_LOG(DEBUG, POWER, "Package number %02u can not exceed %u\n",
                pkg, RTE_MAX_NUMA_NODES - 1U);
        return -1;
    }

    if (die >= RTE_MAX_NUMA_DIE) {
        RTE_LOG(DEBUG, POWER, "Die number %02u can not exceed %u\n",
                die, RTE_MAX_NUMA_DIE - 1U);
        return -1;
    }

    ui = &uncore_info[pkg][die];

    /* Close FD of setting freq */
    fclose(ui->f_cur_min);
    fclose(ui->f_cur_max);
    fclose(ui->f_base_max);
    fclose(ui->f_base_min);
    ui->f_cur_min = NULL;
    ui->f_cur_max = NULL;
    ui->f_base_min = NULL;
    ui->f_base_max = NULL;

    return 0;
}

int
rte_power_get_uncore_freq(unsigned int pkg, unsigned int die)
{
    if (pkg >= RTE_MAX_NUMA_NODES) {
        RTE_LOG(DEBUG, POWER, "Invalid package number\n");
        return -1;
    }

    if (die >= RTE_MAX_NUMA_DIE) {
        RTE_LOG(DEBUG, POWER, "Invalid die number\n");
        return -1;
    }

    return uncore_info[pkg][die].cur_idx;
}

int
rte_power_set_uncore_freq(unsigned int pkg, unsigned int die, uint32_t index)
{
    if (pkg >= RTE_MAX_NUMA_NODES) {
        RTE_LOG(DEBUG, POWER, "Invalid package number\n");
        return -1;
    }

    if (die >= RTE_MAX_NUMA_DIE) {
        RTE_LOG(DEBUG, POWER, "Invalid die number\n");
        return -1;
    }

    return set_uncore_freq_internal(&(uncore_info[pkg][die]), index);
}

int
rte_power_uncore_freq_max(unsigned int pkg, unsigned int die)
{
    if (pkg >= RTE_MAX_NUMA_NODES) {
        RTE_LOG(DEBUG, POWER, "Invalid package number\n");
        return -1;
    }

    if (die >= RTE_MAX_NUMA_DIE) {
        RTE_LOG(DEBUG, POWER, "Invalid die number\n");
        return -1;
    }

    struct uncore_power_info *ui = &uncore_info[pkg][die];

    if (fprintf(ui->f_cur_max, "%u", 0) < 0) {
        RTE_LOG(ERR, POWER, "Fail to write new uncore frequency for "
                "pkg %02u die %02u\n", ui->pkg, ui->die);
        return -1;
    }

    fflush(ui->f_cur_max);
    return 0;
}


int
rte_power_uncore_freq_min(unsigned int pkg, unsigned int die)
{
    if (pkg >= RTE_MAX_NUMA_NODES) {
        RTE_LOG(DEBUG, POWER, "Invalid package number\n");
        return -1;
    }

    if (die >= RTE_MAX_NUMA_DIE) {
        RTE_LOG(DEBUG, POWER, "Invalid die number\n");
        return -1;
    }

    struct uncore_power_info *ui = &uncore_info[pkg][die];

    if (fprintf(ui->f_cur_min, "%u",  ui->freqs[ui->nb_freqs - 1]) < 0) {
        RTE_LOG(ERR, POWER, "Fail to write new uncore frequency for "
                "pkg %02u die %02u\n", ui->pkg, ui->die);
        return -1;
    }

    fflush(ui->f_cur_min);
    return 0;
}

int
rte_power_uncore_get_num_freqs(unsigned int pkg, unsigned int die)
{
    if (pkg >= RTE_MAX_NUMA_NODES) {
        RTE_LOG(DEBUG, POWER, "Invalid package number\n");
        return -1;
    }

    if (die >= RTE_MAX_NUMA_DIE) {
        RTE_LOG(DEBUG, POWER, "Invalid die number\n");
        return -1;
    }

    return uncore_info[pkg][die].nb_freqs;
}
