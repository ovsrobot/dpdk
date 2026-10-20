/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <inttypes.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_os_shim.h>
#include <rte_pause.h>
#include <rte_eal.h>
#include <rte_time.h>

#include <eal_export.h>
#include "eal_private.h"
#include "eal_memcfg.h"

/* The frequency of the RDTSC timer resolution */
static uint64_t eal_tsc_resolution_hz;

/* Reference point relating the TSC to the wall clock, taken at init */
static uint64_t eal_tsc_base;
static uint64_t eal_epoch_ns;

/* Pointer to user delay function */
RTE_EXPORT_SYMBOL(rte_delay_us)
void (*rte_delay_us)(unsigned int) = NULL;

RTE_EXPORT_SYMBOL(rte_delay_us_block)
void
rte_delay_us_block(unsigned int us)
{
	const uint64_t start = rte_get_timer_cycles();
	const uint64_t ticks = (uint64_t)us * rte_get_timer_hz() / 1E6;
	while ((rte_get_timer_cycles() - start) < ticks)
		rte_pause();
}

RTE_EXPORT_SYMBOL(rte_get_tsc_hz)
uint64_t
rte_get_tsc_hz(void)
{
	return eal_tsc_resolution_hz;
}

/*
 * Convert a count of cycles to nanoseconds.
 *
 * Compute the whole seconds first, so that the remainder is always
 * less than the frequency and scaling it by NS_PER_S cannot overflow.
 */
static uint64_t
cycles_to_ns(uint64_t cycles)
{
	uint64_t secs = cycles / eal_tsc_resolution_hz;
	uint64_t rem = cycles % eal_tsc_resolution_hz;

	return secs * NS_PER_S + (rem * NS_PER_S) / eal_tsc_resolution_hz;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_tsc_to_ns, 26.11)
uint64_t
rte_tsc_to_ns(uint64_t tsc)
{
	/*
	 * A caller may convert a TSC value sampled before the reference
	 * point was taken, so handle both directions on an unsigned
	 * magnitude.
	 */
	if (unlikely(tsc < eal_tsc_base))
		return eal_epoch_ns - cycles_to_ns(eal_tsc_base - tsc);

	return eal_epoch_ns + cycles_to_ns(tsc - eal_tsc_base);
}

static uint64_t
estimate_tsc_freq(void)
{
#define CYC_PER_10MHZ 1E7
	EAL_LOG(WARNING, "WARNING: TSC frequency estimated roughly"
		" - clock timings may be less accurate.");
	/* assume that the rte_delay_us_sleep() will sleep for 1 second */
	uint64_t start = rte_rdtsc();
	rte_delay_us_sleep(US_PER_S);
	/* Round up to 10Mhz. 1E7 ~ 10Mhz */
	return RTE_ALIGN_MUL_NEAR(rte_rdtsc() - start, CYC_PER_10MHZ);
}

/*
 * Record the TSC value matching a wall clock reading, so that any TSC
 * value can later be expressed as nanoseconds since the Unix epoch.
 * Read the TSC either side of the clock to halve the sampling error.
 */
static void
init_tsc_base(void)
{
	struct timespec ts;
	uint64_t cycles;

	cycles = rte_get_tsc_cycles();
	if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
		EAL_LOG(WARNING, "Could not read wall clock,"
			" TSC to epoch conversion unavailable");
		return;
	}
	eal_tsc_base = (cycles + rte_get_tsc_cycles()) / 2;
	eal_epoch_ns = rte_timespec_to_ns(&ts);
}

int
init_tsc_freq(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	uint64_t freq;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		/*
		 * Just use the primary process calculated TSC rate in any
		 * secondary process.  It avoids any unnecessary overhead on
		 * systems where arch-specific frequency detection is not
		 * available.
		 */
		if (mcfg->tsc_hz == 0) {
			EAL_LOG(ERR, "Primary process TSC frequency is zero");
			return -1;
		}

		eal_tsc_resolution_hz = mcfg->tsc_hz;
		init_tsc_base();
		return 0;
	}

	freq = get_tsc_freq_arch();
	freq = get_tsc_freq(freq);
	if (freq == 0) {
		freq = estimate_tsc_freq();
		if (freq == 0) {
			EAL_LOG(ERR, "TSC frequency is too slow");
			return -1;
		}
	}

	EAL_LOG(DEBUG, "TSC frequency is ~%" PRIu64 " KHz", freq / 1000);
	eal_tsc_resolution_hz = freq;
	mcfg->tsc_hz = freq;
	init_tsc_base();
	return 0;
}

RTE_EXPORT_SYMBOL(rte_delay_us_callback_register)
void rte_delay_us_callback_register(void (*userfunc)(unsigned int))
{
	rte_delay_us = userfunc;
}

RTE_INIT(rte_timer_init)
{
	/* set rte_delay_us_block as a delay function */
	rte_delay_us_callback_register(rte_delay_us_block);
}
