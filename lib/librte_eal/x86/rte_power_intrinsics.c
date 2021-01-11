/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include "rte_power_intrinsics.h"

static bool wait_supported;

static inline uint64_t
__get_umwait_val(const volatile void *p, const uint8_t sz)
{
	switch (sz) {
	case sizeof(uint8_t):
		return *(const volatile uint8_t *)p;
	case sizeof(uint16_t):
		return *(const volatile uint16_t *)p;
	case sizeof(uint32_t):
		return *(const volatile uint32_t *)p;
	case sizeof(uint64_t):
		return *(const volatile uint64_t *)p;
	default:
		/* this is an intrinsic, so we can't have any error handling */
		RTE_ASSERT(0);
		return 0;
	}
}

/**
 * This function uses UMONITOR/UMWAIT instructions and will enter C0.2 state.
 * For more information about usage of these instructions, please refer to
 * Intel(R) 64 and IA-32 Architectures Software Developer's Manual.
 */
void
rte_power_monitor(const struct rte_power_monitor_cond *pmc,
		const uint64_t tsc_timestamp)
{
	const uint32_t tsc_l = (uint32_t)tsc_timestamp;
	const uint32_t tsc_h = (uint32_t)(tsc_timestamp >> 32);

	/* prevent user from running this instruction if it's not supported */
	if (!wait_supported)
		return;

	/*
	 * we're using raw byte codes for now as only the newest compiler
	 * versions support this instruction natively.
	 */

	/* set address for UMONITOR */
	asm volatile(".byte 0xf3, 0x0f, 0xae, 0xf7;"
			:
			: "D"(pmc->addr));

	if (pmc->mask) {
		const uint64_t cur_value = __get_umwait_val(
				pmc->addr, pmc->data_sz);
		const uint64_t masked = cur_value & pmc->mask;

		/* if the masked value is already matching, abort */
		if (masked == pmc->val)
			return;
	}
	/* execute UMWAIT */
	asm volatile(".byte 0xf2, 0x0f, 0xae, 0xf7;"
			: /* ignore rflags */
			: "D"(0), /* enter C0.2 */
			  "a"(tsc_l), "d"(tsc_h));
}

/**
 * This function uses TPAUSE instruction  and will enter C0.2 state. For more
 * information about usage of this instruction, please refer to Intel(R) 64 and
 * IA-32 Architectures Software Developer's Manual.
 */
void
rte_power_pause(const uint64_t tsc_timestamp)
{
	const uint32_t tsc_l = (uint32_t)tsc_timestamp;
	const uint32_t tsc_h = (uint32_t)(tsc_timestamp >> 32);

	/* prevent user from running this instruction if it's not supported */
	if (!wait_supported)
		return;

	/* execute TPAUSE */
	asm volatile(".byte 0x66, 0x0f, 0xae, 0xf7;"
		: /* ignore rflags */
		: "D"(0), /* enter C0.2 */
		  "a"(tsc_l), "d"(tsc_h));
}

RTE_INIT(rte_power_intrinsics_init) {
	struct rte_cpu_intrinsics i;

	rte_cpu_get_intrinsics_support(&i);

	if (i.power_monitor && i.power_pause)
		wait_supported = 1;
}
